/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "resource_manager_broadcast_handler.h"
#include <string.h>
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "broadcast_receiver.h"
#include "wifi_direct_p2p_adapter.h"
#include "channel/default_negotiate_channel.h"
#include "data/resource_manager.h"
#include "utils/wifi_direct_anonymous.h"

#define LOG_LABEL "[WD] RMBrH: "

static void HandleP2pStateChanged(enum P2pState state)
{
    struct InterfaceInfo info;
    InterfaceInfoConstructorWithName(&info, IF_NAME_P2P);

    bool enabled = false;
    if (state != P2P_STATE_STARTED) {
        enabled = false;
        info.remove(&info, II_KEY_BASE_MAC);
        info.remove(&info, II_KEY_IPV4);
    } else {
        char localMac[MAC_ADDR_STR_LEN] = {0};
        GetWifiDirectP2pAdapter()->getMacAddress(localMac, sizeof(localMac));
        info.putString(&info, II_KEY_BASE_MAC, localMac);
        enabled = true;
    }

    CLOGI(LOG_LABEL "state=%d enable=%d", state, enabled);
    info.putBoolean(&info, II_KEY_IS_ENABLE, enabled);
    GetResourceManager()->notifyInterfaceInfoChange(&info);
    InterfaceInfoDestructor(&info);

    struct InterfaceInfo *interfaceInfo = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    if (interfaceInfo) {
        int32_t connectCap = interfaceInfo->getInt(interfaceInfo, II_KEY_CONNECT_CAPABILITY, WIFI_DIRECT_API_ROLE_NONE);
        CLOGI(LOG_LABEL "connectCap=%d", connectCap);
        if (connectCap == WIFI_DIRECT_API_ROLE_NONE) {
            GetResourceManager()->initWifiDirectInfo();
        }
    }
}

static void ResetInterfaceInfo(void)
{
    CLOGI(LOG_LABEL "enter");
    struct InterfaceInfo *oldInfo = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    int32_t port = oldInfo->getInt(oldInfo, II_KEY_PORT, -1);
    if (port > 0) {
        CLOGI(LOG_LABEL "stop auth listening");
        StopListeningForDefaultChannel();
    }

    struct InterfaceInfo info;
    InterfaceInfoConstructorWithName(&info, IF_NAME_P2P);
    info.putInt(&info, II_KEY_CONNECTED_DEVICE_COUNT, 0);
    info.putInt(&info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_NONE);
    info.putInt(&info, II_KEY_REUSE_COUNT, 0);
    info.remove(&info, II_KEY_PORT);
    info.remove(&info, II_KEY_SSID);
    info.remove(&info, II_KEY_DYNAMIC_MAC);
    info.remove(&info, II_KEY_PSK);
    info.remove(&info, II_KEY_CENTER_20M);
    info.remove(&info, II_KEY_IPV4);

    char localMac[MAC_ADDR_STR_LEN] = {0};
    GetWifiDirectP2pAdapter()->getMacAddress(localMac, sizeof(localMac));
    info.putString(&info, II_KEY_BASE_MAC, localMac);
    GetResourceManager()->notifyInterfaceInfoChange(&info);
    InterfaceInfoDestructor(&info);
}

static void UpdateInterfaceInfo(struct WifiDirectP2pGroupInfo *groupInfo)
{
    CLOGI(LOG_LABEL "isGroupOwner=%d clientDeviceSize=%d", groupInfo->isGroupOwner, groupInfo->clientDeviceSize);

    char localMac[MAC_ADDR_STR_LEN] = {0};
    GetWifiDirectP2pAdapter()->getMacAddress(localMac, sizeof(localMac));

    char dynamicMacString[MAC_ADDR_STR_LEN] = {0};
    int32_t ret = GetWifiDirectP2pAdapter()->getDynamicMacAddress(dynamicMacString, sizeof(dynamicMacString));
    CONN_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, LOG_LABEL "get mac failed");
    CLOGI(LOG_LABEL "localDynamicMac=%s", WifiDirectAnonymizeMac(dynamicMacString));

    char ipString[IP_ADDR_STR_LEN] = {0};
    ret = GetWifiDirectP2pAdapter()->getIpAddress(ipString, sizeof(ipString));
    CONN_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, LOG_LABEL "get ip failed");
    CLOGI(LOG_LABEL "localIp=%s", WifiDirectAnonymizeIp(ipString));

    struct InterfaceInfo info;
    InterfaceInfoConstructorWithName(&info, IF_NAME_P2P);
    info.putString(&info, II_KEY_BASE_MAC, localMac);
    info.putString(&info, II_KEY_DYNAMIC_MAC, dynamicMacString);
    info.putIpString(&info, ipString);
    info.putInt(&info, II_KEY_CONNECTED_DEVICE_COUNT, groupInfo->clientDeviceSize);

    if (groupInfo->isGroupOwner) {
        char groupConfigInfo[GROUP_CONFIG_STR_LEN] = {0};
        size_t groupConfigInfoSize = GROUP_CONFIG_STR_LEN;
        ret = GetWifiDirectP2pAdapter()->getGroupConfig(groupConfigInfo, &groupConfigInfoSize);
        CONN_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, LOG_LABEL "get group config failed");
        CLOGI(LOG_LABEL "set groupConfig");
        ret = info.setP2pGroupConfig(&info, groupConfigInfo);
        CONN_CHECK_AND_RETURN_LOG(ret == SOFTBUS_OK, LOG_LABEL "interface set group config failed");
        CLOGI(LOG_LABEL "myRole=WIFI_DIRECT_ROLE_GO");
        info.putInt(&info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GO);
    } else {
        CLOGI(LOG_LABEL "myRole=WIFI_DIRECT_ROLE_GC");
        info.putInt(&info, II_KEY_WIFI_DIRECT_ROLE, WIFI_DIRECT_API_ROLE_GC);
    }

    GetResourceManager()->notifyInterfaceInfoChange(&info);
    InterfaceInfoDestructor(&info);
}

static void HandleP2pConnectionChanged(const struct BroadcastParam *param)
{
    CLOGI(LOG_LABEL "enter");
    struct InterfaceInfo info;
    InterfaceInfoConstructor(&info);
    info.putName(&info, IF_NAME_P2P);

    if (param->p2pParam.p2pLinkInfo.connectState == P2P_DISCONNECTED || param->p2pParam.groupInfo == NULL) {
        CLOGI(LOG_LABEL "p2p disconnected, reset p2p interface info");
        ResetInterfaceInfo();
        return;
    }

    CLOGI(LOG_LABEL "p2p has group, update p2p interface info");
    UpdateInterfaceInfo(param->p2pParam.groupInfo);
}

static void Listener(enum BroadcastReceiverAction action, const struct BroadcastParam *param)
{
    if (action == WIFI_P2P_STATE_CHANGED_ACTION) {
        CLOGI(LOG_LABEL "WIFI_P2P_STATE_CHANGED_ACTION");
        HandleP2pStateChanged(param->p2pParam.p2pState);
    } else if (action == WIFI_P2P_CONNECTION_CHANGED_ACTION) {
        CLOGI(LOG_LABEL "WIFI_P2P_CONNECTION_CHANGED_ACTION");
        HandleP2pConnectionChanged(param);
    }
}

void ResourceManagerBroadcastHandlerInit(void)
{
    struct BroadcastReceiver *broadcastReceiver = GetBroadcastReceiver();
    enum BroadcastReceiverAction actions[] = {
        WIFI_P2P_STATE_CHANGED_ACTION,
        WIFI_P2P_CONNECTION_CHANGED_ACTION,
    };

    broadcastReceiver->registerBroadcastListener(actions, ARRAY_SIZE(actions), "ResourceManager", Listener);
}