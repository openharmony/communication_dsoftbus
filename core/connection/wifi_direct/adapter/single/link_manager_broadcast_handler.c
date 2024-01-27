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

#include "link_manager_broadcast_handler.h"
#include <string.h>
#include <securec.h>
#include "conn_log.h"
#include "softbus_error_code.h"
#include "broadcast_receiver.h"
#include "wifi_direct_p2p_adapter.h"
#include "wifi_direct_decision_center.h"
#include "data/link_manager.h"
#include "data/resource_manager.h"
#include "utils/wifi_direct_network_utils.h"
#include "utils/wifi_direct_ipv4_info.h"
#include "utils/wifi_direct_anonymous.h"

static void UpdateInnerLink(struct WifiDirectP2pGroupInfo *groupInfo)
{
    struct InterfaceInfo *localInfo = GetResourceManager()->getInterfaceInfo(IF_NAME_P2P);
    struct WifiDirectIpv4Info *localIpv4 = (struct WifiDirectIpv4Info *)localInfo->getRawData(localInfo,
        II_KEY_IPV4, NULL, NULL);

    if (!groupInfo->isGroupOwner) {
        CONN_LOGI(CONN_WIFI_DIRECT, "not group owner");
        char groupOwnerMac[MAC_ADDR_STR_LEN] = {0};
        int32_t ret = GetWifiDirectNetWorkUtils()->macArrayToString(groupInfo->groupOwner.address, MAC_ADDR_ARRAY_SIZE,
                                                                    groupOwnerMac, sizeof(groupOwnerMac));
        CONN_CHECK_AND_RETURN_LOGW(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "convert mac to string failed");
        CONN_LOGI(CONN_WIFI_DIRECT, "groupOwnerMac=%{public}s", WifiDirectAnonymizeMac(groupOwnerMac));

        struct InnerLink link;
        InnerLinkConstructorWithArgs(&link, WIFI_DIRECT_LINK_TYPE_P2P, IF_NAME_P2P, groupOwnerMac);
        link.putInt(&link, IL_KEY_STATE, INNER_LINK_STATE_CONNECTED);
        link.putInt(&link, IL_KEY_FREQUENCY, groupInfo->frequency);
        GetLinkManager()->notifyLinkChange(&link);
        InnerLinkDestructor(&link);
        return;
    }

    char clientDevicesBuf[MAX_CONNECTED_DEVICE_COUNT][MAC_ADDR_STR_LEN];
    (void)memset_s(clientDevicesBuf, sizeof(clientDevicesBuf), 0, sizeof(clientDevicesBuf));
    char *clientDevices[MAX_CONNECTED_DEVICE_COUNT] = {NULL};
    int32_t clientDeviceSize = MIN(groupInfo->clientDeviceSize, MAX_CONNECTED_DEVICE_COUNT);
    CONN_LOGI(CONN_WIFI_DIRECT, "local is group owner, clientDeviceSize=%{public}d", clientDeviceSize);

    for (int32_t i = 0; i < clientDeviceSize; i++) {
        clientDevices[i] = clientDevicesBuf[i];
        GetWifiDirectNetWorkUtils()->macArrayToString(groupInfo->clientDevices[i].address, MAC_ADDR_ARRAY_SIZE,
                                                      clientDevices[i], MAC_ADDR_STR_LEN);
        CONN_LOGI(CONN_WIFI_DIRECT, "remoteMac=%{public}s", WifiDirectAnonymizeMac(clientDevices[i]));
        struct InnerLink newLink;
        InnerLinkConstructorWithArgs(&newLink, WIFI_DIRECT_LINK_TYPE_P2P, IF_NAME_P2P, clientDevices[i]);
        newLink.putInt(&newLink, IL_KEY_STATE, INNER_LINK_STATE_CONNECTED);
        newLink.putRawData(&newLink, IL_KEY_LOCAL_IPV4, localIpv4, sizeof(*localIpv4));
        newLink.putInt(&newLink, IL_KEY_FREQUENCY, groupInfo->frequency);
        GetLinkManager()->notifyLinkChange(&newLink);
        InnerLinkDestructor(&newLink);
    }

    GetLinkManager()->refreshLinks(WIFI_DIRECT_LINK_TYPE_P2P, clientDeviceSize, clientDevices);
}

static void HandleP2pConnectionChanged(const struct P2pBroadcastParam *param)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    if (param->p2pLinkInfo.connectState == P2P_DISCONNECTED) {
        GetLinkManager()->removeLinksByLinkType(WIFI_DIRECT_LINK_TYPE_P2P);
        return;
    }

    if (!param->groupInfo) {
        CONN_LOGI(CONN_WIFI_DIRECT, "groupInfo is null");
        return;
    }

    UpdateInnerLink(param->groupInfo);
}

static void Listener(enum BroadcastReceiverAction action, const struct BroadcastParam *param)
{
    if (action == WIFI_P2P_CONNECTION_CHANGED_ACTION) {
        CONN_LOGI(CONN_WIFI_DIRECT, "WIFI_P2P_CONNECTION_CHANGED_ACTION");
        HandleP2pConnectionChanged(&param->p2pParam);
    }
}

void LinkManagerBroadcastHandlerInit(void)
{
    struct BroadcastReceiver *broadcastReceiver = GetBroadcastReceiver();
    enum BroadcastReceiverAction actions[] = {
        WIFI_P2P_CONNECTION_CHANGED_ACTION,
    };

    broadcastReceiver->registerBroadcastListener(actions, ARRAY_SIZE(actions), "LinkManager",
                                                 LISTENER_PRIORITY_MIDDLE, Listener);
}