/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "lnn_network_info.h"

#include <securec.h>

#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_deviceinfo_to_profile.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_net_capability.h"
#include "lnn_node_info.h"
#include "lnn_net_builder.h"
#include "lnn_sync_info_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_wifi_api_adapter.h"
#include "softbus_json_utils.h"
#include "softbus_def.h"
#include "wifi_direct_types.h"
#include "wifi_direct_p2p_adapter.h"

#define MSG_LEN 10
#define BITS 8
#define BITLEN 4
#define STRING_INTERFACE_BUFFER_LEN 16

static SoftBusWifiState g_wifiState = SOFTBUS_WIFI_UNKNOWN;
static bool g_isWifiDirectSupported = false;
static bool g_isApCoexistSupported = false;
static bool g_isWifiEnable = false;
static bool g_isApEnable = false;

static uint32_t ConvertMsgToCapability(uint32_t *capability, const uint8_t *msg, uint32_t len)
{
    if (capability == NULL || msg == NULL || len < BITS) {
        return SOFTBUS_ERR;
    }
    for (uint32_t i = 0; i < BITLEN; i++) {
        *capability = *capability | (*(msg + i) << BITS*i);
    }
    return SOFTBUS_OK;
}

static void PostNetchangedInfo(const char *networkId, ConnectionAddrType type)
{
    LNN_LOGI(LNN_BUILDER, "start post offline, conntype=%{public}d", type);
    if (LnnRequestLeaveSpecific(networkId, type) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "send request to NetBuilder fail");
    }
}

static void HandlePeerNetCapchanged(const char *networkId, uint32_t capability)
{
    if (!LnnHasCapability(capability, BIT_WIFI) || networkId == NULL) {
        LNN_LOGI(LNN_BUILDER, "only support close ble");
        return;
    }
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get node info fail");
        return;
    }
    if (LnnHasDiscoveryType(&info, DISCOVERY_TYPE_BLE) && !LnnHasCapability(capability, BIT_BLE)) {
        LNN_LOGI(LNN_BUILDER, "remote device lost ble, ble need offline");
        PostNetchangedInfo(networkId, CONNECTION_ADDR_BLE);
    }
    if (LnnHasDiscoveryType(&info, DISCOVERY_TYPE_BR) && !LnnHasCapability(capability, BIT_BR)) {
        LNN_LOGI(LNN_BUILDER, "remote device lost br, br need offline");
        PostNetchangedInfo(networkId, CONNECTION_ADDR_BR);
    }
}

static void UpdateNetworkInfo(const char *udid)
{
    NodeBasicInfo basic;
    (void)memset_s(&basic, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
    if (LnnGetBasicInfoByUdid(udid, &basic) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "GetBasicInfoByUdid fail");
        return;
    }
    LnnNotifyBasicInfoChanged(&basic, TYPE_NETWORK_INFO);
}

static void OnReceiveCapaSyncInfoMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    LNN_LOGI(LNN_BUILDER, "Recv capability info. type=%{public}d, len=%{public}d", type, len);
    if (type != LNN_INFO_TYPE_CAPABILITY) {
        return;
    }
    if (networkId == NULL) {
        return;
    }
    if (msg == NULL || len == 0) {
        return;
    }
    uint32_t capability = 0;
    if (ConvertMsgToCapability(&capability, msg, len) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "convert msg to capability fail");
        return;
    }
    LNN_LOGI(LNN_BUILDER, "capability=%{public}d", capability);
    // update ledger
    NodeInfo info;
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get node info fail");
        return;
    }
    if (info.discoveryType != capability) {
        LNN_LOGI(LNN_BUILDER, "capability change, need to updateProfile");
        UpdateProfile(&info);
        UpdateNetworkInfo(info.deviceInfo.deviceUdid);
    }
    if (LnnSetDLConnCapability(networkId, capability)) {
        LNN_LOGE(LNN_BUILDER, "update conn capability fail.");
        return;
    }
    HandlePeerNetCapchanged(networkId, capability);
}

static uint8_t *ConvertCapabilityToMsg(uint32_t localCapability)
{
    LNN_LOGE(LNN_BUILDER, "convert capability to msg enter");
    uint8_t *arr = (uint8_t *)SoftBusCalloc(MSG_LEN);
    if (arr == NULL) {
        LNN_LOGE(LNN_BUILDER, "convert capability to msg calloc msg fail");
        return NULL;
    }
    for (uint32_t i = 0; i < BITLEN; i++) {
        *(arr + i) = (localCapability >> (i * BITS)) & 0xFF;
    }
    return arr;
}

static bool IsNeedToSend(NodeInfo *nodeInfo, uint32_t type)
{
    if ((type & (1 << (uint32_t)DISCOVERY_TYPE_BR)) && (LnnHasDiscoveryType(nodeInfo, DISCOVERY_TYPE_BR))) {
        return true;
    } else if ((type & (1 << (uint32_t)DISCOVERY_TYPE_BLE)) && (LnnHasDiscoveryType(nodeInfo, DISCOVERY_TYPE_BLE))) {
        return true;
    } else if ((type & (1 << (uint32_t)DISCOVERY_TYPE_WIFI)) && (LnnHasDiscoveryType(nodeInfo, DISCOVERY_TYPE_WIFI))) {
        return true;
    } else {
        LNN_LOGI(LNN_BUILDER, "online device discovery type not match select link");
        return false;
    }
}

static void SendNetCapabilityToRemote(uint32_t netCapability, uint32_t type)
{
    uint8_t *msg = ConvertCapabilityToMsg(netCapability);
    if (msg ==NULL) {
        return;
    }
    int32_t infoNum = 0;
    NodeBasicInfo *netInfo = NULL;
    if (LnnGetAllOnlineNodeInfo(&netInfo, &infoNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "get all online node info fail.");
        SoftBusFree(msg);
        return;
    }
    if (infoNum == 0) {
        LNN_LOGI(LNN_BUILDER, "online device num is 0, not need to send network info");
        SoftBusFree(msg);
        return;
    }
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    for (int32_t i = 0; i < infoNum; i++) {
        if (LnnIsLSANode(&netInfo[i])) {
            continue;
        }
        if (LnnGetRemoteNodeInfoById(netInfo[i].networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
            continue;
        }
        if (IsNeedToSend(&nodeInfo, type)) {
            int32_t ret = LnnSendSyncInfoMsg(LNN_INFO_TYPE_CAPABILITY, netInfo[i].networkId, msg, MSG_LEN, NULL);
            LNN_LOGE(LNN_BUILDER,
                "sync network info ret=%{public}d, deviceName=%{public}s.", ret, netInfo[i].deviceName);
        }
    }
    SoftBusFree(netInfo);
    SoftBusFree(msg);
}

static void WifiStateProcess(uint32_t netCapability, bool isSend)
{
    LNN_LOGI(LNN_BUILDER, "wifi state change. netCapability=%{public}u, isSend=%{public}d", netCapability, isSend);
    if (LnnSetLocalNumInfo(NUM_KEY_NET_CAP, (int32_t)netCapability) != SOFTBUS_OK) {
        return;
    }
    if (!isSend) {
        return;
    }
    uint32_t type = (1 << (uint32_t)DISCOVERY_TYPE_BLE) | (1 << (uint32_t)DISCOVERY_TYPE_BR);
    SendNetCapabilityToRemote(netCapability, type);
    LNN_LOGI(LNN_BUILDER, "WifiStateEventHandler exit");
    return;
}

static bool IsP2pAvailable(bool isApSwitchOn)
{
    bool isTripleMode = SoftBusIsWifiTripleMode();
    return g_isWifiDirectSupported && (g_isApCoexistSupported || !isApSwitchOn || isTripleMode) && g_isWifiEnable;
}

static void LnnSetNetworkCapability(uint32_t *capability)
{
    (void)LnnSetNetCapability(capability, BIT_WIFI);
    (void)LnnSetNetCapability(capability, BIT_WIFI_5G);
    (void)LnnSetNetCapability(capability, BIT_WIFI_24G);
}

static void LnnClearNetworkCapability(uint32_t *capability)
{
    (void)LnnClearNetCapability(capability, BIT_WIFI);
    (void)LnnClearNetCapability(capability, BIT_WIFI_5G);
    (void)LnnClearNetCapability(capability, BIT_WIFI_24G);
}

static void GetNetworkCapability(SoftBusWifiState wifiState, uint32_t *capability, bool *needSync)
{
    switch (wifiState) {
        case SOFTBUS_WIFI_OBTAINING_IPADDR:
            LnnSetNetworkCapability(capability);
            break;
        case SOFTBUS_WIFI_ENABLED:
            g_isWifiEnable = true;
            LnnSetNetworkCapability(capability);
            (void)LnnSetNetCapability(capability, BIT_WIFI_P2P);
            *needSync = true;
            break;
        case SOFTBUS_WIFI_CONNECTED:
            LnnSetNetworkCapability(capability);
            break;
        case SOFTBUS_WIFI_DISABLED:
            g_isWifiEnable = false;
            if (!g_isApEnable) {
                LnnClearNetworkCapability(capability);
                if (!GetWifiDirectP2pAdapter()->isWifiP2pEnabled()) {
                    (void)LnnClearNetCapability(capability, BIT_WIFI_P2P);
                }
            }
            *needSync = true;
            break;
        case SOFTBUS_AP_ENABLED:
            g_isApEnable = true;
            LnnSetNetworkCapability(capability);
            if (IsP2pAvailable(true)) {
                (void)LnnSetNetCapability(capability, BIT_WIFI_P2P);
            }
            *needSync = true;
            break;
        case SOFTBUS_AP_DISABLED:
            g_isApEnable = false;
            if (IsP2pAvailable(false)) {
                (void)LnnSetNetCapability(capability, BIT_WIFI_P2P);
            }
            *needSync = true;
            break;
        default:
            break;
    }
}

static void WifiStateEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_WIFI_STATE_CHANGED) {
        LNN_LOGE(LNN_BUILDER, "bt state change evt handler get invalid param");
        return;
    }
    const LnnMonitorWlanStateChangedEvent *event = (const LnnMonitorWlanStateChangedEvent *)info;
    SoftBusWifiState wifiState = (SoftBusWifiState)event->status;
    uint32_t netCapability = 0;
    if (LnnGetLocalNumInfo(NUM_KEY_NET_CAP, (int32_t *)&netCapability) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "wifi state handler get capability fail from local.");
        return;
    }
    LNN_LOGI(LNN_BUILDER, "WifiStateEventHandler WifiState=%{public}d", wifiState);
    if (g_wifiState == wifiState) {
        return;
    }
    g_wifiState = wifiState;
    bool needSync = false;
    GetNetworkCapability(wifiState, &netCapability, &needSync);
    WifiStateProcess(netCapability, needSync);
}

static void BtStateChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_BT_STATE_CHANGED) {
        LNN_LOGE(LNN_BUILDER, "HB bt state change evt handler get invalid param");
        return;
    }
    uint32_t netCapability = 0;
    if (LnnGetLocalNumInfo(NUM_KEY_NET_CAP, (int32_t *)&netCapability) != SOFTBUS_OK) {
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusBtState btState = (SoftBusBtState)event->status;
    bool isSend = false;
    LNN_LOGI(LNN_BUILDER, "bt state change btState=%{public}d", btState);
    switch (btState) {
        case SOFTBUS_BR_TURN_ON:
            (void)LnnSetNetCapability(&netCapability, BIT_BR);
            (void)LnnSetNetCapability(&netCapability, BIT_BLE);
            break;
        case SOFTBUS_BR_TURN_OFF:
            (void)LnnClearNetCapability(&netCapability, BIT_BR);
            (void)LnnClearNetCapability(&netCapability, BIT_BLE);
            isSend = true;
            break;
        default:
            return;
    }

    LNN_LOGI(LNN_BUILDER, "bt state change. netCapability=%{public}d, isSend=%{public}d",
        netCapability, isSend);
    if (LnnSetLocalNumInfo(NUM_KEY_NET_CAP, (int32_t)netCapability) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "set cap to local ledger fail");
        return;
    }
    if (!isSend) {
        return;
    }
    SendNetCapabilityToRemote(netCapability, 1 << (uint32_t)DISCOVERY_TYPE_WIFI);
    return;
}

static bool IsSupportApCoexist(const char *coexistCap)
{
    cJSON *coexistObj = cJSON_ParseWithLength(coexistCap, strlen(coexistCap) + 1);
    LNN_CHECK_AND_RETURN_RET_LOGE(coexistObj, false, LNN_BUILDER, "create json object failed");

    if (!cJSON_IsArray(coexistObj)) {
        cJSON_Delete(coexistObj);
        LNN_LOGE(LNN_BUILDER, "coexistObj is not a array");
        return false;
    }

    for (int i = 0; i < cJSON_GetArraySize(coexistObj); i++) {
        cJSON *subItems = cJSON_GetArrayItem(coexistObj, i);
        if (!cJSON_IsArray(subItems)) {
            LNN_LOGE(LNN_BUILDER, "item is not array, i=%{public}d", i);
            continue;
        }

        bool apCap = false;
        bool p2pCap = false;
        for (int j = 0; j < cJSON_GetArraySize(subItems); j++) {
            cJSON *subItem = cJSON_GetArrayItem(subItems, j);
            char interface[IF_NAME_LEN] = {0};
            if (!GetJsonObjectStringItem(subItem, "IF", interface, sizeof(interface))) {
                LNN_LOGE(LNN_BUILDER, "get interface failed");
                continue;
            }

            enum WifiDirectApiRole mode = WIFI_DIRECT_API_ROLE_NONE;
            if (!GetJsonObjectInt32Item(subItem, "MODE", (int32_t *)&mode)) {
                LNN_LOGE(LNN_BUILDER, "interface get mode failed. interface=%{public}s", interface);
                continue;
            }

            LNN_LOGI(LNN_BUILDER, "interface=%{public}s, mode=%{public}d", interface, mode);
            if ((mode & WIFI_DIRECT_API_ROLE_AP)) {
                apCap = true;
            } else if ((mode & WIFI_DIRECT_API_ROLE_GC) || (mode & WIFI_DIRECT_API_ROLE_GO)) {
                p2pCap = true;
            }
            if (apCap && p2pCap) {
                cJSON_Delete(coexistObj);
                return true;
            }
        }
    }

    cJSON_Delete(coexistObj);
    return false;
}

static void InitWifiDirectCapability(void)
{
    g_isWifiDirectSupported = SoftBusHasWifiDirectCapability();
    char *coexistCap = SoftBusGetWifiInterfaceCoexistCap();
    LNN_CHECK_AND_RETURN_LOGE(coexistCap, LNN_INIT, "coexistCap is null");
    LNN_LOGI(LNN_BUILDER, "coexistCap=%{public}s", coexistCap);
    g_isApCoexistSupported = IsSupportApCoexist(coexistCap);
    SoftBusFree(coexistCap);
    LNN_LOGI(LNN_BUILDER, "g_isWifiDirectSupported=%{public}d, g_isApCoexistSupported=%{public}d",
        g_isWifiDirectSupported, g_isApCoexistSupported);
}

int32_t LnnInitNetworkInfo(void)
{
    InitWifiDirectCapability();
    if (LnnRegisterEventHandler(LNN_EVENT_BT_STATE_CHANGED, BtStateChangeEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "network info register bt state change fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_WIFI_STATE_CHANGED, WifiStateEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_BUILDER, "network info register wifi state change fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegSyncInfoHandler(LNN_INFO_TYPE_CAPABILITY, OnReceiveCapaSyncInfoMsg) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    LNN_LOGE(LNN_BUILDER, "lnn init network info sync done");
    return SOFTBUS_OK;
}

void LnnDeinitNetworkInfo(void)
{
    (void)LnnUnregSyncInfoHandler(LNN_INFO_TYPE_CAPABILITY, OnReceiveCapaSyncInfoMsg);
}
