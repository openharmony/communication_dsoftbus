/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_local_net_ledger.h"
#include "lnn_sync_info_manager.h"
#include "lnn_net_capability.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_wifi_api_adapter.h"
#include "softbus_json_utils.h"

#define MSG_LEN 10
#define BITS 8
#define BITLEN 4

static uint32_t ConvertMsgToCapability(uint32_t *capability, const uint8_t *msg, int32_t len)
{
    if (capability == NULL || msg == NULL || len < BITS) {
        return SOFTBUS_ERR;
    }
    for (uint32_t i = 0; i < BITLEN; i++) {
        *capability = *capability | (*(msg + i) << BITS*i);
    }
    return SOFTBUS_OK;
}
static void OnReceiveCapaSyncInfoMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "Recv capability info, type:%d, len: %d", type, len);
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
    if (ConvertMsgToCapability(&capability, (const uint8_t *)msg, len) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "convert msg to capability fail");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "capability:%d", capability);
    // update ledger
    if (LnnSetDLConnCapability(networkId, capability)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "update conn capability fail.");
        return;
    }
}

static uint8_t *ConvertCapabilityToMsg(uint32_t localCapability)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "convert capability to msg enter");
    uint8_t *arr = SoftBusCalloc(MSG_LEN);
    if (arr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "convert capability to msg calloc msg fail");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "online device discovery type not match select link");
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get all online node info fail.");
        SoftBusFree(msg);
        return;
    }
    if (infoNum == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "online device num is 0, not need to network info");
        SoftBusFree(msg);
        return;
    }
    for (int32_t i = 0; i< infoNum; i++) {
        NodeInfo *nodeInfo = LnnGetNodeInfoById(netInfo[i].networkId, CATEGORY_NETWORK_ID);
        if (nodeInfo == NULL) {
            continue;
        }
        if (IsNeedToSend(nodeInfo, type)) {
            int32_t ret = LnnSendSyncInfoMsg(LNN_INFO_TYPE_CAPABILITY, netInfo[i].networkId, msg, MSG_LEN, NULL);
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "sync network info ret = %d to %s.",
             ret, netInfo[i].deviceName);
        }
    }
    SoftBusFree(netInfo);
    SoftBusFree(msg);
}

static void WifiStateProcess(uint32_t netCapability, bool isSend)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "wifi state change netCapability= %d, isSend = %d",
            netCapability, isSend);
    if (LnnSetLocalNumInfo(NUM_KEY_NET_CAP, netCapability) != SOFTBUS_OK) {
        return;
    }
    if (!isSend) {
        return;
    }
    uint32_t type = (1 << (uint32_t)DISCOVERY_TYPE_BLE) | (1 << (uint32_t)DISCOVERY_TYPE_BR);
    SendNetCapabilityToRemote(netCapability, type);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "WifiStateEventHandler exit");
    return;
}

static void WifiStateEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_WIFI_STATE_CHANGED) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LNN_EVENT_WIFI_STATE_CHANGED get invalid param");
        return;
    }
    const LnnMonitorWlanStateChangedEvent *event = (const LnnMonitorWlanStateChangedEvent *)info;
    SoftBusWifiState wifiState = (SoftBusWifiState)event->status;
    uint32_t netCapability = 0;
    if (LnnGetLocalNumInfo(NUM_KEY_NET_CAP, (int32_t *)&netCapability) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "wifi state handler get capability fail from local.");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "WifiStateEventHandler WifiState = %d", wifiState);
    bool isSend = false;
    switch (wifiState) {
        case SOFTBUS_WIFI_OBTAINING_IPADDR:
            (void)LnnSetNetCapability(&netCapability, BIT_WIFI);
            (void)LnnSetNetCapability(&netCapability, BIT_WIFI_5G);
            (void)LnnSetNetCapability(&netCapability, BIT_WIFI_24G);
            break;
        case SOFTBUS_WIFI_ENABLED:
            (void)LnnClearNetCapability(&netCapability, BIT_WIFI);
            (void)LnnClearNetCapability(&netCapability, BIT_WIFI_24G);
            (void)LnnClearNetCapability(&netCapability, BIT_WIFI_5G);
            (void)LnnSetNetCapability(&netCapability, BIT_WIFI_P2P);
            isSend = true;
            break;
        case SOFTBUS_WIFI_CONNECTED:
            (void)LnnSetNetCapability(&netCapability, BIT_WIFI);
            (void)LnnSetNetCapability(&netCapability, BIT_WIFI_5G);
            (void)LnnSetNetCapability(&netCapability, BIT_WIFI_24G);
            break;
        case SOFTBUS_WIFI_DISCONNECTED:
            (void)LnnClearNetCapability(&netCapability, BIT_WIFI);
            (void)LnnClearNetCapability(&netCapability, BIT_WIFI_24G);
            (void)LnnClearNetCapability(&netCapability, BIT_WIFI_5G);
            isSend = false;
            break;
        case SOFTBUS_WIFI_DISABLED:
            (void)LnnClearNetCapability(&netCapability, BIT_WIFI);
            (void)LnnClearNetCapability(&netCapability, BIT_WIFI_24G);
            (void)LnnClearNetCapability(&netCapability, BIT_WIFI_5G);
            isSend = true;
            break;
        default:
            break;
    }
    WifiStateProcess(netCapability, isSend);
    return;
}

static void BtStateChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_BT_STATE_CHANGED) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB bt state change evt handler get invalid param");
        return;
    }
    uint32_t netCapability = 0;
    if (LnnGetLocalNumInfo(NUM_KEY_NET_CAP, (int32_t *)&netCapability) != SOFTBUS_OK) {
        return;
    }
    const LnnMonitorBtStateChangedEvent *event = (const LnnMonitorBtStateChangedEvent *)info;
    SoftBusBtState btState = (SoftBusBtState)event->status;
    bool isSend = false;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "bt state change btState = %d", btState);
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

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "bt state change netCapability= %d, isSend = %d",
            netCapability, isSend);
    if (LnnSetLocalNumInfo(NUM_KEY_NET_CAP, netCapability) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "set cap to local ledger fail");
        return;
    }
    if (!isSend) {
        return;
    }
    SendNetCapabilityToRemote(netCapability, 1 << (uint32_t)DISCOVERY_TYPE_WIFI);
    return;
}

int32_t LnnInitNetworkInfo(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lnn init network info sync enter");
    if (LnnRegisterEventHandler(LNN_EVENT_BT_STATE_CHANGED, BtStateChangeEventHandler) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "network info register bt state change fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_WIFI_STATE_CHANGED, WifiStateEventHandler) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "network info register wifi state change fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegSyncInfoHandler(LNN_INFO_TYPE_CAPABILITY, OnReceiveCapaSyncInfoMsg) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lnn init network info sync exit");
    return SOFTBUS_OK;
}

void LnnDeinitNetworkInfo(void)
{
    (void)LnnUnregSyncInfoHandler(LNN_INFO_TYPE_CAPABILITY, OnReceiveCapaSyncInfoMsg);
}