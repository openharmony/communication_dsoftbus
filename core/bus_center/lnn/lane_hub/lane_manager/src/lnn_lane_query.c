/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lnn_lane_query.h"

#include <securec.h>
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_lane_link.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"
#include "softbus_wifi_api_adapter.h"
#include "wifi_direct_manager.h"

#define QOS_MIN_BANDWIDTH (384 * 1024)
#define QOS_P2P_ONLY_BANDWIDTH (160 * 1024 * 1024)

typedef struct {
    bool available;
    int32_t (*QueryLink)(const char *networkId);
} LinkState;

static void GetFileLaneLink(LaneLinkType *linkList, uint32_t *listNum, bool isHighBand)
{
    linkList[(*listNum)++] = LANE_HML;
    linkList[(*listNum)++] = LANE_WLAN_5G;
    linkList[(*listNum)++] = LANE_WLAN_2P4G;
    linkList[(*listNum)++] = LANE_P2P;
    if (!isHighBand) {
        linkList[(*listNum)++] = LANE_BR;
    }
}

static void GetStreamLaneLink(LaneLinkType *linkList, uint32_t *listNum, bool isHighBand)
{
    linkList[(*listNum)++] = LANE_HML;
    linkList[(*listNum)++] = LANE_WLAN_5G;
    linkList[(*listNum)++] = LANE_WLAN_2P4G;
    linkList[(*listNum)++] = LANE_P2P;
}

static void GetMsgLaneLink(LaneLinkType *linkList, uint32_t *listNum, bool isHighBand)
{
    linkList[(*listNum)++] = LANE_HML;
    linkList[(*listNum)++] = LANE_WLAN_5G;
    linkList[(*listNum)++] = LANE_WLAN_2P4G;
    linkList[(*listNum)++] = LANE_P2P;
    if (!isHighBand) {
        linkList[(*listNum)++] = LANE_BLE;
        linkList[(*listNum)++] = LANE_BR;
    }
}

static void GetBytesLaneLink(LaneLinkType *linkList, uint32_t *listNum, bool isHighBand)
{
    linkList[(*listNum)++] = LANE_HML;
    linkList[(*listNum)++] = LANE_WLAN_5G;
    linkList[(*listNum)++] = LANE_WLAN_2P4G;
    linkList[(*listNum)++] = LANE_P2P;
    if (!isHighBand) {
        linkList[(*listNum)++] = LANE_BLE;
        linkList[(*listNum)++] = LANE_BR;
    }
}

static int32_t GetLaneResource(LaneTransType transType, LaneLinkType *optLink, uint32_t *linkNum,
    bool isHighBand)
{
    LaneLinkType defaultLink[LANE_LINK_TYPE_BUTT];
    (void)memset_s(defaultLink, sizeof(defaultLink), -1, sizeof(defaultLink));
    uint32_t optLinkMaxNum = *linkNum;
    uint32_t index = 0;
    switch (transType) {
        case LANE_T_MSG:
            GetMsgLaneLink(defaultLink, &index, isHighBand);
            break;
        case LANE_T_BYTE:
            GetBytesLaneLink(defaultLink, &index, isHighBand);
            break;
        case LANE_T_FILE:
            GetFileLaneLink(defaultLink, &index, isHighBand);
            break;
        case LANE_T_RAW_STREAM:
        case LANE_T_COMMON_VIDEO:
        case LANE_T_COMMON_VOICE:
            GetStreamLaneLink(defaultLink, &index, isHighBand);
            break;
        default:
            LNN_LOGE(LNN_LANE, "lane type is not supported, transType=%{public}d", transType);
            return SOFTBUS_INVALID_PARAM;
    }
    *linkNum = 0;
    if (memcpy_s(optLink, optLinkMaxNum * sizeof(LaneLinkType), defaultLink, sizeof(defaultLink)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy default linkList to optinal fail");
        return SOFTBUS_MEM_ERR;
    }
    *linkNum = index;
    return SOFTBUS_OK;
}

static bool GetNetCap(const char *networkId, uint32_t *local, uint32_t *remote)
{
    int32_t ret = LnnGetLocalNumU32Info(NUM_KEY_NET_CAP, local);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "LnnGetLocalNumInfo err, ret=%{public}d, local=%{public}u", ret, *local);
        return false;
    }
    ret = LnnGetRemoteNumU32Info(networkId, NUM_KEY_NET_CAP, remote);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "LnnGetRemoteNumInfo err, ret=%{public}d, remote=%{public}u", ret, *remote);
        return false;
    }
    return true;
}

static int32_t BrLinkState(const char *networkId)
{
    uint32_t local;
    uint32_t remote;
    if (!GetNetCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "GetNetCap error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (!(local & (1 << BIT_BR))) {
        LNN_LOGE(LNN_LANE, "local bluetooth close, local=%{public}u", local);
        return SOFTBUS_BLUETOOTH_OFF;
    }
    if (!(remote & (1 << BIT_BR))) {
        LNN_LOGE(LNN_LANE, "remote bluetooth close, remote=%{public}u", remote);
        return SOFTBUS_BLUETOOTH_OFF;
    }
    LNN_LOGI(LNN_LANE, "br link ok, local=%{public}u, remote=%{public}u", local, remote);
    return SOFTBUS_OK;
}

static int32_t BleLinkState(const char *networkId)
{
    uint32_t local;
    uint32_t remote;
    if (!GetNetCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "GetNetCap error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (!(local & (1 << BIT_BLE))) {
        LNN_LOGE(LNN_LANE, "local bluetooth close, local=%{public}u", local);
        return SOFTBUS_BLUETOOTH_OFF;
    }
    if (!(remote & (1 << BIT_BLE))) {
        LNN_LOGE(LNN_LANE, "remote bluetooth close, remote=%{public}u", remote);
        return SOFTBUS_BLUETOOTH_OFF;
    }
    LNN_LOGI(LNN_LANE, "ble link ok, local=%{public}u, remote=%{public}u", local, remote);
    return SOFTBUS_OK;
}

static int32_t WlanLinkState(const char *networkId)
{
    if (!SoftBusIsWifiActive()) {
        return SOFTBUS_WIFI_OFF;
    }
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &node) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote node info fail");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (!LnnHasDiscoveryType(&node, DISCOVERY_TYPE_WIFI) && !LnnHasDiscoveryType(&node, DISCOVERY_TYPE_LSA)) {
        LNN_LOGE(LNN_LANE, "peer node not wifi online");
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    uint32_t local;
    uint32_t remote;
    if (!GetNetCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "GetNetCap error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (!(local & (1 << BIT_WIFI))) {
        LNN_LOGE(LNN_LANE, "local wifi close, local=%{public}u", local);
        return SOFTBUS_WIFI_DISCONNECT;
    }
    if (!(remote & (1 << BIT_WIFI))) {
        LNN_LOGE(LNN_LANE, "remote wifi close, remote=%{public}u", remote);
        return SOFTBUS_WIFI_DISCONNECT;
    }
    LNN_LOGI(LNN_LANE, "wifi link ok, local=%{public}u, remote=%{public}u", local, remote);
    return SOFTBUS_OK;
}

static int32_t P2pLinkState(const char *networkId)
{
    struct WifiDirectManager *pManager = GetWifiDirectManager();
    if (pManager == NULL) {
        LNN_LOGE(LNN_LANE, "not support wifi direct");
        return SOFTBUS_P2P_NOT_SUPPORT;
    }
    SoftBusWifiDetailState wifiState = SoftBusGetWifiState();
    if (wifiState == SOFTBUS_WIFI_STATE_INACTIVE || wifiState == SOFTBUS_WIFI_STATE_DEACTIVATING) {
        return SOFTBUS_WIFI_OFF;
    }
    uint32_t local;
    uint32_t remote;
    if (!GetNetCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "GetNetCap error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (((local & (1 << BIT_WIFI_P2P)) == 0) || ((remote & (1 << BIT_WIFI_P2P)) == 0)) {
        LNN_LOGE(LNN_LANE, "p2p capa disable, local=%{public}u, remote=%{public}u", local, remote);
        return SOFTBUS_P2P_NOT_SUPPORT;
    }
    int32_t ret = pManager->prejudgeAvailability(networkId, WIFI_DIRECT_LINK_TYPE_P2P);
    if (ret == V1_ERROR_GC_CONNECTED_TO_ANOTHER_DEVICE) {
        return SOFTBUS_P2P_ROLE_CONFLICT;
    }
    return ret;
}

static int32_t HmlLinkState(const char *networkId)
{
    struct WifiDirectManager *pManager = GetWifiDirectManager();
    if (pManager == NULL) {
        LNN_LOGE(LNN_LANE, "not support wifi direct");
        return SOFTBUS_HML_NOT_SUPPORT;
    }
    SoftBusWifiDetailState wifiState = SoftBusGetWifiState();
    if (wifiState == SOFTBUS_WIFI_STATE_INACTIVE || wifiState == SOFTBUS_WIFI_STATE_DEACTIVATING) {
        return SOFTBUS_WIFI_OFF;
    }
    uint64_t feature = LnnGetFeatureCapabilty();
    if (!IsFeatureSupport(feature, BIT_WIFI_DIRECT_TLV_NEGOTIATION)) {
        LNN_LOGE(LNN_LANE, "local feature not supported");
        return SOFTBUS_HML_NOT_SUPPORT;
    }
    bool result = false;
    if (LnnGetRemoteBoolInfo(networkId, BOOL_KEY_TLV_NEGOTIATION, &result) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote feature failed");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (!result) {
        LNN_LOGE(LNN_LANE, "remote feature not supported");
        return SOFTBUS_HML_NOT_SUPPORT;
    }
    int32_t ret = pManager->prejudgeAvailability(networkId, WIFI_DIRECT_LINK_TYPE_HML);
    if (ret == ERROR_LOCAL_THREE_VAP_CONFLICT) {
        return SOFTBUS_HML_THREE_VAP_CONFLIC;
    }
    return ret;
}

static LinkState g_linkState[LANE_LINK_TYPE_BUTT] = {
    [LANE_BR] = {true,   BrLinkState},
    [LANE_BLE] = { true,   BleLinkState},
    [LANE_WLAN_2P4G] = { true,   WlanLinkState},
    [LANE_WLAN_5G] = { true,   WlanLinkState},
    [LANE_P2P] = { true,   P2pLinkState},
    [LANE_HML] = { true,   HmlLinkState},
};

static int32_t IsValidLaneLink(const char *networkId, LaneLinkType linkType)
{
    if ((linkType < 0) || (linkType >= LANE_LINK_TYPE_BUTT)) {
        LNN_LOGE(LNN_LANE, "invalid linkType=%{public}d", linkType);
        return SOFTBUS_INVALID_PARAM;
    }
    if (!g_linkState[linkType].available) {
        LNN_LOGE(LNN_LANE, "invalid QueryLink, linkType=%{public}d", linkType);
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_linkState[linkType].QueryLink == NULL) {
        LNN_LOGE(LNN_LANE, "invalid QueryLink, linkType=%{public}d", linkType);
        return SOFTBUS_INVALID_PARAM;
    }
    return g_linkState[linkType].QueryLink(networkId);
}

static bool isHighRequire(const QosInfo *qosInfo, bool *isHighBand)
{
    if (qosInfo->minBW > QOS_MIN_BANDWIDTH) {
        *isHighBand = true;
        return true;
    } else {
        *isHighBand = false;
        return true;
    }
    return false;
}

static int32_t QueryByRequireLink(const LaneQueryInfo *queryInfo, const QosInfo *qosInfo)
{
    if (qosInfo->minBW == QOS_P2P_ONLY_BANDWIDTH) {
        return IsValidLaneLink(queryInfo->networkId, LANE_P2P);
    }
    bool isHighBand = false;
    if (!isHighRequire(qosInfo, &isHighBand)) {
        LNN_LOGE(LNN_LANE, "set param failed");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneLinkType optLink[LANE_LINK_TYPE_BUTT];
    (void)memset_s(optLink, sizeof(optLink), 0, sizeof(optLink));
    uint32_t linkNum = LANE_LINK_TYPE_BUTT;
    int32_t ret = GetLaneResource(queryInfo->transType, optLink, &linkNum, isHighBand);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get defaultLinkList fail");
        return ret;
    }
    for (uint32_t i = 0; i < linkNum; i++) {
        ret = IsValidLaneLink(queryInfo->networkId, optLink[i]);
        if (ret == SOFTBUS_OK) {
            LNN_LOGI(LNN_LANE, "high require get enable Link, linktype=%{public}d", optLink[i]);
            return ret;
        }
    }
    return ret;
}

static int32_t QueryByDefaultLink(const LaneQueryInfo *queryInfo)
{
    LaneLinkType optLink[LANE_LINK_TYPE_BUTT];
    (void)memset_s(optLink, sizeof(optLink), 0, sizeof(optLink));
    uint32_t linkNum = LANE_LINK_TYPE_BUTT;
    int32_t ret = GetLaneResource(queryInfo->transType, optLink, &linkNum, false);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get defaultLinkList fail");
        return ret;
    }
    for (uint32_t i = 0; i < linkNum; i++) {
        ret = IsValidLaneLink(queryInfo->networkId, optLink[i]);
        if (ret == SOFTBUS_OK) {
            LNN_LOGI(LNN_LANE, "default get enable Link, linktype=%{public}d", optLink[i]);
            return ret;
        }
    }
    return ret;
}

int32_t QueryLaneResource(const LaneQueryInfo *queryInfo, const QosInfo *qosInfo)
{
    if (queryInfo == NULL || qosInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (qosInfo->minBW > 0) {
        LNN_LOGI(LNN_LANE, "Query lane by prefer linklist, transType=%{public}d, minBW=%{public}d",
            queryInfo->transType, qosInfo->minBW);
        return QueryByRequireLink(queryInfo, qosInfo);
    } else {
        LNN_LOGI(LNN_LANE, "Query lane by default linklist, transType=%{public}d", queryInfo->transType);
        return QueryByDefaultLink(queryInfo);
    }
}