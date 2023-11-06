/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "lnn_select_rule.h"

#include <securec.h>

#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_score.h"
#include "lnn_local_net_ledger.h"
#include "lnn_net_capability.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_hisysevt_bus_center.h"
#include "softbus_log.h"
#include "softbus_network_utils.h"
#include "softbus_utils.h"
#include "softbus_wifi_api_adapter.h"


#define LNN_LINK_DEFAULT_SCORE 60    /* Indicates that scoring is not supported */
#define LNN_ONLINETIME_OUT     10000 /*BLE connection reuse time*/

#define LOW_BW                  (500 * 1024)
#define HIGH_BW                 (160 * 1024 * 1024)
#define COC_DIRECT_LATENCY      1000
#define BR_LATENCY              2500
#define WLAN_LATENCY            800
#define P2P_LATENCY             1600
#define HML_LATENCY             1000


int32_t GetWlanLinkedFrequency(void)
{
    LnnWlanLinkedInfo info;
    int32_t ret = LnnGetWlanLinkedInfo(&info);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get linked info fail, reason:%d", ret);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "wlan linked frequency:%d", info.frequency);
    return info.frequency;
}

static bool GetNetCap(const char *networkId, int32_t *local, int32_t *remote)
{
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_NET_CAP, local);
    if (ret != SOFTBUS_OK || *local < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetLocalNumInfo err, ret = %d, local = %d", ret, *local);
        return false;
    }
    ret = LnnGetRemoteNumInfo(networkId, NUM_KEY_NET_CAP, remote);
    if (ret != SOFTBUS_OK || *remote < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LnnGetRemoteNumInfo err, ret = %d, remote = %d", ret, *remote);
        return false;
    }
    return true;
}

static bool GetFeatureCap(const char *networkId, uint64_t *local, uint64_t *remote)
{
    int32_t ret = LnnGetLocalNumU64Info(NUM_KEY_FEATURE_CAPA, local);
    if (ret != SOFTBUS_OK || *local < 0) {
        LLOGE("LnnGetLocalNumInfo err, ret = %d, local = %d", ret, *local);
        return false;
    }
    ret = LnnGetRemoteNumU64Info(networkId, NUM_KEY_FEATURE_CAPA, remote);
    if (ret != SOFTBUS_OK || *remote < 0) {
        LLOGE("LnnGetRemoteNumInfo err, ret = %d, remote = %d", ret, *remote);
        return false;
    }
    return true;
}

static bool IsEnableWlan2P4G(const char *networkId)
{
    SoftBusBand band = SoftBusGetLinkBand();
    if (band != BAND_24G && band != BAND_UNKNOWN) {
        LLOGE("band isn't 2.4G or unknown");
        return false;
    }
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &node) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (!LnnHasDiscoveryType(&node, DISCOVERY_TYPE_WIFI) && !LnnHasDiscoveryType(&node, DISCOVERY_TYPE_LSA)) {
        return SOFTBUS_ERR;
    }
    int32_t local, remote;
    if (!GetNetCap(networkId, &local, &remote)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNetCap error");
        return false;
    }
    if (((local & (1 << BIT_WIFI_24G)) || (local & (1 << BIT_ETH)) || (local & (1 << BIT_WIFI_5G))) &&
        ((remote & (1 << BIT_WIFI_24G)) || (remote & (1 << BIT_ETH)) || (local & (1 << BIT_WIFI_5G)))) {
        return true;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "2.4G capa disable, local:%d, remote:%d", local, remote);
    return false;
}

static bool IsEnableWlan5G(const char *networkId)
{
    SoftBusBand band = SoftBusGetLinkBand();
    if (band != BAND_5G && band != BAND_UNKNOWN) {
        LLOGE("band isn't 5G or unknown");
        return false;
    }
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &node) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (!LnnHasDiscoveryType(&node, DISCOVERY_TYPE_WIFI) && !LnnHasDiscoveryType(&node, DISCOVERY_TYPE_LSA)) {
        return SOFTBUS_ERR;
    }
    int32_t local, remote;
    if (!GetNetCap(networkId, &local, &remote)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNetCap error");
        return false;
    }
    if (((local & (1 << BIT_WIFI_5G)) || (local & (1 << BIT_ETH)) || (local & (1 << BIT_WIFI_24G))) &&
        ((remote & (1 << BIT_WIFI_5G)) || (remote & (1 << BIT_ETH)) || (local & (1 << BIT_WIFI_24G)))) {
        return true;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "5G capa disable, local:%d, remote:%d", local, remote);
    return false;
}

static bool IsEnableBr(const char *networkId)
{
    int32_t local, remote;
    if (!GetNetCap(networkId, &local, &remote)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNetCap error");
        return false;
    }
    if ((local & (1 << BIT_BR)) && (remote & (1 << BIT_BR))) {
        return true;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "BR capa disable, local:%d, remote:%d", local, remote);
    return false;
}

static bool IsEnableP2p(const char *networkId)
{
    int32_t local, remote;
    if (!GetNetCap(networkId, &local, &remote)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNetCap error");
        return false;
    }
    if (((local & (1 << BIT_WIFI_P2P)) == 0) || ((remote & (1 << BIT_WIFI_P2P)) == 0)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "p2p capa disable, local:%d, remote:%d", local, remote);
        return false;
    }
    return true;
}

static bool IsEnableHml(const char *networkId)
{
    if (!IsEnableP2p(networkId)) {
        return false;
    }
    uint64_t local, remote;
    if (!GetFeatureCap(networkId, &local, &remote)) {
        return false;
    }
    if (((local & (1 << BIT_WIFI_DIRECT_TLV_NEGOTIATION)) == 0) ||
        ((remote & (1 << BIT_WIFI_DIRECT_TLV_NEGOTIATION)) == 0)) {
        return false;
    }
    return true;
}

static bool IsEnableP2pReuse(const char *networkId)
{
    if (!IsEnableP2p(networkId)) {
        return false;
    }
    uint64_t local, remote;
    if (!GetFeatureCap(networkId, &local, &remote)) {
        return false;
    }
    if (((local & (1 << BIT_WIFI_P2P_REUSE)) == 0) || ((remote & (1 << BIT_WIFI_P2P_REUSE)) == 0)) {
        return false;
    }
    return true;
}

static bool IsEnableBle(const char *networkId)
{
    int32_t local, remote;
    if (!GetNetCap(networkId, &local, &remote)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNetCap error");
        return false;
    }
    if (((local & (1 << BIT_BLE)) == 0) || ((remote & (1 << BIT_BLE)) == 0)) {
        return false;
    }
    return true;
}

static bool IsEnableBleDirect(const char *networkId)
{
    if (!IsEnableBle(networkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ble is not enable");
        return false;
    }

    uint64_t local, remote;
    if (!GetFeatureCap(networkId, &local, &remote)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetFeatureCap error");
        return false;
    }
    if (((local & (1 << BIT_BLE_DIRECT_CONNECT_CAPABILITY)) == 0) ||
        ((remote & (1 << BIT_BLE_DIRECT_CONNECT_CAPABILITY)) == 0)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ble direct capa disable, local:%" PRIu64 ", remote:%" PRIu64,
            local, remote);
        return false;
    }
    return true;
}

static bool IsEnableCoc(const char *networkId)
{
    if (!IsEnableBle(networkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ble is not enable");
        return false;
    }
    uint64_t local = 0, remote = 0;
    if (!GetFeatureCap(networkId, &local, &remote)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetFeatureCap error");
        return false;
    }
    if (((local & (1 << BIT_COC_CONNECT_CAPABILITY)) == 0) || ((remote & (1 << BIT_COC_CONNECT_CAPABILITY)) == 0)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "coc capa disable, local:%" PRIu64 ", remote:%" PRIu64,
            local, remote);
        return false;
    }
    return true;
}

static bool IsEnableCocDirect(const char *networkId)
{
    if (!IsEnableCoc(networkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "coc is not enable");
        return false;
    }
    if (!IsEnableBleDirect(networkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ble direct is not enable");
        return false;
    }
    return true;
}

static int32_t GetBrScore(const char *networkId, uint32_t expectedBw)
{
    (void)networkId;
    (void)expectedBw;
    return LNN_LINK_DEFAULT_SCORE;
}

static int32_t GetBleScore(const char *networkId, uint32_t expectedBw)
{
    (void)networkId;
    (void)expectedBw;
    return LNN_LINK_DEFAULT_SCORE;
}

static int32_t GetP2pScore(const char *networkId, uint32_t expectedBw)
{
    (void)networkId;
    (void)expectedBw;
    return LNN_LINK_DEFAULT_SCORE;
}

static int32_t GetHmlScore(const char *networkId, uint32_t expectedBw)
{
    (void)networkId;
    (void)expectedBw;
    return LNN_LINK_DEFAULT_SCORE;
}


static int32_t GetLinkedChannelScore(void)
{
    int32_t frequency = GetWlanLinkedFrequency();
    if (frequency <= 0) {
        return LNN_LINK_DEFAULT_SCORE;
    }
    int32_t channel = SoftBusFrequencyToChannel(frequency);
    if (channel < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get curr channel fail");
        return LNN_LINK_DEFAULT_SCORE;
    }
    int32_t score = LnnGetCurrChannelScore(channel);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "current channel:%d, score:%d", channel, score);
    if (score <= 0) {
        score = LNN_LINK_DEFAULT_SCORE;
    }
    return score;
}

static int32_t GetWlan2P4GScore(const char *networkId, uint32_t expectedBw)
{
    (void)networkId;
    (void)expectedBw;
    return GetLinkedChannelScore();
}

static int32_t GetWlan5GScore(const char *networkId, uint32_t expectedBw)
{
    (void)networkId;
    (void)expectedBw;
    return GetLinkedChannelScore();
}

static int32_t GetCocScore(const char *networkId, uint32_t expectedBw)
{
    (void)networkId;
    (void)expectedBw;
    return LNN_LINK_DEFAULT_SCORE;
}

static LinkAttribute g_linkAttr[LANE_LINK_TYPE_BUTT] = {
    [LANE_BR] = {true,   IsEnableBr,        GetBrScore      },
    [LANE_BLE] = { true,  IsEnableBle,       GetBleScore     },
    [LANE_P2P] = { true,  IsEnableP2p,       GetP2pScore     },
    [LANE_HML] = { true,  IsEnableHml,       GetHmlScore     },
    [LANE_WLAN_2P4G] = { true,  IsEnableWlan2P4G,  GetWlan2P4GScore},
    [LANE_WLAN_5G] = { true,  IsEnableWlan5G,    GetWlan5GScore  },
    [LANE_ETH] = { false, NULL,              NULL            },
    [LANE_P2P_REUSE] = { true,  IsEnableP2pReuse,  GetP2pScore     },
    [LANE_BLE_DIRECT] = { true,  IsEnableBleDirect, GetBleScore     },
    [LANE_BLE_REUSE] = { false, NULL,              NULL            },
    [LANE_COC] = { true,  IsEnableCoc,       GetCocScore     },
    [LANE_COC_DIRECT] = { true,  IsEnableCocDirect, GetCocScore     },
};

LinkAttribute *GetLinkAttrByLinkType(LaneLinkType linkType)
{
    if ((linkType < 0) || (linkType >= LANE_LINK_TYPE_BUTT)) {
        return NULL;
    }
    return &g_linkAttr[linkType];
}

static uint32_t g_laneLatency[LANE_LINK_TYPE_BUTT] = {
    [LANE_BR] = BR_LATENCY,
    [LANE_P2P] = P2P_LATENCY,
    [LANE_HML] = HML_LATENCY,
    [LANE_WLAN_2P4G] = WLAN_LATENCY,
    [LANE_WLAN_5G] = WLAN_LATENCY,
    [LANE_COC_DIRECT] = COC_DIRECT_LATENCY,
};

static uint32_t g_laneBandWidth[BW_TYPE_BUTT][LANE_LINK_TYPE_BUTT + 1] = {
    [HIGH_BAND_WIDTH] = {LANE_P2P, LANE_LINK_TYPE_BUTT},
    [MIDDLE_BAND_WIDTH] = {LANE_HML, LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_LINK_TYPE_BUTT},
    [LOW_BAND_WIDTH] = {LANE_HML, LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_COC_DIRECT, LANE_LINK_TYPE_BUTT},
};

static uint32_t g_retryLaneList[BW_TYPE_BUTT][LANE_LINK_TYPE_BUTT + 1] = {
    [HIGH_BAND_WIDTH] = {LANE_P2P, LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_LINK_TYPE_BUTT},
    [MIDDLE_BAND_WIDTH] = {LANE_HML, LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_P2P,
        LANE_BR, LANE_LINK_TYPE_BUTT},
    [LOW_BAND_WIDTH] = {LANE_HML, LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_P2P, LANE_COC_DIRECT,
        LANE_BR, LANE_LINK_TYPE_BUTT},
};

static bool IsLinkTypeValid(LaneLinkType type)
{
    if ((type < 0) || (type >= LANE_LINK_TYPE_BUTT)) {
        return false;
    }
    return true;
}

static bool IsValidLane(const char *networkId, LaneLinkType linkType, LaneTransType transType)
{
    if (!IsLinkTypeValid(linkType)) {
        return false;
    }
    LinkAttribute *linkAttr = GetLinkAttrByLinkType(linkType);
    if ((linkAttr == NULL) || (!linkAttr->available)) {
        return false;
    }
    if (linkAttr->IsEnable(networkId) != true) {
        return false;
    }
    bool isStream = (transType == LANE_T_RAW_STREAM || transType == LANE_T_COMMON_VIDEO ||
                    transType == LANE_T_COMMON_VOICE);
    bool isBt = (linkType == LANE_BR || linkType == LANE_BLE || linkType == LANE_BLE_DIRECT ||
                linkType == LANE_BLE_REUSE || linkType == LANE_COC || linkType == LANE_COC_DIRECT);
    if (isStream && isBt) {
        return false;
    }
    return true;
}

static bool IsLaneFillMinLatency(uint32_t minLaneLatency, LaneLinkType linkType)
{
    if (minLaneLatency >= g_laneLatency[linkType]) {
        return true;
    }
    return false;
}

static void DecideOptimalLinks(const char *networkId, const LaneSelectParam *request,
    LaneLinkType *linkList, uint32_t *linksNum)
{
    uint32_t minBandWidth = request->qosRequire.minBW;
    uint32_t minLaneLatency = request->qosRequire.minLaneLatency;
    if (minBandWidth == 0) {
        minBandWidth = LOW_BW;
    }
    if (minLaneLatency == 0) {
        minLaneLatency = BR_LATENCY;
    }
    int32_t bandWidthType;
    if (minBandWidth >= HIGH_BW) {
        bandWidthType = HIGH_BAND_WIDTH;
    } else if (minBandWidth >= LOW_BW) {
        bandWidthType = MIDDLE_BAND_WIDTH;
    } else {
        bandWidthType = LOW_BAND_WIDTH;
    }
    for (uint32_t i = 0; i < (LANE_LINK_TYPE_BUTT + 1); i++) {
        if (g_laneBandWidth[bandWidthType][i] == LANE_LINK_TYPE_BUTT) {
            break;
        }
        if (IsValidLane(networkId, g_laneBandWidth[bandWidthType][i], request->transType) &&
            IsLaneFillMinLatency(minLaneLatency, g_laneBandWidth[bandWidthType][i])) {
            linkList[(*linksNum)++] = g_laneBandWidth[bandWidthType][i];
            break;
        }
    }
}

static bool isLaneExist(LaneLinkType *linkList, LaneLinkType laneType)
{
    for (int i = 0; i < LANE_LINK_TYPE_BUTT; i++) {
        if (linkList[i] == laneType) {
            return true;
        }
    }
    return false;
}

static void DecideRetryLinks(const char *networkId, const LaneSelectParam *request,
    LaneLinkType *linkList, uint32_t *linksNum)
{
    uint32_t minBandWidth = request->qosRequire.minBW;
    uint32_t maxLaneLatency = request->qosRequire.maxLaneLatency;
    if (maxLaneLatency == 0) {
        maxLaneLatency = (BR_LATENCY + BR_LATENCY + BR_LATENCY + BR_LATENCY);
    }
    int32_t bandWidthType;
    if (minBandWidth >= HIGH_BW) {
        bandWidthType = HIGH_BAND_WIDTH;
    } else if (minBandWidth >= LOW_BW) {
        bandWidthType = MIDDLE_BAND_WIDTH;
    } else {
        bandWidthType = LOW_BAND_WIDTH;
    }
    int32_t retryTime;
    if (linksNum == 0) {
        retryTime = maxLaneLatency;
    } else {
        retryTime = maxLaneLatency - g_laneLatency[linkList[0]];
    }
    for (uint32_t i = 0; i < (LANE_LINK_TYPE_BUTT + 1); i++) {
        if (g_retryLaneList[bandWidthType][i] == LANE_LINK_TYPE_BUTT) {
            break;
        }
        if (IsValidLane(networkId, g_retryLaneList[bandWidthType][i], request->transType) &&
            !isLaneExist(linkList, g_retryLaneList[bandWidthType][i]) &&
            retryTime - g_laneLatency[g_retryLaneList[bandWidthType][i]] >= 0) {
            retryTime -= g_laneLatency[g_retryLaneList[bandWidthType][i]];
            linkList[(*linksNum)++] = g_retryLaneList[bandWidthType][i];
        }
    }
}

int32_t DecideAvailableLane(const char *networkId, const LaneSelectParam *request, LanePreferredLinkList *recommendList)
{
    if (request == NULL || recommendList == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    LaneLinkType linkList[LANE_LINK_TYPE_BUTT] = {0};
    uint32_t linksNum = 0;
    DecideOptimalLinks(networkId, request, linkList, &linksNum);
    DecideRetryLinks(networkId, request, linkList, &linksNum);
    for (uint32_t i = 0; i < linksNum; i++) {
        recommendList->linkType[i] = linkList[i];
    }
    recommendList->linkTypeNum = linksNum;
    return SOFTBUS_OK;
}
