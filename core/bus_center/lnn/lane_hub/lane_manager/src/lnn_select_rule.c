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

#include "anonymizer.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_score.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_net_capability.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_hisysevt_bus_center.h"
#include "softbus_network_utils.h"
#include "softbus_utils.h"
#include "softbus_wifi_api_adapter.h"
#include "trans_event.h"


#define LNN_LINK_DEFAULT_SCORE 60    /* Indicates that scoring is not supported */
#define LNN_ONLINETIME_OUT     10000 /*BLE connection reuse time*/

#define LOW_BW                  (384 * 1024)
#define MID_BW                  (30 * 1024 * 1024)
#define HIGH_BW                 (160 * 1024 * 1024)
#define COC_DIRECT_LATENCY      1200
#define BR_LATENCY              2500
#define WLAN_LATENCY            800
#define P2P_LATENCY             1600
#define BLE_LATENCY             1500
#define HML_LATENCY             1500
#define BR_REUSE_LATENCY        1000


int32_t GetWlanLinkedFrequency(void)
{
    LnnWlanLinkedInfo info;
    int32_t ret = LnnGetWlanLinkedInfo(&info);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get linked info fail, reason=%{public}d", ret);
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_LANE, "wlan linked frequency=%{public}d", info.frequency);
    return info.frequency;
}

static bool GetNetCap(const char *networkId, int32_t *local, int32_t *remote)
{
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_NET_CAP, local);
    if (ret != SOFTBUS_OK || *local < 0) {
        LNN_LOGE(LNN_LANE, "LnnGetLocalNumInfo err, ret=%{public}d, local=%{public}d", ret, *local);
        return false;
    }
    ret = LnnGetRemoteNumInfo(networkId, NUM_KEY_NET_CAP, remote);
    if (ret != SOFTBUS_OK || *remote < 0) {
        LNN_LOGE(LNN_LANE, "LnnGetRemoteNumInfo err, ret=%{public}d, remote=%{public}d", ret, *remote);
        return false;
    }
    return true;
}

static bool GetFeatureCap(const char *networkId, uint64_t *local, uint64_t *remote)
{
    int32_t ret = LnnGetLocalNumU64Info(NUM_KEY_FEATURE_CAPA, local);
    if (ret != SOFTBUS_OK || *local < 0) {
        LNN_LOGE(LNN_LANE, "LnnGetLocalNumInfo err, ret=%{public}d, local=%{public}" PRIu64, ret, *local);
        return false;
    }
    ret = LnnGetRemoteNumU64Info(networkId, NUM_KEY_FEATURE_CAPA, remote);
    if (ret != SOFTBUS_OK || *remote < 0) {
        LNN_LOGE(LNN_LANE, "LnnGetRemoteNumInfo err, ret=%{public}d, remote=%{public}" PRIu64, ret, *remote);
        return false;
    }
    return true;
}

static bool IsEnableWlan2P4G(const char *networkId)
{
    SoftBusBand band = SoftBusGetLinkBand();
    if (band != BAND_24G && band != BAND_UNKNOWN) {
        LNN_LOGE(LNN_LANE, "band isn't 2.4G or unknown");
        return false;
    }
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &node) != SOFTBUS_OK) {
        char *anonyNetworkId = NULL;
        Anonymize(networkId, &anonyNetworkId);
        LNN_LOGE(LNN_LANE, "get remote node info fail, networkId=%{public}s", anonyNetworkId);
        AnonymizeFree(anonyNetworkId);
        return false;
    }
    if (!LnnHasDiscoveryType(&node, DISCOVERY_TYPE_WIFI) && !LnnHasDiscoveryType(&node, DISCOVERY_TYPE_LSA)) {
        char *anonyNetworkId = NULL;
        Anonymize(networkId, &anonyNetworkId);
        LNN_LOGE(LNN_LANE, "anonyNetworkId=%{public}s, DISCOVERY_TYPE_WIFI=%{public}d, DISCOVERY_TYPE_LSA=%{public}d",
            anonyNetworkId, DISCOVERY_TYPE_WIFI, DISCOVERY_TYPE_LSA);
        AnonymizeFree(anonyNetworkId);
        return false;
    }
    int32_t local, remote;
    if (!GetNetCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "GetNetCap error");
        return false;
    }
    if (((local & (1 << BIT_WIFI_24G)) || (local & (1 << BIT_ETH)) || (local & (1 << BIT_WIFI_5G))) &&
        ((remote & (1 << BIT_WIFI_24G)) || (remote & (1 << BIT_ETH)) || (local & (1 << BIT_WIFI_5G)))) {
        return true;
    }
    LNN_LOGE(LNN_LANE, "2.4G capa disable, local=%{public}d, remote=%{public}d", local, remote);
    return false;
}

static bool IsEnableWlan5G(const char *networkId)
{
    SoftBusBand band = SoftBusGetLinkBand();
    if (band != BAND_5G && band != BAND_UNKNOWN) {
        LNN_LOGE(LNN_LANE, "band isn't 5G or unknown");
        return false;
    }
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &node) != SOFTBUS_OK) {
        char *anonyNetworkId = NULL;
        Anonymize(networkId, &anonyNetworkId);
        LNN_LOGE(LNN_LANE, "get remote node info fail, networkId=%{public}s", anonyNetworkId);
        AnonymizeFree(anonyNetworkId);
        return false;
    }
    if (!LnnHasDiscoveryType(&node, DISCOVERY_TYPE_WIFI) && !LnnHasDiscoveryType(&node, DISCOVERY_TYPE_LSA)) {
        char *anonyNetworkId = NULL;
        Anonymize(networkId, &anonyNetworkId);
        LNN_LOGE(LNN_LANE, "anonyNetworkId=%{public}s, DISCOVERY_TYPE_WIFI=%{public}d, DISCOVERY_TYPE_LSA=%{public}d",
            anonyNetworkId, DISCOVERY_TYPE_WIFI, DISCOVERY_TYPE_LSA);
        AnonymizeFree(anonyNetworkId);
        return false;
    }
    int32_t local, remote;
    if (!GetNetCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "GetNetCap error");
        return false;
    }
    if (((local & (1 << BIT_WIFI_5G)) || (local & (1 << BIT_ETH)) || (local & (1 << BIT_WIFI_24G))) &&
        ((remote & (1 << BIT_WIFI_5G)) || (remote & (1 << BIT_ETH)) || (local & (1 << BIT_WIFI_24G)))) {
        return true;
    }
    LNN_LOGE(LNN_LANE, "5G capa disable, local=%{public}d, remote=%{public}d", local, remote);
    return false;
}

static bool IsEnableBr(const char *networkId)
{
    int32_t local, remote;
    if (!GetNetCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "GetNetCap error");
        return false;
    }
    if ((local & (1 << BIT_BR)) && (remote & (1 << BIT_BR))) {
        return true;
    }
    LNN_LOGE(LNN_LANE, "BR capa disable, local=%{public}d, remote=%{public}d", local, remote);
    return false;
}

static bool IsEnableP2p(const char *networkId)
{
    int32_t local, remote;
    if (!GetNetCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "GetNetCap error");
        return false;
    }
    if (((local & (1 << BIT_WIFI_P2P)) == 0) || ((remote & (1 << BIT_WIFI_P2P)) == 0)) {
        LNN_LOGE(LNN_LANE, "p2p capa disable, local=%{public}d, remote=%{public}d", local, remote);
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
        LNN_LOGE(LNN_LANE, "GetNetCap error");
        return false;
    }
    if (((local & (1 << BIT_WIFI_P2P_REUSE)) == 0) || ((remote & (1 << BIT_WIFI_P2P_REUSE)) == 0)) {
        LNN_LOGE(LNN_LANE, "p2p reuse capa disable, local=%{public}" PRIu64 ", remote=%{public}"  PRIu64,
            local, remote);
        return false;
    }
    return true;
}

static bool IsEnableBle(const char *networkId)
{
    int32_t local, remote;
    if (!GetNetCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "GetNetCap error");
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
        LNN_LOGE(LNN_LANE, "ble is not enable");
        return false;
    }

    uint64_t local, remote;
    if (!GetFeatureCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "GetFeatureCap error");
        return false;
    }
    if (((local & (1 << BIT_BLE_DIRECT_CONNECT_CAPABILITY)) == 0) ||
        ((remote & (1 << BIT_BLE_DIRECT_CONNECT_CAPABILITY)) == 0)) {
        LNN_LOGE(LNN_LANE, "ble direct capa disable, local=%{public}" PRIu64 ", remote=%{public}" PRIu64,
            local, remote);
        return false;
    }
    return true;
}

static bool IsEnableCoc(const char *networkId)
{
    if (!IsEnableBle(networkId)) {
        LNN_LOGE(LNN_LANE, "ble is not enable");
        return false;
    }
    uint64_t local = 0, remote = 0;
    if (!GetFeatureCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "GetFeatureCap error");
        return false;
    }
    if (((local & (1 << BIT_COC_CONNECT_CAPABILITY)) == 0) || ((remote & (1 << BIT_COC_CONNECT_CAPABILITY)) == 0)) {
        LNN_LOGE(LNN_LANE, "coc capa disable, local=%{public}" PRIu64 ", remote=%{public}" PRIu64,
            local, remote);
        return false;
    }
    return true;
}

static bool IsEnableCocDirect(const char *networkId)
{
    if (!IsEnableCoc(networkId)) {
        LNN_LOGE(LNN_LANE, "coc is not enable");
        return false;
    }
    if (!IsEnableBleDirect(networkId)) {
        LNN_LOGE(LNN_LANE, "ble direct is not enable");
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
        LNN_LOGE(LNN_LANE, "get curr channel fail");
        return LNN_LINK_DEFAULT_SCORE;
    }
    int32_t score = LnnGetCurrChannelScore(channel);
    LNN_LOGI(LNN_LANE, "current channel=%{public}d, score=%{public}d", channel, score);
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

static int32_t g_laneLatency[LANE_LINK_TYPE_BUTT] = {
    [LANE_BR] = BR_LATENCY,
    [LANE_P2P] = P2P_LATENCY,
    [LANE_HML] = HML_LATENCY,
    [LANE_WLAN_2P4G] = WLAN_LATENCY,
    [LANE_WLAN_5G] = WLAN_LATENCY,
    [LANE_COC_DIRECT] = COC_DIRECT_LATENCY,
    [LANE_BLE] = BLE_LATENCY,
};

static uint32_t g_laneBandWidth[BW_TYPE_BUTT][LANE_LINK_TYPE_BUTT + 1] = {
    [HIGH_BAND_WIDTH] = {LANE_HML, LANE_P2P, LANE_LINK_TYPE_BUTT},
    [MIDDLE_HIGH_BAND_WIDTH] = {LANE_HML, LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_LINK_TYPE_BUTT},
    [MIDDLE_LOW_BAND_WIDTH] = {LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_HML, LANE_LINK_TYPE_BUTT},
    [LOW_BAND_WIDTH] = {LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_HML, LANE_COC_DIRECT, LANE_LINK_TYPE_BUTT},
};

static uint32_t g_retryLaneList[BW_TYPE_BUTT][LANE_LINK_TYPE_BUTT + 1] = {
    [HIGH_BAND_WIDTH] = {LANE_HML, LANE_P2P, LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_LINK_TYPE_BUTT},
    [MIDDLE_HIGH_BAND_WIDTH] = {LANE_HML, LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_P2P,
        LANE_LINK_TYPE_BUTT},
    [MIDDLE_LOW_BAND_WIDTH] = {LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_HML, LANE_P2P,
        LANE_LINK_TYPE_BUTT},
    [LOW_BAND_WIDTH] = {LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_HML, LANE_P2P, LANE_COC_DIRECT,
        LANE_BR, LANE_BLE, LANE_LINK_TYPE_BUTT},
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
        LNN_LOGE(LNN_LANE, "link capacity is not support. linkType=%{public}d", linkType);
        return false;
    }
    bool isStream = (transType == LANE_T_RAW_STREAM || transType == LANE_T_COMMON_VIDEO ||
                    transType == LANE_T_COMMON_VOICE);
    bool isBt = (linkType == LANE_BR || linkType == LANE_BLE || linkType == LANE_BLE_DIRECT ||
                linkType == LANE_BLE_REUSE || linkType == LANE_COC || linkType == LANE_COC_DIRECT);
    if (isStream && isBt) {
        LNN_LOGE(LNN_LANE, "Bt not support stream datatype, link=%{public}d", linkType);
        return false;
    }
    return true;
}

static bool IsLaneFillMinLatency(uint32_t minLaneLatency, LaneLinkType linkType)
{
    if (minLaneLatency >= (uint32_t)g_laneLatency[linkType]) {
        return true;
    }
    return false;
}

static int32_t GetBwType(uint32_t bandWidth)
{
    int32_t bandWidthType;
    if (bandWidth >= HIGH_BW) {
        bandWidthType = HIGH_BAND_WIDTH;
    } else if (bandWidth > MID_BW) {
        bandWidthType = MIDDLE_HIGH_BAND_WIDTH;
    } else if (bandWidth > LOW_BW) {
        bandWidthType = MIDDLE_LOW_BAND_WIDTH;
    } else {
        bandWidthType = LOW_BAND_WIDTH;
    }
    return bandWidthType;
}

static void DecideOptimalLinks(const char *networkId, const LaneSelectParam *request,
    LaneLinkType *linkList, uint32_t *linksNum)
{
    uint32_t minBandWidth = request->qosRequire.minBW;
    uint32_t minLaneLatency = request->qosRequire.minLaneLatency;
    if (minLaneLatency == 0) {
        LNN_LOGI(LNN_LANE, "minLaneLatency is zero, cancel decide optimal link");
        return;
    }
    int32_t bandWidthType = GetBwType(minBandWidth);
    LNN_LOGI(LNN_LANE,
        "decide optimal link, bandWidthType=%{public}d, minLaneLatency=%{public}d", bandWidthType, minLaneLatency);
    for (uint32_t i = 0; i < (LANE_LINK_TYPE_BUTT + 1); i++) {
        if (g_laneBandWidth[bandWidthType][i] == LANE_LINK_TYPE_BUTT) {
            break;
        }
        if (IsValidLane(networkId, g_laneBandWidth[bandWidthType][i], request->transType) &&
            IsLaneFillMinLatency(minLaneLatency, g_laneBandWidth[bandWidthType][i])) {
            linkList[(*linksNum)++] = g_laneBandWidth[bandWidthType][i];
            LNN_LOGI(LNN_LANE, "decide optimal linkType=%{public}d", g_laneBandWidth[bandWidthType][i]);
            continue;
        }
    }
    LNN_LOGI(LNN_LANE, "decide optimal links num=%{public}d", *linksNum);
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

static void GetAllLinksWithBw(const char *networkId, int32_t bandWidthType, const LaneSelectParam *request,
    LaneLinkType *linkList, uint32_t *linksNum)
{
    for (uint32_t i = 0; i < (LANE_LINK_TYPE_BUTT + 1); i++) {
        if (g_retryLaneList[bandWidthType][i] == LANE_LINK_TYPE_BUTT) {
            break;
        }
        if (IsValidLane(networkId, g_retryLaneList[bandWidthType][i], request->transType) &&
            !isLaneExist(linkList, g_retryLaneList[bandWidthType][i])) {
            linkList[(*linksNum)++] = g_retryLaneList[bandWidthType][i];
            LNN_LOGI(LNN_LANE, "decide retry linkType=%{public}d", g_retryLaneList[bandWidthType][i]);
        }
    }
}

static void DecideRetryLinks(const char *networkId, const LaneSelectParam *request,
    LaneLinkType *linkList, uint32_t *linksNum)
{
    uint32_t minBandWidth = request->qosRequire.minBW;
    uint32_t maxLaneLatency = request->qosRequire.maxLaneLatency;
    int32_t bandWidthType = GetBwType(minBandWidth);
    if (maxLaneLatency == 0) {
        LNN_LOGI(LNN_LANE, "maxLaneLatency is zero, get all retry link");
        GetAllLinksWithBw(networkId, bandWidthType, request, linkList, linksNum);
        return;
    }
    int32_t retryTime;
    if (*linksNum == 0) {
        LNN_LOGI(LNN_LANE, "optimal links num=0");
        retryTime = maxLaneLatency;
    } else {
        retryTime = maxLaneLatency - request->qosRequire.minLaneLatency;
    }
    LNN_LOGI(LNN_LANE,
        "decide retry link, band width type=%{public}d, retrytime=%{public}d", bandWidthType, retryTime);
    for (uint32_t i = 0; i < (LANE_LINK_TYPE_BUTT + 1); i++) {
        if (g_retryLaneList[bandWidthType][i] == LANE_LINK_TYPE_BUTT) {
            break;
        }
        if (retryTime - g_laneLatency[g_retryLaneList[bandWidthType][i]] >= 0 &&
            IsValidLane(networkId, g_retryLaneList[bandWidthType][i], request->transType) &&
            !isLaneExist(linkList, g_retryLaneList[bandWidthType][i])) {
            retryTime -= g_laneLatency[g_retryLaneList[bandWidthType][i]];
            linkList[(*linksNum)++] = g_retryLaneList[bandWidthType][i];
            LNN_LOGI(LNN_LANE, "decide retry linkType=%{public}d", g_retryLaneList[bandWidthType][i]);
        }
    }
    if (bandWidthType == LOW_BAND_WIDTH &&
        IsValidLane(networkId, LANE_BR, request->transType) && !isLaneExist(linkList, LANE_BR)) {
        linkList[(*linksNum)++] = LANE_BR;
        LNN_LOGI(LNN_LANE, "decide retry linkType=%{public}d", LANE_BR);
    }
}

static bool IsSupportBrReuse(const char *peerNetWorkId)
{
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    connOpt.type = CONNECT_BR;
    if (LnnGetRemoteStrInfo(peerNetWorkId, STRING_KEY_BT_MAC, connOpt.brOption.brMac, BT_MAC_LEN) != SOFTBUS_OK ||
        connOpt.brOption.brMac[0] == '\0') {
        return false;
    }
    return CheckActiveConnection(&connOpt);
}

static void UpdataLaneLatency(const char *peerNetWorkId)
{
    if (IsSupportBrReuse(peerNetWorkId)) {
        g_laneLatency[LANE_BR] = BR_REUSE_LATENCY;
    } else {
        g_laneLatency[LANE_BR] = BR_LATENCY;
    }
}

int32_t DecideAvailableLane(const char *networkId, const LaneSelectParam *request, LanePreferredLinkList *recommendList)
{
    if (request == NULL || recommendList == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    LaneLinkType linkList[LANE_LINK_TYPE_BUTT];
    (void)memset_s(linkList, sizeof(linkList), -1, sizeof(linkList));
    uint32_t linksNum = 0;
    UpdataLaneLatency(networkId);
    DecideOptimalLinks(networkId, request, linkList, &linksNum);
    DecideRetryLinks(networkId, request, linkList, &linksNum);
    for (uint32_t i = 0; i < linksNum; i++) {
        recommendList->linkType[i] = linkList[i];
    }
    recommendList->linkTypeNum = linksNum;
    if (linksNum == 0) {
        TransAlarmExtra extra = {
            .conflictName = NULL,
            .conflictedName = NULL,
            .occupyedName = NULL,
            .permissionName = NULL,
            .sessionName = NULL,
            .minBw = request->qosRequire.minBW,
            .linkType = request->transType,
        };
        TRANS_ALARM(BANDWIDTH_INSUFFICIANT_ALARM, MANAGE_ALARM_TYPE, extra);
    }
    return SOFTBUS_OK;
}
