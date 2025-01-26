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
#include "lnn_lane_link.h"
#include "lnn_lane_score.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_net_capability.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hisysevt_bus_center.h"
#include "softbus_network_utils.h"
#include "softbus_utils.h"
#include "softbus_wifi_api_adapter.h"
#include "trans_event.h"

#define LNN_LINK_DEFAULT_SCORE 60    /* Indicates that scoring is not supported */
#define LNN_ONLINETIME_OUT     10000 /*BLE connection reuse time*/

#define LOW_BW                  (384 * 1024)
#define MID_BW                  (30 * 1024 * 1024)
#define HIGH_BW                 (160 * 1024 * 1024)

typedef enum {
    LANE_DATA_MSG = 0,
    LANE_DATA_BYTES,
    LANE_DATA_FILE,
    LANE_DATA_STREAM,
    LANE_DATA_BUTT,
} LaneDataType;

int32_t GetWlanLinkedFrequency(void)
{
    LnnWlanLinkedInfo info;
    int32_t ret = LnnGetWlanLinkedInfo(&info);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get linked info fail, reason=%{public}d", ret);
        return ret;
    }
    LNN_LOGI(LNN_LANE, "wlan linked frequency=%{public}d", info.frequency);
    return info.frequency;
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

static int32_t NodeStateCheck(const char *networkId)
{
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &node) != SOFTBUS_OK) {
        char *anonyNetworkId = NULL;
        Anonymize(networkId, &anonyNetworkId);
        LNN_LOGE(LNN_LANE, "get remote node info fail, networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (!LnnHasDiscoveryType(&node, DISCOVERY_TYPE_WIFI) && !LnnHasDiscoveryType(&node, DISCOVERY_TYPE_LSA)) {
        char *anonyNetworkId = NULL;
        Anonymize(networkId, &anonyNetworkId);
        LNN_LOGE(LNN_LANE, "wlan not online, anonyNetworkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_LANE_WIFI_NOT_ONLINE;
    }
    return SOFTBUS_OK;
}

static int32_t Wlan2P4GCapCheck(const char *networkId)
{
    int32_t ret = NodeStateCheck(networkId);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    SoftBusBand band = SoftBusGetLinkBand();
    if (band != BAND_24G && band != BAND_UNKNOWN) {
        char *anonyNetworkId = NULL;
        Anonymize(networkId, &anonyNetworkId);
        LNN_LOGE(LNN_LANE, "band isn't 2.4G or unknown, networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_LANE_WIFI_BAND_ERR;
    }
    uint32_t local;
    uint32_t remote;
    if (!GetNetCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "GetNetCap error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (((local & (1 << BIT_WIFI_24G)) || (local & (1 << BIT_ETH)) || (local & (1 << BIT_WIFI_5G))) &&
        ((remote & (1 << BIT_WIFI_24G)) || (remote & (1 << BIT_ETH)) ||
        (remote & (1 << BIT_WIFI_5G)) || (local & (1 << BIT_WIFI_5G)))) {
        return SOFTBUS_OK;
    }
    LNN_LOGE(LNN_LANE, "2.4G capa disable, local=%{public}u, remote=%{public}u", local, remote);
    return ((local & (1 << BIT_WIFI_24G)) || (local & (1 << BIT_ETH)) || (local & (1 << BIT_WIFI_5G))) ?
        SOFTBUS_LANE_REMOTE_NO_WIFI_CAP : SOFTBUS_LANE_LOCAL_NO_WIFI_CAP;
}

static int32_t Wlan5GCapCheck(const char *networkId)
{
    int32_t ret = NodeStateCheck(networkId);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    SoftBusBand band = SoftBusGetLinkBand();
    if (band != BAND_5G && band != BAND_UNKNOWN) {
        char *anonyNetworkId = NULL;
        Anonymize(networkId, &anonyNetworkId);
        LNN_LOGE(LNN_LANE, "band isn't 5G or unknown, networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_LANE_WIFI_BAND_ERR;
    }
    uint32_t local;
    uint32_t remote;
    if (!GetNetCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "GetNetCap error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (((local & (1 << BIT_WIFI_5G)) || (local & (1 << BIT_ETH)) || (local & (1 << BIT_WIFI_24G))) &&
        ((remote & (1 << BIT_WIFI_5G)) || (remote & (1 << BIT_ETH)) ||
        (remote & (1 << BIT_WIFI_24G)) || (local & (1 << BIT_WIFI_24G)))) {
        return SOFTBUS_OK;
    }
    LNN_LOGE(LNN_LANE, "5G capa disable, local=%{public}u, remote=%{public}u", local, remote);
    return ((local & (1 << BIT_WIFI_5G)) || (local & (1 << BIT_ETH)) || (local & (1 << BIT_WIFI_24G))) ?
        SOFTBUS_LANE_REMOTE_NO_WIFI_CAP : SOFTBUS_LANE_LOCAL_NO_WIFI_CAP;
}

static int32_t BrCapCheck(const char *networkId)
{
    uint32_t local;
    uint32_t remote;
    if (!GetNetCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "GetNetCap error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if ((local & (1 << BIT_BR)) && (remote & (1 << BIT_BR))) {
        return SOFTBUS_OK;
    }
    LNN_LOGE(LNN_LANE, "BR capa disable, local=%{public}u, remote=%{public}u", local, remote);
    return (local & (1 << BIT_BR)) ? SOFTBUS_LANE_REMOTE_NO_BR_CAP : SOFTBUS_LANE_LOCAL_NO_BR_CAP;
}

static int32_t P2pCapCheck(const char *networkId)
{
    uint32_t local;
    uint32_t remote;
    if (!GetNetCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "GetNetCap error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if ((local & (1 << BIT_WIFI_P2P)) == 0) {
        SoftBusWifiDetailState wifiState = SoftBusGetWifiState();
        if (wifiState == SOFTBUS_WIFI_STATE_INACTIVE || wifiState == SOFTBUS_WIFI_STATE_DEACTIVATING) {
            LNN_LOGE(LNN_LANE, "p2p capa disable, local=%{public}u, remote=%{public}u", local, remote);
            return SOFTBUS_LANE_LOCAL_NO_WIFI_DIRECT_CAP;
        } else {
            (void)LnnSetNetCapability(&local, BIT_WIFI_P2P);
            (void)LnnSetLocalNumU32Info(NUM_KEY_NET_CAP, local);
        }
    }
    if ((remote & (1 << BIT_WIFI_P2P)) == 0) {
        LNN_LOGE(LNN_LANE, "p2p capa disable, local=%{public}u, remote=%{public}u", local, remote);
        return SOFTBUS_LANE_REMOTE_NO_WIFI_DIRECT_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t HmlCapCheck(const char *networkId)
{
    int32_t ret = P2pCapCheck(networkId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "p2p cap check error");
        return ret;
    }
    uint64_t local;
    uint64_t remote;
    if (!GetFeatureCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "get feature cap error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (((local & (1 << BIT_WIFI_DIRECT_TLV_NEGOTIATION)) == 0) ||
        ((remote & (1 << BIT_WIFI_DIRECT_TLV_NEGOTIATION)) == 0)) {
        LNN_LOGE(LNN_LANE, "hml capa disable, local=%{public}" PRIu64 ", remote=%{public}"  PRIu64, local, remote);
        return ((local & (1 << BIT_WIFI_DIRECT_TLV_NEGOTIATION)) == 0) ?
            SOFTBUS_LANE_LOCAL_NO_WIFI_DIRECT_CAP : SOFTBUS_LANE_REMOTE_NO_WIFI_DIRECT_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t P2pReuseCapCheck(const char *networkId)
{
    int32_t ret = P2pCapCheck(networkId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "p2p cap check error");
        return ret;
    }
    uint64_t local;
    uint64_t remote;
    if (!GetFeatureCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "get feature cap error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (((local & (1 << BIT_WIFI_P2P_REUSE)) == 0) || ((remote & (1 << BIT_WIFI_P2P_REUSE)) == 0)) {
        LNN_LOGE(LNN_LANE, "p2p reuse capa disable, local=%{public}" PRIu64 ", remote=%{public}"  PRIu64,
            local, remote);
        return ((local & (1 << BIT_WIFI_P2P_REUSE)) == 0) ?
            SOFTBUS_LANE_LOCAL_NO_WIFI_DIRECT_CAP : SOFTBUS_LANE_REMOTE_NO_WIFI_DIRECT_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t BleCapCheck(const char *networkId)
{
    uint32_t local;
    uint32_t remote;
    if (!GetNetCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "GetNetCap error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (((local & (1 << BIT_BLE)) == 0) || ((remote & (1 << BIT_BLE)) == 0)) {
        LNN_LOGE(LNN_LANE, "ble capa disable, local=%{public}u, remote=%{public}u", local, remote);
        return ((local & (1 << BIT_BLE)) == 0) ? SOFTBUS_LANE_LOCAL_NO_BLE_CAP : SOFTBUS_LANE_REMOTE_NO_BLE_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t BleDirectCapCheck(const char *networkId)
{
    int32_t ret = BleCapCheck(networkId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "ble is not enable");
        return ret;
    }

    uint64_t local;
    uint64_t remote;
    if (!GetFeatureCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "GetFeatureCap error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (((local & (1 << BIT_BLE_DIRECT_CONNECT_CAPABILITY)) == 0) ||
        ((remote & (1 << BIT_BLE_DIRECT_CONNECT_CAPABILITY)) == 0)) {
        LNN_LOGE(LNN_LANE, "ble direct capa disable, local=%{public}" PRIu64 ", remote=%{public}" PRIu64,
            local, remote);
        return ((local & (1 << BIT_BLE_DIRECT_CONNECT_CAPABILITY)) == 0) ?
            SOFTBUS_LANE_LOCAL_NO_BLE_DIRECT_CAP : SOFTBUS_LANE_REMOTE_NO_BLE_DIRECT_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t CocCapCheck(const char *networkId)
{
    int32_t ret = BleCapCheck(networkId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "ble is not enable");
        return ret;
    }
    uint64_t local;
    uint64_t remote;
    if (!GetFeatureCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "GetFeatureCap error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    if (((local & (1 << BIT_COC_CONNECT_CAPABILITY)) == 0) || ((remote & (1 << BIT_COC_CONNECT_CAPABILITY)) == 0)) {
        LNN_LOGE(LNN_LANE, "coc capa disable, local=%{public}" PRIu64 ", remote=%{public}" PRIu64,
            local, remote);
        return ((local & (1 << BIT_COC_CONNECT_CAPABILITY)) == 0) ?
            SOFTBUS_LANE_LOCAL_NO_COC_CAP : SOFTBUS_LANE_REMOTE_NO_COC_CAP;
    }
    return SOFTBUS_OK;
}

static int32_t CocDirectCapCheck(const char *networkId)
{
    int32_t ret = CocCapCheck(networkId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "coc is not enable");
        return ret;
    }
    ret = BleDirectCapCheck(networkId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "ble direct is not enable");
        return ret;
    }
    return SOFTBUS_OK;
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
    int32_t channel = 0;
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
    [LANE_BR] = {true,   BrCapCheck,        GetBrScore      },
    [LANE_BLE] = { true,  BleCapCheck,       GetBleScore     },
    [LANE_P2P] = { true,  P2pCapCheck,       GetP2pScore     },
    [LANE_HML] = { true,  HmlCapCheck,       GetHmlScore     },
    [LANE_WLAN_2P4G] = { true,  Wlan2P4GCapCheck,  GetWlan2P4GScore},
    [LANE_WLAN_5G] = { true,  Wlan5GCapCheck,    GetWlan5GScore  },
    [LANE_ETH] = { false, NULL,              NULL            },
    [LANE_P2P_REUSE] = { true,  P2pReuseCapCheck,  GetP2pScore     },
    [LANE_BLE_DIRECT] = { true,  BleDirectCapCheck, GetBleScore     },
    [LANE_BLE_REUSE] = { false, NULL,              NULL            },
    [LANE_COC] = { true,  CocCapCheck,       GetCocScore     },
    [LANE_COC_DIRECT] = { true,  CocDirectCapCheck, GetCocScore     },
};

LinkAttribute *GetLinkAttrByLinkType(LaneLinkType linkType)
{
    if ((linkType < 0) || (linkType >= LANE_LINK_TYPE_BUTT)) {
        return NULL;
    }
    return &g_linkAttr[linkType];
}

static uint32_t g_laneBandWidth[BW_TYPE_BUTT][LANE_LINK_TYPE_BUTT + 1] = {
    [HIGH_BAND_WIDTH] = {LANE_HML, LANE_P2P, LANE_LINK_TYPE_BUTT},
    [MIDDLE_HIGH_BAND_WIDTH] = {LANE_HML, LANE_WLAN_5G, LANE_LINK_TYPE_BUTT},
    [MIDDLE_LOW_BAND_WIDTH] = {LANE_WLAN_5G, LANE_HML, LANE_WLAN_2P4G, LANE_LINK_TYPE_BUTT},
    [LOW_BAND_WIDTH] = {LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_HML, LANE_LINK_TYPE_BUTT},
};

static uint32_t g_retryLaneList[BW_TYPE_BUTT][LANE_LINK_TYPE_BUTT + 1] = {
    [HIGH_BAND_WIDTH] = {LANE_HML, LANE_P2P, LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_LINK_TYPE_BUTT},
    [MIDDLE_HIGH_BAND_WIDTH] = {LANE_HML, LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_P2P,
        LANE_LINK_TYPE_BUTT},
    [MIDDLE_LOW_BAND_WIDTH] = {LANE_WLAN_5G, LANE_HML, LANE_WLAN_2P4G, LANE_P2P,
        LANE_LINK_TYPE_BUTT},
    [LOW_BAND_WIDTH] = {LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_HML, LANE_BR, LANE_P2P,
        LANE_COC_DIRECT, LANE_BLE, LANE_LINK_TYPE_BUTT},
};

static uint32_t g_defaultLinkList[LANE_DATA_BUTT][LANE_LINK_TYPE_BUTT + 1] = {
    [LANE_DATA_MSG] = {LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_BLE, LANE_BR, LANE_COC_DIRECT, LANE_LINK_TYPE_BUTT},
    [LANE_DATA_BYTES] = {LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_BLE, LANE_BR, LANE_COC_DIRECT, LANE_LINK_TYPE_BUTT},
    [LANE_DATA_FILE] = {LANE_WLAN_5G, LANE_HML, LANE_P2P, LANE_WLAN_2P4G, LANE_BR, LANE_LINK_TYPE_BUTT},
    [LANE_DATA_STREAM] = {LANE_WLAN_5G, LANE_HML, LANE_P2P, LANE_WLAN_2P4G, LANE_LINK_TYPE_BUTT},
};

static uint32_t g_customLinkList[CUSTOM_QOS_BUTT][LANE_LINK_TYPE_BUTT + 1] = {
    [CUSTOM_QOS_MESH] = {LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_BR, LANE_COC_DIRECT, LANE_LINK_TYPE_BUTT},
    [CUSTOM_QOS_DB] = {LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_P2P, LANE_BR, LANE_COC_DIRECT, LANE_LINK_TYPE_BUTT},
    [CUSTOM_QOS_RTT] = {LANE_HML, LANE_P2P, LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_LINK_TYPE_BUTT},
};

static bool IsLinkTypeValid(LaneLinkType type)
{
    if ((type < 0) || (type >= LANE_LINK_TYPE_BUTT)) {
        return false;
    }
    return true;
}

static int32_t CheckLaneCap(const char *networkId, LaneLinkType linkType)
{
    LinkAttribute *linkAttr = GetLinkAttrByLinkType(linkType);
    if ((linkAttr == NULL) || (!linkAttr->available)) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = linkAttr->linkCapCheck(networkId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "link capacity is not support. linkType=%{public}d", linkType);
        return ret;
    }
    return SOFTBUS_OK;
}

static bool IsTransTypeValid(LaneTransType type)
{
    if ((type < 0) || (type >= LANE_T_BUTT)) {
        return false;
    }
    return true;
}

static int32_t CheckLinkWithTransType(LaneTransType transType, LaneLinkType linkType)
{
    bool isStream = (transType == LANE_T_RAW_STREAM || transType == LANE_T_COMMON_VIDEO ||
                    transType == LANE_T_COMMON_VOICE);
    bool isBt = (linkType == LANE_BR || linkType == LANE_BLE || linkType == LANE_BLE_DIRECT ||
                linkType == LANE_BLE_REUSE || linkType == LANE_COC || linkType == LANE_COC_DIRECT);
    if (isStream && isBt) {
        LNN_LOGE(LNN_LANE, "Bt not support stream datatype, transType=%{public}d, link=%{public}d",
            transType, linkType);
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

int32_t LaneCheckLinkValid(const char *networkId, LaneLinkType linkType, LaneTransType transType)
{
    if (networkId == NULL || !IsLinkTypeValid(linkType)) {
        LNN_LOGE(LNN_LANE, "invalid param, linkType=%{public}d", linkType);
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = SOFTBUS_OK;
    if (IsTransTypeValid(transType)) {
        ret = CheckLinkWithTransType(transType, linkType);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "check link with transType err, ret=%{public}d", ret);
            return ret;
        }
    }
    ret = CheckLaneCap(networkId, linkType);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "checkLaneCap err, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
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
        if ((LaneCheckLinkValid(networkId, g_laneBandWidth[bandWidthType][i], request->transType) == SOFTBUS_OK)) {
            linkList[(*linksNum)++] = g_laneBandWidth[bandWidthType][i];
            LNN_LOGI(LNN_LANE, "decide optimal linkType=%{public}d", g_laneBandWidth[bandWidthType][i]);
            continue;
        }
    }
    LNN_LOGI(LNN_LANE, "decide optimal links num=%{public}d", *linksNum);
}

static bool IsLaneExist(LaneLinkType *linkList, LaneLinkType linkType)
{
    for (int i = 0; i < LANE_LINK_TYPE_BUTT; i++) {
        if (linkList[i] == linkType) {
            return true;
        }
    }
    return false;
}

static void DecideRetryLinks(const char *networkId, const LaneSelectParam *request,
    LaneLinkType *linkList, uint32_t *linksNum)
{
    uint32_t minBandWidth = request->qosRequire.minBW;
    int32_t bandWidthType = GetBwType(minBandWidth);
    for (uint32_t i = 0; i < (LANE_LINK_TYPE_BUTT + 1); i++) {
        if (g_retryLaneList[bandWidthType][i] == LANE_LINK_TYPE_BUTT) {
            break;
        }
        if (!IsLaneExist(linkList, g_retryLaneList[bandWidthType][i]) &&
            (LaneCheckLinkValid(networkId, g_retryLaneList[bandWidthType][i], request->transType) == SOFTBUS_OK)) {
            linkList[(*linksNum)++] = g_retryLaneList[bandWidthType][i];
            LNN_LOGI(LNN_LANE, "decide retry linkType=%{public}d", g_retryLaneList[bandWidthType][i]);
        }
    }
}

static bool IsExistWatchDevice(const char *networkId)
{
    int32_t localDevTypeId = TYPE_UNKNOW_ID;
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &localDevTypeId);
    if (ret == SOFTBUS_OK && localDevTypeId == TYPE_WATCH_ID) {
        LNN_LOGI(LNN_LANE, "local is watch");
        return true;
    }
    int32_t remoteDevTypeId = TYPE_UNKNOW_ID;
    ret = LnnGetRemoteNumInfo(networkId, NUM_KEY_DEV_TYPE_ID, &remoteDevTypeId);
    if (ret == SOFTBUS_OK && remoteDevTypeId == TYPE_WATCH_ID) {
        LNN_LOGI(LNN_LANE, "remote is watch");
        return true;
    }
    return false;
}

static bool IsSupportWifiDirect(const char *networkId)
{
    if (IsExistWatchDevice(networkId)) {
        return false;
    }
    uint64_t localFeature = 0;
    uint64_t remoteFeature = 0;
    bool isFound = GetFeatureCap(networkId, &localFeature, &remoteFeature);
    if (!isFound) {
        LNN_LOGE(LNN_LANE, "getFeature fail");
        return false;
    }
    if (((localFeature & (1 << BIT_BLE_TRIGGER_CONNECTION)) == 0) ||
        ((remoteFeature & (1 << BIT_BLE_TRIGGER_CONNECTION)) == 0)) {
        LNN_LOGE(LNN_LANE, "local=%{public}" PRIu64 ", remote=%{public}" PRIu64, localFeature, remoteFeature);
        return false;
    }
    return true;
}

static void GenerateLinkList(LaneLinkType *linkListSrc, uint32_t numsSrc,
    LaneLinkType *linkList, uint32_t *linksNum)
{
    uint32_t size = sizeof(LaneLinkType) * LANE_LINK_TYPE_BUTT;
    (void)memset_s(linkList, size, -1, size);
    *linksNum = numsSrc;
    for (uint32_t i = 0; i < *linksNum; i++) {
        linkList[i] = linkListSrc[i];
    }
}

static void FilterLinksWithContinuous(LaneLinkType *linkList, uint32_t *linksNum)
{
    uint32_t num = 0;
    LaneLinkType tmpList[LANE_LINK_TYPE_BUTT] = { 0 };
    for (uint32_t i = 0; i < *linksNum; i++) {
        if (linkList[i] == LANE_P2P || linkList[i] == LANE_HML) {
            LNN_LOGI(LNN_LANE, "filter linkType=%{public}d", linkList[i]);
            continue;
        }
        tmpList[num++] = linkList[i];
    }
    if (num == *linksNum) {
        return;
    }
    GenerateLinkList(tmpList, num, linkList, linksNum);
}

static void FilterLinksWithWifiDirect(LaneLinkType *linkList, uint32_t *linksNum)
{
    uint32_t num = 0;
    LaneLinkType tmpList[LANE_LINK_TYPE_BUTT] = { 0 };
    for (uint32_t i = 0; i < *linksNum; i++) {
        if (linkList[i] == LANE_HML) {
            LNN_LOGI(LNN_LANE, "filter linkType=%{public}d", linkList[i]);
            continue;
        }
        tmpList[num++] = linkList[i];
    }
    if (num == *linksNum) {
        return;
    }
    GenerateLinkList(tmpList, num, linkList, linksNum);
}

static bool IsRemoteLegacy(const char *networkId)
{
    int32_t osType = 0;
    if (LnnGetOsTypeByNetworkId(networkId, &osType) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote osType fail");
        return false;
    }
    if (osType == OH_OS_TYPE) {
        return false;
    }
    return true;
}

static void DecideLinksWithLegacy(const char *networkId, const LaneSelectParam *request,
    LaneLinkType *linkList, uint32_t *linksNum)
{
    if (*linksNum <= 0 || *linksNum > LANE_LINK_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "link num exceed lisk list");
        return;
    }
    if (!IsRemoteLegacy(networkId)) {
        LNN_LOGE(LNN_LANE, "valid os, no need filter links");
        return;
    }
    if (GetBwType(request->qosRequire.minBW) == LOW_BAND_WIDTH) {
        if (request->qosRequire.continuousTask) {
            FilterLinksWithContinuous(linkList, linksNum);
        } else if (!IsSupportWifiDirect(networkId)) {
            FilterLinksWithWifiDirect(linkList, linksNum);
        }
    }
}

static void UpdateHmlPriority(const char *peerNetWorkId, const LaneSelectParam *request,
    LaneLinkType *linkList, uint32_t *linksNum)
{
    if (*linksNum > LANE_LINK_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "link num exceed lisk list");
        return;
    }
    char peerUdid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(peerNetWorkId, STRING_KEY_DEV_UDID, peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return;
    }
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (FindLaneResourceByLinkType(peerUdid, LANE_HML, &resourceItem) != SOFTBUS_OK ||
        (LaneCheckLinkValid(peerNetWorkId, LANE_HML, request->transType) != SOFTBUS_OK)) {
        LNN_LOGE(LNN_LANE, "hml not support reuse");
        return;
    }
    LNN_LOGI(LNN_LANE, "hml exist reuse laneId=%{public}" PRIu64 ", update priority", resourceItem.laneId);
    LaneLinkType tmpList[LANE_LINK_TYPE_BUTT] = {0};
    uint32_t num = 0;
    tmpList[num++] = LANE_HML;
    for (uint32_t i = 0; i < *linksNum; i++) {
        if (linkList[i] != LANE_HML) {
            tmpList[num++] = linkList[i];
        }
    }
    uint32_t size = sizeof(LaneLinkType) * LANE_LINK_TYPE_BUTT;
    (void)memset_s(linkList, size, -1, size);
    *linksNum = num;
    for (uint32_t i = 0; i < *linksNum; i++) {
        linkList[i] = tmpList[i];
    }
}

static void DelHasAllocedLink(uint64_t allocedLaneId, LaneLinkType *linkList, uint32_t *linksNum)
{
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (FindLaneResourceByLaneId(allocedLaneId, &resourceItem) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "invalid allocedLaneId=%{public}" PRIu64 "", allocedLaneId);
        return;
    }
    uint32_t num = 0;
    LaneLinkType tmpList[LANE_LINK_TYPE_BUTT] = {0};
    if (*linksNum > LANE_LINK_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "link num exceed lisk list");
        return;
    }
    for (uint32_t i = 0; i < *linksNum; i++) {
        if (linkList[i] != resourceItem.link.type) {
            tmpList[num++] = linkList[i];
        }
    }
    uint32_t size = sizeof(LaneLinkType) * LANE_LINK_TYPE_BUTT;
    (void)memset_s(linkList, size, -1, size);
    *linksNum = num;
    for (uint32_t i = 0; i < *linksNum; i++) {
        linkList[i] = tmpList[i];
    }
}

int32_t FinalDecideLinkType(const char *networkId, LaneLinkType *linkList,
    uint32_t listNum, LanePreferredLinkList *recommendList)
{
    if (networkId == NULL || linkList == NULL || recommendList == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (listNum >= LANE_LINK_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "linkList size exceed limit, size=%{public}d", listNum);
        return SOFTBUS_INVALID_PARAM;
    }
    bool isFilterP2p = IsSupportWifiDirect(networkId);
    uint32_t availableLinkNums = 0;
    for (uint32_t i = 0; i < listNum; i++) {
        if (isFilterP2p && linkList[i] == LANE_P2P) {
            LNN_LOGI(LNN_LANE, "p2pLink is filtered");
            continue;
        }
        recommendList->linkType[availableLinkNums++] = linkList[i];
    }
    recommendList->linkTypeNum = availableLinkNums;
    if (availableLinkNums == 0) {
        LNN_LOGE(LNN_LANE, "not available link");
        return SOFTBUS_LANE_NO_AVAILABLE_LINK;
    }
    return SOFTBUS_OK;
}

static bool IsSupportP2pReuse(const char *networkId)
{
    char peerUdid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return false;
    }
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (FindLaneResourceByLinkType(peerUdid, LANE_P2P, &resourceItem) != SOFTBUS_OK) {
        LNN_LOGD(LNN_LANE, "p2p not support reuse");
        return false;
    }
    return true;
}

static int32_t GetErrCodeOfRequest(const char *networkId, const LaneSelectParam *request)
{
    SoftBusWifiDetailState wifiState = SoftBusGetWifiState();
    if (wifiState == SOFTBUS_WIFI_STATE_INACTIVE || wifiState == SOFTBUS_WIFI_STATE_DEACTIVATING) {
        return SOFTBUS_LANE_WIFI_OFF;
    }
    int32_t bandWidthType = GetBwType(request->qosRequire.minBW);
    return LaneCheckLinkValid(networkId, g_laneBandWidth[bandWidthType][0], request->transType);
}

static void GetDefaultLinkByDataType(LaneDataType dataType, LaneLinkType *linkList, uint32_t *listNum)
{
    for (uint32_t i = 0; i < (LANE_LINK_TYPE_BUTT + 1); i++) {
        if (g_defaultLinkList[dataType][i] == LANE_LINK_TYPE_BUTT) {
            break;
        }
        linkList[(*listNum)++] = g_defaultLinkList[dataType][i];
    }
}

static void GetCustomLinkByType(CustomQos customQos, LaneLinkType *linkList, uint32_t *listNum)
{
    for (uint32_t i = 0; i < (LANE_LINK_TYPE_BUTT + 1); i++) {
        if (g_customLinkList[customQos][i] == LANE_LINK_TYPE_BUTT) {
            break;
        }
        linkList[(*listNum)++] = g_customLinkList[customQos][i];
    }
}

static void SelectDbLinks(const char *networkId, LaneLinkType *resList, uint32_t *resNum)
{
    LaneLinkType optionalLink[LANE_LINK_TYPE_BUTT];
    (void)memset_s(optionalLink, sizeof(optionalLink), -1, sizeof(optionalLink));
    uint32_t optLinkNum = 0;
    GetCustomLinkByType(CUSTOM_QOS_DB, optionalLink, &optLinkNum);
    *resNum = 0;
    for (uint32_t i = 0; i < optLinkNum; i++) {
        if (optionalLink[i] == LANE_P2P && (!IsRemoteLegacy(networkId) || !IsSupportP2pReuse(networkId))) {
            continue;
        }
        resList[(*resNum)++] = optionalLink[i];
    }
}

static void SelectRttLinks(const char *networkId, LaneLinkType *resList, uint32_t *resNum)
{
    LaneLinkType optionalLink[LANE_LINK_TYPE_BUTT];
    (void)memset_s(optionalLink, sizeof(optionalLink), 0, sizeof(optionalLink));
    uint32_t optLinkNum = 0;
    GetCustomLinkByType(CUSTOM_QOS_RTT, optionalLink, &optLinkNum);
    LanePreferredLinkList recommendList = {0};
    int32_t ret = FinalDecideLinkType(networkId, optionalLink, optLinkNum, &recommendList);
    if (recommendList.linkTypeNum == 0) {
        LNN_LOGE(LNN_LANE, "there is none linkResource can be used, reason=%{public}d", ret);
        return;
    }
    *resNum = 0;
    for (uint32_t i = 0; i < recommendList.linkTypeNum; i++) {
        resList[(*resNum)++] = recommendList.linkType[i];
    }
}

int32_t DecideDefaultLink(const char *networkId, LaneTransType transType, LaneLinkType *resList, uint32_t *resNum)
{
    if (networkId == NULL || !IsTransTypeValid(transType) || resList == NULL || resNum == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param, transType=%{public}d", transType);
        return SOFTBUS_INVALID_PARAM;
    }
    LaneLinkType defaultLink[LANE_LINK_TYPE_BUTT];
    (void)memset_s(defaultLink, sizeof(defaultLink), -1, sizeof(defaultLink));
    uint32_t index = 0;
    switch (transType) {
        case LANE_T_MSG:
            GetDefaultLinkByDataType(LANE_DATA_MSG, defaultLink, &index);
            break;
        case LANE_T_BYTE:
            GetDefaultLinkByDataType(LANE_DATA_BYTES, defaultLink, &index);
            break;
        case LANE_T_FILE:
            GetDefaultLinkByDataType(LANE_DATA_FILE, defaultLink, &index);
            break;
        case LANE_T_RAW_STREAM:
        case LANE_T_COMMON_VIDEO:
        case LANE_T_COMMON_VOICE:
            GetDefaultLinkByDataType(LANE_DATA_STREAM, defaultLink, &index);
            break;
        default:
            LNN_LOGE(LNN_LANE, "lane type is not supported. type=%{public}d", transType);
            return SOFTBUS_INVALID_PARAM;
    }
    *resNum = 0;
    for (uint32_t i = 0; i < index; i++) {
        if (LaneCheckLinkValid(networkId, defaultLink[i], LANE_T_BUTT) != SOFTBUS_OK) {
            continue;
        }
        resList[(*resNum)++] = defaultLink[i];
    }
    if (*resNum == 0) {
        LNN_LOGE(LNN_LANE, "there is none default linkResource can be used");
        return GetErrCodeOfLink(networkId, defaultLink[0]);
    }
    return SOFTBUS_OK;
}

int32_t DecideCustomLink(const char *networkId, CustomQos customQos, LaneLinkType *resList, uint32_t *resNum)
{
    if (networkId == NULL || resList == NULL || resNum == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneLinkType customLink[LANE_LINK_TYPE_BUTT];
    (void)memset_s(customLink, sizeof(customLink), -1, sizeof(customLink));
    uint32_t index = 0;
    switch (customQos) {
        case CUSTOM_QOS_MESH:
            GetCustomLinkByType(CUSTOM_QOS_MESH, customLink, &index);
            break;
        case CUSTOM_QOS_DB:
            SelectDbLinks(networkId, customLink, &index);
            break;
        case CUSTOM_QOS_RTT:
            SelectRttLinks(networkId, customLink, &index);
            break;
        default:
            LNN_LOGE(LNN_LANE, "custom type is not supported. type=%{public}d", customQos);
            return SOFTBUS_INVALID_PARAM;
    }
    *resNum = 0;
    for (uint32_t i = 0; i < index; i++) {
        if (LaneCheckLinkValid(networkId, customLink[i], LANE_T_BUTT) != SOFTBUS_OK) {
            continue;
        }
        resList[(*resNum)++] = customLink[i];
    }
    if (*resNum == 0) {
        LNN_LOGE(LNN_LANE, "there is none custom linkResource can be used");
        return GetErrCodeOfLink(networkId, customLink[0]);
    }
    return SOFTBUS_OK;
}

static void DecideLinksWithDevice(const char *networkId, const LaneSelectParam *request,
    LaneLinkType *linkList, uint32_t *linksNum)
{
    if (*linksNum <= 0 || *linksNum > LANE_LINK_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "link num exceed lisk list");
        return;
    }
    if (!IsExistWatchDevice(networkId)) {
        return;
    }
    uint32_t num = 0;
    LaneLinkType tmpList[LANE_LINK_TYPE_BUTT] = {0};
    bool needFilter = false;
    for (uint32_t i = 0; i < *linksNum; i++) {
        if (linkList[i] == LANE_HML ||
            (request->qosRequire.continuousTask && (linkList[i] == LANE_P2P || linkList[i] == LANE_COC_DIRECT))) {
            needFilter = true;
            LNN_LOGI(LNN_LANE, "filter linkType=%{public}d", linkList[i]);
            continue;
        }
        tmpList[num++] = linkList[i];
    }
    if (!needFilter) {
        return;
    }
    uint32_t size = sizeof(LaneLinkType) * LANE_LINK_TYPE_BUTT;
    (void)memset_s(linkList, size, -1, size);
    *linksNum = num;
    for (uint32_t i = 0; i < *linksNum; i++) {
        linkList[i] = tmpList[i];
    }
}

int32_t DecideAvailableLane(const char *networkId, const LaneSelectParam *request,
    LanePreferredLinkList *recommendList)
{
    if (request == NULL || recommendList == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    LaneLinkType linkList[LANE_LINK_TYPE_BUTT];
    (void)memset_s(linkList, sizeof(linkList), -1, sizeof(linkList));
    uint32_t linksNum = 0;
    DecideOptimalLinks(networkId, request, linkList, &linksNum);
    DecideRetryLinks(networkId, request, linkList, &linksNum);
    DecideLinksWithDevice(networkId, request, linkList, &linksNum);
    DecideLinksWithLegacy(networkId, request, linkList, &linksNum);
    UpdateHmlPriority(networkId, request, linkList, &linksNum);
    if (request->allocedLaneId != INVALID_LANE_ID) {
        DelHasAllocedLink(request->allocedLaneId, linkList, &linksNum);
    }
    int32_t ret = FinalDecideLinkType(networkId, linkList, linksNum, recommendList);
    if (recommendList->linkTypeNum == 0) {
        LNN_LOGE(LNN_LANE, "there is none linkResource can be used");
        return GetErrCodeOfRequest(networkId, request);
    }
    return ret;
}

int32_t DecideReuseLane(const char *networkId, const LaneSelectParam *request,
    LanePreferredLinkList *recommendList)
{
    if (networkId == NULL || request == NULL || recommendList == NULL ||
        recommendList->linkTypeNum != 0) {
        LNN_LOGE(LNN_LANE, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!IsExistWatchDevice(networkId)) {
        LNN_LOGE(LNN_LANE, "reuse best effort only support watch");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneLinkType reuseLink = LANE_BR;
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    char peerUdid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    int32_t ret = FindLaneResourceByLinkType(peerUdid, reuseLink, &resourceItem);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "linkType=%{public}d not support reuse", reuseLink);
        return ret;
    }
    ret = LaneCheckLinkValid(networkId, reuseLink, request->transType);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "linkType=%{public}d no capability", reuseLink);
        return ret;
    }
    LNN_LOGI(LNN_LANE, "linkType=%{public}d exist reuse laneId=%{public}" PRIu64 "",
        reuseLink, resourceItem.laneId);
    recommendList->linkType[(recommendList->linkTypeNum)++] = reuseLink;
    return SOFTBUS_OK;
}
