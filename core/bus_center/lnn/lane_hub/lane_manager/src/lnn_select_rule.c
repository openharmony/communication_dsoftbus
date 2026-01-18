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
#include "g_enhance_lnn_func.h"
#include "g_enhance_lnn_func_pack.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_lane_communication_capability.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_link.h"
#include "lnn_lane_link_ledger.h"
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
#include "softbus_init_common.h"
#include "trans_event.h"

#define LNN_LINK_DEFAULT_SCORE 60    /* Indicates that scoring is not supported */
#define LNN_ONLINETIME_OUT     10000 /*BLE connection reuse time*/
#define WIFI_DIRECT_EXT_CAP_VALID_TIME  10000

#define LOW_BW                  (384 * 1024)
#define MID_BW                  (30 * 1024 * 1024)
#define HIGH_BW                 (160 * 1024 * 1024)
#define TRY_BUILD_INTERVAL_TIME (60 * 1000)

typedef enum {
    LANE_DATA_MSG = 0,
    LANE_DATA_BYTES,
    LANE_DATA_FILE,
    LANE_DATA_STREAM,
    LANE_DATA_BUTT,
} LaneDataType;

typedef struct {
    ListNode node;
    char peerUdid[UDID_BUF_LEN];
    bool isP2pAvailable;
    uint64_t effectiveTime;
} WifiDirectExtCap;

static SoftBusList g_wifiDirectExtCapList;

static int32_t WifiDirectExtCapLock(void)
{
    return SoftBusMutexLock(&g_wifiDirectExtCapList.lock);
}

static void WifiDirectExtCapUnlock(void)
{
    (void)SoftBusMutexUnlock(&g_wifiDirectExtCapList.lock);
}

static WifiDirectExtCap* GetValidWifiDirectExtCap(const char *peerUdid)
{
    WifiDirectExtCap *item = NULL;
    WifiDirectExtCap *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_wifiDirectExtCapList.list, WifiDirectExtCap, node) {
        if (strcmp(item->peerUdid, peerUdid) == 0) {
            return item;
        }
    }
    return NULL;
}

static int32_t CreateNewWifiDirectExtCapInfo(const char *peerUdid, bool isP2pAvailable)
{
    WifiDirectExtCap *item = (WifiDirectExtCap *)SoftBusCalloc(sizeof(WifiDirectExtCap));
    if (item == NULL) {
        LNN_LOGE(LNN_LANE, "calloc wifiDirectExtCap item fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strcpy_s(item->peerUdid, sizeof(item->peerUdid), peerUdid) != EOK) {
        LNN_LOGE(LNN_LANE, "copy peerUdid failed");
        SoftBusFree(item);
        return SOFTBUS_STRCPY_ERR;
    }
    item->isP2pAvailable = isP2pAvailable;
    item->effectiveTime = SoftBusGetSysTimeMs();
    if (WifiDirectExtCapLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "wifiDirect extCap lock fail");
        SoftBusFree(item);
        return SOFTBUS_LOCK_ERR;
    }
    ListAdd(&g_wifiDirectExtCapList.list, &item->node);
    g_wifiDirectExtCapList.cnt++;
    WifiDirectExtCapUnlock();
    char *anonyUdid = NULL;
    Anonymize(peerUdid, &anonyUdid);
    LNN_LOGI(LNN_LANE, "create new wifiDirectExtCap info succ, peerUdid=%{public}s, isP2pAvailable=%{public}s",
        AnonymizeWrapper(anonyUdid), isP2pAvailable ? "true" : "false");
    AnonymizeFree(anonyUdid);
    return SOFTBUS_OK;
}

int32_t UpdateP2pAvailability(const char *peerUdid, bool isP2pAvailable)
{
    if (peerUdid == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (WifiDirectExtCapLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "wifiDirect extCap lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    WifiDirectExtCap *item = GetValidWifiDirectExtCap(peerUdid);
    if (item != NULL) {
        item->isP2pAvailable = isP2pAvailable;
        item->effectiveTime = SoftBusGetSysTimeMs();
        LNN_LOGE(LNN_LANE, "update exists wifidirect cap ext info succ");
        WifiDirectExtCapUnlock();
        return SOFTBUS_OK;
    }
    WifiDirectExtCapUnlock();
    int32_t ret = CreateNewWifiDirectExtCapInfo(peerUdid, isP2pAvailable);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "create wifiDirectExtCap fail, reason=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t DelWifiDirectExtCapInfo(const char *peerUdid)
{
    if (WifiDirectExtCapLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "wifiDirect extCap lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    WifiDirectExtCap *item = NULL;
    WifiDirectExtCap *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_wifiDirectExtCapList.list, WifiDirectExtCap, node) {
        if (strcmp(item->peerUdid, peerUdid) == 0) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_wifiDirectExtCapList.cnt--;
            WifiDirectExtCapUnlock();
            return SOFTBUS_OK;
        }
    }
    WifiDirectExtCapUnlock();
    char *anonyUdid = NULL;
    Anonymize(peerUdid, &anonyUdid);
    LNN_LOGE(LNN_LANE, "not found wifiDirectExtCap info by peerUdid=%{public}s", AnonymizeWrapper(anonyUdid));
    AnonymizeFree(anonyUdid);
    return SOFTBUS_LANE_NOT_FOUND;
}

int32_t GetWlanLinkedFrequency(void)
{
    LnnWlanLinkedInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    int32_t ret = LnnGetWlanLinkedInfoPacked(&info);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get linked info fail, reason=%{public}d", ret);
        return ret;
    }
    LNN_LOGI(LNN_LANE, "wlan linked frequency=%{public}d", info.frequency);
    return info.frequency;
}

static bool GetFeatureCap(const char *networkId, uint64_t *local, uint64_t *remote)
{
    int32_t ret = LnnGetLocalNumU64Info(NUM_KEY_FEATURE_CAPA, local);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "LnnGetLocalNumInfo err, ret=%{public}d", ret);
        return false;
    }
    ret = LnnGetRemoteNumU64Info(networkId, NUM_KEY_FEATURE_CAPA, remote);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "LnnGetRemoteNumInfo err, ret=%{public}d", ret);
        return false;
    }
    return true;
}

static int32_t DefaultFeatureCheck(const char *networkId)
{
    (void)networkId;
    return SOFTBUS_OK;
}

static int32_t CheckTargetFeature(const char *networkId, uint32_t feature, bool *localEnable, bool *remoteEnable)
{
    uint64_t local = 0;
    uint64_t remote = 0;
    if (!GetFeatureCap(networkId, &local, &remote)) {
        LNN_LOGE(LNN_LANE, "get feature cap failed");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    *localEnable = (local & (1 << feature)) > 0;
    *remoteEnable = (remote & (1 << feature)) > 0;
    if (!(*localEnable) || !(*remoteEnable)) {
        LNN_LOGE(LNN_LANE, "feature not support, feature=%{public}u, local=%{public}" PRIu64
            ", remote=%{public}" PRIu64, feature, local, remote);
    }
    return SOFTBUS_OK;
}

static int32_t HmlFeatureCheck(const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, SOFTBUS_INVALID_PARAM, LNN_LANE, "networkId is nullptr");
    bool localEnable = false;
    bool remoteEnable = false;
    int32_t ret = CheckTargetFeature(networkId, BIT_WIFI_DIRECT_ENHANCE_CAPABILITY, &localEnable, &remoteEnable);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (!localEnable) {
        return SOFTBUS_LANE_LOCAL_NO_WIFI_DIRECT_ENHANCE_FEATURE;
    }
    if (!remoteEnable) {
        return SOFTBUS_LANE_REMOTE_NO_WIFI_DIRECT_ENHANCE_FEATURE;
    }
    return SOFTBUS_OK;
}

static int32_t P2pReuseFeatureCheck(const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, SOFTBUS_INVALID_PARAM, LNN_LANE, "networkId is nullptr");
    bool localEnable = false;
    bool remoteEnable = false;
    int32_t ret = CheckTargetFeature(networkId, BIT_WIFI_P2P_REUSE, &localEnable, &remoteEnable);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (!localEnable) {
        return SOFTBUS_LANE_LOCAL_NO_P2P_REUSE_FEATURE;
    }
    if (!remoteEnable) {
        return SOFTBUS_LANE_REMOTE_NO_P2P_REUSE_FEATURE;
    }
    return SOFTBUS_OK;
}

static int32_t BleDirectFeatureCheck(const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, SOFTBUS_INVALID_PARAM, LNN_LANE, "networkId is nullptr");
    bool localEnable = false;
    bool remoteEnable = false;
    int32_t ret = CheckTargetFeature(networkId, BIT_BLE_DIRECT_CONNECT_CAPABILITY, &localEnable, &remoteEnable);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (!localEnable) {
        return SOFTBUS_LANE_LOCAL_NO_BLE_DIRECT_FEATURE;
    }
    if (!remoteEnable) {
        return SOFTBUS_LANE_REMOTE_NO_BLE_DIRECT_FEATURE;
    }
    return SOFTBUS_OK;
}

static int32_t CocFeatureCheck(const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, SOFTBUS_INVALID_PARAM, LNN_LANE, "networkId is nullptr");
    bool localEnable = false;
    bool remoteEnable = false;
    int32_t ret = CheckTargetFeature(networkId, BIT_COC_CONNECT_CAPABILITY, &localEnable, &remoteEnable);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (!localEnable) {
        return SOFTBUS_LANE_LOCAL_NO_COC_FEATURE;
    }
    if (!remoteEnable) {
        return SOFTBUS_LANE_REMOTE_NO_COC_FEATURE;
    }
    return SOFTBUS_OK;
}

static int32_t CocDirectFeatureCheck(const char *networkId)
{
    int32_t ret = CocFeatureCheck(networkId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "coc is not enable");
        return ret;
    }
    ret = BleDirectFeatureCheck(networkId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "ble direct is not enable");
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t SleFeatureCheck(const char *networkId)
{
    LNN_CHECK_AND_RETURN_RET_LOGE(networkId != NULL, SOFTBUS_INVALID_PARAM, LNN_LANE, "networkId is nullptr");
    bool localEnable = false;
    bool remoteEnable = false;
    int32_t ret = CheckTargetFeature(networkId, BIT_SUPPORT_SLE_CAPABILITY, &localEnable, &remoteEnable);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (!localEnable) {
        return SOFTBUS_LANE_LOCAL_NO_SLE_FEATURE;
    }
    if (!remoteEnable) {
        return SOFTBUS_LANE_REMOTE_NO_SLE_FEATURE;
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
    int32_t score = LnnGetCurrChannelScorePacked(channel);
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

static int32_t GetUsbScore(const char *networkId, uint32_t expectedBw)
{
    (void)networkId;
    (void)expectedBw;
    return LNN_LINK_DEFAULT_SCORE;
}

static int32_t GetSleScore(const char *networkId, uint32_t expectedBw)
{
    (void)networkId;
    (void)expectedBw;
    return LNN_LINK_DEFAULT_SCORE;
}

static LinkAttribute g_linkAttr[LANE_LINK_TYPE_BUTT] = {
    [LANE_BR] = {true, DefaultFeatureCheck, GetBrScore},
    [LANE_BLE] = { true,  DefaultFeatureCheck,       GetBleScore     },
    [LANE_P2P] = { true,  DefaultFeatureCheck,       GetP2pScore     },
    [LANE_HML] = { true, HmlFeatureCheck, GetHmlScore},
    [LANE_WLAN_2P4G] = { true,  DefaultFeatureCheck,  GetWlan2P4GScore},
    [LANE_WLAN_5G] = { true,  DefaultFeatureCheck,    GetWlan5GScore  },
    [LANE_ETH] = { false, NULL,              NULL            },
    [LANE_P2P_REUSE] = { true,  P2pReuseFeatureCheck,  GetP2pScore     },
    [LANE_BLE_DIRECT] = { true,  BleDirectFeatureCheck, GetBleScore     },
    [LANE_BLE_REUSE] = { false, NULL,              NULL            },
    [LANE_COC] = { true,  CocFeatureCheck,       GetCocScore     },
    [LANE_COC_DIRECT] = { true,  CocDirectFeatureCheck, GetCocScore     },
    [LANE_USB] = { true,  DefaultFeatureCheck, GetUsbScore     },
    [LANE_SLE] = { true,  SleFeatureCheck, GetSleScore     },
    [LANE_SLE_DIRECT] = { true,  SleFeatureCheck, GetSleScore     },
};

LinkAttribute *GetLinkAttrByLinkType(LaneLinkType linkType)
{
    if ((linkType < 0) || (linkType >= LANE_LINK_TYPE_BUTT)) {
        return NULL;
    }
    return &g_linkAttr[linkType];
}

static uint32_t g_firstPriorityLane[BW_TYPE_BUTT][LANE_LINK_TYPE_BUTT + 1] = {
    [HIGH_BAND_WIDTH] = {LANE_USB, LANE_HML, LANE_P2P, LANE_LINK_TYPE_BUTT},
    [MIDDLE_HIGH_BAND_WIDTH] = {LANE_HML, LANE_WLAN_5G, LANE_LINK_TYPE_BUTT},
    [MIDDLE_LOW_BAND_WIDTH] = {LANE_WLAN_5G, LANE_HML, LANE_WLAN_2P4G, LANE_LINK_TYPE_BUTT},
    [LOW_BAND_WIDTH] = {LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_HML, LANE_LINK_TYPE_BUTT},
};

static uint32_t g_retryLaneList[BW_TYPE_BUTT][LANE_LINK_TYPE_BUTT + 1] = {
    [HIGH_BAND_WIDTH] = {LANE_USB, LANE_HML, LANE_P2P, LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_LINK_TYPE_BUTT},
    [MIDDLE_HIGH_BAND_WIDTH] = {LANE_HML, LANE_WLAN_5G, LANE_P2P, LANE_WLAN_2P4G, LANE_LINK_TYPE_BUTT},
    [MIDDLE_LOW_BAND_WIDTH] = {LANE_WLAN_5G, LANE_HML, LANE_WLAN_2P4G, LANE_P2P, LANE_LINK_TYPE_BUTT},
    [LOW_BAND_WIDTH] = {LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_HML, LANE_BR, LANE_P2P,
        LANE_SLE_DIRECT, LANE_SLE, LANE_COC_DIRECT, LANE_BLE, LANE_LINK_TYPE_BUTT},
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
        return SOFTBUS_LANE_TRANS_TYPE_NOT_MATCH;
    }
    return SOFTBUS_OK;
}

static int32_t CheckSleLinkWithTransType(LaneTransType transType, LaneLinkType linkType)
{
    bool isStreamOrFile = (transType == LANE_T_RAW_STREAM || transType == LANE_T_COMMON_VIDEO ||
        transType == LANE_T_COMMON_VOICE || transType == LANE_T_FILE);
    bool IsSle = (linkType == LANE_SLE || linkType == LANE_SLE_DIRECT);
    if (isStreamOrFile && IsSle) {
        LNN_LOGE(LNN_LANE, "sle not support stream and file datatype, transType=%{public}d, link=%{public}d",
            transType, linkType);
        return SOFTBUS_LANE_TRANS_TYPE_NOT_MATCH;
    }
    return SOFTBUS_OK;
}

static int32_t CheckLinkParam(LaneLinkType linkType, LaneTransType transType)
{
    if (!IsLinkTypeValid(linkType)) {
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
        ret = CheckSleLinkWithTransType(transType, linkType);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "check sle link with transType err, ret=%{public}d", ret);
        }
    }
    return ret;
}

static int32_t CheckFeature(const char *networkId, LaneLinkType linkType)
{
    LinkAttribute *linkAttr = GetLinkAttrByLinkType(linkType);
    if ((linkAttr == NULL) || (!linkAttr->available)) {
        return SOFTBUS_INVALID_PARAM;
    }
    return linkAttr->linkFeatureCheck(networkId);
}

int32_t LaneCheckLinkValid(const char *networkId, LaneLinkType linkType, LaneTransType transType)
{
    if (networkId == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param, linkType=%{public}d", linkType);
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = CheckLinkParam(linkType, transType);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "check link with transType err, ret=%{public}d", ret);
        return ret;
    }
    ret = CheckStaticNetCap(networkId, linkType);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "static cap disable. linkType=%{public}d, ret=%{public}d", linkType, ret);
        return ret;
    }
    ret = CheckFeature(networkId, linkType);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "feature disable. linkType=%{public}d, ret=%{public}d", linkType, ret);
        return ret;
    }
    ret = CheckDynamicNetCap(networkId, linkType);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "dynamic cap disable. linkType=%{public}d, ret=%{public}d", linkType, ret);
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

static void DecideOptimalLinks(const LaneSelectParam *request, LaneLinkType *linkList, uint32_t *linksNum)
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
        if (g_firstPriorityLane[bandWidthType][i] == LANE_LINK_TYPE_BUTT) {
            break;
        }
        if ((CheckLinkParam(g_firstPriorityLane[bandWidthType][i], request->transType) == SOFTBUS_OK)) {
            linkList[(*linksNum)++] = g_firstPriorityLane[bandWidthType][i];
            LNN_LOGI(LNN_LANE, "decide optimal linkType=%{public}d", g_firstPriorityLane[bandWidthType][i]);
            continue;
        }
    }
}

static bool IsLaneExist(LaneLinkType *linkList, uint32_t linksNum, LaneLinkType linkType)
{
    for (uint32_t i = 0; i < linksNum; i++) {
        if (linkList[i] == linkType) {
            return true;
        }
    }
    return false;
}

static void DecideRetryLinks(const LaneSelectParam *request,
    LaneLinkType *linkList, uint32_t *linksNum)
{
    uint32_t minBandWidth = request->qosRequire.minBW;
    int32_t bandWidthType = GetBwType(minBandWidth);
    for (uint32_t i = 0; i < (LANE_LINK_TYPE_BUTT + 1); i++) {
        if (g_retryLaneList[bandWidthType][i] == LANE_LINK_TYPE_BUTT) {
            break;
        }
        if (!IsLaneExist(linkList, *linksNum, g_retryLaneList[bandWidthType][i]) &&
            (CheckLinkParam(g_retryLaneList[bandWidthType][i], request->transType) == SOFTBUS_OK)) {
            linkList[(*linksNum)++] = g_retryLaneList[bandWidthType][i];
            LNN_LOGI(LNN_LANE, "decide retry linkType=%{public}d", g_retryLaneList[bandWidthType][i]);
        }
    }
}

static bool IsDeviceTypeExist(const char *networkId, int32_t deviceType)
{
    int32_t localDevTypeId = TYPE_UNKNOW_ID;
    int32_t ret = LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &localDevTypeId);
    if (ret == SOFTBUS_OK && localDevTypeId == deviceType) {
        LNN_LOGI(LNN_LANE, "local is matched, deviceType=%{public}d", localDevTypeId);
        return true;
    }
    int32_t remoteDevTypeId = TYPE_UNKNOW_ID;
    ret = LnnGetRemoteNumInfo(networkId, NUM_KEY_DEV_TYPE_ID, &remoteDevTypeId);
    if (ret == SOFTBUS_OK && remoteDevTypeId == deviceType) {
        LNN_LOGI(LNN_LANE, "remote is matched, deviceType=%{public}d", remoteDevTypeId);
        return true;
    }
    return false;
}

bool IsEnhancedWifiDirectSupported(const char *networkId)
{
    uint64_t localFeature = 0;
    uint64_t remoteFeature = 0;
    bool isFound = GetFeatureCap(networkId, &localFeature, &remoteFeature);
    if (!isFound) {
        LNN_LOGE(LNN_LANE, "getFeature fail");
        return false;
    }
    if (((localFeature & (1 << BIT_WIFI_DIRECT_ENHANCE_CAPABILITY)) == 0) ||
        ((remoteFeature & (1 << BIT_WIFI_DIRECT_ENHANCE_CAPABILITY)) == 0)) {
        LNN_LOGE(LNN_LANE, "local=%{public}" PRIu64 ", remote=%{public}" PRIu64, localFeature, remoteFeature);
        return false;
    }
    int32_t ret = CheckStaticNetCap(networkId, LANE_HML);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "static cap disable, ret=%{public}d", ret);
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
        LNN_LOGE(LNN_LANE, "invalid linksNum=%{public}u", *linksNum);
        return;
    }
    if (!IsRemoteLegacy(networkId)) {
        LNN_LOGE(LNN_LANE, "valid os, no need filter links");
        return;
    }
    if (GetBwType(request->qosRequire.minBW) == LOW_BAND_WIDTH) {
        if (request->qosRequire.continuousTask) {
            FilterLinksWithContinuous(linkList, linksNum);
        }
    }
}

static bool IsNeedUpdateHmlPriority(LaneLinkType *linkList, uint32_t *linksNum)
{
    if (linkList == NULL || *linksNum > LANE_LINK_TYPE_BUTT || *linksNum <= 0) {
        LNN_LOGE(LNN_LANE, "linkList is null or invalid linksNum, update hml priority.");
        return true;
    }
    bool hmlExist = false;
    for (uint32_t i = 0; i < *linksNum; i++) {
        if (linkList[i] == LANE_USB) {
            LNN_LOGI(LNN_LANE, "lane usb is in preferList, don't update hml priority.");
            return false;
        }
        if (linkList[i] == LANE_HML) {
            hmlExist = true;
        }
    }
    return hmlExist;
}

static void UpdateHmlPriority(const char *peerNetWorkId, const LaneSelectParam *request,
    LaneLinkType *linkList, uint32_t *linksNum)
{
    if (*linksNum > LANE_LINK_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "invalid linksNum=%{public}u", *linksNum);
        return;
    }
    if (!IsNeedUpdateHmlPriority(linkList, linksNum)) {
        LNN_LOGI(LNN_LANE, "no need update hml priority.");
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
        LNN_LOGE(LNN_LANE, "invalid linksNum=%{public}u", *linksNum);
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
    bool isFilterP2p = IsEnhancedWifiDirectSupported(networkId);
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

static bool IsSupportWifiDirectReuse(const char *networkId)
{
    char peerUdid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return false;
    }
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (FindLaneResourceByLinkType(peerUdid, LANE_P2P, &resourceItem) != SOFTBUS_OK &&
        FindLaneResourceByLinkType(peerUdid, LANE_HML, &resourceItem) != SOFTBUS_OK &&
        FindLaneResourceByLinkType(peerUdid, LANE_HML_RAW, &resourceItem) != SOFTBUS_OK) {
        LNN_LOGD(LNN_LANE, "wifidirect not support reuse");
        return false;
    }
    return true;
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
    if (FindLaneResourceByLinkType(peerUdid, LANE_P2P, &resourceItem) != SOFTBUS_OK &&
        FindLaneResourceByLinkType(peerUdid, LANE_HML, &resourceItem) != SOFTBUS_OK) {
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
    return LaneCheckLinkValid(networkId, g_firstPriorityLane[bandWidthType][0], request->transType);
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

static bool IsValidWifiDirectExtCap(uint64_t effectiveTime)
{
    uint64_t currTime = SoftBusGetSysTimeMs();
    return (currTime > (effectiveTime + WIFI_DIRECT_EXT_CAP_VALID_TIME)) ? false : true;
}

static bool CheckP2pIsAvailable(const char *peerUdid)
{
    if (WifiDirectExtCapLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "wifiDirect extCap lock fail");
        return true;
    }
    WifiDirectExtCap *item = GetValidWifiDirectExtCap(peerUdid);
    if (item == NULL) {
        LNN_LOGD(LNN_LANE, "not find p2p availability info, available by default");
        WifiDirectExtCapUnlock();
        return true;
    }
    uint64_t effectiveTime = item->effectiveTime;
    bool isP2pAvailable = item->isP2pAvailable;
    WifiDirectExtCapUnlock();
    if (!IsValidWifiDirectExtCap(effectiveTime)) {
        (void)DelWifiDirectExtCapInfo(peerUdid);
        LNN_LOGD(LNN_LANE, "p2p availability exceed timeliness, available by default");
        return true;
    }
    LNN_LOGI(LNN_LANE, "p2p available is %{public}s", isP2pAvailable ? "true" : "false");
    return isP2pAvailable ? true : false;
}

static void AdjustLinkPriorityForRtt(const char *networkId, LanePreferredLinkList *recommendList)
{
    if (!IsRemoteLegacy(networkId)) {
        LNN_LOGD(LNN_LANE, "valid os, no need adjust");
        return;
    }
    char peerUdid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return;
    }
    if (CheckP2pIsAvailable(peerUdid)) {
        return;
    }
    LNN_LOGI(LNN_LANE, "adjust link priority for rtt");
    LaneLinkType tmpList[LANE_LINK_TYPE_BUTT] = {0};
    uint32_t num = 0;
    for (uint32_t i = 0; i < recommendList->linkTypeNum; i++) {
        if (recommendList->linkType[i] != LANE_P2P) {
            tmpList[num++] = recommendList->linkType[i];
        }
    }
    tmpList[num++] = LANE_P2P;
    uint32_t size = sizeof(LaneLinkType) * LANE_LINK_TYPE_BUTT;
    (void)memset_s(&recommendList->linkType, size, -1, size);
    recommendList->linkTypeNum = num;
    for (uint32_t i = 0; i < recommendList->linkTypeNum; i++) {
        recommendList->linkType[i] = tmpList[i];
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
    AdjustLinkPriorityForRtt(networkId, &recommendList);
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
        /* fall-through */
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
        LNN_LOGE(LNN_LANE, "invalid linksNum=%{public}u", *linksNum);
        return;
    }
    if (!request->qosRequire.continuousTask) {
        return;
    }
    if (!IsDeviceTypeExist(networkId, TYPE_WATCH_ID) && !IsDeviceTypeExist(networkId, TYPE_GLASS_ID)) {
        return;
    }
    uint32_t num = 0;
    LaneLinkType tmpList[LANE_LINK_TYPE_BUTT] = {0};
    bool needFilter = false;
    for (uint32_t i = 0; i < *linksNum; i++) {
        if (linkList[i] == LANE_HML || linkList[i] == LANE_P2P || linkList[i] == LANE_COC_DIRECT) {
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

static void DecideLinksWithQosRequire(const LaneSelectParam *request, LaneLinkType *linkList, uint32_t *linksNum)
{
    DecideOptimalLinks(request, linkList, linksNum);
    DecideRetryLinks(request, linkList, linksNum);
    LNN_LOGI(LNN_LANE, "decide links num=%{public}d", *linksNum);
}

static void DecideLinksWithFeature(const char *networkId, LaneLinkType *linkList, uint32_t *linksNum)
{
    if (networkId == NULL || linkList == NULL || linksNum == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    if (*linksNum <= 0 || *linksNum > LANE_LINK_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "invalid linksNum=%{public}u", *linksNum);
        return;
    }

    uint32_t resNum = 0;
    LaneLinkType resList[LANE_LINK_TYPE_BUTT] = {0};
    for (uint32_t i = 0; i < *linksNum; i++) {
        int32_t ret = CheckFeature(networkId, linkList[i]);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "feature disable. linkType=%{public}d, ret=%{public}d", linkList[i], ret);
            continue;
        }
        resList[resNum++] = linkList[i];
    }
    if (resNum == *linksNum) {
        return;
    }
    GenerateLinkList(resList, resNum, linkList, linksNum);
}

static void DecideLinksWithStaticCapa(const char *networkId, LaneLinkType *linkList, uint32_t *linksNum)
{
    if (networkId == NULL || linkList == NULL || linksNum == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    if (*linksNum <= 0 || *linksNum > LANE_LINK_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "invalid linksNum=%{public}u", *linksNum);
        return;
    }

    uint32_t resNum = 0;
    LaneLinkType resList[LANE_LINK_TYPE_BUTT] = {0};
    for (uint32_t i = 0; i < *linksNum; i++) {
        int32_t ret = CheckStaticNetCap(networkId, linkList[i]);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "static cap disable. linkType=%{public}d, ret=%{public}d", linkList[i], ret);
            continue;
        }
        resList[resNum++] = linkList[i];
    }
    if (resNum == *linksNum) {
        return;
    }
    GenerateLinkList(resList, resNum, linkList, linksNum);
}

static int64_t GetTimeInterval(uint64_t curTime, uint64_t lastTime)
{
    if (lastTime > curTime) {
        LNN_LOGW(LNN_LANE, "curTime=%{public}" PRIu64 "is less than lastTime=%{public}" PRIu64, curTime, lastTime);
        return -(int64_t)(lastTime - curTime);
    }
    return (int64_t)(curTime - lastTime);
}

static int32_t AllowSelectNoCapLink(const char *networkId)
{
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    LNN_LOGI(LNN_LANE, "networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
    AnonymizeFree(anonyNetworkId);
    char udid[UDID_BUF_LEN] = {0};
    int32_t ret = LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, udid, sizeof(udid));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid err");
        return ret;
    }
    uint64_t curTime = SoftBusGetSysTimeMs();
    LinkLedgerInfo info;
    (void)memset_s(&info, sizeof(LinkLedgerInfo), 0, sizeof(LinkLedgerInfo));
    ret = LnnGetLinkLedgerInfo(udid, &info);
    if (ret != SOFTBUS_OK && ret != SOFTBUS_NOT_FIND) {
        LNN_LOGI(LNN_LANE, "get link ledger fail, ret=%{public}d", ret);
        return ret;
    }
    if (ret == SOFTBUS_OK) {
        int64_t intervalTime = GetTimeInterval(curTime, info.lastTryBuildTime);
        LNN_LOGI(LNN_LANE, "lastTryBuildTime=%{public}" PRIu64 ", intervalTime=%{public}" PRId64,
            info.lastTryBuildTime, intervalTime);
        if (intervalTime < TRY_BUILD_INTERVAL_TIME) {
            return SOFTBUS_DATA_NOT_ENOUGH;
        }
    }
    info.lastTryBuildTime = curTime;
    return LnnAddLinkLedgerInfo(udid, &info);
}

static void DecideLinksWithDynamicCapa(const char *networkId, LaneLinkType *linkList, uint32_t *linksNum)
{
    if (networkId == NULL || linkList == NULL || linksNum == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return;
    }
    if (*linksNum <= 0 || *linksNum > LANE_LINK_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "invalid linksNum=%{public}u", *linksNum);
        return;
    }

    uint32_t resNum = 0;
    uint32_t remoteNoCapNum = 0;
    LaneLinkType resList[LANE_LINK_TYPE_BUTT] = {0};
    LaneLinkType remoteNoCapList[LANE_LINK_TYPE_BUTT] = {0};
    for (uint32_t i = 0; i < *linksNum; i++) {
        int32_t ret = CheckDynamicNetCap(networkId, linkList[i]);
        if (ret == SOFTBUS_OK) {
            resList[resNum++] = linkList[i];
            LNN_LOGI(LNN_LANE, "available linkType=%{public}d", linkList[i]);
            continue;
        }
        if (ret == SOFTBUS_LANE_REMOTE_NO_WIFI_DIRECT_CAP) {
            remoteNoCapList[remoteNoCapNum++] = linkList[i];
            LNN_LOGI(LNN_LANE, "remote dynamic cap disable, linkType=%{public}d", linkList[i]);
            continue;
        }
        LNN_LOGE(LNN_LANE, "dynamic cap disable, linkType=%{public}d, ret=%{public}d", linkList[i], ret);
    }
    if (resNum == 0 && remoteNoCapNum != 0) {
        int32_t ret = AllowSelectNoCapLink(networkId);
        if (ret == SOFTBUS_OK) {
            LNN_LOGI(LNN_LANE, "allow select no cap links, remoteNoCapNum=%{public}u", remoteNoCapNum);
            GenerateLinkList(remoteNoCapList, remoteNoCapNum, linkList, linksNum);
            return;
        } else {
            LNN_LOGI(LNN_LANE, "not allow select no cap links, ret=%{public}d", ret);
        }
    }
    if (resNum == *linksNum) {
        return;
    }
    GenerateLinkList(resList, resNum, linkList, linksNum);
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
    DecideLinksWithQosRequire(request, linkList, &linksNum);
    DecideLinksWithStaticCapa(networkId, linkList, &linksNum);
    DecideLinksWithFeature(networkId, linkList, &linksNum);
    DecideLinksWithDynamicCapa(networkId, linkList, &linksNum);
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

static bool IsReuseLinkValid(const char *networkId, LaneLinkType linkType,
    const LaneSelectParam *request, const char *peerUdid)
{
    bool isLinkValid = false;
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    switch (linkType) {
        case LANE_WLAN_2P4G:
        /* fall-through */
        case LANE_WLAN_5G:
            isLinkValid = true;
            break;
        case LANE_P2P:
        /* fall-through */
        case LANE_HML:
            if (IsSupportWifiDirectReuse(networkId)) {
                isLinkValid = true;
            }
            break;
        default:
            if (FindLaneResourceByLinkType(peerUdid, linkType, &resourceItem) == SOFTBUS_OK) {
                isLinkValid = true;
            }
            break;
    }
    return isLinkValid;
}

static int32_t FilterWithReuse(const char *networkId, const LaneSelectParam *request,
    LaneLinkType *reuseLink, uint32_t *linkSum)
{
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    char peerUdid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    LaneLinkType filterLinks[LANE_LINK_TYPE_BUTT];
    uint32_t filterCount = 0;
    for (uint32_t i = 0; i < *linksNum; i++) {
        LaneLinkType linkType = reuseLink[i];
        bool isLinkValid = IsReuseLinkValid(networkId, linkType, request, peerUdid);
        if (isLinkValid && (LaneCheckLinkValid(networkId, linkType, request->transType) == SOFTBUS_OK)) {
            filterLinks[filterCount++] = linkType;
        } else {
            LNN_LOGE(LNN_LANE, "linkType=%{public}d not valid, removed", linkType);
        }
    }
    if (filterCount = 0) {
        LNN_LOGE(LNN_LANE, "no valid reuse linkType");
    }
    GenerateLinkList(filterLinks, filterCount, reuseLink, linksNum);
    return SOFTBUS_OK;
}

int32_t DecideReuseLane(const char *networkId, const LaneSelectParam *request,
    LanePreferredLinkList *recommendList)
{
    if (networkId == NULL || request == NULL || recommendList == NULL ||
        recommendList->linkTypeNum != 0) {
        LNN_LOGE(LNN_LANE, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneLinkType reuseLink[LANE_LINK_TYPE_BUTT];
    (void)memset_s(reuseLink, sizeof(reuseLink), -1, sizeof(reuseLink));
    uint32_t linksNum = 0;
    DecideLinksWithQosRequire(request, reuseLink, &linksNum);
    int32_t ret = FilterWithReuse(networkId, request, reuseLink, &linksNum);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "filter reuse check fail");
        return ret;
    }
    for (uint32_t i = 0; i < linksNum; i++) {
        recommendList->linkType[(recommendList->linkTypeNum)++] = reuseLink[i];
    }
    return SOFTBUS_OK;
}

int32_t InitLaneSelectRule(void)
{
    if (SoftBusMutexInit(&g_wifiDirectExtCapList.lock, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "wifidirect extcap mutex init fail");
        return SOFTBUS_NO_INIT;
    }
    ListInit(&g_wifiDirectExtCapList.list);
    g_wifiDirectExtCapList.cnt = 0;
    return SOFTBUS_OK;
}

void DeinitLaneSelectRule(void)
{
    if (WifiDirectExtCapLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "wifiDirect extCap lock fail");
        return;
    }
    WifiDirectExtCap *item = NULL;
    WifiDirectExtCap *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_wifiDirectExtCapList.list, WifiDirectExtCap, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
        g_wifiDirectExtCapList.cnt--;
    }
    WifiDirectExtCapUnlock();
    (void)SoftBusMutexDestroy(&g_wifiDirectExtCapList.lock);
}

static uint32_t g_laneBandWidth[BW_TYPE_BUTT][LANE_LINK_TYPE_BUTT + 1] = {
    [HIGH_BAND_WIDTH] = {LANE_USB, LANE_HML, LANE_LINK_TYPE_BUTT},
    [MIDDLE_HIGH_BAND_WIDTH] = {LANE_WLAN_5G, LANE_LINK_TYPE_BUTT},
    [MIDDLE_LOW_BAND_WIDTH] = {LANE_WLAN_2P4G, LANE_LINK_TYPE_BUTT},
    [LOW_BAND_WIDTH] = {LANE_BR, LANE_P2P, LANE_LINK_TYPE_BUTT},
};

int32_t GetSupportBandWidth(const char *peerNetworkId, LaneTransType transType, uint32_t *supportBw)
{
    if (peerNetworkId == NULL || supportBw == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    for (uint32_t i = 0; i < BW_TYPE_BUTT; i++) {
        for (uint32_t j = 0; j < (LANE_LINK_TYPE_BUTT + 1); j++) {
            if (g_laneBandWidth[i][j] == LANE_LINK_TYPE_BUTT) {
                break;
            }
            if (LaneCheckLinkValid(peerNetworkId, g_laneBandWidth[i][j], transType) == SOFTBUS_OK) {
                *supportBw = i;
                return SOFTBUS_OK;
            }
        }
    }
    return SOFTBUS_LANE_NO_AVAILABLE_LINK;
}

static bool IsBwExist(uint32_t *bwList, uint8_t bWNum, uint32_t bWValue)
{
    for (uint32_t i = 0; i < bWNum; i++) {
        if (bwList[i] == bWValue) {
            return true;
        }
    }
    return false;
}

static int32_t BuildSupportReuseQosList(LaneLinkType *linkList, uint8_t linkNum,
    uint32_t **supportBw, uint8_t *bwCnt, LaneTransType transType)
{
    uint32_t validBwList[BW_TYPE_BUTT];
    (void)memset_s(validBwList, sizeof(validBwList), 0, sizeof(validBwList));
    uint8_t tmpCnt = 0;
    for (uint32_t i = 0; i < BW_TYPE_BUTT; i++) {
        for (uint32_t j = 0; j < (LANE_LINK_TYPE_BUTT + 1); j++) {
            if (g_laneBandWidth[i][j] == LANE_LINK_TYPE_BUTT) {
                break;
            }
            if (CheckLinkWithTransType(transType, g_laneBandWidth[i][j]) == SOFTBUS_OK &&
                IsLaneExist(linkList, linkNum, g_laneBandWidth[i][j]) &&
                !(IsBwExist(validBwList, tmpCnt, i))) {
                validBwList[tmpCnt++] = i;
            }
        }
    }
    if (tmpCnt == 0) {
        LNN_LOGE(LNN_LANE, "no support reuse qos");
        return SOFTBUS_LANE_NO_AVAILABLE_LINK;
    }
    uint32_t *tmpList = (uint32_t *)SoftBusCalloc(tmpCnt * sizeof(uint32_t));
    if (tmpList == NULL) {
        LNN_LOGE(LNN_LANE, "calloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    for (uint32_t i = 0; i < tmpCnt; i++) {
        *(tmpList + i) = validBwList[i];
    }
    *supportBw = tmpList;
    *bwCnt = tmpCnt;
    return SOFTBUS_OK;
}

int32_t GetAllSupportReuseBandWidth(const char *peerNetworkId, LaneTransType transType,
    uint32_t **supportBw, uint8_t *bwCnt)
{
    if (peerNetworkId == NULL || supportBw == NULL || bwCnt == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char peerUdid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(peerNetworkId, STRING_KEY_DEV_UDID, peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
    }
    LaneLinkType *linkList = NULL;
    uint8_t linkNum = 0;
    int32_t ret = GetAllLinkWithDevId(peerUdid, &linkList, &linkNum);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    ret = BuildSupportReuseQosList(linkList, linkNum, supportBw, bwCnt, transType);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "build reuse qos list fail, ret=%{public}d", ret);
    }
    SoftBusFree(linkList);
    return ret;
}