/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "lnn_log.h"

#include "anonymizer.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_lane_communication_capability.h"
#include "lnn_lane_link.h"
#include "softbus_adapter_mem.h"
#include "softbus_wifi_api_adapter.h"

#define LOW_BW                  (384 * 1024)
#define MID_BW                  (30 * 1024 * 1024)
#define HIGH_BW                 (160 * 1024 * 1024)

static int32_t DefaultFeatureCheck(const char *networkId)
{
    (void)networkId;
    return SOFTBUS_OK;
}

static int32_t GetWlanDefaultScore(const char *networkId, uint32_t expectedBw)
{
    (void)networkId;
    (void)expectedBw;
    return 0;
}

static LinkAttribute g_linkAttr[LANE_LINK_TYPE_BUTT] = {
    [LANE_WLAN_2P4G] = { true,  DefaultFeatureCheck,  GetWlanDefaultScore},
    [LANE_WLAN_5G] = { true,  DefaultFeatureCheck,    GetWlanDefaultScore},
};

LinkAttribute *GetLinkAttrByLinkType(LaneLinkType linkType)
{
    if ((linkType < 0) || (linkType >= LANE_LINK_TYPE_BUTT)) {
        return NULL;
    }
    return &g_linkAttr[linkType];
}

static uint32_t g_firstPriorityLane[BW_TYPE_BUTT][LANE_LINK_TYPE_BUTT + 1] = {
    [HIGH_BAND_WIDTH] = {LANE_WLAN_5G, LANE_LINK_TYPE_BUTT},
    [MIDDLE_HIGH_BAND_WIDTH] = {LANE_WLAN_5G, LANE_LINK_TYPE_BUTT},
    [MIDDLE_LOW_BAND_WIDTH] = {LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_LINK_TYPE_BUTT},
    [LOW_BAND_WIDTH] = {LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_LINK_TYPE_BUTT},
};

static uint32_t g_retryLaneList[BW_TYPE_BUTT][LANE_LINK_TYPE_BUTT + 1] = {
    [HIGH_BAND_WIDTH] = {LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_LINK_TYPE_BUTT},
    [MIDDLE_HIGH_BAND_WIDTH] = {LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_LINK_TYPE_BUTT},
    [MIDDLE_LOW_BAND_WIDTH] = {LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_LINK_TYPE_BUTT},
    [LOW_BAND_WIDTH] = {LANE_WLAN_5G, LANE_WLAN_2P4G, LANE_LINK_TYPE_BUTT},
};

static bool IsLinkTypeValid(LaneLinkType type)
{
    if ((type < 0) || (type >= LANE_LINK_TYPE_BUTT)) {
        return false;
    }
    return true;
}

static int32_t CheckLinkParam(LaneLinkType linkType, LaneTransType transType)
{
    (void)transType;
    if (!IsLinkTypeValid(linkType)) {
        LNN_LOGE(LNN_LANE, "invalid param, linkType=%{public}d", linkType);
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
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

static int32_t GetErrCodeOfRequest(const char *networkId, const LaneSelectParam *request)
{
    SoftBusWifiDetailState wifiState = SoftBusGetWifiState();
    if (wifiState == SOFTBUS_WIFI_STATE_INACTIVE || wifiState == SOFTBUS_WIFI_STATE_DEACTIVATING) {
        return SOFTBUS_LANE_WIFI_OFF;
    }
    int32_t bandWidthType = GetBwType(request->qosRequire.minBW);
    return LaneCheckLinkValid(networkId, g_firstPriorityLane[bandWidthType][0], request->transType);
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
    LaneLinkType resList[LANE_LINK_TYPE_BUTT] = {0};
    for (uint32_t i = 0; i < *linksNum; i++) {
        int32_t ret = CheckDynamicNetCap(networkId, linkList[i]);
        if (ret == SOFTBUS_OK) {
            resList[resNum++] = linkList[i];
            LNN_LOGI(LNN_LANE, "available linkType=%{public}d", linkList[i]);
            continue;
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
    for (uint32_t i = 0; i < linksNum; i++) {
        recommendList->linkType[i] = linkList[i];
    }
    recommendList->linkTypeNum = linksNum;
    if (recommendList->linkTypeNum == 0) {
        LNN_LOGE(LNN_LANE, "there is none linkResource can be used");
        return GetErrCodeOfRequest(networkId, request);
    }
    return SOFTBUS_OK;
}
