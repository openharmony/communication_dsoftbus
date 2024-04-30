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

#include "lnn_lane_select.h"

#include <securec.h>

#include "anonymizer.h"
#include "common_list.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_log.h"
#include "lnn_parameter_utils.h"
#include "lnn_select_rule.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"
#include "lnn_select_rule.h"
#include "lnn_common_utils.h"

#define INVALID_LINK (-1)
#define MESH_MAGIC_NUMBER 0x5A5A5A5A

static void GetFileDefaultLink(LaneLinkType *linkList, uint32_t *listNum)
{
    linkList[(*listNum)++] = LANE_WLAN_5G;
    linkList[(*listNum)++] = LANE_HML;
    linkList[(*listNum)++] = LANE_P2P;
    linkList[(*listNum)++] = LANE_WLAN_2P4G;
    linkList[(*listNum)++] = LANE_BR;
}

static void GetStreamDefaultLink(LaneLinkType *linkList, uint32_t *listNum)
{
    linkList[(*listNum)++] = LANE_WLAN_5G;
    linkList[(*listNum)++] = LANE_HML;
    linkList[(*listNum)++] = LANE_P2P;
    linkList[(*listNum)++] = LANE_WLAN_2P4G;
}

static void GetMsgDefaultLink(LaneLinkType *linkList, uint32_t *listNum)
{
    linkList[(*listNum)++] = LANE_WLAN_5G;
    linkList[(*listNum)++] = LANE_WLAN_2P4G;
    linkList[(*listNum)++] = LANE_BLE;
    linkList[(*listNum)++] = LANE_BR;
}

static void GetBytesDefaultLink(LaneLinkType *linkList, uint32_t *listNum)
{
    linkList[(*listNum)++] = LANE_WLAN_5G;
    linkList[(*listNum)++] = LANE_WLAN_2P4G;
    linkList[(*listNum)++] = LANE_BLE;
    linkList[(*listNum)++] = LANE_BR;
}

static int32_t GetLaneDefaultLink(LaneTransType transType, LaneLinkType *optLink, uint32_t *linkNum)
{
    LaneLinkType defaultLink[LANE_LINK_TYPE_BUTT];
    (void)memset_s(defaultLink, sizeof(defaultLink), -1, sizeof(defaultLink));
    uint32_t optLinkMaxNum = *linkNum;
    uint32_t index = 0;
    switch (transType) {
        case LANE_T_MSG:
            GetMsgDefaultLink(defaultLink, &index);
            break;
        case LANE_T_BYTE:
            GetBytesDefaultLink(defaultLink, &index);
            break;
        case LANE_T_FILE:
            GetFileDefaultLink(defaultLink, &index);
            break;
        case LANE_T_RAW_STREAM:
        case LANE_T_COMMON_VIDEO:
        case LANE_T_COMMON_VOICE:
            GetStreamDefaultLink(defaultLink, &index);
            break;
        default:
            LNN_LOGE(LNN_LANE, "lane type is not supported. type=%{public}d", transType);
            return SOFTBUS_ERR;
    }
    *linkNum = 0;
    if (memcpy_s(optLink, optLinkMaxNum * sizeof(LaneLinkType), defaultLink, sizeof(defaultLink)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy default linkList to optinal fail");
        return SOFTBUS_MEM_ERR;
    }
    *linkNum = index;
    return SOFTBUS_OK;
}

static bool IsLinkTypeValid(LaneLinkType type)
{
    if ((type < 0) || (type >= LANE_LINK_TYPE_BUTT)) {
        return false;
    }
    return true;
}

static bool IsValidLane(const char *networkId, LaneLinkType linkType)
{
    if (!IsLinkTypeValid(linkType)) {
        return false;
    }
    LinkAttribute *linkAttr = GetLinkAttrByLinkType(linkType);
    if ((linkAttr == NULL) || (!linkAttr->available)) {
        return false;
    }
    if (!linkAttr->IsEnable(networkId)) {
        LNN_LOGE(LNN_LANE, "link capacity is not support. linkType=%{public}d", linkType);
        return false;
    }
    return true;
}

static char *GetLinkTypeStrng(LaneLinkType preferredLink)
{
    switch (preferredLink) {
        case LANE_BR:
            return "BR";
        case LANE_BLE:
            return "BLE";
        case LANE_P2P:
            return "P2P";
        case LANE_HML:
            return "HML";
        case LANE_WLAN_2P4G:
            return "WLAN 2.4G";
        case LANE_WLAN_5G:
            return "WLAN 5G";
        case LANE_ETH:
            return "ETH";
        case LANE_P2P_REUSE:
            return "P2P_REUSE";
        case LANE_BLE_DIRECT:
            return "BLE_DIRECT";
        case LANE_COC:
            return "COC";
        case LANE_COC_DIRECT:
            return "COC_DIRECT";
        default:
            return "INVALID_LINK";
    }
}

static void DumpPreferredLink(LaneLinkType preferredLink, uint32_t priority)
{
    LNN_LOGD(LNN_LANE, "priority=%{public}u, linkType=%{public}s", priority, GetLinkTypeStrng(preferredLink));
}

static void SelectByPreferredLink(const char *networkId, const LaneSelectParam *request,
    LaneLinkType *resList, uint32_t *resNum)
{
    LaneLinkType *preferredList = (LaneLinkType *)&(request->list.linkType[0]);
    uint32_t listNum = request->list.linkTypeNum;
    *resNum = 0;
    bool isStream = (request->transType == LANE_T_RAW_STREAM ||
                    request->transType == LANE_T_COMMON_VIDEO ||
                    request->transType == LANE_T_COMMON_VOICE);
    for (uint32_t i = 0; i < listNum; i++) {
        bool isBt = (preferredList[i] == LANE_BR || preferredList[i] == LANE_BLE ||
                    preferredList[i] == LANE_BLE_DIRECT || preferredList[i] == LANE_BLE_REUSE ||
                    preferredList[i] == LANE_COC || preferredList[i] == LANE_COC_DIRECT);
        if (isStream && isBt) {
            continue;
        }
        if (!IsValidLane(networkId, preferredList[i])) {
            continue;
        }
        resList[(*resNum)] = preferredList[i];
        (*resNum)++;
        DumpPreferredLink(preferredList[i], i);
    }
    return;
}
static void SelectByDefaultLink(const char *networkId, const LaneSelectParam *request,
    LaneLinkType *resList, uint32_t *resNum)
{
    LaneLinkType optionalLink[LANE_LINK_TYPE_BUTT];
    (void)memset_s(optionalLink, sizeof(optionalLink), 0, sizeof(optionalLink));
    uint32_t optLinkNum = LANE_LINK_TYPE_BUTT;
    if (GetLaneDefaultLink(request->transType, optionalLink, &optLinkNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get defaultLinkList fail");
        return;
    }
    *resNum = 0;
    for (uint32_t i = 0; i < optLinkNum; i++) {
        if (!IsValidLane(networkId, optionalLink[i])) {
            continue;
        }
        resList[(*resNum)++] = optionalLink[i];
    }
}

static int32_t PreProcLaneSelect(const char *networkId, const LaneSelectParam *request,
    LanePreferredLinkList *recommendList, const uint32_t *listNum)
{
    if ((networkId == NULL) || (request == NULL) || (recommendList == NULL) || (listNum == NULL)) {
        LNN_LOGE(LNN_LANE, "laneSelect params invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!LnnGetOnlineStateById(networkId, CATEGORY_NETWORK_ID)) {
        char *anonyNetworkId = NULL;
        Anonymize(networkId, &anonyNetworkId);
        LNN_LOGE(LNN_LANE, "device not online, cancel selectLane, networkId=%{public}s", anonyNetworkId);
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GetListScore(const char *networkId, uint32_t expectedBw, const LaneLinkType *resList,
    int32_t *resListScore, uint32_t resNum)
{
    for (uint32_t i = 0; i < resNum; ++i) {
        if (resList[i] < 0 || resList[i] >= LANE_LINK_TYPE_BUTT) {
            LNN_LOGE(LNN_LANE, "LaneLinkType is invalid, i=%{public}d, resList[i]=%{public}d", i, resList[i]);
            continue;
        }
        LinkAttribute *linkAttr = GetLinkAttrByLinkType(resList[i]);
        resListScore[resList[i]] = linkAttr->GetLinkScore(networkId, expectedBw);
        LNN_LOGI(LNN_LANE, "LaneLinkType=%{public}d, Score=%{public}d",
            resList[i], resListScore[resList[i]]);
    }
    return SOFTBUS_OK;
}

static void SwapListNode(LaneLinkType *left, LaneLinkType *right)
{
    LaneLinkType tmp = *left;
    *left = *right;
    *right = tmp;
}

static int32_t AdjustLanePriority(const char *networkId, const LaneSelectParam *request,
    LaneLinkType *resList, uint32_t resNum)
{
    int32_t resListScore[LANE_LINK_TYPE_BUTT];
    (void)memset_s(resListScore, sizeof(resListScore), INVALID_LINK, sizeof(resListScore));
    int32_t ret = GetListScore(networkId, request->expectedBw, resList, resListScore, resNum);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get linklist score fail");
        return ret;
    }
    if ((resListScore[LANE_WLAN_2P4G] == INVALID_LINK && resListScore[LANE_WLAN_5G] == INVALID_LINK) ||
        (resListScore[LANE_P2P] == INVALID_LINK && resListScore[LANE_HML] == INVALID_LINK)) {
        char *anonyNetworkId = NULL;
        Anonymize(networkId, &anonyNetworkId);
        LNN_LOGI(LNN_LANE, "linklist does not require any changes, networkId=%{public}s, resNum=%{public}u",
            anonyNetworkId, resNum);
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_OK;
    }
    uint32_t idxWlan = LANE_LINK_TYPE_BUTT;
    for (uint32_t i = 0; i < resNum; ++i) {
        if (resList[i] == LANE_WLAN_2P4G || resList[i] == LANE_WLAN_5G) {
            idxWlan = i;
            break;
        }
    }
    if (resListScore[resList[idxWlan]] >= UNACCEPT_SCORE) {
        return SOFTBUS_OK;
    }
    for (uint32_t j = idxWlan; j < resNum; ++j) {
        if (resList[j] == LANE_HML || resList[j] == LANE_P2P) {
            SwapListNode(&resList[idxWlan], &resList[j]);
            idxWlan = j;
        }
    }
    for (uint32_t k = 0; k < resNum; ++k) {
        LNN_LOGD(LNN_LANE, "adjusted linklist, priority link=%{public}d, score=%{public}d", resList[k],
            resListScore[resList[k]]);
    }
    return SOFTBUS_OK;
}

static bool HmlIsExist(LaneLinkType *resList, uint32_t resNum)
{
    for (uint32_t i = 0; i < resNum; i++) {
        if (resList[i] == LANE_HML) {
            return true;
        }
    }
    return false;
}

static int32_t LaneAddHml(const char *networkId, LaneLinkType *resList, uint32_t *resNum)
{
    LaneLinkType laneList[LANE_LINK_TYPE_BUTT];
    (void)memset_s(laneList, sizeof(laneList), -1, sizeof(laneList));
    uint32_t laneNum = 0;
    for (uint32_t i = 0; i < *resNum; i++) {
        if (resList[i] == LANE_P2P && IsValidLane(networkId, LANE_HML)) {
            laneList[laneNum++] = LANE_HML;
        }
        laneList[laneNum++] = resList[i];
    }
    if (memcpy_s(resList, sizeof(laneList), laneList, sizeof(laneList)) != EOK) {
        LNN_LOGE(LNN_LANE, "resList memcpy fail");
        return SOFTBUS_MEM_ERR;
    }
    *resNum = laneNum;
    return SOFTBUS_OK;
}

int32_t SelectLane(const char *networkId, const LaneSelectParam *request,
    LanePreferredLinkList *recommendList, uint32_t *listNum)
{
    if (PreProcLaneSelect(networkId, request, recommendList, listNum) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    LaneLinkType resList[LANE_LINK_TYPE_BUTT];
    uint32_t resNum = 0;
    (void)memset_s(resList, sizeof(resList), -1, sizeof(resList));
    if ((request->list.linkTypeNum > 0) && (request->list.linkTypeNum <= LANE_LINK_TYPE_BUTT)) {
        LNN_LOGI(LNN_LANE, "Select lane by preferred linklist, networkId=%{public}s", anonyNetworkId);
        SelectByPreferredLink(networkId, request, resList, &resNum);
    } else {
        LNN_LOGI(LNN_LANE, "Select lane by default linklist, networkId=%{public}s", anonyNetworkId);
        SelectByDefaultLink(networkId, request, resList, &resNum);
    }
    AnonymizeFree(anonyNetworkId);
    if (resNum == 0) {
        LNN_LOGE(LNN_LANE, "there is none linkResource can be used");
        *listNum = 0;
        return SOFTBUS_ERR;
    }
    if (!HmlIsExist(resList, resNum) && LaneAddHml(networkId, resList, &resNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "LaneAddHml fail");
        return SOFTBUS_ERR;
    }
    if (AdjustLanePriority(networkId, request, resList, resNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "AdjustLanePriority fail");
        return SOFTBUS_ERR;
    }

    recommendList->linkTypeNum = resNum;
    for (uint32_t i = 0; i < resNum; i++) {
        recommendList->linkType[i] = resList[i];
    }
    *listNum = resNum;
    return SOFTBUS_OK;
}

static void SelectMeshLinks(const char *networkId, LaneLinkType *resList, uint32_t *resNum)
{
    LaneLinkType optionalLink[LANE_LINK_TYPE_BUTT];
    (void)memset_s(optionalLink, sizeof(optionalLink), 0, sizeof(optionalLink));
    uint32_t optLinkNum = 0;
    optionalLink[optLinkNum++] = LANE_WLAN_5G;
    optionalLink[optLinkNum++] = LANE_WLAN_2P4G;
    optionalLink[optLinkNum++] = LANE_BR;
    *resNum = 0;
    for (uint32_t i = 0; i < optLinkNum; i++) {
        if (!IsValidLane(networkId, optionalLink[i])) {
            continue;
        }
        resList[(*resNum)++] = optionalLink[i];
    }
}

static int32_t AddRecommendLinkType(LanePreferredLinkList *setRecommendLinkList,
    LaneLinkType linkType, int32_t *linkNum)
{
    if ((*linkNum) < 0 || (*linkNum) >= LANE_LINK_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "enum out of bounds");
        return SOFTBUS_ERR;
    }
    setRecommendLinkList->linkType[(*linkNum)++] = linkType;
    setRecommendLinkList->linkTypeNum = *linkNum;
    return SOFTBUS_OK;
}

int32_t SelectExpectLaneByParameter(LanePreferredLinkList *setRecommendLinkList)
{
    if (setRecommendLinkList == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int linkNum = 0;
    if (IsLinkEnabled(LANE_HML)) {
        AddRecommendLinkType(setRecommendLinkList, LANE_HML, &linkNum);
        LNN_LOGI(LNN_LANE, "hml_only = on");
        return SOFTBUS_OK;
    } else if (IsLinkEnabled(LANE_P2P)) {
        AddRecommendLinkType(setRecommendLinkList, LANE_P2P, &linkNum);
        LNN_LOGI(LNN_LANE, "p2p_only = on");
        return SOFTBUS_OK;
    } else if (IsLinkEnabled(LANE_BR)) {
        AddRecommendLinkType(setRecommendLinkList, LANE_BR, &linkNum);
        LNN_LOGI(LNN_LANE, "br_only = on");
        return SOFTBUS_OK;
    } else if (IsLinkEnabled(LANE_WLAN_5G) || IsLinkEnabled(LANE_WLAN_2P4G)) {
        AddRecommendLinkType(setRecommendLinkList, LANE_WLAN_5G, &linkNum);
        AddRecommendLinkType(setRecommendLinkList, LANE_WLAN_2P4G, &linkNum);
        LNN_LOGI(LNN_LANE, "wlan_only = on");
        return SOFTBUS_OK;
    } else if (IsLinkEnabled(LANE_COC_DIRECT)) {
        AddRecommendLinkType(setRecommendLinkList, LANE_COC_DIRECT, &linkNum);
        LNN_LOGI(LNN_LANE, "coc_only = on");
        return SOFTBUS_OK;
    } else if (IsLinkEnabled(LANE_BLE_DIRECT)) {
        AddRecommendLinkType(setRecommendLinkList, LANE_BLE_DIRECT, &linkNum);
        LNN_LOGI(LNN_LANE, "ble_only = on");
        return SOFTBUS_OK;
    } else {
        return SOFTBUS_ERR;
    }
}

static void SelectRttLinks(const char *networkId, LaneLinkType *resList, uint32_t *resNum)
{
    LaneLinkType optionalLink[LANE_LINK_TYPE_BUTT];
    (void)memset_s(optionalLink, sizeof(optionalLink), 0, sizeof(optionalLink));
    uint32_t optLinkNum = 0;
    optionalLink[optLinkNum++] = LANE_HML;
    optionalLink[optLinkNum++] = LANE_P2P;
    optionalLink[optLinkNum++] = LANE_WLAN_5G;
    optionalLink[optLinkNum++] = LANE_WLAN_2P4G;
    *resNum = 0;
    for (uint32_t i = 0; i < optLinkNum; i++) {
        if (!IsValidLane(networkId, optionalLink[i])) {
            continue;
        }
        resList[(*resNum)++] = optionalLink[i];
    }
}

int32_t SelectExpectLanesByQos(const char *networkId, const LaneSelectParam *request,
    LanePreferredLinkList *recommendList)
{
    if ((networkId == NULL) || (request == NULL) || (recommendList == NULL)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (!LnnGetOnlineStateById(networkId, CATEGORY_NETWORK_ID)) {
        char *anonyNetworkId = NULL;
        Anonymize(networkId, &anonyNetworkId);
        LNN_LOGE(LNN_LANE, "device not online, cancel selectLane by qos, networkId=%{public}s", anonyNetworkId);
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    LanePreferredLinkList laneLinkList = {0};
    if (request->qosRequire.minBW == 0 && request->qosRequire.maxLaneLatency == 0 &&
        request->qosRequire.minLaneLatency == 0) {
        LNN_LOGI(LNN_LANE, "select lane by default linkList");
        SelectByDefaultLink(networkId, request, laneLinkList.linkType, &(laneLinkList.linkTypeNum));
    } else if (request->qosRequire.minBW == MESH_MAGIC_NUMBER) {
        LNN_LOGI(LNN_LANE, "select lane by mesh linkList");
        SelectMeshLinks(networkId, laneLinkList.linkType, &(laneLinkList.linkTypeNum));
    } else if (request->qosRequire.rttLevel == LANE_RTT_LEVEL_LOW) {
        LNN_LOGI(LNN_LANE, "select lane by RTT linkList");
        SelectRttLinks(networkId, laneLinkList.linkType, &(laneLinkList.linkTypeNum));
    } else {
        LNN_LOGI(LNN_LANE, "select lane by qos require");
        if (DecideAvailableLane(networkId, request, &laneLinkList) != SOFTBUS_OK) {
            return SOFTBUS_LANE_SELECT_FAIL;
        }
    }
    recommendList->linkTypeNum = 0;
    for (uint32_t i = 0; i < laneLinkList.linkTypeNum; i++) {
        recommendList->linkType[recommendList->linkTypeNum] = laneLinkList.linkType[i];
        recommendList->linkTypeNum++;
    }
    int32_t ret = AdjustLanePriority(networkId, request, recommendList->linkType, recommendList->linkTypeNum);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "AdjustLanePriority fail");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t SelectAuthLane(const char *networkId, LanePreferredLinkList *request,
    LanePreferredLinkList *recommendList)
{
    if ((networkId == NULL) || (request == NULL) || (recommendList == NULL)) {
        return SOFTBUS_INVALID_PARAM;
    }
    recommendList->linkTypeNum = 0;
    for (uint32_t i = 0; i < request->linkTypeNum; ++i) {
        if (IsValidLane(networkId, request->linkType[i])) {
            recommendList->linkType[recommendList->linkTypeNum] = request->linkType[i];
            recommendList->linkTypeNum++;
        }
    }
    return SOFTBUS_OK;
}