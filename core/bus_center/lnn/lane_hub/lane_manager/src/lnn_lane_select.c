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
#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_common_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_link.h"
#include "lnn_log.h"
#include "lnn_select_rule.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"
#include "softbus_wifi_api_adapter.h"
#include "wifi_direct_manager.h"

#define INVALID_LINK (-1)
#define DB_MAGIC_NUMBER 0x5A5A5A5A
#define MESH_MAGIC_NUMBER 0xA5A5A5A5

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
    linkList[(*listNum)++] = LANE_COC_DIRECT;
}

static void GetBytesDefaultLink(LaneLinkType *linkList, uint32_t *listNum)
{
    linkList[(*listNum)++] = LANE_WLAN_5G;
    linkList[(*listNum)++] = LANE_WLAN_2P4G;
    linkList[(*listNum)++] = LANE_BLE;
    linkList[(*listNum)++] = LANE_BR;
    linkList[(*listNum)++] = LANE_COC_DIRECT;
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

static bool IsLinkTypeValid(LaneLinkType type)
{
    if ((type < 0) || (type >= LANE_LINK_TYPE_BUTT)) {
        return false;
    }
    return true;
}

int32_t LaneCapCheck(const char *networkId, LaneLinkType linkType)
{
    if (!IsLinkTypeValid(linkType)) {
        return SOFTBUS_INVALID_PARAM;
    }
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

int32_t GetErrCodeOfLink(const char *networkId, LaneLinkType linkType)
{
    SoftBusWifiDetailState wifiState = SoftBusGetWifiState();
    if ((linkType == LANE_WLAN_2P4G || linkType == LANE_WLAN_5G || linkType == LANE_P2P ||
        linkType == LANE_P2P_REUSE || linkType == LANE_HML) &&
        (wifiState == SOFTBUS_WIFI_STATE_INACTIVE || wifiState == SOFTBUS_WIFI_STATE_DEACTIVATING)) {
        return SOFTBUS_LANE_WIFI_OFF;
    }
    if ((linkType == LANE_BR || linkType == LANE_BLE || linkType == LANE_BLE_DIRECT || linkType == LANE_BLE_REUSE) &&
        SoftBusGetBtState() != BLE_ENABLE) {
        return SOFTBUS_LANE_BT_OFF;
    }
    return LaneCapCheck(networkId, linkType);
}

static int32_t SelectByPreferredLink(const char *networkId, const LaneSelectParam *request,
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
        if (LaneCapCheck(networkId, preferredList[i]) != SOFTBUS_OK) {
            continue;
        }
        resList[(*resNum)] = preferredList[i];
        (*resNum)++;
        DumpPreferredLink(preferredList[i], i);
    }
    if (*resNum == 0) {
        LNN_LOGE(LNN_LANE, "there is none linkResource can be used");
        return GetErrCodeOfLink(networkId, preferredList[0]);
    }
    return SOFTBUS_OK;
}

static int32_t SelectByDefaultLink(const char *networkId, const LaneSelectParam *request,
    LaneLinkType *resList, uint32_t *resNum)
{
    LaneLinkType optionalLink[LANE_LINK_TYPE_BUTT];
    (void)memset_s(optionalLink, sizeof(optionalLink), 0, sizeof(optionalLink));
    uint32_t optLinkNum = LANE_LINK_TYPE_BUTT;
    int32_t ret = GetLaneDefaultLink(request->transType, optionalLink, &optLinkNum);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get defaultLinkList fail");
        return ret;
    }
    *resNum = 0;
    for (uint32_t i = 0; i < optLinkNum; i++) {
        if (LaneCapCheck(networkId, optionalLink[i]) != SOFTBUS_OK) {
            continue;
        }
        resList[(*resNum)++] = optionalLink[i];
    }
    if (*resNum == 0) {
        LNN_LOGE(LNN_LANE, "there is none linkResource can be used");
        return GetErrCodeOfLink(networkId, optionalLink[0]);
    }
    return SOFTBUS_OK;
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
        return SOFTBUS_NETWORK_NODE_OFFLINE;
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
        resListScore[resList[i]] = linkAttr->getLinkScore(networkId, expectedBw);
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
    if (GetListScore(networkId, request->expectedBw, resList, resListScore, resNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get linklist score fail");
        return SOFTBUS_LANE_GET_LINK_SCORE_ERR;
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
        if (resList[i] == LANE_P2P && (LaneCapCheck(networkId, LANE_HML) == SOFTBUS_OK)) {
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
    int32_t ret = PreProcLaneSelect(networkId, request, recommendList, listNum);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    LaneLinkType resList[LANE_LINK_TYPE_BUTT];
    uint32_t resNum = 0;
    (void)memset_s(resList, sizeof(resList), -1, sizeof(resList));
    if ((request->list.linkTypeNum > 0) && (request->list.linkTypeNum <= LANE_LINK_TYPE_BUTT)) {
        LNN_LOGI(LNN_LANE, "Select lane by preferred linklist, networkId=%{public}s", anonyNetworkId);
        ret = SelectByPreferredLink(networkId, request, resList, &resNum);
    } else {
        LNN_LOGI(LNN_LANE, "Select lane by default linklist, networkId=%{public}s", anonyNetworkId);
        ret = SelectByDefaultLink(networkId, request, resList, &resNum);
    }
    AnonymizeFree(anonyNetworkId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "select lane fail");
        *listNum = 0;
        return ret;
    }
    if (!HmlIsExist(resList, resNum) && LaneAddHml(networkId, resList, &resNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "LaneAddHml fail");
        return SOFTBUS_LANE_SELECT_FAIL;
    }
    ret = AdjustLanePriority(networkId, request, resList, resNum);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "AdjustLanePriority fail");
        return ret;
    }
    ret = FinalDecideLinkType(networkId, resList, resNum, recommendList);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "final decide linkType fail");
        return ret;
    }
    *listNum = recommendList->linkTypeNum;
    return SOFTBUS_OK;
}

static int32_t SelectMeshLinks(const char *networkId, LaneLinkType *resList, uint32_t *resNum)
{
    LaneLinkType optionalLink[LANE_LINK_TYPE_BUTT];
    (void)memset_s(optionalLink, sizeof(optionalLink), 0, sizeof(optionalLink));
    uint32_t optLinkNum = 0;
    optionalLink[optLinkNum++] = LANE_WLAN_5G;
    optionalLink[optLinkNum++] = LANE_WLAN_2P4G;
    optionalLink[optLinkNum++] = LANE_BR;
    optionalLink[optLinkNum++] = LANE_COC_DIRECT;
    *resNum = 0;
    for (uint32_t i = 0; i < optLinkNum; i++) {
        if (LaneCapCheck(networkId, optionalLink[i]) != SOFTBUS_OK) {
            continue;
        }
        resList[(*resNum)++] = optionalLink[i];
    }
    if (*resNum == 0) {
        LNN_LOGE(LNN_LANE, "there is none linkResource can be used");
        return GetErrCodeOfLink(networkId, optionalLink[0]);
    }
    return SOFTBUS_OK;
}

static bool IsSupportP2pReuse(const char *networkId)
{
    if (networkId == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return false;
    }
    int32_t osType = 0;
    if (LnnGetOsTypeByNetworkId(networkId, &osType) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote osType fail");
        return false;
    }
    if (osType == OH_OS_TYPE) {
        LNN_LOGI(LNN_LANE, "valid os type, no need reuse p2p");
        return false;
    }
    char peerUdid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, peerUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid error");
        return false;
    }
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (FindLaneResourceByLinkType(peerUdid, LANE_P2P, &resourceItem) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "p2p not support reuse");
        return false;
    }
    return true;
}

static int32_t SelectDbLinks(const char *networkId, LaneLinkType *resList, uint32_t *resNum)
{
    LaneLinkType optionalLink[LANE_LINK_TYPE_BUTT];
    (void)memset_s(optionalLink, sizeof(optionalLink), 0, sizeof(optionalLink));
    uint32_t optLinkNum = 0;
    optionalLink[optLinkNum++] = LANE_WLAN_5G;
    optionalLink[optLinkNum++] = LANE_WLAN_2P4G;
    if (IsSupportP2pReuse(networkId)) {
        optionalLink[optLinkNum++] = LANE_P2P;
    }
    optionalLink[optLinkNum++] = LANE_BR;
    optionalLink[optLinkNum++] = LANE_COC_DIRECT;
    *resNum = 0;
    for (uint32_t i = 0; i < optLinkNum; i++) {
        if (LaneCapCheck(networkId, optionalLink[i]) != SOFTBUS_OK) {
            continue;
        }
        resList[(*resNum)++] = optionalLink[i];
    }
    if (*resNum == 0) {
        LNN_LOGE(LNN_LANE, "there is none linkResource can be used");
        return GetErrCodeOfLink(networkId, optionalLink[0]);
    }
    return SOFTBUS_OK;
}

static int32_t SelectRttLinks(const char *networkId, LaneLinkType *resList, uint32_t *resNum)
{
    LaneLinkType optionalLink[LANE_LINK_TYPE_BUTT];
    (void)memset_s(optionalLink, sizeof(optionalLink), 0, sizeof(optionalLink));
    uint32_t optLinkNum = 0;
    optionalLink[optLinkNum++] = LANE_HML;
    optionalLink[optLinkNum++] = LANE_P2P;
    optionalLink[optLinkNum++] = LANE_WLAN_5G;
    optionalLink[optLinkNum++] = LANE_WLAN_2P4G;
    LanePreferredLinkList recommendList = {0};
    int32_t ret = FinalDecideLinkType(networkId, optionalLink, optLinkNum, &recommendList);
    if (recommendList.linkTypeNum == 0) {
        LNN_LOGE(LNN_LANE, "there is none linkResource can be used, reason=%{public}d", ret);
        return GetErrCodeOfLink(networkId, optionalLink[0]);
    }
    *resNum = 0;
    for (uint32_t i = 0; i < recommendList.linkTypeNum; i++) {
        if (LaneCapCheck(networkId, recommendList.linkType[i]) != SOFTBUS_OK) {
            continue;
        }
        resList[(*resNum)++] = recommendList.linkType[i];
    }
    if (*resNum == 0) {
        LNN_LOGE(LNN_LANE, "there is none linkResource can be used");
        return GetErrCodeOfLink(networkId, optionalLink[0]);
    }
    return SOFTBUS_OK;
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
    int32_t ret = SOFTBUS_LANE_SELECT_FAIL;
    if (request->qosRequire.minBW == 0 && request->qosRequire.maxLaneLatency == 0 &&
        request->qosRequire.minLaneLatency == 0) {
        LNN_LOGI(LNN_LANE, "select lane by default linkList");
        ret = SelectByDefaultLink(networkId, request, laneLinkList.linkType, &(laneLinkList.linkTypeNum));
    } else if (request->qosRequire.minBW == MESH_MAGIC_NUMBER) {
        LNN_LOGI(LNN_LANE, "select lane by mesh linkList");
        ret = SelectMeshLinks(networkId, laneLinkList.linkType, &(laneLinkList.linkTypeNum));
    } else if (request->qosRequire.minBW == DB_MAGIC_NUMBER) {
        LNN_LOGI(LNN_LANE, "select lane by db linkList");
        ret = SelectDbLinks(networkId, laneLinkList.linkType, &(laneLinkList.linkTypeNum));
    } else if (request->qosRequire.rttLevel == LANE_RTT_LEVEL_LOW) {
        LNN_LOGI(LNN_LANE, "select lane by RTT linkList");
        ret = SelectRttLinks(networkId, laneLinkList.linkType, &(laneLinkList.linkTypeNum));
    } else {
        LNN_LOGI(LNN_LANE, "select lane by qos require");
        ret = DecideAvailableLane(networkId, request, &laneLinkList);
    }
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane select fail");
        return ret;
    }
    recommendList->linkTypeNum = 0;
    for (uint32_t i = 0; i < laneLinkList.linkTypeNum; i++) {
        recommendList->linkType[recommendList->linkTypeNum] = laneLinkList.linkType[i];
        recommendList->linkTypeNum++;
    }
    ret = AdjustLanePriority(networkId, request, recommendList->linkType, recommendList->linkTypeNum);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "AdjustLanePriority fail");
        return ret;
    }
    return SOFTBUS_OK;
}

static bool IsAuthReuseWifiDirect(const char *networkId, LaneLinkType linkType)
{
    char udid[UDID_BUF_LEN] = {0};
    if (LnnGetRemoteStrInfo(networkId, STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get peer udid fail");
        return false;
    }
    LaneResource resoureItem;
    if (memset_s(&resoureItem, sizeof(LaneResource), 0, sizeof(LaneResource)) != EOK) {
        LNN_LOGE(LNN_LANE, "memset_s LaneResource fail");
        return false;
    }
    if (linkType == LANE_HML && FindLaneResourceByLinkType(udid, LANE_HML, &resoureItem) == SOFTBUS_OK &&
        !GetWifiDirectManager()->isNegotiateChannelNeeded(networkId, WIFI_DIRECT_LINK_TYPE_HML)) {
        LNN_LOGI(LNN_LANE, "can use HML");
        return true;
    } else if (linkType == LANE_P2P && FindLaneResourceByLinkType(udid, LANE_P2P, &resoureItem) == SOFTBUS_OK &&
        !GetWifiDirectManager()->isNegotiateChannelNeeded(networkId, WIFI_DIRECT_LINK_TYPE_P2P)) {
        LNN_LOGI(LNN_LANE, "can use P2P");
        return true;
    } else {
        return false;
    }
}

int32_t SelectAuthLane(const char *networkId, LanePreferredLinkList *request, LanePreferredLinkList *recommendList)
{
    if ((networkId == NULL) || (request == NULL) || (recommendList == NULL)) {
        return SOFTBUS_INVALID_PARAM;
    }
    recommendList->linkTypeNum = 0;
    for (uint32_t i = 0; i < request->linkTypeNum; ++i) {
        if ((request->linkType[i] == LANE_HML || request->linkType[i] == LANE_P2P) &&
            !IsAuthReuseWifiDirect(networkId, request->linkType[i])) {
            continue;
        }
        if (LaneCapCheck(networkId, request->linkType[i]) == SOFTBUS_OK) {
            recommendList->linkType[recommendList->linkTypeNum] = request->linkType[i];
            recommendList->linkTypeNum++;
        }
    }
    if (recommendList->linkTypeNum == 0) {
        LNN_LOGE(LNN_LANE, "no available link resources");
        return SOFTBUS_LANE_NO_AVAILABLE_LINK;
    }
    return SOFTBUS_OK;
}