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

#include "common_list.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_select_rule.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

static void GetFileDefaultLink(LaneLinkType *linkList, uint32_t *listNum)
{
    linkList[(*listNum)++] = LANE_WLAN_5G;
    linkList[(*listNum)++] = LANE_P2P;
    linkList[(*listNum)++] = LANE_WLAN_2P4G;
    linkList[(*listNum)++] = LANE_BR;
}

static void GetStreamDefaultLink(LaneLinkType *linkList, uint32_t *listNum)
{
    linkList[(*listNum)++] = LANE_WLAN_5G;
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
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lane type:[%d] is not supported", transType);
            return SOFTBUS_ERR;
    }
    *linkNum = 0;
    if (memcpy_s(optLink, optLinkMaxNum * sizeof(LaneLinkType), defaultLink, sizeof(defaultLink)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy default linkList to optinal fail");
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

static bool IsValidLane(const char *networkId, LaneLinkType linkType, uint32_t expectedBw, bool isIgnoreScore)
{
    if (!IsLinkTypeValid(linkType)) {
        return false;
    }
    LinkAttribute *linkAttr = GetLinkAttrByLinkType(linkType);
    if ((linkAttr == NULL) || (linkAttr->available != true)) {
        return false;
    }
    if (linkAttr->IsEnable(networkId) != true) {
        return false;
    }
    if (isIgnoreScore) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "ignore score");
        return true;
    }

    if (linkAttr->GetLinkScore(networkId, expectedBw) <= UNACCEPT_SCORE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "curr score is unaccept, linkType:%d", linkType);
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
    LLOGD("the %u priority link: %s", priority, GetLinkTypeStrng(preferredLink));
}

static bool IsIgnoreLinkScore(const char *networkId, LaneLinkType *list, uint32_t num)
{
    if (list == NULL || num == 0) {
        return false;
    }
    NodeInfo node = {0};
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &node) != SOFTBUS_OK) {
        LLOGW("can not get peer node");
        return false;
    }
    if (node.discoveryType == (1 << (uint32_t)DISCOVERY_TYPE_WIFI)) {
        LLOGI("lnn discoveryType is only wifi");
        return true;
    }
    for (uint32_t i = 0; i < num; i++) {
        if (list[i] != LANE_WLAN_2P4G && list[i] != LANE_WLAN_5G) {
            return false;
        }
    }
    return true;
}

static void SelectByPreferredLink(const char *networkId, const LaneSelectParam *request,
    LaneLinkType *resList, uint32_t *resNum)
{
    LaneLinkType *preferredList = (LaneLinkType *)&(request->list.linkType[0]);
    uint32_t listNum = request->list.linkTypeNum;
    *resNum = 0;
    bool isIgnoreScore = IsIgnoreLinkScore(networkId, preferredList, listNum);
    for (uint32_t i = 0; i < listNum; i++) {
        if (!IsValidLane(networkId, preferredList[i], request->expectedBw, isIgnoreScore)) {
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get defaultLinkList fail");
        return;
    }
    *resNum = 0;
    for (uint32_t i = 0; i < optLinkNum; i++) {
        if (!IsValidLane(networkId, optionalLink[i], request->expectedBw, false)) {
            continue;
        }
        resList[(*resNum)++] = optionalLink[i];
    }
}

static int32_t PreProcLaneSelect(const char *networkId, const LaneSelectParam *request,
    LanePreferredLinkList *recommendList, const uint32_t *listNum)
{
    if ((networkId == NULL) || (request == NULL) || (recommendList == NULL) || (listNum == NULL)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "laneSelect params invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!LnnGetOnlineStateById(networkId, CATEGORY_NETWORK_ID)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "device not online, cancel selectLane, networkId:%s",
            AnonymizesNetworkID(networkId));
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SelectLane(const char *networkId, const LaneSelectParam *request,
    LanePreferredLinkList *recommendList, uint32_t *listNum)
{
    if (PreProcLaneSelect(networkId, request, recommendList, listNum) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    LaneLinkType resList[LANE_LINK_TYPE_BUTT];
    uint32_t resNum = 0;
    (void)memset_s(resList, sizeof(resList), -1, sizeof(resList));
    if ((request->list.linkTypeNum > 0) && (request->list.linkTypeNum <= LANE_LINK_TYPE_BUTT)) {
        LLOGI("Select lane by preferred linklist");
        SelectByPreferredLink(networkId, request, resList, &resNum);
    } else {
        LLOGI("Select lane by default linklist");
        SelectByDefaultLink(networkId, request, resList, &resNum);
    }
    if (resNum == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "there is none linkResource can be used");
        *listNum = 0;
        return SOFTBUS_ERR;
    }
    recommendList->linkTypeNum = resNum;
    for (uint32_t i = 0; i < resNum; i++) {
        recommendList->linkType[i] = resList[i];
    }
    *listNum = resNum;
    return SOFTBUS_OK;
}