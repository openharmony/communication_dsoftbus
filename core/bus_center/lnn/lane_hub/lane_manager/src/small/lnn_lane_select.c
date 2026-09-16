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

#include "lnn_lane_select.h"

#include <securec.h>

#include "anonymizer.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_link.h"
#include "lnn_log.h"
#include "lnn_select_rule.h"
#include "softbus_wifi_api_adapter.h"

static void DumpPreferredLink(LaneLinkType preferredLink, uint32_t priority)
{
    LNN_LOGD(LNN_LANE, "priority=%{public}u, linkType=%{public}d", priority, preferredLink);
}

int32_t GetErrCodeOfLink(const char *networkId, LaneLinkType linkType)
{
    SoftBusWifiDetailState wifiState = SoftBusGetWifiState();
    if ((linkType == LANE_WLAN_2P4G || linkType == LANE_WLAN_5G || linkType == LANE_P2P ||
        linkType == LANE_P2P_REUSE || linkType == LANE_HML) &&
        (wifiState == SOFTBUS_WIFI_STATE_INACTIVE || wifiState == SOFTBUS_WIFI_STATE_DEACTIVATING)) {
        return SOFTBUS_LANE_WIFI_OFF;
    }
    return LaneCheckLinkValid(networkId, linkType, LANE_T_BUTT);
}

static int32_t SelectByPreferredLink(const char *networkId, const LaneSelectParam *request,
    LaneLinkType *resList, uint32_t *resNum)
{
    LaneLinkType *preferredList = (LaneLinkType *)&(request->list.linkType[0]);
    uint32_t listNum = request->list.linkTypeNum;
    *resNum = 0;
    for (uint32_t i = 0; i < listNum; i++) {
        if (LaneCheckLinkValid(networkId, preferredList[i], request->transType) != SOFTBUS_OK) {
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
        LNN_LOGE(LNN_LANE, "device not online, cancel selectLane, networkId=%{public}s",
            AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
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
        LNN_LOGI(LNN_LANE, "Select lane by preferred linklist, networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
        ret = SelectByPreferredLink(networkId, request, resList, &resNum);
    } else {
        LNN_LOGI(LNN_LANE, "Select lane by default linklist, networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
        ret = DecideDefaultLink(networkId, request->transType, resList, &resNum);
    }
    AnonymizeFree(anonyNetworkId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "select lane fail");
        *listNum = 0;
        return ret;
    }

    recommendList->linkTypeNum = 0;
    for (uint32_t i = 0; i < resNum; i++) {
        recommendList->linkType[recommendList->linkTypeNum] = resList[i];
        recommendList->linkTypeNum++;
    }
    *listNum = recommendList->linkTypeNum;
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
        LNN_LOGE(LNN_LANE, "device not online, cancel selectLane by qos, networkId=%{public}s",
            AnonymizeWrapper(anonyNetworkId));
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    LanePreferredLinkList laneLinkList = {0};
    LNN_LOGI(LNN_LANE, "select lane by qos require");
    int32_t ret = DecideAvailableLane(networkId, request, &laneLinkList);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane select fail");
        return ret;
    }
    recommendList->linkTypeNum = 0;
    for (uint32_t i = 0; i < laneLinkList.linkTypeNum; i++) {
        recommendList->linkType[recommendList->linkTypeNum] = laneLinkList.linkType[i];
        recommendList->linkTypeNum++;
    }
    return SOFTBUS_OK;
}
