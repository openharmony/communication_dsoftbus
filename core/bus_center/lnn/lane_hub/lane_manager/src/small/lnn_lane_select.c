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
