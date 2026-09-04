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

#include "lnn_trans_free_lane.h"

#include <securec.h>

#include "lnn_log.h"

#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_trans_lane.h"

typedef enum {
    NOTIFY_TYPE_NORMAL,
    NOTIFY_TYPE_FREE_BEFORE_ALLOC_SUCC,
    NOTIFY_TYPE_ALLOC_SUCC_AFTER_FREE,
    NOTIFY_TYPE_ALLOC_SUCC_AFTER_CANCEL,
    NOTIFY_TYPE_UNUSED,
    NOTIFY_TYPE_UNKNOWN,
} NotifyFreeType;

void HandleNotifyFreeLaneResult(SoftBusMessage *msg)
{
    if (msg == NULL) {
        LNN_LOGE(LNN_LANE, "invalid parameter");
        return;
    }
    uint32_t laneReqId = (uint32_t)msg->arg1;
    int32_t errCode = (int32_t)msg->arg2;
    LNN_LOGI(LNN_LANE, "handle notify free lane result, laneReqId=%{public}u, errCode=%{public}d",
        laneReqId, errCode);
    NotifyFreeLaneResult(laneReqId, errCode);
}

static void NotifyFreeLaneCallback(const TransReqInfo *reqInfo, int32_t errCode)
{
    if (!reqInfo->isWithQos || !reqInfo->notifyFree || reqInfo->hasNotifiedFree) {
        LNN_LOGW(LNN_LANE, "not need notify, isWithQos=%{public}d, notifyFree=%{public}d, hasNotifiedFree=%{public}d",
            reqInfo->isWithQos, reqInfo->notifyFree, reqInfo->hasNotifiedFree);
        return;
    }
    UpdateFreeLaneStatus(reqInfo->laneReqId);
    if (errCode == SOFTBUS_OK && reqInfo->listener.onLaneFreeSuccess != NULL) {
        reqInfo->listener.onLaneFreeSuccess(reqInfo->laneReqId);
    } else if (errCode != SOFTBUS_OK && reqInfo->listener.onLaneFreeFail != NULL) {
        reqInfo->listener.onLaneFreeFail(reqInfo->laneReqId, errCode);
    }
}

static NotifyFreeType GetFreeLaneType(const TransReqInfo *reqInfo, int32_t errCode)
{
    if (!reqInfo->notifyFree) {
        if (reqInfo->isWithQos && reqInfo->isCanceled) {
            return NOTIFY_TYPE_ALLOC_SUCC_AFTER_CANCEL;
        }
        return NOTIFY_TYPE_UNUSED;
    }
    if (errCode == SOFTBUS_LANE_ALLOC_NOT_COMPLETED) {
        return NOTIFY_TYPE_FREE_BEFORE_ALLOC_SUCC;
    }
    if (!reqInfo->isNotified) {
        return NOTIFY_TYPE_ALLOC_SUCC_AFTER_FREE;
    }
    return NOTIFY_TYPE_NORMAL;
}

void NotifyFreeLaneResult(uint32_t laneReqId, int32_t errCode)
{
    TransReqInfo reqInfo;
    (void)memset_s(&reqInfo, sizeof(TransReqInfo), 0, sizeof(TransReqInfo));
    if (GetTransReqInfoByLaneReqId(laneReqId, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get trans req info fail, laneReqId=%{public}u", laneReqId);
        return;
    }
    NotifyFreeType type = GetFreeLaneType(&reqInfo, errCode);
    switch (type) {
        case NOTIFY_TYPE_FREE_BEFORE_ALLOC_SUCC: {
            LNN_LOGI(LNN_LANE, "free unfinished link only notify success, laneReqId=%{public}u", laneReqId);
            NotifyFreeLaneCallback(&reqInfo, SOFTBUS_OK);
            break;
        }
        case NOTIFY_TYPE_ALLOC_SUCC_AFTER_FREE: {
            LNN_LOGI(LNN_LANE, "free abandoned link, try notify and free reqInfo, laneReqId=%{public}u", laneReqId);
            NotifyFreeLaneCallback(&reqInfo, errCode);
            DeleteRequestNode(laneReqId);
            FreeLaneReqId(laneReqId);
            break;
        }
        case NOTIFY_TYPE_ALLOC_SUCC_AFTER_CANCEL: {
            LNN_LOGI(LNN_LANE, "free canceled link, clear reqInfo, laneReqId=%{public}u", laneReqId);
            DeleteRequestNode(laneReqId);
            FreeLaneReqId(laneReqId);
            break;
        }
        case NOTIFY_TYPE_UNUSED:
            LNN_LOGI(LNN_LANE, "free unused link do nothing, laneReqId=%{public}u", laneReqId);
            break;
        case NOTIFY_TYPE_NORMAL: {
            LNN_LOGI(LNN_LANE, "notify free lane result, laneReqId=%{public}d, errCode=%{public}d", laneReqId, errCode);
            NotifyFreeLaneCallback(&reqInfo, errCode);
            DeleteRequestNode(laneReqId);
            FreeLaneReqId(laneReqId);
            break;
        }
        default: {
            LNN_LOGE(LNN_LANE, "laneReqId=%{public}u, errCode=%{public}d, isWithQos=%{public}d, isCanceled=%{public}d, "
                "isNotified=%{public}d, notifyFree=%{public}d, hasNotifiedFree=%{public}d",
                laneReqId, errCode, reqInfo.isWithQos, reqInfo.isCanceled, reqInfo.isNotified,
                reqInfo.notifyFree, reqInfo.hasNotifiedFree);
            break;
        }
    }
}

static int32_t FreeLink(uint32_t laneReqId, uint64_t laneId, LaneType type)
{
    (void)type;
    (void)laneId;
    // wlan link no need to DestoryLink
    return PostNotifyFreeLaneResult(laneReqId, SOFTBUS_OK, 0);
}

int32_t FreeLane(uint32_t laneReqId)
{
    if (laneReqId == INVALID_LANE_REQ_ID) {
        LNN_LOGE(LNN_LANE, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    TransReqInfo transReqInfo;
    (void)memset_s(&transReqInfo, sizeof(TransReqInfo), 0, sizeof(TransReqInfo));
    int32_t ret = UpdateAndGetReqInfoByFree(laneReqId, &transReqInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get transReqInfo fail, ret=%{public}d laneReqId=%{public}d", ret, laneReqId);
        FreeLaneReqId(laneReqId);
        return ret;
    }
    if (transReqInfo.laneId == INVALID_LANE_ID) {
        LNN_LOGE(LNN_LANE, "allocLane not completed laneReqId=%{public}d", laneReqId);
        return PostNotifyFreeLaneResult(laneReqId, SOFTBUS_LANE_ALLOC_NOT_COMPLETED, 0);
    }
    LaneType type = (LaneType)(laneReqId >> LANE_REQ_ID_TYPE_SHIFT);
    ret = FreeLink(laneReqId, transReqInfo.laneId, type);
    if (ret != SOFTBUS_OK) {
        DeleteRequestNode(laneReqId);
        FreeLaneReqId(laneReqId);
    }
    return ret;
}

void FreeUnusedLink(uint32_t laneReqId, const LaneLinkInfo *linkInfo)
{
    if (laneReqId == INVALID_LANE_REQ_ID || linkInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid parameter");
        return;
    }
    LNN_LOGI(LNN_LANE, "free unused link, laneReqId=%{public}u, linkType=%{public}d", laneReqId, linkInfo->type);
}
