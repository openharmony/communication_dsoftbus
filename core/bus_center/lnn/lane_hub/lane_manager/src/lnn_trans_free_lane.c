/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "g_enhance_lnn_func.h"
#include "g_enhance_lnn_func_pack.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_dfx.h"
#include "lnn_lane_interface.h"
#include "lnn_log.h"
#include "lnn_trans_lane.h"

#define DELAY_DESTROY_LANE_TIME 5000

void HandelNotifyFreeLaneResult(SoftBusMessage *msg)
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

static uint64_t GetCostTime(uint64_t triggerLinkTime)
{
    uint64_t currentSysTime = SoftBusGetSysTimeMs();
    if (currentSysTime < triggerLinkTime) {
        LNN_LOGE(LNN_LANE, "get cost time fail");
        return 0;
    }
    return currentSysTime - triggerLinkTime;
}

static void UpdateLaneEventWithFreeLinkTime(uint32_t laneHandle)
{
    LaneProcess laneProcess;
    (void)memset_s(&laneProcess, sizeof(LaneProcess), 0, sizeof(LaneProcess));
    if (GetLaneEventInfo(laneHandle, &laneProcess) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get laneProcess fail, laneHandle=%{public}u", laneHandle);
        return;
    }
    uint64_t freeLinkTime = GetCostTime(laneProcess.laneProcessList64Bit[EVENT_COST_TIME]);
    UpdateLaneEventInfo(laneHandle, EVENT_COST_TIME, LANE_PROCESS_TYPE_UINT64, (void *)(&freeLinkTime));
}

static void ReportLaneEventWithFreeLinkInfo(uint32_t laneReqId, int32_t errCode)
{
    UpdateLaneEventWithFreeLinkTime(laneReqId);
    if (errCode == SOFTBUS_OK) {
        (void)ReportLaneEventInfo(EVENT_STAGE_LANE_FREE, laneReqId, errCode);
    } else {
        (void)ReportLaneEventInfo(EVENT_STAGE_LANE_FREE, laneReqId, errCode);
    }
}

static void NotifyFreeLaneCallback(const TransReqInfo *reqInfo, int32_t errCode)
{
    if (reqInfo->isWithQos && reqInfo->notifyFree && !reqInfo->hasNotifiedFree) {
        UpdateFreeLaneStatus(reqInfo->laneReqId);
        if (errCode == SOFTBUS_OK && reqInfo->listener.onLaneFreeSuccess != NULL) {
            reqInfo->listener.onLaneFreeSuccess(reqInfo->laneReqId);
        } else if (errCode != SOFTBUS_OK && reqInfo->listener.onLaneFreeFail != NULL) {
            reqInfo->listener.onLaneFreeFail(reqInfo->laneReqId, errCode);
        }
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
    if (laneReqId == INVALID_LANE_REQ_ID) {
        LNN_LOGE(LNN_LANE, "invalid parameter");
        return;
    }
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
            LNN_LOGI(LNN_LANE, "free abandoned link only try notify and clear reqInfo, laneReqId=%{public}u, errCode=%{public}d",
                laneReqId, type, errCode);
            NotifyFreeLaneCallback(&reqInfo, errCode);
            DeleteRequestNode(laneReqId);
            FreeLaneReqId(laneReqId);
            break;
        }
        case NOTIFY_TYPE_ALLOC_SUCC_AFTER_CANCEL: {
            LNN_LOGI(LNN_LANE, "free canceled link only clear reqInfo, laneReqId=%{public}u, type=%{public}d, "
                "errCode=%{public}d", laneReqId, type, errCode);
            DeleteRequestNode(laneReqId);
            FreeLaneReqId(laneReqId);
            break;
        }
        case NOTIFY_TYPE_UNUSED: {
            LNN_LOGI(LNN_LANE, "free unused link do nothing, laneReqId=%{public}u, errCode=%{public}d",
                laneReqId, errCode);
            break;
        }
        case NOTIFY_TYPE_NORMAL: {
            LNN_LOGI(LNN_LANE, "notify free lane result, laneReqId=%{public}d, errCode=%{public}d", laneReqId, errCode);
            ReportLaneEventWithFreeLinkInfo(laneReqId, errCode);
            DelLaneResourceByLaneId(reqInfo.laneId, false);
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

static void AsyncNotifyWhenDelayFree(uint32_t laneReqId)
{
    LNN_LOGI(LNN_LANE, "handle notify free lane succ, laneReqId=%{public}u", laneReqId);
    TransReqInfo reqInfo;
    (void)memset_s(&reqInfo, sizeof(TransReqInfo), 0, sizeof(TransReqInfo));
    UpdateLaneEventWithFreeLinkTime(laneReqId);
    (void)ReportLaneEventInfo(EVENT_STAGE_LANE_FREE, laneReqId, SOFTBUS_OK);
    if (GetTransReqInfoByLaneReqId(laneReqId, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get trans req info fail");
        return;
    }
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (FindLaneResourceByLaneId(reqInfo.laneId, &resourceItem) != SOFTBUS_OK) {
        return;
    }
    if (resourceItem.link.type == LANE_HML) {
        if (reqInfo.isWithQos && reqInfo.listener.onLaneFreeSuccess != NULL) {
            UpdateFreeLaneStatus(laneReqId);
            reqInfo.listener.onLaneFreeSuccess(laneReqId);
        }
    } else {
        DelLaneResourceByLaneId(reqInfo.laneId, false);
        if (reqInfo.isWithQos && reqInfo.listener.onLaneFreeSuccess != NULL) {
            UpdateFreeLaneStatus(laneReqId);
            reqInfo.listener.onLaneFreeSuccess(laneReqId);
        }
        DeleteRequestNode(laneReqId);
        FreeLaneReqId(laneReqId);
    }
}

static int32_t FreeLaneLink(uint32_t laneReqId, uint64_t laneId)
{
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (FindLaneResourceByLaneId(laneId, &resourceItem) != SOFTBUS_OK) {
        return PostNotifyFreeLaneResult(laneReqId, SOFTBUS_OK, 0);
    }
    if (resourceItem.link.type == LANE_HML_RAW) {
        LNN_LOGI(LNN_LANE, "del flag for raw hml laneReqId=%{public}u", laneReqId);
        (void)RemoveAuthSessionServer(resourceItem.link.linkInfo.rawWifiDirect.peerIp);
    }
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetNetworkIdByUdid(resourceItem.link.peerUdid, networkId, sizeof(networkId));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get networkId fail, ret=%{public}d", ret);
    }
    return DestroyLink(networkId, laneReqId, resourceItem.link.type);
}

void HandleDelayDestroyLink(SoftBusMessage *msg)
{
    if (msg == NULL) {
        LNN_LOGE(LNN_LANE, "invalid parameter");
        return;
    }
    uint32_t laneReqId = (uint32_t)msg->arg1;
    uint64_t laneId = (uint64_t)msg->arg2;
    LNN_LOGI(LNN_LANE, "handle delay destroy message, laneReqId=%{public}u, laneId=%{public}" PRIu64 "",
        laneReqId, laneId);
    if (laneId == INVALID_LANE_ID) {
        AsyncNotifyWhenDelayFree(laneReqId);
        return;
    }
    int32_t ret = FreeLaneLink(laneReqId, laneId);
    if (ret != SOFTBUS_OK) {
        NotifyFreeLaneResult(laneReqId, ret);
    }
}

static bool GetAuthType(const char *peerNetWorkId)
{
    int32_t value = 0;
    int32_t ret = LnnGetRemoteNumInfo(peerNetWorkId, NUM_KEY_META_NODE, &value);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get mate node info fail, ret=%{public}d", ret);
        return false;
    }
    LNN_LOGD(LNN_LANE, "get mate node info success, value=%{public}d", value);
    return ((1 << ONLINE_HICHAIN) == value);
}

static void IsNeedDelayFreeLane(uint32_t laneReqId, uint64_t laneId, bool *isDelayFree)
{
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (FindLaneResourceByLaneId(laneId, &resourceItem) != SOFTBUS_OK) {
        *isDelayFree = false;
        return;
    }
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (LnnConvertDlId(resourceItem.link.peerUdid, CATEGORY_UDID, CATEGORY_NETWORK_ID,
        networkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "LnnConvertDlId fail");
        *isDelayFree = false;
        return;
    }

    bool isHichain = GetAuthType(networkId);
    LNN_LOGD(LNN_LANE, "isHichain=%{public}d", isHichain);
    if (resourceItem.link.type == LANE_HML && resourceItem.clientRef == 1 && isHichain &&
        !HaveConcurrencyPreLinkNodeByLaneReqIdPacked(laneReqId, true) &&
        CheckLinkConflictByReleaseLink(resourceItem.link.type) != SOFTBUS_OK &&
        !CheckVirtualLinkByLaneReqId(laneReqId)) {
        if (PostDelayDestroyMessage(laneReqId, laneId, DELAY_DESTROY_LANE_TIME) == SOFTBUS_OK) {
            *isDelayFree = true;
            return;
        }
    }
    *isDelayFree = false;
    return;
}

static int32_t FreeLink(uint32_t laneReqId, uint64_t laneId, LaneType type)
{
    (void)DelLaneBusinessInfoItem(type, laneId);
    bool isDelayDestroy = false;
    IsNeedDelayFreeLane(laneReqId, laneId, &isDelayDestroy);
    LNN_LOGI(LNN_LANE, "free lane, laneReqId=%{public}u, laneId=%{public}" PRIu64 ", delayDestroy=%{public}s",
        laneReqId, laneId, isDelayDestroy ? "true" : "false");
    if (isDelayDestroy) {
        uint32_t isDelayFree = (uint32_t)(isDelayDestroy);
        UpdateLaneEventInfo(laneReqId, EVENT_DELAY_FREE,
            LANE_PROCESS_TYPE_UINT32, (void *)(&isDelayFree));
        PostDelayDestroyMessage(laneReqId, INVALID_LANE_ID, 0);
        return SOFTBUS_OK;
    }
    return FreeLaneLink(laneReqId, laneId);
}

static void InitFreeLaneProcess(uint32_t laneReqId, uint64_t freeLinkStartTime)
{
    LaneProcess processInfo;
    (void)memset_s(&processInfo, sizeof(LaneProcess), 0, sizeof(LaneProcess));
    processInfo.laneProcessList32Bit[EVENT_LANE_HANDLE] = laneReqId;
    processInfo.laneProcessList64Bit[EVENT_COST_TIME] = freeLinkStartTime;
    TransReqInfo reqInfo;
    (void)memset_s(&reqInfo, sizeof(TransReqInfo), 0, sizeof(TransReqInfo));
    if (GetTransReqInfoByLaneReqId(laneReqId, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get transReqInfo fail, laneHandle=%{public}u", laneReqId);
        return;
    }
    if (memcpy_s(processInfo.peerNetWorkId, NETWORK_ID_BUF_LEN,
        reqInfo.allocInfo.networkId, NETWORK_ID_BUF_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "peerNetWorkId memcpy fail");
        return;
    }
    CreateLaneEventInfo(&processInfo);
}

int32_t FreeLane(uint32_t laneReqId)
{
    if (laneReqId == INVALID_LANE_REQ_ID) {
        LNN_LOGE(LNN_LANE, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    uint64_t freeLinkStartTime = SoftBusGetSysTimeMs();
    InitFreeLaneProcess(laneReqId, freeLinkStartTime);
    TransReqInfo transReqInfo;
    (void)memset_s(&transReqInfo, sizeof(TransReqInfo), 0, sizeof(TransReqInfo));
    int32_t ret = UpdateAndGetReqInfoByFree(laneReqId, &transReqInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get transReqInfo fail, ret=%{public}d laneReqId=%{public}d", ret, laneReqId);
        FreeLaneReqId(laneReqId);
        ReportLaneEventWithFreeLinkInfo(laneReqId, ret);
        return ret;
    }
    if (transReqInfo.laneId == INVALID_LANE_ID) {
        LNN_LOGE(LNN_LANE, "allocLane not completed laneReqId=%{public}d", laneReqId);
        ReportLaneEventWithFreeLinkInfo(laneReqId, ret);
        return PostNotifyFreeLaneResult(laneReqId, SOFTBUS_LANE_ALLOC_NOT_COMPLETED, 0);
    }
    LaneType type = (LaneType)(laneReqId >> LANE_REQ_ID_TYPE_SHIFT);
    ret = FreeLink(laneReqId, transReqInfo.laneId, type);
    if (ret != SOFTBUS_OK) {
        DeleteRequestNode(laneReqId);
        FreeLaneReqId(laneReqId);
        ReportLaneEventWithFreeLinkInfo(laneReqId, ret);
    }
    return ret;
}

void FreeUnusedLink(uint32_t laneReqId, const LaneLinkInfo *linkInfo)
{
    if (laneReqId == INVALID_LANE_REQ_ID || linkInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid parameter");
        return;
    }
    LNN_LOGI(LNN_LANE, "free unused link, laneReqId=%{public}u", laneReqId);
    if (linkInfo->type == LANE_P2P || linkInfo->type == LANE_HML) {
        char networkId[NETWORK_ID_BUF_LEN] = {0};
        if (LnnGetNetworkIdByUdid(linkInfo->peerUdid, networkId, sizeof(networkId)) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "get networkId fail, laneReqId=%{public}u", laneReqId);
            return;
        }
        LnnDisconnectP2p(networkId, laneReqId);
    }
}

void ReleaseUndeliverableLink(uint32_t laneReqId, uint64_t laneId)
{
    if (laneReqId == INVALID_LANE_REQ_ID || laneId == INVALID_LANE_ID) {
        LNN_LOGE(LNN_LANE, "invalid parameter");
        return;
    }
    int32_t ret = FreeLaneLink(laneReqId, laneId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "release link fail, laneReqId=%{public}u, ret=%{public}d", laneReqId, ret);
    }
}