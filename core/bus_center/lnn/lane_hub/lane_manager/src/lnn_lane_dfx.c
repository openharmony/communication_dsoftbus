/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lnn_lane_dfx.h"

#include "securec.h"

#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

static SoftBusList g_laneProcessInfo;

static int32_t LaneEventLock(void)
{
    return SoftBusMutexLock(&g_laneProcessInfo.lock);
}

static void LaneEventUnLock(void)
{
    (void)SoftBusMutexUnlock(&g_laneProcessInfo.lock);
}

static LaneProcess* GetLaneEventWithoutLock(uint32_t laneHandle)
{
    if (laneHandle == INVALID_LANE_REQ_ID) {
        LNN_LOGE(LNN_LANE, "laneHandle is invalid parameter");
        return NULL;
    }
    LaneProcess *laneProcess = NULL;
    LIST_FOR_EACH_ENTRY(laneProcess, &g_laneProcessInfo.list, LaneProcess, node) {
        if (laneProcess->laneProcessList32Bit[EVENT_LANE_HANDLE] == laneHandle) {
            return laneProcess;
        }
    }
    LNN_LOGE(LNN_LANE, "not found laneProcess, laneHandle=%{public}u", laneHandle);
    return NULL;
}

int32_t CreateLaneEventInfo(const LaneProcess *processInfo)
{
    if (processInfo == NULL) {
        LNN_LOGE(LNN_LANE, "param processInfo is null");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneProcess *info = (LaneProcess *)SoftBusCalloc(sizeof(LaneProcess));
    if (info == NULL) {
        LNN_LOGE(LNN_LANE, "processInfo calloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(info, sizeof(LaneProcess), processInfo, sizeof(LaneProcess)) != EOK) {
        LNN_LOGE(LNN_LANE, "copy processInfo fail");
        SoftBusFree(info);
        return SOFTBUS_MEM_ERR;
    }
    if (LaneEventLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        SoftBusFree(info);
        return SOFTBUS_LOCK_ERR;
    }
    ListAdd(&g_laneProcessInfo.list, &info->node);
    g_laneProcessInfo.cnt++;
    LaneEventUnLock();
    return SOFTBUS_OK;
}

static int32_t DeleteLaneEventInfo(uint32_t laneHandle)
{
    if (LaneEventLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneProcess *next = NULL;
    LaneProcess *item = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneProcessInfo.list, LaneProcess, node) {
        if (item->laneProcessList32Bit[EVENT_LANE_HANDLE] == laneHandle) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_laneProcessInfo.cnt--;
            LaneEventUnLock();
            return SOFTBUS_OK;
        }
    }
    LaneEventUnLock();
    LNN_LOGE(LNN_LANE, "not found laneProcess, laneHandle=%{public}u", laneHandle);
    return SOFTBUS_LANE_NOT_FOUND;
}

int32_t UpdateLaneEventInfo(uint32_t laneHandle, uint32_t eventType, LaneProcessValueType valueType, void *arg)
{
    if (arg == NULL || valueType == LANE_PROCESS_TYPE_BUTT ||
        (valueType == LANE_PROCESS_TYPE_UINT32 && eventType >= EVENT_32_BIT_BUTT) ||
        (valueType == LANE_PROCESS_TYPE_UINT64 && eventType >= EVENT_64_BIT_BUTT) ||
        laneHandle == INVALID_LANE_REQ_ID) {
        LNN_LOGE(LNN_LANE, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneProcess *info = NULL;
    if (LaneEventLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    info = GetLaneEventWithoutLock(laneHandle);
    if (info == NULL) {
        LaneEventUnLock();
        return SOFTBUS_LANE_NOT_FOUND;
    }
    if (valueType == LANE_PROCESS_TYPE_UINT32) {
        info->laneProcessList32Bit[eventType] = *((uint32_t *)arg);
    } else if (valueType == LANE_PROCESS_TYPE_UINT64) {
        info->laneProcessList64Bit[eventType] = *((uint64_t *)arg);
    }
    LaneEventUnLock();
    return SOFTBUS_OK;
}

int32_t GetLaneEventInfo(uint32_t laneHandle, LaneProcess *laneProcess)
{
    if (laneHandle == INVALID_LANE_REQ_ID || laneProcess == NULL) {
        LNN_LOGE(LNN_LANE, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneEventLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneProcess *info = NULL;
    info = GetLaneEventWithoutLock(laneHandle);
    if (info == NULL) {
        LaneEventUnLock();
        return SOFTBUS_LANE_NOT_FOUND;
    }
    if (memcpy_s(laneProcess, sizeof(LaneProcess), info, sizeof(LaneProcess)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy LaneProcess fail");
        LaneEventUnLock();
        return SOFTBUS_MEM_ERR;
    }
    LaneEventUnLock();
    return SOFTBUS_OK;
}

int32_t ReportLaneEventInfo(uint32_t laneHandle, int32_t result)
{
    if (laneHandle == INVALID_LANE_REQ_ID) {
        LNN_LOGE(LNN_LANE, "laneHandle is invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LaneEventLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneProcess info = { 0 };
    LaneProcess *laneProcess = NULL;
    laneProcess = GetLaneEventWithoutLock(laneHandle);
    if (laneProcess == NULL) {
        LaneEventUnLock();
        return SOFTBUS_LANE_NOT_FOUND;
    }
    if (memcpy_s(&info, sizeof(LaneProcess), laneProcess, sizeof(LaneProcess)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy LaneProcess fail");
        LaneEventUnLock();
        return SOFTBUS_MEM_ERR;
    }
    LaneEventUnLock();
    LnnEventExtra extra = {
        .result = EVENT_STAGE_RESULT_OK,
        .errcode = result,
        .laneStage = info.laneProcessList32Bit[EVENT_LANE_STAGE],
        .laneHandle = info.laneProcessList32Bit[EVENT_LANE_HANDLE],
        .laneId = info.laneProcessList64Bit[EVENT_LANE_ID],
        .laneLinkType = info.laneProcessList32Bit[EVENT_LANE_LINK_TYPE],
        .minBW = info.laneProcessList32Bit[EVENT_LANE_MIN_BW],
        .maxLaneLatency = info.laneProcessList32Bit[EVENT_LANE_MAX_LANE_LATENCY],
        .minLaneLatency = info.laneProcessList32Bit[EVENT_LANE_MIN_LANE_LATENCY],
        .rttLevel = info.laneProcessList32Bit[EVENT_LANE_RTT_LEVEL],
        .peerNetworkId = (const char *)info.peerNetWorkId,
        .transType = info.laneProcessList32Bit[EVENT_TRANS_TYPE],
        .localDynamicCap = info.laneProcessList32Bit[EVENT_LOCAL_CAP],
        .remoteDynamicCap = info.laneProcessList32Bit[EVENT_REMOTE_CAP],
        .onlineType = info.laneProcessList32Bit[EVENT_ONLINE_STATE],
        .guideType = info.laneProcessList32Bit[EVENT_GUIDE_TYPE],
        .isGuideRetry = info.laneProcessList32Bit[EVENT_GUIDE_RETRY],
        .wifiDetectState = info.laneProcessList32Bit[EVENT_WIFI_DETECT_STATE],
        .wifiDetectTime = info.laneProcessList64Bit[EVENT_WIFI_DETECT_TIME],
        .buildLinkTime = info.laneProcessList64Bit[EVENT_BUILD_LINK_TIME],
        .isHmlReuse = info.laneProcessList32Bit[EVENT_HML_REUSE],
        .isDelayFree = info.laneProcessList32Bit[EVENT_DELAY_FREE],
        .freeLinkTime = info.laneProcessList64Bit[EVENT_FREE_LINK_TIME],
    };
    LNN_EVENT(EVENT_SCENE_LNN, EVENT_STAGE_LNN_LANE_SELECT_END, extra);
    return DeleteLaneEventInfo(laneHandle);
}

int32_t InitLaneEvent(void)
{
    if (SoftBusMutexInit(&g_laneProcessInfo.lock, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane process info mutex init fail");
        return SOFTBUS_NO_INIT;
    }
    ListInit(&g_laneProcessInfo.list);
    g_laneProcessInfo.cnt = 0;
    return SOFTBUS_OK;
}

void DeinitLaneEvent(void)
{
    if (LaneEventLock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane lock fail");
        return;
    }
    LaneProcess *next = NULL;
    LaneProcess *item = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneProcessInfo.list, LaneProcess, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    g_laneProcessInfo.cnt = 0;
    LaneEventUnLock();
    SoftBusMutexUnlock(&g_laneProcessInfo.lock);
    (void)SoftBusMutexDestroy(&g_laneProcessInfo.lock);
}
