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

#include "lnn_lane.h"

#include <securec.h>
#include <string.h>

#include "anonymizer.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_log.h"
#include "lnn_select_rule.h"
#include "lnn_trans_lane.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

#define ID_SHIFT_STEP 5
#define ID_CALC_MASK 0x1F
#define IS_USED 1
#define IS_NOT_USED 0
#define LANE_REQ_ID_BITMAP_COUNT ((MAX_LANE_REQ_ID_NUM + ID_CALC_MASK) >> ID_SHIFT_STEP)
#define LANE_REQ_RANDOM_ID_MASK 0xFFFFFFF

static uint32_t g_laneReqIdBitmap[LANE_REQ_ID_BITMAP_COUNT];
static SoftBusMutex g_laneMutex;
static uint32_t g_laneReqId = 0;
static LaneInterface *g_laneObject[LANE_TYPE_BUTT];

static int32_t Lock(void)
{
    return SoftBusMutexLock(&g_laneMutex);
}

static void Unlock(void)
{
    (void)SoftBusMutexUnlock(&g_laneMutex);
}

/*
 *  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  type |          randomId(1 ~ MAX_LANE_REQ_ID_NUM)                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static uint32_t AllocLaneReqId(LaneType type)
{
    if (Lock() != SOFTBUS_OK) {
        return INVALID_LANE_REQ_ID;
    }
    uint32_t laneReqId;
    uint32_t randomId;
    uint32_t idIndex = (g_laneReqId + 1) % MAX_LANE_REQ_ID_NUM;
    while (true) {
        if (((g_laneReqIdBitmap[idIndex >> ID_SHIFT_STEP] >> (idIndex & ID_CALC_MASK)) & IS_USED) == IS_NOT_USED) {
            g_laneReqIdBitmap[idIndex >> ID_SHIFT_STEP] |= (IS_USED << (idIndex & ID_CALC_MASK));
            g_laneReqId = idIndex;
            randomId = idIndex + 1;
            laneReqId = randomId | ((uint32_t)type << LANE_REQ_ID_TYPE_SHIFT);
            Unlock();
            return laneReqId;
        }
        if (idIndex == g_laneReqId) {
            break;
        }
        idIndex = (idIndex + 1) % MAX_LANE_REQ_ID_NUM;
    }
    Unlock();
    LNN_LOGE(LNN_LANE, "laneReqId num exceeds the limit");
    return INVALID_LANE_REQ_ID;
}

static void DestroyLaneReqId(uint32_t laneReqId)
{
    uint32_t randomId = laneReqId & LANE_REQ_RANDOM_ID_MASK;
    if ((randomId == INVALID_LANE_REQ_ID) || (randomId > MAX_LANE_REQ_ID_NUM)) {
        LNN_LOGE(LNN_LANE, "[DestroyLaneReqId]invalid laneReqId");
        return;
    }
    if (Lock() != SOFTBUS_OK) {
        return;
    }
    LNN_LOGD(LNN_LANE, "destroy laneReqId=%{public}u", laneReqId);
    uint32_t idIndex = randomId - 1;
    g_laneReqIdBitmap[idIndex >> ID_SHIFT_STEP] &= (~(IS_USED << (idIndex & ID_CALC_MASK)));
    Unlock();
}

static bool RequestInfoCheck(const LaneRequestOption *request, const ILaneListener *listener)
{
    if ((request == NULL) || (listener == NULL)) {
        return false;
    }
    if ((request->type >= LANE_TYPE_BUTT) || (request->type < 0)) {
        LNN_LOGE(LNN_LANE, "laneType is invalid. type=%{public}d", request->type);
        return false;
    }
    return true;
}

static bool AllocInfoCheck(const LaneAllocInfo *allocInfo, const LaneAllocListener *listener)
{
    if ((allocInfo == NULL) || (listener == NULL)) {
        return false;
    }
    if ((allocInfo->type >= LANE_TYPE_BUTT) || (allocInfo->type < 0)) {
        LNN_LOGE(LNN_LANE, "laneType is invalid. type=%{public}d", allocInfo->type);
        return false;
    }
    return true;
}

/* return laneReqId if the operation is successful, return 0 otherwise. */
uint32_t ApplyLaneReqId(LaneType type)
{
    return AllocLaneReqId(type);
}

void FreeLaneReqId(uint32_t laneReqId)
{
    return DestroyLaneReqId(laneReqId);
}

static int32_t LnnAllocLane(uint32_t laneReqId, const LaneAllocInfo *allocInfo, const LaneAllocListener *listener)
{
    if (!AllocInfoCheck(allocInfo, listener)) {
        LNN_LOGE(LNN_LANE, "lane alloc info invalid");
        FreeLaneReqId(laneReqId);
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_laneObject[allocInfo->type] == NULL) {
        LNN_LOGE(LNN_LANE, "laneType is not supported. laneType=%{public}d", allocInfo->type);
        FreeLaneReqId(laneReqId);
        return SOFTBUS_INVALID_PARAM;
    }
    LNN_LOGI(LNN_LANE, "alloc lane enter, laneReqId=%{public}u, laneType=%{public}d, transType=%{public}d, "
        "minBW=%{public}u, maxLaneLatency=%{public}u, minLaneLatency=%{public}u",
        laneReqId, allocInfo->type, allocInfo->transType,
        allocInfo->qosRequire.minBW,
        allocInfo->qosRequire.maxLaneLatency,
        allocInfo->qosRequire.minLaneLatency);
    int32_t result = g_laneObject[allocInfo->type]->allocLaneByQos(laneReqId, allocInfo, listener);
    if (result != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "alloc lane fail, laneReqId=%{public}u, result=%{public}d", laneReqId, result);
        FreeLaneReqId(laneReqId);
        return result;
    }
    return SOFTBUS_OK;
}

static int32_t CheckLaneObject(uint32_t laneReqId, LaneType *type)
{
    *type = laneReqId >> LANE_REQ_ID_TYPE_SHIFT;
    if (*type >= LANE_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "laneType invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_laneObject[*type] == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static int32_t LnnCancelLane(uint32_t laneReqId)
{
    LaneType type;
    if (CheckLaneObject(laneReqId, &type) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "laneType invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    LNN_LOGD(LNN_LANE, "cancel lane enter, laneReqId=%{public}u", laneReqId);
    int32_t result = g_laneObject[type]->cancelLane(laneReqId);
    if (result != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "cancelLane fail, result=%{public}d", result);
        return result;
    }
    return SOFTBUS_OK;
}

static int32_t LnnFreeLink(uint32_t laneReqId)
{
    LaneType type;
    if (CheckLaneObject(laneReqId, &type) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "laneType invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    LNN_LOGD(LNN_LANE, "free lane enter, laneReqId=%{public}u", laneReqId);
    int32_t result = g_laneObject[type]->freeLane(laneReqId);
    if (result != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "freeLane fail, result=%{public}d", result);
        return result;
    }
    return SOFTBUS_OK;
}

static LnnLaneManager g_laneManager = {
    .lnnGetLaneHandle = ApplyLaneReqId,
    .lnnAllocLane = LnnAllocLane,
    .lnnCancelLane = LnnCancelLane,
    .lnnFreeLane = LnnFreeLink,
};

LnnLaneManager *GetLaneManager(void)
{
    return &g_laneManager;
}

int32_t LnnFreeLane(uint32_t laneReqId)
{
    LaneType type;
    if (CheckLaneObject(laneReqId, &type) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "laneType invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    LNN_LOGD(LNN_LANE, "free lane enter, laneReqId=%{public}u", laneReqId);
    int32_t result = g_laneObject[type]->freeLane(laneReqId);
    if (result != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "freeLane fail, result=%{public}d", result);
        return result;
    }
    return SOFTBUS_OK;
}

int32_t InitLane(void)
{
    if (SoftBusMutexInit(&g_laneMutex, NULL) != SOFTBUS_OK) {
        return SOFTBUS_NO_INIT;
    }
    g_laneObject[LANE_TYPE_TRANS] = TransLaneGetInstance();
    if (g_laneObject[LANE_TYPE_TRANS] != NULL) {
        LNN_LOGI(LNN_LANE, "transLane get instance succ");
        g_laneObject[LANE_TYPE_TRANS]->init(NULL);
    }
    LNN_LOGI(LNN_INIT, "lane init ok");
    return SOFTBUS_OK;
}

void DeinitLane(void)
{
    if (g_laneObject[LANE_TYPE_TRANS] != NULL) {
        g_laneObject[LANE_TYPE_TRANS]->deinit();
    }
    (void)SoftBusMutexDestroy(&g_laneMutex);
}
