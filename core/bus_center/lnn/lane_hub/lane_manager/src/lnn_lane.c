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

#include "lnn_lane.h"

#include <securec.h>
#include <string.h>

#include "anonymizer.h"
#include "common_list.h"
#include "lnn_async_callback_utils.h"
#include "lnn_ctrl_lane.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_assign.h"
#include "lnn_lane_common.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_link.h"
#include "lnn_lane_model.h"
#include "lnn_lane_query.h"
#include "lnn_lane_score.h"
#include "lnn_log.h"
#include "lnn_trans_lane.h"
#include "lnn_lane_reliability.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"

#define ID_SHIFT_STEP 5
#define ID_CALC_MASK 0x1F
#define IS_USED 1
#define IS_NOT_USED 0
#define LANE_REQ_ID_BITMAP_COUNT ((MAX_LANE_REQ_ID_NUM + ID_CALC_MASK) >> ID_SHIFT_STEP)
#define LANE_REQ_ID_TYPE_SHIFT 28
#define LANE_REQ_RANDOM_ID_MASK 0xFFFFFFF

#define LANE_SCORING_INTERVAL 300 /* 5min */
#define CHANNEL_RATING_DELAY (5 * 60 * 1000)

typedef struct {
    ListNode node;
    ILaneIdStateListener listener;
} LaneIdListenerNode;

typedef struct {
    ListNode list;
    uint32_t cnt;
} LaneListenerList;

static uint32_t g_laneReqIdBitmap[LANE_REQ_ID_BITMAP_COUNT];
static SoftBusMutex g_laneMutex;
static LaneListenerList g_laneListenerList;
static LaneInterface *g_laneObject[LANE_TYPE_BUTT];
static ILaneIdStateListener g_laneIdListener;
static uint32_t g_laneReqId = 0;

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

static bool CheckListener(const ILaneIdStateListener *listener)
{
    if (listener == NULL) {
        LNN_LOGE(LNN_LANE, "laneIdListener is null");
        return false;
    }
    if ((listener->OnLaneIdEnabled == NULL) && (listener->OnLaneIdDisabled == NULL)) {
        LNN_LOGE(LNN_LANE, "listener invalid");
        return false;
    }
    if (Lock() != SOFTBUS_OK) {
        return false;
    }
    LaneIdListenerNode *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_laneListenerList.list, LaneIdListenerNode, node) {
        if (memcmp(&item->listener, listener, sizeof(ILaneIdStateListener)) == 0) {
            LNN_LOGW(LNN_LANE, "the listener has been registered");
            Unlock();
            return false;
        }
    }
    Unlock();
    return true;
}

void RegisterLaneIdListener(const ILaneIdStateListener *listener)
{
    if (CheckListener(listener) == false) {
        LNN_LOGE(LNN_LANE, "register fail");
        return;
    }
    LaneIdListenerNode *newNode = (LaneIdListenerNode *)SoftBusCalloc(sizeof(LaneIdListenerNode));
    if (newNode == NULL) {
        LNN_LOGE(LNN_LANE, "register laneIdListener malloc fail");
        return;
    }
    ListInit(&newNode->node);
    if (memcpy_s(&newNode->listener, sizeof(ILaneIdStateListener), listener,
        sizeof(ILaneIdStateListener)) != EOK) {
        SoftBusFree(newNode);
        return;
    }
    if (Lock() != SOFTBUS_OK) {
        SoftBusFree(newNode);
        return;
    }
    ListTailInsert(&g_laneListenerList.list, &newNode->node);
    g_laneListenerList.cnt++;
    Unlock();
}

void UnregisterLaneIdListener(const ILaneIdStateListener *listener)
{
    if (listener == NULL) {
        return;
    }
    if (Lock() != SOFTBUS_OK) {
        return;
    }
    LaneIdListenerNode *item = NULL;
    LaneIdListenerNode *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_laneListenerList.list, LaneIdListenerNode, node) {
        if (memcmp(&item->listener, listener, sizeof(ILaneIdStateListener)) == 0) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_laneListenerList.cnt--;
            break;
        }
    }
    Unlock();
}

static int32_t GetAllLaneIdListener(ILaneIdStateListener **listener, uint32_t *listenerNum)
{
    if (Lock() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (g_laneListenerList.cnt == 0) {
        Unlock();
        LNN_LOGE(LNN_LANE, "laneIdListener num is zero");
        return SOFTBUS_ERR;
    }
    uint32_t num = g_laneListenerList.cnt;
    *listener = (ILaneIdStateListener *)SoftBusCalloc(sizeof(ILaneIdStateListener) * num);
    if (*listener == NULL) {
        Unlock();
        LNN_LOGE(LNN_LANE, "malloc laneIdListener fail");
        return SOFTBUS_MALLOC_ERR;
    }
    LaneIdListenerNode *item = NULL;
    num = 0;
    LIST_FOR_EACH_ENTRY(item, &g_laneListenerList.list, LaneIdListenerNode, node) {
        if (memcpy_s(*listener + num, sizeof(ILaneIdStateListener),
            &item->listener, sizeof(ILaneIdStateListener)) != EOK) {
            continue;
        }
        num++;
    }
    *listenerNum = num;
    Unlock();
    return SOFTBUS_OK;
}

static void LaneIdEnabled(uint64_t laneId, uint32_t profileId)
{
    ILaneIdStateListener *listener = NULL;
    uint32_t listenerNum = 0;
    if (GetAllLaneIdListener(&listener, &listenerNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get laneListener fail");
        return;
    }
    for (uint32_t i = 0; i < listenerNum; i++) {
        if (listener[i].OnLaneIdEnabled != NULL) {
            listener[i].OnLaneIdEnabled(laneId, profileId);
        }
    }
    SoftBusFree(listener);
}

static void LaneIdDisabled(uint64_t laneId, uint32_t laneProfileId)
{
    ILaneIdStateListener *listener = NULL;
    uint32_t listenerNum = 0;
    if (GetAllLaneIdListener(&listener, &listenerNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get laneListener fail");
        return;
    }
    for (uint32_t i = 0; i < listenerNum; i++) {
        if (listener[i].OnLaneIdDisabled != NULL) {
            listener[i].OnLaneIdDisabled(laneId, laneProfileId);
        }
    }
    SoftBusFree(listener);
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
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_laneObject[allocInfo->type] == NULL) {
        LNN_LOGE(LNN_LANE, "laneType is not supported. laneType=%{public}d", allocInfo->type);
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
        return result;
    }
    return SOFTBUS_OK;
}

static int32_t LnnReAllocLane(uint32_t laneReqId, uint64_t laneId, const LaneAllocInfo *allocInfo,
    const LaneAllocListener *listener)
{
    if (!AllocInfoCheck(allocInfo, listener)) {
        LNN_LOGE(LNN_LANE, "lane realloc info invalid");
        return SOFTBUS_ERR;
    }
    if (g_laneObject[allocInfo->type] == NULL) {
        LNN_LOGE(LNN_LANE, "laneType is not supported. laneType=%{public}d", allocInfo->type);
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_LANE, "realloc lane enter, laneReqId=%{public}u, laneId=%{public}" PRIu64 ", laneType=%{public}d, "
        "transType=%{public}d, minBW=%{public}u, maxLaneLatency=%{public}u, minLaneLatency=%{public}u",
        laneReqId, laneId, allocInfo->type, allocInfo->transType,
        allocInfo->qosRequire.minBW,
        allocInfo->qosRequire.maxLaneLatency,
        allocInfo->qosRequire.minLaneLatency);
    int32_t result = g_laneObject[allocInfo->type]->reallocLaneByQos(laneReqId, laneId, allocInfo, listener);
    if (result != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "realloc lane fail, laneReqId=%{public}u, result=%{public}d", laneReqId, result);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LnnCancelLane(uint32_t laneReqId)
{
    LaneType type = laneReqId >> LANE_REQ_ID_TYPE_SHIFT;
    if (type >= LANE_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "laneType invalid");
        return SOFTBUS_ERR;
    }
    if (g_laneObject[type] == NULL) {
        return SOFTBUS_ERR;
    }
    LNN_LOGD(LNN_LANE, "cancel lane enter, laneReqId=%{public}u", laneReqId);
    int32_t result = g_laneObject[type]->cancelLane(laneReqId);
    if (result != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "freeLane fail, result=%{public}d", result);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LnnFreeLink(uint32_t laneReqId)
{
    LaneType type = laneReqId >> LANE_REQ_ID_TYPE_SHIFT;
    if (type >= LANE_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "laneType invalid");
        return SOFTBUS_ERR;
    }
    if (g_laneObject[type] == NULL) {
        return SOFTBUS_ERR;
    }
    LNN_LOGD(LNN_LANE, "free lane enter, laneReqId=%{public}u", laneReqId);
    int32_t result = g_laneObject[type]->freeLane(laneReqId);
    if (result != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "freeLane fail, result=%{public}d", result);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static LnnLaneManager g_LaneManager = {
    .lnnQueryLaneResource = LnnQueryLaneResource,
    .lnnGetLaneHandle = ApplyLaneReqId,
    .lnnAllocLane = LnnAllocLane,
    .lnnReAllocLane = LnnReAllocLane,
    .lnnCancelLane = LnnCancelLane,
    .lnnFreeLane = LnnFreeLink,
    .registerLaneListener = RegisterLaneListener,
    .unRegisterLaneListener = UnRegisterLaneListener,
};

LnnLaneManager* GetLaneManager(void)
{
    return &g_LaneManager;
}

int32_t LnnRequestLane(uint32_t laneReqId, const LaneRequestOption *request,
    const ILaneListener *listener)
{
    if (RequestInfoCheck(request, listener) == false) {
        LNN_LOGE(LNN_LANE, "lane requestInfo invalid");
        return SOFTBUS_ERR;
    }
    if (g_laneObject[request->type] == NULL) {
        LNN_LOGE(LNN_LANE, "lane type is not supported. type=%{public}d", request->type);
        return SOFTBUS_ERR;
    }
    int32_t result;
    LNN_LOGI(LNN_LANE, "laneRequest, laneReqId=%{public}u, laneType=%{public}d, transType=%{public}d",
        laneReqId, request->type, request->requestInfo.trans.transType);
    for (uint32_t i = 0; i < request->requestInfo.trans.expectedLink.linkTypeNum; i++) {
        LNN_LOGI(LNN_LANE, "laneRequest assign the priority=%{public}u, link=%{public}d",
            i, request->requestInfo.trans.expectedLink.linkType[i]);
    }
    result = g_laneObject[request->type]->allocLane(laneReqId, request, listener);
    if (result != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "alloc lane fail, result=%{public}d", result);
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_LANE, "request lane success, laneReqId=%{public}u", laneReqId);
    return SOFTBUS_OK;
}

int32_t LnnFreeLane(uint32_t laneReqId)
{
    LaneType type = laneReqId >> LANE_REQ_ID_TYPE_SHIFT;
    if (type >= LANE_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "laneType invalid");
        return SOFTBUS_ERR;
    }
    if (g_laneObject[type] == NULL) {
        return SOFTBUS_ERR;
    }
    LNN_LOGD(LNN_LANE, "free lane enter, laneReqId=%{public}u", laneReqId);
    int32_t result = g_laneObject[type]->freeLane(laneReqId);
    if (result != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "freeLane fail, result=%{public}d", result);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnQueryLaneResource(const LaneQueryInfo *queryInfo, const QosInfo *qosInfo)
{
    if (queryInfo == NULL || qosInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (!LnnGetOnlineStateById(queryInfo->networkId, CATEGORY_NETWORK_ID)) {
        char *anonyNetworkId = NULL;
        Anonymize(queryInfo->networkId, &anonyNetworkId);
        LNN_LOGE(LNN_LANE, "device not online, cancel query peerNetworkId=%{public}s", anonyNetworkId);
        AnonymizeFree(anonyNetworkId);
        return SOFTBUS_NETWORK_NODE_OFFLINE;
    }
    return QueryLaneResource(queryInfo, qosInfo);
}

static void LaneInitChannelRatingDelay(void *para)
{
    (void)para;
    if (LnnInitScore() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "init laneScoring fail");
        return;
    }
    if (LnnStartScoring(LANE_SCORING_INTERVAL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "start laneScoring fail");
    }
}

static int32_t LaneDelayInit(void)
{
    int32_t ret = LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), LaneInitChannelRatingDelay,
        NULL, CHANNEL_RATING_DELAY);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "post channelRating msg fail");
    }
    return ret;
}

int32_t InitLane(void)
{
    if (LnnInitLaneLooper() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "[InitLane]init laneLooper fail");
        return SOFTBUS_ERR;
    }
    if (InitLaneModel() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "[InitLane]init laneModel fail");
        return SOFTBUS_ERR;
    }
    if (InitLaneLink() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "[InitLane]init laneLink fail");
        return SOFTBUS_ERR;
    }
    if (InitLaneListener() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "[InitLane]init laneListener fail");
        return SOFTBUS_ERR;
    }
    if (LaneDelayInit() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "[InitLane]laneDelayInit fail");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexInit(&g_laneMutex, NULL) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    g_laneIdListener.OnLaneIdEnabled = LaneIdEnabled;
    g_laneIdListener.OnLaneIdDisabled = LaneIdDisabled;
    g_laneObject[LANE_TYPE_TRANS] = TransLaneGetInstance();
    if (g_laneObject[LANE_TYPE_TRANS] != NULL) {
        LNN_LOGI(LNN_LANE, "transLane get instance succ");
        g_laneObject[LANE_TYPE_TRANS]->init(&g_laneIdListener);
    }
    g_laneObject[LANE_TYPE_CTRL] = CtrlLaneGetInstance();
    if (g_laneObject[LANE_TYPE_CTRL] != NULL) {
        LNN_LOGI(LNN_LANE, "ctrl get instance succ");
    }
    ListInit(&g_laneListenerList.list);
    g_laneListenerList.cnt = 0;
    return SOFTBUS_OK;
}

void DeinitLane(void)
{
    DeinitLaneModel();
    DeinitLaneLink();
    LnnDeinitScore();
    LnnDeinitLaneLooper();
    if (g_laneObject[LANE_TYPE_TRANS] != NULL) {
        g_laneObject[LANE_TYPE_TRANS]->deinit();
    }
    (void)SoftBusMutexDestroy(&g_laneMutex);
}
