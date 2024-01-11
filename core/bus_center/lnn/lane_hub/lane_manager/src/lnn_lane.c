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
#define LANE_ID_BITMAP_COUNT ((MAX_LANE_ID_NUM + ID_CALC_MASK) >> ID_SHIFT_STEP)
#define LANE_ID_TYPE_SHIFT 28
#define LANE_RANDOM_ID_MASK 0xFFFFFFF

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

static uint32_t g_laneIdBitmap[LANE_ID_BITMAP_COUNT];
static SoftBusMutex g_laneMutex;
static LaneListenerList g_laneListenerList;
static LaneInterface *g_laneObject[LANE_TYPE_BUTT];
static ILaneIdStateListener g_laneIdListener;

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
 * |  type |          randomId(1 ~ MAX_LANE_ID_NUM)                |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
static uint32_t AllocLaneId(LaneType type)
{
    if (Lock() != SOFTBUS_OK) {
        return INVALID_LANE_ID;
    }
    uint32_t laneId, randomId;
    for (uint32_t idIndex = 0; idIndex < MAX_LANE_ID_NUM; idIndex++) {
        if (((g_laneIdBitmap[idIndex >> ID_SHIFT_STEP] >> (idIndex & ID_CALC_MASK)) & IS_USED) == IS_NOT_USED) {
            g_laneIdBitmap[idIndex >> ID_SHIFT_STEP] |= (IS_USED << (idIndex & ID_CALC_MASK));
            randomId = idIndex + 1;
            laneId = randomId | ((uint32_t)type << LANE_ID_TYPE_SHIFT);
            Unlock();
            return laneId;
        }
    }
    Unlock();
    LNN_LOGE(LNN_LANE, "laneId num exceeds the limit");
    return INVALID_LANE_ID;
}

static void DestroyLaneId(uint32_t laneId)
{
    uint32_t randomId = laneId & LANE_RANDOM_ID_MASK;
    if ((randomId == INVALID_LANE_ID) || (randomId > MAX_LANE_ID_NUM)) {
        LNN_LOGE(LNN_LANE, "[DestroyLaneId]invalid laneId");
        return;
    }
    if (Lock() != SOFTBUS_OK) {
        return;
    }
    LNN_LOGD(LNN_LANE, "laneId=%{public}u", laneId);
    uint32_t idIndex = randomId - 1;
    g_laneIdBitmap[idIndex >> ID_SHIFT_STEP] &= (~(IS_USED << (idIndex & ID_CALC_MASK)));
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
    if (memcpy_s(&newNode->listener, sizeof(ILaneIdStateListener), listener, sizeof(ILaneIdStateListener)) != EOK) {
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

static void LaneIdEnabled(uint32_t laneId, uint32_t profileId)
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

static void LaneIdDisabled(uint32_t laneId, uint32_t laneProfileId)
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

/* return laneId if the operation is successful, return 0 otherwise. */
uint32_t ApplyLaneId(LaneType type)
{
    return AllocLaneId(type);
}

void FreeLaneId(uint32_t laneId)
{
    return DestroyLaneId(laneId);
}

static int32_t LnnRequestLaneByQos(uint32_t laneId, const LaneRequestOption *request,
    const ILaneListener *listener)
{
    if (RequestInfoCheck(request, listener) == false) {
        LNN_LOGE(LNN_LANE, "lane requestInfo by qos invalid");
        return SOFTBUS_ERR;
    }
    if (g_laneObject[request->type] == NULL) {
        LNN_LOGE(LNN_LANE, "laneType is not supported. laneType=%{public}d", request->type);
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_LANE, "laneRequestByQos, laneId=%{public}u, laneType=%{public}d, transType=%{public}d, "
        "minBW=%{public}u, maxLaneLatency=%{public}u, minLaneLatency=%{public}u",
        laneId, request->type, request->requestInfo.trans.transType,
        request->requestInfo.trans.qosRequire.minBW,
        request->requestInfo.trans.qosRequire.maxLaneLatency,
        request->requestInfo.trans.qosRequire.minLaneLatency);
    int32_t result = g_laneObject[request->type]->allocLaneByQos(laneId, request, listener);
    if (result != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "alloc lane by qos fail, laneId=%{public}u, result=%{public}d", laneId, result);
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_LANE, "request lane by qos success, laneId=%{public}u", laneId);
    return SOFTBUS_OK;
}

static LnnLaneManager g_LaneManager = {
    .lnnQueryLaneResource = LnnQueryLaneResource,
    .applyLaneId = ApplyLaneId,
    .lnnRequestLane = LnnRequestLaneByQos,
    .lnnFreeLane = LnnFreeLane,
};

LnnLaneManager* GetLaneManager(void)
{
    return &g_LaneManager;
}

int32_t LnnRequestLane(uint32_t laneId, const LaneRequestOption *request,
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
    LNN_LOGI(LNN_LANE, "laneRequest, laneId=%{public}u, laneType=%{public}d, transType=%{public}d",
        laneId, request->type, request->requestInfo.trans.transType);
    result = g_laneObject[request->type]->AllocLane(laneId, request, listener);
    if (result != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "alloc lane fail, result=%{public}d", result);
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_LANE, "request lane success, laneId=%{public}u", laneId);
    return SOFTBUS_OK;
}

int32_t LnnFreeLane(uint32_t laneId)
{
    uint32_t laneType = laneId >> LANE_ID_TYPE_SHIFT;
    if (laneType >= LANE_TYPE_BUTT) {
        LNN_LOGE(LNN_LANE, "laneType invalid");
        return SOFTBUS_ERR;
    }
    if (g_laneObject[laneType] == NULL) {
        return SOFTBUS_ERR;
    }
    LNN_LOGD(LNN_LANE, "free lane enter, laneId=%{public}u", laneId);
    int32_t result = g_laneObject[laneType]->FreeLane(laneId);
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
        g_laneObject[LANE_TYPE_TRANS]->Init(&g_laneIdListener);
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
        g_laneObject[LANE_TYPE_TRANS]->Deinit();
    }
    (void)SoftBusMutexDestroy(&g_laneMutex);
}
