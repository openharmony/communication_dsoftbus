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

#include "lnn_trans_lane.h"

#include <securec.h>

#include "anonymizer.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_lane.h"
#include "lnn_lane_common.h"
#include "lnn_lane_def.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_listener.h"
#include "lnn_lane_model.h"
#include "lnn_lane_select.h"
#include "lnn_log.h"
#include "lnn_lane_link_p2p.h"
#include "message_handler.h"
#include "wifi_direct_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"
#include "softbus_protocol_def.h"
#include "wifi_direct_error_code.h"
#include "lnn_lane_reliability.h"

#define LANE_REQ_ID_TYPE_SHIFT 28
#define DEFAULT_LINK_LATENCY 30000
#define DELAY_DESTROY_LANE_TIME 5000

typedef enum {
    MSG_TYPE_LANE_TRIGGER_LINK = 0,
    MSG_TYPE_LANE_LINK_SUCCESS,
    MSG_TYPE_LANE_LINK_FAIL,
    MSG_TYPE_LANE_STATE_CHANGE,
    MSG_TYPE_DELAY_DESTROY_LINK,
    MSG_TYPE_LANE_DETECT_TIMEOUT,
} LaneMsgType;

typedef struct {
    uint32_t cnt;
    ListNode list;
} TransLaneList;

typedef struct {
    ListNode node;
    uint32_t laneReqId;
    int32_t pid;
    char networkId[NETWORK_ID_BUF_LEN];
    LanePreferredLinkList *linkList; /* Mem provided by laneSelect module */
    uint32_t listNum;
    uint32_t linkRetryIdx;
    bool networkDelegate;
    int32_t p2pErrCode;
    uint64_t restTime;
    uint64_t startTime;
    char peerBleMac[MAX_MAC_LEN];
    LaneTransType transType;
    ProtocolType acceptableProtocols;
    // OldInfo
    int32_t psm;
    bool p2pOnly;
} LaneLinkNodeInfo;

typedef struct {
    LaneState state;
    char peerUdid[UDID_BUF_LEN];
    LaneLinkInfo laneLinkInfo;
} StateNotifyInfo;

static ListNode g_multiLinkList;
static SoftBusMutex g_transLaneMutex;
static TransLaneList *g_requestList = NULL;
static SoftBusHandler g_laneLoopHandler;
static ILaneIdStateListener *g_laneIdCallback = NULL;

static int32_t Lock(void)
{
    return SoftBusMutexLock(&g_transLaneMutex);
}

static void Unlock(void)
{
    (void)SoftBusMutexUnlock(&g_transLaneMutex);
}

static int32_t LnnLanePostMsgToHandler(int32_t msgType, uint64_t param1, uint64_t param2,
    void *obj, uint64_t delayMillis)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        LNN_LOGE(LNN_LANE, "[transLane]create handler msg failed");
        return SOFTBUS_MALLOC_ERR;
    }
    msg->what = msgType;
    msg->arg1 = param1;
    msg->arg2 = param2;
    msg->handler = &g_laneLoopHandler;
    msg->obj = obj;
    if (delayMillis == 0) {
        g_laneLoopHandler.looper->PostMessage(g_laneLoopHandler.looper, msg);
    } else {
        g_laneLoopHandler.looper->PostMessageDelay(g_laneLoopHandler.looper, msg, delayMillis);
    }
    return SOFTBUS_OK;
}

static void LinkSuccess(uint32_t laneReqId, const LaneLinkInfo *linkInfo)
{
    if (linkInfo == NULL) {
        LNN_LOGE(LNN_LANE, "linkSuccess param invalid");
        return;
    }
    LaneLinkInfo *linkParam = (LaneLinkInfo *)SoftBusCalloc(sizeof(LaneLinkInfo));
    if (linkParam == NULL) {
        LNN_LOGE(LNN_LANE, "linkSuccess info malloc fail");
        return;
    }
    if (memcpy_s(linkParam, sizeof(LaneLinkInfo), linkInfo, sizeof(LaneLinkInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "linkParam memcpy fail, laneReqId=%{public}u", laneReqId);
        SoftBusFree(linkParam);
        (void)LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_FAIL, laneReqId, SOFTBUS_MEM_ERR, NULL, 0);
        return;
    }
    char localUdid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid fail");
        SoftBusFree(linkParam);
        (void)LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_FAIL, laneReqId, SOFTBUS_LANE_GET_LEDGER_INFO_ERR, NULL, 0);
        return;
    }
    uint64_t laneId = ApplyLaneId(localUdid, linkInfo->peerUdid, linkInfo->type);
    if (laneId == INVALID_LANE_ID) {
        LNN_LOGE(LNN_LANE, "apply laneId fail, laneReqId=%{public}u", laneReqId);
        SoftBusFree(linkParam);
        (void)LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_FAIL, laneReqId, SOFTBUS_LANE_ID_GENERATE_FAIL, NULL, 0);
        return;
    }
    int32_t ret = AddLaneResourceToPool(linkInfo, laneId, false);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add linkInfo item fail, laneReqId=%{public}u", laneReqId);
        SoftBusFree(linkParam);
        (void)LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_FAIL, laneReqId, ret, NULL, 0);
        return;
    }
    if (LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_SUCCESS, laneReqId, laneId, linkParam, 0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "post LaneLinkSuccess msg err, laneReqId=%{public}u", laneReqId);
        (void)DelLaneResourceByLaneId(laneId, false);
        SoftBusFree(linkParam);
        return;
    }
}

static void LinkFail(uint32_t laneReqId, int32_t reason)
{
    if (LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_FAIL, laneReqId, reason, NULL, 0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "post lanelink fail msg err");
        return;
    }
}

static void DeleteLaneLinkNode(uint32_t laneReqId)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return;
    }
    LaneLinkNodeInfo *item = NULL;
    LaneLinkNodeInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_multiLinkList, LaneLinkNodeInfo, node) {
        if (item->laneReqId == laneReqId) {
            ListDelete(&item->node);
            SoftBusFree(item->linkList);
            SoftBusFree(item);
            break;
        }
    }
    Unlock();
}

static int32_t TriggerLink(uint32_t laneReqId, TransOption *request,
    LanePreferredLinkList *recommendLinkList)
{
    LaneLinkNodeInfo *linkNode = (LaneLinkNodeInfo *)SoftBusCalloc(sizeof(LaneLinkNodeInfo));
    if (linkNode == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(linkNode->networkId, NETWORK_ID_BUF_LEN,
        request->networkId, NETWORK_ID_BUF_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy fail for networkId");
        SoftBusFree(linkNode);
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(linkNode->peerBleMac, MAX_MAC_LEN, request->peerBleMac, MAX_MAC_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy fail for peerBleMac");
        SoftBusFree(linkNode);
        return SOFTBUS_MEM_ERR;
    }
    linkNode->psm = request->psm;
    linkNode->transType = request->transType;
    linkNode->laneReqId = laneReqId;
    linkNode->linkRetryIdx = 0;
    linkNode->listNum = recommendLinkList->linkTypeNum;
    linkNode->linkList = recommendLinkList;
    linkNode->pid = request->pid;
    linkNode->networkDelegate = request->networkDelegate;
    linkNode->p2pOnly = request->p2pOnly;
    linkNode->p2pErrCode = SOFTBUS_OK;
    linkNode->acceptableProtocols = request->acceptableProtocols;
    linkNode->restTime = DEFAULT_LINK_LATENCY;
    ListInit(&linkNode->node);
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        SoftBusFree(linkNode);
        return SOFTBUS_LOCK_ERR;
    }
    ListTailInsert(&g_multiLinkList, &linkNode->node);
    Unlock();
    if (LnnLanePostMsgToHandler(MSG_TYPE_LANE_TRIGGER_LINK, laneReqId, 0, NULL, 0) != SOFTBUS_OK) {
        DeleteLaneLinkNode(laneReqId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static TransReqInfo *CreateRequestNode(uint32_t laneReqId, const TransOption *option, const ILaneListener *listener)
{
    TransReqInfo *newNode = (TransReqInfo *)SoftBusCalloc(sizeof(TransReqInfo));
    if (newNode == NULL) {
        LNN_LOGE(LNN_LANE, "malloc fail");
        return NULL;
    }
    if (memcpy_s(&newNode->extraInfo.listener, sizeof(ILaneListener), listener, sizeof(ILaneListener)) != EOK) {
        SoftBusFree(newNode);
        return NULL;
    }
    if (memcpy_s(&newNode->extraInfo.info, sizeof(TransOption), option, sizeof(TransOption)) != EOK) {
        SoftBusFree(newNode);
        return NULL;
    }
    newNode->isWithQos = false;
    newNode->isCanceled = false;
    newNode->isNotified = false;
    newNode->laneReqId = laneReqId;
    ListInit(&newNode->node);
    return newNode;
}

static void DeleteRequestNode(uint32_t laneReqId)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return;
    }
    TransReqInfo *item = NULL;
    TransReqInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_requestList->list, TransReqInfo, node) {
        if (item->laneReqId == laneReqId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_requestList->cnt--;
            break;
        }
    }
    Unlock();
}

static TransReqInfo *CreateReqNodeWithQos(uint32_t laneReqId, const LaneAllocInfo *allocInfo,
    const LaneAllocListener *listener)
{
    TransReqInfo *newNode = (TransReqInfo *)SoftBusCalloc(sizeof(TransReqInfo));
    if (newNode == NULL) {
        LNN_LOGE(LNN_LANE, "malloc fail");
        return NULL;
    }
    if (memcpy_s(&newNode->listener, sizeof(LaneAllocListener), listener, sizeof(LaneAllocListener)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy fail for lane alloc listener");
        SoftBusFree(newNode);
        return NULL;
    }
    if (memcpy_s(&newNode->allocInfo, sizeof(LaneAllocInfo), allocInfo, sizeof(LaneAllocInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy fail for lane alloc info");
        SoftBusFree(newNode);
        return NULL;
    }
    newNode->laneReqId = laneReqId;
    newNode->isWithQos = true;
    newNode->isCanceled = false;
    newNode->isNotified = false;
    ListInit(&newNode->node);
    return newNode;
}

static int32_t TriggerLinkWithQos(uint32_t laneReqId, const LaneAllocInfo *allocInfo,
    LanePreferredLinkList *recommendLinkList)
{
    LaneLinkNodeInfo *linkNode = (LaneLinkNodeInfo *)SoftBusCalloc(sizeof(LaneLinkNodeInfo));
    if (linkNode == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(linkNode->networkId, NETWORK_ID_BUF_LEN,
        allocInfo->networkId, NETWORK_ID_BUF_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy fail for networkId");
        SoftBusFree(linkNode);
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(linkNode->peerBleMac, MAX_MAC_LEN, allocInfo->extendInfo.peerBleMac, MAX_MAC_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy fail for peerBleMac");
        SoftBusFree(linkNode);
        return SOFTBUS_MEM_ERR;
    }
    linkNode->transType = allocInfo->transType;
    linkNode->laneReqId = laneReqId;
    linkNode->linkRetryIdx = 0;
    linkNode->listNum = recommendLinkList->linkTypeNum;
    linkNode->linkList = recommendLinkList;
    linkNode->pid = allocInfo->pid;
    linkNode->networkDelegate = allocInfo->extendInfo.networkDelegate;
    linkNode->p2pErrCode = SOFTBUS_OK;
    linkNode->acceptableProtocols = allocInfo->acceptableProtocols;
    linkNode->restTime = allocInfo->qosRequire.maxLaneLatency != 0 ?
        allocInfo->qosRequire.maxLaneLatency : DEFAULT_LINK_LATENCY;
    ListInit(&linkNode->node);
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        SoftBusFree(linkNode);
        return SOFTBUS_LOCK_ERR;
    }
    ListTailInsert(&g_multiLinkList, &linkNode->node);
    Unlock();
    int32_t ret = LnnLanePostMsgToHandler(MSG_TYPE_LANE_TRIGGER_LINK, laneReqId, 0, NULL, 0);
    if (ret != SOFTBUS_OK) {
        DeleteLaneLinkNode(laneReqId);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t StartTriggerLink(uint32_t laneReqId, const LaneAllocInfo *allocInfo, const LaneAllocListener *listener,
    LanePreferredLinkList *recommendLinkList)
{
    TransReqInfo *newItem = CreateReqNodeWithQos(laneReqId, allocInfo, listener);
    if (newItem == NULL) {
        return SOFTBUS_MEM_ERR;
    }
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        SoftBusFree(newItem);
        return SOFTBUS_LOCK_ERR;
    }
    ListTailInsert(&g_requestList->list, &newItem->node);
    g_requestList->cnt++;
    Unlock();
    int32_t ret = TriggerLinkWithQos(laneReqId, allocInfo, recommendLinkList);
    if (ret != SOFTBUS_OK) {
        DeleteRequestNode(laneReqId);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t AllocValidLane(uint32_t laneReqId, uint64_t allocLaneId, const LaneAllocInfo *allocInfo,
    const LaneAllocListener *listener)
{
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = allocInfo->transType;
    selectParam.qosRequire = allocInfo->qosRequire;
    selectParam.allocedLaneId = allocLaneId;
    LanePreferredLinkList *recommendLinkList = (LanePreferredLinkList *)SoftBusMalloc(sizeof(LanePreferredLinkList));
    if (recommendLinkList == NULL) {
        LNN_LOGE(LNN_LANE, "recommendLinkList malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    recommendLinkList->linkTypeNum = 0;
    if (SelectExpectLaneByParameter(recommendLinkList) == SOFTBUS_OK) {
        LNN_LOGI(LNN_LANE, "SelectExpectLaneByParameter succ, laneReqId=%{public}u", laneReqId);
    } else if (SelectExpectLanesByQos((const char *)allocInfo->networkId, &selectParam,
        recommendLinkList) != SOFTBUS_OK) {
        SoftBusFree(recommendLinkList);
        LNN_LOGE(LNN_LANE, "selectExpectLanesByQos fail, laneReqId=%{public}u", laneReqId);
        return SOFTBUS_LANE_SELECT_FAIL;
    }
    if (recommendLinkList->linkTypeNum == 0) {
        SoftBusFree(recommendLinkList);
        LNN_LOGE(LNN_LANE, "no available link resources, laneReqId=%{public}u", laneReqId);
        return SOFTBUS_LANE_SELECT_FAIL;
    }
    for (uint32_t i = 0; i < recommendLinkList->linkTypeNum; i++) {
        LNN_LOGI(LNN_LANE, "expect linklist nums=%{public}u, priority=%{public}u, link=%{public}u",
            recommendLinkList->linkTypeNum, i, recommendLinkList->linkType[i]);
    }
    int32_t ret = StartTriggerLink(laneReqId, allocInfo, listener, recommendLinkList);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(recommendLinkList);
        LNN_LOGE(LNN_LANE, "trigger link fail, laneReqId=%{public}u", laneReqId);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t AllocLaneByQos(uint32_t laneReqId, const LaneAllocInfo *allocInfo, const LaneAllocListener *listener)
{
    if (laneReqId == INVALID_LANE_REQ_ID || allocInfo == NULL || allocInfo->type != LANE_TYPE_TRANS) {
        LNN_LOGE(LNN_LANE, "AllocLane param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = AllocValidLane(laneReqId, INVALID_LANE_ID, allocInfo, listener);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "alloc valid lane fail, laneReqId=%{public}u", laneReqId);
        FreeLaneReqId(laneReqId);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t ReallocLaneByQos(uint32_t laneReqId, uint64_t laneId, const LaneAllocInfo *allocInfo,
    const LaneAllocListener *listener)
{
    if (laneReqId == INVALID_LANE_REQ_ID || allocInfo == NULL || allocInfo->type != LANE_TYPE_TRANS ||
        laneId == INVALID_LANE_ID) {
        LNN_LOGE(LNN_LANE, "AllocLane param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (AllocValidLane(laneReqId, laneId, allocInfo, listener) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "alloc valid lane fail, laneReqId=%{public}u", laneReqId);
        FreeLaneReqId(laneReqId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t Alloc(uint32_t laneReqId, const LaneRequestOption *request, const ILaneListener *listener)
{
    if ((request == NULL) || (request->type != LANE_TYPE_TRANS)) {
        return SOFTBUS_INVALID_PARAM;
    }
    TransOption *transRequest = (TransOption *)&request->requestInfo.trans;
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = transRequest->transType;
    selectParam.expectedBw = transRequest->expectedBw;
    if (memcpy_s(&selectParam.list, sizeof(selectParam.list),
        &transRequest->expectedLink, sizeof(transRequest->expectedLink)) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    LanePreferredLinkList *recommendLinkList = (LanePreferredLinkList *)SoftBusMalloc(sizeof(LanePreferredLinkList));
    if (recommendLinkList == NULL) {
        return SOFTBUS_ERR;
    }
    recommendLinkList->linkTypeNum = 0;
    uint32_t listNum = 0;
    if (SelectLane((const char *)transRequest->networkId, &selectParam, recommendLinkList, &listNum) != SOFTBUS_OK) {
        SoftBusFree(recommendLinkList);
        return SOFTBUS_ERR;
    }
    if (recommendLinkList->linkTypeNum == 0) {
        LNN_LOGE(LNN_LANE, "no link resources available, alloc fail");
        SoftBusFree(recommendLinkList);
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_LANE, "select lane link success, linkNum=%{public}d, laneReqId=%{public}u", listNum, laneReqId);
    TransReqInfo *newItem = CreateRequestNode(laneReqId, transRequest, listener);
    if (newItem == NULL) {
        SoftBusFree(recommendLinkList);
        return SOFTBUS_ERR;
    }
    if (Lock() != SOFTBUS_OK) {
        SoftBusFree(newItem);
        SoftBusFree(recommendLinkList);
        return SOFTBUS_ERR;
    }
    ListTailInsert(&g_requestList->list, &newItem->node);
    g_requestList->cnt++;
    Unlock();
    if (TriggerLink(laneReqId, transRequest, recommendLinkList) != SOFTBUS_OK) {
        SoftBusFree(recommendLinkList);
        DeleteRequestNode(laneReqId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ParseLaneTypeByLaneReqId(uint32_t laneReqId, LaneType *laneType)
{
    if (laneReqId == INVALID_LANE_REQ_ID || laneType == NULL) {
        LNN_LOGE(LNN_LANE, "[ParseLaneType]invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    *laneType = (LaneType)(laneReqId >> LANE_REQ_ID_TYPE_SHIFT);
    return SOFTBUS_OK;
}

static int32_t FreeLaneLink(uint32_t laneReqId, uint64_t laneId)
{
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (FindLaneResourceByLaneId(laneId, &resourceItem) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (LnnGetNetworkIdByUdid(resourceItem.link.peerUdid, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    DestroyLink(networkId, laneReqId, resourceItem.link.type);
    DelLaneResourceByLaneId(laneId, false);
    return SOFTBUS_OK;
}

static int32_t CancelLane(uint32_t laneReqId)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return SOFTBUS_ERR;
    }
    TransReqInfo *item = NULL;
    TransReqInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_requestList->list, TransReqInfo, node) {
        if (item->isWithQos && item->laneReqId == laneReqId) {
            if (item->isNotified) {
                Unlock();
                LNN_LOGE(LNN_LANE, "cancel lane fail, lane result has notified, laneReqId=%{public}u", laneReqId);
                return SOFTBUS_ERR;
            }
            item->isCanceled = true;
            Unlock();
            LNN_LOGI(LNN_LANE, "cancel lane succ, laneReqId=%{public}u", laneReqId);
            return SOFTBUS_OK;
        }
    }
    Unlock();
    LNN_LOGE(LNN_LANE, "cancel lane fail, lane reqinfo not find, laneReqId=%{public}u", laneReqId);
    return SOFTBUS_ERR;
}

static void IsNeedDelayFreeLane(uint32_t laneReqId, uint64_t laneId, bool *isDelayFree)
{
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (FindLaneResourceByLaneId(laneId, &resourceItem) != SOFTBUS_OK) {
        *isDelayFree = false;
        return;
    }
    if (resourceItem.link.type == LANE_HML && resourceItem.clientRef == 1) {
        if (PostDelayDestroyMessage(laneReqId, laneId, DELAY_DESTROY_LANE_TIME) == SOFTBUS_OK) {
            *isDelayFree = true;
            return;
        }
    }
    *isDelayFree = false;
    return;
}

static int32_t Freelink(uint32_t laneReqId, uint64_t laneId, LaneType type)
{
    (void)DelLaneBusinessInfoItem(type, laneId);
    bool isDelayDestroy = false;
    IsNeedDelayFreeLane(laneReqId, laneId, &isDelayDestroy);
    LNN_LOGI(LNN_LANE, "free lane, laneReqId=%{public}u, laneId=%{public}" PRIu64 ", delayDestroy=%{public}s",
        laneReqId, laneId, isDelayDestroy ? "true" : "false");
    if (isDelayDestroy) {
        return SOFTBUS_OK;
    }
    return FreeLaneLink(laneReqId, laneId);
}

static int32_t Free(uint32_t laneReqId)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return SOFTBUS_ERR;
    }
    LaneType type = laneReqId >> LANE_REQ_ID_TYPE_SHIFT;
    TransReqInfo *item = NULL;
    TransReqInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_requestList->list, TransReqInfo, node) {
        if (item->laneReqId == laneReqId) {
            ListDelete(&item->node);
            g_requestList->cnt--;
            Unlock();
            Freelink(laneReqId, item->laneId, type);
            SoftBusFree(item);
            FreeLaneReqId(laneReqId);
            return SOFTBUS_OK;
        }
    }
    Unlock();
    LNN_LOGI(LNN_LANE, "no find lane need free, laneReqId=%{public}u", laneReqId);
    FreeLaneReqId(laneReqId);
    return SOFTBUS_OK;
}

static void UpdateReqInfoWithLaneReqId(uint32_t laneReqId, uint64_t laneId)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return;
    }
    TransReqInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_requestList->list, TransReqInfo, node) {
        if (item->laneReqId == laneReqId) {
            item->laneId = laneId;
            if (item->isWithQos && !item->isCanceled) {
                item->isNotified = true;
            }
            Unlock();
            return;
        }
    }
    Unlock();
}

static void NotifyLaneAllocSuccess(uint32_t laneReqId, uint64_t laneId, const LaneLinkInfo *info)
{
    UpdateReqInfoWithLaneReqId(laneReqId, laneId);
    TransReqInfo reqInfo;
    (void)memset_s(&reqInfo, sizeof(TransReqInfo), 0, sizeof(TransReqInfo));
    if (GetTransReqInfoByLaneReqId(laneReqId, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lane reqInfo fail");
        return;
    }
    if (reqInfo.isWithQos && reqInfo.isCanceled) {
        LNN_LOGI(LNN_LANE, "lane has canceled not need notify succ, laneReqId=%{public}u", laneReqId);
        (void)Free(laneReqId);
        return;
    }
    LaneProfile profile;
    LaneConnInfo connInfo;
    (void)memset_s(&profile, sizeof(LaneProfile), 0, sizeof(LaneProfile));
    if (LaneInfoProcess(info, &connInfo, &profile) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane alloc success, but laneInfo proc fail");
        return;
    }
    LNN_LOGI(LNN_LANE, "Notify laneAlloc succ, laneReqId=%{public}u, linkType=%{public}d, "
        "laneId=%{public}" PRIu64 "", laneReqId, info->type, laneId);
    if (reqInfo.isWithQos) {
        connInfo.laneId = laneId;
        reqInfo.listener.onLaneAllocSuccess(laneReqId, &connInfo);
    } else {
        connInfo.laneId = INVALID_LANE_ID;
        reqInfo.extraInfo.listener.onLaneRequestSuccess(laneReqId, &connInfo);
    }
}

static void NotifyLaneAllocFail(uint32_t laneReqId, int32_t reason)
{
    UpdateReqInfoWithLaneReqId(laneReqId, INVALID_LANE_ID);
    TransReqInfo reqInfo;
    (void)memset_s(&reqInfo, sizeof(TransReqInfo), 0, sizeof(TransReqInfo));
    if (GetTransReqInfoByLaneReqId(laneReqId, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lane reqInfo fail");
        return;
    }
    if (reqInfo.isWithQos && reqInfo.isCanceled) {
        LNN_LOGI(LNN_LANE, "lane has canceled not need notify fail, laneReqId=%{public}u", laneReqId);
        DeleteRequestNode(laneReqId);
        FreeLaneReqId(laneReqId);
        return;
    }
    LNN_LOGE(LNN_LANE, "Notify laneAlloc fail, laneReqId=%{public}u, reason=%{public}d", laneReqId, reason);
    if (reqInfo.isWithQos) {
        reqInfo.listener.onLaneAllocFail(laneReqId, reason);
        FreeLaneReqId(laneReqId);
    } else {
        reqInfo.extraInfo.listener.onLaneRequestFail(laneReqId, reason);
    }
    DeleteRequestNode(laneReqId);
}

static LaneLinkNodeInfo *GetLaneLinkNodeWithoutLock(uint32_t laneReqId)
{
    LaneLinkNodeInfo *linkNode = NULL;
    LIST_FOR_EACH_ENTRY(linkNode, &g_multiLinkList, LaneLinkNodeInfo, node) {
        if (linkNode->laneReqId == laneReqId) {
            return linkNode;
        }
    }
    return NULL;
}

static int32_t CreateLinkRequestNode(const LaneLinkNodeInfo *nodeInfo, LinkRequest *requestInfo)
{
    requestInfo->networkDelegate = nodeInfo->networkDelegate;
    requestInfo->p2pOnly = nodeInfo->p2pOnly;
    requestInfo->linkType = nodeInfo->linkList->linkType[nodeInfo->linkRetryIdx];
    requestInfo->pid = nodeInfo->pid;
    requestInfo->acceptableProtocols = nodeInfo->acceptableProtocols;
    requestInfo->transType = nodeInfo->transType;
    requestInfo->psm = nodeInfo->psm;
    if (memcpy_s(requestInfo->peerNetworkId, NETWORK_ID_BUF_LEN,
        nodeInfo->networkId, NETWORK_ID_BUF_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(requestInfo->peerBleMac, MAX_MAC_LEN, nodeInfo->peerBleMac, MAX_MAC_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy peerBleMac fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static void LaneTriggerLink(SoftBusMessage *msg)
{
    uint32_t laneReqId = msg->arg1;
    LaneLinkCb linkCb = {
        .OnLaneLinkSuccess = LinkSuccess,
        .OnLaneLinkFail = LinkFail,
    };
    LinkRequest requestInfo = { 0 };
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return;
    }
    LaneLinkNodeInfo *nodeInfo = GetLaneLinkNodeWithoutLock(laneReqId);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LANE, "get lane link node info fail");
        Unlock();
        return;
    }
    int32_t ret = SOFTBUS_LANE_TRIGGER_LINK_FAIL;
    do {
        if (nodeInfo->linkRetryIdx >= nodeInfo->listNum) {
            LNN_LOGE(LNN_LANE, "All linkType have been tried");
            Unlock();
            break;
        }
        ret = CreateLinkRequestNode(nodeInfo, &requestInfo);
        if (ret != SOFTBUS_OK) {
            Unlock();
            break;
        }
        nodeInfo->linkRetryIdx++;
        nodeInfo->startTime = SoftBusGetSysTimeMs();
        Unlock();
        ret = BuildLink(&requestInfo, laneReqId, &linkCb);
        if (ret == SOFTBUS_OK) {
            return;
        }
    } while (false);
    if (LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_FAIL, laneReqId, ret, NULL, 0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "post laneLinkFail msg err");
    }
}

static void LaneLinkSuccess(SoftBusMessage *msg)
{
    if (msg->obj == NULL) {
        LNN_LOGE(LNN_LANE, "invalid msg->obj");
        return;
    }
    LaneLinkInfo *info = (LaneLinkInfo *)msg->obj;
    uint32_t laneReqId = (uint32_t)msg->arg1;
    uint64_t laneId = (uint64_t)msg->arg2;
    DeleteLaneLinkNode(laneReqId);
    LaneType laneType;
    if (ParseLaneTypeByLaneReqId(laneReqId, &laneType) != SOFTBUS_OK ||
        AddLaneBusinessInfoItem(laneType, laneId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "create laneBusinessInfo fail, laneReqId=%{public}u", laneReqId);
    }
    NotifyLaneAllocSuccess(laneReqId, laneId, info);
    SoftBusFree(info);
    return;
}

static void LaneLinkFail(SoftBusMessage *msg)
{
    uint32_t laneReqId = (uint32_t)msg->arg1;
    int32_t reason = (int32_t)msg->arg2;
    LNN_LOGI(LNN_LANE, "lane link fail, laneReqId=%{public}u, reason=%{public}d", laneReqId, reason);
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return;
    }
    LaneLinkNodeInfo *nodeInfo = GetLaneLinkNodeWithoutLock(laneReqId);
    if (nodeInfo == NULL) {
        Unlock();
        LNN_LOGE(LNN_LANE, "getLinkNode fail. laneReqId=%{public}u", laneReqId);
        NotifyLaneAllocFail(laneReqId, SOFTBUS_LANE_TRIGGER_LINK_FAIL);
        return;
    }
    if ((reason >= ERROR_WIFI_DIRECT_END && reason <= ERROR_WIFI_DIRECT_START) ||
        (reason >= V1_ERROR_END && reason <= V1_ERROR_START) || nodeInfo->linkRetryIdx == 1) {
        nodeInfo->p2pErrCode = reason;
    }
    uint64_t costTime = SoftBusGetSysTimeMs() - nodeInfo->startTime;
    if (costTime >= nodeInfo->restTime || nodeInfo->linkRetryIdx >= nodeInfo->listNum) {
        LNN_LOGE(LNN_LANE, "link retry exceed limit, laneReqId=%{public}u", laneReqId);
        if (nodeInfo->p2pErrCode != SOFTBUS_OK) {
            reason = nodeInfo->p2pErrCode;
        }
        Unlock();
        DeleteLaneLinkNode(laneReqId);
        NotifyLaneAllocFail(laneReqId, reason);
        return;
    }
    nodeInfo->restTime = nodeInfo->restTime - costTime;
    LNN_LOGI(LNN_LANE, "previous link costTime=%{public}" PRIu64 ", restTime=%{public}" PRIu64 " "
        " support continue to build link, laneReqId=%{public}u", costTime, nodeInfo->restTime, laneReqId);
    Unlock();
    if (LnnLanePostMsgToHandler(MSG_TYPE_LANE_TRIGGER_LINK, laneReqId, 0, NULL, 0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "post triggerLink msg fail");
        return;
    }
}

static void LaneStateChange(SoftBusMessage *msg)
{
    if (msg->obj == NULL) {
        LNN_LOGE(LNN_LANE, "invalid msg->obj");
        return;
    }
    StateNotifyInfo *info = (StateNotifyInfo*)msg->obj;
    switch (info->state) {
        case LANE_STATE_LINKUP:
            if (LaneLinkupNotify(info->peerUdid, &info->laneLinkInfo) != SOFTBUS_OK) {
                LNN_LOGE(LNN_LANE, "notify lane linkup fail");
            }
            break;
        case LANE_STATE_LINKDOWN:
            if (LaneLinkdownNotify(info->peerUdid, &info->laneLinkInfo) != SOFTBUS_OK) {
                LNN_LOGE(LNN_LANE, "notify lane linkdown fail");
            }
            break;
        default:
            LNN_LOGE(LNN_LANE, "lane state=%{public}d cannot found", info->state);
    }
    SoftBusFree(info);
}

static void HandleDelayDestroyLink(SoftBusMessage *msg)
{
    uint32_t laneReqId = (uint32_t)msg->arg1;
    uint64_t laneId = (uint64_t)msg->arg2;
    LNN_LOGI(LNN_LANE, "handle delay destroy message, laneReqId=%{public}u, laneId=%{public}" PRIu64 "",
        laneReqId, laneId);
    FreeLaneLink(laneReqId, laneId);
}

static void HandleDetectTimeout(SoftBusMessage *msg)
{
    uint32_t detectId = (uint32_t)msg->arg1;
    LNN_LOGI(LNN_LANE, "lane detect timeout. detectId=%{public}u", detectId);
    NotifyDetectTimeout(detectId);
}

static void MsgHandler(SoftBusMessage *msg)
{
    if (msg == NULL) {
        return;
    }
    switch (msg->what) {
        case MSG_TYPE_LANE_TRIGGER_LINK:
            LaneTriggerLink(msg);
            break;
        case MSG_TYPE_LANE_LINK_SUCCESS:
            LaneLinkSuccess(msg);
            break;
        case MSG_TYPE_LANE_LINK_FAIL:
            LaneLinkFail(msg);
            break;
        case MSG_TYPE_LANE_STATE_CHANGE:
            LaneStateChange(msg);
            break;
        case MSG_TYPE_DELAY_DESTROY_LINK:
            HandleDelayDestroyLink(msg);
            break;
        case MSG_TYPE_LANE_DETECT_TIMEOUT:
            HandleDetectTimeout(msg);
            break;
        default:
            LNN_LOGE(LNN_LANE, "msg type=%{public}d cannot found", msg->what);
            break;
    }
    return;
}

static int32_t InitLooper(void)
{
    g_laneLoopHandler.name = "transLaneLooper";
    g_laneLoopHandler.HandleMessage = MsgHandler;
    g_laneLoopHandler.looper = GetLooper(LOOP_TYPE_LANE);
    if (g_laneLoopHandler.looper == NULL) {
        LNN_LOGE(LNN_LANE, "transLane init looper fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void Init(const ILaneIdStateListener *listener)
{
    if (g_requestList != NULL) {
        LNN_LOGW(LNN_LANE, "already init");
        return;
    }
    if (InitLooper() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "init looper fail");
        return;
    }

    if (SoftBusMutexInit(&g_transLaneMutex, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "transLane mutex init fail");
        return;
    }
    g_requestList = (TransLaneList *)SoftBusCalloc(sizeof(TransLaneList));
    if (g_requestList == NULL) {
        LNN_LOGE(LNN_LANE, "transLane malloc fail");
        (void)SoftBusMutexDestroy(&g_transLaneMutex);
        return;
    }
    ListInit(&g_requestList->list);
    ListInit(&g_multiLinkList);
    g_laneIdCallback = (ILaneIdStateListener *)listener;
    if (InitLaneReliability() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "init laneReliability fail");
        return;
    }
}

static void Deinit(void)
{
    if (g_requestList == NULL) {
        return;
    }
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return;
    }
    TransReqInfo *item = NULL;
    TransReqInfo *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_requestList->list, TransReqInfo, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
        g_requestList->cnt--;
    }
    Unlock();
    (void)SoftBusMutexDestroy(&g_transLaneMutex);
    SoftBusFree(g_requestList);
    g_requestList = NULL;
}

static LaneInterface g_transLaneObject = {
    .init = Init,
    .deinit = Deinit,
    .allocLane = Alloc,
    .allocLaneByQos = AllocLaneByQos,
    .reallocLaneByQos = ReallocLaneByQos,
    .cancelLane = CancelLane,
    .freeLane = Free,
};

LaneInterface *TransLaneGetInstance(void)
{
    return &g_transLaneObject;
}

int32_t GetTransReqInfoByLaneReqId(uint32_t laneReqId, TransReqInfo *reqInfo)
{
    if (reqInfo == NULL || laneReqId == INVALID_LANE_REQ_ID) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return SOFTBUS_ERR;
    }
    TransReqInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_requestList->list, TransReqInfo, node) {
        if (item->laneReqId == laneReqId) {
            if (memcpy_s(reqInfo, sizeof(TransReqInfo), item, sizeof(TransReqInfo)) != EOK) {
                LNN_LOGE(LNN_LANE, "memcpy TransReqInfo fail");
                Unlock();
                return SOFTBUS_ERR;
            }
            Unlock();
            return SOFTBUS_OK;
        }
    }
    Unlock();
    return SOFTBUS_ERR;
}

int32_t PostDetectTimeoutMessage(uint32_t detectId, uint64_t delayMillis)
{
    LNN_LOGI(LNN_LANE, "post timeout message, detectId=%{public}u", detectId);
    return LnnLanePostMsgToHandler(MSG_TYPE_LANE_DETECT_TIMEOUT, detectId, 0, NULL, delayMillis);
}

static int32_t RemoveDetectTimeout(const SoftBusMessage *msg, void *data)
{
    uint32_t *detectId = (uint32_t *)data;
    if (msg->what != MSG_TYPE_LANE_DETECT_TIMEOUT) {
        return SOFTBUS_ERR;
    }
    if (msg->arg1 == *detectId) {
        LNN_LOGE(LNN_LANE, "remove detect timeout message success. detectId=%{public}u", *detectId);
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

void RemoveDetectTimeoutMessage(uint32_t detectId)
{
    LNN_LOGI(LNN_LANE, "remove detect timeout message. detectId=%{public}u", detectId);
    g_laneLoopHandler.looper->RemoveMessageCustom(g_laneLoopHandler.looper, &g_laneLoopHandler,
        RemoveDetectTimeout, &detectId);
}

int32_t PostDelayDestroyMessage(uint32_t laneReqId, uint64_t laneId, uint64_t delayMillis)
{
    LNN_LOGI(LNN_LANE, "post dely destroy message. laneReqId=%{public}u, laneId=%{public}" PRIu64 "",
        laneReqId, laneId);
    return LnnLanePostMsgToHandler(MSG_TYPE_DELAY_DESTROY_LINK, laneReqId, laneId, NULL, delayMillis);
}

int32_t PostLaneStateChangeMessage(LaneState state, const char *peerUdid, const LaneLinkInfo *laneLinkInfo)
{
    LNN_LOGI(LNN_LANE, "post lane state change msg, state=%{public}d", state);
    if (peerUdid == NULL || laneLinkInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    StateNotifyInfo *stateNotifyInfo = (StateNotifyInfo *)SoftBusCalloc(sizeof(StateNotifyInfo));
    if (stateNotifyInfo == NULL) {
        LNN_LOGE(LNN_LANE, "calloc stateNotifyInfo fail");
        return SOFTBUS_MALLOC_ERR;
    }
    stateNotifyInfo->state = state;
    if (strncpy_s(stateNotifyInfo->peerUdid, UDID_BUF_LEN, peerUdid, UDID_BUF_LEN) != EOK) {
        SoftBusFree(stateNotifyInfo);
        LNN_LOGE(LNN_STATE, "copy peerUdid fail");
        return SOFTBUS_STRCPY_ERR;
    }
    if (memcpy_s(&stateNotifyInfo->laneLinkInfo, sizeof(LaneLinkInfo), laneLinkInfo,
        sizeof(LaneLinkInfo)) != EOK) {
        SoftBusFree(stateNotifyInfo);
        LNN_LOGE(LNN_LANE, "memcpy laneLinkInfo fail");
        return SOFTBUS_MEM_ERR;
    }
    if (LnnLanePostMsgToHandler(MSG_TYPE_LANE_STATE_CHANGE, 0, 0, stateNotifyInfo, 0) != SOFTBUS_OK) {
        SoftBusFree(stateNotifyInfo);
        LNN_LOGE(LNN_LANE, "post lane state change msg fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t RemoveDelayDestroy(const SoftBusMessage *msg, void *data)
{
    uint64_t *laneId = (uint64_t *)data;
    if (msg->what == MSG_TYPE_DELAY_DESTROY_LINK && *laneId == (uint64_t)msg->arg2) {
        LNN_LOGI(LNN_LANE, "remove delay destroy message succ, laneId=%{public}" PRIu64 "", *laneId);
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

void RemoveDelayDestroyMessage(uint64_t laneId)
{
    g_laneLoopHandler.looper->RemoveMessageCustom(g_laneLoopHandler.looper, &g_laneLoopHandler,
        RemoveDelayDestroy, &laneId);
}

void DelLogicAndLaneRelationship(uint64_t laneId)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return;
    }
    TransReqInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_requestList->list, TransReqInfo, node) {
        if (item->laneId == laneId) {
            item->laneId = INVALID_LANE_ID;
        }
    }
    Unlock();
}
