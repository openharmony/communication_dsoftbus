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
#include "lnn_ctrl_lane.h"
#include "lnn_lane.h"
#include "lnn_lane_common.h"
#include "lnn_lane_def.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_link_p2p.h"
#include "lnn_lane_listener.h"
#include "lnn_lane_model.h"
#include "lnn_lane_reliability.h"
#include "lnn_lane_select.h"
#include "lnn_log.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_protocol_def.h"
#include "softbus_utils.h"
#include "wifi_direct_error_code.h"
#include "wifi_direct_manager.h"

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
    MSG_TYPE_LANE_RESULT_TIMEOUT,
} LaneMsgType;

typedef struct {
    uint32_t cnt;
    ListNode list;
} TransLaneList;

typedef enum {
    BUILD_LINK_STATUS_BUILDING = 0,
    BUILD_LINK_STATUS_FAIL,
    BUILD_LINK_STATUS_SUCC,
    BUILD_LINK_STATUS_BUTT,
} BuildLinkStatus;

typedef struct {
    BuildLinkStatus status;
    LaneLinkInfo linkInfo;
} LinkStatusInfo;

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
    char peerBleMac[MAX_MAC_LEN];
    LaneTransType transType;
    ProtocolType acceptableProtocols;
    // OldInfo
    int32_t psm;
    bool p2pOnly;
    LinkStatusInfo statusList[LANE_LINK_TYPE_BUTT];
    bool isCompleted;
} LaneLinkNodeInfo;

typedef struct {
    LaneState state;
    char peerUdid[UDID_BUF_LEN];
    LaneLinkInfo laneLinkInfo;
} StateNotifyInfo;

typedef struct {
    int32_t reason;
    LaneLinkType linkType;
} LinkFailInfo;

typedef struct {
    uint32_t laneReqId;
    LaneLinkType linkType;
} LaneTimeoutInfo;

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

static int32_t RemoveLaneTimeout(const SoftBusMessage *msg, void *data)
{
    LaneTimeoutInfo *info = (LaneTimeoutInfo *)data;
    if (msg->what != MSG_TYPE_LANE_RESULT_TIMEOUT || msg->arg1 != info->laneReqId) {
        return SOFTBUS_ERR;
    }
    if (info->linkType == LANE_LINK_TYPE_BUTT) {
        return SOFTBUS_OK;
    }
    if (msg->arg2 == info->linkType) {
        return SOFTBUS_OK;
    }
    LNN_LOGE(LNN_LANE, "remove build link timeout message fail. laneReqId=%{public}u, linkType=%{public}d",
        info->laneReqId, info->linkType);
    return SOFTBUS_ERR;
}

static void RemoveLaneTimeoutMessage(uint32_t laneReqId, LaneLinkType linkType)
{
    LNN_LOGI(LNN_LANE, "remove build link timeout message. laneReqId=%{public}u, linkType=%{public}d",
        laneReqId, linkType);
    LaneTimeoutInfo info = {
        .laneReqId = laneReqId,
        .linkType = linkType,
    };
    g_laneLoopHandler.looper->RemoveMessageCustom(g_laneLoopHandler.looper, &g_laneLoopHandler,
        RemoveLaneTimeout, &info);
}

static void LinkSuccess(uint32_t laneReqId, LaneLinkType linkType, const LaneLinkInfo *linkInfo)
{
    if (linkInfo == NULL) {
        LNN_LOGE(LNN_LANE, "linkSuccess param invalid");
        return;
    }
    RemoveLaneTimeoutMessage(laneReqId, linkType);
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
    if (LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_SUCCESS, laneReqId, linkType, linkParam, 0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "post LaneLinkSuccess msg err, laneReqId=%{public}u", laneReqId);
        SoftBusFree(linkParam);
    }
}

static void LinkFail(uint32_t laneReqId, int32_t reason, LaneLinkType linkType)
{
    RemoveLaneTimeoutMessage(laneReqId, linkType);
    LinkFailInfo *failInfo = (LinkFailInfo *)SoftBusCalloc(sizeof(LinkFailInfo));
    if (failInfo == NULL) {
        LNN_LOGE(LNN_LANE, "failInfo malloc fail");
        return;
    }
    failInfo->reason = reason;
    failInfo->linkType = linkType;
    if (LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_FAIL, laneReqId, 0, failInfo, 0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "post lanelink fail msg err");
        SoftBusFree(failInfo);
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

static int32_t PostLaneTimeoutMessage(uint32_t laneReqId, LaneLinkType linkType, uint64_t delayMillis)
{
    LNN_LOGI(LNN_LANE, "post build link timeout message, laneReqId=%{public}u, linkType=%{public}d",
        laneReqId, linkType);
    return LnnLanePostMsgToHandler(MSG_TYPE_LANE_RESULT_TIMEOUT, laneReqId, linkType, NULL, delayMillis);
}

static void InitStatusList(LaneLinkNodeInfo *linkNode)
{
    for (uint32_t i = 0; i < LANE_LINK_TYPE_BUTT; i++) {
        linkNode->statusList[i].status = BUILD_LINK_STATUS_BUTT;
        (void)memset_s(&linkNode->statusList[i].linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    }
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
    InitStatusList(linkNode);
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
    ret = PostLaneTimeoutMessage(laneReqId, LANE_LINK_TYPE_BUTT, DEFAULT_LINK_LATENCY);
    if (ret != SOFTBUS_OK) {
        DeleteLaneLinkNode(laneReqId);
        return ret;
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
    uint64_t maxLaneLatency = linkNode->restTime;
    InitStatusList(linkNode);
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
    ret = PostLaneTimeoutMessage(laneReqId, LANE_LINK_TYPE_BUTT, maxLaneLatency);
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
    LaneType type = (LaneType)(laneReqId >> LANE_REQ_ID_TYPE_SHIFT);
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
    if (reason == SOFTBUS_OK) {
        reason = SOFTBUS_LANE_SELECT_FAIL;
    }
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

static int32_t g_laneLatency[LANE_LINK_TYPE_BUTT] = {
    [LANE_BR] = BR_LATENCY,
    [LANE_BLE] = COC_DIRECT_LATENCY,
    [LANE_P2P] = P2P_LATENCY,
    [LANE_WLAN_2P4G] = WLAN_LATENCY,
    [LANE_WLAN_5G] = WLAN_LATENCY,
    [LANE_ETH] = WLAN_LATENCY,
    [LANE_P2P_REUSE] = P2P_LATENCY,
    [LANE_BLE_DIRECT] = COC_DIRECT_LATENCY,
    [LANE_BLE_REUSE] = COC_DIRECT_LATENCY,
    [LANE_COC] = COC_DIRECT_LATENCY,
    [LANE_COC_DIRECT] = COC_DIRECT_LATENCY,
    [LANE_HML] = HML_LATENCY,
};

static void LaneTriggerLink(SoftBusMessage *msg)
{
    uint32_t laneReqId = (uint32_t)msg->arg1;
    LaneLinkCb linkCb = {
        .OnLaneLinkSuccess = LinkSuccess,
        .OnLaneLinkFail = LinkFail,
    };
    LinkRequest requestInfo;
    (void)memset_s(&requestInfo, sizeof(LinkRequest), 0, sizeof(LinkRequest));
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
            LNN_LOGE(LNN_LANE, "Create LinkRequestNode fail.");
            Unlock();
            break;
        }
        nodeInfo->linkRetryIdx++;
        nodeInfo->statusList[requestInfo.linkType].status = BUILD_LINK_STATUS_BUILDING;
        Unlock();
        uint64_t delayMillis = g_laneLatency[requestInfo.linkType] * 9 / 10;
        // latancy * 9 / 10: timeout for each type of build link
        (void)PostLaneTimeoutMessage(laneReqId, requestInfo.linkType, delayMillis);
        ret = BuildLink(&requestInfo, laneReqId, &linkCb);
        if (ret == SOFTBUS_OK) {
            return;
        }
    } while (false);
    linkCb.OnLaneLinkFail(laneReqId, ret, requestInfo.linkType);
}

static void FreeUnusedLink(uint32_t laneReqId, const LaneLinkInfo *linkInfo)
{
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

static int32_t UpdateLinkStatus(uint32_t laneReqId, BuildLinkStatus status, LaneLinkType linkType,
    const LaneLinkInfo *linkInfo)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneLinkNodeInfo *nodeInfo = GetLaneLinkNodeWithoutLock(laneReqId);
    if (nodeInfo == NULL) {
        Unlock();
        LNN_LOGE(LNN_LANE, "get lane link node info fail, laneReqId=%{public}u", laneReqId);
        if (status == BUILD_LINK_STATUS_SUCC) {
            FreeUnusedLink(laneReqId, linkInfo);
        }
        return SOFTBUS_ERR;
    }
    if (nodeInfo->isCompleted) {
        Unlock();
        LNN_LOGE(LNN_LANE, "build link has completed, not need update link status. laneReqId=%{public}u, "
            "linkType=%{public}d", laneReqId, linkType);
        if (status == BUILD_LINK_STATUS_SUCC) {
            FreeUnusedLink(laneReqId, linkInfo);
        }
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_LANE, "update link status, laneReqId=%{public}u, status=%{public}d, linkType=%{public}d",
        laneReqId, status, linkType);
    nodeInfo->statusList[linkType].status = status;
    if (status != BUILD_LINK_STATUS_SUCC) {
        Unlock();
        return SOFTBUS_OK;
    }
    if (memcpy_s(&(nodeInfo->statusList[linkType].linkInfo), sizeof(LaneLinkInfo), linkInfo,
        sizeof(LaneLinkInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "linkParam memcpy fail, laneReqId=%{public}u", laneReqId);
        Unlock();
        return SOFTBUS_ERR;
    }
    Unlock();
    return SOFTBUS_OK;
}

static bool IsNeedNotifySucc(uint32_t laneReqId)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return false;
    }
    LaneLinkNodeInfo *nodeInfo = GetLaneLinkNodeWithoutLock(laneReqId);
    if (nodeInfo == NULL) {
        Unlock();
        LNN_LOGE(LNN_LANE, "get lane link node info fail, laneReqId=%{public}u", laneReqId);
        return false;
    }
    bool isBuilding = false;
    for (uint32_t i = 0; i < nodeInfo->listNum; i++) {
        LaneLinkType linkType = nodeInfo->linkList->linkType[i];
        if (nodeInfo->statusList[linkType].status == BUILD_LINK_STATUS_BUILDING) {
            isBuilding = true;
        }
        if (!isBuilding && nodeInfo->statusList[linkType].status == BUILD_LINK_STATUS_SUCC) {
            nodeInfo->isCompleted = true;
            Unlock();
            return true;
        }
    }
    Unlock();
    return false;
}

static int32_t GetLaneLinkInfo(uint32_t laneReqId, LaneLinkType *type, LaneLinkInfo *info)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneLinkNodeInfo *nodeInfo = GetLaneLinkNodeWithoutLock(laneReqId);
    if (nodeInfo == NULL) {
        Unlock();
        LNN_LOGE(LNN_LANE, "get lane link node info fail, laneReqId=%{public}u", laneReqId);
        return SOFTBUS_ERR;
    }
    for (uint32_t i = 0; i < nodeInfo->listNum; i++) {
        LaneLinkType linkType = nodeInfo->linkList->linkType[i];
        if (nodeInfo->statusList[linkType].status == BUILD_LINK_STATUS_SUCC) {
            if (memcpy_s(info, sizeof(LaneLinkInfo), &(nodeInfo->statusList[linkType].linkInfo),
                sizeof(LaneLinkInfo)) != EOK) {
                Unlock();
                LNN_LOGE(LNN_LANE, "info memcpy fail, laneReqId=%{public}u", laneReqId);
                return SOFTBUS_ERR;
            }
            *type = linkType;
            Unlock();
            return SOFTBUS_OK;
        }
    }
    Unlock();
    LNN_LOGE(LNN_LANE, "not found LaneLinkInfo, laneReqId=%{public}u", laneReqId);
    return SOFTBUS_ERR;
}

static void FreeLowPriorityLink(uint32_t laneReqId, LaneLinkType linkType)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return;
    }
    LaneLinkNodeInfo *nodeInfo = GetLaneLinkNodeWithoutLock(laneReqId);
    if (nodeInfo == NULL) {
        Unlock();
        LNN_LOGE(LNN_LANE, "get lane link node info fail, laneReqId=%{public}u", laneReqId);
        return;
    }
    LinkStatusInfo statusList[LANE_LINK_TYPE_BUTT];
    (void)memset_s(&statusList, sizeof(statusList), 0, sizeof(statusList));
    uint32_t listNum = 0;
    for (uint32_t i = 0; i < nodeInfo->listNum; i++) {
        LaneLinkType type = nodeInfo->linkList->linkType[i];
        if (type != linkType && nodeInfo->statusList[type].status == BUILD_LINK_STATUS_SUCC) {
            if (memcpy_s(&statusList[listNum++], sizeof(LinkStatusInfo), &nodeInfo->statusList[type],
                sizeof(LinkStatusInfo)) != EOK) {
                continue;
            }
        }
    }
    Unlock();
    for (uint32_t i = 0; i < listNum; i++) {
        FreeUnusedLink(laneReqId, &statusList[i].linkInfo);
    }
}

static void NotifyLinkSucc(uint32_t laneReqId)
{
    LaneLinkType linkType;
    LaneLinkInfo info;
    (void)memset_s(&info, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    if (GetLaneLinkInfo(laneReqId, &linkType, &info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get LaneLinkInfo fail, laneReqId=%{public}u", laneReqId);
        NotifyLaneAllocFail(laneReqId, SOFTBUS_LANE_TRIGGER_LINK_FAIL);
        return;
    }
    char localUdid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid fail, laneReqId=%{public}u", laneReqId);
        NotifyLaneAllocFail(laneReqId, SOFTBUS_LANE_TRIGGER_LINK_FAIL);
        return;
    }
    uint64_t laneId = ApplyLaneId(localUdid, info.peerUdid, info.type);
    if (laneId == INVALID_LANE_ID) {
        LNN_LOGE(LNN_LANE, "apply laneId fail, laneReqId=%{public}u", laneReqId);
        NotifyLaneAllocFail(laneReqId, SOFTBUS_LANE_TRIGGER_LINK_FAIL);
        return;
    }
    int32_t ret = AddLaneResourceToPool(&info, laneId, false);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add linkInfo item fail, laneReqId=%{public}u", laneReqId);
        NotifyLaneAllocFail(laneReqId, SOFTBUS_LANE_TRIGGER_LINK_FAIL);
        return;
    }
    NotifyLaneAllocSuccess(laneReqId, laneId, &info);
    FreeLowPriorityLink(laneReqId, linkType);
    LaneType laneType;
    if (ParseLaneTypeByLaneReqId(laneReqId, &laneType) != SOFTBUS_OK ||
        AddLaneBusinessInfoItem(laneType, laneId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "create laneBusinessInfo fail, laneReqId=%{public}u", laneReqId);
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
    LaneLinkType linkType = (LaneLinkType)msg->arg2;
    if (UpdateLinkStatus(laneReqId, BUILD_LINK_STATUS_SUCC, linkType, info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "update link status fail, laneReqId=%{public}u", laneReqId);
        SoftBusFree(info);
        return;
    }
    SoftBusFree(info);
    if (IsNeedNotifySucc(laneReqId)) {
        RemoveLaneTimeoutMessage(laneReqId, LANE_LINK_TYPE_BUTT);
        NotifyLinkSucc(laneReqId);
        DeleteLaneLinkNode(laneReqId);
    }
}

static void NotifyRetryOrFail(uint32_t laneReqId, LaneLinkType linkType, int32_t reason)
{
    int32_t failReason = SOFTBUS_ERR;
    bool allFail = false;
    bool needRetry = false;
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return;
    }
    LaneLinkNodeInfo *nodeInfo = GetLaneLinkNodeWithoutLock(laneReqId);
    if (nodeInfo == NULL) {
        Unlock();
        LNN_LOGE(LNN_LANE, "get lane link node info fail, laneReqId=%{public}u", laneReqId);
        return;
    }
    if ((reason >= ERROR_WIFI_DIRECT_END && reason <= ERROR_WIFI_DIRECT_START) ||
        (reason >= V1_ERROR_END && reason <= V1_ERROR_START) || nodeInfo->linkRetryIdx == 1) {
        nodeInfo->p2pErrCode = reason;
    }
    failReason = nodeInfo->p2pErrCode;
    if (nodeInfo->linkRetryIdx >= nodeInfo->listNum) {
        LNN_LOGE(LNN_LANE, "All linkType have been tried, laneReqId=%{public}u", laneReqId);
        allFail = true;
    } else {
        needRetry = true;
    }
    for (uint32_t i = 0; i < nodeInfo->linkRetryIdx; i++) {
        LaneLinkType linkType = nodeInfo->linkList->linkType[i];
        if (nodeInfo->statusList[linkType].status != BUILD_LINK_STATUS_FAIL) {
            allFail = false;
        }
        if (nodeInfo->statusList[linkType].status == BUILD_LINK_STATUS_SUCC) {
            needRetry = false;
        }
    }
    nodeInfo->isCompleted = allFail ? true : false;
    Unlock();
    if (allFail) {
        RemoveLaneTimeoutMessage(laneReqId, LANE_LINK_TYPE_BUTT);
        NotifyLaneAllocFail(laneReqId, failReason);
        DeleteLaneLinkNode(laneReqId);
    }
    if (needRetry) {
        (void)LnnLanePostMsgToHandler(MSG_TYPE_LANE_TRIGGER_LINK, laneReqId, 0, NULL, 0);
    }
}

static void LaneLinkFail(SoftBusMessage *msg)
{
    if (msg->obj == NULL) {
        LNN_LOGE(LNN_LANE, "invalid msg->obj");
        return;
    }
    LinkFailInfo *failInfo = (LinkFailInfo *)msg->obj;
    int32_t reason = failInfo->reason;
    LaneLinkType linkType = failInfo->linkType;
    SoftBusFree(failInfo);
    uint32_t laneReqId = (uint32_t)msg->arg1;
    LNN_LOGI(LNN_LANE, "lane link fail, laneReqId=%{public}u, reason=%{public}d", laneReqId, reason);
    if (UpdateLinkStatus(laneReqId, BUILD_LINK_STATUS_FAIL, linkType, NULL) != SOFTBUS_OK) {
        return;
    }
    if (IsNeedNotifySucc(laneReqId)) {
        RemoveLaneTimeoutMessage(laneReqId, LANE_LINK_TYPE_BUTT);
        NotifyLinkSucc(laneReqId);
        DeleteLaneLinkNode(laneReqId);
    } else {
        NotifyRetryOrFail(laneReqId, linkType, reason);
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

static void HandleWholeProcessTimeout(uint32_t laneReqId)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return;
    }
    LaneLinkNodeInfo *nodeInfo = GetLaneLinkNodeWithoutLock(laneReqId);
    if (nodeInfo == NULL) {
        Unlock();
        LNN_LOGE(LNN_LANE, "get lane link node info fail, laneReqId=%{public}u", laneReqId);
        return;
    }
    int32_t failReason = nodeInfo->p2pErrCode;
    if (nodeInfo->p2pErrCode == SOFTBUS_OK) {
        nodeInfo->p2pErrCode = SOFTBUS_TIMOUT;
        failReason = SOFTBUS_TIMOUT;
    }
    bool hasSucc = false;
    for (uint32_t i = 0; i < nodeInfo->listNum; i++) {
        LaneLinkType linkType = nodeInfo->linkList->linkType[i];
        if (nodeInfo->statusList[linkType].status == BUILD_LINK_STATUS_SUCC) {
            hasSucc = true;
            break;
        }
    }
    nodeInfo->isCompleted = true;
    Unlock();
    if (hasSucc) {
        NotifyLinkSucc(laneReqId);
    } else {
        NotifyLaneAllocFail(laneReqId, failReason);
    }
    DeleteLaneLinkNode(laneReqId);
}

static void HandleTypeProcessTimeout(uint32_t laneReqId)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return;
    }
    LaneLinkNodeInfo *nodeInfo = GetLaneLinkNodeWithoutLock(laneReqId);
    if (nodeInfo == NULL) {
        Unlock();
        LNN_LOGE(LNN_LANE, "get lane link node info fail, laneReqId=%{public}u", laneReqId);
        return;
    }
    if (nodeInfo->linkRetryIdx >= nodeInfo->listNum) {
        LNN_LOGE(LNN_LANE, "All linkType have been tried, laneReqId=%{public}u", laneReqId);
        Unlock();
        return;
    }
    for (uint32_t i = 0; i < nodeInfo->linkRetryIdx; i++) {
        LaneLinkType linkType = nodeInfo->linkList->linkType[i];
        if (nodeInfo->statusList[linkType].status == BUILD_LINK_STATUS_SUCC) {
            Unlock();
            return;
        }
    }
    if (nodeInfo->linkList->linkType[nodeInfo->linkRetryIdx] == LANE_P2P) {
        for (uint32_t i = 0; i < nodeInfo->linkRetryIdx; i++) {
            LaneLinkType type = nodeInfo->linkList->linkType[i];
            if (type == LANE_HML && nodeInfo->statusList[type].status == BUILD_LINK_STATUS_BUILDING) {
                LNN_LOGI(LNN_LANE, "refuse same type link repeat build, laneReqId=%{public}u", laneReqId);
                Unlock();
                return;
            }
        }
    }
    Unlock();
    (void)LnnLanePostMsgToHandler(MSG_TYPE_LANE_TRIGGER_LINK, laneReqId, 0, NULL, 0);
}

static void HandleLaneTimeout(SoftBusMessage *msg)
{
    uint32_t laneReqId = (uint32_t)msg->arg1;
    LaneLinkType linkType = (LaneLinkType)msg->arg2;
    if (linkType == LANE_LINK_TYPE_BUTT) {
        HandleWholeProcessTimeout(laneReqId);
    } else {
        HandleTypeProcessTimeout(laneReqId);
    }
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
        case MSG_TYPE_LANE_RESULT_TIMEOUT:
            HandleLaneTimeout(msg);
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

static int32_t AllocAuthLane(uint32_t laneHandle, const LaneAllocInfo *allocInfo, const LaneAllocListener *listener)
{
    AuthLinkTypeList authList;
    if (memset_s(&authList, sizeof(AuthLinkTypeList), 0, sizeof(AuthLinkTypeList)) != EOK) {
        LNN_LOGE(LNN_LANE, "memset_s authList fail");
        return SOFTBUS_ERR;
    }
    if (GetAuthLinkTypeList(allocInfo->networkId, &authList) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get authList fail");
        return SOFTBUS_ERR;
    }

    LanePreferredLinkList request;
    if (memset_s(&request, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList)) != EOK) {
        LNN_LOGE(LNN_LANE, "memset_s request fail");
        return SOFTBUS_ERR;
    }
    if (ConvertAuthLinkToLaneLink(&authList, &request) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "convert authLink to laneLink fail");
        return SOFTBUS_ERR;
    }
    LanePreferredLinkList *recommendLinkList = (LanePreferredLinkList *)SoftBusCalloc(sizeof(LanePreferredLinkList));
    if (recommendLinkList == NULL) {
        LNN_LOGE(LNN_LANE, "calloc recommendLinkList fail");
        return SOFTBUS_MALLOC_ERR;
    }
    recommendLinkList->linkTypeNum = 0;
    if (SelectAuthLane(allocInfo->networkId, &request, recommendLinkList) != SOFTBUS_OK ||
        recommendLinkList->linkTypeNum == 0) {
        SoftBusFree(recommendLinkList);
        LNN_LOGE(LNN_LANE, "no abailable link resources, laneHandle=%{public}u", laneHandle);
        return SOFTBUS_ERR;
    }
    for (uint32_t i = 0; i < recommendLinkList->linkTypeNum; ++i) {
        LNN_LOGI(LNN_LANE, "auth expect recommendLinkList nums=%{public}u, priority=%{public}u, link=%{public}u",
            recommendLinkList->linkTypeNum, i, recommendLinkList->linkType[i]);
    }
    if (StartTriggerLink(laneHandle, allocInfo, listener, recommendLinkList) != SOFTBUS_OK) {
        SoftBusFree(recommendLinkList);
        LNN_LOGE(LNN_LANE, "trigger link fail, laneHandle=%{public}u", laneHandle);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t CtrlAlloc(uint32_t laneHandle, const LaneAllocInfo *allocInfo, const LaneAllocListener *listener)
{
    if (laneHandle == INVALID_LANE_REQ_ID || allocInfo == NULL || allocInfo->type != LANE_TYPE_CTRL) {
        LNN_LOGE(LNN_LANE, "param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (AllocAuthLane(laneHandle, allocInfo, listener) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "alloc valid lane fail, laneHandle=%{public}u", laneHandle);
        FreeLaneReqId(laneHandle);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t CtrlFree(uint32_t laneHandle)
{
    return Free(laneHandle);
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
