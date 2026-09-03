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

#include "lnn_trans_lane.h"

#include <securec.h>

#include "lnn_log.h"

#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_lane_common.h"
#include "lnn_lane_reliability.h"
#include "lnn_select_rule.h"
#include "lnn_trans_free_lane.h"
#include "softbus_adapter_mem.h"

#define DEFAULT_LINK_LATENCY 30000

typedef enum {
    MSG_TYPE_LANE_TRIGGER_LINK = 0,
    MSG_TYPE_LANE_LINK_SUCCESS,
    MSG_TYPE_LANE_LINK_FAIL,
    MSG_TYPE_LANE_STATE_CHANGE,
    MSG_TYPE_DELAY_DESTROY_LINK,
    MSG_TYPE_LANE_DETECT_TIMEOUT,
    MSG_TYPE_LANE_LINK_TIMEOUT,
    MSG_TYPE_NOTIFY_FREE_LANE_RESULT,
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
    int32_t result;
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
    uint32_t bandWidth;
    uint64_t triggerLinkTime;
    uint64_t availableLinkTime;
    uint64_t singleLinkTime[LANE_LINK_TYPE_BUTT];
    char peerBleMac[MAX_MAC_LEN];
    LaneTransType transType;
    ProtocolType acceptableProtocols;
    // OldInfo
    int32_t psm;
    bool p2pOnly;
    LinkStatusInfo statusList[LANE_LINK_TYPE_BUTT];
    bool isCompleted;
    uint32_t actionAddr;
    bool isSupportIpv6;
    bool isVirtualLink;
    bool isInnerCalled; // Indicates whether to select a link for TransOpenNetWorkingChannel
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

static int32_t RemoveLinkTimeout(const SoftBusMessage *msg, void *data)
{
    LaneTimeoutInfo *info = (LaneTimeoutInfo *)data;
    if (msg->what != MSG_TYPE_LANE_LINK_TIMEOUT || msg->arg1 != info->laneReqId) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (info->linkType == LANE_LINK_TYPE_BUTT) {
        LNN_LOGI(LNN_LANE, "remove build link timeout message succ. laneReqId=%{public}u, linkType=%{public}d",
            info->laneReqId, info->linkType);
        return SOFTBUS_OK;
    }
    if (msg->arg2 == info->linkType) {
        LNN_LOGI(LNN_LANE, "remove build link timeout message succ. laneReqId=%{public}u, linkType=%{public}d",
            info->laneReqId, info->linkType);
        return SOFTBUS_OK;
    }
    return SOFTBUS_INVALID_PARAM;
}

static void RemoveLinkTimeoutMessage(uint32_t laneReqId, LaneLinkType linkType)
{
    LNN_LOGI(LNN_LANE, "remove build link timeout message. laneReqId=%{public}u, linkType=%{public}d",
        laneReqId, linkType);
    LaneTimeoutInfo info = {
        .laneReqId = laneReqId,
        .linkType = linkType,
    };
    g_laneLoopHandler.looper->RemoveMessageCustom(g_laneLoopHandler.looper, &g_laneLoopHandler,
        RemoveLinkTimeout, &info);
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

static uint64_t GetBuildLinkTime(uint32_t laneReqId, LaneLinkType linkType)
{
    if (linkType >= LANE_LINK_TYPE_BUTT) {
        return 0;
    }
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return 0;
    }
    LaneLinkNodeInfo *nodeInfo = GetLaneLinkNodeWithoutLock(laneReqId);
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LANE, "get lane link node info fail, laneReqId=%{public}u", laneReqId);
        Unlock();
        return 0;
    }
    uint64_t startBuildTime = nodeInfo->singleLinkTime[linkType];
    Unlock();
    return startBuildTime > 0 ? GetCostTime(startBuildTime) : 0;
}

static void LinkSuccess(uint32_t laneReqId, LaneLinkType linkType, const LaneLinkInfo *linkInfo)
{
    LNN_LOGI(LNN_LANE, "build link succ, laneReqId=%{public}u, link=%{public}d", laneReqId, linkType);
    if (linkInfo == NULL) {
        LNN_LOGE(LNN_LANE, "linkSuccess param invalid");
        return;
    }
    RemoveLinkTimeoutMessage(laneReqId, linkType);
    LaneLinkInfo *linkParam = (LaneLinkInfo *)SoftBusCalloc(sizeof(LaneLinkInfo));
    if (linkParam == NULL) {
        LNN_LOGE(LNN_LANE, "linkSuccess info malloc fail");
        (void)LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_FAIL, laneReqId, SOFTBUS_MALLOC_ERR, NULL, 0);
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
    LNN_LOGE(LNN_LANE, "build link fail, laneReqId=%{public}u, link=%{public}d, reason=%{public}d",
        laneReqId, linkType, reason);
    RemoveLinkTimeoutMessage(laneReqId, linkType);
    LinkFailInfo *failInfo = (LinkFailInfo *)SoftBusCalloc(sizeof(LinkFailInfo));
    if (failInfo == NULL) {
        LNN_LOGE(LNN_LANE, "failInfo malloc fail");
        (void)LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_FAIL, laneReqId, SOFTBUS_MALLOC_ERR, NULL, 0);
        return;
    }
    failInfo->reason = reason;
    failInfo->linkType = linkType;
    if (LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_FAIL, laneReqId, (uint64_t)reason, failInfo, 0) != SOFTBUS_OK) {
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

static int32_t PostLinkTimeoutMessage(uint32_t laneReqId, LaneLinkType linkType, uint64_t delayMillis)
{
    LNN_LOGI(LNN_LANE, "post build link timeout message, laneReqId=%{public}u, linkType=%{public}d",
        laneReqId, linkType);
    return LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_TIMEOUT, laneReqId, linkType, NULL, delayMillis);
}

static void InitStatusList(LaneLinkNodeInfo *linkNode)
{
    for (uint32_t i = 0; i < LANE_LINK_TYPE_BUTT; i++) {
        linkNode->statusList[i].status = BUILD_LINK_STATUS_BUTT;
        linkNode->statusList[i].result = SOFTBUS_LANE_BUILD_LINK_FAIL;
        (void)memset_s(&linkNode->statusList[i].linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    }
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
    if (memcpy_s(&newNode->allocInfo.networkId, NETWORK_ID_BUF_LEN,
        option->networkId, NETWORK_ID_BUF_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy fail for allocInfo networkId");
        SoftBusFree(newNode);
        return NULL;
    }
    newNode->isWithQos = false;
    newNode->isCanceled = false;
    newNode->isNotified = false;
    newNode->notifyFree = false;
    newNode->hasNotifiedFree = false;
    newNode->laneReqId = laneReqId;
    newNode->extraInfo.isSupportIpv6 = option->isSupportIpv6;
    ListInit(&newNode->node);
    return newNode;
}

int32_t DeleteRequestNode(uint32_t laneReqId)
{
    if (laneReqId == INVALID_LANE_REQ_ID) {
        LNN_LOGE(LNN_LANE, "laneHandle is invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    TransReqInfo *item = NULL;
    TransReqInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_requestList->list, TransReqInfo, node) {
        if (item->laneReqId == laneReqId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_requestList->cnt--;
            Unlock();
            return SOFTBUS_OK;
        }
    }
    Unlock();
    LNN_LOGE(LNN_LANE, "not found request node, laneReqId=%{public}d", laneReqId);
    return SOFTBUS_LANE_NOT_FOUND;
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
    newNode->extraInfo.actionAddr = allocInfo->extendInfo.actionAddr;
    newNode->extraInfo.isSupportIpv6 = allocInfo->extendInfo.isSupportIpv6;
    newNode->extraInfo.isVirtualLink = allocInfo->extendInfo.isVirtualLink;
    newNode->laneReqId = laneReqId;
    newNode->isWithQos = true;
    newNode->isCanceled = false;
    newNode->isNotified = false;
    newNode->notifyFree = false;
    newNode->hasNotifiedFree = false;
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
    if (memcpy_s(linkNode->networkId, NETWORK_ID_BUF_LEN, allocInfo->networkId, NETWORK_ID_BUF_LEN) != EOK) {
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
    linkNode->acceptableProtocols = allocInfo->acceptableProtocols;
    linkNode->actionAddr = allocInfo->extendInfo.actionAddr;
    linkNode->isSupportIpv6 = allocInfo->extendInfo.isSupportIpv6;
    linkNode->isVirtualLink = allocInfo->extendInfo.isVirtualLink;
    linkNode->bandWidth = allocInfo->qosRequire.minBW;
    linkNode->triggerLinkTime = SoftBusGetSysTimeMs();
    linkNode->availableLinkTime = allocInfo->qosRequire.maxLaneLatency != 0 ?
        allocInfo->qosRequire.maxLaneLatency : DEFAULT_LINK_LATENCY;
    (void)memset_s(linkNode->singleLinkTime, sizeof(linkNode->singleLinkTime), 0, sizeof(linkNode->singleLinkTime));
    linkNode->isCompleted = false;
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
    LanePreferredLinkList *recommendLinkList = (LanePreferredLinkList *)SoftBusCalloc(sizeof(LanePreferredLinkList));
    if (recommendLinkList == NULL) {
        LNN_LOGE(LNN_LANE, "recommendLinkList malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    recommendLinkList->linkTypeNum = 0;
    int32_t ret = SelectExpectLanesByQos((const char *)allocInfo->networkId, &selectParam, recommendLinkList);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(recommendLinkList);
        LNN_LOGE(LNN_LANE, "selectExpectLanesByQos fail, laneReqId=%{public}u", laneReqId);
        return ret;
    }
    if (recommendLinkList->linkTypeNum == 0) {
        SoftBusFree(recommendLinkList);
        LNN_LOGE(LNN_LANE, "no available link resources, laneReqId=%{public}u", laneReqId);
        return SOFTBUS_LANE_NO_AVAILABLE_LINK;
    }
    for (uint32_t i = 0; i < recommendLinkList->linkTypeNum; i++) {
        LNN_LOGI(LNN_LANE, "expect linklist nums=%{public}u, priority=%{public}u, link=%{public}u",
            recommendLinkList->linkTypeNum, i, recommendLinkList->linkType[i]);
    }
    ret = StartTriggerLink(laneReqId, allocInfo, listener, recommendLinkList);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(recommendLinkList);
        LNN_LOGE(LNN_LANE, "trigger link fail, laneReqId=%{public}u", laneReqId);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t AllocLaneByQos(uint32_t laneReqId, const LaneAllocInfo *allocInfo, const LaneAllocListener *listener)
{
    if (laneReqId == INVALID_LANE_REQ_ID || allocInfo == NULL ||
        allocInfo->type != LANE_TYPE_TRANS || listener == NULL) {
        LNN_LOGE(LNN_LANE, "allocLane param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = AllocValidLane(laneReqId, INVALID_LANE_ID, allocInfo, listener);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "alloc valid lane fail, laneReqId=%{public}u", laneReqId);
        return ret;
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

int32_t PostNotifyFreeLaneResult(uint32_t laneReqId, int32_t errCode, uint64_t delayMillis)
{
    LNN_LOGI(LNN_LANE, "post notify free lane result message, laneReqId=%{public}u, errCode=%{public}d",
        laneReqId, errCode);
    return LnnLanePostMsgToHandler(MSG_TYPE_NOTIFY_FREE_LANE_RESULT, laneReqId, errCode, NULL, delayMillis);
}

static int32_t CancelLane(uint32_t laneReqId)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    TransReqInfo *item = NULL;
    TransReqInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_requestList->list, TransReqInfo, node) {
        if (item->isWithQos && item->laneReqId == laneReqId) {
            if (item->isNotified) {
                Unlock();
                LNN_LOGE(LNN_LANE, "cancel lane fail, lane result has notified, laneReqId=%{public}u", laneReqId);
                return SOFTBUS_INVALID_PARAM;
            }
            item->isCanceled = true;
            Unlock();
            LNN_LOGI(LNN_LANE, "cancel lane succ, laneReqId=%{public}u", laneReqId);
            return SOFTBUS_OK;
        }
    }
    Unlock();
    LNN_LOGE(LNN_LANE, "cancel lane fail, lane reqinfo not find, laneReqId=%{public}u", laneReqId);
    return SOFTBUS_LANE_NOT_FOUND;
}

int32_t UpdateAndGetReqInfoByFree(uint32_t laneReqId, TransReqInfo *reqInfo)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    TransReqInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_requestList->list, TransReqInfo, node) {
        if (item->laneReqId == laneReqId) {
            if (memcpy_s(reqInfo, sizeof(TransReqInfo), item, sizeof(TransReqInfo)) != EOK) {
                Unlock();
                return SOFTBUS_MEM_ERR;
            }
            item->notifyFree = true;
            reqInfo->notifyFree = true;
            Unlock();
            return SOFTBUS_OK;
        }
    }
    Unlock();
    LNN_LOGE(LNN_LANE, "not found lane need free, laneReqId=%{public}u", laneReqId);
    return SOFTBUS_LANE_NOT_FOUND;
}

static bool IsValidLaneAllocRequest(TransReqInfo *reqInfo)
{
    if (reqInfo->isCanceled || reqInfo->notifyFree) {
        return false;
    }
    return true;
}

static int32_t UpdateAndGetReqInfByAlloc(uint32_t laneReqId, uint64_t laneId, TransReqInfo *reqInfo)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    TransReqInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_requestList->list, TransReqInfo, node) {
        if (item->laneReqId == laneReqId) {
            if (memcpy_s(reqInfo, sizeof(TransReqInfo), item, sizeof(TransReqInfo)) != EOK) {
                Unlock();
                return SOFTBUS_MEM_ERR;
            }
            if (IsValidLaneAllocRequest(reqInfo)) {
                item->isNotified = true;
                item->laneId = laneId;
                reqInfo->isNotified = true;
                reqInfo->laneId = laneId;
            }
            Unlock();
            return SOFTBUS_OK;
        }
    }
    Unlock();
    return SOFTBUS_LANE_NOT_FOUND;
}

static void NotifyLaneAllocSuccess(uint32_t laneReqId, uint64_t laneId, const LaneLinkInfo *info)
{
    TransReqInfo reqInfo;
    (void)memset_s(&reqInfo, sizeof(TransReqInfo), 0, sizeof(TransReqInfo));
    int32_t ret = UpdateAndGetReqInfByAlloc(laneReqId, laneId, &reqInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get reqInfo failed, ret=%{public}d", ret);
        return;
    }
    if (!reqInfo.isNotified) {
        LNN_LOGE(LNN_LANE, "request status abnormal. laneReqId=%{public}u isCanceled=%{public}d notifyFree=%{public}d",
            reqInfo.laneReqId, reqInfo.isCanceled, reqInfo.notifyFree);
        if (reqInfo.isCanceled) {
            reqInfo.listener.onLaneAllocFail(laneReqId, SOFTBUS_LANE_SUCC_AFTER_CANCELED);
        }
        if (reqInfo.notifyFree) {
            // do nothing
        }
        return;
    }
    LaneConnInfo connInfo;
    if (LaneInfoProcess(info, &connInfo, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lane alloc success, but laneInfo proc fail");
        return;
    }
    LNN_LOGI(LNN_LANE, "Notify laneAlloc succ, laneReqId=%{public}u, linkType=%{public}d, "
        "laneId=%{public}" PRIu64 "", laneReqId, info->type, laneId);
    connInfo.laneId = laneId;
    reqInfo.listener.onLaneAllocSuccess(laneReqId, &connInfo);
}

static void NotifyLaneAllocFail(uint32_t laneReqId, int32_t reason)
{
    TransReqInfo reqInfo;
    (void)memset_s(&reqInfo, sizeof(TransReqInfo), 0, sizeof(TransReqInfo));
    if (UpdateAndGetReqInfByAlloc(laneReqId, INVALID_LANE_ID, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lane reqInfo fail");
        return;
    }
    if (reqInfo.isWithQos && reqInfo.isCanceled) {
        LNN_LOGE(LNN_LANE, "lane has canceled only notify fail, laneReqId=%{public}u", laneReqId);
    }
    LNN_LOGE(LNN_LANE, "Notify laneAlloc fail, laneReqId=%{public}u, reason=%{public}d", laneReqId, reason);
    if (reqInfo.isWithQos) {
        reqInfo.listener.onLaneAllocFail(laneReqId, reason);
    } else {
        reqInfo.extraInfo.listener.onLaneRequestFail(laneReqId, reason);
    }
    DeleteRequestNode(laneReqId);
    FreeLaneReqId(laneReqId);
}

static int32_t GetErrCodeWithLock(uint32_t laneReqId)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneLinkNodeInfo *nodeInfo = GetLaneLinkNodeWithoutLock(laneReqId);
    if (nodeInfo == NULL || nodeInfo->linkList == NULL) {
        LNN_LOGE(LNN_LANE, "get lane link node info fail, laneReqId=%{public}u", laneReqId);
        Unlock();
        return SOFTBUS_LANE_NOT_FOUND;
    }
    LaneLinkType linkType = nodeInfo->linkList->linkType[0];
    int32_t result = nodeInfo->statusList[linkType].result;
    Unlock();
    return result;
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
    requestInfo->actionAddr = nodeInfo->actionAddr;
    requestInfo->isSupportIpv6 = nodeInfo->isSupportIpv6;
    requestInfo->isVirtualLink = nodeInfo->isVirtualLink;
    requestInfo->isInnerCalled = nodeInfo->isInnerCalled;
    if (memcpy_s(requestInfo->peerNetworkId, NETWORK_ID_BUF_LEN, nodeInfo->networkId, NETWORK_ID_BUF_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(requestInfo->peerBleMac, MAX_MAC_LEN, nodeInfo->peerBleMac, MAX_MAC_LEN) != EOK) {
        LNN_LOGE(LNN_LANE, "memcpy peerBleMac fail");
        return SOFTBUS_MEM_ERR;
    }
    requestInfo->bandWidth = nodeInfo->bandWidth;
    requestInfo->triggerLinkTime = nodeInfo->triggerLinkTime;
    requestInfo->availableLinkTime = nodeInfo->availableLinkTime;
    return SOFTBUS_OK;
}

static int32_t g_laneLatency[LANE_LINK_TYPE_BUTT] = {
    [LANE_WLAN_2P4G] = WLAN_LATENCY,
    [LANE_WLAN_5G] = WLAN_LATENCY,
};

static void LaneTriggerLink(SoftBusMessage *msg)
{
    uint32_t laneReqId = (uint32_t)msg->arg1;
    LaneLinkCb linkCb = {
        .onLaneLinkSuccess = LinkSuccess,
        .onLaneLinkFail = LinkFail,
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
    int32_t ret = SOFTBUS_LANE_BUILD_LINK_FAIL;
    do {
        ret = CreateLinkRequestNode(nodeInfo, &requestInfo);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "Create LinkRequestNode fail.");
            Unlock();
            break;
        }
        nodeInfo->linkRetryIdx++;
        if (requestInfo.linkType >= LANE_LINK_TYPE_BUTT) {
            LNN_LOGE(LNN_LANE, "invalid linkType=%{public}d", requestInfo.linkType);
            Unlock();
            break;
        }
        nodeInfo->statusList[requestInfo.linkType].status = BUILD_LINK_STATUS_BUILDING;
        nodeInfo->singleLinkTime[requestInfo.linkType] = SoftBusGetSysTimeMs();
        Unlock();
        uint64_t delayMillis = (uint64_t)g_laneLatency[requestInfo.linkType];
        (void)PostLinkTimeoutMessage(laneReqId, requestInfo.linkType, delayMillis);
        ret = BuildLink(&requestInfo, laneReqId, &linkCb);
        if (ret == SOFTBUS_OK) {
            return;
        }
    } while (false);
    linkCb.onLaneLinkFail(laneReqId, ret, requestInfo.linkType);
}

static int32_t UpdateLinkStatus(uint32_t laneReqId, BuildLinkStatus status, LaneLinkType linkType,
    const LaneLinkInfo *linkInfo, int32_t result)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneLinkNodeInfo *nodeInfo = GetLaneLinkNodeWithoutLock(laneReqId);
    if (nodeInfo == NULL) {
        Unlock();
        LNN_LOGI(LNN_LANE, "link result has notified, not need update link status. laneReqId=%{public}u", laneReqId);
        if (status == BUILD_LINK_STATUS_SUCC) {
            FreeUnusedLink(laneReqId, linkInfo);
        }
        return SOFTBUS_LANE_NOT_FOUND;
    }
    if (nodeInfo->isCompleted) {
        Unlock();
        LNN_LOGI(LNN_LANE, "build link has completed, not need update link status. laneReqId=%{public}u, "
            "linkType=%{public}d", laneReqId, linkType);
        if (status == BUILD_LINK_STATUS_SUCC) {
            FreeUnusedLink(laneReqId, linkInfo);
        }
        return SOFTBUS_LANE_TRIGGER_LINK_FAIL;
    }
    LNN_LOGI(LNN_LANE, "update link status, laneReqId=%{public}u, status=%{public}d, linkType=%{public}d",
        laneReqId, status, linkType);
    nodeInfo->statusList[linkType].status = status;
    nodeInfo->statusList[linkType].result = result;
    if (status != BUILD_LINK_STATUS_SUCC) {
        Unlock();
        return SOFTBUS_OK;
    }
    if (memcpy_s(&(nodeInfo->statusList[linkType].linkInfo), sizeof(LaneLinkInfo), linkInfo,
        sizeof(LaneLinkInfo)) != EOK) {
        LNN_LOGE(LNN_LANE, "linkParam memcpy fail, laneReqId=%{public}u", laneReqId);
        Unlock();
        return SOFTBUS_MEM_ERR;
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
        if (linkType >= LANE_LINK_TYPE_BUTT) {
            LNN_LOGE(LNN_LANE, "invalid linkType=%{public}d", linkType);
            continue;
        }
        if (nodeInfo->statusList[linkType].status == BUILD_LINK_STATUS_BUILDING) {
            Unlock();
            isBuilding = true;
            LNN_LOGE(LNN_LANE, "has exist building link, laneReqId=%{public}u", laneReqId);
            return false;
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
        return SOFTBUS_LANE_NOT_FOUND;
    }
    for (uint32_t i = 0; i < nodeInfo->listNum; i++) {
        LaneLinkType linkType = nodeInfo->linkList->linkType[i];
        if (linkType >= LANE_LINK_TYPE_BUTT) {
            LNN_LOGE(LNN_LANE, "invalid linkType=%{public}d", linkType);
            continue;
        }
        if (nodeInfo->statusList[linkType].status == BUILD_LINK_STATUS_SUCC) {
            if (memcpy_s(info, sizeof(LaneLinkInfo), &(nodeInfo->statusList[linkType].linkInfo),
                sizeof(LaneLinkInfo)) != EOK) {
                Unlock();
                LNN_LOGE(LNN_LANE, "info memcpy fail, laneReqId=%{public}u", laneReqId);
                return SOFTBUS_MEM_ERR;
            }
            *type = linkType;
            Unlock();
            return SOFTBUS_OK;
        }
    }
    Unlock();
    LNN_LOGE(LNN_LANE, "not found LaneLinkInfo, laneReqId=%{public}u", laneReqId);
    return SOFTBUS_LANE_NOT_FOUND;
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
    int32_t ret = SOFTBUS_LANE_RESULT_REPORT_ERR;
    (void)memset_s(&info, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    ret = GetLaneLinkInfo(laneReqId, &linkType, &info);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get LaneLinkInfo fail, laneReqId=%{public}u", laneReqId);
        goto FAIL;
    }
    char localUdid[UDID_BUF_LEN] = {0};
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get udid fail, laneReqId=%{public}u", laneReqId);
        ret = SOFTBUS_LANE_GET_LEDGER_INFO_ERR;
        goto FAIL;
    }
    LNN_LOGI(LNN_LANE, "check is need peerIp, udidlen=%{public}zu", strlen(info.peerUdid));
    uint64_t laneId = GenerateLaneId(localUdid, info.peerUdid, info.type);
    if (laneId == INVALID_LANE_ID) {
        LNN_LOGE(LNN_LANE, "generate laneId fail, laneReqId=%{public}u", laneReqId);
        ret = SOFTBUS_LANE_ID_GENERATE_FAIL;
        goto FAIL;
    }
    TransReqInfo transReqInfo;
    (void)memset_s(&transReqInfo, sizeof(TransReqInfo), 0, sizeof(TransReqInfo));
    if (GetTransReqInfoByLaneReqId(laneReqId, &transReqInfo) == SOFTBUS_OK) {
        (void)strcpy_s(info.networkId, sizeof(info.networkId), transReqInfo.allocInfo.networkId);
    }
    NotifyLaneAllocSuccess(laneReqId, laneId, &info);
    FreeLowPriorityLink(laneReqId, linkType);
    return;
FAIL:
    NotifyLaneAllocFail(laneReqId, ret);
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
    if (UpdateLinkStatus(laneReqId, BUILD_LINK_STATUS_SUCC, linkType, info, SOFTBUS_OK) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "update link status fail, laneReqId=%{public}u", laneReqId);
        SoftBusFree(info);
        return;
    }
    SoftBusFree(info);
    if (IsNeedNotifySucc(laneReqId)) {
        RemoveLinkTimeoutMessage(laneReqId, LANE_LINK_TYPE_BUTT);
        NotifyLinkSucc(laneReqId);
        DeleteLaneLinkNode(laneReqId);
    }
}

static bool IsNeedNotifyFail(uint32_t laneReqId)
{
    bool notifyFail = false;
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return true;
    }
    LaneLinkNodeInfo *nodeInfo = GetLaneLinkNodeWithoutLock(laneReqId);
    if (nodeInfo == NULL) {
        Unlock();
        LNN_LOGE(LNN_LANE, "get lane link node info fail, laneReqId=%{public}u", laneReqId);
        return true;
    }
    uint64_t costTime = GetCostTime(nodeInfo->triggerLinkTime);
    if (costTime >= nodeInfo->availableLinkTime || nodeInfo->linkRetryIdx >= nodeInfo->listNum) {
        LNN_LOGE(LNN_LANE, "link retry exceed limit, laneReqId=%{public}u", laneReqId);
        notifyFail = true;
    }
    if (!notifyFail) {
        nodeInfo->isCompleted = false;
        Unlock();
        return notifyFail;
    }
    for (uint32_t i = 0; i < nodeInfo->linkRetryIdx; i++) {
        LaneLinkType linkType = nodeInfo->linkList->linkType[i];
        if (linkType >= LANE_LINK_TYPE_BUTT) {
            LNN_LOGE(LNN_LANE, "invalid linkType=%{public}d", linkType);
            continue;
        }
        if (nodeInfo->statusList[linkType].status != BUILD_LINK_STATUS_FAIL) {
            notifyFail = false;
        }
    }
    nodeInfo->isCompleted = notifyFail ? true : false;
    Unlock();
    return notifyFail;
}

static void BuildLinkRetry(uint32_t laneReqId)
{
    bool needRetry = true;
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        NotifyLaneAllocFail(laneReqId, SOFTBUS_LOCK_ERR);
        return;
    }
    LaneLinkNodeInfo *nodeInfo = GetLaneLinkNodeWithoutLock(laneReqId);
    if (nodeInfo == NULL) {
        Unlock();
        LNN_LOGE(LNN_LANE, "get lane link node info fail, laneReqId=%{public}u", laneReqId);
        NotifyLaneAllocFail(laneReqId, SOFTBUS_LANE_NOT_FOUND);
        return;
    }
    uint64_t costTime = GetCostTime(nodeInfo->triggerLinkTime);
    if (costTime >= nodeInfo->availableLinkTime || nodeInfo->linkRetryIdx >= nodeInfo->listNum) {
        LNN_LOGE(LNN_LANE, "link retry exceed limit, laneReqId=%{public}u", laneReqId);
        Unlock();
        return;
    }
    for (uint32_t i = 0; i < nodeInfo->linkRetryIdx; i++) {
        LaneLinkType linkType = nodeInfo->linkList->linkType[i];
        if (linkType >= LANE_LINK_TYPE_BUTT) {
            LNN_LOGE(LNN_LANE, "invalid linkType=%{public}d", linkType);
            continue;
        }
        if (nodeInfo->statusList[linkType].status == BUILD_LINK_STATUS_SUCC) {
            LNN_LOGI(LNN_LANE, "has exist high priority succ link, laneReqId=%{public}u", laneReqId);
            needRetry = false;
        }
    }
    Unlock();
    if (needRetry) {
        LNN_LOGI(LNN_LANE, "continue to build link, laneReqId=%{public}u", laneReqId);
        (void)LnnLanePostMsgToHandler(MSG_TYPE_LANE_TRIGGER_LINK, laneReqId, 0, NULL, 0);
    }
}

static void LaneLinkFail(SoftBusMessage *msg)
{
    uint32_t laneReqId = (uint32_t)msg->arg1;
    int32_t failReason = (int32_t)msg->arg2;
    if (msg->obj == NULL) {
        LNN_LOGE(LNN_LANE, "invalid msg->obj");
        NotifyLaneAllocFail(laneReqId, failReason);
        return;
    }
    LinkFailInfo *failInfo = (LinkFailInfo *)msg->obj;
    LaneLinkType linkType = failInfo->linkType;
    SoftBusFree(failInfo);
    if (linkType < LANE_LINK_TYPE_BUTT &&
        UpdateLinkStatus(laneReqId, BUILD_LINK_STATUS_FAIL, linkType, NULL, failReason) != SOFTBUS_OK) {
        return;
    }
    if (IsNeedNotifySucc(laneReqId)) {
        RemoveLinkTimeoutMessage(laneReqId, LANE_LINK_TYPE_BUTT);
        NotifyLinkSucc(laneReqId);
        DeleteLaneLinkNode(laneReqId);
    } else if (IsNeedNotifyFail(laneReqId)) {
        RemoveLinkTimeoutMessage(laneReqId, LANE_LINK_TYPE_BUTT);
        NotifyLaneAllocFail(laneReqId, GetErrCodeWithLock(laneReqId));
        DeleteLaneLinkNode(laneReqId);
    } else {
        BuildLinkRetry(laneReqId);
    }
}

int32_t UpdateFreeLaneStatus(uint32_t laneReqId)
{
    if (laneReqId == INVALID_LANE_REQ_ID) {
        LNN_LOGE(LNN_LANE, "laneHandle is invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    TransReqInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_requestList->list, TransReqInfo, node) {
        if (item->laneReqId == laneReqId) {
            item->hasNotifiedFree = true;
            Unlock();
            return SOFTBUS_OK;
        }
    }
    Unlock();
    LNN_LOGE(LNN_LANE, "Update free lane status fail, laneReqId=%{public}d", laneReqId);
    return SOFTBUS_LANE_NOT_FOUND;
}

static void HandleDetectTimeout(SoftBusMessage *msg)
{
    uint32_t detectId = (uint32_t)msg->arg1;
    LNN_LOGI(LNN_LANE, "lane detect timeout. detectId=%{public}u", detectId);
    NotifyDetectTimeout(detectId);
}

static void HandleLinkTimeout(SoftBusMessage *msg)
{
    uint32_t laneReqId = (uint32_t)msg->arg1;
    LaneLinkType timeoutLinkType = (LaneLinkType)msg->arg2;
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
    uint64_t costTime = GetCostTime(nodeInfo->triggerLinkTime);
    if (costTime >= nodeInfo->availableLinkTime || nodeInfo->linkRetryIdx >= nodeInfo->listNum) {
        LNN_LOGE(LNN_LANE, "link retry exceed limit, laneReqId=%{public}u", laneReqId);
        Unlock();
        return;
    }
    for (uint32_t i = 0; i < nodeInfo->linkRetryIdx; i++) {
        LaneLinkType linkType = nodeInfo->linkList->linkType[i];
        if (nodeInfo->statusList[linkType].status == BUILD_LINK_STATUS_SUCC) {
            LNN_LOGI(LNN_LANE, "a successful link already exist, laneReqId=%{public}u, linkType=%{public}d",
                laneReqId, linkType);
            Unlock();
            return;
        }
    }
    Unlock();
    LNN_LOGI(LNN_LANE, "continue to build link, laneReqId=%{public}u, timeoutLinkType=%{public}d",
        laneReqId, timeoutLinkType);
    (void)LnnLanePostMsgToHandler(MSG_TYPE_LANE_TRIGGER_LINK, laneReqId, 0, NULL, 0);
}

static void LaneStateChange(SoftBusMessage *msg)
{
    if (msg == NULL) {
        return;
    }
    if (msg->obj != NULL) {
        SoftBusFree(msg->obj);
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
        case MSG_TYPE_LANE_DETECT_TIMEOUT:
            HandleDetectTimeout(msg);
            break;
        case MSG_TYPE_LANE_LINK_TIMEOUT:
            HandleLinkTimeout(msg);
            break;
        case MSG_TYPE_NOTIFY_FREE_LANE_RESULT:
            HandleNotifyFreeLaneResult(msg);
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
    g_laneLoopHandler.looper = GetLooper(LOOP_TYPE_LNN);
    if (g_laneLoopHandler.looper == NULL) {
        LNN_LOGE(LNN_LANE, "transLane init looper fail");
        return SOFTBUS_NO_INIT;
    }
    return SOFTBUS_OK;
}

static void Init(const ILaneIdStateListener *listener)
{
    (void)listener;
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
    DeinitLaneReliability();
}

static LaneInterface g_transLaneObject = {
    .init = Init,
    .deinit = Deinit,
    .allocLaneByQos = AllocLaneByQos,
    .cancelLane = CancelLane,
    .freeLane = FreeLane,
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
        return SOFTBUS_LOCK_ERR;
    }
    TransReqInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_requestList->list, TransReqInfo, node) {
        if (item->laneReqId == laneReqId) {
            if (memcpy_s(reqInfo, sizeof(TransReqInfo), item, sizeof(TransReqInfo)) != EOK) {
                LNN_LOGE(LNN_LANE, "memcpy TransReqInfo fail");
                Unlock();
                return SOFTBUS_MEM_ERR;
            }
            Unlock();
            return SOFTBUS_OK;
        }
    }
    Unlock();
    return SOFTBUS_LANE_NOT_FOUND;
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
        return SOFTBUS_INVALID_PARAM;
    }
    if (msg->arg1 == *detectId) {
        LNN_LOGE(LNN_LANE, "remove detect timeout message success. detectId=%{public}u", *detectId);
        return SOFTBUS_OK;
    }
    return SOFTBUS_INVALID_PARAM;
}

void RemoveDetectTimeoutMessage(uint32_t detectId)
{
    LNN_LOGI(LNN_LANE, "remove detect timeout message. detectId=%{public}u", detectId);
    g_laneLoopHandler.looper->RemoveMessageCustom(g_laneLoopHandler.looper, &g_laneLoopHandler,
        RemoveDetectTimeout, &detectId);
}
