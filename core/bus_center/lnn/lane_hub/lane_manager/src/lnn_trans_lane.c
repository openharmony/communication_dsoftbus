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
#include "auth_interface.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_event.h"
#include "lnn_event_form.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_lane.h"
#include "lnn_lane_common.h"
#include "lnn_lane_def.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_link_p2p.h"
#include "lnn_lane_listener.h"
#include "lnn_lane_model.h"
#include "lnn_lane_reliability.h"
#include "lnn_log.h"
#include "lnn_parameter_utils.h"
#include "lnn_select_rule.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_protocol_def.h"
#include "softbus_utils.h"
#include "wifi_direct_error_code.h"
#include "wifi_direct_manager.h"

#define LANE_REQ_ID_TYPE_SHIFT 28
#define DEFAULT_LINK_LATENCY 30000
#define DELAY_DESTROY_LANE_TIME 5000
#define WIFI_DIRECET_NUM_LIMIT 4

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
    linkNode->acceptableProtocols = request->acceptableProtocols;
    linkNode->bandWidth = 0;
    linkNode->triggerLinkTime = SoftBusGetSysTimeMs();
    linkNode->availableLinkTime = DEFAULT_LINK_LATENCY;
    linkNode->isCompleted = false;
    linkNode->isInnerCalled = request->isInnerCalled;
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
    newNode->notifyFree = false;
    newNode->hasNotifiedFree = false;
    newNode->laneReqId = laneReqId;
    newNode->extraInfo.isSupportIpv6 = option->isSupportIpv6;
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
    newNode->extraInfo.actionAddr = allocInfo->extendInfo.actionAddr;
    newNode->extraInfo.isSupportIpv6 = allocInfo->extendInfo.isSupportIpv6;
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
    linkNode->bandWidth = allocInfo->qosRequire.minBW;
    linkNode->triggerLinkTime = SoftBusGetSysTimeMs();
    linkNode->availableLinkTime = allocInfo->qosRequire.maxLaneLatency != 0 ?
        allocInfo->qosRequire.maxLaneLatency : DEFAULT_LINK_LATENCY;
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

static void DumpInputLinkList(const LanePreferredLinkList *linkInfo)
{
    for (uint32_t i = 0; i < linkInfo->linkTypeNum; i++) {
        LNN_LOGD(LNN_LANE, "priority=%{public}u, linkType=%{public}d", i, linkInfo->linkType[i]);
    }
}

static int32_t LaneAllocInfoConvert(const LaneAllocInfoExt *allocInfoExt, LaneAllocInfo *allocInfo)
{
    allocInfo->type = allocInfoExt->type;
    allocInfo->transType = allocInfoExt->commInfo.transType;
    allocInfo->extendInfo.isSupportIpv6 = allocInfoExt->commInfo.isSupportIpv6;
    allocInfo->extendInfo.actionAddr = allocInfoExt->commInfo.actionAddr;
    if (strcpy_s(allocInfo->networkId, NETWORK_ID_BUF_LEN, allocInfoExt->commInfo.networkId) != EOK) {
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t BuildTargetLink(uint32_t laneHandle, const LaneAllocInfoExt *allocInfoExt,
    const LaneAllocListener *listener)
{
    LanePreferredLinkList *linkList = (LanePreferredLinkList *)SoftBusCalloc(sizeof(LanePreferredLinkList));
    if (linkList == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(linkList, sizeof(LanePreferredLinkList), &allocInfoExt->linkList,
        sizeof(LanePreferredLinkList)) != EOK) {
        SoftBusFree(linkList);
        return SOFTBUS_MEM_ERR;
    }
    LaneAllocInfo allocInfo;
    (void)memset_s(&allocInfo, sizeof(allocInfo), 0, sizeof(allocInfo));
    int32_t ret = LaneAllocInfoConvert(allocInfoExt, &allocInfo);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(linkList);
        return ret;
    }
    TransReqInfo *newItem = CreateReqNodeWithQos(laneHandle, &allocInfo, listener);
    if (newItem == NULL) {
        SoftBusFree(linkList);
        return SOFTBUS_MEM_ERR;
    }
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        SoftBusFree(newItem);
        SoftBusFree(linkList);
        return SOFTBUS_LOCK_ERR;
    }
    ListTailInsert(&g_requestList->list, &newItem->node);
    g_requestList->cnt++;
    Unlock();
    ret = TriggerLinkWithQos(laneHandle, &allocInfo, linkList);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(linkList);
        DeleteRequestNode(laneHandle);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t AllocTargetLane(uint32_t laneHandle, const LaneAllocInfoExt *allocInfo,
    const LaneAllocListener *listener)
{
    if (laneHandle == INVALID_LANE_REQ_ID || allocInfo == NULL ||
        allocInfo->type != LANE_TYPE_TRANS || listener == NULL) {
        LNN_LOGE(LNN_LANE, "alloc targetLane param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (allocInfo->linkList.linkTypeNum >= LANE_LINK_TYPE_BUTT) {
        return SOFTBUS_INVALID_PARAM;
    }
    DumpInputLinkList((const LanePreferredLinkList *)&allocInfo->linkList);
    return BuildTargetLink(laneHandle, allocInfo, listener);
}

static int32_t SpecifiedLinkConvert(const char *networkId, LaneSpecifiedLink link, LanePreferredLinkList *preferLink)
{
    LaneLinkType optionalLink[LANE_LINK_TYPE_BUTT];
    (void)memset_s(optionalLink, sizeof(optionalLink), 0, sizeof(optionalLink));
    uint32_t linkNum = 0;
    switch (link) {
        case LANE_LINK_TYPE_WIFI_WLAN:
            optionalLink[linkNum++] = LANE_WLAN_5G;
            optionalLink[linkNum++] = LANE_WLAN_2P4G;
            break;
        case LANE_LINK_TYPE_WIFI_P2P:
            optionalLink[linkNum++] = LANE_P2P;
            break;
        case LANE_LINK_TYPE_BR:
            optionalLink[linkNum++] = LANE_BR;
            break;
        case LANE_LINK_TYPE_COC_DIRECT:
            optionalLink[linkNum++] = LANE_COC_DIRECT;
            break;
        case LANE_LINK_TYPE_BLE_DIRECT:
            optionalLink[linkNum++] = LANE_BLE_DIRECT;
            break;
        case LANE_LINK_TYPE_HML:
            optionalLink[linkNum++] = LANE_HML;
            break;
        default:
            LNN_LOGE(LNN_LANE, "unexpected link=%{public}d", link);
            break;
    }
    if (linkNum == 0) {
        return SOFTBUS_LANE_NO_AVAILABLE_LINK;
    }
    uint32_t resNum = 0;
    for (uint32_t i = 0; i < linkNum; i++) {
        if (LaneCheckLinkValid(networkId, optionalLink[i], LANE_T_BUTT) != SOFTBUS_OK) {
            LNN_LOGE(LNN_LANE, "SpecifiedLink capcheck fail, linkType=%{public}d", optionalLink[i]);
            continue;
        }
        preferLink->linkType[resNum] = optionalLink[i];
        resNum++;
    }
    if (resNum == 0) {
        return GetErrCodeOfLink(networkId, optionalLink[0]);
    }
    preferLink->linkTypeNum = resNum;
    return SOFTBUS_OK;
}

static int32_t ProcessSpecifiedLink(uint32_t laneHandle, const LaneAllocInfo *allocInfo,
    const LaneAllocListener *listener)
{
    LaneAllocInfoExt info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    if (SpecifiedLinkConvert((const char *)allocInfo->networkId, allocInfo->extendInfo.linkType, &info.linkList)
        != SOFTBUS_OK) {
        return SOFTBUS_LANE_SELECT_FAIL;
    }
    info.type = allocInfo->type;
    info.commInfo.transType = allocInfo->transType;
    info.commInfo.isSupportIpv6 = allocInfo->extendInfo.isSupportIpv6;
    info.commInfo.actionAddr = allocInfo->extendInfo.actionAddr;
    if (strcpy_s(info.commInfo.networkId, NETWORK_ID_BUF_LEN, allocInfo->networkId) != EOK) {
        return SOFTBUS_STRCPY_ERR;
    }
    return BuildTargetLink(laneHandle, &info, listener);
}

static int32_t AllocLaneByQos(uint32_t laneReqId, const LaneAllocInfo *allocInfo, const LaneAllocListener *listener)
{
    if (laneReqId == INVALID_LANE_REQ_ID || allocInfo == NULL ||
        allocInfo->type != LANE_TYPE_TRANS || listener == NULL) {
        LNN_LOGE(LNN_LANE, "allocLane param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (allocInfo->extendInfo.isSpecifiedLink) {
        LNN_LOGW(LNN_LANE, "process specifiedLink, linkType=%{public}d", allocInfo->extendInfo.linkType);
        return ProcessSpecifiedLink(laneReqId, allocInfo, listener);
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
        listener == NULL || laneId == INVALID_LANE_ID) {
        LNN_LOGE(LNN_LANE, "reallocLane param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = AllocValidLane(laneReqId, laneId, allocInfo, listener);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "alloc valid lane fail, laneReqId=%{public}u", laneReqId);
        FreeLaneReqId(laneReqId);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t AllocRawLane(uint32_t laneHandle, const RawLaneAllocInfo *allocInfo, const LaneAllocListener *listener)
{
    if ((allocInfo == NULL) || (allocInfo->type != LANE_TYPE_TRANS) || (listener == NULL)) {
        LNN_LOGE(LNN_LANE, "allocLane param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    LNN_LOGI(LNN_LANE, "get raw lane info, actionAddr=%{public}u", allocInfo->actionAddr);
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = allocInfo->transType;
    selectParam.qosRequire = allocInfo->qosRequire;
    selectParam.allocedLaneId = INVALID_LANE_ID;
    LanePreferredLinkList *recommendLinkList = (LanePreferredLinkList *)SoftBusCalloc(sizeof(LanePreferredLinkList));
    if (recommendLinkList == NULL) {
        LNN_LOGE(LNN_LANE, "recommendLinkList malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    recommendLinkList->linkTypeNum = 1;
    recommendLinkList->linkType[0] = LANE_HML_RAW;
    LaneAllocInfo laneAllocInfo;
    (void)memset_s(&laneAllocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo));
    laneAllocInfo.type = allocInfo->type;
    laneAllocInfo.transType = allocInfo->transType;
    laneAllocInfo.qosRequire = allocInfo->qosRequire;
    laneAllocInfo.extendInfo.actionAddr = allocInfo->actionAddr;
    laneAllocInfo.extendInfo.isSupportIpv6 = true;
    int32_t ret = StartTriggerLink(laneHandle, &laneAllocInfo, listener, recommendLinkList);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(recommendLinkList);
        LNN_LOGE(LNN_LANE, "trigger link fail, laneHandle=%{public}u", laneHandle);
        return ret;
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
    LanePreferredLinkList *recommendLinkList = (LanePreferredLinkList *)SoftBusCalloc(sizeof(LanePreferredLinkList));
    if (recommendLinkList == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    uint32_t listNum = 0;
    int32_t ret = SelectLane((const char *)transRequest->networkId, &selectParam, recommendLinkList, &listNum);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(recommendLinkList);
        return ret;
    }
    if (recommendLinkList->linkTypeNum == 0) {
        LNN_LOGE(LNN_LANE, "no available link to request, laneReqId=%{public}u", laneReqId);
        SoftBusFree(recommendLinkList);
        return SOFTBUS_LANE_NO_AVAILABLE_LINK;
    }
    LNN_LOGI(LNN_LANE, "select lane link success, linkNum=%{public}d, laneReqId=%{public}u", listNum, laneReqId);
    TransReqInfo *newItem = CreateRequestNode(laneReqId, transRequest, listener);
    if (newItem == NULL) {
        SoftBusFree(recommendLinkList);
        return SOFTBUS_MEM_ERR;
    }
    if (Lock() != SOFTBUS_OK) {
        SoftBusFree(newItem);
        SoftBusFree(recommendLinkList);
        return SOFTBUS_LOCK_ERR;
    }
    ListTailInsert(&g_requestList->list, &newItem->node);
    g_requestList->cnt++;
    Unlock();
    ret = TriggerLink(laneReqId, transRequest, recommendLinkList);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(recommendLinkList);
        DeleteRequestNode(laneReqId);
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

void NotifyFreeLaneResult(uint32_t laneReqId, int32_t errCode)
{
    TransReqInfo reqInfo;
    (void)memset_s(&reqInfo, sizeof(TransReqInfo), 0, sizeof(TransReqInfo));
    if (GetTransReqInfoByLaneReqId(laneReqId, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGI(LNN_LANE, "get trans req info fail, laneReqId=%{public}d", laneReqId);
        return;
    }
    if (!reqInfo.notifyFree) {
        LNN_LOGI(LNN_LANE, "free unused link no notify, laneReqId=%{public}u, errCode=%{public}d",
            laneReqId, errCode);
        return;
    }
    LNN_LOGI(LNN_LANE, "notify free lane result, laneReqId=%{public}d, errCode=%{public}d",
        laneReqId, errCode);
    DelLaneResourceByLaneId(reqInfo.laneId, false);
    if (reqInfo.isWithQos && !reqInfo.hasNotifiedFree) {
        if (errCode == SOFTBUS_OK && reqInfo.listener.onLaneFreeSuccess != NULL) {
            reqInfo.listener.onLaneFreeSuccess(laneReqId);
        } else if (errCode != SOFTBUS_OK && reqInfo.listener.onLaneFreeFail != NULL) {
            reqInfo.listener.onLaneFreeFail(laneReqId, errCode);
        }
    }
    DeleteRequestNode(laneReqId);
    FreeLaneReqId(laneReqId);
}

static int32_t PostNotifyFreeLaneResult(uint32_t laneReqId, int32_t errCode, uint64_t delayMillis)
{
    LNN_LOGI(LNN_LANE, "post notify free lane result message, laneReqId=%{public}u, errCode=%{public}d",
        laneReqId, errCode);
    return LnnLanePostMsgToHandler(MSG_TYPE_NOTIFY_FREE_LANE_RESULT, laneReqId, errCode, NULL, delayMillis);
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
    if (LnnGetNetworkIdByUdid(resourceItem.link.peerUdid, networkId, sizeof(networkId)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get networkId fail");
    }
    return DestroyLink(networkId, laneReqId, resourceItem.link.type);
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
            LnnCancelWifiDirect(laneReqId);
            LNN_LOGI(LNN_LANE, "cancel lane succ, laneReqId=%{public}u", laneReqId);
            return SOFTBUS_OK;
        }
    }
    Unlock();
    LNN_LOGE(LNN_LANE, "cancel lane fail, lane reqinfo not find, laneReqId=%{public}u", laneReqId);
    return SOFTBUS_LANE_NOT_FOUND;
}

int32_t UpdateReqListLaneId(uint64_t oldLaneId, uint64_t newLaneId)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    TransReqInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_requestList->list, TransReqInfo, node) {
        if (item->laneId == oldLaneId) {
            item->laneId = newLaneId;
            LNN_LOGI(LNN_LANE, "update newLaneId=%{public}" PRIu64 "oldLaneId=%{public}" PRIu64,
                newLaneId, oldLaneId);
            Unlock();
            return SOFTBUS_OK;
        }
    }
    Unlock();
    return SOFTBUS_NOT_FIND;
}

static bool GetAuthType(const char *peerNetWorkId)
{
    int32_t value = 0;
    int32_t ret = LnnGetRemoteNumInfo(peerNetWorkId, NUM_KEY_META_NODE, &value);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "fail, ret=%{public}d", ret);
        return false;
    }
    LNN_LOGD(LNN_LANE, "success, value=%{public}d", value);
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
        CheckLinkConflictByReleaseLink(resourceItem.link.type) != SOFTBUS_OK) {
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
        PostDelayDestroyMessage(laneReqId, INVALID_LANE_ID, 0);
        return SOFTBUS_OK;
    }
    return FreeLaneLink(laneReqId, laneId);
}

static int32_t Free(uint32_t laneReqId)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    LaneType type = (LaneType)(laneReqId >> LANE_REQ_ID_TYPE_SHIFT);
    TransReqInfo *item = NULL;
    TransReqInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_requestList->list, TransReqInfo, node) {
        if (item->laneReqId == laneReqId) {
            item->notifyFree = true;
            Unlock();
            int32_t ret = FreeLink(laneReqId, item->laneId, type);
            if (ret != SOFTBUS_OK) {
                DeleteRequestNode(laneReqId);
                FreeLaneReqId(laneReqId);
            }
            return ret;
        }
    }
    Unlock();
    LNN_LOGI(LNN_LANE, "no find lane need free, laneReqId=%{public}u", laneReqId);
    FreeLaneReqId(laneReqId);
    return SOFTBUS_LANE_NOT_FOUND;
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

static void DfxReportLinkResult(uint32_t laneReqId, LaneLinkType linkType, int32_t reason)
{
    LnnEventExtra extra = { 0 };
    extra.errcode = reason;
    extra.laneReqId = (int32_t)laneReqId;
    extra.laneLinkType = (int32_t)linkType;
    LNN_EVENT(EVENT_SCENE_LNN, EVENT_STAGE_LNN_LANE_SELECT_END, extra);
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

static void NotifyLaneAllocSuccess(uint32_t laneReqId, uint64_t laneId, const LaneLinkInfo *info)
{
    UpdateReqInfoWithLaneReqId(laneReqId, laneId);
    TransReqInfo reqInfo;
    (void)memset_s(&reqInfo, sizeof(TransReqInfo), 0, sizeof(TransReqInfo));
    if (GetTransReqInfoByLaneReqId(laneReqId, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lane reqInfo fail");
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
        if (reqInfo.isCanceled) {
            LNN_LOGE(LNN_LANE, "lane has canceled only notify fail, laneReqId=%{public}u", laneReqId);
            reqInfo.listener.onLaneAllocFail(laneReqId, SOFTBUS_LANE_SUCC_AFTER_CANCELED);
            (void)Free(laneReqId);
            return;
        }
        connInfo.laneId = laneId;
        reqInfo.listener.onLaneAllocSuccess(laneReqId, &connInfo);
    } else {
        connInfo.laneId = INVALID_LANE_ID;
        reqInfo.extraInfo.listener.onLaneRequestSuccess(laneReqId, &connInfo);
    }
    LaneType laneType;
    if (ParseLaneTypeByLaneReqId(laneReqId, &laneType) != SOFTBUS_OK ||
        AddLaneBusinessInfoItem(laneType, laneId) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "create laneBusinessInfo fail, laneReqId=%{public}u", laneReqId);
    }
    DfxReportLinkResult(laneReqId, info->type, SOFTBUS_OK);
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
        LNN_LOGE(LNN_LANE, "lane has canceled only notify fail, laneReqId=%{public}u", laneReqId);
    }
    LNN_LOGE(LNN_LANE, "Notify laneAlloc fail, laneReqId=%{public}u, reason=%{public}d", laneReqId, reason);
    if (reqInfo.isWithQos) {
        reqInfo.listener.onLaneAllocFail(laneReqId, reason);
        FreeLaneReqId(laneReqId);
    } else {
        reqInfo.extraInfo.listener.onLaneRequestFail(laneReqId, reason);
    }
    LaneLinkType laneType;
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return;
    }
    LaneLinkNodeInfo *nodeInfo = GetLaneLinkNodeWithoutLock(laneReqId);
    if (nodeInfo == NULL || nodeInfo->linkList == NULL) {
        LNN_LOGE(LNN_LANE, "get lane link node info fail, laneReqId=%{public}u", laneReqId);
        Unlock();
        return;
    }
    laneType = nodeInfo->linkList->linkType[0];
    Unlock();
    DfxReportLinkResult(laneReqId, laneType, reason);
    DeleteRequestNode(laneReqId);
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
    LaneLinkType linkType;
    int32_t result = SOFTBUS_LANE_BUILD_LINK_FAIL;
    for (uint32_t i = 0; i < nodeInfo->linkList->linkTypeNum; i++) {
        linkType = nodeInfo->linkList->linkType[i];
        if (linkType == LANE_HML || linkType == LANE_P2P) {
            result = nodeInfo->statusList[linkType].result;
            Unlock();
            return result;
        }
    }
    linkType = nodeInfo->linkList->linkType[0];
    result = nodeInfo->statusList[linkType].result;
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
        .onLaneLinkSuccess = LinkSuccess,
        .onLaneLinkFail = LinkFail,
    };
    LinkRequest requestInfo = {0};
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
        nodeInfo->statusList[requestInfo.linkType].status = BUILD_LINK_STATUS_BUILDING;
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

static void FreeUnusedLink(uint32_t laneReqId, const LaneLinkInfo *linkInfo)
{
    LNN_LOGI(LNN_LANE, "free unused link, laneReqId=%{public}u", laneReqId);
    if (linkInfo == NULL) {
        LNN_LOGE(LNN_LANE, "linkInfo is null, laneReqId=%{public}u", laneReqId);
        return;
    }
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

static void ProcessPowerControlInfoByLaneReqId(const LaneLinkType linkType, uint32_t laneReqId)
{
    LaneTransType transType = LANE_T_BUTT;
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return;
    }
    TransReqInfo *item = NULL;
    TransReqInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_requestList->list, TransReqInfo, node) {
        if (item->laneReqId == laneReqId) {
            transType = item->allocInfo.transType;
        }
    }
    Unlock();
    if (linkType == LANE_HML && IsPowerControlEnabled()) {
        LNN_LOGI(LNN_LANE, "low-power transtype = %{public}d", transType);
        if (transType == LANE_T_BYTE || transType == LANE_T_MSG) {
            DetectDisableWifiDirectApply();
        } else {
            DetectEnableWifiDirectApply();
        }
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
    uint64_t laneId = INVALID_LANE_ID;
    if (strlen(info.peerUdid) == 0) {
        laneId = GenerateLaneId(localUdid, info.linkInfo.rawWifiDirect.peerIp, info.type);
    } else {
        laneId = GenerateLaneId(localUdid, info.peerUdid, info.type);
    }
    if (laneId == INVALID_LANE_ID) {
        LNN_LOGE(LNN_LANE, "generate laneId fail, laneReqId=%{public}u", laneReqId);
        ret = SOFTBUS_LANE_ID_GENERATE_FAIL;
        goto FAIL;
    }
    ret = AddLaneResourceToPool(&info, laneId, false);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "add linkInfo item fail, laneReqId=%{public}u", laneReqId);
        goto FAIL;
    }
    ProcessPowerControlInfoByLaneReqId(linkType, laneReqId);
    NotifyLaneAllocSuccess(laneReqId, laneId, &info);
    (void)HandleLaneQosChange(&info);
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

static uint64_t GetCostTime(uint64_t triggerLinkTime)
{
    if (SoftBusGetSysTimeMs() < triggerLinkTime) {
        return 0;
    }
    return SoftBusGetSysTimeMs() - triggerLinkTime;
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
        nodeInfo->isCompleted = notifyFail ? true : false;
        Unlock();
        return notifyFail;
    }
    for (uint32_t i = 0; i < nodeInfo->linkRetryIdx; i++) {
        LaneLinkType linkType = nodeInfo->linkList->linkType[i];
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
        if (nodeInfo->statusList[linkType].status == BUILD_LINK_STATUS_SUCC) {
            LNN_LOGI(LNN_LANE, "has exist high priority succ link, laneReqId=%{public}u", laneReqId);
            needRetry = false;
        }
        if (nodeInfo->linkRetryIdx < nodeInfo->listNum &&
            nodeInfo->linkList->linkType[nodeInfo->linkRetryIdx] == LANE_P2P && linkType == LANE_HML &&
            nodeInfo->statusList[linkType].status == BUILD_LINK_STATUS_BUILDING) {
            LNN_LOGI(LNN_LANE, "refuse same type link repeat build, laneReqId=%{public}u", laneReqId);
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
    LnnDumpLocalBasicInfo();
    LnnDumpOnlineDeviceInfo();
    if (UpdateLinkStatus(laneReqId, BUILD_LINK_STATUS_FAIL, linkType, NULL, failReason) != SOFTBUS_OK) {
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

static void UpdateFreeLaneStatus(uint32_t laneReqId)
{
    if (Lock() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get lock fail");
        return ;
    }
    TransReqInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_requestList->list, TransReqInfo, node) {
        if (item->laneReqId == laneReqId) {
            item->hasNotifiedFree = true;
            Unlock();
            return;
        }
    }
    Unlock();
    LNN_LOGE(LNN_LANE, "Update free lane status fail, laneReqId=%{public}d", laneReqId);
    return;
}

static void HandleAsyncNotifySucc(uint32_t laneReqId)
{
    LNN_LOGI(LNN_LANE, "handle notify free lane succ, laneReqId=%{public}u", laneReqId);
    TransReqInfo reqInfo;
    (void)memset_s(&reqInfo, sizeof(TransReqInfo), 0, sizeof(TransReqInfo));
    if (GetTransReqInfoByLaneReqId(laneReqId, &reqInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get trans req info fail, laneReqId=%{public}d", laneReqId);
        return;
    }
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (FindLaneResourceByLaneId(reqInfo.laneId, &resourceItem) != SOFTBUS_OK) {
        return;
    }
    if (resourceItem.link.type == LANE_HML) {
        if (reqInfo.isWithQos && reqInfo.listener.onLaneFreeSuccess != NULL) {
            reqInfo.listener.onLaneFreeSuccess(laneReqId);
            UpdateFreeLaneStatus(laneReqId);
        }
    } else {
        DelLaneResourceByLaneId(reqInfo.laneId, false);
        if (reqInfo.isWithQos && reqInfo.listener.onLaneFreeSuccess != NULL) {
            reqInfo.listener.onLaneFreeSuccess(laneReqId);
        }
        DeleteRequestNode(laneReqId);
        FreeLaneReqId(laneReqId);
    }
}

static void HandleDelayDestroyLink(SoftBusMessage *msg)
{
    uint32_t laneReqId = (uint32_t)msg->arg1;
    uint64_t laneId = (uint64_t)msg->arg2;
    LNN_LOGI(LNN_LANE, "handle delay destroy message, laneReqId=%{public}u, laneId=%{public}" PRIu64 "",
        laneReqId, laneId);
    if (laneId == INVALID_LANE_ID) {
        HandleAsyncNotifySucc(laneReqId);
        return;
    }
    int32_t ret = FreeLaneLink(laneReqId, laneId);
    if (ret != SOFTBUS_OK) {
        NotifyFreeLaneResult(laneReqId, ret);
    }
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
    LNN_LOGI(LNN_LANE, "continue to build link, laneReqId=%{public}u, timeoutLinkType=%{public}d",
        laneReqId, timeoutLinkType);
    (void)LnnLanePostMsgToHandler(MSG_TYPE_LANE_TRIGGER_LINK, laneReqId, 0, NULL, 0);
}

static void HandelNotifyFreeLaneResult(SoftBusMessage *msg)
{
    uint32_t laneReqId = (uint32_t)msg->arg1;
    int32_t errCode = (int32_t)msg->arg2;
    LNN_LOGI(LNN_LANE, "handle notify free lane result, laneReqId=%{public}u, errCode=%{public}d",
        laneReqId, errCode);
    NotifyFreeLaneResult(laneReqId, errCode);
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
        case MSG_TYPE_LANE_LINK_TIMEOUT:
            HandleLinkTimeout(msg);
            break;
        case MSG_TYPE_NOTIFY_FREE_LANE_RESULT:
            HandelNotifyFreeLaneResult(msg);
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
    DeinitLaneReliability();
}

static LaneInterface g_transLaneObject = {
    .init = Init,
    .deinit = Deinit,
    .allocLane = Alloc,
    .allocLaneByQos = AllocLaneByQos,
    .allocRawLane = AllocRawLane,
    .reallocLaneByQos = ReallocLaneByQos,
    .allocTargetLane = AllocTargetLane,
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

int32_t PostDelayDestroyMessage(uint32_t laneReqId, uint64_t laneId, uint64_t delayMillis)
{
    LNN_LOGI(LNN_LANE, "post delay destroy message. laneReqId=%{public}u, laneId=%{public}" PRIu64 "",
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
    int32_t ret = LnnLanePostMsgToHandler(MSG_TYPE_LANE_STATE_CHANGE, 0, 0, stateNotifyInfo, 0);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(stateNotifyInfo);
        LNN_LOGE(LNN_LANE, "post lane state change msg fail");
        return ret;
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
    return SOFTBUS_INVALID_PARAM;
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

static void DestroyRequestNodeList(ListNode *reqInfoList)
{
    TransReqInfo *item = NULL;
    TransReqInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, reqInfoList, TransReqInfo, node) {
        ListDelete(&item->node);
        SoftBusFree(item);
    }
}

static int32_t GetNodeToNotifyQosEvent(const char *peerNetworkId, ListNode *reqInfoList)
{
    if (peerNetworkId == NULL || reqInfoList == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (Lock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = SOFTBUS_OK;
    TransReqInfo *item = NULL;
    TransReqInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_requestList->list, TransReqInfo, node) {
        if (strcmp(item->allocInfo.networkId, peerNetworkId) != 0 ||
            item->allocInfo.qosRequire.minBW != DB_MAGIC_NUMBER) {
            continue;
        }
        LNN_LOGI(LNN_LANE, "laneReqId=%{public}u, laneId=%{public}" PRIu64 "", item->laneReqId, item->laneId);
        TransReqInfo *info = (TransReqInfo *)SoftBusCalloc(sizeof(TransReqInfo));
        if (info == NULL) {
            ret = SOFTBUS_MALLOC_ERR;
            break;
        }
        ListInit(&info->node);
        if (memcpy_s(info, sizeof(TransReqInfo), item, sizeof(TransReqInfo)) != EOK) {
            LNN_LOGE(LNN_LANE, "memcpy fail");
            SoftBusFree(info);
            ret = SOFTBUS_MEM_ERR;
            break;
        }
        ListTailInsert(reqInfoList, &info->node);
    }
    Unlock();
    if (ret != SOFTBUS_OK) {
        DestroyRequestNodeList(reqInfoList);
    }
    return ret;
}

static bool NeedToNotify(const TransReqInfo *info)
{
    if (info == NULL) {
        return false;
    }
    LaneResource laneLinkInfo;
    (void)memset_s(&laneLinkInfo, sizeof(LaneResource), 0, sizeof(LaneResource));
    int32_t ret = FindLaneResourceByLaneId(info->laneId, &laneLinkInfo);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "find laneId=%{public}" PRIu64 " fail, ret=%{public}d", info->laneId, ret);
        return false;
    }
    LNN_LOGI(LNN_LANE, "laneReqId=%{public}u, type=%{public}d", info->laneReqId, laneLinkInfo.link.type);
    return laneLinkInfo.link.type == LANE_BR;
}

int32_t HandleLaneQosChange(const LaneLinkInfo *laneLinkInfo)
{
    if (laneLinkInfo == NULL) {
        LNN_LOGE(LNN_LANE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (laneLinkInfo->type != LANE_P2P && laneLinkInfo->type != LANE_HML) {
        return SOFTBUS_OK;
    }
    char peerNetworkId[NETWORK_ID_BUF_LEN] = {0};
    int32_t ret = LnnGetNetworkIdByUdid(laneLinkInfo->peerUdid, peerNetworkId, sizeof(peerNetworkId));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get networkId by udid fail");
        return ret;
    }
    ListNode reqInfoList;
    ListInit(&reqInfoList);
    ret = GetNodeToNotifyQosEvent(peerNetworkId, &reqInfoList);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get list fail, ret=%{public}d", ret);
        return ret;
    }
    TransReqInfo *item = NULL;
    TransReqInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &reqInfoList, TransReqInfo, node) {
        if (item->listener.onLaneQosEvent != NULL && NeedToNotify(item)) {
            item->listener.onLaneQosEvent(item->laneReqId, LANE_OWNER_OTHER, LANE_QOS_BW_HIGH);
        }
    }
    DestroyRequestNodeList(&reqInfoList);
    return SOFTBUS_OK;
}