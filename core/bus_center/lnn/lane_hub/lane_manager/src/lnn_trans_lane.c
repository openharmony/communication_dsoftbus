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

#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_lane.h"
#include "lnn_lane_common.h"
#include "lnn_lane_def.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_link_proc.h"
#include "lnn_lane_model.h"
#include "lnn_lane_select.h"
#include "message_handler.h"
#include "p2plink_interface.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

typedef enum {
    MSG_TYPE_LANE_TRIGGER_LINK = 0,
    MSG_TYPE_LANE_LINK_SUCCESS,
    MSG_TYPE_LANE_LINK_FAIL,
    MSG_TYPE_LANE_LINK_EXCEPTION,
} LaneMsgType;

typedef struct {
    ListNode node;
    uint32_t laneId;
    TransOption info;
    LaneLinkType type;
    char p2pMac[P2P_MAC_LEN];
    ILaneListener listener;
} TransReqInfo;

typedef struct {
    uint32_t cnt;
    ListNode list;
} TransLaneList;

typedef struct {
    ListNode node;
    uint32_t laneId;
    char networkId[NETWORK_ID_BUF_LEN];
    int32_t pid;
    LaneTransType transType;
    LaneLinkType *linkList; /* Mem provided by laneSelect module */
    uint32_t listNum;
    uint32_t linkRetryIdx;
} LaneLinkNodeInfo;

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

static int32_t PostMsgToHandler(int32_t msgType, uint64_t param1, uint64_t param2, void *obj)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[transLane]create handler msg failed");
        return SOFTBUS_MALLOC_ERR;
    }
    msg->what = msgType;
    msg->arg1 = param1;
    msg->arg2 = param2;
    msg->handler = &g_laneLoopHandler;
    msg->obj = obj;
    g_laneLoopHandler.looper->PostMessage(g_laneLoopHandler.looper, msg);
    return SOFTBUS_OK;
}

static void LinkSuccess(uint32_t laneId, const LaneLinkInfo *linkInfo)
{
    if (linkInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "linkSuccess param invalid");
    }
    LaneLinkInfo *linkParam = (LaneLinkInfo *)SoftBusCalloc(sizeof(LaneLinkInfo));
    if (linkParam == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "linkSuccess info malloc fail");
        return;
    }
    if (memcpy_s(linkParam, sizeof(LaneLinkInfo), linkInfo, sizeof(LaneLinkInfo)) != EOK) {
        SoftBusFree(linkParam);
        return;
    }
    if (PostMsgToHandler(MSG_TYPE_LANE_LINK_SUCCESS, laneId, 0, linkParam) != SOFTBUS_OK) {
        SoftBusFree(linkParam);
        return;
    }
}

static void LinkFail(uint32_t laneId, int32_t reason)
{
    if (PostMsgToHandler(MSG_TYPE_LANE_LINK_FAIL, laneId, reason, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post lanelink fail msg err");
        return;
    }
}

static void LinkException(uint32_t laneId, int32_t reason)
{
    if (PostMsgToHandler(MSG_TYPE_LANE_LINK_EXCEPTION, laneId, reason, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post laneStateException msg err");
        return;
    }
}

static void DeleteLaneLinkNode(uint32_t laneId)
{
    if (Lock() != SOFTBUS_OK) {
        return;
    }
    LaneLinkNodeInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_multiLinkList, LaneLinkNodeInfo, node) {
        if (item->laneId == laneId) {
            ListDelete(&item->node);
            SoftBusFree(item->linkList);
            SoftBusFree(item);
            break;
        }
    }
    Unlock();
}

static int32_t TriggerLink(uint32_t laneId, TransOption *request, LaneLinkType *recommendLinkList, uint32_t listNum)
{
    LaneLinkNodeInfo *linkNode = (LaneLinkNodeInfo *)SoftBusCalloc(sizeof(LaneLinkNodeInfo));
    if (linkNode == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(linkNode->networkId, NETWORK_ID_BUF_LEN,
        request->networkId, NETWORK_ID_BUF_LEN) != EOK) {
        SoftBusFree(linkNode);
        return SOFTBUS_MEM_ERR;
    }
    linkNode->laneId = laneId;
    linkNode->linkRetryIdx = 0;
    linkNode->listNum = listNum;
    linkNode->linkList = recommendLinkList;
    linkNode->transType = request->transType;
    linkNode->pid = request->pid;
    ListInit(&linkNode->node);
    if (Lock() != SOFTBUS_OK) {
        SoftBusFree(linkNode);
        return SOFTBUS_LOCK_ERR;
    }
    ListTailInsert(&g_multiLinkList, &linkNode->node);
    Unlock();
    if (PostMsgToHandler(MSG_TYPE_LANE_TRIGGER_LINK, laneId, 0, NULL) != SOFTBUS_OK) {
        DeleteLaneLinkNode(laneId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static TransReqInfo *CreateRequestNode(uint32_t laneId, const TransOption *option, const ILaneListener *listener)
{
    TransReqInfo *newNode = (TransReqInfo *)SoftBusCalloc(sizeof(TransReqInfo));
    if (newNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "CreateRequestNode malloc fail");
        return NULL;
    }
    if (memcpy_s(&newNode->listener, sizeof(ILaneListener), listener, sizeof(ILaneListener)) != EOK) {
        SoftBusFree(newNode);
        return NULL;
    }
    if (memcpy_s(&newNode->info, sizeof(TransOption), option, sizeof(TransOption)) != EOK) {
        SoftBusFree(newNode);
        return NULL;
    }
    newNode->laneId = laneId;
    ListInit(&newNode->node);
    return newNode;
}

static void DeleteRequestNode(uint32_t laneId)
{
    if (Lock() != SOFTBUS_OK) {
        return;
    }
    TransReqInfo *infoNode = NULL;
    LIST_FOR_EACH_ENTRY(infoNode, &g_requestList->list, TransReqInfo, node) {
        if (infoNode->laneId == laneId) {
            ListDelete(&infoNode->node);
            SoftBusFree(infoNode);
            g_requestList->cnt--;
            break;
        }
    }
    Unlock();
}

static int32_t Alloc(uint32_t laneId, const LaneRequestOption *request, const ILaneListener *listener)
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "memcpy fail");
        return SOFTBUS_MEM_ERR;
    }
    LaneLinkType *recommendLinkList = NULL;
    uint32_t listNum = 0;
    if (SelectLane((const char *)transRequest->networkId, &selectParam, &recommendLinkList, &listNum) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (recommendLinkList == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no link resources available, alloc fail");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "select lane link success, linkNum:%d", listNum);
    TransReqInfo *newItem = CreateRequestNode(laneId, transRequest, listener);
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
    if (TriggerLink(laneId, transRequest, recommendLinkList, listNum) != SOFTBUS_OK) {
        SoftBusFree(recommendLinkList);
        DeleteRequestNode(laneId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void UnbindLaneId(uint32_t laneId, const TransReqInfo *infoNode)
{
    LaneGenerateParam param;
    param.linkType = infoNode->type;
    param.transType = infoNode->info.transType;
    param.priority = 0; /* default:0 */
    uint32_t profileId = GenerateLaneProfileId(&param);
    g_laneIdCallback->OnLaneIdDisabled(laneId, profileId);
    UnbindLaneIdFromProfile(laneId, profileId);
}

static int32_t Free(uint32_t laneId)
{
    if (Lock() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    TransReqInfo *infoNode = NULL;
    LIST_FOR_EACH_ENTRY(infoNode, &g_requestList->list, TransReqInfo, node) {
        if (infoNode->laneId == laneId) {
            ListDelete(&infoNode->node);
            g_requestList->cnt--;
            Unlock();
            DestroyLink(laneId, infoNode->type, infoNode->info.pid, infoNode->p2pMac, infoNode->info.networkId);
            UnbindLaneId(laneId, infoNode);
            SoftBusFree(infoNode);
            return SOFTBUS_OK;
        }
    }
    Unlock();
    return SOFTBUS_OK;
}

static int32_t GetLaneReqInfo(uint32_t laneId, TransReqInfo *reqInfo)
{
    if (Lock() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    bool isFound = false;
    TransReqInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_requestList->list, TransReqInfo, node) {
        if (item->laneId == laneId) {
            isFound = true;
            break;
        }
    }
    if (isFound == false) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[transLane] cannot find reqInfo");
        Unlock();
        return SOFTBUS_ERR;
    }
    if (memcpy_s(reqInfo, sizeof(TransReqInfo), item, sizeof(TransReqInfo)) != EOK) {
        Unlock();
        return SOFTBUS_ERR;
    }
    Unlock();
    return SOFTBUS_OK;
}

static void UpdateP2pInfo(TransReqInfo *nodeInfo)
{
    if (nodeInfo->type != LANE_P2P) {
        return;
    }
    if (LnnGetRemoteStrInfo(nodeInfo->info.networkId, STRING_KEY_P2P_MAC,
        nodeInfo->p2pMac, P2P_MAC_LEN) != SOFTBUS_OK) {
        LLOGE("get remote p2p mac fail.");
        return;
    }
}

static void UpdateLinkType(uint32_t laneId, LaneLinkType linkType)
{
    if (Lock() != SOFTBUS_OK) {
        return;
    }
    TransReqInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_requestList->list, TransReqInfo, node) {
        if (item->laneId == laneId) {
            item->type = linkType;
            UpdateP2pInfo(item);
            break;
        }
    }
    Unlock();
}

static void NotifyLaneAllocSuccess(uint32_t laneId, const LaneLinkInfo *info)
{
    TransReqInfo reqInfo;
    if (GetLaneReqInfo(laneId, &reqInfo) != SOFTBUS_OK) {
        return;
    }
    LaneProfile profile;
    LaneConnInfo connInfo;
    (void)memset_s(&profile, sizeof(LaneProfile), 0, sizeof(LaneProfile));
    if (LaneInfoProcess(info, &connInfo, &profile) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lane alloc success, but laneInfo proc fail");
        return;
    }
    profile.content = reqInfo.info.transType;
    if (BindLaneIdToProfile(laneId, &profile) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bind laneId to profile fail");
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "Notify laneAlloc succ, laneId:0x%x, linkType:%d",
        laneId, info->type);
    reqInfo.listener.OnLaneRequestSuccess(laneId, &connInfo);
    UpdateLinkType(laneId, info->type);
    LaneGenerateParam param;
    param.linkType = profile.linkType;
    param.transType = profile.content;
    param.priority = profile.priority;
    uint32_t profileId = GenerateLaneProfileId(&param);
    g_laneIdCallback->OnLaneIdEnabled(laneId, profileId);
}

static void NotifyLaneAllocFail(uint32_t laneId, int32_t reason)
{
    TransReqInfo reqInfo;
    if (GetLaneReqInfo(laneId, &reqInfo) != SOFTBUS_OK) {
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Notify laneAlloc fail, laneId:0x%x, reason:%d", laneId, reason);
    reqInfo.listener.OnLaneRequestFail(laneId, LANE_LINK_FAILED);
    if (Lock() != SOFTBUS_OK) {
        return;
    }
    TransReqInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_requestList->list, TransReqInfo, node) {
        if (item->laneId == laneId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            break;
        }
    }
    Unlock();
}

static void NotifyLaneStateChange(uint32_t laneId, int32_t state)
{
    TransReqInfo reqInfo;
    if (GetLaneReqInfo(laneId, &reqInfo) != SOFTBUS_OK) {
        return;
    }
    LaneState laneState = LANE_STATE_OK;
    if (state != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lane state is changed, state:%d", state);
        laneState = LANE_STATE_EXCEPTION;
    }
    reqInfo.listener.OnLaneStateChange(laneId, laneState);
}

static LaneLinkNodeInfo *GetLaneLinkNodeWithoutLock(uint32_t laneId)
{
    LaneLinkNodeInfo *linkNode = NULL;
    LIST_FOR_EACH_ENTRY(linkNode, &g_multiLinkList, LaneLinkNodeInfo, node) {
        if (linkNode->laneId == laneId) {
            return linkNode;
        }
    }
    return NULL;
}

static void LaneTriggerLink(SoftBusMessage *msg)
{
    uint32_t laneId = msg->arg1;
    LaneLinkCb linkCb = {
        .OnLaneLinkSuccess = LinkSuccess,
        .OnLaneLinkFail = LinkFail,
        .OnLaneLinkException = LinkException,
    };
    LinkRequest requestInfo;
    if (Lock() != SOFTBUS_OK) {
        return;
    }
    LaneLinkNodeInfo *nodeInfo = GetLaneLinkNodeWithoutLock(laneId);
    if (nodeInfo == NULL) {
        Unlock();
        return;
    }
    if (nodeInfo->linkRetryIdx >= nodeInfo->listNum) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "All linkType have been tried");
        Unlock();
        return;
    }
    requestInfo.linkType = nodeInfo->linkList[nodeInfo->linkRetryIdx];
    nodeInfo->linkRetryIdx++;
    requestInfo.pid = nodeInfo->pid;
    requestInfo.transType = nodeInfo->transType;
    Unlock();
    if (memcpy_s(requestInfo.peerNetworkId, sizeof(requestInfo.peerNetworkId),
        nodeInfo->networkId, sizeof(nodeInfo->networkId)) != EOK) {
        return;
    }
    int32_t ret = BuildLink(&requestInfo, laneId, &linkCb);
    if (ret == SOFTBUS_OK) {
        return;
    }
    if (PostMsgToHandler(MSG_TYPE_LANE_LINK_FAIL, laneId, ret, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post laneLinkFail msg err");
    }
}

static void LaneLinkSuccess(SoftBusMessage *msg)
{
    if (msg->obj == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "invalid msg->obj");
        return;
    }
    LaneLinkInfo *info = (LaneLinkInfo *)msg->obj;
    uint32_t laneId = (uint32_t)msg->arg1;
    DeleteLaneLinkNode(laneId);
    NotifyLaneAllocSuccess(laneId, info);
    SoftBusFree(msg->obj);
    return;
}

static void LaneLinkFail(SoftBusMessage *msg)
{
    uint32_t laneId = (uint32_t)msg->arg1;
    int32_t reason = (int32_t)msg->arg2;
    if (Lock() != SOFTBUS_OK) {
        return;
    }
    LaneLinkNodeInfo *nodeInfo = GetLaneLinkNodeWithoutLock(laneId);
    if (nodeInfo == NULL) {
        Unlock();
        return;
    }
    if (nodeInfo->linkRetryIdx >= nodeInfo->listNum) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "All linkTypes failed, notify the result");
        Unlock();
        DeleteLaneLinkNode(laneId);
        NotifyLaneAllocFail(laneId, reason);
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "Continue to build link");
    Unlock();
    if (PostMsgToHandler(MSG_TYPE_LANE_TRIGGER_LINK, laneId, 0, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post triggerLink msg fail");
        return;
    }
}

static void LaneLinkException(SoftBusMessage *msg)
{
    uint32_t laneId = (uint32_t)msg->arg1;
    int32_t state = (int32_t)msg->arg2;
    NotifyLaneStateChange(laneId, state);
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
        case MSG_TYPE_LANE_LINK_EXCEPTION:
            LaneLinkException(msg);
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "msg type[%d]cannot found", msg->what);
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "transLane init looper fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void Init(const ILaneIdStateListener *listener)
{
    if (g_requestList != NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "already init");
        return;
    }
    if (InitLooper() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init looper fail");
        return;
    }
    if (SoftBusMutexInit(&g_transLaneMutex, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "transLane mutex init fail");
        return;
    }
    g_requestList = (TransLaneList *)SoftBusCalloc(sizeof(TransLaneList));
    if (g_requestList == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "[init]transLane malloc fail");
        (void)SoftBusMutexDestroy(&g_transLaneMutex);
        return;
    }
    ListInit(&g_requestList->list);
    ListInit(&g_multiLinkList);
    g_laneIdCallback = (ILaneIdStateListener *)listener;
}

static void Deinit(void)
{
    if (g_requestList == NULL) {
        return;
    }
    if (Lock() != SOFTBUS_OK) {
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
    .Init = Init,
    .Deinit = Deinit,
    .AllocLane = Alloc,
    .FreeLane = Free,
};

LaneInterface *TransLaneGetInstance(void)
{
    return &g_transLaneObject;
}
