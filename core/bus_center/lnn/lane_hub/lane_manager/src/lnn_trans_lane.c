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
#include "lnn_lane_model.h"
#include "lnn_lane_select.h"
#include "lnn_log.h"
#include "message_handler.h"
#include "wifi_direct_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_utils.h"
#include "softbus_protocol_def.h"
#include "wifi_direct_error_code.h"
#include "lnn_lane_reliability.h"

#define DETECT_LANE_TIMELINESS 2000

typedef enum {
    MSG_TYPE_LANE_TRIGGER_LINK = 0,
    MSG_TYPE_LANE_LINK_SUCCESS,
    MSG_TYPE_LANE_LINK_FAIL,
    MSG_TYPE_LANE_LINK_EXCEPTION,
    MSG_TYPE_DELAY_DESTROY_LINK,
    MSG_TYPE_LANE_DETECT_TIMEOUT,
    MSG_TYPE_RELIABILITY_TIME,
} LaneMsgType;

typedef struct {
    ListNode node;
    uint32_t laneId;
    TransOption info;
    LaneLinkType type;
    char p2pMac[MAC_ADDR_STR_LEN];
    ILaneListener listener;
} TransReqInfo;

typedef struct {
    uint32_t cnt;
    ListNode list;
} TransLaneList;

typedef struct {
    ListNode node;
    uint32_t laneId;
    int32_t pid;
    char networkId[NETWORK_ID_BUF_LEN];
    LanePreferredLinkList *linkList; /* Mem provided by laneSelect module */
    uint32_t listNum;
    uint32_t linkRetryIdx;
    bool networkDelegate;
    bool p2pOnly;
    int32_t p2pErrCode;
    // OldInfo
    char peerBleMac[MAX_MAC_LEN];
    int32_t psm;
    LaneTransType transType;
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

static void LinkSuccess(uint32_t laneId, const LaneLinkInfo *linkInfo)
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
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    if (memcpy_s(linkParam, sizeof(LaneLinkInfo), linkInfo, sizeof(LaneLinkInfo)) != EOK) {
        SoftBusFree(linkParam);
        LNN_LOGE(LNN_LANE, "linkParam memcpy fail, laneId=%{public}u", laneId);
        (void)LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_FAIL, laneId, SOFTBUS_MEM_ERR, NULL, 0);
        return;
    }
    linkParam->laneId = laneId;
    resourceItem.laneRef = 1;
    resourceItem.laneTimeliness = 0;
    resourceItem.isReliable = true;
    if (ConvertToLaneResource(linkParam, &resourceItem) != SOFTBUS_OK) {
        SoftBusFree(linkParam);
        LNN_LOGE(LNN_LANE, "convert to laneResource fail, laneId=%{public}u", laneId);
        (void)LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_FAIL, laneId, SOFTBUS_ERR, NULL, 0);
        return;
    }
    if (AddLinkInfoItem(linkParam) != SOFTBUS_OK || AddLaneResourceItem(&resourceItem) != SOFTBUS_OK) {
        SoftBusFree(linkParam);
        LNN_LOGE(LNN_LANE, "add linkInfo item fail, laneId=%{public}u", laneId);
        (void)LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_FAIL, laneId, SOFTBUS_ERR, NULL, 0);
        return;
    }
    if (LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_SUCCESS, laneId, 0, linkParam, 0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "post LaneLinkSuccess msg err, laneId=%{public}u", laneId);
        SoftBusFree(linkParam);
        DelLaneResourceItem(&resourceItem);
        DelLinkInfoItem(laneId);
        return;
    }
}

static void LinkFail(uint32_t laneId, int32_t reason)
{
    if (LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_FAIL, laneId, reason, NULL, 0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "post lanelink fail msg err");
        return;
    }
}

static void LinkException(uint32_t laneId, int32_t reason)
{
    if (LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_EXCEPTION, laneId, reason, NULL, 0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "post laneStateException msg err");
        return;
    }
}

static void DeleteLaneLinkNode(uint32_t laneId)
{
    if (Lock() != SOFTBUS_OK) {
        return;
    }
    LaneLinkNodeInfo *item = NULL;
    LaneLinkNodeInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_multiLinkList, LaneLinkNodeInfo, node) {
        if (item->laneId == laneId) {
            ListDelete(&item->node);
            SoftBusFree(item->linkList);
            SoftBusFree(item);
            break;
        }
    }
    Unlock();
}

static int32_t TriggerLink(uint32_t laneId, TransOption *request,
    LanePreferredLinkList *recommendLinkList)
{
    LNN_LOGI(LNN_LANE, "TriggerLink enter");
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
    linkNode->laneId = laneId;
    linkNode->linkRetryIdx = 0;
    linkNode->listNum = recommendLinkList->linkTypeNum;
    linkNode->linkList = recommendLinkList;
    linkNode->pid = request->pid;
    linkNode->networkDelegate = request->networkDelegate;
    linkNode->p2pOnly = request->p2pOnly;
    linkNode->p2pErrCode = SOFTBUS_OK;
    ListInit(&linkNode->node);
    if (Lock() != SOFTBUS_OK) {
        SoftBusFree(linkNode);
        return SOFTBUS_LOCK_ERR;
    }
    ListTailInsert(&g_multiLinkList, &linkNode->node);
    Unlock();
    if (LnnLanePostMsgToHandler(MSG_TYPE_LANE_TRIGGER_LINK, laneId,
        request->acceptableProtocols, NULL, 0) != SOFTBUS_OK) {
        DeleteLaneLinkNode(laneId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static TransReqInfo *CreateRequestNode(uint32_t laneId, const TransOption *option, const ILaneListener *listener)
{
    TransReqInfo *newNode = (TransReqInfo *)SoftBusCalloc(sizeof(TransReqInfo));
    if (newNode == NULL) {
        LNN_LOGE(LNN_LANE, "malloc fail");
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
    TransReqInfo *item = NULL;
    TransReqInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_requestList->list, TransReqInfo, node) {
        if (item->laneId == laneId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_requestList->cnt--;
            break;
        }
    }
    Unlock();
}

static int32_t StartTriggerLink(uint32_t laneId, TransOption *transRequest, const ILaneListener *listener,
    LanePreferredLinkList *recommendLinkList)
{
    LNN_LOGI(LNN_LANE, "enter");
    TransReqInfo *newItem = CreateRequestNode(laneId, transRequest, listener);
    if (newItem == NULL) {
        return SOFTBUS_ERR;
    }
    newItem->info.isWithQos = true;
    if (Lock() != SOFTBUS_OK) {
        SoftBusFree(newItem);
        return SOFTBUS_ERR;
    }
    ListTailInsert(&g_requestList->list, &newItem->node);
    g_requestList->cnt++;
    Unlock();
    if (TriggerLink(laneId, transRequest, recommendLinkList) != SOFTBUS_OK) {
        DeleteRequestNode(laneId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t AllocLane(uint32_t laneId, const LaneRequestOption *request, const ILaneListener *listener)
{
    if ((request == NULL) || (request->type != LANE_TYPE_TRANS)) {
        LNN_LOGE(LNN_LANE, "AllocLane param invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    TransOption *transRequest = (TransOption *)&request->requestInfo.trans;
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = transRequest->transType;
    selectParam.qosRequire = transRequest->qosRequire;
    LanePreferredLinkList *recommendLinkList = (LanePreferredLinkList *)SoftBusMalloc(sizeof(LanePreferredLinkList));
    if (recommendLinkList == NULL) {
        LNN_LOGE(LNN_LANE, "recommendLinkList malloc fail");
        return SOFTBUS_ERR;
    }
    recommendLinkList->linkTypeNum = 0;
    if (SelectExpectLanesByQos((const char *)transRequest->networkId, &selectParam,
            recommendLinkList) != SOFTBUS_OK) {
        SoftBusFree(recommendLinkList);
        LNN_LOGE(LNN_LANE, "selectExpectLanesByQos fail, laneId=%{public}u", laneId);
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_LANE, "select lane link by qos success, laneId=%{public}u, linkNum=%{public}d",
        laneId, recommendLinkList->linkTypeNum);
    if (recommendLinkList->linkTypeNum == 0) {
        SoftBusFree(recommendLinkList);
        LNN_LOGE(LNN_LANE, "no link resources available, allocLane fail, laneId=%{public}u", laneId);
        return SOFTBUS_ERR;
    }
    if (StartTriggerLink(laneId, transRequest, listener, recommendLinkList) != SOFTBUS_OK) {
        SoftBusFree(recommendLinkList);
        LNN_LOGE(LNN_LANE, "trigger link fail, laneId=%{public}u", laneId);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
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
        LNN_LOGE(LNN_LANE, "memcpy fail");
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
    LNN_LOGI(LNN_LANE, "select lane link success, linkNum=%{public}d, laneId=%{public}u", listNum, laneId);
    TransReqInfo *newItem = CreateRequestNode(laneId, transRequest, listener);
    if (newItem == NULL) {
        SoftBusFree(recommendLinkList);
        return SOFTBUS_ERR;
    }
    newItem->info.isWithQos = false;
    if (Lock() != SOFTBUS_OK) {
        SoftBusFree(newItem);
        SoftBusFree(recommendLinkList);
        return SOFTBUS_ERR;
    }
    ListTailInsert(&g_requestList->list, &newItem->node);
    g_requestList->cnt++;
    Unlock();
    if (TriggerLink(laneId, transRequest, recommendLinkList) != SOFTBUS_OK) {
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

static int32_t FreeLaneLink(uint32_t laneId, LaneResource *laneResourceInfo, bool isDelayDestroy)
{
    if (Lock() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    TransReqInfo *item = NULL;
    TransReqInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_requestList->list, TransReqInfo, node) {
        if (item->laneId == laneId) {
            ListDelete(&item->node);
            g_requestList->cnt--;
            Unlock();
            DelLinkInfoItem(laneId);
            if (isDelayDestroy) {
                LNN_LOGI(LNN_LANE, "delayDestroy finished. laneId=%{public}u", laneId);
                DelLaneResourceItem(laneResourceInfo);
                SoftBusFree(laneResourceInfo);
            }
            DestroyLink(item->info.networkId, laneId, item->type, item->info.pid);
            UnbindLaneId(laneId, item);
            SoftBusFree(item);
            FreeLaneId(laneId);
            return SOFTBUS_OK;
        }
    }
    DelLinkInfoItem(laneId);
    if (isDelayDestroy) {
        DelLaneResourceItem(laneResourceInfo);
        SoftBusFree(laneResourceInfo);
    }
    Unlock();
    FreeLaneId(laneId);
    return SOFTBUS_OK;
}

static int32_t Free(uint32_t laneId)
{
    LaneLinkInfo laneLinkInfo;
    (void)memset_s(&laneLinkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    LaneResource laneResourceInfo;
    (void)memset_s(&laneResourceInfo, sizeof(LaneResource), 0, sizeof(LaneResource));
    FindLaneLinkInfoByLaneId(laneId, &laneLinkInfo);
    ConvertToLaneResource(&laneLinkInfo, &laneResourceInfo);
    bool isDelayDestroy = false;
    DelLaneResourceItemWithDelay(&laneResourceInfo, laneId, &isDelayDestroy);
    LNN_LOGI(LNN_LANE, "laneId=%{public}u, delayDestroy=%{public}s", laneId, isDelayDestroy ? "true" : "false");
    if (isDelayDestroy) {
        return SOFTBUS_OK;
    }
    return FreeLaneLink(laneId, &laneResourceInfo, isDelayDestroy);
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
        LNN_LOGE(LNN_LANE, "[transLane] cannot find reqInfo");
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
    if (nodeInfo->type != LANE_P2P && nodeInfo->type != LANE_HML) {
        return;
    }
    if (LnnGetRemoteStrInfo(nodeInfo->info.networkId, STRING_KEY_P2P_MAC,
        nodeInfo->p2pMac, MAC_ADDR_STR_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "get remote p2p mac fail.");
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
        LNN_LOGE(LNN_LANE, "lane alloc success, but laneInfo proc fail");
        return;
    }
    profile.content = reqInfo.info.transType;
    if (BindLaneIdToProfile(laneId, &profile) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "bind laneId to profile fail");
    }
    LNN_LOGI(LNN_LANE, "Notify laneAlloc succ, laneId=%{public}u, linkType=%{public}d", laneId, info->type);
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
    LNN_LOGE(LNN_LANE, "Notify laneAlloc fail, laneId=%{public}u, reason=%{public}d", laneId, reason);
    reqInfo.listener.OnLaneRequestFail(laneId, reason);
    if (Lock() != SOFTBUS_OK) {
        return;
    }
    TransReqInfo *item = NULL;
    TransReqInfo *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_requestList->list, TransReqInfo, node) {
        if (item->laneId == laneId) {
            ListDelete(&item->node);
            SoftBusFree(item);
            g_requestList->cnt--;
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
        LNN_LOGE(LNN_LANE, "lane state is changed, state=%{public}d", state);
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
    ProtocolType acceptableProtocols = (ProtocolType)msg->arg2;
    LaneLinkCb linkCb = {
        .OnLaneLinkSuccess = LinkSuccess,
        .OnLaneLinkFail = LinkFail,
        .OnLaneLinkException = LinkException,
    };
    LinkRequest requestInfo = { 0 };
    if (Lock() != SOFTBUS_OK) {
        return;
    }
    LaneLinkNodeInfo *nodeInfo = GetLaneLinkNodeWithoutLock(laneId);
    if (nodeInfo == NULL) {
        Unlock();
        return;
    }
    if (nodeInfo->linkRetryIdx >= nodeInfo->listNum) {
        LNN_LOGE(LNN_LANE, "All linkType have been tried");
        Unlock();
        return;
    }
    requestInfo.networkDelegate = nodeInfo->networkDelegate;
    requestInfo.p2pOnly = nodeInfo->p2pOnly;
    requestInfo.linkType = nodeInfo->linkList->linkType[nodeInfo->linkRetryIdx];
    nodeInfo->linkRetryIdx++;
    requestInfo.pid = nodeInfo->pid;
    requestInfo.acceptableProtocols = acceptableProtocols;
    if (memcpy_s(requestInfo.peerNetworkId, sizeof(requestInfo.peerNetworkId),
        nodeInfo->networkId, sizeof(nodeInfo->networkId)) != EOK) {
        Unlock();
        return;
    }
    requestInfo.transType = nodeInfo->transType;
    if (memcpy_s(requestInfo.peerBleMac, MAX_MAC_LEN, nodeInfo->peerBleMac, MAX_MAC_LEN) != EOK) {
        Unlock();
        return;
    }
    requestInfo.psm = nodeInfo->psm;
    Unlock();
    int32_t ret = BuildLink(&requestInfo, laneId, &linkCb);
    if (ret == SOFTBUS_OK) {
        return;
    }
    if (LnnLanePostMsgToHandler(MSG_TYPE_LANE_LINK_FAIL, laneId, acceptableProtocols, NULL, 0) != SOFTBUS_OK) {
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
    uint32_t laneId = (uint32_t)msg->arg1;
    DeleteLaneLinkNode(laneId);
    NotifyLaneAllocSuccess(laneId, info);
    SoftBusFree(info);
    return;
}

static void LaneLinkFail(SoftBusMessage *msg)
{
    uint32_t laneId = (uint32_t)msg->arg1;
    int32_t reason = SOFTBUS_ERR;
    if (Lock() != SOFTBUS_OK) {
        return;
    }
    LaneLinkNodeInfo *nodeInfo = GetLaneLinkNodeWithoutLock(laneId);
    if (nodeInfo == NULL) {
        Unlock();
        LNN_LOGE(LNN_LANE, "getLinkNode fail. laneId=%{public}u", laneId);
        NotifyLaneAllocFail(laneId, reason);
        return;
    }
    if ((reason >= ERROR_WIFI_DIRECT_END && reason <= ERROR_WIFI_DIRECT_START) ||
        (reason >= V1_ERROR_END && reason <= V1_ERROR_START)) {
        nodeInfo->p2pErrCode = reason;
    }
    if (nodeInfo->linkRetryIdx >= nodeInfo->listNum) {
        LNN_LOGE(LNN_LANE, "All linkTypes failed, notify the result");
        if (nodeInfo->p2pErrCode != SOFTBUS_OK) {
            reason = nodeInfo->p2pErrCode;
        }
        Unlock();
        DeleteLaneLinkNode(laneId);
        NotifyLaneAllocFail(laneId, reason);
        return;
    }
    LNN_LOGI(LNN_LANE, "Continue to build link");
    Unlock();
    ProtocolType acceptableProtocols = (ProtocolType)msg->arg2;
    if (msg->arg2 == (uint64_t)SOFTBUS_ERR) {
        acceptableProtocols = LNN_PROTOCOL_ALL ^ LNN_PROTOCOL_NIP;
    }
    if (LnnLanePostMsgToHandler(MSG_TYPE_LANE_TRIGGER_LINK, laneId, acceptableProtocols, NULL, 0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "post triggerLink msg fail");
        return;
    }
}

static void LaneLinkException(SoftBusMessage *msg)
{
    uint32_t laneId = (uint32_t)msg->arg1;
    int32_t state = (int32_t)msg->arg2;
    NotifyLaneStateChange(laneId, state);
}

static void HandleDelayDestroyLink(SoftBusMessage *msg)
{
    if (msg->obj == NULL) {
        LNN_LOGE(LNN_LANE, "invalid msg->obj");
        return;
    }
    uint32_t laneId = (uint32_t)msg->arg1;
    bool isDelayDestroy = (bool)msg->arg2;
    LaneResource *resourceItem = (LaneResource*)msg->obj;
    LNN_LOGI(LNN_LANE, "handle delay destroy message, laneId=%{public}u", laneId);
    FreeLaneLink(laneId, resourceItem, isDelayDestroy);
}

static void HandleDetectTimeout(SoftBusMessage *msg)
{
    uint32_t detectId = (uint32_t)msg->arg1;
    LNN_LOGI(LNN_LANE, "lane detect timeout. detectId=%{public}u", detectId);
    NotifyDetectTimeout(detectId);
}

static void HandleReliabilityTime(SoftBusMessage *msg)
{
    HandleLaneReliabilityTime();
    (void)LnnLanePostMsgToHandler(MSG_TYPE_RELIABILITY_TIME, 0, 0, NULL, DETECT_LANE_TIMELINESS);
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
        case MSG_TYPE_DELAY_DESTROY_LINK:
            HandleDelayDestroyLink(msg);
            break;
        case MSG_TYPE_LANE_DETECT_TIMEOUT:
            HandleDetectTimeout(msg);
            break;
        case MSG_TYPE_RELIABILITY_TIME:
            HandleReliabilityTime(msg);
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
    if (PostReliabilityTimeMessage() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "post Reliability Time Message failed");
        return;
    }
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
    .allocLaneByQos = AllocLane,
    .FreeLane = Free,
};

LaneInterface *TransLaneGetInstance(void)
{
    return &g_transLaneObject;
}

int32_t GetTransOptionByLaneId(uint32_t laneId, TransOption *reqInfo)
{
    if (reqInfo == NULL || laneId == INVALID_LANE_ID) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (Lock() != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    TransReqInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_requestList->list, TransReqInfo, node) {
        if (item->laneId == laneId) {
            if (memcpy_s(reqInfo, sizeof(TransOption), &item->info, sizeof(TransOption)) != EOK) {
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
    LNN_LOGI(LNN_LANE, "post timeout message, detect=%{public}u", detectId);
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

int32_t PostReliabilityTimeMessage(void)
{
    return LnnLanePostMsgToHandler(MSG_TYPE_RELIABILITY_TIME, 0, 0, NULL, DETECT_LANE_TIMELINESS);
}

int32_t PostDelayDestroyMessage(uint32_t laneId, LaneResource *resourceItem, uint64_t delayMillis)
{
    LNN_LOGI(LNN_LANE, "post dely destroy message. laneId=%{public}u", laneId);
    return LnnLanePostMsgToHandler(MSG_TYPE_DELAY_DESTROY_LINK, laneId, true, resourceItem, delayMillis);
}