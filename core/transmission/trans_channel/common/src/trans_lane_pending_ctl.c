/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "trans_lane_pending_ctl.h"

#include <securec.h>

#include "access_control.h"
#include "auth_interface.h"
#include "bus_center_manager.h"
#include "common_list.h"
#include "lnn_distributed_net_ledger.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_hisysevt_transreporter.h"
#include "softbus_utils.h"
#include "trans_channel_common.h"
#include "trans_client_proxy.h"
#include "trans_event.h"
#include "trans_lane_manager.h"
#include "trans_log.h"
#include "trans_session_manager.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define TRANS_REQUEST_PENDING_TIMEOUT (5000)
#define SESSION_NAME_PHONEPAD "com.huawei.pcassistant.phonepad-connect-channel"
#define SESSION_NAME_CASTPLUS "CastPlusSessionName"
#define SESSION_NAME_DISTRIBUTE_COMMUNICATION "com.huawei.boosterd.user"
#define SESSION_NAME_ISHARE "IShare"
#define ISHARE_MIN_NAME_LEN 6

#define SESSION_NAME_DBD "distributeddata-default"
#define SESSION_NAME_DSL "device.security.level"
#define MESH_MAGIC_NUMBER 0x5A5A5A5A

typedef struct {
    ListNode node;
    uint32_t laneHandle;
    int32_t errCode;
    SoftBusCond cond;
    bool bSucc;
    bool isFinished;
    LaneConnInfo connInfo;
    SessionParam param;
    uint32_t callingTokenId; // used for transmission access control
    uint32_t firstTokenId; // used for dfx connection success rate
} TransReqLaneItem;

static SoftBusList *g_reqLanePendingList = NULL;

static SoftBusList *g_asyncReqLanePendingList = NULL;

int32_t TransReqLanePendingInit(void)
{
    g_reqLanePendingList = CreateSoftBusList();
    if (g_reqLanePendingList == NULL) {
        TRANS_LOGE(TRANS_INIT, "g_reqLanePendingList is null.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransAsyncReqLanePendingInit(void)
{
    g_asyncReqLanePendingList = CreateSoftBusList();
    if (g_asyncReqLanePendingList == NULL) {
        TRANS_LOGE(TRANS_INIT, "g_asyncReqLanePendingList is null.");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void DestroyAsyncReqItemParam(SessionParam *param)
{
    if (param->sessionName != NULL) {
        SoftBusFree((void *)(param->sessionName));
        param->sessionName = NULL;
    }
    if (param->peerSessionName != NULL) {
        SoftBusFree((void *)(param->peerSessionName));
        param->peerSessionName = NULL;
    }
    if (param->peerDeviceId != NULL) {
        SoftBusFree((void *)(param->peerDeviceId));
        param->peerDeviceId = NULL;
    }
    if (param->groupId != NULL) {
        SoftBusFree((void *)(param->groupId));
        param->groupId = NULL;
    }
    if (param->attr != NULL) {
        SoftBusFree((void *)(param->attr));
        param->attr = NULL;
    }
}

void TransReqLanePendingDeinit(void)
{
    TRANS_LOGI(TRANS_SVC, "enter.");
    if (g_reqLanePendingList == NULL) {
        TRANS_LOGE(TRANS_INIT, "g_reqLanePendingList is null.");
        return;
    }

    if (SoftBusMutexLock(&g_reqLanePendingList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "lock failed.");
        return;
    }

    TransReqLaneItem *item = NULL;
    TransReqLaneItem *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_reqLanePendingList->list, TransReqLaneItem, node) {
        (void)SoftBusCondDestroy(&item->cond);
        ListDelete(&item->node);
        SoftBusFree(item);
    }
    (void)SoftBusMutexUnlock(&g_reqLanePendingList->lock);
    DestroySoftBusList(g_reqLanePendingList);
    g_reqLanePendingList = NULL;
}

void TransAsyncReqLanePendingDeinit(void)
{
    TRANS_LOGI(TRANS_SVC, "enter.");
    if (g_asyncReqLanePendingList == NULL) {
        TRANS_LOGE(TRANS_INIT, "g_asyncReqLanePendingList is null.");
        return;
    }

    if (SoftBusMutexLock(&g_asyncReqLanePendingList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "lock failed.");
        return;
    }

    TransReqLaneItem *item = NULL;
    TransReqLaneItem *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_asyncReqLanePendingList->list, TransReqLaneItem, node) {
        ListDelete(&item->node);
        DestroyAsyncReqItemParam(&(item->param));
        SoftBusFree(item);
    }
    (void)SoftBusMutexUnlock(&g_asyncReqLanePendingList->lock);
    DestroySoftBusList(g_asyncReqLanePendingList);
    g_asyncReqLanePendingList = NULL;
}

static int32_t TransDelLaneReqFromPendingList(uint32_t laneHandle, bool isAsync)
{
    TRANS_LOGD(TRANS_SVC, "del tran request from pending laneHandle=%{public}u, isAsync=%{public}d",
        laneHandle, isAsync);
    SoftBusList *pendingList = isAsync ? g_asyncReqLanePendingList : g_reqLanePendingList;
    if (pendingList == NULL) {
        TRANS_LOGE(TRANS_SVC, "lane pending list no init.");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&(pendingList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    TransReqLaneItem *laneItem = NULL;
    TransReqLaneItem *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(laneItem, next, &(pendingList->list), TransReqLaneItem, node) {
        if (laneItem->laneHandle == laneHandle) {
            if (!isAsync) {
                (void)SoftBusCondDestroy(&laneItem->cond);
            }
            ListDelete(&(laneItem->node));
            TRANS_LOGI(TRANS_SVC, "delete laneHandle = %{public}u", laneItem->laneHandle);
            pendingList->cnt--;
            if (isAsync) {
                DestroyAsyncReqItemParam(&(laneItem->param));
            }
            SoftBusFree(laneItem);
            (void)SoftBusMutexUnlock(&(pendingList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(pendingList->lock));
    TRANS_LOGE(TRANS_SVC, "trans lane request not found, laneHandle=%{public}u", laneHandle);
    return SOFTBUS_ERR;
}

static int32_t TransAddLaneReqFromPendingList(uint32_t laneHandle)
{
    if (g_reqLanePendingList == NULL) {
        TRANS_LOGE(TRANS_SVC, "lane pending list no init.");
        return SOFTBUS_ERR;
    }

    TransReqLaneItem *item = (TransReqLaneItem *)SoftBusCalloc(sizeof(TransReqLaneItem));
    if (item == NULL) {
        TRANS_LOGE(TRANS_SVC, "malloc lane request item err.");
        return SOFTBUS_MALLOC_ERR;
    }
    item->errCode = SOFTBUS_ERR;
    item->laneHandle = laneHandle;
    item->bSucc = false;
    item->isFinished = false;

    if (SoftBusMutexLock(&g_reqLanePendingList->lock) != SOFTBUS_OK) {
        SoftBusFree(item);
        TRANS_LOGE(TRANS_SVC, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    if (SoftBusCondInit(&item->cond) != 0) {
        SoftBusFree(item);
        (void)SoftBusMutexUnlock(&g_reqLanePendingList->lock);
        TRANS_LOGE(TRANS_SVC, "cond init failed.");
        return SOFTBUS_ERR;
    }
    ListInit(&(item->node));
    ListAdd(&(g_reqLanePendingList->list), &(item->node));
    g_reqLanePendingList->cnt++;
    (void)SoftBusMutexUnlock(&g_reqLanePendingList->lock);

    TRANS_LOGI(TRANS_SVC, "add tran request to pending laneHandle=%{public}u", laneHandle);
    return SOFTBUS_OK;
}

static void BuildTransEventExtra(
    TransEventExtra *extra, const SessionParam *param, uint32_t laneHandle, LaneTransType transType, int32_t ret)
{
    extra->calleePkg = NULL;
    extra->callerPkg = NULL;
    extra->socketName = param->sessionName;
    extra->laneId = (int32_t)laneHandle;
    extra->peerNetworkId = param->peerDeviceId;
    extra->laneTransType = transType;
    extra->errcode = ret;
    extra->result = (ret == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;
    extra->result = (ret == SOFTBUS_TRANS_STOP_BIND_BY_CANCEL) ? EVENT_STAGE_RESULT_CANCELED : extra->result;
}

static void CallBackOpenChannelFailed(const SessionParam *param, const AppInfo *appInfo, int32_t errCode)
{
    if (param->isAsync) {
        ChannelMsg data = {
            .msgChannelId = param->sessionId,
            .msgChannelType = CHANNEL_TYPE_UNDEFINED,
            .msgPkgName = appInfo->myData.pkgName,
            .msgPid = appInfo->myData.pid,
        };
        (void)ClientIpcOnChannelOpenFailed(&data, errCode);
    }
}

static int32_t CopyAsyncReqItemSessionParamIds(const SessionParam *source, SessionParam *target)
{
    char *groupId = (char *)SoftBusCalloc(sizeof(char) * GROUP_ID_SIZE_MAX);
    TRANS_CHECK_AND_RETURN_RET_LOGE(groupId != NULL, SOFTBUS_MALLOC_ERR, TRANS_SVC, "SoftBusCalloc groupId failed");
    if (source->groupId != NULL && strcpy_s(groupId, GROUP_ID_SIZE_MAX, source->groupId) != EOK) {
        TRANS_LOGE(TRANS_SVC, "strcopy groupId failed");
        SoftBusFree(groupId);
        return SOFTBUS_MEM_ERR;
    }
    target->groupId = groupId;

    SessionAttribute *tmpAttr = (SessionAttribute *)SoftBusCalloc(sizeof(SessionAttribute));
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        tmpAttr != NULL, SOFTBUS_MALLOC_ERR, TRANS_SVC, "SoftBusCalloc SessionAttribute failed");
    if (memcpy_s(tmpAttr, sizeof(SessionAttribute), source->attr, sizeof(SessionAttribute)) != EOK) {
        TRANS_LOGE(TRANS_SVC, "memcpy_s SessionAttribute failed");
        SoftBusFree(tmpAttr);
        return SOFTBUS_MEM_ERR;
    }
    target->attr = tmpAttr;
    target->qosCount = source->qosCount;
    if ((source->qosCount > 0) &&
        (memcpy_s(target->qos, sizeof(target->qos), source->qos, sizeof(QosTV) * (source->qosCount)) != EOK)) {
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t CopyAsyncReqItemSessionParam(const SessionParam *source, SessionParam *target)
{
    char *sessionName = (char *)SoftBusCalloc(sizeof(char) * SESSION_NAME_SIZE_MAX);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        sessionName != NULL, SOFTBUS_MALLOC_ERR, TRANS_SVC, "SoftBusCalloc sessionName failed");
    if (source->sessionName != NULL && strcpy_s(sessionName, SESSION_NAME_SIZE_MAX, source->sessionName) != EOK) {
        TRANS_LOGE(TRANS_SVC, "strcopy sessionName failed");
        SoftBusFree(sessionName);
        return SOFTBUS_MEM_ERR;
    }
    target->sessionName = sessionName;

    char *peerSessionName = (char *)SoftBusCalloc(sizeof(char) * SESSION_NAME_SIZE_MAX);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        peerSessionName != NULL, SOFTBUS_MALLOC_ERR, TRANS_SVC, "SoftBusCalloc peerSessionName failed");
    if (source->peerSessionName != NULL &&
        strcpy_s(peerSessionName, SESSION_NAME_SIZE_MAX, source->peerSessionName) != EOK) {
        TRANS_LOGE(TRANS_SVC, "strcopy peerSessionName failed");
        SoftBusFree(peerSessionName);
        return SOFTBUS_MEM_ERR;
    }
    target->peerSessionName = peerSessionName;

    char *peerDeviceId = (char *)SoftBusCalloc(sizeof(char) * DEVICE_ID_SIZE_MAX);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        peerDeviceId != NULL, SOFTBUS_MALLOC_ERR, TRANS_SVC, "SoftBusCalloc peerDeviceId failed");
    if (source->peerDeviceId != NULL && strcpy_s(peerDeviceId, DEVICE_ID_SIZE_MAX, source->peerDeviceId) != EOK) {
        TRANS_LOGE(TRANS_SVC, "strcopy peerDeviceId failed");
        SoftBusFree(peerDeviceId);
        return SOFTBUS_MEM_ERR;
    }
    target->peerDeviceId = peerDeviceId;

    return CopyAsyncReqItemSessionParamIds(source, target);
}

static int32_t TransAddAsyncLaneReqFromPendingList(uint32_t laneHandle, const SessionParam *param,
    uint32_t callingTokenId)
{
    if (g_asyncReqLanePendingList == NULL) {
        TRANS_LOGE(TRANS_SVC, "lane pending list no init.");
        return SOFTBUS_ERR;
    }

    TransReqLaneItem *item = (TransReqLaneItem *)SoftBusCalloc(sizeof(TransReqLaneItem));
    if (item == NULL) {
        TRANS_LOGE(TRANS_SVC, "malloc lane request item err.");
        return SOFTBUS_MALLOC_ERR;
    }
    item->errCode = SOFTBUS_ERR;
    item->laneHandle = laneHandle;
    item->bSucc = false;
    item->isFinished = false;
    item->callingTokenId = callingTokenId;
    item->firstTokenId = TransACLGetFirstTokenID();
    if (CopyAsyncReqItemSessionParam(param, &(item->param)) != SOFTBUS_OK) {
        DestroyAsyncReqItemParam(&(item->param));
        SoftBusFree(item);
        TRANS_LOGE(TRANS_SVC, "copy async lane req attach param failed.");
        return SOFTBUS_MEM_ERR;
    }
    item->param.isQosLane = param->isQosLane;
    item->param.isAsync = param->isAsync;
    item->param.sessionId = param->sessionId;
    if (SoftBusMutexLock(&g_asyncReqLanePendingList->lock) != SOFTBUS_OK) {
        DestroyAsyncReqItemParam(&(item->param));
        SoftBusFree(item);
        TRANS_LOGE(TRANS_SVC, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    ListInit(&(item->node));
    ListAdd(&(g_asyncReqLanePendingList->list), &(item->node));
    g_asyncReqLanePendingList->cnt++;
    (void)SoftBusMutexUnlock(&g_asyncReqLanePendingList->lock);
    TRANS_LOGI(TRANS_SVC, "add async request to pending list laneHandle=%{public}u", laneHandle);
    return SOFTBUS_OK;
}

static int32_t TransGetLaneReqItemByLaneHandle(uint32_t laneHandle, bool *bSucc, LaneConnInfo *connInfo,
    int32_t *errCode)
{
    if (g_reqLanePendingList == NULL) {
        TRANS_LOGE(TRANS_SVC, "lane request list hasn't init.");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&(g_reqLanePendingList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    TransReqLaneItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_reqLanePendingList->list), TransReqLaneItem, node) {
        if (item->laneHandle == laneHandle) {
            *bSucc = item->bSucc;
            *errCode = item->errCode;
            if (memcpy_s(connInfo, sizeof(LaneConnInfo), &(item->connInfo), sizeof(LaneConnInfo)) != EOK) {
                (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
                TRANS_LOGE(TRANS_SVC, "memcpy_s connInfo failed");
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
    TRANS_LOGE(TRANS_SVC, "trans lane request not found. laneHandle=%{public}u", laneHandle);
    return SOFTBUS_ERR;
}

static int32_t TransGetLaneReqItemParamByLaneHandle(
    uint32_t laneHandle, SessionParam *param, uint32_t *callingTokenId, uint32_t *firstTokenId)
{
    if (param == NULL) {
        TRANS_LOGE(TRANS_SVC, "param err.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_asyncReqLanePendingList == NULL) {
        TRANS_LOGE(TRANS_SVC, "lane request list hasn't init.");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&(g_asyncReqLanePendingList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }

    TransReqLaneItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_asyncReqLanePendingList->list), TransReqLaneItem, node) {
        if (item->laneHandle == laneHandle) {
            *callingTokenId = item->callingTokenId;
            if (firstTokenId != NULL) {
                *firstTokenId = item->firstTokenId;
            }
            if (memcpy_s(param, sizeof(SessionParam), &(item->param), sizeof(SessionParam)) != EOK) {
                (void)SoftBusMutexUnlock(&(g_asyncReqLanePendingList->lock));
                TRANS_LOGE(TRANS_SVC, "copy session param failed.");
                return SOFTBUS_MEM_ERR;
            }
            (void)SoftBusMutexUnlock(&(g_asyncReqLanePendingList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_asyncReqLanePendingList->lock));
    TRANS_LOGE(TRANS_SVC, "trans lane request not found. laneHandle=%{public}u", laneHandle);
    return SOFTBUS_ERR;
}

static int32_t TransUpdateLaneConnInfoByLaneHandle(uint32_t laneHandle, bool bSucc, const LaneConnInfo *connInfo,
    bool isAsync, int32_t errCode)
{
    SoftBusList *pendingList = isAsync ? g_asyncReqLanePendingList : g_reqLanePendingList;
    if (pendingList == NULL) {
        TRANS_LOGE(TRANS_SVC, "lane pending list no init.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&(pendingList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }

    TransReqLaneItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(pendingList->list), TransReqLaneItem, node) {
        if (item->laneHandle == laneHandle) {
            item->bSucc = bSucc;
            item->errCode = errCode;
            if ((connInfo != NULL) &&
                (memcpy_s(&(item->connInfo), sizeof(LaneConnInfo), connInfo, sizeof(LaneConnInfo)) != EOK)) {
                (void)SoftBusMutexUnlock(&(pendingList->lock));
                return SOFTBUS_ERR;
            }
            item->isFinished = true;
            if (!isAsync) {
                (void)SoftBusCondSignal(&item->cond);
            }
            (void)SoftBusMutexUnlock(&(pendingList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(pendingList->lock));
    TRANS_LOGE(TRANS_SVC, "trans lane request not found. laneHandle=%{public}u", laneHandle);
    return SOFTBUS_ERR;
}

static void TransOnLaneRequestSuccess(uint32_t laneHandle, const LaneConnInfo *connInfo)
{
    TRANS_LOGI(TRANS_SVC, "request success. laneHandle=%{public}u, laneId=%{public}" PRIu64,
        laneHandle, connInfo->laneId);
    int32_t ret = TransUpdateLaneConnInfoByLaneHandle(laneHandle, true, connInfo, false, SOFTBUS_OK);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "update lane connInfo failed, laneHandle=%{public}u, ret=%{public}d", laneHandle, ret);
    }
}

static void RecordFailOpenSessionKpi(AppInfo *appInfo, LaneConnInfo *connInfo, int64_t timeStart)
{
    SoftbusRecordOpenSessionKpi(appInfo->myData.pkgName, connInfo->type, SOFTBUS_EVT_OPEN_SESSION_FAIL,
        GetSoftbusRecordTimeMillis() - timeStart);
}

static void TransAsyncOpenChannelProc(uint32_t laneHandle, SessionParam *param, AppInfo *appInfo,
    TransEventExtra *extra, LaneConnInfo *connInnerInfo)
{
    int64_t timeStart = GetSoftbusRecordTimeMillis();
    TransInfo transInfo = { .channelId = INVALID_CHANNEL_ID, .channelType = CHANNEL_TYPE_BUTT};
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t ret = TransGetConnectOptByConnInfo(connInnerInfo, &connOpt);
    if (ret != SOFTBUS_OK) {
        RecordFailOpenSessionKpi(appInfo, connInnerInfo, timeStart);
        goto EXIT_ERR;
    }
    appInfo->connectType = connOpt.type;
    extra->linkType = connOpt.type;
    FillAppInfo(appInfo, param, &transInfo, connInnerInfo);
    TransOpenChannelSetModule(transInfo.channelType, &connOpt);
    TRANS_LOGI(TRANS_SVC, "laneHandle=%{public}u, channelType=%{public}u", laneHandle, transInfo.channelType);
    ret = TransOpenChannelProc((ChannelType)transInfo.channelType, appInfo, &connOpt, &(transInfo.channelId));
    if (ret != SOFTBUS_OK) {
        SoftbusReportTransErrorEvt(SOFTBUS_TRANS_CREATE_CHANNEL_ERR);
        RecordFailOpenSessionKpi(appInfo, connInnerInfo, timeStart);
        goto EXIT_ERR;
    }
    TransUpdateSocketChannelInfoBySession(
        param->sessionName, param->sessionId, transInfo.channelId, transInfo.channelType);
    ret = ClientIpcSetChannelInfo(
        appInfo->myData.pkgName, param->sessionName, param->sessionId, &transInfo, appInfo->myData.pid);
    if (ret != SOFTBUS_OK) {
        RecordFailOpenSessionKpi(appInfo, connInnerInfo, timeStart);
        TransCommonCloseChannel(NULL, transInfo.channelId, transInfo.channelType);
        goto EXIT_ERR;
    }
    TransSetSocketChannelStateByChannel(transInfo.channelId, transInfo.channelType, CORE_SESSION_STATE_CHANNEL_OPENED);
    if (((ChannelType)transInfo.channelType == CHANNEL_TYPE_TCP_DIRECT) && (connOpt.type != CONNECT_P2P)) {
        TransFreeLane(laneHandle, param->isQosLane);
    } else if (TransLaneMgrAddLane(transInfo.channelId, transInfo.channelType, connInnerInfo,
        laneHandle, param->isQosLane, &(appInfo->myData)) != SOFTBUS_OK) {
        RecordFailOpenSessionKpi(appInfo, connInnerInfo, timeStart);
        TransCommonCloseChannel(NULL, transInfo.channelId, transInfo.channelType);
        goto EXIT_ERR;
    }
    return;
EXIT_ERR:
    TransBuildTransOpenChannelEndEvent(extra, &transInfo, timeStart, ret);
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_END, *extra);
    TransAlarmExtra extraAlarm;
    TransBuildTransAlarmEvent(&extraAlarm, appInfo, ret);
    TRANS_ALARM(OPEN_SESSION_FAIL_ALARM, CONTROL_ALARM_TYPE, extraAlarm);
    CallBackOpenChannelFailed(param, appInfo, ret);
    TransFreeLane(laneHandle, param->isQosLane);
    (void)TransDeleteSocketChannelInfoBySession(param->sessionName, param->sessionId);
    TRANS_LOGE(TRANS_SVC, "server TransOpenChannel err, ret=%{public}d", ret);
    return;
}

static void TransAsyncSetFirstTokenInfo(uint32_t firstTokenId, AppInfo *appInfo, TransEventExtra *event)
{
    event->firstTokenId = firstTokenId;
    if (event->firstTokenId == TOKENID_NOT_SET) {
        event->firstTokenId = appInfo->callingTokenId;
    }
    TransGetTokenInfo(event->firstTokenId, appInfo->tokenName, sizeof(appInfo->tokenName), &event->firstTokenType);
    event->firstTokenName = appInfo->tokenName;
}

static void TransOnAsyncLaneSuccess(uint32_t laneHandle, const LaneConnInfo *connInfo)
{
    TRANS_LOGI(TRANS_SVC, "request success. laneHandle=%{public}u, laneId=%{public}" PRIu64 "",
        laneHandle, connInfo->laneId);
    LaneConnInfo tmpConnInfo;
    if (memcpy_s(&tmpConnInfo, sizeof(LaneConnInfo), connInfo, sizeof(LaneConnInfo)) != EOK) {
        TRANS_LOGE(TRANS_SVC, "memcpy tmpConnInfo failed");
        return;
    }
    SessionParam param;
    uint32_t callingTokenId = TOKENID_NOT_SET;
    uint32_t firstTokenId = TOKENID_NOT_SET;
    int32_t ret = TransGetLaneReqItemParamByLaneHandle(laneHandle, &param, &callingTokenId, &firstTokenId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get lane req item failed. laneHandle=%{public}u, ret=%{public}d", laneHandle, ret);
        (void)TransDelLaneReqFromPendingList(laneHandle, true);
        return;
    }
    LaneTransType transType = (LaneTransType)TransGetLaneTransTypeBySession(&param);
    TransEventExtra extra;
    BuildTransEventExtra(&extra, &param, laneHandle, transType, SOFTBUS_OK);
    extra.linkType = tmpConnInfo.type;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_SELECT_LANE, extra);
    CoreSessionState state = CORE_SESSION_STATE_INIT;
    TransGetSocketChannelStateBySession(param.sessionName, param.sessionId, &state);
    if (state == CORE_SESSION_STATE_CANCELLING) {
        TRANS_LOGI(
            TRANS_SVC, "cancel state laneHandle=%{public}u, laneId=%{public}" PRId64, laneHandle, connInfo->laneId);
        TransFreeLane(laneHandle, param.isQosLane);
        BuildTransEventExtra(&extra, &param, laneHandle, transType, SOFTBUS_TRANS_STOP_BIND_BY_CANCEL);
        extra.linkType = tmpConnInfo.type;
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_SELECT_LANE, extra);
        (void)TransDelLaneReqFromPendingList(laneHandle, true);
        (void)TransDeleteSocketChannelInfoBySession(param.sessionName, param.sessionId);
        return;
    }
    TransSetSocketChannelStateBySession(param.sessionName, param.sessionId, CORE_SESSION_STATE_LAN_COMPLETE);
    AppInfo *appInfo = TransCommonGetAppInfo(&param);
    TRANS_CHECK_AND_RETURN_LOGW(!(appInfo == NULL), TRANS_SVC, "GetAppInfo is null.");
    appInfo->callingTokenId = callingTokenId;
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t peerRet = LnnGetRemoteNodeInfoById(appInfo->peerNetWorkId, CATEGORY_NETWORK_ID, &nodeInfo);
    TransBuildTransOpenChannelStartEvent(&extra, appInfo, &nodeInfo, peerRet);
    TransAsyncSetFirstTokenInfo(firstTokenId, appInfo, &extra);
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_START, extra);
    TransAsyncOpenChannelProc(laneHandle, &param, appInfo, &extra, &tmpConnInfo);
    TransFreeAppInfo(appInfo);
    (void)TransDelLaneReqFromPendingList(laneHandle, true);
}

static void TransOnAsyncLaneFail(uint32_t laneHandle, int32_t reason)
{
    TRANS_LOGI(TRANS_SVC, "request failed, laneHandle=%{public}u, reason=%{public}d", laneHandle, reason);
    SessionParam param;
    uint32_t callingTokenId = TOKENID_NOT_SET;
    int32_t ret = TransGetLaneReqItemParamByLaneHandle(laneHandle, &param, &callingTokenId, NULL);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get lane req item failed. laneHandle=%{public}u, ret=%{public}d", laneHandle, ret);
        (void)TransDelLaneReqFromPendingList(laneHandle, true);
        return;
    }
    LaneTransType transType = (LaneTransType)TransGetLaneTransTypeBySession(&param);
    TransEventExtra extra;
    BuildTransEventExtra(&extra, &param, laneHandle, transType, SOFTBUS_ERR);
    extra.linkType = LANE_LINK_TYPE_BUTT;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_SELECT_LANE, extra);
    AppInfo *appInfo = TransCommonGetAppInfo(&param);
    TRANS_CHECK_AND_RETURN_LOGW(!(appInfo == NULL), TRANS_SVC, "GetAppInfo is null.");
    appInfo->callingTokenId = callingTokenId;
    CallBackOpenChannelFailed(&param, appInfo, reason);
    if (!param.isQosLane) {
        TransFreeLane(laneHandle, param.isQosLane);
    }
    (void)TransDelLaneReqFromPendingList(laneHandle, true);
    TransFreeAppInfo(appInfo);
    (void)TransDeleteSocketChannelInfoBySession(param.sessionName, param.sessionId);
}

static void TransOnLaneRequestFail(uint32_t laneHandle, int32_t reason)
{
    TRANS_LOGI(TRANS_SVC, "request failed, laneHandle=%{public}u, reason=%{public}d", laneHandle, reason);
    if (reason == SOFTBUS_TIMOUT) {
        TRANS_LOGW(TRANS_SVC, "request laneHandle=%{public}u timeout, convert to trans error code", laneHandle);
        reason = SOFTBUS_TRANS_STOP_BIND_BY_TIMEOUT;
    }
    int32_t ret = TransUpdateLaneConnInfoByLaneHandle(laneHandle, false, NULL, false, reason);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "update lane connInfo failed, laneHandle=%{public}u, ret=%{public}d", laneHandle, ret);
    }
}

static const LaneLinkType g_laneMap[LINK_TYPE_MAX + 1] = {
    LANE_LINK_TYPE_BUTT,
    LANE_WLAN_5G,
    LANE_WLAN_2P4G,
    LANE_P2P,
    LANE_BR,
    LANE_BLE,
    LANE_P2P_REUSE,
    LANE_BLE_DIRECT,
    LANE_COC,
    LANE_COC_DIRECT,
};
static LaneLinkType TransGetLaneLinkTypeBySessionLinkType(LinkType type)
{
    return g_laneMap[type];
}

static void TransformSessionPreferredToLanePreferred(const SessionParam *param,
    LanePreferredLinkList *preferred, TransOption *transOption)
{
    (void)transOption;
    if (param->attr->linkTypeNum <= 0 || param->attr->linkTypeNum > LINK_TYPE_MAX) {
        preferred->linkTypeNum = 0;
        return;
    }
    preferred->linkTypeNum = 0;
    for (int32_t i = 0; i < param->attr->linkTypeNum; ++i) {
        LaneLinkType linkType = TransGetLaneLinkTypeBySessionLinkType(param->attr->linkType[i]);
        if (linkType == LANE_LINK_TYPE_BUTT) {
            continue;
        }
        if (preferred->linkTypeNum >= LINK_TYPE_MAX) {
            TRANS_LOGE(TRANS_SVC,
                "session preferred linknum override lane maxcnt=%{public}d.", LANE_LINK_TYPE_BUTT);
            break;
        }
        preferred->linkType[preferred->linkTypeNum] = linkType;
        preferred->linkTypeNum += 1;
    }
    return;
}

static bool IsShareSession(const char *sessionName)
{
    if (strlen(sessionName) < ISHARE_MIN_NAME_LEN ||
        strncmp(sessionName, SESSION_NAME_ISHARE, ISHARE_MIN_NAME_LEN) != 0) {
        return false;
    }
    return true;
}

static bool PeerDeviceIsLegacyOs(const char *peerNetworkId, const char *sessionName)
{
    uint32_t authCapacity;
    if (LnnGetDLAuthCapacity(peerNetworkId, &authCapacity) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "failed to get auth capacity");
        return false;
    }
    TRANS_LOGD(TRANS_SVC, "authCapacity=%{public}u", authCapacity);
    if (authCapacity == 0 &&
        (strncmp(sessionName, SESSION_NAME_DBD, strlen(SESSION_NAME_DBD)) == 0 ||
        strncmp(sessionName, SESSION_NAME_DSL, strlen(SESSION_NAME_DSL)) == 0)) {
        return true;
    }
    return false;
}

static bool IsMeshSync(const char *sessionName)
{
    uint32_t dslSessionLen = strlen(SESSION_NAME_DSL);
    if (strlen(sessionName) < dslSessionLen ||
        strncmp(sessionName, SESSION_NAME_DSL, dslSessionLen) != 0) {
        return false;
    }
    TRANS_LOGI(TRANS_SVC, "dsl module");
    return true;
}

static void ModuleLaneAdapter(LanePreferredLinkList *preferred)
{
    static LaneLinkType link[] = {
        LANE_WLAN_5G,
        LANE_WLAN_2P4G,
        LANE_BR,
    };
    (void)memset_s(preferred->linkType, sizeof(preferred->linkType), 0, sizeof(preferred->linkType));
    preferred->linkTypeNum = MIN(sizeof(link) / sizeof(link[0]), LANE_LINK_TYPE_BUTT);
    for (uint32_t i = 0; i < preferred->linkTypeNum; i++) {
        preferred->linkType[i] = link[i];
        TRANS_LOGD(TRANS_SVC, "link=%{public}d", preferred->linkType[i]);
    }
}

static void TransGetQosInfo(const SessionParam *param, QosInfo *qosInfo)
{
    if (!(param->isQosLane)) {
        TRANS_LOGD(TRANS_SVC, "not support qos lane");
        return;
    }

    for (uint32_t i = 0; i < param->qosCount; i++) {
        switch (param->qos[i].qos) {
            case QOS_TYPE_MIN_BW:
                qosInfo->minBW = param->qos[i].value;
                break;
            case QOS_TYPE_MAX_LATENCY:
                qosInfo->maxLaneLatency = param->qos[i].value;
                break;
            case QOS_TYPE_MIN_LATENCY:
                qosInfo->minLaneLatency = param->qos[i].value;
                break;
            case QOS_TYPE_RTT_LEVEL:
                qosInfo->rttLevel = (LaneRttLevel)((param->qos[i].value > 0) ? param->qos[i].value : 0);
                break;
            default:
                break;
        }
    }
}

#ifdef SOFTBUS_MINI_SYSTEM
static void TransGetBleMac(const SessionParam *param, LaneRequestOption *requestOption)
{
    if (LnnGetRemoteStrInfo(requestOption->requestInfo.trans.networkId, STRING_KEY_BLE_MAC,
        requestOption->requestInfo.trans.peerBleMac, BT_MAC_LEN) != SOFTBUS_OK) {
        if (strcpy_s(requestOption->requestInfo.trans.peerBleMac, BT_MAC_LEN, "") != EOK) {
            TRANS_LOGE(TRANS_SVC, "strcpy fail");
        }
        TRANS_LOGW(TRANS_SVC, "requestOption get ble mac fail.");
    }
}
#endif

#ifdef SOFTBUS_MINI_SYSTEM
static void TransGetBleMacForAllocLane(const SessionParam *param, LaneAllocInfo *allocInfo)
{
    if (LnnGetRemoteStrInfo(allocInfo->networkId, STRING_KEY_BLE_MAC,
        allocInfo->extendInfo.peerBleMac, BT_MAC_LEN) != SOFTBUS_OK) {
        if (strcpy_s(allocInfo->extendInfo.peerBleMac, BT_MAC_LEN, "") != EOK) {
            TRANS_LOGE(TRANS_SVC, "strcpy fail");
        }
        TRANS_LOGW(TRANS_SVC, "allocInfo get ble mac fail.");
    }
}
#endif

static int32_t GetAllocInfoBySessionParam(const SessionParam *param, LaneAllocInfo *allocInfo)
{
    allocInfo->type = LANE_TYPE_TRANS;
    if (memcpy_s(allocInfo->networkId, NETWORK_ID_BUF_LEN, param->peerDeviceId, NETWORK_ID_BUF_LEN) != EOK) {
        TRANS_LOGE(TRANS_SVC, "memcpy networkId failed.");
        return SOFTBUS_MEM_ERR;
    }
    LaneTransType transType = (LaneTransType)TransGetLaneTransTypeBySession(param);
    if (transType == LANE_T_BUTT) {
        return SOFTBUS_TRANS_INVALID_SESSION_TYPE;
    }
    allocInfo->extendInfo.networkDelegate = false;
    if (strcmp(param->sessionName, SESSION_NAME_PHONEPAD) == 0 ||
        strcmp(param->sessionName, SESSION_NAME_CASTPLUS) == 0) {
        allocInfo->extendInfo.networkDelegate = true;
    }
    allocInfo->transType = transType;
    allocInfo->acceptableProtocols = LNN_PROTOCOL_ALL ^ LNN_PROTOCOL_NIP;
    TransGetQosInfo(param, &allocInfo->qosRequire);

    if (PeerDeviceIsLegacyOs(param->peerDeviceId, param->sessionName) || IsMeshSync(param->sessionName)) {
        allocInfo->qosRequire.minBW = MESH_MAGIC_NUMBER;
        TRANS_LOGI(TRANS_SVC, "adapt legacy os device and mesh, isQosLane=%{public}d", param->isQosLane);
    }

    NodeInfo info;
    int32_t ret = LnnGetRemoteNodeInfoById(allocInfo->networkId, CATEGORY_NETWORK_ID, &info);
    if ((ret == SOFTBUS_OK) && LnnHasDiscoveryType(&info, DISCOVERY_TYPE_LSA)) {
        allocInfo->acceptableProtocols |= LNN_PROTOCOL_NIP;
    }
#ifdef SOFTBUS_MINI_SYSTEM
    // get ble mac only on mini system
    TransGetBleMacForAllocLane(param, allocInfo);
#endif
    int32_t uid;
    ret = TransGetUidAndPid(param->sessionName, &uid, &(allocInfo->pid));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "transGetUidAndPid failed");
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t GetRequestOptionBySessionParam(const SessionParam *param, LaneRequestOption *requestOption)
{
    requestOption->type = LANE_TYPE_TRANS;
    if (memcpy_s(requestOption->requestInfo.trans.networkId, NETWORK_ID_BUF_LEN,
        param->peerDeviceId, NETWORK_ID_BUF_LEN) != EOK) {
        TRANS_LOGE(TRANS_SVC, "memcpy networkId failed.");
        return SOFTBUS_MEM_ERR;
    }

    LaneTransType transType = (LaneTransType)TransGetLaneTransTypeBySession(param);
    if (transType == LANE_T_BUTT) {
        return SOFTBUS_TRANS_INVALID_SESSION_TYPE;
    }
    requestOption->requestInfo.trans.networkDelegate = false;
    if (strcmp(param->sessionName, SESSION_NAME_PHONEPAD) == 0 ||
        strcmp(param->sessionName, SESSION_NAME_CASTPLUS) == 0) {
        requestOption->requestInfo.trans.networkDelegate = true;
    }
    requestOption->requestInfo.trans.p2pOnly = false;
    if (strcmp(param->sessionName, SESSION_NAME_DISTRIBUTE_COMMUNICATION) == 0 || IsShareSession(param->sessionName)) {
        requestOption->requestInfo.trans.p2pOnly = true;
    }
    requestOption->requestInfo.trans.transType = transType;
    requestOption->requestInfo.trans.expectedBw = 0; /* init expectBW */
    requestOption->requestInfo.trans.acceptableProtocols = LNN_PROTOCOL_ALL ^ LNN_PROTOCOL_NIP;

    NodeInfo info;
    int32_t ret = LnnGetRemoteNodeInfoById(requestOption->requestInfo.trans.networkId, CATEGORY_NETWORK_ID, &info);
    if ((ret == SOFTBUS_OK) && LnnHasDiscoveryType(&info, DISCOVERY_TYPE_LSA)) {
        requestOption->requestInfo.trans.acceptableProtocols |= LNN_PROTOCOL_NIP;
    }
#ifdef SOFTBUS_MINI_SYSTEM
    // get ble mac only on mini system
    TransGetBleMac(param, requestOption);
#endif
    int32_t uid;
    ret = TransGetUidAndPid(param->sessionName, &uid, &(requestOption->requestInfo.trans.pid));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "transGetUidAndPid failed.");
        return ret;
    }

    TransformSessionPreferredToLanePreferred(param, &(requestOption->requestInfo.trans.expectedLink),
        &requestOption->requestInfo.trans);
    if (!(param->isQosLane) &&
        (PeerDeviceIsLegacyOs(param->peerDeviceId, param->sessionName) || IsMeshSync(param->sessionName))) {
        ModuleLaneAdapter(&(requestOption->requestInfo.trans.expectedLink));
        TRANS_LOGI(TRANS_SVC, "adapt legacy os device and mesh, isQosLane=%{public}d", param->isQosLane);
    }
    return SOFTBUS_OK;
}

static int32_t TransSoftBusCondWait(SoftBusCond *cond, SoftBusMutex *mutex, uint32_t timeMillis)
{
#define CONVERSION_BASE 1000LL
    if (timeMillis == 0) {
        return SoftBusCondWait(cond, mutex, NULL);
    }

    SoftBusSysTime now;
    if (SoftBusGetTime(&now) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "trans softbus get time failed.");
        return SOFTBUS_ERR;
    }
    int64_t usTime = now.sec * CONVERSION_BASE * CONVERSION_BASE + now.usec + (int32_t)timeMillis * CONVERSION_BASE;
    SoftBusSysTime tv;
    tv.sec = usTime / CONVERSION_BASE / CONVERSION_BASE;
    tv.usec = usTime % (CONVERSION_BASE * CONVERSION_BASE);
    TRANS_LOGI(TRANS_SVC, "start wait cond endSecond=%{public}" PRId64, tv.sec);
    return SoftBusCondWait(cond, mutex, &tv);
}

static int32_t TransWaitingRequestCallback(uint32_t laneHandle)
{
    if (g_reqLanePendingList == NULL) {
        TRANS_LOGE(TRANS_SVC, "lane request list hasn't init.");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&(g_reqLanePendingList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    bool isFound = false;
    TransReqLaneItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_reqLanePendingList->list), TransReqLaneItem, node) {
        if (item->laneHandle == laneHandle) {
            isFound = true;
            break;
        }
    }
    if (!isFound) {
        (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
        TRANS_LOGI(TRANS_SVC, "not found laneHandle in pending. laneHandle=%{public}u", laneHandle);
        return SOFTBUS_ERR;
    }
    if (item->isFinished == false) {
        int32_t rc = TransSoftBusCondWait(&item->cond, &g_reqLanePendingList->lock, 0);
        if (rc != SOFTBUS_OK) {
            (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
            TRANS_LOGI(TRANS_SVC, "wait cond failed laneHandle=%{public}u", laneHandle);
            return rc;
        }
    }
    (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
    TRANS_LOGI(TRANS_SVC, "receive lane cond laneHandle=%{public}u", laneHandle);
    return SOFTBUS_OK;
}

static int32_t TransAddLaneReqToPendingAndWaiting(uint32_t laneHandle, const LaneRequestOption *requestOption)
{
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "add laneHandle to pending failed. laneHandle=%{public}u, ret=%{public}d",
            laneHandle, ret);
        return ret;
    }
    ILaneListener listener;
    listener.onLaneRequestSuccess = TransOnLaneRequestSuccess;
    listener.onLaneRequestFail = TransOnLaneRequestFail;
    ret = LnnRequestLane(laneHandle, requestOption, &listener);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "trans request lane failed. ret=%{public}d", ret);
        (void)TransDelLaneReqFromPendingList(laneHandle, false);
        return ret;
    }
    TRANS_LOGI(TRANS_SVC, "add laneHandle to pending and start waiting. laneHandle=%{public}u", laneHandle);
    if (TransWaitingRequestCallback(laneHandle) != SOFTBUS_OK) {
        (void)TransDelLaneReqFromPendingList(laneHandle, false);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TransAddLaneAllocToPendingAndWaiting(uint32_t laneHandle, const LaneAllocInfo *allocInfo)
{
    int32_t ret = TransAddLaneReqFromPendingList(laneHandle);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "add laneHandle to pending failed. laneHandle=%{public}u, ret=%{public}d",
            laneHandle, ret);
        TransFreeLane(laneHandle, true);
        return ret;
    }
    LaneAllocListener allocListener;
    allocListener.onLaneAllocSuccess = TransOnLaneRequestSuccess;
    allocListener.onLaneAllocFail = TransOnLaneRequestFail;
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        GetLaneManager() != NULL, SOFTBUS_TRANS_GET_LANE_INFO_ERR, TRANS_SVC, "GetLaneManager is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(GetLaneManager()->lnnAllocLane != NULL, SOFTBUS_TRANS_GET_LANE_INFO_ERR,
        TRANS_SVC, "lnnAllocLane is null");
    ret = GetLaneManager()->lnnAllocLane(laneHandle, allocInfo, &allocListener);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "trans request lane failed, ret=%{public}d", ret);
        (void)TransDelLaneReqFromPendingList(laneHandle, false);
        return ret;
    }
    TRANS_LOGI(TRANS_SVC, "add laneHandle to pending and start waiting. laneHandle=%{public}u", laneHandle);
    if (TransWaitingRequestCallback(laneHandle) != SOFTBUS_OK) {
        (void)TransDelLaneReqFromPendingList(laneHandle, false);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void CancelLaneOnWaitLaneState(uint32_t laneHandle, bool isQosLane)
{
    TRANS_LOGI(TRANS_SVC, "Cancel lane, laneHandle=%{public}u, isQosLane=%{public}d", laneHandle, isQosLane);
    if (isQosLane && laneHandle != 0) {
        TRANS_CHECK_AND_RETURN_LOGE(GetLaneManager() != NULL, TRANS_SVC, "GetLaneManager is null");
        TRANS_CHECK_AND_RETURN_LOGE(GetLaneManager()->lnnCancelLane != NULL, TRANS_SVC, "lnnCancelLane is null");
        int32_t ret = GetLaneManager()->lnnCancelLane(laneHandle);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(
                TRANS_SVC, "Cancel lane failed, free lane. laneHandle=%{public}u, ret=%{public}d", laneHandle, ret);
            TransFreeLane(laneHandle, isQosLane);
        }
    }
}

int32_t TransGetLaneInfoByOption(const LaneRequestOption *requestOption, LaneConnInfo *connInfo, uint32_t *laneHandle)
{
    if ((requestOption == NULL) || (connInfo == NULL) || (laneHandle == NULL)) {
        TRANS_LOGE(TRANS_SVC, "get lane info by option param error.");
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        GetLaneManager() != NULL, SOFTBUS_TRANS_GET_LANE_INFO_ERR, TRANS_SVC, "GetLaneManager is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(GetLaneManager()->lnnGetLaneHandle != NULL, SOFTBUS_TRANS_GET_LANE_INFO_ERR,
        TRANS_SVC, "lnnGetLaneHandle is null");
    *laneHandle = GetLaneManager()->lnnGetLaneHandle(LANE_TYPE_TRANS);
    if (TransAddLaneReqToPendingAndWaiting(*laneHandle, requestOption) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "trans add lane to pending list failed.");
        return SOFTBUS_ERR;
    }
    bool bSuccess = false;
    int32_t errCode = SOFTBUS_ERR;
    if (TransGetLaneReqItemByLaneHandle(*laneHandle, &bSuccess, connInfo, &errCode) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get lane req item failed. laneHandle=%{public}u, errCode=%{public}d",
            *laneHandle, errCode);
        (void)TransDelLaneReqFromPendingList(*laneHandle, false);
        return errCode;
    }

    TRANS_LOGI(TRANS_SVC, "request lane conninfo end. laneHandle=%{public}u. errCode=%{public}d",
        *laneHandle, errCode);
    (void)TransDelLaneReqFromPendingList(*laneHandle, false);
    return errCode;
}

int32_t TransGetLaneInfoByQos(const LaneAllocInfo *allocInfo, LaneConnInfo *connInfo, uint32_t *laneHandle)
{
    if ((allocInfo == NULL) || (connInfo == NULL) || (laneHandle == NULL)) {
        TRANS_LOGE(TRANS_SVC, "get lane info param error.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = TransAddLaneAllocToPendingAndWaiting(*laneHandle, allocInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "trans add lane to pending list failed. ret=%{public}d", ret);
        return ret;
    }
    bool bSuccess = false;
    int32_t errCode = SOFTBUS_ERR;
    if (TransGetLaneReqItemByLaneHandle(*laneHandle, &bSuccess, connInfo, &errCode) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get lane req item failed. laneHandle=%{public}u, errCode=%{public}d",
            *laneHandle, errCode);
        (void)TransDelLaneReqFromPendingList(*laneHandle, false);
        return errCode;
    }

    TRANS_LOGI(TRANS_SVC, "request lane conninfo end. laneHandle=%{public}u. errCode=%{public}d",
        *laneHandle, errCode);
    (void)TransDelLaneReqFromPendingList(*laneHandle, false);
    return errCode;
}

int32_t TransGetLaneInfo(const SessionParam *param, LaneConnInfo *connInfo, uint32_t *laneHandle)
{
    if (param == NULL || connInfo == NULL || laneHandle == NULL) {
        TRANS_LOGE(TRANS_SVC, "get lane info param error.");
        return SOFTBUS_INVALID_PARAM;
    }
    CoreSessionState state = CORE_SESSION_STATE_INIT;
    TransGetSocketChannelStateBySession(param->sessionName, param->sessionId, &state);
    TRANS_CHECK_AND_RETURN_RET_LOGW(state != CORE_SESSION_STATE_CANCELLING, SOFTBUS_TRANS_STOP_BIND_BY_CANCEL,
        TRANS_SVC, "cancel state, return cancel code.");
    TransSetSocketChannelStateBySession(param->sessionName, param->sessionId, CORE_SESSION_STATE_WAIT_LANE);
    int32_t ret = SOFTBUS_OK;
    TransEventExtra extra;
    if (!(param->isQosLane)) {
        LaneRequestOption requestOption;
        (void)memset_s(&requestOption, sizeof(LaneRequestOption), 0, sizeof(LaneRequestOption));
        ret = GetRequestOptionBySessionParam(param, &requestOption);
        TRANS_CHECK_AND_RETURN_RET_LOGE(
            ret == SOFTBUS_OK, ret, TRANS_SVC, "get request option failed ret=%{public}d", ret);
        ret = TransGetLaneInfoByOption(&requestOption, connInfo, laneHandle);
        BuildTransEventExtra(&extra, param, *laneHandle, requestOption.requestInfo.trans.transType, ret);
        extra.linkType = connInfo->type;
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_SELECT_LANE, extra);
        TransUpdateSocketChannelLaneInfoBySession(
            param->sessionName, param->sessionId, *laneHandle, param->isQosLane, param->isAsync);
        TRANS_CHECK_AND_RETURN_RET_LOGE(
            ret == SOFTBUS_OK, ret, TRANS_SVC, "get lane info by option failed, ret=%{public}d", ret);
    } else {
        LaneAllocInfo allocInfo;
        (void)memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo));
        ret = GetAllocInfoBySessionParam(param, &allocInfo);
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SVC, "get alloc Info failed ret=%{public}d", ret);
        TRANS_CHECK_AND_RETURN_RET_LOGE(
            GetLaneManager() != NULL, SOFTBUS_TRANS_GET_LANE_INFO_ERR, TRANS_SVC, "GetLaneManager is null");
        TRANS_CHECK_AND_RETURN_RET_LOGE(GetLaneManager()->lnnGetLaneHandle != NULL, SOFTBUS_TRANS_GET_LANE_INFO_ERR,
            TRANS_SVC, "lnnGetLaneHandle is null");
        *laneHandle = GetLaneManager()->lnnGetLaneHandle(LANE_TYPE_TRANS);
        TransUpdateSocketChannelLaneInfoBySession(
            param->sessionName, param->sessionId, *laneHandle, param->isQosLane, param->isAsync);
        ret = TransGetLaneInfoByQos(&allocInfo, connInfo, laneHandle);
        BuildTransEventExtra(&extra, param, *laneHandle, allocInfo.transType, ret);
        extra.linkType = connInfo->type;
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_SELECT_LANE, extra);
        if (ret != SOFTBUS_OK) {
            *laneHandle = INVALID_LANE_REQ_ID; // qos lane failed no need free lane again
            TRANS_LOGE(TRANS_SVC, "get lane info by allocInfo failed, ret=%{public}d", ret);
            return ret;
        }
    }
    return SOFTBUS_OK;
}

int32_t TransAsyncGetLaneInfoByOption(const SessionParam *param, const LaneRequestOption *requestOption,
    uint32_t *laneHandle, uint32_t callingTokenId)
{
    if (param == NULL || requestOption == NULL || laneHandle == NULL) {
        TRANS_LOGE(TRANS_SVC, "async get lane info param error.");
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        GetLaneManager() != NULL, SOFTBUS_TRANS_GET_LANE_INFO_ERR, TRANS_SVC, "GetLaneManager is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(GetLaneManager()->lnnGetLaneHandle != NULL, SOFTBUS_TRANS_GET_LANE_INFO_ERR,
        TRANS_SVC, "lnnGetLaneHandle is null");
    *laneHandle = GetLaneManager()->lnnGetLaneHandle(LANE_TYPE_TRANS);
    TransUpdateSocketChannelLaneInfoBySession(
        param->sessionName, param->sessionId, *laneHandle, param->isQosLane, param->isAsync);
    int32_t ret = TransAddAsyncLaneReqFromPendingList(*laneHandle, param, callingTokenId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(
            TRANS_SVC, "add laneHandle=%{public}u to async pending list failed, ret=%{public}d", *laneHandle, ret);
        return ret;
    }
    ILaneListener listener;
    listener.onLaneRequestSuccess = TransOnAsyncLaneSuccess;
    listener.onLaneRequestFail = TransOnAsyncLaneFail;
    ret = LnnRequestLane(*laneHandle, requestOption, &listener);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "trans request lane failed, ret=%{public}d", ret);
        (void)TransDelLaneReqFromPendingList(*laneHandle, true);
        return ret;
    }
    CoreSessionState state = CORE_SESSION_STATE_INIT;
    TransGetSocketChannelStateBySession(param->sessionName, param->sessionId, &state);
    if (state == CORE_SESSION_STATE_CANCELLING) {
        CancelLaneOnWaitLaneState(*laneHandle, param->isQosLane);
        (void)TransDelLaneReqFromPendingList(*laneHandle, true);
        return SOFTBUS_TRANS_STOP_BIND_BY_CANCEL;
    }
    TransSetSocketChannelStateBySession(param->sessionName, param->sessionId, CORE_SESSION_STATE_WAIT_LANE);
    return SOFTBUS_OK;
}

int32_t TransAsyncGetLaneInfoByQos(const SessionParam *param, const LaneAllocInfo *allocInfo,
    uint32_t *laneHandle, uint32_t callingTokenId)
{
    if (param == NULL || allocInfo == NULL || laneHandle == NULL) {
        TRANS_LOGE(TRANS_SVC, "async get lane info param error.");
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        GetLaneManager() != NULL, SOFTBUS_TRANS_GET_LANE_INFO_ERR, TRANS_SVC, "GetLaneManager is null");
    TRANS_CHECK_AND_RETURN_RET_LOGE(GetLaneManager()->lnnGetLaneHandle != NULL, SOFTBUS_TRANS_GET_LANE_INFO_ERR,
        TRANS_SVC, "lnnGetLaneHandle is null");
    *laneHandle = GetLaneManager()->lnnGetLaneHandle(LANE_TYPE_TRANS);
    TransUpdateSocketChannelLaneInfoBySession(
        param->sessionName, param->sessionId, *laneHandle, param->isQosLane, param->isAsync);
    int32_t ret = TransAddAsyncLaneReqFromPendingList(*laneHandle, param, callingTokenId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(
            TRANS_SVC, "add laneHandle=%{public}u to async pending list failed, ret=%{public}d", *laneHandle, ret);
        TransFreeLane(*laneHandle, true);
        return ret;
    }
    LaneAllocListener allocListener;
    allocListener.onLaneAllocSuccess = TransOnAsyncLaneSuccess;
    allocListener.onLaneAllocFail = TransOnAsyncLaneFail;
    TRANS_CHECK_AND_RETURN_RET_LOGE(GetLaneManager()->lnnAllocLane != NULL, SOFTBUS_TRANS_GET_LANE_INFO_ERR,
        TRANS_SVC, "lnnAllocLane is null");
    ret = GetLaneManager()->lnnAllocLane(*laneHandle, allocInfo, &allocListener);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "trans request lane failed, ret=%{public}d", ret);
        (void)TransDelLaneReqFromPendingList(*laneHandle, true);
        return ret;
    }
    CoreSessionState state = CORE_SESSION_STATE_INIT;
    TransGetSocketChannelStateBySession(param->sessionName, param->sessionId, &state);
    if (state == CORE_SESSION_STATE_CANCELLING) {
        CancelLaneOnWaitLaneState(*laneHandle, param->isQosLane);
        (void)TransDelLaneReqFromPendingList(*laneHandle, true);
        return SOFTBUS_TRANS_STOP_BIND_BY_CANCEL;
    }
    TransSetSocketChannelStateBySession(param->sessionName, param->sessionId, CORE_SESSION_STATE_WAIT_LANE);
    return SOFTBUS_OK;
}

int32_t TransAsyncGetLaneInfo(const SessionParam *param, uint32_t *laneHandle, uint32_t callingTokenId)
{
    if (param == NULL || laneHandle == NULL) {
        TRANS_LOGE(TRANS_SVC, "async get lane info param error.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = SOFTBUS_OK;
    if (!(param->isQosLane)) {
        LaneRequestOption requestOption;
        (void)memset_s(&requestOption, sizeof(LaneRequestOption), 0, sizeof(LaneRequestOption));
        ret = GetRequestOptionBySessionParam(param, &requestOption);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SVC, "get request option failed. laneHandle=%{public}u, ret=%{public}d", *laneHandle, ret);
            return ret;
        }
        ret = TransAsyncGetLaneInfoByOption(param, &requestOption, laneHandle, callingTokenId);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SVC, "get lane info by option failed, ret=%{public}d", ret);
            return ret;
        }
    } else {
        LaneAllocInfo allocInfo;
        (void)memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo));
        ret = GetAllocInfoBySessionParam(param, &allocInfo);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SVC, "get alloc Info failed. laneHandle=%{public}u, ret=%{public}d", *laneHandle, ret);
            return ret;
        }
        ret = TransAsyncGetLaneInfoByQos(param, &allocInfo, laneHandle, callingTokenId);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SVC, "get lane info by allocInfo failed, ret=%{public}d", ret);
            *laneHandle = INVALID_LANE_REQ_ID; // qos lane failed no need free lane again
            return ret;
        }
    }
    return SOFTBUS_OK;
}

static int32_t SetP2pConnInfo(const P2pConnInfo *p2pInfo, ConnectOption *connOpt)
{
    TRANS_LOGI(TRANS_SVC, "set p2p conn info.");
    connOpt->type = CONNECT_P2P;
    if (strcpy_s(connOpt->socketOption.addr, sizeof(connOpt->socketOption.addr), p2pInfo->peerIp) != EOK) {
        TRANS_LOGE(TRANS_SVC, "set p2p localIp err");
        return SOFTBUS_STRCPY_ERR;
    }
    connOpt->socketOption.protocol = LNN_PROTOCOL_IP;
    connOpt->socketOption.port = -1;
    return SOFTBUS_OK;
}
static int32_t SetP2pReusesConnInfo(const WlanConnInfo *connInfo, ConnectOption *connOpt)
{
    connOpt->type = CONNECT_P2P_REUSE;
    connOpt->socketOption.port = (int32_t)connInfo->port;
    connOpt->socketOption.protocol = connInfo->protocol;
    if (strcpy_s(connOpt->socketOption.addr, sizeof(connOpt->socketOption.addr), connInfo->addr) != EOK) {
        TRANS_LOGE(TRANS_SVC, "set p2p reuse localIp err");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SetWlanConnInfo(const WlanConnInfo *connInfo, ConnectOption *connOpt)
{
    connOpt->type = CONNECT_TCP;
    connOpt->socketOption.port = (int32_t)connInfo->port;
    connOpt->socketOption.protocol = connInfo->protocol;
    if (strcpy_s(connOpt->socketOption.addr, sizeof(connOpt->socketOption.addr), connInfo->addr) != EOK) {
        TRANS_LOGE(TRANS_SVC, "set wlan localIp err");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SetBrConnInfo(const BrConnInfo *brInfo, ConnectOption *connOpt)
{
    connOpt->type = CONNECT_BR;
    if (strcpy_s(connOpt->brOption.brMac, sizeof(connOpt->brOption.brMac), brInfo->brMac) != EOK) {
        TRANS_LOGE(TRANS_SVC, "set br mac err");
        return SOFTBUS_STRCPY_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t SetBleConnInfo(const BleConnInfo *bleInfo, ConnectOption *connOpt)
{
    connOpt->type = CONNECT_BLE;
    if (strcpy_s(connOpt->bleOption.bleMac, sizeof(connOpt->bleOption.bleMac), bleInfo->bleMac) != EOK) {
        TRANS_LOGE(TRANS_SVC, "set ble mac err");
        return SOFTBUS_STRCPY_ERR;
    }
    if (memcpy_s(connOpt->bleOption.deviceIdHash, sizeof(connOpt->bleOption.deviceIdHash),
            bleInfo->deviceIdHash, sizeof(bleInfo->deviceIdHash)) != EOK) {
        TRANS_LOGE(TRANS_SVC, "memcpy_s deviceId hash err");
        return SOFTBUS_MEM_ERR;
    }
    connOpt->bleOption.protocol = bleInfo->protoType;
    connOpt->bleOption.psm = bleInfo->psm;
    connOpt->bleOption.fastestConnectEnable = true;
    return SOFTBUS_OK;
}

static int32_t SetBleDirectConnInfo(const BleDirectConnInfo *bleDirect, ConnectOption *connOpt)
{
    if (strcpy_s(connOpt->bleDirectOption.networkId, NETWORK_ID_BUF_LEN, bleDirect->networkId) != EOK) {
        TRANS_LOGW(TRANS_SVC, "set networkId err.");
        return SOFTBUS_STRCPY_ERR;
    }
    connOpt->type = CONNECT_BLE_DIRECT;
    connOpt->bleDirectOption.protoType = bleDirect->protoType;
    return SOFTBUS_OK;
}

static int32_t SetHmlConnectInfo(const P2pConnInfo *p2pInfo, ConnectOption *connOpt)
{
    TRANS_LOGI(TRANS_SVC, "set hml conn info.");
    connOpt->type = CONNECT_HML;
    if (strcpy_s(connOpt->socketOption.addr, sizeof(connOpt->socketOption.addr), p2pInfo->peerIp) != EOK) {
        TRANS_LOGE(TRANS_SVC, "set hml localIp err");
        return SOFTBUS_STRCPY_ERR;
    }
    connOpt->socketOption.protocol = LNN_PROTOCOL_IP;
    connOpt->socketOption.port = -1;
    return SOFTBUS_OK;
}

int32_t TransGetConnectOptByConnInfo(const LaneConnInfo *info, ConnectOption *connOpt)
{
    if (info == NULL || connOpt == NULL) {
        TRANS_LOGW(TRANS_SVC, "invalid param.");
        return SOFTBUS_ERR;
    }
    if (info->type == LANE_P2P || info->type == LANE_HML) {
        return SetP2pConnInfo(&(info->connInfo.p2p), connOpt);
    } else if (info->type == LANE_WLAN_2P4G || info->type == LANE_WLAN_5G || info->type == LANE_ETH) {
        return SetWlanConnInfo(&(info->connInfo.wlan), connOpt);
    } else if (info->type == LANE_BR) {
        return SetBrConnInfo(&(info->connInfo.br), connOpt);
    } else if ((info->type == LANE_BLE) || (info->type == LANE_COC)) {
        return SetBleConnInfo(&(info->connInfo.ble), connOpt);
    } else if (info->type == LANE_P2P_REUSE) {
        return SetP2pReusesConnInfo(&(info->connInfo.wlan), connOpt);
    } else if (info->type == LANE_BLE_DIRECT || info->type == LANE_COC_DIRECT) {
        return SetBleDirectConnInfo(&(info->connInfo.bleDirect), connOpt);
    } else if (info->type == LANE_HML) {
        return SetHmlConnectInfo(&(info->connInfo.p2p), connOpt);
    }

    TRANS_LOGE(TRANS_SVC, "get conn opt err: type=%{public}d", info->type);
    return SOFTBUS_ERR;
}

bool TransGetAuthTypeByNetWorkId(const char *peerNetWorkId)
{
    int32_t value = 0;
    int32_t ret = LnnGetRemoteNumInfo(peerNetWorkId, NUM_KEY_META_NODE, &value);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "GetAuthType fail, ret=%{public}d", ret);
        return false;
    }
    return ((uint32_t)value == (1 << ONLINE_METANODE)) ? true : false;
}

int32_t TransDeleteLaneReqItemByLaneHandle(uint32_t laneHandle, bool isAsync)
{
    return TransDelLaneReqFromPendingList(laneHandle, isAsync);
}

int32_t TransCancelLaneItemCondByLaneHandle(uint32_t laneHandle, bool bSucc, bool isAsync, int32_t errCode)
{
    SoftBusList *pendingList = isAsync ? g_asyncReqLanePendingList : g_reqLanePendingList;
    if (pendingList == NULL) {
        TRANS_LOGE(TRANS_SVC, "lane pending list no init.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&(pendingList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }

    TransReqLaneItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(pendingList->list), TransReqLaneItem, node) {
        if (item->laneHandle == laneHandle) {
            item->bSucc = bSucc;
            item->errCode = errCode;
            item->isFinished = true;
            if (!isAsync) {
                (void)SoftBusCondSignal(&item->cond);
            }
            (void)SoftBusMutexUnlock(&(pendingList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(pendingList->lock));
    TRANS_LOGE(TRANS_SVC, "trans lane request not found. laneHandle=%{public}u", laneHandle);
    return SOFTBUS_NOT_FIND;
}