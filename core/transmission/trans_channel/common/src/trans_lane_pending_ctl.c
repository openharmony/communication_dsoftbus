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

typedef struct {
    ListNode node;
    uint32_t laneReqId;
    int32_t errCode;
    SoftBusCond cond;
    bool bSucc;
    bool isFinished;
    LaneConnInfo connInfo;
    SessionParam param;
    uint32_t firstTokenId;
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
        SoftBusFree((void*)(param->sessionName));
        param->sessionName = NULL;
    }
    if (param->peerSessionName != NULL) {
        SoftBusFree((void*)(param->peerSessionName));
        param->peerSessionName = NULL;
    }
    if (param->peerDeviceId != NULL) {
        SoftBusFree((void*)(param->peerDeviceId));
        param->peerDeviceId = NULL;
    }
    if (param->groupId != NULL) {
        SoftBusFree((void*)(param->groupId));
        param->groupId = NULL;
    }
    if (param->attr != NULL) {
        SoftBusFree((void*)(param->attr));
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

    if (g_asyncReqLanePendingList == NULL) {
        TRANS_LOGE(TRANS_INIT, "g_asyncReqLanePendingList is null.");
        return;
    }

    if (SoftBusMutexLock(&g_asyncReqLanePendingList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "lock failed.");
        return;
    }

    item = NULL;
    next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_asyncReqLanePendingList->list, TransReqLaneItem, node) {
        ListDelete(&item->node);
        DestroyAsyncReqItemParam(&(item->param));
        SoftBusFree(item);
    }
    (void)SoftBusMutexUnlock(&g_asyncReqLanePendingList->lock);
    DestroySoftBusList(g_asyncReqLanePendingList);
    g_asyncReqLanePendingList = NULL;
}

static int32_t TransDelLaneReqFromPendingList(uint32_t laneReqId, bool isAsync)
{
    TRANS_LOGD(TRANS_SVC, "del tran request from pending laneReqId=%{public}u, isAsync=%{public}d", laneReqId, isAsync);
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
        if (laneItem->laneReqId == laneReqId) {
            if (!isAsync) {
                (void)SoftBusCondDestroy(&laneItem->cond);
            }
            ListDelete(&(laneItem->node));
            TRANS_LOGI(TRANS_SVC, "delete laneReqId = %{public}u", laneItem->laneReqId);
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
    TRANS_LOGE(TRANS_SVC, "trans lane request not found, laneReqId=%{public}u", laneReqId);
    return SOFTBUS_ERR;
}

static int32_t TransAddLaneReqFromPendingList(uint32_t laneReqId)
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
    item->laneReqId = laneReqId;
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

    TRANS_LOGI(TRANS_SVC, "add tran request to pending laneReqId=%{public}u", laneReqId);
    return SOFTBUS_OK;
}

static void ReportTransEventExtra(const SessionParam *param, const LaneConnInfo *connInfo, const uint32_t *laneReqId,
    LaneRequestOption requestOption, int32_t ret)
{
    TransEventExtra extra = { .calleePkg = NULL,
        .callerPkg = NULL,
        .socketName = param->sessionName,
        .laneId = (int32_t)*laneReqId,
        .peerNetworkId = param->peerDeviceId,
        .laneTransType = requestOption.requestInfo.trans.transType,
        .linkType = connInfo->type,
        .errcode = ret,
        .result = (ret == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED };
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_SELECT_LANE, extra);
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

static int32_t TransAddAsyncLaneReqFromPendingList(uint32_t laneReqId, const SessionParam *param, uint32_t firstTokenId)
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
    item->laneReqId = laneReqId;
    item->bSucc = false;
    item->isFinished = false;
    item->firstTokenId = firstTokenId;
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
    TRANS_LOGI(TRANS_SVC, "add async request to pending list laneReqId=%{public}u", laneReqId);
    return SOFTBUS_OK;
}

static int32_t TransGetLaneReqItemByLaneReqId(uint32_t laneReqId, bool *bSucc, LaneConnInfo *connInfo, int32_t *errCode)
{
    if (bSucc == NULL || connInfo == NULL) {
        TRANS_LOGE(TRANS_SVC, "param err.");
        return SOFTBUS_ERR;
    }
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
        if (item->laneReqId == laneReqId) {
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
    TRANS_LOGE(TRANS_SVC, "trans lane request not found. laneReqId=%{public}u", laneReqId);
    return SOFTBUS_ERR;
}

static int32_t TransGetLaneReqItemParamByLaneReqId(uint32_t laneReqId, SessionParam *param, uint32_t *firstTokenId)
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
        if (item->laneReqId == laneReqId) {
            *firstTokenId = item->firstTokenId;
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
    TRANS_LOGE(TRANS_SVC, "trans lane request not found. laneReqId=%{public}u", laneReqId);
    return SOFTBUS_ERR;
}

static int32_t TransUpdateLaneConnInfoByLaneReqId(uint32_t laneReqId, bool bSucc,
    const LaneConnInfo *connInfo, bool isAsync, int32_t errCode)
{
    SoftBusList *pendingList = isAsync ? g_asyncReqLanePendingList : g_reqLanePendingList;
    if (pendingList == NULL) {
        TRANS_LOGE(TRANS_SVC, "lane pending list no init.");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&(pendingList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "lock failed.");
        return SOFTBUS_LOCK_ERR;
    }

    TransReqLaneItem *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(pendingList->list), TransReqLaneItem, node) {
        if (item->laneReqId == laneReqId) {
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
    TRANS_LOGE(TRANS_SVC, "trans lane request not found. laneReqId=%{public}u", laneReqId);
    return SOFTBUS_ERR;
}

static void TransOnLaneRequestSuccess(uint32_t laneReqId, const LaneConnInfo *connInfo)
{
    TRANS_LOGI(TRANS_SVC, "request success. laneReqId=%{public}u", laneReqId);
    int ret = TransUpdateLaneConnInfoByLaneReqId(laneReqId, true, connInfo, false, SOFTBUS_OK);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "update lane connInfo failed, laneReqId=%{public}u, ret=%{public}d", laneReqId, ret);
    }
    return;
}

static void TransAsyncOpenChannelProc(
    uint32_t laneReqId, SessionParam *param, AppInfo *appInfo, TransEventExtra extra, LaneConnInfo *connInnerInfo)
{
    int64_t timeStart = GetSoftbusRecordTimeMillis();
    TransInfo transInfo = { .channelId = INVALID_CHANNEL_ID, .channelType = CHANNEL_TYPE_BUTT};
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t errCode = TransGetConnectOptByConnInfo(connInnerInfo, &connOpt);
    if (errCode != SOFTBUS_OK) {
        SoftbusRecordOpenSessionKpi(appInfo->myData.pkgName, connInnerInfo->type, SOFTBUS_EVT_OPEN_SESSION_FAIL,
            GetSoftbusRecordTimeMillis() - timeStart);
        CallBackOpenChannelFailed(param, appInfo, errCode);
        goto EXIT_ERR;
    }
    appInfo->connectType = connOpt.type;
    extra.linkType = connOpt.type;
    FillAppInfo(appInfo, param, &transInfo, connInnerInfo);
    TransOpenChannelSetModule(transInfo.channelType, &connOpt);
    TRANS_LOGI(TRANS_SVC, "laneReqId=%{public}u, channelType=%{public}u", laneReqId, transInfo.channelType);
    errCode = TransOpenChannelProc((ChannelType)transInfo.channelType, appInfo, &connOpt, &(transInfo.channelId));
    if (errCode != SOFTBUS_OK) {
        SoftbusReportTransErrorEvt(SOFTBUS_TRANS_CREATE_CHANNEL_ERR);
        SoftbusRecordOpenSessionKpi(appInfo->myData.pkgName, appInfo->linkType, SOFTBUS_EVT_OPEN_SESSION_FAIL,
            GetSoftbusRecordTimeMillis() - timeStart);
        CallBackOpenChannelFailed(param, appInfo, errCode);
        goto EXIT_ERR;
    }
    if (param->isAsync && ClientIpcSetChannelInfo(appInfo->myData.pkgName, param->sessionName,
                                                  param->sessionId, &transInfo, appInfo->myData.pid) != SOFTBUS_OK) {
        CallBackOpenChannelFailed(param, appInfo, errCode);
        TransCommonCloseChannel(transInfo.channelId, transInfo.channelType);
        goto EXIT_ERR;
    }
    if (((ChannelType)transInfo.channelType == CHANNEL_TYPE_TCP_DIRECT) && (connOpt.type != CONNECT_P2P)) {
        LnnFreeLane(laneReqId);
    } else if (TransLaneMgrAddLane(transInfo.channelId, transInfo.channelType, connInnerInfo, laneReqId,
                                   &(appInfo->myData)) != SOFTBUS_OK) {
        SoftbusRecordOpenSessionKpi(appInfo->myData.pkgName, appInfo->linkType, SOFTBUS_EVT_OPEN_SESSION_FAIL,
            GetSoftbusRecordTimeMillis() - timeStart);
        TransCommonCloseChannel(transInfo.channelId, transInfo.channelType);
        goto EXIT_ERR;
    }
    return;
EXIT_ERR:
    ReportTransOpenChannelEndEvent(extra, &transInfo, timeStart, errCode);
    ReportTransAlarmEvent(appInfo, errCode);
    if (laneReqId != 0) {
        LnnFreeLane(laneReqId);
    }
    TRANS_LOGE(TRANS_SVC, "server TransOpenChannel err, ret=%{public}d", errCode);
    return;
}

static void TransOnAsyncLaneRequestSuccess(uint32_t laneReqId, const LaneConnInfo *connInfo)
{
    TRANS_LOGI(TRANS_SVC, "request success. laneReqId=%{public}u", laneReqId);
    int32_t ret = TransUpdateLaneConnInfoByLaneReqId(laneReqId, true, connInfo, true, SOFTBUS_OK);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "update lane connInfo failed, laneReqId=%{public}u, ret=%{public}d", laneReqId, ret);
        return;
    }
    LaneConnInfo tmpConnInfo;
    if (memcpy_s(&tmpConnInfo, sizeof(LaneConnInfo), connInfo, sizeof(LaneConnInfo)) != EOK) {
        TRANS_LOGE(TRANS_SVC, "memcpy tmpConnInfo failed");
        return;
    }
    SessionParam param;
    uint32_t firstTokenId = 0;
    ret = TransGetLaneReqItemParamByLaneReqId(laneReqId, &param, &firstTokenId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get lane req item failed. laneReqId=%{public}u, ret=%{public}d", laneReqId, ret);
        (void)TransDelLaneReqFromPendingList(laneReqId, true);
        return;
    }
    LaneTransType transType = TransGetLaneTransTypeBySession(&param);
    LaneRequestOption requestOption = {
        .requestInfo.trans.transType = transType,
    };
    ReportTransEventExtra(&param, &tmpConnInfo, &laneReqId, requestOption, SOFTBUS_OK);
    AppInfo *appInfo = TransCommonGetAppInfo(&param);
    TRANS_CHECK_AND_RETURN_LOGW(!(appInfo == NULL), TRANS_SVC, "GetAppInfo is null.");
    appInfo->firstTokenId = firstTokenId;
    char peerUdid[UDID_BUF_LEN] = {0};
    int32_t udidRet = LnnGetRemoteStrInfo(appInfo->peerNetWorkId, STRING_KEY_DEV_UDID, peerUdid, sizeof(peerUdid));
    TransEventExtra extra = {
        .calleePkg = NULL,
        .callerPkg = appInfo->myData.pkgName,
        .socketName = appInfo->myData.sessionName,
        .dataType = appInfo->businessType,
        .peerNetworkId = appInfo->peerNetWorkId,
        .peerUdid = udidRet == SOFTBUS_OK ? peerUdid : NULL,
        .result = EVENT_STAGE_RESULT_OK
    };
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_START, extra);
    TransAsyncOpenChannelProc(laneReqId, &param, appInfo, extra, &tmpConnInfo);
    if (appInfo->fastTransData != NULL) {
        SoftBusFree((void*)(appInfo->fastTransData));
    }
    SoftBusFree(appInfo);
    (void)TransDelLaneReqFromPendingList(laneReqId, true);
}

static void TransOnLaneRequestFail(uint32_t laneReqId, int32_t reason)
{
    TRANS_LOGI(TRANS_SVC, "request failed, laneReqId=%{public}u, reason=%{public}d", laneReqId, reason);
    int32_t ret = TransUpdateLaneConnInfoByLaneReqId(laneReqId, false, NULL, false, reason);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "update lane connInfo failed, laneReqId=%{public}u, ret=%{public}d", laneReqId, ret);
    }
    return;
}

static void TransOnAsyncLaneRequestFail(uint32_t laneReqId, int32_t reason)
{
    TRANS_LOGI(TRANS_SVC, "request failed, laneReqId=%{public}u, reason=%{public}d", laneReqId, reason);
    int32_t ret = TransUpdateLaneConnInfoByLaneReqId(laneReqId, false, NULL, true, reason);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "update lane connInfo failed, laneReqId=%{public}u, ret=%{public}d", laneReqId, ret);
        return;
    }
    SessionParam param;
    uint32_t firstTokenId = 0;
    ret = TransGetLaneReqItemParamByLaneReqId(laneReqId, &param, &firstTokenId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get lane req item failed. laneReqId=%{public}u, ret=%{public}d", laneReqId, ret);
        (void)TransDelLaneReqFromPendingList(laneReqId, true);
        return;
    }
    LaneTransType transType = TransGetLaneTransTypeBySession(&param);
    LaneRequestOption requestOption = {
        .requestInfo.trans.transType = transType,
    };
    LaneConnInfo connInfo = {
        .type = LANE_LINK_TYPE_BUTT, // failed case unknow type
    };
    ReportTransEventExtra(&param, &connInfo, &laneReqId, requestOption, SOFTBUS_ERR);
    AppInfo *appInfo = TransCommonGetAppInfo(&param);
    TRANS_CHECK_AND_RETURN_LOGW(!(appInfo == NULL), TRANS_SVC, "GetAppInfo is null.");
    appInfo->firstTokenId = firstTokenId;
    CallBackOpenChannelFailed(&param, appInfo, reason);
    (void)TransDelLaneReqFromPendingList(laneReqId, true);
    if (appInfo->fastTransData != NULL) {
        SoftBusFree((void*)appInfo->fastTransData);
    }
    SoftBusFree(appInfo);
    return;
}

static void TransOnLaneStateChange(uint32_t laneReqId, LaneState state)
{
    /* current no treatment */
    (void)laneReqId;
    (void)state;
    return;
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

static bool PeerDeviceIsDoubleFrame(const char *peerNetworkId, const char *sessionName)
{
    uint32_t authCapacity;
    if (LnnGetDLAuthCapacity(peerNetworkId, &authCapacity) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "failed to get auth capacity");
        return false;
    }
    TRANS_LOGI(TRANS_SVC, "authCapacity=%{public}u", authCapacity);
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

static void ModuleLaneAdapter(LanePreferredLinkList *preferred, bool *isQosLane)
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
    *isQosLane = false;
}

static void TransGetQosInfo(const SessionParam *param, QosInfo *qosInfo, bool *isQosLane)
{
    *isQosLane = param->isQosLane;
    if (!(*isQosLane)) {
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

static int32_t GetRequestOptionBySessionParam(const SessionParam *param, LaneRequestOption *requestOption,
    bool *isQosLane)
{
    requestOption->type = LANE_TYPE_TRANS;
    if (memcpy_s(requestOption->requestInfo.trans.networkId, NETWORK_ID_BUF_LEN,
        param->peerDeviceId, NETWORK_ID_BUF_LEN) != EOK) {
        TRANS_LOGE(TRANS_SVC, "memcpy networkId failed.");
        return SOFTBUS_MEM_ERR;
    }

    LaneTransType transType = TransGetLaneTransTypeBySession(param);
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
    TransGetQosInfo(param, &requestOption->requestInfo.trans.qosRequire, isQosLane);

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
    if (PeerDeviceIsDoubleFrame(param->peerDeviceId, param->sessionName) || IsMeshSync(param->sessionName)) {
        ModuleLaneAdapter(&(requestOption->requestInfo.trans.expectedLink), isQosLane);
        TRANS_LOGI(TRANS_SVC, "adapt double frame device and mesh, isQosLane=%{public}d", *isQosLane);
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
    int64_t usTime = now.sec * CONVERSION_BASE * CONVERSION_BASE + now.usec + timeMillis * CONVERSION_BASE;
    SoftBusSysTime tv;
    tv.sec = usTime / CONVERSION_BASE / CONVERSION_BASE;
    tv.usec = usTime % (CONVERSION_BASE * CONVERSION_BASE);
    TRANS_LOGI(TRANS_SVC, "start wait cond endSecond=%{public}" PRId64, tv.sec);
    return SoftBusCondWait(cond, mutex, &tv);
}

static int32_t TransWaitingRequestCallback(uint32_t laneReqId)
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
        if (item->laneReqId == laneReqId) {
            isFound = true;
            break;
        }
    }
    if (!isFound) {
        (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
        TRANS_LOGI(TRANS_SVC, "not found laneReqId in pending. laneReqId=%{public}u", laneReqId);
        return SOFTBUS_ERR;
    }
    if (item->isFinished == false) {
        int32_t rc = TransSoftBusCondWait(&item->cond, &g_reqLanePendingList->lock, 0);
        if (rc != SOFTBUS_OK) {
            (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
            TRANS_LOGI(TRANS_SVC, "wait cond failed laneReqId=%{public}u", laneReqId);
            return rc;
        }
    }
    (void)SoftBusMutexUnlock(&(g_reqLanePendingList->lock));
    TRANS_LOGI(TRANS_SVC, "receive lane cond laneReqId=%{public}u", laneReqId);
    return SOFTBUS_OK;
}

static int32_t TransAddLaneReqToPendingAndWaiting(bool isQosLane, uint32_t laneReqId,
    const LaneRequestOption *requestOption)
{
    if (requestOption == NULL) {
        TRANS_LOGE(TRANS_SVC, "param error.");
        return SOFTBUS_ERR;
    }

    int32_t ret = TransAddLaneReqFromPendingList(laneReqId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "add laneReqId to pending failed. laneReqId=%{public}u", laneReqId);
        return SOFTBUS_ERR;
    }

    ILaneListener listener;
    listener.OnLaneRequestSuccess = TransOnLaneRequestSuccess;
    listener.OnLaneRequestFail = TransOnLaneRequestFail;
    listener.OnLaneStateChange = TransOnLaneStateChange;
    if (isQosLane) {
        // lane by qos
        ret = GetLaneManager()->lnnRequestLane(laneReqId, requestOption, &listener);
    } else {
        ret = LnnRequestLane(laneReqId, requestOption, &listener);
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "trans request lane failed.");
        (void)TransDelLaneReqFromPendingList(laneReqId, false);
        return SOFTBUS_ERR;
    }
    TRANS_LOGI(TRANS_SVC, "add laneReqId to pending and start waiting. laneReqId=%{public}u", laneReqId);
    if (TransWaitingRequestCallback(laneReqId) != SOFTBUS_OK) {
        (void)TransDelLaneReqFromPendingList(laneReqId, false);
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

int32_t TransGetLaneInfoByOption(bool isQosLane, const LaneRequestOption *requestOption, LaneConnInfo *connInfo,
    uint32_t *laneReqId)
{
    if ((requestOption == NULL) || (connInfo == NULL) || (laneReqId == NULL)) {
        TRANS_LOGE(TRANS_SVC, "get lane info by option param error.");
        return SOFTBUS_ERR;
    }

    *laneReqId = GetLaneManager()->applyLaneReqId(LANE_TYPE_TRANS);
    if (TransAddLaneReqToPendingAndWaiting(isQosLane, *laneReqId, requestOption) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "trans add lane to pending list failed.");
        return SOFTBUS_ERR;
    }
    bool bSuccess = false;
    int32_t errCode = SOFTBUS_ERR;
    if (TransGetLaneReqItemByLaneReqId(*laneReqId, &bSuccess, connInfo, &errCode) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get lane req item failed. laneReqId=%{public}u.", *laneReqId);
        (void)TransDelLaneReqFromPendingList(*laneReqId, false);
        return SOFTBUS_ERR;
    }

    int32_t ret = SOFTBUS_OK;
    if (!bSuccess) {
        ret = errCode;
        TRANS_LOGE(TRANS_SVC, "request lane conninfo failed. laneReqId=%{public}u.", *laneReqId);
    }
    TRANS_LOGI(TRANS_SVC, "request lane conninfo success. laneReqId=%{public}u.", *laneReqId);
    (void)TransDelLaneReqFromPendingList(*laneReqId, false);
    return ret;
}

int32_t TransGetLaneInfo(const SessionParam *param, LaneConnInfo *connInfo, uint32_t *laneReqId)
{
    if ((param == NULL) || (connInfo == NULL) || (laneReqId == NULL)) {
        TRANS_LOGE(TRANS_SVC, "get lane info param error.");
        return SOFTBUS_INVALID_PARAM;
    }

    LaneRequestOption requestOption;
    (void)memset_s(&requestOption, sizeof(LaneRequestOption), 0, sizeof(LaneRequestOption));
    bool isQosLane = false;
    if (GetRequestOptionBySessionParam(param, &requestOption, &isQosLane) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }

    int32_t ret = TransGetLaneInfoByOption(isQosLane, &requestOption, connInfo, laneReqId);
    ReportTransEventExtra(param, connInfo, laneReqId, requestOption, ret);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get lane info by option failed.");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t TransAsyncGetLaneInfo(const SessionParam *param, uint32_t *laneReqId, uint32_t firstTokenId)
{
    if ((param == NULL) || (laneReqId == NULL)) {
        TRANS_LOGE(TRANS_SVC, "get lane info param error.");
        return SOFTBUS_INVALID_PARAM;
    }
    LaneRequestOption requestOption;
    (void)memset_s(&requestOption, sizeof(LaneRequestOption), 0, sizeof(LaneRequestOption));
    bool isQosLane = false;
    int32_t ret = GetRequestOptionBySessionParam(param, &requestOption, &isQosLane);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "get request option failed. laneReqId=%{public}u, ret=%{public}d", *laneReqId, ret);
        return ret;
    }
    *laneReqId = GetLaneManager()->applyLaneReqId(LANE_TYPE_TRANS);
    ret = TransAddAsyncLaneReqFromPendingList(*laneReqId, param, firstTokenId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "add laneReqId to pending failed. laneReqId=%{public}u, ret=%{public}d", *laneReqId, ret);
        return ret;
    }
    ILaneListener listener;
    listener.OnLaneRequestSuccess = TransOnAsyncLaneRequestSuccess;
    listener.OnLaneRequestFail = TransOnAsyncLaneRequestFail;
    listener.OnLaneStateChange = TransOnLaneStateChange;
    if (isQosLane) {
        // lane by qos
        ret = GetLaneManager()->lnnRequestLane(*laneReqId, &requestOption, &listener);
    } else {
        ret = LnnRequestLane(*laneReqId, &requestOption, &listener);
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "trans request lane failed.");
        (void)TransDelLaneReqFromPendingList(*laneReqId, true);
        return ret;
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