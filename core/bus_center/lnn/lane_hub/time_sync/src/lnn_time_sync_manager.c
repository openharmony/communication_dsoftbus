/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "lnn_time_sync_manager.h"

#include <securec.h>
#include <string.h>

#include "bus_center_manager.h"
#include "lnn_time_sync_impl.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#define THOUSAND 1000

typedef enum {
    MSG_TYPE_START_TIME_SYNC = 0,
    MSG_TYPE_STOP_TIME_SYNC,
    MSG_TYPE_TIME_SYNC_COMPLETE,
    MSG_TYPE_REMOVE_ALL,
    MSG_TYPE_MAX,
} TimeSyncMessageType;

typedef struct {
    ListNode node;
    char pkgName[PKG_NAME_SIZE_MAX];
    TimeSyncAccuracy accuracy;
    TimeSyncPeriod period;
} StartTimeSyncReq;

typedef struct {
    ListNode node;
    char targetNetworkId[NETWORK_ID_BUF_LEN];
    // list of StartTimeSyncReq
    ListNode startReqList;
    TimeSyncAccuracy curAccuracy;
    TimeSyncPeriod curPeriod;
} TimeSyncReqInfo;

typedef struct {
    // list of TimeSyncRequestInfo
    ListNode reqList;
    SoftBusLooper *looper;
    SoftBusHandler handler;
} TimeSyncCtrl;

typedef struct {
    char pkgName[PKG_NAME_SIZE_MAX];
    char targetNetworkId[NETWORK_ID_BUF_LEN];
    TimeSyncAccuracy accuracy;
    TimeSyncPeriod period;
} StartTimeSyncReqMsgPara;

typedef struct {
    char pkgName[PKG_NAME_SIZE_MAX];
    char targetNetworkId[NETWORK_ID_BUF_LEN];
} StopTimeSyncReqMsgPara;

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    double offset;
    int32_t retCode;
} TimeSyncCompleteMsgPara;

static void OnTimeSyncImplComplete(const char *networkId, double offset, int32_t retCode);

static TimeSyncCtrl g_timeSyncCtrl;

static TimeSyncImplCallback g_timeSyncImplCb = {
    .onTimeSyncImplComplete = OnTimeSyncImplComplete,
};

static TimeSyncReqInfo *FindTimeSyncReqInfo(const char *networkId)
{
    TimeSyncReqInfo *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &g_timeSyncCtrl.reqList, TimeSyncReqInfo, node) {
        if (strcmp(networkId, item->targetNetworkId) == 0) {
            return item;
        }
    }
    return NULL;
}

static StartTimeSyncReq *CreateStartTimeSyncReq(const char *pkgName, TimeSyncAccuracy accuracy,
    TimeSyncPeriod period)
{
    StartTimeSyncReq *req = SoftBusMalloc(sizeof(StartTimeSyncReq));

    if (req == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc start time sync request fail: %s", pkgName);
        return NULL;
    }
    if (strncpy_s(req->pkgName, PKG_NAME_SIZE_MAX, pkgName, strlen(pkgName)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy pkgName fail: %s", pkgName);
        SoftBusFree(req);
        return NULL;
    }
    req->accuracy = accuracy;
    req->period = period;
    ListInit(&req->node);
    return req;
}

static TimeSyncReqInfo *CreateTimeSyncReqInfo(const StartTimeSyncReqMsgPara *para)
{
    TimeSyncReqInfo *info = SoftBusMalloc(sizeof(TimeSyncReqInfo));

    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc time sync request info fail");
        return NULL;
    }
    if (strncpy_s(info->targetNetworkId, NETWORK_ID_BUF_LEN, para->targetNetworkId,
        strlen(para->targetNetworkId)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy time sync networkId fail");
        SoftBusFree(info);
        return NULL;
    }
    info->curAccuracy = para->accuracy;
    info->curPeriod = para->period;
    ListInit(&info->node);
    ListInit(&info->startReqList);
    return info;
}

static int32_t TryUpdateStartTimeSyncReq(TimeSyncReqInfo *info, const StartTimeSyncReqMsgPara *startReq)
{
    StartTimeSyncReq *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &info->startReqList, StartTimeSyncReq, node) {
        if (strcmp(startReq->pkgName, item->pkgName) != 0) {
            continue;
        }
        if (item->accuracy < startReq->accuracy || item->period > startReq->period) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "update exist request(%d-->%d, %d-->%d) for %s",
                item->accuracy, startReq->accuracy, item->period, startReq->period, startReq->pkgName);
            item->accuracy = startReq->accuracy;
            item->period = startReq->period;
        }
        return SOFTBUS_OK;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "add start time sync request(%d, %d) for %s",
        startReq->accuracy, startReq->period, startReq->pkgName);
    item = CreateStartTimeSyncReq(startReq->pkgName, startReq->accuracy, startReq->period);
    if (item == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create start time sync request fail");
        return SOFTBUS_ERR;
    }
    ListAdd(&info->startReqList, &item->node);
    return SOFTBUS_OK;
}

static void RemoveStartTimeSyncReq(const TimeSyncReqInfo *info, const char *pkgName)
{
    StartTimeSyncReq *item = NULL;

    LIST_FOR_EACH_ENTRY(item, &info->startReqList, StartTimeSyncReq, node) {
        if (strcmp(pkgName, item->pkgName) != 0) {
            continue;
        }
        ListDelete(&item->node);
        SoftBusFree(item);
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "remove start time sync req for %s", pkgName);
        break;
    }
}

static bool TryUpdateTimeSyncReqInfo(TimeSyncReqInfo *info, TimeSyncAccuracy accuracy, TimeSyncPeriod period)
{
    if (info->curAccuracy < accuracy || info->curPeriod > period) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "update exist request(%d-->%d, %d-->%d)",
            info->curAccuracy, accuracy, info->curPeriod, period);
        info->curAccuracy = accuracy;
        info->curPeriod = period;
        return true;
    } else {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "exist request already can satify");
    }
    return false;
}

static int32_t ProcessStartTimeSyncRequest(const StartTimeSyncReqMsgPara *para)
{
    TimeSyncReqInfo *existInfo = NULL;
    bool isCreateTimeSyncReq = false;
    bool isUpdateTimeSyncReq = false;
    int32_t rc = SOFTBUS_ERR;

    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "start time sync request msg para null");
        return SOFTBUS_INVALID_PARAM;
    }
    do {
        existInfo = FindTimeSyncReqInfo(para->targetNetworkId);
        if (existInfo == NULL) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "start new time sync request");
            existInfo = CreateTimeSyncReqInfo(para);
            if (existInfo == NULL) {
                break;
            }
            isCreateTimeSyncReq = true;
        } else {
            isUpdateTimeSyncReq = TryUpdateTimeSyncReqInfo(existInfo, para->accuracy, para->period);
        }
        if (TryUpdateStartTimeSyncReq(existInfo, para) != SOFTBUS_OK) {
            break;
        }
        if (isCreateTimeSyncReq || isUpdateTimeSyncReq) {
            if (LnnStartTimeSyncImpl(existInfo->targetNetworkId, existInfo->curAccuracy,
                existInfo->curPeriod, &g_timeSyncImplCb) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "start time sync fail");
                RemoveStartTimeSyncReq(existInfo, para->pkgName);
                break;
            }
        }
        rc = SOFTBUS_OK;
    } while (false);
    if (rc != SOFTBUS_OK) {
        if (isCreateTimeSyncReq && existInfo != NULL) {
            SoftBusFree(existInfo);
        }
    } else {
        if (isCreateTimeSyncReq) {
            ListAdd(&g_timeSyncCtrl.reqList, &existInfo->node);
        }
    }
    SoftBusFree((void *)para);
    return rc;
}

static void TryUpdateTimeSyncReq(TimeSyncReqInfo *info)
{
    StartTimeSyncReq *item = NULL;
    TimeSyncAccuracy curAccuracy = LOW_ACCURACY;
    TimeSyncPeriod curPeriod = LONG_PERIOD;
    uint32_t count = 0;

    LIST_FOR_EACH_ENTRY(item, &info->startReqList, StartTimeSyncReq, node) {
        ++count;
        if (item->accuracy > curAccuracy) {
            curAccuracy = item->accuracy;
        }
        if (item->period < curPeriod) {
            curPeriod = item->period;
        }
    }
    if (count > 0) {
        if (curAccuracy > info->curAccuracy || curPeriod < info->curPeriod) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "update time sync request(%d-->%d, %d-->%d) for",
                info->curAccuracy, curAccuracy, info->curPeriod, curPeriod);
            info->curAccuracy = curAccuracy;
            info->curPeriod = curPeriod;
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "update time sync request rc=%d",
                LnnStartTimeSyncImpl(info->targetNetworkId, curAccuracy, curPeriod, &g_timeSyncImplCb));
        }
    } else {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "stop time sync request rc=%d",
            LnnStopTimeSyncImpl(info->targetNetworkId));
        ListDelete(&info->node);
        SoftBusFree(info);
    }
}

static int32_t ProcessStopTimeSyncRequest(const StopTimeSyncReqMsgPara *para)
{
    TimeSyncReqInfo *info = NULL;

    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "stop time sync request msg para null");
        return SOFTBUS_INVALID_PARAM;
    }
    info = FindTimeSyncReqInfo(para->targetNetworkId);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "no specific networkId for %s", para->pkgName);
        SoftBusFree((void *)para);
        return SOFTBUS_ERR;
    }
    RemoveStartTimeSyncReq(info, para->pkgName);
    TryUpdateTimeSyncReq(info);
    SoftBusFree((void *)para);
    return SOFTBUS_OK;
}

static void NotifyTimeSyncResult(const TimeSyncReqInfo *info, double offset, int32_t retCode)
{
    StartTimeSyncReq *item = NULL;
    TimeSyncResultInfo resultInfo;

    (void)memset_s(&resultInfo, sizeof(TimeSyncResultInfo), 0, sizeof(TimeSyncResultInfo));
    if (retCode == SOFTBUS_OK || retCode == SOFTBUS_NETWORK_TIME_SYNC_INTERFERENCE) {
        resultInfo.result.millisecond = (int32_t)offset;
        resultInfo.result.microsecond = ((int32_t)(offset * THOUSAND)) % THOUSAND;
        resultInfo.result.accuracy = info->curAccuracy;
        resultInfo.flag = NODE_SPECIFIC;
    } else {
        resultInfo.result.millisecond = -1;
        resultInfo.result.microsecond = -1;
        resultInfo.result.accuracy = UNAVAIL_ACCURACY;
    }
    if (strncpy_s(resultInfo.target.targetNetworkId, NETWORK_ID_BUF_LEN, info->targetNetworkId,
        strlen(info->targetNetworkId)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy networkId fail");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "notify time sync result(%d, %d, %d, %d)",
        resultInfo.result.millisecond, resultInfo.result.microsecond, resultInfo.result.accuracy, resultInfo.flag);
    LIST_FOR_EACH_ENTRY(item, &info->startReqList, StartTimeSyncReq, node) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "notify time sync result to %s", item->pkgName);
        LnnNotifyTimeSyncResult(item->pkgName, &resultInfo, retCode);
    }
}


static void RemoveAllStartTimeSyncReq(TimeSyncReqInfo *info)
{
    StartTimeSyncReq *startTimeSyncItem = NULL;
    StartTimeSyncReq *startTimeSyncNextItem = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(startTimeSyncItem, startTimeSyncNextItem, &info->startReqList, StartTimeSyncReq, node) {
        RemoveStartTimeSyncReq(info, startTimeSyncItem->pkgName);
    }
    (void)LnnStopTimeSyncImpl(info->targetNetworkId);
    ListDelete(&info->node);
    SoftBusFree(info);
}

static int32_t ProcessTimeSyncComplete(const TimeSyncCompleteMsgPara *para)
{
    TimeSyncReqInfo *info = NULL;

    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "time sync complete msg para null");
        return SOFTBUS_INVALID_PARAM;
    }
    info = FindTimeSyncReqInfo(para->networkId);
    if (info == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no specific networkId");
        SoftBusFree((void *)para);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "time sync complete result(offset=%.6lf, retCode=%d)",
        para->offset, para->retCode);
    NotifyTimeSyncResult(info, para->offset, para->retCode);
    if (para->retCode == SOFTBUS_NETWORK_TIME_SYNC_HANDSHAKE_ERR || para->retCode == SOFTBUS_ERR) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "time sync fail(%d), stop it internal", para->retCode);
        RemoveAllStartTimeSyncReq(info);
    }
    SoftBusFree((void *)para);
    return SOFTBUS_OK;
}

static void ProcessRemoveAll(void)
{
    TimeSyncReqInfo *timeSyncItem = NULL;
    TimeSyncReqInfo *timeSyncNextItem = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(timeSyncItem, timeSyncNextItem, &g_timeSyncCtrl.reqList, TimeSyncReqInfo, node) {
        RemoveAllStartTimeSyncReq(timeSyncItem);
    }
}

static void TimeSyncMessageHandler(SoftBusMessage *msg)
{
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "time sync msg is null");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "process time sync msg: %d", msg->what);
    switch (msg->what) {
        case MSG_TYPE_START_TIME_SYNC:
            ProcessStartTimeSyncRequest((const StartTimeSyncReqMsgPara *)msg->obj);
            break;
        case MSG_TYPE_STOP_TIME_SYNC:
            ProcessStopTimeSyncRequest((const StopTimeSyncReqMsgPara *)msg->obj);
            break;
        case MSG_TYPE_TIME_SYNC_COMPLETE:
            ProcessTimeSyncComplete((const TimeSyncCompleteMsgPara *)msg->obj);
            break;
        case MSG_TYPE_REMOVE_ALL:
            ProcessRemoveAll();
            break;
        default:
            break;
    }
}

static SoftBusMessage *CreateTimeSyncMessage(int32_t msgType, void *para)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc time sync message failed");
        return NULL;
    }
    msg->what = msgType;
    msg->obj = para;
    msg->handler = &g_timeSyncCtrl.handler;
    return msg;
}

static int32_t PostMessageToHandler(int32_t msgType, void *para)
{
    SoftBusMessage *msg = CreateTimeSyncMessage(msgType, para);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create time sync message failed");
        return SOFTBUS_ERR;
    }
    g_timeSyncCtrl.looper->PostMessage(g_timeSyncCtrl.looper, msg);
    return SOFTBUS_OK;
}

static void OnTimeSyncImplComplete(const char *networkId, double offset, int32_t retCode)
{
    TimeSyncCompleteMsgPara *para = NULL;

    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "time sync complete para invalid");
        return;
    }
    para = SoftBusMalloc(sizeof(TimeSyncCompleteMsgPara));
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc time sync complete msg para fail");
        return;
    }
    if (strncpy_s(para->networkId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy time sync complete msg info fail");
        SoftBusFree(para);
        return;
    }
    para->offset = offset;
    para->retCode = retCode;
    if (PostMessageToHandler(MSG_TYPE_TIME_SYNC_COMPLETE, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post time sync complete msg fail");
        SoftBusFree(para);
    }
}

static bool CheckTimeSyncReqInfo(const StartTimeSyncReqMsgPara *info)
{
    char uuid[UUID_BUF_LEN] = {0};

    if (LnnGetRemoteStrInfo(info->targetNetworkId, STRING_KEY_UUID, uuid, UUID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get uuid fail");
        return false;
    }
    return true;
}

int32_t LnnInitTimeSync(void)
{
    ListInit(&g_timeSyncCtrl.reqList);
    g_timeSyncCtrl.looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (g_timeSyncCtrl.looper == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "time sync get default looper fail");
        return SOFTBUS_ERR;
    }
    g_timeSyncCtrl.handler.name = "TimeSync";
    g_timeSyncCtrl.handler.looper = g_timeSyncCtrl.looper;
    g_timeSyncCtrl.handler.HandleMessage = TimeSyncMessageHandler;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "init time sync success");
    return LnnTimeSyncImplInit();
}

void LnnDeinitTimeSync(void)
{
    if (g_timeSyncCtrl.looper == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "time sync not init");
        return;
    }
    if (PostMessageToHandler(MSG_TYPE_REMOVE_ALL, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post remove all time sync msg fail");
    }
    LnnTimeSyncImplDeinit();
}

int32_t LnnStartTimeSync(const char *pkgName, const char *targetNetworkId,
    TimeSyncAccuracy accuracy, TimeSyncPeriod period)
{
    StartTimeSyncReqMsgPara *para = NULL;

    if (pkgName == NULL || targetNetworkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "start time sync para invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_timeSyncCtrl.looper == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "time sync not init");
        return SOFTBUS_NO_INIT;
    }
    para = SoftBusMalloc(sizeof(StartTimeSyncReqMsgPara));
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc stop time sync request msg para fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strncpy_s(para->pkgName, PKG_NAME_SIZE_MAX, pkgName, strlen(pkgName)) != EOK ||
        strncpy_s(para->targetNetworkId, NETWORK_ID_BUF_LEN, targetNetworkId, strlen(targetNetworkId)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy time sync request info fail");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    para->accuracy = accuracy;
    para->period = period;
    if (!CheckTimeSyncReqInfo(para)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "check time sync request info fail");
        SoftBusFree(para);
        return SOFTBUS_INVALID_PARAM;
    }
    if (PostMessageToHandler(MSG_TYPE_START_TIME_SYNC, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post start time sync msg fail");
        SoftBusFree(para);
        return SOFTBUS_NETWORK_LOOPER_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnStopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    StopTimeSyncReqMsgPara *para = NULL;

    if (pkgName == NULL || targetNetworkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "stop time sync para invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_timeSyncCtrl.looper == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "time sync not init");
        return SOFTBUS_NO_INIT;
    }
    para = SoftBusMalloc(sizeof(StopTimeSyncReqMsgPara));
    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc stop time sync request msg para fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strncpy_s(para->pkgName, PKG_NAME_SIZE_MAX, pkgName, strlen(pkgName)) != EOK ||
        strncpy_s(para->targetNetworkId, NETWORK_ID_BUF_LEN, targetNetworkId, strlen(targetNetworkId)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy time sync request info fail");
        SoftBusFree(para);
        return SOFTBUS_ERR;
    }
    if (PostMessageToHandler(MSG_TYPE_STOP_TIME_SYNC, para) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "post stop time sync msg fail");
        SoftBusFree(para);
        return SOFTBUS_NETWORK_LOOPER_ERR;
    }
    return SOFTBUS_OK;
}