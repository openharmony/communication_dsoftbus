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

#include "anonymizer.h"
#include "bus_center_manager.h"
#include "lnn_time_sync_impl.h"
#include "lnn_log.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

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
    int32_t pid;
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
    int32_t pid;
    char targetNetworkId[NETWORK_ID_BUF_LEN];
    TimeSyncAccuracy accuracy;
    TimeSyncPeriod period;
} StartTimeSyncReqMsgPara;

typedef struct {
    int32_t pid;
    char pkgName[PKG_NAME_SIZE_MAX];
    char targetNetworkId[NETWORK_ID_BUF_LEN];
} StopTimeSyncReqMsgPara;

typedef struct {
    char networkId[NETWORK_ID_BUF_LEN];
    double offset;
    int32_t retCode;
} TimeSyncCompleteMsgPara;

static SoftBusMutex g_startReqListLock;

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
    TimeSyncPeriod period, int32_t pid)
{
    StartTimeSyncReq *req = (StartTimeSyncReq *)SoftBusMalloc(sizeof(StartTimeSyncReq));

    if (req == NULL) {
        LNN_LOGE(LNN_CLOCK, "malloc start time sync request fail=%{public}s", pkgName);
        return NULL;
    }
    if (strncpy_s(req->pkgName, PKG_NAME_SIZE_MAX, pkgName, strlen(pkgName)) != EOK) {
        LNN_LOGE(LNN_CLOCK, "copy pkgName fail=%{public}s", pkgName);
        SoftBusFree(req);
        return NULL;
    }
    req->accuracy = accuracy;
    req->pid = pid;
    req->period = period;
    ListInit(&req->node);
    return req;
}

static TimeSyncReqInfo *CreateTimeSyncReqInfo(const StartTimeSyncReqMsgPara *para)
{
    TimeSyncReqInfo *info = (TimeSyncReqInfo *)SoftBusMalloc(sizeof(TimeSyncReqInfo));

    if (info == NULL) {
        LNN_LOGE(LNN_CLOCK, "malloc time sync request info fail");
        return NULL;
    }
    if (strncpy_s(info->targetNetworkId, NETWORK_ID_BUF_LEN, para->targetNetworkId,
        strlen(para->targetNetworkId)) != EOK) {
        LNN_LOGE(LNN_CLOCK, "copy time sync networkId fail");
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

    if (SoftBusMutexLock(&g_startReqListLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock list err");
        return SOFTBUS_LOCK_ERR;
    }
    char *anonyPkgName = NULL;
    Anonymize(startReq->pkgName, &anonyPkgName);
    LIST_FOR_EACH_ENTRY(item, &info->startReqList, StartTimeSyncReq, node) {
        if (strcmp(startReq->pkgName, item->pkgName) != 0 || item->pid != startReq->pid) {
            continue;
        }
        if (item->accuracy < startReq->accuracy || item->period > startReq->period) {
            LNN_LOGI(LNN_CLOCK,
                "update exist request. pkgName=%{public}s, "
                "accuracy:%{public}d->%{public}d, period:%{public}d->%{public}d",
                AnonymizeWrapper(anonyPkgName), item->accuracy, startReq->accuracy, item->period, startReq->period);
            item->accuracy = startReq->accuracy;
            item->period = startReq->period;
        }
        AnonymizeFree(anonyPkgName);
        SoftBusMutexUnlock(&g_startReqListLock);
        return SOFTBUS_OK;
    }
    LNN_LOGI(LNN_CLOCK, "add start time sync request. pkgName=%{public}s, accuracy=%{public}d, period=%{public}d",
        AnonymizeWrapper(anonyPkgName), startReq->accuracy, startReq->period);
    AnonymizeFree(anonyPkgName);
    item = CreateStartTimeSyncReq(startReq->pkgName, startReq->accuracy, startReq->period, startReq->pid);
    if (item == NULL) {
        LNN_LOGE(LNN_CLOCK, "create start time sync request fail");
        SoftBusMutexUnlock(&g_startReqListLock);
        return SOFTBUS_MEM_ERR;
    }
    ListAdd(&info->startReqList, &item->node);
    SoftBusMutexUnlock(&g_startReqListLock);
    return SOFTBUS_OK;
}

static void RemoveStartTimeSyncReq(const TimeSyncReqInfo *info, const char *pkgName, int32_t pid)
{
    StartTimeSyncReq *item = NULL;
    StartTimeSyncReq *next = NULL;

    if (SoftBusMutexLock(&g_startReqListLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock list err");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &info->startReqList, StartTimeSyncReq, node) {
        if (strcmp(pkgName, item->pkgName) != 0 || item->pid != pid) {
            continue;
        }
        ListDelete(&item->node);
        SoftBusFree(item);
        char *anonyPkgName = NULL;
        Anonymize(pkgName, &anonyPkgName);
        LNN_LOGI(LNN_CLOCK, "remove start time sync req. pkgName=%{public}s", AnonymizeWrapper(anonyPkgName));
        AnonymizeFree(anonyPkgName);
        break;
    }
    SoftBusMutexUnlock(&g_startReqListLock);
}

static bool TryUpdateTimeSyncReqInfo(TimeSyncReqInfo *info, TimeSyncAccuracy accuracy, TimeSyncPeriod period)
{
    if (info->curAccuracy < accuracy || info->curPeriod > period) {
        LNN_LOGI(LNN_CLOCK, "update exist request. accuracy:%{public}d->%{public}d, period:%{public}d->%{public}d",
            info->curAccuracy, accuracy, info->curPeriod, period);
        info->curAccuracy = accuracy;
        info->curPeriod = period;
        return true;
    } else {
        LNN_LOGI(LNN_CLOCK, "exist request already can satify");
    }
    return false;
}

static int32_t ProcessStartTimeSyncRequest(const StartTimeSyncReqMsgPara *para)
{
    TimeSyncReqInfo *existInfo = NULL;
    bool isCreateTimeSyncReq = false;
    bool isUpdateTimeSyncReq = false;
    int32_t rc = SOFTBUS_NOT_FIND;

    if (para == NULL) {
        LNN_LOGE(LNN_CLOCK, "start time sync request msg para null");
        return SOFTBUS_INVALID_PARAM;
    }
    do {
        existInfo = FindTimeSyncReqInfo(para->targetNetworkId);
        if (existInfo == NULL) {
            LNN_LOGI(LNN_CLOCK, "start new time sync request");
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
                LNN_LOGE(LNN_CLOCK, "start time sync fail");
                RemoveStartTimeSyncReq(existInfo, para->pkgName, para->pid);
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

    if (SoftBusMutexLock(&g_startReqListLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LANE, "lock list err");
        return;
    }
    LIST_FOR_EACH_ENTRY(item, &info->startReqList, StartTimeSyncReq, node) {
        ++count;
        if (item->accuracy > curAccuracy) {
            curAccuracy = item->accuracy;
        }
        if (item->period < curPeriod) {
            curPeriod = item->period;
        }
    }
    SoftBusMutexUnlock(&g_startReqListLock);
    if (count > 0) {
        if (curAccuracy > info->curAccuracy || curPeriod < info->curPeriod) {
            LNN_LOGI(LNN_CLOCK,
                "update time sync request. accuracy:%{public}d->%{public}d, period:%{public}d->%{public}d",
                info->curAccuracy, curAccuracy, info->curPeriod, curPeriod);
            info->curAccuracy = curAccuracy;
            info->curPeriod = curPeriod;
            LNN_LOGI(LNN_CLOCK, "update time sync request. rc=%{public}d",
                LnnStartTimeSyncImpl(info->targetNetworkId, curAccuracy, curPeriod, &g_timeSyncImplCb));
        }
    } else {
        LNN_LOGI(LNN_CLOCK, "stop time sync request. rc=%{public}d",
            LnnStopTimeSyncImpl(info->targetNetworkId));
        ListDelete(&info->node);
        SoftBusFree(info);
    }
}

static int32_t ProcessStopTimeSyncRequest(const StopTimeSyncReqMsgPara *para)
{
    TimeSyncReqInfo *info = NULL;

    if (para == NULL) {
        LNN_LOGE(LNN_CLOCK, "stop time sync request msg para null");
        return SOFTBUS_INVALID_PARAM;
    }
    info = FindTimeSyncReqInfo(para->targetNetworkId);
    if (info == NULL) {
        char *anonyPkgName = NULL;
        Anonymize(para->pkgName, &anonyPkgName);
        LNN_LOGI(LNN_CLOCK, "no specific networkId. pkgName=%{public}s", AnonymizeWrapper(anonyPkgName));
        AnonymizeFree(anonyPkgName);
        SoftBusFree((void *)para);
        return SOFTBUS_NOT_FIND;
    }
    RemoveStartTimeSyncReq(info, para->pkgName, para->pid);
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
        LNN_LOGE(LNN_CLOCK, "copy networkId fail");
        return;
    }
    LNN_LOGI(LNN_CLOCK,
        "notify time sync result. millisecond=%{public}d, microsecond=%{public}d, accuracy=%{public}d, flag=%{public}d",
        resultInfo.result.millisecond, resultInfo.result.microsecond, resultInfo.result.accuracy, resultInfo.flag);
    LIST_FOR_EACH_ENTRY(item, &info->startReqList, StartTimeSyncReq, node) {
        char *anonyPkgName = NULL;
        Anonymize(item->pkgName, &anonyPkgName);
        LNN_LOGI(LNN_CLOCK, "notify time sync result. pkgName=%{public}s", AnonymizeWrapper(anonyPkgName));
        AnonymizeFree(anonyPkgName);
        LnnNotifyTimeSyncResult(item->pkgName, item->pid, &resultInfo, retCode);
    }
}


static void RemoveAllStartTimeSyncReq(TimeSyncReqInfo *info)
{
    StartTimeSyncReq *startTimeSyncItem = NULL;
    StartTimeSyncReq *startTimeSyncNextItem = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(startTimeSyncItem, startTimeSyncNextItem, &info->startReqList, StartTimeSyncReq, node) {
        RemoveStartTimeSyncReq(info, startTimeSyncItem->pkgName, startTimeSyncItem->pid);
    }
    (void)LnnStopTimeSyncImpl(info->targetNetworkId);
    ListDelete(&info->node);
    SoftBusFree(info);
}

static int32_t ProcessTimeSyncComplete(const TimeSyncCompleteMsgPara *para)
{
    TimeSyncReqInfo *info = NULL;

    if (para == NULL) {
        LNN_LOGE(LNN_CLOCK, "time sync complete msg para null");
        return SOFTBUS_INVALID_PARAM;
    }
    info = FindTimeSyncReqInfo(para->networkId);
    if (info == NULL) {
        LNN_LOGE(LNN_CLOCK, "no specific networkId");
        SoftBusFree((void *)para);
        return SOFTBUS_NOT_FIND;
    }
    LNN_LOGI(LNN_CLOCK, "time sync complete result. offset=%{public}.6lf, retCode=%{public}d",
        para->offset, para->retCode);
    NotifyTimeSyncResult(info, para->offset, para->retCode);
    if (para->retCode == SOFTBUS_NETWORK_TIME_SYNC_HANDSHAKE_ERR || para->retCode == SOFTBUS_INVALID_PARAM) {
        LNN_LOGE(LNN_CLOCK, "time sync fail, stop it internal. retCode=%{public}d", para->retCode);
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
        LNN_LOGE(LNN_CLOCK, "time sync msg is null");
        return;
    }
    LNN_LOGI(LNN_CLOCK, "process time sync msg=%{public}d", msg->what);
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
        LNN_LOGE(LNN_CLOCK, "malloc time sync message failed");
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
        LNN_LOGE(LNN_CLOCK, "create time sync message failed");
        return SOFTBUS_MALLOC_ERR;
    }
    g_timeSyncCtrl.looper->PostMessage(g_timeSyncCtrl.looper, msg);
    return SOFTBUS_OK;
}

static void OnTimeSyncImplComplete(const char *networkId, double offset, int32_t retCode)
{
    TimeSyncCompleteMsgPara *para = NULL;

    if (networkId == NULL) {
        LNN_LOGE(LNN_CLOCK, "time sync complete para invalid");
        return;
    }
    para = (TimeSyncCompleteMsgPara *)SoftBusMalloc(sizeof(TimeSyncCompleteMsgPara));
    if (para == NULL) {
        LNN_LOGE(LNN_CLOCK, "malloc time sync complete msg para fail");
        return;
    }
    if (strncpy_s(para->networkId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK) {
        LNN_LOGE(LNN_CLOCK, "copy time sync complete msg info fail");
        SoftBusFree(para);
        return;
    }
    para->offset = offset;
    para->retCode = retCode;
    if (PostMessageToHandler(MSG_TYPE_TIME_SYNC_COMPLETE, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_CLOCK, "post time sync complete msg fail");
        SoftBusFree(para);
    }
}

static bool CheckTimeSyncReqInfo(const StartTimeSyncReqMsgPara *info)
{
    char uuid[UUID_BUF_LEN] = {0};

    if (LnnGetRemoteStrInfo(info->targetNetworkId, STRING_KEY_UUID, uuid, UUID_BUF_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_CLOCK, "get uuid fail");
        return false;
    }
    return true;
}

int32_t LnnInitTimeSync(void)
{
    ListInit(&g_timeSyncCtrl.reqList);
    g_timeSyncCtrl.looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (g_timeSyncCtrl.looper == NULL) {
        LNN_LOGE(LNN_INIT, "time sync get default looper fail");
        return SOFTBUS_LOOPER_ERR;
    }
    g_timeSyncCtrl.handler.name = (char *)"TimeSync";
    g_timeSyncCtrl.handler.looper = g_timeSyncCtrl.looper;
    g_timeSyncCtrl.handler.HandleMessage = TimeSyncMessageHandler;
    if (SoftBusMutexInit(&g_startReqListLock, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "mutex init fail");
        return SOFTBUS_NO_INIT;
    }
    LNN_LOGI(LNN_INIT, "init time sync success");
    return LnnTimeSyncImplInit();
}

void LnnDeinitTimeSync(void)
{
    if (g_timeSyncCtrl.looper == NULL) {
        LNN_LOGE(LNN_INIT, "time sync not init");
        return;
    }
    if (PostMessageToHandler(MSG_TYPE_REMOVE_ALL, NULL) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "post remove all time sync msg fail");
    }
    (void)SoftBusMutexDestroy(&g_startReqListLock);
    LnnTimeSyncImplDeinit();
}

int32_t LnnStartTimeSync(const char *pkgName, int32_t callingPid, const char *targetNetworkId,
    TimeSyncAccuracy accuracy, TimeSyncPeriod period)
{
    StartTimeSyncReqMsgPara *para = NULL;

    if (pkgName == NULL || targetNetworkId == NULL) {
        LNN_LOGE(LNN_CLOCK, "start time sync para invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_timeSyncCtrl.looper == NULL) {
        LNN_LOGE(LNN_CLOCK, "time sync not init");
        return SOFTBUS_NO_INIT;
    }
    para = (StartTimeSyncReqMsgPara *)SoftBusMalloc(sizeof(StartTimeSyncReqMsgPara));
    if (para == NULL) {
        LNN_LOGE(LNN_CLOCK, "malloc stop time sync request msg para fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strncpy_s(para->pkgName, PKG_NAME_SIZE_MAX, pkgName, strlen(pkgName)) != EOK ||
        strncpy_s(para->targetNetworkId, NETWORK_ID_BUF_LEN, targetNetworkId, strlen(targetNetworkId)) != EOK) {
        LNN_LOGE(LNN_CLOCK, "copy time sync request info fail");
        SoftBusFree(para);
        return SOFTBUS_STRCPY_ERR;
    }
    para->accuracy = accuracy;
    para->period = period;
    para->pid = callingPid;
    if (!CheckTimeSyncReqInfo(para)) {
        LNN_LOGE(LNN_CLOCK, "check time sync request info fail");
        SoftBusFree(para);
        return SOFTBUS_INVALID_PARAM;
    }
    if (PostMessageToHandler(MSG_TYPE_START_TIME_SYNC, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_CLOCK, "post start time sync msg fail");
        SoftBusFree(para);
        return SOFTBUS_NETWORK_LOOPER_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnStopTimeSync(const char *pkgName, const char *targetNetworkId, int32_t callingPid)
{
    StopTimeSyncReqMsgPara *para = NULL;

    if (pkgName == NULL || targetNetworkId == NULL) {
        LNN_LOGE(LNN_CLOCK, "stop time sync para invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_timeSyncCtrl.looper == NULL) {
        LNN_LOGE(LNN_CLOCK, "time sync not init");
        return SOFTBUS_NO_INIT;
    }
    para = (StopTimeSyncReqMsgPara *)SoftBusMalloc(sizeof(StopTimeSyncReqMsgPara));
    if (para == NULL) {
        LNN_LOGE(LNN_CLOCK, "malloc stop time sync request msg para fail");
        return SOFTBUS_MALLOC_ERR;
    }
    para->pid = callingPid;
    if (strncpy_s(para->pkgName, PKG_NAME_SIZE_MAX, pkgName, strlen(pkgName)) != EOK ||
        strncpy_s(para->targetNetworkId, NETWORK_ID_BUF_LEN, targetNetworkId, strlen(targetNetworkId)) != EOK) {
        LNN_LOGE(LNN_CLOCK, "copy time sync request info fail");
        SoftBusFree(para);
        return SOFTBUS_STRCPY_ERR;
    }
    if (PostMessageToHandler(MSG_TYPE_STOP_TIME_SYNC, para) != SOFTBUS_OK) {
        LNN_LOGE(LNN_CLOCK, "post stop time sync msg fail");
        SoftBusFree(para);
        return SOFTBUS_NETWORK_LOOPER_ERR;
    }
    return SOFTBUS_OK;
}