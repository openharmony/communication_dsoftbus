/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "wifi_direct_timer_list.h"
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"
#include "wifi_direct_types.h"

#define LOG_LABEL "[WifiDirect] WifiDirectTimerList: "

struct WifiDirectTimerStruct {
    ListNode node;
    int32_t timerId;
    int64_t timeoutMs;
    enum WifiDirectTimerFlag flag;
    TimeoutHandler handler;
    struct WifiDirectWork *work;
    void *data;
};

static int32_t AllocTimerId(void)
{
    struct WifiDirectTimerList *self = GetWifiDirectTimerList();
    SoftBusMutexLock(&self->mutex);
    if (self->timerId < 0) {
        self->timerId = 0;
    }
    int32_t res = self->timerId++;
    SoftBusMutexUnlock(&self->mutex);
    return res;
}

static void WorkHandler(void *data)
{
    struct WifiDirectTimerList *self = GetWifiDirectTimerList();
    struct WifiDirectTimerStruct *timerStruct = data;
    CLOGI(LOG_LABEL "timerId=%d", timerStruct->timerId);
    timerStruct->handler(timerStruct->data);

    if (timerStruct->flag == TIMER_FLAG_ONE_SHOOT) {
        SoftBusMutexLock(&self->mutex);
        ListDelete(&timerStruct->node);
        SoftBusMutexUnlock(&self->mutex);
        SoftBusFree(timerStruct);
        return;
    }

    if (timerStruct->flag == TIMER_FLAG_REPEATED) {
        struct WifiDirectWorkQueue *queue = GetWifiDirectWorkQueue();
        struct WifiDirectWork *work = ObtainWifiDirectWork(WorkHandler, timerStruct);
        if (work == NULL) {
            CLOGE(LOG_LABEL "obtain new work failed");
            SoftBusMutexLock(&self->mutex);
            ListDelete(&timerStruct->node);
            SoftBusMutexUnlock(&self->mutex);
            SoftBusFree(timerStruct);
            return;
        }

        queue->scheduleDelayWork(work, timerStruct->timeoutMs);
    }
}

static int32_t StartTimer(TimeoutHandler handler, int64_t timeoutMs, enum WifiDirectTimerFlag flag, void *data)
{
    struct WifiDirectTimerStruct *timerStruct = (struct WifiDirectTimerStruct*)SoftBusCalloc(sizeof(*timerStruct));
    CONN_CHECK_AND_RETURN_RET_LOG(timerStruct, SOFTBUS_MALLOC_ERR, "malloc failed");

    ListInit(&timerStruct->node);
    timerStruct->timerId = AllocTimerId();
    timerStruct->handler = handler;
    timerStruct->timeoutMs = timeoutMs;
    timerStruct->flag = flag;
    timerStruct->data = data;
    CLOGI(LOG_LABEL "timerId=%d", timerStruct->timerId);

    struct WifiDirectWorkQueue *queue = GetWifiDirectWorkQueue();
    struct WifiDirectWork *work = ObtainWifiDirectWork(WorkHandler, timerStruct);
    if (work == NULL) {
        SoftBusFree(timerStruct);
        return SOFTBUS_MALLOC_ERR;
    }
    timerStruct->work = work;

    struct WifiDirectTimerList *self = GetWifiDirectTimerList();
    SoftBusMutexLock(&self->mutex);
    ListAdd(&GetWifiDirectTimerList()->timers, &timerStruct->node);
    SoftBusMutexUnlock(&self->mutex);

    queue->scheduleDelayWork(work, timeoutMs);
    return timerStruct->timerId;
}

static void* StopTimer(int32_t timeId)
{
    CLOGI(LOG_LABEL "timerId=%d", timeId);
    struct WifiDirectTimerList *self = GetWifiDirectTimerList();
    struct WifiDirectTimerStruct *timerStruct = NULL;
    SoftBusMutexLock(&self->mutex);
    LIST_FOR_EACH_ENTRY(timerStruct, &GetWifiDirectTimerList()->timers, struct WifiDirectTimerStruct, node) {
        if (timerStruct->timerId == timeId) {
            GetWifiDirectWorkQueue()->removeWork(timerStruct->work);
            ListDelete(&timerStruct->node);
            void *res = timerStruct->data;
            SoftBusFree(timerStruct);
            SoftBusMutexUnlock(&self->mutex);
            return res;
        }
    }
    CLOGI(LOG_LABEL "not find timer");
    SoftBusMutexUnlock(&self->mutex);
    return NULL;
}

struct WifiDirectTimerList g_timerList = {
    .startTimer = StartTimer,
    .stopTimer = StopTimer,
    .timerId = 0,
};

struct WifiDirectTimerList* GetWifiDirectTimerList(void)
{
    return &g_timerList;
}

int32_t WifiDirectTimerListInit(void)
{
    ListInit(&g_timerList.timers);
    SoftBusMutexAttr attr;
    int32_t ret = SoftBusMutexAttrInit(&attr);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "init mutex attr failed");
    attr.type = SOFTBUS_MUTEX_RECURSIVE;
    ret = SoftBusMutexInit(&g_timerList.mutex, &attr);
    CONN_CHECK_AND_RETURN_RET_LOG(ret == SOFTBUS_OK, SOFTBUS_ERR, LOG_LABEL "init mutex failed");
    return SOFTBUS_OK;
}