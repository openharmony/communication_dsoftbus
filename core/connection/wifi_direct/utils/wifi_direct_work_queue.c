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

#include "wifi_direct_work_queue.h"

#include "conn_log.h"
#include "message_handler.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"

struct WifiDirectWork {
    WorkFunction work;
    void *data;
};

static void DeleteMessage(SoftBusMessage *msg)
{
    SoftBusFree(msg->obj);
    SoftBusFree(msg);
}

static SoftBusMessage* NewMessage(struct WifiDirectWork *work)
{
    SoftBusMessage *msg = SoftBusCalloc(sizeof(*msg));
    if (msg == NULL) {
        return msg;
    }

    msg->handler = &GetWifiDirectWorkQueue()->handler;
    msg->obj = work;
    msg->FreeMessage = DeleteMessage;
    return msg;
}

static void ScheduleWork(struct WifiDirectWork *work)
{
    struct WifiDirectWorkQueue *self = GetWifiDirectWorkQueue();
    SoftBusMessage *msg = NewMessage(work);
    if (msg != NULL) {
        SoftBusLooper *looper = self->handler.looper;
        looper->PostMessage(looper, msg);
    }
}

static void ScheduleDelayWork(struct WifiDirectWork *work, int64_t timeMs)
{
    struct WifiDirectWorkQueue *self = GetWifiDirectWorkQueue();
    SoftBusMessage *msg = NewMessage(work);
    if (msg != NULL) {
        SoftBusLooper *looper = self->handler.looper;
        looper->PostMessageDelay(looper, msg, timeMs);
    }
}

static int CompareMessage(const SoftBusMessage *msg, void *data)
{
    if (msg->obj == data) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

static void RemoveWork(struct WifiDirectWork *work)
{
    struct WifiDirectWorkQueue *self = GetWifiDirectWorkQueue();
    SoftBusHandler *handler = &self->handler;
    handler->looper->RemoveMessageCustom(handler->looper, handler, CompareMessage, work);
}

static void MessageHandler(SoftBusMessage *msg)
{
    struct WifiDirectWork *work = msg->obj;
    work->work(work->data);
}

static struct WifiDirectWorkQueue g_queue = {
    .scheduleWork = ScheduleWork,
    .scheduleDelayWork = ScheduleDelayWork,
    .removeWork = RemoveWork,
    .handler.name = "WifiDirectWorkQueueHandler",
    .handler.HandleMessage = MessageHandler,
    .isInited = false,
};

struct WifiDirectWork* ObtainWifiDirectWork(WorkFunction function, void *data)
{
    struct WifiDirectWork *work = SoftBusCalloc(sizeof(*work));
    if (work == NULL) {
        return work;
    }

    work->work = function;
    work->data = data;
    return work;
}

struct WifiDirectWorkQueue* GetWifiDirectWorkQueue(void)
{
    return &g_queue;
}

int32_t CallMethodAsync(WorkFunction function, void *data, int64_t delayTimeMs)
{
    struct WifiDirectWorkQueue *queue = GetWifiDirectWorkQueue();
    CONN_CHECK_AND_RETURN_RET_LOGW(queue->isInited, SOFTBUS_ERR, CONN_WIFI_DIRECT, "queue is not inited");
    struct WifiDirectWork *work = ObtainWifiDirectWork(function, data);
    CONN_CHECK_AND_RETURN_RET_LOGW(work, SOFTBUS_MALLOC_ERR, CONN_WIFI_DIRECT, "alloc work failed");
    if (delayTimeMs <= 0) {
        queue->scheduleWork(work);
        return SOFTBUS_OK;
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "delayTimeMs=%{public}"  PRId64, delayTimeMs);
    queue->scheduleDelayWork(work, delayTimeMs);
    return SOFTBUS_OK;
}

int32_t WifiDirectWorkQueueInit(void)
{
    CONN_LOGI(CONN_INIT, "init enter");
    SoftBusLooper *looper = CreateNewLooper("WDWQLooper");
    if (looper == NULL) {
        CONN_LOGE(CONN_INIT, "create looper failed");
        return SOFTBUS_ERR;
    }

    g_queue.handler.looper = looper;
    g_queue.isInited = true;
    return SOFTBUS_OK;
}