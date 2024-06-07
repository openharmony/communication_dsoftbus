/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

namespace OHOS::SoftBus {
static void MessageHandler(SoftBusMessage *msg)
{
    auto *work = static_cast<WifiDirectWorkQueue::Work *>(msg->obj);
    work->work(work->data);
}

static void DeleteMessage(SoftBusMessage *msg)
{
    SoftBusFree(msg->obj);
    SoftBusFree(msg);
}

static int CompareMessage(const SoftBusMessage *msg, void *data)
{
    if (msg->obj == data) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

WifiDirectWorkQueue::WifiDirectWorkQueue()
{
    SoftBusLooper *looper = CreateNewLooper("WDWQ_Lp");
    if (looper == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "create looper failed");
        return;
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "create looper success");
    handler_.looper = looper;
    handler_.HandleMessage = MessageHandler;
}

WifiDirectWorkQueue::~WifiDirectWorkQueue()
{
    if (handler_.looper != nullptr) {
        CONN_LOGI(CONN_WIFI_DIRECT, "destroy looper success");
        DestroyLooper(handler_.looper);
    }
}

void WifiDirectWorkQueue::ScheduleDelayWork(const Work *work, uint64_t timeMs)
{
    CONN_CHECK_AND_RETURN_LOGE(handler_.looper != nullptr, CONN_WIFI_DIRECT, "looper is null");
    auto *msg = static_cast<SoftBusMessage *>(SoftBusCalloc(sizeof(SoftBusMessage)));
    CONN_CHECK_AND_RETURN_LOGE(msg != nullptr, CONN_WIFI_DIRECT, "msg is null");

    msg->handler = &handler_;
    msg->obj = (void *)work;
    msg->FreeMessage = DeleteMessage;
    if (timeMs > 0) {
        handler_.looper->PostMessageDelay(handler_.looper, msg, timeMs);
    } else {
        handler_.looper->PostMessage(handler_.looper, msg);
    }
}

void WifiDirectWorkQueue::RemoveWork(const Work *work)
{
    CONN_CHECK_AND_RETURN_LOGE(handler_.looper != nullptr, CONN_WIFI_DIRECT, "looper is null");
    handler_.looper->RemoveMessageCustom(handler_.looper, &handler_, CompareMessage, (void *)work);
}
}
