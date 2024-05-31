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
#include "wifi_direct_timer.h"
#include "conn_log.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"

namespace OHOS::SoftBus {
WifiDirectTimer::WifiDirectTimer(const std::string &name)
    : name_(name)
{
}

WifiDirectTimer::~WifiDirectTimer()
{
}

void WifiDirectTimer::WorkHandler(void *data)
{
    std::lock_guard lock(timerIdMapLock_);
    auto *timer = static_cast<TimerDescriptor *>(data);
    CONN_LOGI(CONN_WIFI_DIRECT, "timerId=%{public}d", timer->timerId);
    timer->callback();
    timerIdMap_.erase(timer->timerId);
    SoftBusFree(timer);

    if (timerIdMap_.empty()) {
        CONN_LOGI(CONN_WIFI_DIRECT, "destroy work queue");
        workQueue_ = nullptr;
    }
}

int32_t WifiDirectTimer::Register(const TimerCallback &callback, int32_t timeout)
{
    std::lock_guard lock(timerIdMapLock_);
    auto *timer = static_cast<TimerDescriptor *>(SoftBusCalloc(sizeof(TimerDescriptor)));
    CONN_CHECK_AND_RETURN_RET_LOGE(timer != nullptr, TIMER_ID_INVALID, CONN_WIFI_DIRECT, "malloc timer failed");
    auto *work = static_cast<WifiDirectWorkQueue::Work *>(SoftBusCalloc(sizeof(WifiDirectWorkQueue::Work)));
    if (work == nullptr) {
        SoftBusFree(timer);
        CONN_LOGE(CONN_WIFI_DIRECT, "malloc work failed");
        return TIMER_ID_INVALID;
    }
    if (timerIdMap_.empty()) {
        workQueue_ = std::make_shared<WifiDirectWorkQueue>();
    }

    work->work = WorkHandler ;
    work->data = timer;
    timer->timerId = AllocTimerId();
    timer->callback = callback;
    timerIdMap_.insert({ timer->timerId, timer });
    workQueue_->ScheduleDelayWork(work, timeout);

    CONN_LOGI(CONN_WIFI_DIRECT, "timerId=%{public}d timeout=%d", timer->timerId, timeout);
    return timer->timerId;
}

void WifiDirectTimer::Unregister(int32_t timerId)
{
    std::lock_guard lock(timerIdMapLock_);
    CONN_LOGI(CONN_WIFI_DIRECT, "timerId=%{public}d", timerId);
    auto it = timerIdMap_.find(timerId);
    if (it == timerIdMap_.end()) {
        CONN_LOGE(CONN_WIFI_DIRECT, "not find timerId=%{public}d", timerId);
        return;
    }

    workQueue_->RemoveWork(it->second->work);
    SoftBusFree(it->second);
    timerIdMap_.erase(it);
    if (timerIdMap_.empty()) {
        CONN_LOGI(CONN_WIFI_DIRECT, "destroy work queue");
        workQueue_ = nullptr;
    }
}

int32_t WifiDirectTimer::AllocTimerId()
{
    if (timerId_ < 0) {
        timerId_ = 0;
    }
    return timerId_++;
}
}
