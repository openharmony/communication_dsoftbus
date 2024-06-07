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
#ifndef WIFI_DIRECT_EVENT_QUEUE_H
#define WIFI_DIRECT_EVENT_QUEUE_H

#include <queue>
#include <mutex>
#include <memory>
#include <condition_variable>
#include "wifi_direct_event_base.h"
#include "wifi_direct_event_wrapper.h"

namespace OHOS::SoftBus {
class WifiDirectEventQueue {
public:
    template<typename Content>
    void Push(const Content &content)
    {
        std::lock_guard<std::mutex> lk(m_);
        queue_.push_back(std::make_shared<WifiDirectEventWrapper<Content>>(content));
        c_.notify_all();
    }

    std::shared_ptr<WifiDirectEventBase> WaitAndPop()
    {
        std::unique_lock<std::mutex> lk(m_);
        c_.wait(lk, [&] { return !queue_.empty(); });
        auto res = queue_.front();
        queue_.pop_front();
        return res;
    }

    using Handler = std::function<void(std::shared_ptr<WifiDirectEventBase> &)>;
    void Process(const Handler &handler)
    {
        std::lock_guard<std::mutex> lk(m_);
        for (auto it = queue_.rbegin(); it != queue_.rend(); it++) {
            handler(*it);
        }
    }

    void Clear()
    {
        std::lock_guard<std::mutex> lk(m_);
        queue_.clear();
    }

private:
    std::mutex m_;
    std::condition_variable c_;
    std::deque<std::shared_ptr<WifiDirectEventBase>> queue_;
};
}
#endif
