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
#ifndef WIFI_DIRECT_EVENT_SENDER_H
#define WIFI_DIRECT_EVENT_SENDER_H

#include "wifi_direct_event_queue.h"

namespace OHOS::SoftBus {
class WifiDirectEventSender {
public:
    explicit WifiDirectEventSender(WifiDirectEventQueue *queue) : queue_(queue) {}

    template<typename Content>
    void Send(const Content &content)
    {
        if (queue_ != nullptr) {
            queue_->Push(content);
        }
    }

    void ProcessUnHandle(const WifiDirectEventQueue::Handler &handler)
    {
        if (queue_ != nullptr) {
            queue_->Process(handler);
        }
    }

    void Clear()
    {
        if (queue_ != nullptr) {
            queue_->Clear();
        }
    }

private:
    WifiDirectEventQueue *queue_;
};
} // namespace OHOS::SoftBus
#endif
