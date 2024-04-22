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
#ifndef WIFI_DIRECT_EVENT_TEMPLATE_DISPATCHER_H
#define WIFI_DIRECT_EVENT_TEMPLATE_DISPATCHER_H

#include <functional>
#include "conn_log.h"
#include "wifi_direct_event_queue.h"
#include "wifi_direct_event_wrapper.h"

namespace OHOS::SoftBus {
template<typename PrevDispatcher, typename Content>
class WifiDirectEventTemplateDispatcher {
public:
    using Func =  std::function<void(Content&)>;
    WifiDirectEventTemplateDispatcher(WifiDirectEventQueue *queue, PrevDispatcher *prev, Func &&func)
        : queue_(queue), prev_(prev), func_(std::forward<Func>(func)), chained_(false)
    {
        prev->chained_ = true;
    }

    ~WifiDirectEventTemplateDispatcher() noexcept(false)
    {
        if (!chained_) {
            WaitAndDispatch();
        }
    }

    template<typename OtherContent>
    WifiDirectEventTemplateDispatcher<WifiDirectEventTemplateDispatcher, OtherContent>
    Handle(std::function<void(OtherContent&)> &&otherFunc)
    {
        return WifiDirectEventTemplateDispatcher<WifiDirectEventTemplateDispatcher, OtherContent>(
            queue_, this, std::forward<std::function<void(OtherContent&)>>(otherFunc));
    }

private:
    template<typename Dispatcher, typename OtherEvent>
    friend class WifiDirectEventTemplateDispatcher;

    void WaitAndDispatch()
    {
        for (;;) {
            if (Dispatch(queue_->WaitAndPop())) {
                break;
            }
        }
    }

    bool Dispatch(const std::shared_ptr<WifiDirectEventBase> &content)
    {
        auto wrapper = dynamic_cast<WifiDirectEventWrapper<Content> *>(content.get());
        if (wrapper != nullptr) {
            func_(wrapper->content_);
            return true;
        }
        return prev_->Dispatch(content);
    }

    WifiDirectEventQueue *queue_;
    PrevDispatcher *prev_;
    Func func_;
    bool chained_;
};
}
#endif
