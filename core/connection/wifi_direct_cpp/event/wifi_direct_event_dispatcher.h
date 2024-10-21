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
#ifndef WIFI_DIRECT_EVENT_DISPATCHER_H
#define WIFI_DIRECT_EVENT_DISPATCHER_H

#include <functional>
#include "conn_log.h"
#include "wifi_direct_event_queue.h"
#include "wifi_direct_event_template_dispatcher.h"

namespace OHOS::SoftBus {
class WifiDirectEventDispatcher {
public:
    WifiDirectEventDispatcher(const WifiDirectEventDispatcher &) = delete;
    WifiDirectEventDispatcher& operator=(const WifiDirectEventDispatcher &) = delete;

    explicit WifiDirectEventDispatcher(WifiDirectEventQueue *queue);
    ~WifiDirectEventDispatcher() noexcept(false);

    template<typename Content>
    WifiDirectEventTemplateDispatcher<WifiDirectEventDispatcher, Content>
    Handle(std::function<void(Content&)> &&func)
    {
        return WifiDirectEventTemplateDispatcher<WifiDirectEventDispatcher, Content>(
            queue_, this, std::forward<std::function<void(Content&)>>(func));
    }

private:
    template<typename Dispatcher, typename Event>
    friend class WifiDirectEventTemplateDispatcher;

    void WaitAndDispatch();
    static bool Dispatch(const std::shared_ptr<WifiDirectEventBase> &event);

    WifiDirectEventQueue *queue_;
    bool chained_;
};

enum class ProcessorTerminateReason {
    SUCCESS,
    FAILURE,
    RETRY,
};

struct ProcessorTerminate : public std::exception {
    ProcessorTerminate(ProcessorTerminateReason reason = ProcessorTerminateReason::SUCCESS) : reason_(reason) {}
    ProcessorTerminateReason reason_;
};
}
#endif
