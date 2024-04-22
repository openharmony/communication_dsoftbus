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
#include "wifi_direct_event_dispatcher.h"
#include "wifi_direct_event_wrapper.h"
#include "wifi_direct_event_template_dispatcher.h"
#include "conn_log.h"

namespace OHOS::SoftBus {
WifiDirectEventDispatcher::WifiDirectEventDispatcher(WifiDirectEventQueue *queue)
    : queue_(queue), chained_(true)
{
}

WifiDirectEventDispatcher::~WifiDirectEventDispatcher() noexcept(false)
{
    if (!chained_) {
        WaitAndDispatch();
    }
}

void WifiDirectEventDispatcher::WaitAndDispatch()
{
    Dispatch(queue_->WaitAndPop());
}

bool WifiDirectEventDispatcher::Dispatch(const std::shared_ptr<WifiDirectEventBase> &event)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "ignore unhandled event");
    return false;
}
}
