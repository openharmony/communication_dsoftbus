/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "lnn_event_monitor_impl.h"

#include <securec.h>

#include "bus_center_event.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "lnn_async_callback_utils.h"
#include "want.h"

#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

static const int32_t DELAY_LEN = 1000;
static const int32_t RETRY_MAX = 10;

namespace OHOS {
namespace EventFwk {
class ScreenStateMonitor : public CommonEventSubscriber {
public:
    explicit ScreenStateMonitor(const CommonEventSubscribeInfo &subscriberInfo);
    virtual ~ScreenStateMonitor() {}
    virtual void OnReceiveEvent(const CommonEventData &data);
};

ScreenStateMonitor::ScreenStateMonitor(const CommonEventSubscribeInfo &subscriberInfo)
    :CommonEventSubscriber(subscriberInfo)
{
}

void ScreenStateMonitor::OnReceiveEvent(const CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    SoftBusScreenState state = SOFTBUS_SCREEN_UNKNOWN;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "notify ScreenState event %s", action.c_str());

    if (action == CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
        state = SOFTBUS_SCREEN_OFF;
    } else if (action == CommonEventSupport::COMMON_EVENT_SCREEN_ON) {
        state = SOFTBUS_SCREEN_ON;
    }
    if (state != SOFTBUS_SCREEN_UNKNOWN) {
        LnnNotifyScreenStateChangeEvent(state);
    }
}

class SubscribeEvent {
public:
    int32_t SubscribeScreenStateEvent();
private:
    std::shared_ptr<ScreenStateMonitor> subscriber_ = nullptr;
};

int32_t SubscribeEvent::SubscribeScreenStateEvent()
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriber_ = std::make_shared<ScreenStateMonitor>(subscriberInfo);
    if (!CommonEventManager::SubscribeCommonEvent(subscriber_)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "SubscribeScreenStateEvent: subscribe ScreenState event err");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
} // namespace EventFwk
} // namespace OHOS

static void LnnSubscribeScreenState(void *para)
{
    (void)para;
    static int32_t retry = 0;
    if (retry > RETRY_MAX) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "try subscribe ScreenState event max times");
        return;
    }
    OHOS::EventFwk::SubscribeEvent *subscriberPtr = new OHOS::EventFwk::SubscribeEvent();
    if (subscriberPtr == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "SubscribeEvent init fail");
        return;
    }
    if (subscriberPtr->SubscribeScreenStateEvent() == SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "subscribe ScreenState on or off state success");
    } else {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "subscribe ScreenState event fail");
        retry++;
        SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
        if (LnnAsyncCallbackDelayHelper(looper, LnnSubscribeScreenState, NULL, DELAY_LEN) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "async call subscribe screen state fail");
        }
    }
    delete subscriberPtr;
}

int32_t LnnInitScreenStateMonitorImpl(void)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    int32_t ret = LnnAsyncCallbackDelayHelper(looper, LnnSubscribeScreenState, NULL, DELAY_LEN);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "init ScreenState LnnAsyncCallbackDelayHelper fail");
    }
    return ret;
}
