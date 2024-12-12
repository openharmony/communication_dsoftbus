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
#include <string>

#include "auth_interface.h"
#include "bus_center_event.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"
#include "lnn_async_callback_utils.h"
#include "lnn_log.h"
#include "lnn_ohos_account.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_ohos_account_adapter.h"
#include "want.h"
#include "want_params.h"

#include "power_mgr_client.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

static const int32_t DELAY_LEN = 1000;
static const int32_t RETRY_MAX = 20;

namespace OHOS {
namespace EventFwk {
class CommonEventMonitor : public CommonEventSubscriber {
public:
    explicit CommonEventMonitor(const CommonEventSubscribeInfo &subscriberInfo);
    virtual ~CommonEventMonitor() {}
    virtual void OnReceiveEvent(const CommonEventData &data);
};

CommonEventMonitor::CommonEventMonitor(const CommonEventSubscribeInfo &subscriberInfo)
    :CommonEventSubscriber(subscriberInfo)
{
}

void CommonEventMonitor::OnReceiveEvent(const CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    LNN_LOGI(LNN_EVENT, "notify common event=%{public}s", action.c_str());

    SoftBusScreenState screenState = SOFTBUS_SCREEN_UNKNOWN;
    if (action == CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
        screenState = SOFTBUS_SCREEN_OFF;
    } else if (action == CommonEventSupport::COMMON_EVENT_SCREEN_ON) {
        screenState = SOFTBUS_SCREEN_ON;
    } else if (action == CommonEventSupport::COMMON_EVENT_USER_UNLOCKED) {
        LnnNotifyScreenLockStateChangeEvent(SOFTBUS_USER_UNLOCK);
    } else if (action == CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED) {
        LnnNotifyScreenLockStateChangeEvent(SOFTBUS_SCREEN_UNLOCK);
    } else if (action == CommonEventSupport::COMMON_EVENT_DATA_SHARE_READY) {
        LnnNotifyDataShareStateChangeEvent(SOFTBUS_DATA_SHARE_READY);
    }
    if (screenState != SOFTBUS_SCREEN_UNKNOWN) {
        LnnNotifyScreenStateChangeEvent(screenState);
    }

    SoftBusAccountState state = SOFTBUS_ACCOUNT_UNKNOWN;

    if (action == CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT ||
        action == CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOFF) {
        const AAFwk::WantParams &wantParams = data.GetWant().GetParams();
        int32_t eventUserId = -1;
        int32_t activeUserId = GetActiveOsAccountIds();
        std::string userIdKey = "userId";
        eventUserId = wantParams.GetIntParam(userIdKey, -1);
        LNN_LOGI(LNN_EVENT, "activeUserId=%{public}d, eventUserId=%{public}d", activeUserId, eventUserId);
        if (eventUserId == activeUserId) {
            state = SOFTBUS_ACCOUNT_LOG_OUT;
        }
    }
    if (state != SOFTBUS_ACCOUNT_UNKNOWN) {
        LnnNotifyAccountStateChangeEvent(state);
    }

    if (action == CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        LnnNotifyUserSwitchEvent(SOFTBUS_USER_SWITCHED);
    }
}

class SubscribeEvent {
public:
    int32_t SubscribeCommonEvent();
private:
    std::shared_ptr<CommonEventMonitor> subscriber_ = nullptr;
};

int32_t SubscribeEvent::SubscribeCommonEvent()
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOFF);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DATA_SHARE_READY);
    CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriber_ = std::make_shared<CommonEventMonitor>(subscriberInfo);
    if (!CommonEventManager::SubscribeCommonEvent(subscriber_)) {
        LNN_LOGE(LNN_EVENT, "subscribe common event err");
        return SOFTBUS_NETWORK_SUBSCRIBE_COMMON_EVENT_FAILED;
    }
    return SOFTBUS_OK;
}
} // namespace EventFwk
} // namespace OHOS

bool LnnQueryLocalScreenStatusOnce(bool notify)
{
    bool isScreenOn = OHOS::PowerMgr::PowerMgrClient::GetInstance().IsScreenOn(true);
    LNN_LOGI(LNN_EVENT, "query screen status is %{public}s", isScreenOn ? "on" : "off");
    if (notify) {
        SoftBusScreenState screenState = isScreenOn ? SOFTBUS_SCREEN_ON : SOFTBUS_SCREEN_OFF;
        LnnNotifyScreenStateChangeEvent(screenState);
    }
    return isScreenOn;
}

static void LnnSubscribeCommonEvent(void *para)
{
    (void)para;
    static int32_t retry = 0;
    if (retry > RETRY_MAX) {
        LNN_LOGE(LNN_EVENT, "try subscribe common event max times");
        return;
    }
    OHOS::EventFwk::SubscribeEvent *subscriberPtr = new OHOS::EventFwk::SubscribeEvent();
    if (subscriberPtr == nullptr) {
        LNN_LOGE(LNN_EVENT, "SubscribeEvent init fail");
        return;
    }
    if (subscriberPtr->SubscribeCommonEvent() == SOFTBUS_OK) {
        LNN_LOGI(LNN_EVENT, "subscribe common event success");
        LnnUpdateOhosAccount(UPDATE_HEARTBEAT);
        if (!LnnIsDefaultOhosAccount()) {
            LnnNotifyAccountStateChangeEvent(SOFTBUS_ACCOUNT_LOG_IN);
        }
    } else {
        LNN_LOGE(LNN_EVENT, "subscribe common event fail");
        retry++;
        SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
        if (LnnAsyncCallbackDelayHelper(looper, LnnSubscribeCommonEvent, NULL, DELAY_LEN) != SOFTBUS_OK) {
            LNN_LOGE(LNN_EVENT, "async call subscribe screen state fail");
        }
    }
    delete subscriberPtr;
    (void)LnnQueryLocalScreenStatusOnce(true);
}

int32_t LnnInitCommonEventMonitorImpl(void)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    int32_t ret = LnnAsyncCallbackHelper(looper, LnnSubscribeCommonEvent, NULL);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "LnnAsyncCallbackHelper fail");
    }
    return ret;
}
