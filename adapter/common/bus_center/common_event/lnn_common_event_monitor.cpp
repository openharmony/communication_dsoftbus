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
#include "g_enhance_lnn_func_pack.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "lnn_async_callback_utils.h"
#include "lnn_log.h"
#include "lnn_ohos_account.h"
#include "power_mgr_client.h"
#include "softbus_error_code.h"
#include "lnn_init_monitor.h"

static const int32_t DELAY_LEN = 1000;
static const int32_t RETRY_MAX = 20;
static const int32_t OPEN_D2D = 1;
namespace OHOS {
namespace EventFwk {
static const char *COMMON_EVENT_DSOFTBUS_D2D_STATE_CHANGE = "usual.event.DSOFTBUS_D2D_STATE_CHANGE";
static const char *COMMON_EVENT_NEARLINK_HOST_DATA_TRANSFER_UPDATE = "usual.event.nearlink.host.DATA_TRANSFER_UPDATE";
static const char *COMMON_EVENT_NEARLINK_HOST_RANGING_UPDATE = "usual.event.nearlink.host.RANGING_UPDATE";
static const char *KEY_SLE_D2D_PAGING_ADV_STATE = "d2d.paging.advertise";
static const char *KEY_SLE_D2D_GROUP_ADV_STATE = "d2d.group.advertise";
static const char *PARAM_KEY_STATE = "state";

std::map<std::string, CommonEventType> g_commonEventMap = {
    {COMMON_EVENT_DSOFTBUS_D2D_STATE_CHANGE, D2D_STATE_UPDATE},
    {COMMON_EVENT_NEARLINK_HOST_DATA_TRANSFER_UPDATE, SLE_DATA_TRANSFER_UPDATE},
    {COMMON_EVENT_NEARLINK_HOST_RANGING_UPDATE, SLE_RANGING_UPDATE},
};

class CommonEventMonitor : public CommonEventSubscriber {
public:
    explicit CommonEventMonitor(const CommonEventSubscribeInfo &subscriberInfo);
    virtual ~CommonEventMonitor() {}
    virtual void OnReceiveEvent(const CommonEventData &data);
private:
    CommonEventType GetEventType(std::string &event);
    void OnReceiveSleEvent(const EventFwk::Want& want);
    void OnReceiveSleBusinessEvent(const EventFwk::Want& want);
    void OnReceiveSleD2dEvent(const EventFwk::Want& want);
};

CommonEventMonitor::CommonEventMonitor(const CommonEventSubscribeInfo &subscriberInfo)
    :CommonEventSubscriber(subscriberInfo)
{
}

CommonEventType CommonEventMonitor::GetEventType(std::string &event)
{
    auto iter = g_commonEventMap.find(event);
    if (iter == g_commonEventMap.end()) {
        return CommonEventType::COMMON_EVENT_UNKNOWN;
    }
    return iter->second;
}

void CommonEventMonitor::OnReceiveSleBusinessEvent(const EventFwk::Want& want)
{
    int32_t state = want.GetIntParam(PARAM_KEY_STATE, 0);
    if (state != 0) {
        LNN_LOGI(LNN_EVENT, "event state=%{public}d", state);
    }
}

void CommonEventMonitor::OnReceiveSleD2dEvent(const EventFwk::Want& want)
{
    int32_t pagingState = want.GetIntParam(KEY_SLE_D2D_PAGING_ADV_STATE, INT_MAX);
    int32_t groupState = want.GetIntParam(KEY_SLE_D2D_GROUP_ADV_STATE, INT_MAX);
    LNN_LOGI(LNN_EVENT, "d2d adv pagingState=%{public}d, groupState=%{public}d", pagingState, groupState);
    if (pagingState == OPEN_D2D || groupState == OPEN_D2D) {
        return;
    }
}
void CommonEventMonitor::OnReceiveSleEvent(const EventFwk::Want& want)
{
    std::string action = want.GetAction();
    switch (GetEventType(action)) {
        case SLE_RANGING_UPDATE:
        case SLE_DATA_TRANSFER_UPDATE:
            OnReceiveSleBusinessEvent(want);
            break;
        case D2D_STATE_UPDATE:
            OnReceiveSleD2dEvent(want);
            break;
        default:
            break;
    }
}

void CommonEventMonitor::OnReceiveEvent(const CommonEventData &data)
{
    auto want = data.GetWant();
    std::string action = data.GetWant().GetAction();
    LNN_LOGI(LNN_EVENT, "notify common event=%{public}s", action.c_str());

    if (action == CommonEventSupport::COMMON_EVENT_TIME_CHANGED) {
        LnnNotifySysTimeChangeEvent();
    }
    if (action == CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED) {
        LnnNotifyDeviceRiskStateChangeEvent();
    }
    OnReceiveSleEvent(want);
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
        int32_t activeUserId = JudgeDeviceTypeAndGetOsAccountIds();
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
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_TIME_CHANGED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_BOOT_COMPLETED);
    matchingSkills.AddEvent(COMMON_EVENT_NEARLINK_HOST_DATA_TRANSFER_UPDATE);
    matchingSkills.AddEvent(COMMON_EVENT_NEARLINK_HOST_RANGING_UPDATE);
    matchingSkills.AddEvent(COMMON_EVENT_DSOFTBUS_D2D_STATE_CHANGE);
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

int32_t LnnSubscribeCommonEvent(void)
{
    OHOS::EventFwk::SubscribeEvent *subscriberPtr = new OHOS::EventFwk::SubscribeEvent();
    if (subscriberPtr == nullptr) {
        LNN_LOGE(LNN_EVENT, "SubscribeEvent init fail");
        return SOFTBUS_MEM_ERR;
    }
    if (subscriberPtr->SubscribeCommonEvent() != SOFTBUS_OK) {
        delete subscriberPtr;
        LNN_LOGE(LNN_EVENT, "subscribe common event fail");
        return SOFTBUS_NETWORK_SUBSCRIBE_COMMON_EVENT_FAILED;
    }
    LNN_LOGI(LNN_EVENT, "subscribe common event success");
    LnnUpdateOhosAccount(UPDATE_HEARTBEAT);
    if (!LnnIsDefaultOhosAccount()) {
        LnnNotifyAccountStateChangeEvent(SOFTBUS_ACCOUNT_LOG_IN);
    }
    (void)LnnQueryLocalScreenStatusOnce(true);
    delete subscriberPtr;
    return SOFTBUS_OK;
}

int32_t LnnInitCommonEventMonitorImpl(void)
{
    int32_t ret = LnnInitModuleNotifyWithRetryAsync(INIT_DEPS_SCREEN_STATUS, LnnSubscribeCommonEvent, RETRY_MAX,
        DELAY_LEN, false);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "LnnAsyncCallbackHelper fail");
    }
    return ret;
}
