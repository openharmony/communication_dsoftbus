/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "lnn_log.h"
#include "want.h"
#include "wifi_msg.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "wifi_event.h"
#include "wifi_ap_msg.h"

static const int32_t DELAY_LEN = 1000;
static const int32_t RETRY_MAX = 20;

namespace OHOS {
namespace EventFwk {
class WifiServiceMonitor : public CommonEventSubscriber {
public:
    explicit WifiServiceMonitor(const CommonEventSubscribeInfo &subscriberInfo);
    virtual ~WifiServiceMonitor(){}
    virtual void OnReceiveEvent(const CommonEventData &data);
};

WifiServiceMonitor::WifiServiceMonitor(const CommonEventSubscribeInfo &subscriberInfo)
    :CommonEventSubscriber(subscriberInfo)
{
}

static void SetSoftBusWifiConnState(const int code, SoftBusWifiState *state)
{
    switch (code) {
        case int(OHOS::Wifi::ConnState::OBTAINING_IPADDR):
            *state = SOFTBUS_WIFI_OBTAINING_IPADDR;
            break;
        case int(OHOS::Wifi::ConnState::CONNECTED):
            *state = SOFTBUS_WIFI_CONNECTED;
            break;
        case int(OHOS::Wifi::ConnState::DISCONNECTED):
            *state = SOFTBUS_WIFI_DISCONNECTED;
            break;
        default: {
            break;
        }
    }
}

static void SetSoftBusWifiUseState(const int code, SoftBusWifiState *state)
{
    switch (code) {
        case int(OHOS::Wifi::WifiState::DISABLED):
            *state = SOFTBUS_WIFI_DISABLED;
            break;
        case int(OHOS::Wifi::WifiState::ENABLED):
            *state = SOFTBUS_WIFI_ENABLED;
            break;
        default: {
            break;
        }
    }
}

static void SetSoftBusWifiHotSpotState(const int code, SoftBusWifiState *state)
{
    switch (code) {
        case int(OHOS::Wifi::ApState::AP_STATE_STARTED):
            *state = SOFTBUS_AP_ENABLED;
            break;
        case int(OHOS::Wifi::ApState::AP_STATE_CLOSED):
            *state = SOFTBUS_AP_DISABLED;
            break;
        default: {
            break;
        }
    }
}
void WifiServiceMonitor::OnReceiveEvent(const CommonEventData &data)
{
    int code = data.GetCode();
    std::string action = data.GetWant().GetAction();
    SoftBusWifiState state = SOFTBUS_WIFI_UNKNOWN;
    LNN_LOGI(LNN_BUILDER, "notify wifiservice event=%{public}s, code=%{public}d", action.c_str(), code);
    if (action == CommonEventSupport::COMMON_EVENT_WIFI_CONN_STATE) {
        SetSoftBusWifiConnState(code, &state);
    }
    if (action == CommonEventSupport::COMMON_EVENT_WIFI_POWER_STATE) {
        SetSoftBusWifiUseState(code, &state);
    }
    if (action == CommonEventSupport::COMMON_EVENT_WIFI_HOTSPOT_STATE) {
        SetSoftBusWifiHotSpotState(code, &state);
    }
    if (state != SOFTBUS_WIFI_UNKNOWN) {
        LnnNotifyWlanStateChangeEvent(state);
    }
}

class SubscribeEvent {
public:
    int32_t SubscribeWifiConnStateEvent();
    int32_t SubscribeWifiPowerStateEvent();
    int32_t SubscribeAPConnStateEvent();
};

int32_t SubscribeEvent::SubscribeAPConnStateEvent()
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_WIFI_HOTSPOT_STATE);
    CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    std::shared_ptr<WifiServiceMonitor> subscriberPtr = std::make_shared<WifiServiceMonitor>(subscriberInfo);
    if (!CommonEventManager::SubscribeCommonEvent(subscriberPtr)) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SubscribeEvent::SubscribeWifiConnStateEvent()
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_WIFI_CONN_STATE);
    CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    std::shared_ptr<WifiServiceMonitor> subscriberPtr = std::make_shared<WifiServiceMonitor>(subscriberInfo);
    if (!CommonEventManager::SubscribeCommonEvent(subscriberPtr)) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SubscribeEvent::SubscribeWifiPowerStateEvent()
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_WIFI_POWER_STATE);
    CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    std::shared_ptr<WifiServiceMonitor> subscriberPtr = std::make_shared<WifiServiceMonitor>(subscriberInfo);
    if (!CommonEventManager::SubscribeCommonEvent(subscriberPtr)) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
} // namespace EventFwk
} // namespace OHOS

static void LnnSubscribeWifiService(void *para)
{
    (void)para;
    static int32_t retry = 0;
    if (retry > RETRY_MAX) {
        LNN_LOGE(LNN_BUILDER, "try subscribe wifiservice event max times");
        return;
    }
    OHOS::EventFwk::SubscribeEvent *subscriberPtr = new OHOS::EventFwk::SubscribeEvent();
    if (subscriberPtr == nullptr) {
        LNN_LOGE(LNN_BUILDER, "SubscribeEvent init fail");
        return;
    }
    if (subscriberPtr->SubscribeWifiConnStateEvent() == SOFTBUS_OK &&
        subscriberPtr->SubscribeWifiPowerStateEvent() == SOFTBUS_OK &&
        subscriberPtr->SubscribeAPConnStateEvent() == SOFTBUS_OK) {
        LNN_LOGI(LNN_BUILDER, "subscribe wifiservice conn and power state success");
    } else {
        LNN_LOGE(LNN_BUILDER, "subscribe wifiservice event fail");
        retry++;
        SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
        if (LnnAsyncCallbackDelayHelper(looper, LnnSubscribeWifiService, NULL, DELAY_LEN) != SOFTBUS_OK) {
            LNN_LOGE(LNN_BUILDER, "LnnAsyncCallbackDelayHelper fail");
        }
    }
    delete subscriberPtr;
}

int32_t LnnInitWifiServiceMonitorImpl(void)
{
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    int32_t ret = LnnAsyncCallbackDelayHelper(looper, LnnSubscribeWifiService, NULL, DELAY_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "LnnAsyncCallbackDelayHelper fail");
    }
    return ret;
}
