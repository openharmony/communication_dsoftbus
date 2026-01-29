/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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


#include "common_event_manager.h"
#include "common_event_support.h"
#include "comm_log.h"
#include "softbus_error_code.h"
#include "br_proxy_server_manager.h"
#include "trans_log.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::EventFwk;
constexpr const char* APP_INDEX = "appIndex";
constexpr const char* USER_ID = "userId";
class HapUninstallObserver : public CommonEventSubscriber {
public:
    explicit HapUninstallObserver(const CommonEventSubscribeInfo &sp) : CommonEventSubscriber(sp) {}

    void OnReceiveEvent(const CommonEventData &data) override
    {
        auto &want = data.GetWant();
        std::string wantAction = want.GetAction();
        TRANS_LOGI(TRANS_SVC, "[br_proxy] wantAction %{public}s", wantAction.c_str());
        if (wantAction == CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED ||
            wantAction == CommonEventSupport::COMMON_EVENT_BUNDLE_REMOVED ||
            wantAction == CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED) {
            std::string bundleName = want.GetBundle();
            int32_t appIndex = want.GetIntParam(APP_INDEX, -1);
            int32_t userId = want.GetIntParam(USER_ID, 0);
            TRANS_LOGI(TRANS_SVC, "[br_proxy] index=%{public}d, userId=%{public}d", appIndex, userId);
            if (IsBrProxy(bundleName.c_str())) {
                UninstallHandler(bundleName.c_str(), appIndex, userId);
            }
        }
    }
};

extern "C" int32_t RegisterHapUninstallEvent(void)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_BUNDLE_REMOVED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED);

    CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    std::shared_ptr<HapUninstallObserver> subscriber = std::make_shared<HapUninstallObserver>(subscriberInfo);

    CommonEventManager::SubscribeCommonEvent(subscriber);

    return SOFTBUS_OK;
}