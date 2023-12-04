/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "auth_hichain.h"

#include <atomic>
#include <cstdint>
#include <string>

#include "auth_log.h"
#include "auth_manager.h"
#include "iservice_registry.h"
#include "softbus_error_code.h"
#include "system_ability_definition.h"
#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace SaEventFwk {
class SystemAbilityListener : public SystemAbilityStatusChangeStub {
public:
    SystemAbilityListener(const SystemAbilityListener&) = delete;
    SystemAbilityListener &operator=(const SystemAbilityListener&) = delete;

    static std::atomic<bool> isReg;
    static SystemAbilityListener *GetInstance();
protected:
    void OnAddSystemAbility(int32_t saId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t saId, const std::string &deviceId) override;
private:
    SystemAbilityListener() = default;
};

SystemAbilityListener *SystemAbilityListener::GetInstance()
{
    static SystemAbilityListener saListener;
    return &saListener;
}

void SystemAbilityListener::OnAddSystemAbility(int32_t saId, const std::string &deviceId)
{
    AUTH_LOGI(AUTH_INIT, "onSaStart saId=%d", saId);
    if (saId == DEVICE_AUTH_SERVICE_ID) {
        (void)RegTrustListenerOnHichainSaStart();
    }
}

void SystemAbilityListener::OnRemoveSystemAbility(int32_t saId, const std::string &deviceId)
{
    AUTH_LOGI(AUTH_INIT, "onRemove saId=%d", saId);
}
} // namespace SaEventFwk
} // namespace OHOS

std::atomic<bool> OHOS::SaEventFwk::SystemAbilityListener::isReg = false;

int32_t RegHichainSaStatusListener(void)
{
    OHOS::sptr<OHOS::ISystemAbilityManager> samgrProxy =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        AUTH_LOGE(AUTH_INIT, "get samgr failed, samgr is nullptr");
        return SOFTBUS_ERR;
    }

    int32_t ret = samgrProxy->SubscribeSystemAbility(OHOS::DEVICE_AUTH_SERVICE_ID,
        OHOS::SaEventFwk::SystemAbilityListener::GetInstance());
    if (ret != OHOS::ERR_OK) {
        AUTH_LOGE(AUTH_INIT, "subscribe hichain sa failed, ret=%d", ret);
        return SOFTBUS_ERR;
    }
    AUTH_LOGI(AUTH_INIT, "subscribe hichain sa succ");
    OHOS::SaEventFwk::SystemAbilityListener::isReg = true;
    return SOFTBUS_OK;
}

int32_t UnRegHichainSaStatusListener(void)
{
    if (!(OHOS::SaEventFwk::SystemAbilityListener::isReg)) {
        AUTH_LOGI(AUTH_INIT, "hichain sa is not subscribe");
        return SOFTBUS_ERR;
    }
    OHOS::sptr<OHOS::ISystemAbilityManager> samgrProxy =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        AUTH_LOGE(AUTH_INIT, "get samgr failed, samgr is nullptr");
        return SOFTBUS_ERR;
    }

    int32_t ret = samgrProxy->UnSubscribeSystemAbility(OHOS::DEVICE_AUTH_SERVICE_ID,
        OHOS::SaEventFwk::SystemAbilityListener::GetInstance());
    if (ret != OHOS::ERR_OK) {
        AUTH_LOGE(AUTH_INIT, "unsubscribe hichain sa failed, ret=%d", ret);
        return SOFTBUS_ERR;
    }
    AUTH_LOGI(AUTH_INIT, "unsubscribe hichain sa succ");
    OHOS::SaEventFwk::SystemAbilityListener::isReg = false;
    return SOFTBUS_OK;
}
