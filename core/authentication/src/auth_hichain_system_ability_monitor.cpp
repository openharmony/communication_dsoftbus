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
#include <mutex>

#include "auth_log.h"
#include "auth_manager.h"
#include "iservice_registry.h"
#include "lnn_async_callback_utils.h"
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
    static sptr<SystemAbilityListener> GetInstance();
protected:
    void OnAddSystemAbility(int32_t saId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t saId, const std::string &deviceId) override;
private:
    SystemAbilityListener() = default;
};

sptr<SystemAbilityListener> SystemAbilityListener::GetInstance()
{
    static sptr<SystemAbilityListener> instance;
    static std::mutex instanceLock;
    if (instance == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock);
        if (instance == nullptr) {
            instance = new SystemAbilityListener();
        }
    }
    return instance;
}

static void RetryRegTrustListener(void *para)
{
    (void)para;
    if (RegTrustListenerOnHichainSaStart() != SOFTBUS_OK) {
        AUTH_LOGI(AUTH_INIT, "retry reg hichain trust listener failed after 5s");
    }
}

void SystemAbilityListener::OnAddSystemAbility(int32_t saId, const std::string &deviceId)
{
    AUTH_LOGI(AUTH_INIT, "onSaStart saId=%{public}d", saId);
    if (saId == DEVICE_AUTH_SERVICE_ID) {
        int32_t ret = RegTrustListenerOnHichainSaStart();
        if (ret != SOFTBUS_OK) {
            const int delayRegHichainTime = 5000;
            ret = LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), RetryRegTrustListener, nullptr,
                delayRegHichainTime);
            AUTH_LOGI(AUTH_INIT, "LnnAsyncCallbackDelayHelper ret=%{public}d", ret);
        }
    }
}

void SystemAbilityListener::OnRemoveSystemAbility(int32_t saId, const std::string &deviceId)
{
    AUTH_LOGI(AUTH_INIT, "onRemove saId=%{public}d", saId);
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
        return SOFTBUS_AUTH_GET_SA_MANAGER_FAIL;
    }

    int32_t ret = samgrProxy->SubscribeSystemAbility(OHOS::DEVICE_AUTH_SERVICE_ID,
        OHOS::SaEventFwk::SystemAbilityListener::GetInstance());
    if (ret != OHOS::ERR_OK) {
        AUTH_LOGE(AUTH_INIT, "subscribe hichain sa failed, ret=%{public}d", ret);
        return SOFTBUS_AUTH_SUBSCRIBE_HICHAIN_SA_FAIL;
    }
    AUTH_LOGI(AUTH_INIT, "subscribe hichain sa succ");
    OHOS::SaEventFwk::SystemAbilityListener::isReg = true;
    return SOFTBUS_OK;
}

int32_t UnRegHichainSaStatusListener(void)
{
    if (!(OHOS::SaEventFwk::SystemAbilityListener::isReg)) {
        AUTH_LOGI(AUTH_INIT, "hichain sa is not subscribe");
        return SOFTBUS_AUTH_HICHAIN_SA_NOT_SUBSCRIBE;
    }
    OHOS::sptr<OHOS::ISystemAbilityManager> samgrProxy =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        AUTH_LOGE(AUTH_INIT, "get samgr failed, samgr is nullptr");
        return SOFTBUS_AUTH_GET_SA_MANAGER_FAIL;
    }

    int32_t ret = samgrProxy->UnSubscribeSystemAbility(OHOS::DEVICE_AUTH_SERVICE_ID,
        OHOS::SaEventFwk::SystemAbilityListener::GetInstance());
    if (ret != OHOS::ERR_OK) {
        AUTH_LOGE(AUTH_INIT, "unsubscribe hichain sa failed, ret=%{public}d", ret);
        return SOFTBUS_AUTH_UNSUBSCRIBE_HICHAIN_SA_FAIL;
    }
    AUTH_LOGI(AUTH_INIT, "unsubscribe hichain sa succ");
    OHOS::SaEventFwk::SystemAbilityListener::isReg = false;
    return SOFTBUS_OK;
}
