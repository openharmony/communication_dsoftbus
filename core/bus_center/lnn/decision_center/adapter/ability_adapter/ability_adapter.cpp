/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ability_adapter.h"

#include "ability_manager_client.h"
#include "appmgr/app_mgr_client.h"
#include "extension_manager_client.h"
#include "iservice_registry.h"
#include "lnn_log.h"
#include "softbus_error_code.h"
#include "system_ability_definition.h"
#include "want.h"

constexpr int32_t ERR_OK = 0;
constexpr int32_t GET_EXTENSION_UPPER_LIMIT = 100;

int32_t StartAbility(const char *bundleName, const char *abilityName)
{
    if (bundleName == nullptr || abilityName == nullptr) {
        LNN_LOGE(LNN_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    auto client = OHOS::AAFwk::AbilityManagerClient::GetInstance();
    if (client == nullptr) {
        LNN_LOGE(LNN_EVENT, "client is nullptr");
        return SOFTBUS_NETWORK_GET_CLIENT_PROXY_NULL;
    }
    OHOS::AAFwk::Want want;
    want.SetElementName(bundleName, abilityName);
    want.SetParam("launch_type", std::string("softbus_agent_communication"));
    return client->StartAbility(want);
}

bool IsRunningProcess(const char *bundleName, int32_t userId)
{
    if (bundleName == nullptr) {
        LNN_LOGE(LNN_EVENT, "invalid param");
        return false;
    }
    if (userId < 0) {
        LNN_LOGE(LNN_EVENT, "invalid userId");
        return false;
    }
    auto &samgrClient = OHOS::SystemAbilityManagerClient::GetInstance();
    auto samgr = samgrClient.GetSystemAbilityManager();
    if (samgr == nullptr) {
        LNN_LOGE(LNN_EVENT, "samgr is nullptr");
        return false;
    }
    auto appObj = samgr->GetSystemAbility(OHOS::APP_MGR_SERVICE_ID);
    if (appObj == nullptr) {
        LNN_LOGE(LNN_EVENT, "appObj is nullptr");
        return false;
    }
    OHOS::sptr<OHOS::AppExecFwk::IAppMgr> appMgr = OHOS::iface_cast<OHOS::AppExecFwk::IAppMgr>(appObj);
    std::vector<OHOS::AppExecFwk::RunningProcessInfo> processInfos;
    int32_t ret = appMgr->GetRunningProcessInformation(bundleName, userId, processInfos);
    LNN_LOGI(LNN_EVENT, "RunningProcessInfo size: %{public}zu", processInfos.size());
    if (ret != ERR_OK || processInfos.empty()) {
        LNN_LOGE(LNN_EVENT, "not exist ret=%{public}d", ret);
        return false;
    }
    return true;
}

bool IsExtensionAbility(const char *bundleName, const char *abilityName, int32_t upperLimit)
{
    if (bundleName == nullptr || abilityName == nullptr || upperLimit <= 0 ||
        upperLimit > GET_EXTENSION_UPPER_LIMIT) {
        LNN_LOGE(LNN_EVENT, "invalid param");
        return false;
    }
    auto &client = OHOS::AAFwk::ExtensionManagerClient::GetInstance();
    std::vector<OHOS::AAFwk::ExtensionRunningInfo> extensionInfos = {};
    int32_t ret = client.GetExtensionRunningInfos(upperLimit, extensionInfos);
    if (ret != ERR_OK) {
        LNN_LOGE(LNN_EVENT, "get extension failed ret=%{public}d", ret);
        return false;
    }
    LNN_LOGI(LNN_EVENT, "GetExtensionRunningInfos size: %{public}zu", extensionInfos.size());
    std::string targetBundle(bundleName);
    std::string targetAbility(abilityName);
    for (const auto& extensionInfo : extensionInfos) {
        if (extensionInfo.extension.GetBundleName() == targetBundle &&
            extensionInfo.extension.GetAbilityName() == targetAbility) {
            return true;
        }
    }

    auto abilityMgrClient = OHOS::AAFwk::AbilityManagerClient::GetInstance();
    if (abilityMgrClient == nullptr) {
        LNN_LOGE(LNN_EVENT, "get ability mgr client failed");
        return false;
    }
    std::vector<OHOS::AAFwk::AbilityRunningInfo> abilityRunningInfos = {};
    ret = abilityMgrClient->GetAbilityRunningInfos(abilityRunningInfos);
    if (ret != ERR_OK) {
        LNN_LOGE(LNN_EVENT, "get ability info failed ret=%{public}d", ret);
        return false;
    }
    LNN_LOGI(LNN_EVENT, "GetAbilityRunningInfos size: %{public}zu", abilityRunningInfos.size());
    for (const auto& abilityRunningInfo : abilityRunningInfos) {
        if (abilityRunningInfo.ability.GetBundleName() == targetBundle &&
            abilityRunningInfo.ability.GetAbilityName() == targetAbility) {
            return true;
        }
    }
    return false;
}