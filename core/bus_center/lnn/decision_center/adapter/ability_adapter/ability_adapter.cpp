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

#include "anonymizer.h"
#include "ability_manager_client.h"
#include "appmgr/app_mgr_client.h"
#include "bundle_mgr_proxy.h"
#include "extension_manager_client.h"
#include "iservice_registry.h"
#include "lnn_log.h"
#include "softbus_error_code.h"
#include "system_ability_definition.h"
#include "want.h"

constexpr int32_t ERR_OK = 0;
constexpr int32_t GET_EXTENSION_UPPER_LIMIT = 100;

static OHOS::sptr<OHOS::AppExecFwk::IBundleMgr> GetBundleMgrProxy()
{
    auto samgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        LNN_LOGE(LNN_EVENT, "samgr is nullptr");
        return nullptr;
    }
    auto remoteObj = samgr->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObj == nullptr) {
        LNN_LOGE(LNN_EVENT, "remoteObj is nullptr");
        return nullptr;
    }
    return OHOS::iface_cast<OHOS::AppExecFwk::IBundleMgr>(remoteObj);
}

static bool IsSystemApp(const char *bundleName, int32_t userId)
{
    if (bundleName == nullptr) {
        LNN_LOGE(LNN_EVENT, "bundleName is nullptr");
        return false;
    }
    auto bundleMgr = GetBundleMgrProxy();
    if (bundleMgr == nullptr) {
        LNN_LOGE(LNN_EVENT, "bundleMgr is nullptr");
        return false;
    }
    int32_t flag =
        static_cast<int32_t>(OHOS::AppExecFwk::GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT);
    OHOS::AppExecFwk::ApplicationInfo appInfo;
    int32_t ret = bundleMgr->GetApplicationInfoV9(std::string(bundleName), flag, userId, appInfo);
    char *anonyBundlename = nullptr;
    Anonymize(bundleName, &anonyBundlename);
    if (ret != ERR_OK) {
        LNN_LOGE(LNN_EVENT,
            "GetApplicationInfoV9 failed, ret=%{public}d, userId=%{public}d, bundleName=%{public}s",
            ret, userId, AnonymizeWrapper(anonyBundlename));
        AnonymizeFree(anonyBundlename);
        return false;
    }
    if (!appInfo.isSystemApp) {
        LNN_LOGE(LNN_EVENT, "not system app. bundleName=%{public}s", AnonymizeWrapper(anonyBundlename));
        AnonymizeFree(anonyBundlename);
        return false;
    }
    AnonymizeFree(anonyBundlename);
    return true;
}

int32_t StartAbility(const char *bundleName, const char *abilityName, int32_t userId)
{
    if (bundleName == nullptr || abilityName == nullptr || userId < 0) {
        LNN_LOGE(LNN_EVENT, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!IsSystemApp(bundleName, userId)) {
        LNN_LOGE(LNN_EVENT, "only system app can start ability");
        return SOFTBUS_PERMISSION_DENIED;
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