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
#include <securec.h>
#include "ability_manager_client.h"
#include "bundle_mgr_interface.h"
#include "iservice_registry.h"
#include "softbus_error_code.h"
#include "system_ability_definition.h"

using namespace OHOS;

extern "C" int32_t StartAbility(const char *bundleName, const char *abilityName)
{
    OHOS::AAFwk::Want want;
    want.SetElementName(bundleName, abilityName);
    return OHOS::AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
}

static sptr<AppExecFwk::IBundleMgr> GetBundleMgr()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        return nullptr;
    }
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        return nullptr;
    }
    return iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
}

extern "C" int32_t ProxyChannelMgrGetAbilityName(char *abilityName, int32_t userId, uint32_t abilityNameLen,
    std::string bundleName)
{
    AAFwk::Want want;
    want.SetElementName(bundleName, "");
    want.SetAction("action.ohos.pull.listener");

    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    auto bundleMgr = GetBundleMgr();
    if (bundleMgr == nullptr) {
        return SOFTBUS_TRANS_GET_BUNDLE_MGR_FAILED;
    }
    auto flag = static_cast<int32_t>(AppExecFwk::GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);
    int32_t ret = bundleMgr->QueryAbilityInfosV9(want, flag, userId, abilityInfos);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (strcpy_s(abilityName, abilityNameLen, abilityInfos[0].name.c_str()) != EOK) {
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}