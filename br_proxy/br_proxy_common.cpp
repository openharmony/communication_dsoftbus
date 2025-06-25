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
#include "ability_manager_client.h"
#include "ability_manager_errors.h"
#include "accesstoken_kit.h"
#include "bundle_mgr_interface.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_error_code.h"
#include "system_ability_definition.h"
#include "trans_log.h"

using namespace OHOS;

extern "C" int32_t PullUpHap(const char *bundleName, const char *abilityName)
{
    AAFwk::Want want;
    want.SetElementName(bundleName, abilityName);
    return AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
}

sptr<AppExecFwk::IBundleMgr> GetBundleMgr()
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

extern "C" pid_t GetCallerPid()
{
    return IPCSkeleton::GetCallingPid();
}

extern "C" pid_t GetCallerUid()
{
    return IPCSkeleton::GetCallingUid();
}

extern "C" uint32_t GetCallerTokenId()
{
    return IPCSkeleton::GetCallingTokenID();
}

extern "C" int32_t GetCallerHapInfo(char *bundleName, uint32_t bundleNamelen,
    char *abilityName, uint32_t abilityNameLen)
{
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto type = Security::AccessToken::AccessTokenKit::GetTokenType(callerToken);
    if (type != Security::AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        return SOFTBUS_TRANS_TOKEN_HAP_ERR;
    }
    Security::AccessToken::HapTokenInfo hapTokenInfoRes;
    Security::AccessToken::AccessTokenKit::GetHapTokenInfo(callerToken, hapTokenInfoRes);

    AAFwk::Want want;
    want.SetElementName(hapTokenInfoRes.bundleName, "");
    want.SetAction("action.ohos.pull.listener");

    std::vector<AppExecFwk::AbilityInfo> abilityInfos;

    auto bundleMgr = GetBundleMgr();
    if (bundleMgr == nullptr) {
        return SOFTBUS_TRANS_GET_BUNDLE_MGR_FAILED;
    }
    int32_t userId = GetActiveOsAccountIds();
    auto flag = static_cast<int32_t>(AppExecFwk::GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);
    int32_t ret = bundleMgr->QueryAbilityInfosV9(want, flag, userId, abilityInfos);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] get abilityName failed! ret:%{public}d", ret);
        return ret;
    }

    if (strcpy_s(bundleName, bundleNamelen, hapTokenInfoRes.bundleName.c_str()) != EOK ||
        strcpy_s(abilityName, abilityNameLen, abilityInfos[0].name.c_str()) != EOK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] copy bundleName or abilityName failed");
        return SOFTBUS_STRCPY_ERR;
    }

    return SOFTBUS_OK;
}

extern "C" int32_t CheckPushPermission()
{
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto type = Security::AccessToken::AccessTokenKit::GetTokenType(callerToken);
    if (type != Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] push must be native sa");
        return SOFTBUS_TRANS_TOKEN_HAP_ERR;
    }
    TRANS_LOGI(TRANS_SVC, "[br_proxy] The push identity passes the authentication.");
    return SOFTBUS_OK;
}