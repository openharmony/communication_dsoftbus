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
#include "ability_connect_callback_stub.h"
#include "ability_manager_client.h"
#include "bundle_mgr_interface.h"
#include "iservice_registry.h"
#include "softbus_error_code.h"
#include "system_ability_definition.h"
#include "trans_log.h"

using namespace OHOS;

class BrProxyAbility : public AAFwk::AbilityConnectionStub {
public:
    BrProxyAbility() {
    }
    ~BrProxyAbility() {
    }
    void OnAbilityConnectDone(const AppExecFwk::ElementName &element,
                             const sptr<IRemoteObject> &remoteObject,
                             int resultCode) override {
        TRANS_LOGI(TRANS_SVC, "[br_proxy] OnAbilityConnectDone");
        OHOS::AAFwk::AbilityManagerClient::GetInstance()->ReleaseCall(this, element);
    }
 
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
                                int resultCode) override {
        TRANS_LOGI(TRANS_SVC, "[br_proxy] OnAbilityDisconnectDone");
    }
};


extern "C" int32_t StartAbility(const char *bundleName, const char *abilityName, int32_t appIndex)
{
    TRANS_LOGI(TRANS_SVC, "[br_proxy] appIndex:%{public}d", appIndex);
    OHOS::AAFwk::Want want;
    want.SetElementName(bundleName, abilityName);
    want.SetParam(AAFwk::Want::PARAM_APP_CLONE_INDEX_KEY, appIndex);
    sptr<AAFwk::IAbilityConnection> abilityConnection = new BrProxyAbility();
    std::string errMsg = "error";
    return OHOS::AAFwk::AbilityManagerClient::GetInstance()->
        StartAbilityByCallWithErrMsg(want, abilityConnection, nullptr, -1, errMsg);
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
    std::string bundleName, int32_t *appIndex)
{
    if (abilityName == nullptr || appIndex == nullptr || bundleName.empty()) {
        return SOFTBUS_INVALID_PARAM;
    }
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
    *appIndex = abilityInfos[0].appIndex;
    TRANS_LOGI(TRANS_SVC, "[br_proxy] get appIndex:%{public}d", *appIndex);
    return SOFTBUS_OK;
}