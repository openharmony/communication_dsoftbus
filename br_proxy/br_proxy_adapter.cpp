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
#include "app_mgr_constants.h"
#include "app_mgr_interface.h"
#include "allow_type.h"
#include "bundle_mgr_interface.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "res_sched_client.h"
#include "res_type.h"
#include "softbus_error_code.h"
#include "standby_service_client.h"
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
                             int resultCode) override
    {
        TRANS_LOGI(TRANS_SVC, "[br_proxy] OnAbilityConnectDone");
        OHOS::AAFwk::AbilityManagerClient::GetInstance()->ReleaseCall(this, element);
        (void)remoteObject;
        (void)resultCode;
    }
 
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
                                int resultCode) override
    {
        TRANS_LOGI(TRANS_SVC, "[br_proxy] OnAbilityDisconnectDone");
        (void)resultCode;
    }
};

extern "C" int32_t StartAbility(const char *bundleName, const char *abilityName,
    int32_t appIndex, int32_t userId)
{
    TRANS_LOGI(TRANS_SVC, "[br_proxy] appIndex:%{public}d, userId:%{public}d", appIndex, userId);
    OHOS::AAFwk::Want want;
    want.SetElementName(bundleName, abilityName);
    want.SetParam(AAFwk::Want::PARAM_APP_CLONE_INDEX_KEY, appIndex);
    sptr<AAFwk::IAbilityConnection> abilityConnection = new BrProxyAbility();
    std::string errMsg = "error";
    return OHOS::AAFwk::AbilityManagerClient::GetInstance()->
        StartAbilityByCallWithErrMsg(want, abilityConnection, nullptr, userId, errMsg);
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

sptr<AppExecFwk::IAppMgr> GetAppManagerInstance()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] systemAbiliityManager is nullptr");
        return nullptr;
    }
    sptr<IRemoteObject> appObject = systemAbilityManager->GetSystemAbility(APP_MGR_SERVICE_ID);
    if (appObject == nullptr) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] appObject is nullptr");
        return nullptr;
    }
    return iface_cast<AppExecFwk::IAppMgr>(appObject);
}

extern "C" bool GetRunningProcessInformation(const std::string bundleName, int32_t userId, pid_t uid, pid_t *pid)
{
    if (pid == nullptr) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] invalid param");
        return false;
    }
    std::vector<AppExecFwk::RunningProcessInfo> infos;
    sptr<AppExecFwk::IAppMgr> appMgr = GetAppManagerInstance();
    if (appMgr == nullptr) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] GetAppManagerInstance failed");
        return false;
    }
    int32_t ret = appMgr->GetRunningProcessInformation(bundleName, userId, infos);
    if (ret != ERR_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] GetRunningProcessInformation failed: %{public}d", ret);
        return false;
    }
    if (infos.size() <= 0) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] RunningProcessInfo size: %{public}zu", infos.size());
        return false;
    }
    for (auto info : infos) {
        if (info.uid_ == uid && info.processType_ == AppExecFwk::ProcessType::NORMAL) {
            *pid = info.pid_;
            return true;
        }
    }
    TRANS_LOGE(TRANS_SVC, "[br_proxy] find infos failed!");
    return false;
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
    pid_t callerUid = IPCSkeleton::GetCallingUid();
    std::string name;
    ret = bundleMgr->GetNameAndIndexForUid(callerUid, name, *appIndex);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGI(TRANS_SVC, "[br_proxy] get appIndex failed! uid:%{public}d", callerUid);
        return ret;
    }
    TRANS_LOGI(TRANS_SVC, "[br_proxy] get appIndex:%{public}d, uid:%{public}d", *appIndex, callerUid);
    return SOFTBUS_OK;
}

extern "C" int32_t Unrestricted(const char *bundleName, pid_t pid, pid_t uid, bool isThaw)
{
    if (bundleName == nullptr) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] bundleName is null");
        return SOFTBUS_INVALID_PARAM;
    }
    #define SOFTBUS_SERVER_SA_ID 4700
    uint32_t type = OHOS::ResourceSchedule::ResType::RES_TYPE_SA_CONTROL_APP_EVENT;
    int64_t status = isThaw ? OHOS::ResourceSchedule::ResType::SaControlAppStatus::SA_START_APP:
        OHOS::ResourceSchedule::ResType::SaControlAppStatus::SA_STOP_APP;
    std::unordered_map<std::string, std::string> payload;
    payload.emplace("saId", std::to_string(SOFTBUS_SERVER_SA_ID));
    payload.emplace("saName", "softbus_server");
    payload.emplace("pid", std::to_string(pid));
    payload.emplace("uid", std::to_string(uid));
    payload.emplace("bundleName", bundleName);
    OHOS::ResourceSchedule::ResSchedClient::GetInstance().ReportData(type, status, payload);
    if (!isThaw) {
        return SOFTBUS_OK;
    }
    auto resourceRequest = OHOS::sptr<OHOS::DevStandbyMgr::ResourceRequest>(
        new OHOS::DevStandbyMgr::ResourceRequest()
    );
    resourceRequest->SetAllowType(OHOS::DevStandbyMgr::AllowType::NETWORK);
    resourceRequest->SetUid(uid);
    resourceRequest->SetName("softbus_server");
    resourceRequest->SetDuration(5); // 5s
    resourceRequest->SetReason("brproxy");
    resourceRequest->SetReasonCode(OHOS::DevStandbyMgr::ReasonCodeEnum::REASON_NATIVE_API);
    int32_t ret = OHOS::DevStandbyMgr::StandbyServiceClient::GetInstance().ApplyAllowResource(resourceRequest);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] ApplyAllowResource failed! ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}