/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include <vector>
#include <map>

#include "accesstoken_kit.h"
#include "access_control.h"
#include "access_control_profile.h"
#include "anonymizer.h"
#ifdef SUPPORT_ABILITY_RUNTIME
#include "app_mgr_interface.h"
#include "app_mgr_proxy.h"
#endif
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "comm_log.h"
#include "distributed_device_profile_client.h"
#include "distributed_device_profile_enums.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "system_ability_definition.h"

namespace {
    using namespace OHOS::DistributedDeviceProfile;
    using namespace OHOS::Security::AccessToken;
    using namespace OHOS;
}

static int32_t TransCheckAccessControl(uint32_t callingTokenId, const char *deviceId)
{
    char *tmpName = nullptr;
    Anonymize(deviceId, &tmpName);
    COMM_LOGI(COMM_PERM, "tokenId=%{public}u, deviceId=%{public}s", callingTokenId, tmpName);
    AnonymizeFree(tmpName);

    std::string active = std::to_string(static_cast<int>(Status::ACTIVE));
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    std::string tokenIdStr = std::to_string(callingTokenId);
    parms.insert({{"tokenId", tokenIdStr}, {"trustDeviceId", deviceId}, {"status", active}});

    int32_t ret = DistributedDeviceProfileClient::GetInstance().GetAccessControlProfile(parms, profile);
    COMM_LOGI(COMM_PERM, "profile size=%{public}zu, ret=%{public}d", profile.size(), ret);
    if (profile.empty()) {
        COMM_LOGE(COMM_PERM, "check acl failed:tokenId=%{public}u", callingTokenId);
        return SOFTBUS_TRANS_CHECK_ACL_FAILED;
    }
    for (auto &item : profile) {
        COMM_LOGI(COMM_PERM, "BindLevel=%{public}d, BindType=%{public}d", item.GetBindLevel(), item.GetBindType());
    }

    return SOFTBUS_OK;
}

int32_t TransCheckClientAccessControl(const char *peerNetworkId)
{
    if (peerNetworkId == nullptr) {
        COMM_LOGE(COMM_PERM, "peerDeviceId is null");
        return SOFTBUS_INVALID_PARAM;
    }

    uint32_t callingTokenId = OHOS::IPCSkeleton::GetCallingTokenID();
    if (callingTokenId == TOKENID_NOT_SET) {
        return SOFTBUS_OK;
    }

    auto tokenType = AccessTokenKit::GetTokenTypeFlag((AccessTokenID)callingTokenId);
    if (tokenType != ATokenTypeEnum::TOKEN_HAP) {
        COMM_LOGI(COMM_PERM, "tokenType=%{public}d, not hap, no verification required", tokenType);
        return SOFTBUS_OK;
    }

    char deviceId[UDID_BUF_LEN] = {0};
    int32_t ret = LnnGetRemoteStrInfo(peerNetworkId, STRING_KEY_DEV_UDID, deviceId, sizeof(deviceId));
    if (ret != SOFTBUS_OK) {
        char *tmpName = nullptr;
        Anonymize(peerNetworkId, &tmpName);
        COMM_LOGE(COMM_PERM, "get remote udid failed, tokenId=%{public}u, networkId=%{public}s, ret=%{public}d",
            callingTokenId, tmpName, ret);
        AnonymizeFree(tmpName);
        return ret;
    }
    return TransCheckAccessControl(callingTokenId, deviceId);
}

int32_t TransCheckServerAccessControl(uint32_t callingTokenId)
{
    if (callingTokenId == TOKENID_NOT_SET) {
        return SOFTBUS_OK;
    }

    auto tokenType = AccessTokenKit::GetTokenTypeFlag((AccessTokenID)callingTokenId);
    if (tokenType != ATokenTypeEnum::TOKEN_HAP) {
        COMM_LOGI(COMM_PERM, "tokenType=%{public}d, not hap, no verification required", tokenType);
        return SOFTBUS_OK;
    }

    char deviceId[UDID_BUF_LEN] = {0};
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, deviceId, sizeof(deviceId));
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_PERM, "get local udid failed, tokenId=%{public}u, ret=%{public}d", callingTokenId, ret);
        return ret;
    }
    return TransCheckAccessControl(callingTokenId, deviceId);
}

uint32_t TransACLGetFirstTokenID(void)
{
    return OHOS::IPCSkeleton::GetFirstTokenID();
}

uint32_t TransACLGetCallingTokenID(void)
{
    return OHOS::IPCSkeleton::GetCallingTokenID();
}

#ifdef SUPPORT_ABILITY_RUNTIME
static sptr<AppExecFwk::IAppMgr> g_appMgrProxy = nullptr;

namespace OHOS {
class AppMgrDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    AppMgrDeathRecipient() = default;
    virtual ~AppMgrDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override
    {
        g_appMgrProxy = nullptr;
        COMM_LOGW(COMM_PERM, "app Manager died");
    }
};
} // namespace OHOS

static void GetForegroundApplications(uint32_t firstTokenId, int32_t *tokenType)
{
    if (g_appMgrProxy == nullptr) {
        sptr<ISystemAbilityManager> abilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (abilityMgr == nullptr) {
            COMM_LOGW(COMM_PERM, "failed to get SystemAbilityManager");
            return;
        }

        sptr<IRemoteObject> remoteObject = abilityMgr->GetSystemAbility(APP_MGR_SERVICE_ID);
        if (remoteObject == nullptr) {
            COMM_LOGW(COMM_PERM, "failed to get app Manager service");
            return;
        }
        sptr<IRemoteObject::DeathRecipient> clientDeath =
            sptr<IRemoteObject::DeathRecipient>(new (std::nothrow) AppMgrDeathRecipient());
        if (clientDeath == nullptr) {
            COMM_LOGW(COMM_PERM, "failed to new DeathRecipient");
            return;
        }
        remoteObject->AddDeathRecipient(clientDeath);
        g_appMgrProxy = iface_cast<AppExecFwk::IAppMgr>(remoteObject);
        if (g_appMgrProxy == nullptr || !g_appMgrProxy->AsObject()) {
            COMM_LOGW(COMM_PERM, "failed to get app mgr proxy");
            return;
        }
        COMM_LOGI(COMM_PERM, "get app mgr proxy success");
    }

    std::vector<AppExecFwk::AppStateData> appList;
    int32_t ret = g_appMgrProxy->GetForegroundApplications(appList);
    if (ret != ERR_OK) {
        COMM_LOGW(COMM_PERM, "GetForegroundApplications return err:%{public}d", ret);
        return;
    }

    for (auto &item : appList) {
        COMM_LOGI(COMM_PERM, "appList %{public}s state:%{public}d token:%{public}u",
            item.bundleName.c_str(), item.state, item.accessTokenId);
        if (firstTokenId == item.accessTokenId) {
            *tokenType = FOREGROUND_APP_TYPE;
            return;
        }
    }
    *tokenType = BACKGROUND_APP_TYPE;
}
#else
static void GetForegroundApplications(uint32_t firstTokenId, int32_t *tokenType)
{
    (void)firstTokenId;
    (void)tokenType;
}
#endif

void TransGetTokenInfo(uint32_t callingId, char *tokenName, int32_t nameLen, int32_t *tokenType)
{
    if (callingId == TOKENID_NOT_SET || tokenName == nullptr || tokenType == nullptr) {
        COMM_LOGE(COMM_PERM, "param is invalid");
        return;
    }

    auto typeFlag = AccessTokenKit::GetTokenTypeFlag((AccessTokenID)callingId);
    if (typeFlag == ATokenTypeEnum::TOKEN_NATIVE) {
        *tokenType = SYSTEM_SA_TYPE;
        NativeTokenInfo tokenInfo;
        int32_t ret = AccessTokenKit::GetNativeTokenInfo(callingId, tokenInfo);
        if (ret != ERR_OK) {
            COMM_LOGW(COMM_PERM, "GetNativeTokenInfo return err:%{public}d", ret);
            return;
        }
        if (strncpy_s(tokenName, nameLen, tokenInfo.processName.c_str(), nameLen - 1) != EOK) {
            COMM_LOGW(COMM_PERM, "strncpy_s processName failed");
        }
    } else if (typeFlag == ATokenTypeEnum::TOKEN_HAP) {
        *tokenType = TOKEN_HAP_TYPE;
        GetForegroundApplications(callingId, tokenType);
        HapTokenInfo hapTokenInfo;
        int32_t ret = AccessTokenKit::GetHapTokenInfo(callingId, hapTokenInfo);
        if (ret != ERR_OK) {
            COMM_LOGW(COMM_PERM, "GetHapTokenInfo return err:%{public}d", ret);
            return;
        }
        if (strncpy_s(tokenName, nameLen, hapTokenInfo.bundleName.c_str(), nameLen - 1) != EOK) {
            COMM_LOGW(COMM_PERM, "strncpy_s bundleName failed");
        }
    } else {
        *tokenType = TOKEN_SHELL_TYPE;
    }
}
