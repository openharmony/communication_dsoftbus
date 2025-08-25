/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include <map>
#include <securec.h>
#include <vector>

#include "access_control.h"
#include "access_control_profile.h"
#include "anonymizer.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "comm_log.h"
#include "distributed_device_profile_client.h"
#include "distributed_device_profile_enums.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "lnn_ohos_account_adapter.h"
#include "os_account_manager.h"
#include "permission_entry.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_os_account_adapter.h"
#include "softbus_proxychannel_callback.h"
#include "system_ability_definition.h"
#include "trans_session_account_adapter.h"
#include "trans_session_manager.h"

#ifdef SUPPORT_ABILITY_RUNTIME
#include "app_mgr_interface.h"
#include "app_mgr_proxy.h"
#endif

#define DEFAULT_ACCOUNT_UID "ohosAnonymousUid"
#define DBINDER_PREFIX "DBinder"
#define DBINDER_DMS "DBinder5522"

namespace {
    using namespace OHOS::DistributedDeviceProfile;
    using namespace OHOS;
}

static int32_t TransCheckAccessControl(uint64_t callingTokenId, const char *deviceId)
{
    char *tmpName = nullptr;
    Anonymize(deviceId, &tmpName);
    COMM_LOGI(COMM_PERM, "tokenId=%{public}" PRIu64 ", deviceId=%{public}s", callingTokenId, AnonymizeWrapper(tmpName));
    AnonymizeFree(tmpName);

    std::string active = std::to_string(static_cast<int>(Status::ACTIVE));
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    std::string tokenIdStr = std::to_string(callingTokenId);
    parms.insert({{"tokenId", tokenIdStr}, {"trustDeviceId", deviceId}, {"status", active}});

    int32_t ret = DistributedDeviceProfileClient::GetInstance().GetAccessControlProfile(parms, profile);
    COMM_LOGI(COMM_PERM, "profile size=%{public}zu, ret=%{public}d", profile.size(), ret);
    if (profile.empty()) {
        COMM_LOGE(COMM_PERM, "check acl failed:tokenId=%{public}" PRIu64, callingTokenId);
        return SOFTBUS_TRANS_CHECK_ACL_FAILED;
    }
    for (auto &item : profile) {
        COMM_LOGI(COMM_PERM, "BindLevel=%{public}d, BindType=%{public}d", item.GetBindLevel(), item.GetBindType());
    }

    return SOFTBUS_OK;
}

static int32_t TransCheckSourceAccessControl(uint64_t myTokenId, const char *myDeviceId,
    int32_t myUserId, char *accountId, const char *peerDeviceId)
{
    char *tmpMyDeviceId = nullptr;
    char *tmpPeerDeviceId = nullptr;
    char *tmpAccountId = nullptr;
    Anonymize(myDeviceId, &tmpMyDeviceId);
    Anonymize(peerDeviceId, &tmpPeerDeviceId);
    Anonymize(accountId, &tmpAccountId);
    COMM_LOGI(COMM_PERM, "accesserDeviceId=%{public}s, accesserTokenId=%{public}d,\
        accesserUserId=%{public}d, accesserAccountId=%{public}s, accesseeDeviceId=%{public}s",
        AnonymizeWrapper(tmpMyDeviceId), (int32_t)myTokenId, myUserId,
        AnonymizeWrapper(tmpAccountId), AnonymizeWrapper(tmpPeerDeviceId));
    AnonymizeFree(tmpMyDeviceId);
    AnonymizeFree(tmpPeerDeviceId);
    AnonymizeFree(tmpAccountId);

    std::string active = std::to_string(static_cast<int>(Status::ACTIVE));
    std::vector<AccessControlProfile> profile;
    std::map<std::string, std::string> parms;
    parms.insert({{"accesserDeviceId", myDeviceId}, {"accesserTokenId", std::to_string((int32_t)myTokenId)},
        {"accesserUserId", std::to_string(myUserId)}, {"accesserAccountId", accountId},
        {"accesseeDeviceId", peerDeviceId}});
    int32_t ret = DistributedDeviceProfileClient::GetInstance().GetAccessControlProfile(parms, profile);
    COMM_LOGI(COMM_PERM, "profile size=%{public}zu, ret=%{public}d", profile.size(), ret);
    if (profile.empty()) {
        COMM_LOGE(COMM_PERM, "check acl failed:tokenId=%{public}" PRIu64, myTokenId);
        return SOFTBUS_TRANS_CHECK_ACL_FAILED;
    }
    for (auto &item : profile) {
        COMM_LOGI(COMM_PERM, "BindLevel=%{public}d, BindType=%{public}d", item.GetBindLevel(), item.GetBindType());
    }
    return SOFTBUS_OK;
}

static int32_t TransCheckSinkAccessControl(const std::map<std::string, std::string> parms)
{
    std::string active = std::to_string(static_cast<int>(Status::ACTIVE));
    std::vector<AccessControlProfile> profile;
    int32_t ret = DistributedDeviceProfileClient::GetInstance().GetAccessControlProfile(parms, profile);
    if (profile.empty()) {
        COMM_LOGE(COMM_PERM, "profile size=%{public}zu, ret=%{public}d", profile.size(), ret);
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
        COMM_LOGE(COMM_PERM, "peerNetworkId is null");
        return SOFTBUS_INVALID_PARAM;
    }

    uint64_t callingTokenId = OHOS::IPCSkeleton::GetCallingFullTokenID();
    if (callingTokenId == TOKENID_NOT_SET) {
        return SOFTBUS_OK;
    }

    int32_t accessTokenType = SoftBusGetAccessTokenType(callingTokenId);
    if (accessTokenType != ACCESS_TOKEN_TYPE_HAP) {
        COMM_LOGI(COMM_PERM, "accessTokenType=%{public}d, not hap, no verification required", accessTokenType);
        return SOFTBUS_OK;
    }

    pid_t callingUid = OHOS::IPCSkeleton::GetCallingUid();
    int32_t appUserId = GetOsAccountLocalIdFromUidAdapter(callingUid);
    bool isForegroundUser = false;
    int32_t ret = IsOsAccountForegroundAdapter(appUserId, isForegroundUser);
    if (ret != ERR_OK) {
        COMM_LOGE(COMM_PERM, "app userId %{public}d is not Foreground, ret:%{public}d", appUserId, ret);
        return ret;
    }
    if (!isForegroundUser) {
        COMM_LOGE(COMM_PERM, "app userId is not Foreground");
        return SOFTBUS_TRANS_BACKGROUND_USER_DENIED;
    }

    char myDeviceId[UDID_BUF_LEN] = {0};
    ret = LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, myDeviceId, sizeof(myDeviceId));
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_PERM, "get local udid failed, tokenId=%{public}" PRIu64 ", ret=%{public}d",
            callingTokenId, ret);
        return ret;
    }
    char peerDeviceId[UDID_BUF_LEN] = {0};
    ret = LnnGetRemoteStrInfo(peerNetworkId, STRING_KEY_DEV_UDID, peerDeviceId, sizeof(peerDeviceId));
    if (ret != SOFTBUS_OK) {
        char *tmpPeerNetworkId = nullptr;
        Anonymize(peerNetworkId, &tmpPeerNetworkId);
        COMM_LOGE(COMM_PERM,
            "get remote udid failed, tokenId=%{public}" PRIu64 ", networkId=%{public}s, ret=%{public}d",
            callingTokenId, AnonymizeWrapper(tmpPeerNetworkId), ret);
        AnonymizeFree(tmpPeerNetworkId);
        return ret;
    }

    char accountId[ACCOUNT_UID_LEN_MAX] = {0};
    uint32_t size = 0;
    (void)GetOsAccountUidByUserId(accountId, ACCOUNT_UID_LEN_MAX - 1, &size, appUserId);
    return TransCheckSourceAccessControl(callingTokenId, myDeviceId, appUserId, accountId, peerDeviceId);
}

int32_t CheckSecLevelPublic(const char *mySessionName, const char *peerSessionName)
{
    if (mySessionName == nullptr || peerSessionName == nullptr) {
        COMM_LOGE(COMM_PERM, "param is null");
        return SOFTBUS_INVALID_PARAM;
    }

    if (strlen(peerSessionName) == 0) {
        return SOFTBUS_OK;
    }

    if (strcmp(mySessionName, peerSessionName) != 0) {
        if (!PermIsSecLevelPublic(mySessionName)) {
            char *tmpName = nullptr;
            Anonymize(mySessionName, &tmpName);
            COMM_LOGE(COMM_PERM, "SecLevel mismatch, sessionName=%{public}s", AnonymizeWrapper(tmpName));
            AnonymizeFree(tmpName);
            return SOFTBUS_PERMISSION_DENIED;
        }
    }

    return SOFTBUS_OK;
}

static int32_t CheckServerAccessControl(const AppInfo *appInfo, uint64_t myTokenId,
    int32_t appUserId, const char *myDeviceId, const char *peerDeviceId)
{
    char accountId[ACCOUNT_UID_LEN_MAX] = {0};
    uint32_t size = 0;
    (void)GetOsAccountUidByUserId(accountId, ACCOUNT_UID_LEN_MAX - 1, &size, appUserId);
    char *tmpMyDeviceId = nullptr;
    char *tmpPeerDeviceId = nullptr;
    char *tmpPeerAccountId = nullptr;
    char *tmpMyAccountId = nullptr;
    Anonymize(myDeviceId, &tmpMyDeviceId);
    Anonymize(peerDeviceId, &tmpPeerDeviceId);
    Anonymize(appInfo->peerData.accountId, &tmpPeerAccountId);
    Anonymize(accountId, &tmpMyAccountId);
    COMM_LOGI(COMM_PERM, "accesserDeviceId=%{public}s, accesserTokenId=%{public}d,\
        accesserUserId=%{public}d, accesserAccountId=%{public}s,\
        accesseeDeviceId=%{public}s, accesseeTokenId=%{public}d,\
        accesseeUserId=%{public}d, accesserAccountId=%{public}s",
        AnonymizeWrapper(tmpPeerDeviceId), (int32_t)(appInfo->callingTokenId),
        appInfo->peerData.userId, AnonymizeWrapper(tmpPeerAccountId),
        AnonymizeWrapper(tmpMyDeviceId), (int32_t)myTokenId, appUserId, AnonymizeWrapper(tmpMyAccountId));
    AnonymizeFree(tmpMyDeviceId);
    AnonymizeFree(tmpPeerDeviceId);
    AnonymizeFree(tmpPeerAccountId);
    AnonymizeFree(tmpMyAccountId);
    std::map<std::string, std::string> parms;
    parms.insert({{"accesserDeviceId", peerDeviceId},
        {"accesserTokenId", std::to_string((int32_t)(appInfo->callingTokenId))},
        {"accesserUserId", std::to_string(appInfo->peerData.userId)},
        {"accesserAccountId", appInfo->peerData.accountId},
        {"accesseeDeviceId", myDeviceId}, {"accesseeTokenId", std::to_string((int32_t)myTokenId)},
        {"accesseeUserId", std::to_string(appUserId)}, {"accesseeAccountId", accountId}});
    return TransCheckSinkAccessControl(parms);
}

static int32_t CheckSinkAccessControl(const AppInfo *appInfo, uint64_t myTokenId,
    int32_t appUserId, const char *myDeviceId)
{
    char peerNetWorkId[NETWORK_ID_BUF_LEN] = {0};
    int32_t ret = LnnGetNetworkIdByUuid(appInfo->peerData.deviceId, peerNetWorkId, sizeof(peerNetWorkId));
    if (ret != SOFTBUS_OK) {
        char *tmpPeerUUId = nullptr;
        Anonymize(appInfo->peerData.deviceId, &tmpPeerUUId);
        COMM_LOGE(COMM_PERM, "get peerNetWorkId failed, uuid=%{public}s ret=%{public}d",
            AnonymizeWrapper(tmpPeerUUId), ret);
        AnonymizeFree(tmpPeerUUId);
        return ret;
    }
    char peerDeviceId[UDID_BUF_LEN] = {0};
    ret = LnnGetRemoteStrInfo(peerNetWorkId, STRING_KEY_DEV_UDID, peerDeviceId, sizeof(peerDeviceId));
    if (ret != SOFTBUS_OK) {
        char *tmpPeerNetworkId = nullptr;
        Anonymize(appInfo->peerNetWorkId, &tmpPeerNetworkId);
        COMM_LOGE(COMM_PERM, "get remote udid failed, tokenId=%{public}" PRIu64 ", networkId=%{public}s,\
            ret=%{public}d",appInfo->callingTokenId, AnonymizeWrapper(tmpPeerNetworkId), ret);
        AnonymizeFree(tmpPeerNetworkId);
        return ret;
    }
    if (appInfo->peerData.userId == INVALID_USER_ID || strlen(appInfo->peerData.accountId) == 0) {
        return TransCheckAccessControl(appInfo->callingTokenId, myDeviceId);
    } else {
        return CheckServerAccessControl(appInfo, myTokenId, appUserId, myDeviceId, peerDeviceId);
    }
}

static int32_t TranCheckSinkAccessControl(const AppInfo *appInfo, uint64_t myTokenId)
{
    int32_t uid = -1;
    int32_t pid = -1;
    int32_t ret = TransProxyGetUidAndPidBySessionName(appInfo->myData.sessionName, &uid, &pid);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_PERM, "get uid fail, uid=%{public}d pid=%{public}d ret=%{public}d", uid, pid, ret);
        return ret;
    }
    int32_t appUserId = GetOsAccountLocalIdFromUidAdapter(uid);
    bool isForegroundUser = false;
    ret = IsOsAccountForegroundAdapter(appUserId, isForegroundUser);
    if (ret != ERR_OK) {
        COMM_LOGE(COMM_PERM, "app userId %{public}d is not foreground, ret:%{public}d", appUserId, ret);
        return ret;
    }
    if (!isForegroundUser) {
        COMM_LOGE(COMM_PERM, "app userId %{public}d is not foreground", appUserId);
        return SOFTBUS_TRANS_BACKGROUND_USER_DENIED;
    }
    char myDeviceId[UDID_BUF_LEN] = {0};
    ret = LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, myDeviceId, sizeof(myDeviceId));
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_PERM, "get deviceId failed, ret=%{public}d", ret);
        return ret;
    }
    return CheckSinkAccessControl(appInfo, myTokenId, appUserId, myDeviceId);
}

int32_t TransCheckServerAccessControl(const AppInfo *appInfo)
{
    if (appInfo == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    char *tmpPeerSessionName = nullptr;
    char *tmpMySessionName = nullptr;
    Anonymize(appInfo->peerData.sessionName, &tmpPeerSessionName);
    Anonymize(appInfo->myData.sessionName, &tmpMySessionName);
    COMM_LOGI(COMM_PERM, "peerSessionName=%{public}s, mySessionName=%{public}s",
        AnonymizeWrapper(tmpPeerSessionName), AnonymizeWrapper(tmpMySessionName));
    AnonymizeFree(tmpPeerSessionName);
    AnonymizeFree(tmpMySessionName);
    uint64_t callingTokenId = appInfo->callingTokenId;
    if (callingTokenId == TOKENID_NOT_SET) {
        return SOFTBUS_OK;
    }
    uint64_t myTokenId = -1;
    int32_t ret = TransGetTokenIdBySessionName(appInfo->myData.sessionName, &myTokenId);
    if (ret != SOFTBUS_OK) {
        char *tmpSessionName = nullptr;
        Anonymize(appInfo->myData.sessionName, &tmpSessionName);
        COMM_LOGE(COMM_PERM, "get local tokenId failed, sessionName=%{public}s, ret=%{public}d",
            AnonymizeWrapper(tmpSessionName), ret);
        AnonymizeFree(tmpSessionName);
        return ret;
    }
    int32_t peerTokenType = SoftBusGetAccessTokenType(callingTokenId);
    int32_t myTokenType = SoftBusGetAccessTokenType(myTokenId);
    if (peerTokenType != myTokenType) {
        const char *mySessionName = appInfo->myData.sessionName;
        const char *peerSessionName = appInfo->peerData.sessionName;
        if (StrStartWith(peerSessionName, DBINDER_DMS) && (peerTokenType == ACCESS_TOKEN_TYPE_NATIVE) &&
            StrStartWith(mySessionName, DBINDER_PREFIX)) {
            return SOFTBUS_OK;
        }
        COMM_LOGE(COMM_PERM, "peerTokenType=%{public}d, myTokenType=%{public}d, not support",
            peerTokenType, myTokenType);
        return SOFTBUS_TRANS_CROSS_LAYER_DENIED;
    }
    if (peerTokenType != ACCESS_TOKEN_TYPE_HAP) {
        COMM_LOGE(COMM_PERM, "peerTokenType=%{public}d, not hap, no verification required", peerTokenType);
        return SOFTBUS_OK;
    }
    return TranCheckSinkAccessControl(appInfo, myTokenId);
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

static void GetForegroundApplications(uint64_t firstTokenId, int32_t *tokenType)
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
static void GetForegroundApplications(uint64_t firstTokenId, int32_t *tokenType)
{
    (void)firstTokenId;
    (void)tokenType;
}
#endif

void TransGetTokenInfo(uint64_t callingId, char *tokenName, int32_t nameLen, int32_t *tokenType)
{
    if (callingId == TOKENID_NOT_SET || tokenName == nullptr || tokenType == nullptr) {
        COMM_LOGE(COMM_PERM, "param is invalid");
        return;
    }

    int32_t accessTokenType = SoftBusGetAccessTokenType(callingId);
    if (accessTokenType == ACCESS_TOKEN_TYPE_NATIVE) {
        *tokenType = SYSTEM_SA_TYPE;
        SoftBusGetTokenNameByTokenType(tokenName, nameLen, callingId, (SoftBusAccessTokenType)accessTokenType);
    } else if (accessTokenType == ACCESS_TOKEN_TYPE_HAP) {
        *tokenType = TOKEN_HAP_TYPE;
        GetForegroundApplications(callingId, tokenType);
        SoftBusGetTokenNameByTokenType(tokenName, nameLen, callingId, (SoftBusAccessTokenType)accessTokenType);
    } else {
        *tokenType = TOKEN_SHELL_TYPE;
    }
}
