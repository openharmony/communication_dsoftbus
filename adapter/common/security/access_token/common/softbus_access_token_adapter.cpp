/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "softbus_access_token_adapter.h"

#include <securec.h>

#include "accesstoken_kit.h"
#include "comm_log.h"
#include "ipc_skeleton.h"
#include "privacy_kit.h"
#include "regex.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "softbus_permission.h"
#include "tokenid_kit.h"

#define DMS_COLLABATION_NAME_PREFIX "ohos.dtbcollab.dms"
static PermissionChangeCb g_permissionChangeCb = nullptr;
constexpr int32_t JUDG_CNT = 1;
constexpr int32_t DEVICE_KEY_SA_CNT = 3;
const char *SAMGR_PROCESS_NAME = "samgr";
const char *DMS_PROCESS_NAME = "distributedsched";
const std::string DEVICE_KEY_SA_PROCESS_NAME[DEVICE_KEY_SA_CNT] = { "distributedsched", "distributedfiledaemon",
    "distributeddata" };

namespace OHOS {
using namespace Security::AccessToken;
class SoftBusAccessTokenAdapter : public PermStateChangeCallbackCustomize {
public:
    SoftBusAccessTokenAdapter(const PermStateChangeScope &scopeInfo, std::string _pkgName, int32_t _pid)
        : PermStateChangeCallbackCustomize(scopeInfo), pkgName(_pkgName), pid(_pid) {}
    ~ SoftBusAccessTokenAdapter(void) {}
    void PermStateChangeCallback(PermStateChangeInfo &result) override;

private:
    std::string pkgName;
    int32_t pid;
};

extern "C" {
bool SoftBusCheckIsSystemService(uint64_t tokenId)
{
    auto type = AccessTokenKit::GetTokenTypeFlag((AccessTokenID)tokenId);
    COMM_LOGD(COMM_ADAPTER, "access token type=%{public}d", type);
    return type == ATokenTypeEnum::TOKEN_NATIVE;
}

bool SoftBusCheckIsSystemApp(uint64_t tokenId)
{
    return TokenIdKit::IsSystemAppByFullTokenID(tokenId);
}

bool SoftBusCheckIsNormalApp(uint64_t fullTokenId, const char *sessionName)
{
    if (sessionName == nullptr) {
        COMM_LOGE(COMM_PERM, "invalid param, sessionName is nullptr");
        return false;
    }

    // The authorization of dbind and dtbcollab are granted through Samgr and DMS, and there is no control here
    #define DBINDER_BUS_NAME_PREFIX "DBinder"
    if (strncmp(sessionName, DBINDER_BUS_NAME_PREFIX, strlen(DBINDER_BUS_NAME_PREFIX)) == 0) {
        return false;
    }

    if (strncmp(sessionName, DMS_COLLABATION_NAME_PREFIX, strlen(DMS_COLLABATION_NAME_PREFIX)) == 0) {
        return false;
    }

    auto tokenType = AccessTokenKit::GetTokenTypeFlag((AccessTokenID)fullTokenId);
    if (tokenType == ATokenTypeEnum::TOKEN_NATIVE) {
        return false;
    } else if (tokenType == ATokenTypeEnum::TOKEN_HAP) {
        bool isSystemApp = TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
        if (isSystemApp) {
            return false;
        }
        COMM_LOGI(COMM_ADAPTER, "The caller is a normal app");
        return true;
    }
    return false;
}

bool SoftBusCheckIsAccessAndRecordAccessToken(uint64_t tokenId, const char *permission)
{
    if (permission == nullptr) {
        COMM_LOGE(COMM_PERM, "invalid param, permission is nullptr");
        return false;
    }

    int32_t ret = AccessTokenKit::VerifyAccessToken((AccessTokenID)tokenId, permission);
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag((AccessTokenID)tokenId);
    int32_t successCnt = (int32_t)(ret == Security::AccessToken::PERMISSION_GRANTED);
    int32_t failCnt = JUDG_CNT - successCnt;
    if (tokenType == ATokenTypeEnum::TOKEN_HAP) {
        int32_t tmp =
            PrivacyKit::AddPermissionUsedRecord(tokenId, permission, successCnt, failCnt);
        if (tmp != Security::AccessToken::RET_SUCCESS) {
            COMM_LOGW(COMM_ADAPTER,
                "AddPermissionUsedRecord failed, permissionName=%{public}s, successCnt=%{public}d, failCnt=%{public}d, "
                "tmp=%{public}d", permission, successCnt, failCnt, tmp);
        }
    }
    return ret == Security::AccessToken::PERMISSION_GRANTED;
}

int32_t SoftBusCalcPermType(uint64_t fullTokenId, pid_t uid, pid_t pid)
{
    if (uid == static_cast<pid_t>(getuid()) && pid == getpid()) {
        COMM_LOGI(COMM_PERM, "self app");
        return SELF_APP;
    }

    auto tokenType = AccessTokenKit::GetTokenTypeFlag((AccessTokenID)fullTokenId);
    if (tokenType == ATokenTypeEnum::TOKEN_NATIVE) {
        return NATIVE_APP;
    } else if (tokenType == ATokenTypeEnum::TOKEN_HAP) {
        bool isSystemApp = TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
        if (isSystemApp) {
            return SYSTEM_APP;
        }
    }
    return NORMAL_APP;
}

int32_t SoftBusCheckDynamicPermission(uint64_t tokenId)
{
    auto tokenType = AccessTokenKit::GetTokenTypeFlag((AccessTokenID)tokenId);
    if (tokenType != ATokenTypeEnum::TOKEN_NATIVE) {
        COMM_LOGE(COMM_PERM, "not native call");
        return SOFTBUS_PERMISSION_DENIED;
    }
    NativeTokenInfo nativeTokenInfo;
    int32_t result = AccessTokenKit::GetNativeTokenInfo(tokenId, nativeTokenInfo);
    if (result == SOFTBUS_OK && nativeTokenInfo.processName == SAMGR_PROCESS_NAME) {
        return SOFTBUS_OK;
    }
    COMM_LOGE(COMM_PERM,
        "check dynamic permission failed, processName=%{private}s", nativeTokenInfo.processName.c_str());
    return SOFTBUS_PERMISSION_DENIED;
}

void SoftBusAccessTokenAdapter::PermStateChangeCallback(PermStateChangeInfo &result)
{
    COMM_LOGI(COMM_PERM, "permission changed. permissionName=%{public}s", result.permissionName.c_str());
    if (g_permissionChangeCb == nullptr) {
        COMM_LOGE(COMM_PERM, "g_permissionChangeCb is nullptr");
        return;
    }

    if (g_permissionChangeCb(result.permStateChangeType, this->pkgName.c_str(), pid) != SOFTBUS_OK) {
        COMM_LOGE(COMM_PERM, "InformPermissionChange fail");
    }
}

void SoftBusRegisterDataSyncPermission(
    const uint64_t tonkenId, const char *permissionName, const char *pkgName, int32_t pid)
{
    if (permissionName == nullptr || pkgName == nullptr) {
        COMM_LOGE(COMM_PERM, "invalid param, permissionName or pkgName is nullptr");
        return;
    }

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {permissionName};
    scopeInfo.tokenIDs = {tonkenId};
    std::shared_ptr<SoftBusAccessTokenAdapter> callbackPtr_ =
        std::make_shared<SoftBusAccessTokenAdapter>(scopeInfo, pkgName, pid);
    COMM_LOGI(COMM_PERM, "after register. tokenId=%{public}" PRIu64, tonkenId);
    if (AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr_) != SOFTBUS_OK) {
        COMM_LOGE(COMM_PERM, "RegisterPermStateChangeCallback failed.");
    }
}

void SoftBusRegisterPermissionChangeCb(PermissionChangeCb cb)
{
    g_permissionChangeCb = cb;
}

int32_t SoftBusGetAccessTokenType(uint64_t tokenId)
{
    auto tokenType = AccessTokenKit::GetTokenTypeFlag((AccessTokenID)tokenId);
    return (int32_t)tokenType;
}

void SoftBusGetTokenNameByTokenType(
    char *tokenName, int32_t nameLen, uint64_t tokenId, SoftBusAccessTokenType tokenType)
{
    if (tokenName == nullptr || nameLen <= 0) {
        COMM_LOGE(COMM_PERM, "invalid param, tokenName is nullptr or nameLen less then zero");
        return;
    }

    int32_t ret = ERR_OK;
    switch ((ATokenTypeEnum)tokenType) {
        case ATokenTypeEnum::TOKEN_NATIVE: {
            NativeTokenInfo nativeTokenInfo;
            ret = AccessTokenKit::GetNativeTokenInfo(tokenId, nativeTokenInfo);
            if (ret != ERR_OK) {
                COMM_LOGW(COMM_PERM, "GetNativeTokenInfo return ret=%{public}d", ret);
                return;
            }
            if (strncpy_s(tokenName, nameLen, nativeTokenInfo.processName.c_str(), nameLen - 1) != EOK) {
                COMM_LOGW(COMM_PERM, "strncpy_s processName failed");
            }
            break;
        }
        case ATokenTypeEnum::TOKEN_HAP: {
            HapTokenInfo hapTokenInfo;
            ret = AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfo);
            if (ret != ERR_OK) {
                COMM_LOGW(COMM_PERM, "GetHapTokenInfo return ret=%{public}d", ret);
                return;
            }
            if (strncpy_s(tokenName, nameLen, hapTokenInfo.bundleName.c_str(), nameLen - 1) != EOK) {
                COMM_LOGW(COMM_PERM, "strncpy_s bundleName failed");
            }
            break;
        }
        case ATokenTypeEnum::TOKEN_SHELL:
        default: {
            COMM_LOGW(COMM_PERM, "invalid tokenType=%{public}d", (int32_t)tokenType);
            break;
        }
    }
}

int32_t SoftBusCheckDmsServerPermission(uint64_t tokenId)
{
    auto tokenType = AccessTokenKit::GetTokenTypeFlag((AccessTokenID)tokenId);
    if (tokenType != ATokenTypeEnum::TOKEN_NATIVE) {
        COMM_LOGE(COMM_PERM, "not native call");
        return SOFTBUS_PERMISSION_DENIED;
    }
    NativeTokenInfo nativeTokenInfo;
    int32_t result = AccessTokenKit::GetNativeTokenInfo(tokenId, nativeTokenInfo);
    if (result == SOFTBUS_OK && nativeTokenInfo.processName == DMS_PROCESS_NAME) {
        return SOFTBUS_OK;
    }
    COMM_LOGE(COMM_PERM,
        "check dms server permission failed, processName=%{private}s", nativeTokenInfo.processName.c_str());
    return SOFTBUS_PERMISSION_DENIED;
}

bool SoftBusCheckIsCollabApp(uint64_t fullTokenId, const char *sessionName)
{
    if (sessionName == nullptr) {
        COMM_LOGE(COMM_PERM, "invalid param, sessionName is nullptr");
        return false;
    }

    if (strncmp(sessionName, DMS_COLLABATION_NAME_PREFIX, strlen(DMS_COLLABATION_NAME_PREFIX)) != 0) {
        return false;
    }

    auto tokenType = AccessTokenKit::GetTokenTypeFlag((AccessTokenID)fullTokenId);
    if (tokenType != ATokenTypeEnum::TOKEN_HAP) {
        return false;
    }
    COMM_LOGI(COMM_ADAPTER, "The caller is an app");
    return true;
}

bool SoftBusCheckIsAccess(void)
{
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    int32_t ret = AccessTokenKit::VerifyAccessToken((AccessTokenID)callingTokenId,
        OHOS_PERMISSION_DISTRIBUTED_DATASYNC);
    bool isAccessToken = (ret == PERMISSION_GRANTED);
    return isAccessToken;
}

bool SoftBusSaCanUseDeviceKey(uint64_t tokenId)
{
    auto tokenType = AccessTokenKit::GetTokenTypeFlag(static_cast<AccessTokenID>(tokenId));
    if (tokenType != ATokenTypeEnum::TOKEN_NATIVE) {
        COMM_LOGE(COMM_PERM, "not native call");
        return false;
    }
    NativeTokenInfo nativeTokenInfo;
    int32_t result = AccessTokenKit::GetNativeTokenInfo(tokenId, nativeTokenInfo);
    if (result == SOFTBUS_OK) {
        for (int32_t i = 0; i < DEVICE_KEY_SA_CNT; i++) {
            if (nativeTokenInfo.processName.compare(DEVICE_KEY_SA_PROCESS_NAME[i]) == 0) {
                return true;
            }
        }
        COMM_LOGE(COMM_PERM, "check dk server permission failed, processName=%{private}s",
            nativeTokenInfo.processName.c_str());
    }
    return false;
}
}
} // namespace OHOS