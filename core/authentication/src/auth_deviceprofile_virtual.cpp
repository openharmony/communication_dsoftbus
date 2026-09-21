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
 * See the License for the specific language governing permission and
 * limitations under the License.
 */

#include "auth_deviceprofile.h"

#include <cstring>

#include "bus_center_manager.h"
#include "cJSON.h"
#include "lnn_bus_center_ipc.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"

extern "C" {
bool IsPotentialTrustedDeviceDp(const char *deviceIdHash, bool isOnlyPointToPoint)
{
    (void)deviceIdHash;
    (void)isOnlyPointToPoint;
    return true;
}

bool DpHasAccessControlProfile(const char *udid, bool isNeedUserId, int32_t localUserId)
{
    (void)udid;
    (void)isNeedUserId;
    (void)localUserId;
    return false;
}

void UpdateDpSameAccount(UpdateDpAclParams *aclParams, SessionKey sessionKey, bool isNeedUpdateDk,
    AclWriteState aclState)
{
    (void)aclParams;
    (void)sessionKey;
    (void)isNeedUpdateDk;
    (void)aclState;
}

void UpdateDpSameAccountWithoutUserKey(UpdateDpAclParams *aclParams, AclWriteState aclState)
{
    (void)aclParams;
    (void)aclState;
}

void DelNotTrustDevice(const char *udid)
{
    (void)udid;
}

void DelSessionKeyProfile(int32_t sessionKeyId)
{
    (void)sessionKeyId;
}

bool GetSessionKeyProfile(int32_t sessionKeyId, uint8_t *sessionKey, uint32_t *length)
{
    (void)sessionKeyId;
    (void)sessionKey;
    (void)length;
    return false;
}

int32_t GetAccessUkIdSameAccount(const AuthACLInfo *acl, int32_t *ukId, uint64_t *time)
{
    (void)acl;
    (void)ukId;
    (void)time;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t GetAccessUkIdDiffAccountWithUserLevel(const AuthACLInfo *acl, int32_t *ukId, uint64_t *time)
{
    (void)acl;
    (void)ukId;
    (void)time;
    return SOFTBUS_AUTH_ACL_NOT_FOUND;
}

int32_t GetAccessUkIdDiffAccount(const AuthACLInfo *acl, int32_t *ukId, uint64_t *time)
{
    (void)acl;
    (void)ukId;
    (void)time;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t GetAccessUkByUkId(int32_t sessionKeyId, uint8_t *uk, uint32_t ukLen)
{
    (void)sessionKeyId;
    (void)uk;
    (void)ukLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

void UpdateAssetSessionKeyByAcl(
    AuthACLInfo *info, uint8_t *sessionKey, uint32_t sessionKeyLen, int32_t *sessionKeyId, bool isSameAccount)
{
    (void)info;
    (void)sessionKey;
    (void)sessionKeyLen;
    (void)sessionKeyId;
    (void)isSameAccount;
}

bool IsSKIdInvalid(int32_t sessionKeyId, const char *accountHash, const char *udidShortHash, int32_t userId)
{
    (void)sessionKeyId;
    (void)accountHash;
    (void)udidShortHash;
    (void)userId;
    return false;
}

int32_t SelectAllAcl(TrustedInfo **trustedInfoArray, uint32_t *num)
{
    (void)trustedInfoArray;
    (void)num;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool IsTrustedDeviceFromAccess(const char *peerAccountHash, const char *peerUdid, int32_t peerUserId)
{
    (void)peerAccountHash;
    (void)peerUdid;
    (void)peerUserId;
    return false;
}

bool IsExistUkInAclProfile(const char *localUdid, const char *peerUdid)
{
    (void)localUdid;
    (void)peerUdid;
    return false;
}

void UpdateGroupShareToDp(SoftBusAclInfo *peerAclInfo, int32_t creIdType, SessionKey sessionKey, bool isNeedUpdateDk)
{
    (void)peerAclInfo;
    (void)creIdType;
    (void)sessionKey;
    (void)isNeedUpdateDk;
}

int32_t GetAccessUkIdByGroupShare(const AuthACLInfo *acl, int32_t *ukId, uint64_t *time)
{
    (void)acl;
    (void)ukId;
    (void)time;
    return SOFTBUS_NOT_IMPLEMENT;
}

static char *PackCommandAclMsg(const char *peerUdid, int32_t peerUserId, const char *credId)
{
    int32_t localUserId = JudgeDeviceTypeAndGetOsAccountIds();
    const NodeInfo *localNode = LnnGetLocalNodeInfo();
    const char *localUdid = (localNode != nullptr) ? localNode->deviceInfo.deviceUdid : "";
    const char *localName = (localNode != nullptr) ? localNode->deviceInfo.deviceName : "";
    cJSON *json = cJSON_CreateObject();
    if (json == nullptr) {
        LNN_LOGE(LNN_STATE, "create json object fail");
        return nullptr;
    }
    (void)AddNumberToJsonObject(json, ACL_KEY_BIND_TYPE, ACL_BIND_TYPE_P2P);
    (void)AddNumberToJsonObject(json, ACL_KEY_AUTH_TYPE, ACL_AUTH_TYPE_ACROSS_ACCOUNT);
    (void)AddNumberToJsonObject(json, ACL_KEY_BIND_LEVEL, ACL_BIND_LEVEL_APP);
    (void)AddStringToJsonObject(json, ACL_KEY_TRUST_DEVICE_ID, peerUdid);
    cJSON *accesser = cJSON_CreateObject();
    if (accesser != nullptr) {
        (void)AddStringToJsonObject(accesser, ACL_KEY_DEVICE_ID, localUdid);
        (void)AddNumberToJsonObject(accesser, ACL_KEY_USER_ID, localUserId);
        (void)AddStringToJsonObject(accesser, ACL_KEY_ACCOUNT_ID, "-1");
        (void)AddNumberToJsonObject(accesser, ACL_KEY_TOKEN_ID, 0);
        (void)AddStringToJsonObject(accesser, ACL_KEY_BUNDLE_NAME, "softbus_auth");
        (void)AddStringToJsonObject(accesser, ACL_KEY_DEVICE_NAME, localName);
        (void)AddStringToJsonObject(accesser, ACL_KEY_CREDENTIAL_ID, credId);
        cJSON_AddItemToObject(json, ACL_KEY_ACCESSER, accesser);
    }
    cJSON *accessee = cJSON_CreateObject();
    if (accessee != nullptr) {
        (void)AddStringToJsonObject(accessee, ACL_KEY_DEVICE_ID, peerUdid);
        (void)AddNumberToJsonObject(accessee, ACL_KEY_USER_ID, peerUserId);
        (void)AddStringToJsonObject(accessee, ACL_KEY_ACCOUNT_ID, "-1");
        (void)AddNumberToJsonObject(accessee, ACL_KEY_TOKEN_ID, 0);
        (void)AddStringToJsonObject(accessee, ACL_KEY_BUNDLE_NAME, "-1");
        (void)AddStringToJsonObject(accessee, ACL_KEY_DEVICE_NAME, "-1");
        (void)AddStringToJsonObject(accessee, ACL_KEY_CREDENTIAL_ID, "-1");
        cJSON_AddItemToObject(json, ACL_KEY_ACCESSEE, accessee);
    }
    char *value = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (value == nullptr) {
        LNN_LOGE(LNN_STATE, "print json to string fail");
    }
    return value;
}

#ifdef __LITEOS_M__
int32_t LnnNotifyCommandToDmAuthPassed(const char *peerUdid, int32_t peerUserId, const char *credId)
{
    (void)peerUdid;
    (void)peerUserId;
    (void)credId;
    return SOFTBUS_NOT_IMPLEMENT;
}
#else
int32_t LnnNotifyCommandToDmAuthPassed(const char *peerUdid, int32_t peerUserId, const char *credId)
{
    const char *credIdSafe = (credId != nullptr && credId[0] != '\0') ? credId : "-1";
    if (peerUdid == nullptr || peerUdid[0] == '\0') {
        LNN_LOGE(LNN_STATE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!LnnIsCommandCbRegistered()) {
        LNN_LOGW(LNN_STATE, "command cb not registered, skip notify");
        return SOFTBUS_OK;
    }
    char *value = PackCommandAclMsg(peerUdid, peerUserId, credIdSafe);
    if (value == nullptr) {
        return SOFTBUS_CREATE_JSON_ERR;
    }
    int32_t ret = LnnIpcNotifyCommandToDm(LnnGetCommandPkgName(), 0, value, (uint32_t)strlen(value) + 1);
    LNN_LOGI(LNN_STATE, "LnnIpcNotifyCommandToDm ret=%{public}d", ret);
    cJSON_free(value);
    return ret;
}
#endif
} // extern "C"
