/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "auth_hichain_deps_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
constexpr int64_t TEST_AUTH_SEQ = 1;
void *g_hichainMockInterface;
AuthHichainInterfaceMock::AuthHichainInterfaceMock()
{
    g_hichainMockInterface = reinterpret_cast<void *>(this);
}

AuthHichainInterfaceMock::~AuthHichainInterfaceMock()
{
    g_hichainMockInterface = nullptr;
}

static AuthHichainInterface *GetAuthHichainMockInterface()
{
    return reinterpret_cast<AuthHichainInterfaceMock *>(g_hichainMockInterface);
}

extern "C" {
cJSON *cJSON_CreateObject()
{
    return GetAuthHichainMockInterface()->cJSON_CreateObject();
}

bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value)
{
    return GetAuthHichainMockInterface()->AddStringToJsonObject(json, string, value);
}

bool AddBoolToJsonObject(cJSON *json, const char * const string, bool value)
{
    return GetAuthHichainMockInterface()->AddBoolToJsonObject(json, string, value);
}

bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num)
{
    return GetAuthHichainMockInterface()->AddNumberToJsonObject(json, string, num);
}

char *cJSON_PrintUnformatted(const cJSON *json)
{
    return GetAuthHichainMockInterface()->cJSON_PrintUnformatted(json);
}

int32_t AuthSessionPostAuthData(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    return GetAuthHichainMockInterface()->AuthSessionPostAuthData(authSeq, data, len);
}

void LnnEventExtraInit(LnnEventExtra *extra)
{
    return GetAuthHichainMockInterface()->LnnEventExtraInit(extra);
}

void GetLnnTriggerInfo(LnnTriggerInfo *triggerInfo)
{
    return GetAuthHichainMockInterface()->GetLnnTriggerInfo(triggerInfo);
}

uint64_t SoftBusGetSysTimeMs(void)
{
    return GetAuthHichainMockInterface()->SoftBusGetSysTimeMs();
}

AuthFsm *GetAuthFsmByAuthSeq(int64_t authSeq)
{
    return GetAuthHichainMockInterface()->GetAuthFsmByAuthSeq(authSeq);
}

void ReleaseAuthLock(void)
{
    return GetAuthHichainMockInterface()->ReleaseAuthLock();
}

int32_t AuthSessionSaveSessionKey(int64_t authSeq, const uint8_t *key, uint32_t len)
{
    return GetAuthHichainMockInterface()->AuthSessionSaveSessionKey(authSeq, key, len);
}

int32_t AuthSessionHandleAuthFinish(int64_t authSeq, AclWriteState aclState)
{
    return GetAuthHichainMockInterface()->AuthSessionHandleAuthFinish(authSeq, aclState);
}

const char *GetAuthSideStr(bool isServer)
{
    return GetAuthHichainMockInterface()->GetAuthSideStr(isServer);
}

int32_t AuthFailNotifyProofInfo(int32_t errCode, const char *errorReturn, uint32_t errorReturnLen)
{
    return GetAuthHichainMockInterface()->AuthFailNotifyProofInfo(errCode, errorReturn, errorReturnLen);
}

int32_t LnnAsyncCallbackDelayHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback,
    void *para, uint64_t delayMillis)
{
    return GetAuthHichainMockInterface()->LnnAsyncCallbackDelayHelper(looper, callback, para, delayMillis);
}

int32_t AuthSessionHandleAuthError(int64_t authSeq, int32_t reason)
{
    return GetAuthHichainMockInterface()->AuthSessionHandleAuthError(authSeq, reason);
}

int32_t AuthSessionGetUdid(int64_t authSeq, char *udid, uint32_t size)
{
    return GetAuthHichainMockInterface()->AuthSessionGetUdid(authSeq, udid, size);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetAuthHichainMockInterface()->LnnGetLocalStrInfo(key, info, len);
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return GetAuthHichainMockInterface()->SoftBusGenerateStrHash(str, len, hash);
}

int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen,
    const unsigned char *inBuf, uint32_t inLen)
{
    return GetAuthHichainMockInterface()->ConvertBytesToHexString(outBuf, outBufLen, inBuf, inLen);
}

int32_t GetNodeFromPcRestrictMap(const char *udidHash, uint32_t *count)
{
    return GetAuthHichainMockInterface()->GetNodeFromPcRestrictMap(udidHash, count);
}

void DeleteNodeFromPcRestrictMap(const char *udidHash)
{
    return GetAuthHichainMockInterface()->DeleteNodeFromPcRestrictMap(udidHash);
}

bool GetJsonObjectStringItem(const cJSON *json, const char * const string, char *target, uint32_t targetLen)
{
    return GetAuthHichainMockInterface()->GetJsonObjectStringItem(json, string, target, targetLen);
}

bool GetJsonObjectNumberItem(const cJSON *json, const char * const string, int32_t *target)
{
    return GetAuthHichainMockInterface()->GetJsonObjectNumberItem(json, string, target);
}

bool RequireAuthLock(void)
{
    return GetAuthHichainMockInterface()->RequireAuthLock();
}

int32_t AuthSessionGetAuthVersion(int64_t authSeq, int32_t *version)
{
    if (authSeq == TEST_AUTH_SEQ) {
        return SOFTBUS_AUTH_GET_SESSION_INFO_FAIL;
    }

    *version = AUTH_VERSION_V2;
    return SOFTBUS_OK;
}

bool AuthSessionGetIsSameAccount(int64_t authSeq)
{
    (void)authSeq;
    return true;
}

int32_t AuthSessionGetUserId(int64_t authSeq)
{
    (void)authSeq;
    return 0;
}

int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len)
{
    return GetAuthHichainMockInterface()->LnnGetLocalByteInfo(key, info, len);
}

bool JSON_GetStringFromObject(const JsonObj *obj, const char *key, char *value, uint32_t size)
{
    return GetAuthHichainMockInterface()->JSON_GetStringFromObject(obj, key, value, size);
}

int32_t LnnGetLocalNodeInfoSafe(NodeInfo *info)
{
    return GetAuthHichainMockInterface()->LnnGetLocalNodeInfoSafe(info);
}

bool LnnIsDefaultOhosAccount(void)
{
    return GetAuthHichainMockInterface()->LnnIsDefaultOhosAccount();
}

int32_t IdServiceQueryCredential(int32_t userId, const char *udidHash, const char *accountidHash,
    bool isSameAccount, char **credList)
{
    return GetAuthHichainMockInterface()->IdServiceQueryCredential(userId, udidHash, accountidHash, isSameAccount,
        credList);
}

char *IdServiceGetCredIdFromCredList(int32_t userId, const char *credList)
{
    return GetAuthHichainMockInterface()->IdServiceGetCredIdFromCredList(userId, credList);
}

char *AuthSessionGetCredId(int64_t authSeq)
{
    return GetAuthHichainMockInterface()->AuthSessionGetCredId(authSeq);
}

char *IdServiceGenerateAuthParam(HiChainAuthParam *hiChainParam)
{
    return GetAuthHichainMockInterface()->IdServiceGenerateAuthParam(hiChainParam);
}

int32_t IdServiceAuthCredential(int32_t userId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *cb)
{
    return GetAuthHichainMockInterface()->IdServiceAuthCredential(userId, authReqId, authParams, cb);
}

int32_t IdServiceProcessCredData(int64_t authSeq, const uint8_t *data, uint32_t len,
    DeviceAuthCallback *cb)
{
    return GetAuthHichainMockInterface()->IdServiceProcessCredData(authSeq, data, len, cb);
}

bool JSON_AddStringToObject(JsonObj *obj, const char *key, const char *value)
{
    return GetAuthHichainMockInterface()->JSON_AddStringToObject(obj, key, value);
}

void IdServiceDestroyCredentialList(char **returnData)
{
    return GetAuthHichainMockInterface()->IdServiceDestroyCredentialList(returnData);
}

int32_t GetActiveOsAccountIds(void)
{
    return GetAuthHichainMockInterface()->GetActiveOsAccountIds();
}

bool IsSKIdInvalid(int32_t sessionKeyId, const char *accountHash, const char *udidShortHash,
    int32_t userId)
{
    return GetAuthHichainMockInterface()->IsSKIdInvalid(sessionKeyId, accountHash, udidShortHash, userId);
}
} // extern "C"
} // namespace OHOS
