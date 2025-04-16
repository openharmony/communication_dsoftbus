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

#include "auth_identity_service_adapter.h"
#include "auth_log.h"

#define FIELD_AUTHORIZED_SCOPE "authorizedScope"
#define AUTH_APPID "softbus_auth"
#define SCOPE_USER 2

enum SoftbusCredType {
    ACCOUNT_RELATED = 1,
    ACCOUNT_UNRELATED = 2,
    ACCOUNT_SHARE = 3,
    ACCOUNT_BUTT
};

int32_t IdServiceQueryCredential(int32_t userId, const char *udidHash, const char *accountidHash,
    bool isSameAccount, char **credList)
{
    (void)userId;
    (void)udidHash;
    (void)accountidHash;
    (void)isSameAccount;
    (void)credList;

    return SOFTBUS_NOT_IMPLEMENT;
}

void IdServiceDestroyCredentialList(char **returnData)
{
    (void)returnData;

    return;
}

char *IdServiceGetCredIdFromCredList(int32_t userId, const char *credList)
{
    (void)userId;
    (void)credList;

    return NULL;
}

char *IdServiceGenerateAuthParam(HiChainAuthParam *hiChainParam)
{
    (void)hiChainParam;

    return NULL;
}

int32_t IdServiceAuthCredential(int32_t userId, int64_t authReqId, const char *authParams, const DeviceAuthCallback *cb)
{
    (void)userId;
    (void)authReqId;
    (void)authParams;
    (void)cb;

    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t IdServiceProcessCredData(int64_t authSeq, const uint8_t *data, uint32_t len, DeviceAuthCallback *cb)
{
    (void)authSeq;
    (void)data;
    (void)len;
    (void)cb;

    return SOFTBUS_NOT_IMPLEMENT;
}

bool IdServiceIsPotentialTrustedDevice(const char *udidHash, const char *accountIdHash, bool isSameAccount)
{
    char *credList = NULL;
    int32_t userId = GetActiveOsAccountIds();
    AUTH_LOGI(AUTH_HICHAIN, "get userId=%{public}d", userId);
    int32_t ret = IdServiceQueryCredential(userId, udidHash, accountIdHash, isSameAccount, &credList);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "query credential fail, ret=%{public}d", ret);
        return false;
    }
    char *credId = IdServiceGetCredIdFromCredList(userId, credList);
    if (credId == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "get cred id fail");
        IdServiceDestroyCredentialList(&credList);
        return false;
    }
    IdServiceDestroyCredentialList(&credList);
    SoftBusFree(credId);
    return true;
}

static int32_t GetCredInfoFromJson(const char *credInfo, SoftBusCredInfo *info)
{
    JsonObj *json = JSON_Parse(credInfo, strlen(credInfo));
    if (json == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "parse json fail");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    if (!JSON_GetInt32FromOject(json, FIELD_CRED_TYPE, &(info->credIdType)) ||
        !JSON_GetInt32FromOject(json, FIELD_SUBJECT, &(info->subject)) ||
        !JSON_GetStringFromOject(json, FIELD_DEVICE_ID, info->udid, UDID_BUF_LEN) ||
        !JSON_GetStringFromOject(json, FIELD_USER_ID, info->userId, MAX_ACCOUNT_HASH_LEN)) {
        AUTH_LOGD(AUTH_HICHAIN, "parse credential info json fail");
        JSON_Delete(json);
        return SOFTBUS_GET_INFO_FROM_JSON_FAIL;
    }
    JSON_Delete(json);
    return SOFTBUS_OK;
}

static bool IsLocalCredInfo(const char *udid)
{
    char localUdid[UDID_BUF_LEN] = { 0 };
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, UDID_BUF_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "get local udid fail");
        return false;
    }
    return strcmp(udid, localUdid) == 0;
}

static void IdServiceHandleCredAdd(const char *credInfo)
{
    SoftBusCredInfo info = { 0 };
    int32_t localDevTypeId = 0;
    if (GetCredInfoFromJson(credInfo, &info) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "get credential info from json fail");
        return;
    }
    if (IsLocalCredInfo(info.udid)) {
        AUTH_LOGI(AUTH_HICHAIN, "id service no need handle");
        return;
    }
    if (LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &localDevTypeId) == SOFTBUS_OK && localDevTypeId == TYPE_TV_ID &&
        (info.credIdType == ACCOUNT_SHARE || info.credIdType == ACCOUNT_UNRELATED)) {
        AUTH_LOGI(AUTH_HICHAIN, "id service not start heartbeat");
        return;
    }
    if (LnnInsertSpecificTrustedDevInfo(info.udid) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "id service insert trust info fail");
        return;
    }
    LnnHbOnTrustedRelationIncreased(AUTH_PEER_TO_PEER_GROUP);
}

static bool IsExitPotentialTrusted(const char *udid)
{
    uint8_t udidHashResult[SHA_256_HASH_LEN] = { 0 };
    char udidShortHashStr[DISC_MAX_DEVICE_ID_LEN] = { 0 };
    uint8_t localAccountHash[SHA_256_HASH_LEN] = { 0 };
    char accountHexHash[SHA_256_HEX_HASH_LEN] = { 0 };
    if (LnnGetLocalByteInfo(BYTE_KEY_ACCOUNT_HASH, localAccountHash, SHA_256_HASH_LEN) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "get local account hash fail");
        return false;
    }
    if (ConvertBytesToHexString(accountHexHash, SHA_256_HEX_HASH_LEN, localAccountHash, SHA_256_HASH_LEN) !=
        SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "convert account hash fail");
        return false;
    }
    if (SoftBusGenerateStrHash((const unsigned char *)udid, strlen(udid), (unsigned char *)udidHashResult) !=
        SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "gen udid hash err");
        return false;
    }
    (void)ConvertBytesToHexString(udidShortHashStr, HB_SHORT_UDID_HASH_HEX_LEN + 1,
        (const unsigned char *)udidHashResult, HB_SHORT_UDID_HASH_LEN);
    udidShortHashStr[HB_SHORT_UDID_HASH_HEX_LEN + 1] = '\0';

    return IdServiceIsPotentialTrustedDevice(udidShortHashStr, accountHexHash, false);
}

static void OnCredAdd(const char *credId, const char *credInfo)
{
    AUTH_LOGI(AUTH_HICHAIN, "OnCredAdd enter");
    if (credId == NULL || credInfo == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "id service invalid param");
        return;
    }
    IdServiceHandleCredAdd(credInfo);
}

static void OnCredDelete(const char *credId, const char *credInfo)
{
    if (credId == NULL || credInfo == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "id service invalid param");
        return;
    }
    SoftBusCredInfo info = { 0 };
    if (GetCredInfoFromJson(credInfo, &info) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "id service parse json fail");
        return;
    }
    if (IsExitPotentialTrusted(info.udid)) {
        AUTH_LOGI(AUTH_HICHAIN, "id service no need delete");
        return;
    }
    LnnDeleteSpecificTrustedDevInfo(info.udid, GetActiveOsAccountIds());
    LnnHbOnTrustedRelationReduced();
}

static void OnCredUpdate(const char *credId, const char *credInfo)
{
    if (credId == NULL || credInfo == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "id service invalid param");
        return;
    }
    IdServiceHandleCredAdd(credInfo);
}

static CredChangeListener g_regCredChangeListener = {
    .onCredAdd = OnCredAdd,
    .onCredDelete = OnCredDelete,
    .onCredUpdate = OnCredUpdate,
};

int32_t IdServiceRegCredMgr(void)
{
    AUTH_LOGI(AUTH_HICHAIN, "id service init reg");
    const CredManager *credManager = IdServiceGetCredMgrInstance();
    AUTH_CHECK_AND_RETURN_RET_LOGE(credManager != NULL, SOFTBUS_AUTH_GET_CRED_INSTANCE_FALI, AUTH_HICHAIN,
        "hichain identity service not initialized");
    
    if (credManager->registerChangeListener == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "id service register listener is NULL");
        return SOFTBUS_AUTH_REG_CRED_CHANGE_FAIL;
    }
    if (credManager->registerChangeListener(AUTH_APPID, &g_regCredChangeListener) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "id service reg cred change fail");
        return SOFTBUS_AUTH_REG_CRED_CHANGE_FAIL;
    }
    return SOFTBUS_OK;
}

void IdServiceUnRegCredMgr(void)
{
    const CredManager *credManager = IdServiceGetCredMgrInstance();
    if (credManager == NULL) {
        AUTH_LOGI(AUTH_HICHAIN, "hichain identity service get cred manager fail");
        return;
    }
    if ((credManager->unregisterChangeListener != NULL) &&
        credManager->unregisterChangeListener(AUTH_APPID) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_HICHAIN, "id service reg cred change fail");
    }
}