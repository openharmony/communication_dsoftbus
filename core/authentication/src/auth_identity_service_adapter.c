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

#include "anonymizer.h"
#include "auth_identity_service_adapter.h"
#include "auth_log.h"
#include "auth_session_fsm.h"
#include "bus_center_manager.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "lnn_decision_db.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_adapter_json.h"
#include "softbus_adapter_mem.h"

#define FIELD_AUTHORIZED_SCOPE "authorizedScope"
#define AUTH_APPID "softbus_auth"
#define SCOPE_USER 2

enum SoftbusCredType {
    ACCOUNT_RELATED = 1,
    ACCOUNT_UNRELATED = 2,
    ACCOUNT_SHARE = 3,
    ACCOUNT_BUTT
};

static char *IdServiceGenerateQueryParam(const char *udidHash, const char *accountHash, bool isSameAccount)
{
    (void)accountHash;
    int32_t credType = isSameAccount ? ACCOUNT_RELATED : ACCOUNT_BUTT;

    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "create json fail");
        return NULL;
    }

    if (!AddStringToJsonObject(msg, FIELD_DEVICE_ID_HASH, udidHash) ||
        (isSameAccount && !AddNumberToJsonObject(msg, FIELD_CRED_TYPE, credType))) {
        AUTH_LOGE(AUTH_HICHAIN, "add json object fail");
        cJSON_Delete(msg);
        return NULL;
    }

    AUTH_LOGD(AUTH_HICHAIN, "hichain identity service cred type=%{public}d", credType);

    char *data = cJSON_PrintUnformatted(msg);
    if (data == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "json transform unformatted fail");
    }
    cJSON_Delete(msg);
    return data;
}

static const CredManager *IdServiceGetCredMgrInstance()
{
    int32_t ret = InitDeviceAuthService();
    if (ret != 0) {
        AUTH_LOGE(AUTH_HICHAIN, "hichain identity service init device auth service fail err=%{public}d", ret);
        return NULL;
    }

    return GetCredMgrInstance();
}

static const CredAuthManager *IdServiceGetCredAuthInstance()
{
    int32_t ret = InitDeviceAuthService();
    if (ret != 0) {
        AUTH_LOGE(AUTH_HICHAIN, "hichain identity service init device auth service fail err=%{public}d", ret);
        return NULL;
    }

    return GetCredAuthInstance();
}

int32_t IdServiceQueryCredential(int32_t userId, const char *udidHash, const char *accountidHash,
    bool isSameAccount, char **credList)
{
    const CredManager *credManger = IdServiceGetCredMgrInstance();
    AUTH_CHECK_AND_RETURN_RET_LOGE(credManger != NULL, SOFTBUS_AUTH_GET_CRED_INSTANCE_FALI,
        AUTH_HICHAIN, "hichain identity service not initialized");

    char *authParams = IdServiceGenerateQueryParam(udidHash, accountidHash, isSameAccount);
    AUTH_CHECK_AND_RETURN_RET_LOGE(authParams != NULL, SOFTBUS_CREATE_JSON_ERR,
        AUTH_HICHAIN, "hichain identity service generate query parameter fail");

    int32_t ret = credManger->queryCredentialByParams(userId, authParams, credList);
    cJSON_free(authParams);
    if (ret != HC_SUCCESS) {
        uint32_t authErrCode = 0;
        (void)GetSoftbusHichainAuthErrorCode((uint32_t)ret, &authErrCode);
        AUTH_LOGE(AUTH_HICHAIN,
            "hichain identity service query credential list fail err=%{public}d, authErrCode=%{public}d",
            ret, authErrCode);
        return authErrCode;
    }
    AUTH_LOGD(AUTH_HICHAIN, "hichain identity service get credential list");

    return SOFTBUS_OK;
}

void IdServiceDestroyCredentialList(char **returnData)
{
    if (returnData == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "parameter is null");
        return;
    }

    const CredManager *credManger = IdServiceGetCredMgrInstance();
    if (credManger == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "hichain identity service get cred manager fail");
        return;
    }

    credManger->destroyInfo(returnData);
}

static char *IdServiceCopyCredId(char *credId)
{
    char *credIdMem = (char *)SoftBusCalloc(strlen(credId) + 1);
    if (credIdMem == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "credId calloc fail");
        return NULL;
    }

    if (strcpy_s(credIdMem, strlen(credId) + 1, credId) != EOK) {
        AUTH_LOGE(AUTH_HICHAIN, "strcpy_s cred id fail");
        SoftBusFree(credIdMem);
        credIdMem = NULL;
    } else {
        char *anonyCredId = NULL;
        Anonymize(credIdMem, &anonyCredId);
        AUTH_LOGD(AUTH_HICHAIN, "hichain identity service get credid=%{public}s", anonyCredId);
        AnonymizeFree(anonyCredId);
    }
    
    return credIdMem;
}

static int32_t IdServiceGetCredTypeByCredId(int32_t userId, char *credId, int32_t *credType)
{
    const CredManager *credManger = IdServiceGetCredMgrInstance();
    AUTH_CHECK_AND_RETURN_RET_LOGE(credManger != NULL, SOFTBUS_AUTH_GET_CRED_INSTANCE_FALI,
        AUTH_HICHAIN, "hichain identity service not initialized");
    
    char *credInfo = NULL;
    int32_t ret = credManger->queryCredInfoByCredId(userId, credId, &credInfo);
    if (ret != HC_SUCCESS) {
        uint32_t authErrCode = 0;
        (void)GetSoftbusHichainAuthErrorCode((uint32_t)ret, &authErrCode);
        AUTH_LOGE(AUTH_HICHAIN,
            "hichain identity service quere credential info failed, err=%{public}d, authErrCode=%{public}d",
            ret, authErrCode);
        return authErrCode;
    }

    cJSON *credInfoJson = CreateJsonObjectFromString(credInfo);
    IdServiceDestroyCredentialList(&credInfo);
    if (credInfoJson == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "create json fail");
        return SOFTBUS_CREATE_JSON_ERR;
    }

    if (!GetJsonObjectInt32Item(credInfoJson, FIELD_CRED_TYPE, credType)) {
        AUTH_LOGE(AUTH_HICHAIN, "cred type not found");
        cJSON_Delete(credInfoJson);
        return SOFTBUS_PARSE_JSON_ERR;
    }

    if (*credType == ACCOUNT_UNRELATED) {
        int32_t scope = 0;
        if (!GetJsonObjectInt32Item(credInfoJson, FIELD_AUTHORIZED_SCOPE, &scope)) {
            AUTH_LOGE(AUTH_HICHAIN, "scope not found");
            cJSON_Delete(credInfoJson);
            return SOFTBUS_PARSE_JSON_ERR;
        }

        *credType = (scope == SCOPE_USER) ? *credType : ACCOUNT_BUTT;
    }
    cJSON_Delete(credInfoJson);

    return SOFTBUS_OK;
}

char *IdServiceGetCredIdFromCredList(int32_t userId, const char *credList)
{
    if (credList == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "parameter is null");
        return NULL;
    }

    cJSON *credIdJson = CreateJsonObjectFromString(credList);
    if (credIdJson == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "create json fail");
        return NULL;
    }

    int32_t arraySize = GetArrayItemNum(credIdJson);
    if (arraySize == 0) {
        AUTH_LOGE(AUTH_HICHAIN, "array size is 0");
        cJSON_Delete(credIdJson);
        return NULL;
    }

    AUTH_LOGD(AUTH_HICHAIN, "array size is %{public}d", arraySize);

    char *credId = NULL;
    char *credIdMem = NULL;
    int32_t credType = ACCOUNT_BUTT;
    for (int32_t i = 0; i < arraySize; i++) {
        cJSON *item = GetArrayItemFromArray(credIdJson, i);
        if (item == NULL) {
            AUTH_LOGE(AUTH_HICHAIN, "get array item is null");
            break;
        }
        char *credIdTmp = cJSON_GetStringValue(item);
        if (credIdTmp == NULL) {
            AUTH_LOGE(AUTH_HICHAIN, "get credId string fail");
            break;
        }

        int32_t credTypeTmp = ACCOUNT_BUTT;
        int32_t ret = IdServiceGetCredTypeByCredId(userId, credIdTmp, &credTypeTmp);
        if (ret != SOFTBUS_OK) {
            AUTH_LOGE(AUTH_HICHAIN, "get cred type fail");
            break;
        }

        credId = (credTypeTmp < credType) ? credIdTmp : credId;
        credType = (credTypeTmp < credType) ? credTypeTmp : credType;
    }

    if ((credId != NULL) && (credType != ACCOUNT_BUTT)) {
        credIdMem = IdServiceCopyCredId(credId);
        if (credIdMem == NULL) {
            AUTH_LOGE(AUTH_HICHAIN, "copy credId fail");
        }
    }

    cJSON_Delete(credIdJson);
    return credIdMem;
}

char *IdServiceGenerateAuthParam(HiChainAuthParam *hiChainParam)
{
    if (hiChainParam == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "parameter is null");
        return NULL;
    }

    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "create json fail");
        return NULL;
    }

    if (!AddStringToJsonObject(msg, FIELD_CRED_ID, hiChainParam->credId)) {
        AUTH_LOGE(AUTH_HICHAIN, "add json object fail");
        cJSON_Delete(msg);
        return NULL;
    }

    char *data = cJSON_PrintUnformatted(msg);
    if (data == NULL) {
        AUTH_LOGE(AUTH_HICHAIN, "json transform unformatted fail");
    }
    cJSON_Delete(msg);
    return data;
}

int32_t IdServiceAuthCredential(int32_t userId, int64_t authReqId, const char *authParams, const DeviceAuthCallback *cb)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(authParams != NULL && cb != NULL, SOFTBUS_INVALID_PARAM, AUTH_HICHAIN,
        "authParams or cb is null");

    const CredAuthManager *credAuthManger = IdServiceGetCredAuthInstance();
    AUTH_CHECK_AND_RETURN_RET_LOGE(credAuthManger != NULL, SOFTBUS_AUTH_GET_CRED_INSTANCE_FALI,
        AUTH_HICHAIN, "hichain identity service not initialized");

    AUTH_LOGD(AUTH_HICHAIN, "hichain identity service start authenticate credential");
    int32_t ret = credAuthManger->authCredential(userId, authReqId, authParams, cb);
    if (ret != HC_SUCCESS) {
        uint32_t authErrCode = 0;
        (void)GetSoftbusHichainAuthErrorCode((uint32_t)ret, &authErrCode);
        AUTH_LOGE(AUTH_HICHAIN,
            "hichain identity service authenticate credential failed, err=%{public}d, authErrCode=%{public}d",
            ret, authErrCode);
        return authErrCode;
    }

    return SOFTBUS_OK;
}

int32_t IdServiceProcessCredData(int64_t authSeq, const uint8_t *data, uint32_t len, DeviceAuthCallback *cb)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(data != NULL && cb != NULL, SOFTBUS_INVALID_PARAM, AUTH_HICHAIN,
        "data or cb is null");

    const CredAuthManager *credAuthManger = IdServiceGetCredAuthInstance();
    AUTH_CHECK_AND_RETURN_RET_LOGE(credAuthManger != NULL, SOFTBUS_AUTH_GET_CRED_INSTANCE_FALI,
        AUTH_HICHAIN, "hichain identity service not initialized");

    AUTH_LOGD(AUTH_HICHAIN, "hichain identity service start process cred data");
    int32_t ret = credAuthManger->processCredData(authSeq, data, len, cb);
    if (ret != HC_SUCCESS) {
        uint32_t authErrCode = 0;
        (void)GetSoftbusHichainAuthErrorCode((uint32_t)ret, &authErrCode);
        AUTH_LOGE(AUTH_HICHAIN,
            "hichain identity service process cred data failed, ret=%{public}d, authErrCode=%{public}d",
            ret, authErrCode);
        return authErrCode;
    }

    return SOFTBUS_OK;
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
    uint8_t udidShortHash[SHORT_UDID_HASH_LEN + 1] = { 0 };
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
    if (memcpy_s(udidShortHash, SHORT_UDID_HASH_LEN, udidHashResult, SHORT_UDID_HASH_LEN) != EOK) {
        AUTH_LOGE(AUTH_HICHAIN, "memcpy_s fail");
        return false;
    }
    (void)ConvertBytesToHexString(
        udidShortHashStr, HB_SHORT_UDID_HASH_HEX_LEN + 1, (const unsigned char *)udidShortHash, HB_SHORT_UDID_HASH_LEN);
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
    if (IsExitPotentialTrusted(udid)) {
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