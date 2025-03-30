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
#include "device_auth_defines.h"
#include "softbus_adapter_mem.h"

#define FIELD_AUTHORIZED_SCOPE "authorizedScope"
#define SCOPE_USER 2

enum SoftbusCredType {
    ACCOUNT_RELATED = 1,
    ACCOUNT_UNRELATED = 2,
    ACCOUNT_SHARE = 3,
    ACCOUNT_BUTT
};

static char *IdServiceGenerateQueryParam(const char *udidHash, const char *accountHash, bool isSameAccount)
{
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