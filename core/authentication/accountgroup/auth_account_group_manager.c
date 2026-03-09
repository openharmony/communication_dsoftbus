/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "auth_account_group_manager.h"

#include <securec.h>
#include <stdatomic.h>

#include "anonymizer.h"
#include "auth_common.h"
#include "auth_hichain.h"
#include "auth_log.h"
#include "cJSON.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"

#define D2D_CAAS_APPID "d2d_caas_appid"
#define D2D_SESSION_KEY_LEN 32

static bool g_isAccountAuthCbInited = false;
static IAccountAuthCallback *g_accountAuthCallback;

static bool OnTransmitted(int64_t authSeq, const uint8_t *data, uint32_t len);
static void OnSessionKeyReturned(int64_t authSeq, const uint8_t *sessionKey, uint32_t sessionKeyLen);
static void OnFinished(int64_t authSeq, int32_t operationCode, const char *returnData);
static void OnError(int64_t authSeq, int32_t operationCode, int32_t errCode, const char *errorReturn);
static char *OnRequest(int64_t authSeq, int32_t operationCode, const char *reqParams);
static DeviceAuthCallback g_hichainCallback = {
    .onTransmit = OnTransmitted,
    .onSessionKeyReturned = OnSessionKeyReturned,
    .onFinish = OnFinished,
    .onError = OnError,
    .onRequest = OnRequest,
};

void RegisterAccountAuth(IAccountAuthCallback *cb)
{
    g_accountAuthCallback = cb;
    g_isAccountAuthCbInited = true;
}

static bool OnTransmitted(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(data != NULL && len > 0, false, AUTH_KEY, "transmit invalid param");
    AUTH_LOGI(AUTH_KEY, "account auth transmit, authseq=%{public}" PRId64 ", len=%{public}u", authSeq, len);
    if (g_accountAuthCallback == NULL) {
        AUTH_LOGE(AUTH_KEY, "account auth callback is null");
        return false;
    }
    if (g_accountAuthCallback->onTransmit == NULL) {
        AUTH_LOGE(AUTH_KEY, "account auth transmit callback is null");
        return false;
    }
    bool ret = g_accountAuthCallback->onTransmit(authSeq, data, len);
    if (ret != true) {
        AUTH_LOGE(AUTH_KEY, "account auth transmit failed");
    }
    return ret;
}

static void OnSessionKeyReturned(int64_t authSeq, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    AUTH_CHECK_AND_RETURN_LOGE(sessionKey != NULL && sessionKeyLen > 0 && sessionKeyLen <= D2D_SESSION_KEY_LEN,
        AUTH_KEY, "session key return invalid param, keyLen=%{public}u", sessionKeyLen);
    AUTH_LOGI(AUTH_KEY, "account auth sessionkey return, authseq=%{public}" PRId64, authSeq);
    if (g_accountAuthCallback == NULL) {
        AUTH_LOGE(AUTH_KEY, "account auth callback is null");
        return;
    }
    if (g_accountAuthCallback->onSessionKeyReturned == NULL) {
        AUTH_LOGE(AUTH_KEY, "account auth sessionkey return callback is null");
        return;
    }
    g_accountAuthCallback->onSessionKeyReturned(authSeq, sessionKey, sessionKeyLen);
}

static void OnFinished(int64_t authSeq, int32_t operationCode, const char *returnData)
{
    AUTH_CHECK_AND_RETURN_LOGE(returnData != NULL, AUTH_KEY, "account auth finished invalid return data");
    AUTH_LOGI(AUTH_KEY, "account auth finished, authseq=%{public}" PRId64, authSeq);
    if (g_accountAuthCallback == NULL) {
        AUTH_LOGE(AUTH_KEY, "account auth callback is null");
        return;
    }
    if (g_accountAuthCallback->onFinish == NULL) {
        AUTH_LOGE(AUTH_KEY, "account auth finished callback is null");
        return;
    }
    g_accountAuthCallback->onFinish(authSeq, operationCode, returnData);
}

static void OnError(int64_t authSeq, int32_t operationCode, int32_t errCode, const char *returnData)
{
    uint32_t authErrCode = 0;
    GetSoftbusHichainAuthErrorCode((uint32_t)errCode, &authErrCode);
    AUTH_LOGE(AUTH_CONN, "account auth OnError: authSeq=%{public}" PRId64 ", errCode=%{public}d authErrCode=%{public}d",
        authSeq, errCode, authErrCode);
    if (g_accountAuthCallback == NULL) {
        AUTH_LOGE(AUTH_KEY, "account auth callback is null");
        return;
    }
    if (g_accountAuthCallback->onError == NULL) {
        AUTH_LOGE(AUTH_KEY, "account auth error callback is null");
        return;
    }
    g_accountAuthCallback->onError(authSeq, operationCode, authErrCode, returnData);
}

static char *OnRequest(int64_t authSeq, int32_t operationCode, const char *reqParams)
{
    (void)reqParams;
    AUTH_LOGI(AUTH_KEY, "account auth request: authSeq=%{public}" PRId64 ", code=%{public}d", authSeq, operationCode);

    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        AUTH_LOGE(AUTH_KEY, "create json fail");
        return NULL;
    }
    if (!AddStringToJsonObject(msg, FIELD_APP_ID, D2D_CAAS_APPID)) {
        AUTH_LOGE(AUTH_KEY, "add appid failed");
        cJSON_Delete(msg);
        return NULL;
    }
    char *msgStr = cJSON_PrintUnformatted(msg);
    cJSON_Delete(msg);
    if (msgStr == NULL) {
        AUTH_LOGE(AUTH_KEY, "cJSON_PrintUnformatted failed");
        return NULL;
    }
    return msgStr;
}

static const LightAccountVerifier *GetLightAccountInstance()
{
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        AUTH_LOGE(AUTH_KEY, "init device auth service failed, err=%{public}d", ret);
        return NULL;
    }
    return GetLightAccountVerifierInstance();
}

int32_t StartGroupAccountAuth(const char *pkgName, int64_t requestId, const char *serviceId)
{
    AUTH_LOGI(AUTH_KEY, "start account auth, request id=%{public}" PRId64, requestId);
    const LightAccountVerifier *lightAccountVerifier = GetLightAccountInstance();
    AUTH_CHECK_AND_RETURN_RET_LOGE(lightAccountVerifier != NULL, SOFTBUS_AUTH_GET_LIGHT_ACCOUNT_FAIL, AUTH_KEY,
        "light account verifier is not initialized");
    AUTH_CHECK_AND_RETURN_RET_LOGE(lightAccountVerifier->startLightAccountAuth != NULL,
        SOFTBUS_AUTH_GET_LIGHT_ACCOUNT_FAIL, AUTH_KEY, "startLightAccountAuth is not initialized");
    AUTH_CHECK_AND_RETURN_RET_LOGE(g_isAccountAuthCbInited, SOFTBUS_NO_INIT, AUTH_KEY,
        "auth account group manager is not initialized");
    int32_t accountId = JudgeDeviceTypeAndGetOsAccountIds();
    uint32_t ret =
        lightAccountVerifier->startLightAccountAuth(accountId, requestId, serviceId, &g_hichainCallback);
    if (ret != HC_SUCCESS) {
        uint32_t authErrCode = SOFTBUS_AUTH_HICHAIN_AUTH_FAIL;
        GetSoftbusHichainAuthErrorCode(ret, &authErrCode);
        AUTH_LOGE(AUTH_KEY, "hichain start light account auth failed, errcode=%{public}d", authErrCode);
        return authErrCode;
    }
    return SOFTBUS_OK;
}

int32_t ProcessGroupAccountAuth(const char *pkgName, int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    AUTH_LOGI(AUTH_KEY, "process account auth, request id=%{public}" PRId64, requestId);
    const LightAccountVerifier *lightAccountVerifier = GetLightAccountInstance();
    AUTH_CHECK_AND_RETURN_RET_LOGE(lightAccountVerifier != NULL, SOFTBUS_AUTH_GET_LIGHT_ACCOUNT_FAIL, AUTH_KEY,
        "light account verifier is not initialized");
    AUTH_CHECK_AND_RETURN_RET_LOGE(lightAccountVerifier->processLightAccountAuth != NULL,
        SOFTBUS_AUTH_GET_LIGHT_ACCOUNT_FAIL, AUTH_KEY, "processLightAccountAuth is not initialized");
    AUTH_CHECK_AND_RETURN_RET_LOGE(g_isAccountAuthCbInited, SOFTBUS_NO_INIT, AUTH_KEY,
        "auth account group manager is not initialized");
    int32_t accountId = JudgeDeviceTypeAndGetOsAccountIds();
    DataBuff inMsg = { .data = (uint8_t *)data, .length = dataLen };
    int32_t hichainRet =
        lightAccountVerifier->processLightAccountAuth(accountId, requestId, &inMsg, &g_hichainCallback);
    if (hichainRet != HC_SUCCESS) {
        uint32_t authErrCode = SOFTBUS_AUTH_HICHAIN_AUTH_FAIL;
        GetSoftbusHichainAuthErrorCode(hichainRet, &authErrCode);
        AUTH_LOGE(AUTH_KEY, "hichain process light account auth failed, errcode=%{public}d", authErrCode);
        return authErrCode;
    }
    return SOFTBUS_OK;
}
