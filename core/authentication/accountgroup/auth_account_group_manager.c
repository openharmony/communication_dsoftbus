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
#include "lnn_async_callback_utils.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"

#define AUTH_ACCOUNT_PROCESS_TIMEOUT (10 * 1000LL)
#define D2D_CAAS_APPID "d2d_caas_appid"
#define D2D_SESSION_KEY_LEN 32
#define COMPARE_SUCCESS 0
#define COMPARE_FAILED 1

static bool g_isAccountAuthCbInited = false;
static IAccountAuthCallback *g_accountAuthCallback;
static SoftBusList *g_accountAuthList = NULL;
static SoftBusHandler g_authTimeoutHandler;
typedef struct {
    ListNode node;
    int64_t requestId;
} AccountAuthInstance;

enum AuthAccountLooperMsg {
    MSG_AUTH_ACCOUNT_TIMEOUT = 1,
};

static void GenAccountAuthTimeoutProcess(SoftBusMessage *msg);
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

static int32_t AuthAccountLooperInit(void)
{
    g_authTimeoutHandler.looper = GetLooper(LOOP_TYPE_DEFAULT);
    AUTH_CHECK_AND_RETURN_RET_LOGE(
        g_authTimeoutHandler.looper != NULL, SOFTBUS_LOOPER_ERR, AUTH_INIT, "get looper fail");

    g_authTimeoutHandler.name = (char *)"auth_account_handler";
    g_authTimeoutHandler.HandleMessage = GenAccountAuthTimeoutProcess;
    return SOFTBUS_OK;
}

static void AuthFreeMessage(SoftBusMessage *msg)
{
    AUTH_CHECK_AND_RETURN_LOGE(msg != NULL, AUTH_CONN, "ATTENTION UNEXPECTED ERROR, try to free a null msg");
    if (msg->obj != NULL) {
        SoftBusFree(msg->obj);
        msg->obj = NULL;
    }
    SoftBusFree(msg);
}

static int32_t AuthPostMsgToLooper(int64_t requestId, uint64_t delayMillis)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    AUTH_CHECK_AND_RETURN_RET_LOGE(msg != NULL, SOFTBUS_MEM_ERR, AUTH_CONN,
        "ATTENTION, calloc message object fail: requestId=%{public}" PRId64, requestId);
    msg->what = MSG_AUTH_ACCOUNT_TIMEOUT;
    msg->arg1 = (uint64_t)requestId;
    msg->arg2 = 0;
    msg->handler = &g_authTimeoutHandler;
    msg->FreeMessage = AuthFreeMessage;
    msg->obj = NULL;
    g_authTimeoutHandler.looper->PostMessageDelay(g_authTimeoutHandler.looper, msg, delayMillis);
    return SOFTBUS_OK;
}

static int CompareLooperEventFunc(const SoftBusMessage *msg, void *args)
{
    if (msg == NULL || args == NULL) {
        AUTH_LOGE(AUTH_INIT, "auth account param is invalid");
        return COMPARE_FAILED;
    }
    SoftBusMessage *ctx = (SoftBusMessage *)args;
    if (msg->what == ctx->what && msg->arg1 == ctx->arg1 && msg->arg2 == ctx->arg2) {
        return COMPARE_SUCCESS;
    }
    return COMPARE_FAILED;
}

static void AuthRemoveMsgFromLooper(int64_t requestId)
{
    AUTH_CHECK_AND_RETURN_LOGE(g_isAccountAuthCbInited, AUTH_CONN,
        "auth account group timeout handler is not initialized");
    SoftBusMessage ctx = {
        .what = MSG_AUTH_ACCOUNT_TIMEOUT,
        .arg1 = (uint64_t)requestId,
        .arg2 = 0,
        .obj = NULL,
    };
    g_authTimeoutHandler.looper->RemoveMessageCustom(
        g_authTimeoutHandler.looper, &g_authTimeoutHandler, CompareLooperEventFunc, &ctx);
}

static int32_t InitAccountAuthInstanceList(void)
{
    if (g_accountAuthList != NULL) {
        return SOFTBUS_OK;
    }
    g_accountAuthList = CreateSoftBusList();
    if (g_accountAuthList == NULL) {
        AUTH_LOGE(AUTH_INIT, "auth account create instance list fail");
        return SOFTBUS_CREATE_LIST_ERR;
    }
    g_accountAuthList->cnt = 0;
    return SOFTBUS_OK;
}

static void DeInitAccountAuthInstanceList(void)
{
    DestroySoftBusList(g_accountAuthList);
    g_accountAuthList = NULL;
}

void RegisterAccountAuth(IAccountAuthCallback *cb)
{
    if (cb == NULL) {
        AUTH_LOGE(AUTH_CONN, "account auth callback is null");
        return;
    }
    if (InitAccountAuthInstanceList() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_INIT, "init auth account instance fail");
        return;
    }
    if (AuthAccountLooperInit() != SOFTBUS_OK) {
        DeInitAccountAuthInstanceList();
        AUTH_LOGE(AUTH_INIT, "init auth account looper fail");
        return;
    }
    g_accountAuthCallback = cb;
    g_isAccountAuthCbInited = true;
}

static bool IsAccountAuthInstanceExist(int64_t requestId)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(g_isAccountAuthCbInited, false, AUTH_CONN,
        "auth account group manager is not initialized");

    AccountAuthInstance *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_accountAuthList->list, AccountAuthInstance, node) {
        if (item->requestId != requestId) {
            continue;
        }
        return true;
    }
    AUTH_LOGE(AUTH_CONN, "account auth instance not found, requestId=%{public}" PRId64, requestId);
    return false;
}

static int32_t CreateAccountAuthInstance(int64_t requestId)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_accountAuthList->lock) == SOFTBUS_OK,
        SOFTBUS_LOCK_ERR, AUTH_CONN, "lock fail, requestId=%{public}" PRId64, requestId);
    if (IsAccountAuthInstanceExist(requestId)) {
        AUTH_LOGI(AUTH_CONN, "account auth instance is exist, requestId=%{public}" PRId64, requestId);
        (void)SoftBusMutexUnlock(&g_accountAuthList->lock);
        return SOFTBUS_OK;
    }
    AccountAuthInstance *instance = (AccountAuthInstance *)SoftBusCalloc(sizeof(AccountAuthInstance));
    if (instance == NULL) {
        AUTH_LOGE(AUTH_CONN, "calloc instance fail");
        (void)SoftBusMutexUnlock(&g_accountAuthList->lock);
        return SOFTBUS_MEM_ERR;
    }
    instance->requestId = requestId;
    ListInit(&instance->node);
    ListAdd(&g_accountAuthList->list, &instance->node);
    g_accountAuthList->cnt++;
    (void)SoftBusMutexUnlock(&g_accountAuthList->lock);
    AuthPostMsgToLooper(requestId, AUTH_ACCOUNT_PROCESS_TIMEOUT);
    return SOFTBUS_OK;
}

static void DeleteAccountAuthInstance(int64_t requestId)
{
    AUTH_CHECK_AND_RETURN_LOGE(g_isAccountAuthCbInited, AUTH_CONN,
        "auth account group manager is not initialized");

    AccountAuthInstance *item = NULL;
    AccountAuthInstance *nextItem = NULL;
    AUTH_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_accountAuthList->lock) == SOFTBUS_OK,
        AUTH_CONN, "lock fail, requestId=%{public}" PRId64, requestId);
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_accountAuthList->list, AccountAuthInstance, node) {
        if (item->requestId != requestId) {
            continue;
        }
        AUTH_LOGI(AUTH_CONN, "delete account auth instance, requestId=%{public}" PRId64, requestId);
        ListDelete(&(item->node));
        SoftBusFree(item);
        g_accountAuthList->cnt--;
        (void)SoftBusMutexUnlock(&g_accountAuthList->lock);
        return;
    }
    AUTH_LOGE(AUTH_CONN, "account auth instance not found, requestId=%{public}" PRId64, requestId);
    (void)SoftBusMutexUnlock(&g_accountAuthList->lock);
}

static void GenAccountAuthTimeoutProcess(SoftBusMessage *msg)
{
    AUTH_CHECK_AND_RETURN_LOGE(msg != NULL, AUTH_CONN, "msg is null");
    int64_t requestId = (int64_t)msg->arg1;
    AUTH_LOGE(AUTH_CONN, "account auth timeout, requestId=%{public}" PRId64, requestId);
    AUTH_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_accountAuthList->lock) == SOFTBUS_OK,
        AUTH_CONN, "lock fail, requestId=%{public}" PRId64, requestId);
    if (IsAccountAuthInstanceExist(requestId)) {
        (void)SoftBusMutexUnlock(&g_accountAuthList->lock);
        OnError(requestId, 0, SOFTBUS_CHANNEL_AUTH_START_TIMEOUT, NULL);
        return;
    }
    (void)SoftBusMutexUnlock(&g_accountAuthList->lock);
}

static bool OnTransmitted(int64_t authSeq, const uint8_t *data, uint32_t len)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(data != NULL && len > 0, false, AUTH_CONN, "transmit invalid param");
    AUTH_LOGI(AUTH_CONN, "account auth transmit, authseq=%{public}" PRId64 ", len=%{public}u", authSeq, len);
    if (g_accountAuthCallback == NULL) {
        AUTH_LOGE(AUTH_CONN, "account auth callback is null");
        return false;
    }
    if (g_accountAuthCallback->onTransmit == NULL) {
        AUTH_LOGE(AUTH_CONN, "account auth transmit callback is null");
        return false;
    }
    bool ret = g_accountAuthCallback->onTransmit(authSeq, data, len);
    if (!ret) {
        AUTH_LOGE(AUTH_CONN, "account auth transmit failed");
    }
    return ret;
}

static void OnSessionKeyReturned(int64_t authSeq, const uint8_t *sessionKey, uint32_t sessionKeyLen)
{
    AUTH_CHECK_AND_RETURN_LOGE(sessionKey != NULL && sessionKeyLen > 0 && sessionKeyLen <= D2D_SESSION_KEY_LEN,
        AUTH_CONN, "session key return invalid param, keyLen=%{public}u", sessionKeyLen);
    AUTH_LOGI(AUTH_CONN, "account auth sessionkey return, authseq=%{public}" PRId64, authSeq);
    if (g_accountAuthCallback == NULL) {
        AUTH_LOGE(AUTH_CONN, "account auth callback is null");
        return;
    }
    if (g_accountAuthCallback->onSessionKeyReturned == NULL) {
        AUTH_LOGE(AUTH_CONN, "account auth sessionkey return callback is null");
        return;
    }
    g_accountAuthCallback->onSessionKeyReturned(authSeq, sessionKey, sessionKeyLen);
}

static void OnFinished(int64_t authSeq, int32_t operationCode, const char *returnData)
{
    AUTH_CHECK_AND_RETURN_LOGE(returnData != NULL, AUTH_CONN, "account auth finished invalid return data");
    AUTH_LOGI(AUTH_CONN, "account auth finished, authseq=%{public}" PRId64, authSeq);
    if (g_accountAuthCallback == NULL) {
        AUTH_LOGE(AUTH_CONN, "account auth callback is null");
        return;
    }
    if (g_accountAuthCallback->onFinish == NULL) {
        AUTH_LOGE(AUTH_CONN, "account auth finished callback is null");
        return;
    }
    DeleteAccountAuthInstance(authSeq);
    AuthRemoveMsgFromLooper(authSeq);
    g_accountAuthCallback->onFinish(authSeq, operationCode, returnData);
}

static void OnError(int64_t authSeq, int32_t operationCode, int32_t errCode, const char *returnData)
{
    uint32_t authErrCode = 0;
    GetSoftbusHichainAuthErrorCode((uint32_t)errCode, &authErrCode);
    AUTH_LOGE(AUTH_CONN, "account auth OnError: authSeq=%{public}" PRId64 ", errCode=%{public}d authErrCode=%{public}d",
        authSeq, errCode, authErrCode);
    if (g_accountAuthCallback == NULL) {
        AUTH_LOGE(AUTH_CONN, "account auth callback is null");
        return;
    }
    if (g_accountAuthCallback->onError == NULL) {
        AUTH_LOGE(AUTH_CONN, "account auth error callback is null");
        return;
    }
    DeleteAccountAuthInstance(authSeq);
    if (errCode != SOFTBUS_CHANNEL_AUTH_START_TIMEOUT) {
        AuthRemoveMsgFromLooper(authSeq);
    }
    g_accountAuthCallback->onError(authSeq, operationCode, authErrCode, returnData);
}

static char *OnRequest(int64_t authSeq, int32_t operationCode, const char *reqParams)
{
    (void)reqParams;
    AUTH_LOGI(AUTH_CONN, "account auth request: authSeq=%{public}" PRId64 ", code=%{public}d", authSeq, operationCode);

    cJSON *msg = cJSON_CreateObject();
    if (msg == NULL) {
        AUTH_LOGE(AUTH_CONN, "create json fail");
        return NULL;
    }
    if (!AddStringToJsonObject(msg, FIELD_APP_ID, D2D_CAAS_APPID)) {
        AUTH_LOGE(AUTH_CONN, "add appid failed");
        cJSON_Delete(msg);
        return NULL;
    }
    char *msgStr = cJSON_PrintUnformatted(msg);
    cJSON_Delete(msg);
    if (msgStr == NULL) {
        AUTH_LOGE(AUTH_CONN, "cJSON_PrintUnformatted failed");
        return NULL;
    }
    return msgStr;
}

static const LightAccountVerifier *GetLightAccountInstance()
{
    int32_t ret = InitDeviceAuthService();
    if (ret != HC_SUCCESS) {
        AUTH_LOGE(AUTH_CONN, "init device auth service failed, err=%{public}d", ret);
        return NULL;
    }
    return GetLightAccountVerifierInstance();
}

int32_t StartGroupAccountAuth(const char *pkgName, int64_t requestId, const char *serviceId)
{
    AUTH_LOGI(AUTH_CONN, "start account auth, requestId=%{public}" PRId64, requestId);
    AUTH_CHECK_AND_RETURN_RET_LOGE(pkgName != NULL && serviceId != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN,
        "param is invalid");
    const LightAccountVerifier *lightAccountVerifier = GetLightAccountInstance();
    AUTH_CHECK_AND_RETURN_RET_LOGE(lightAccountVerifier != NULL, SOFTBUS_AUTH_GET_LIGHT_ACCOUNT_FAIL, AUTH_CONN,
        "light account verifier is not initialized");
    AUTH_CHECK_AND_RETURN_RET_LOGE(lightAccountVerifier->startLightAccountAuth != NULL,
        SOFTBUS_AUTH_GET_LIGHT_ACCOUNT_FAIL, AUTH_CONN, "startLightAccountAuth is not initialized");
    AUTH_CHECK_AND_RETURN_RET_LOGE(g_isAccountAuthCbInited, SOFTBUS_NO_INIT, AUTH_CONN,
        "auth account group manager is not initialized");
    int32_t ret = CreateAccountAuthInstance(requestId);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "create account auth instance fail");
        return ret;
    }
    int32_t accountId = JudgeDeviceTypeAndGetOsAccountIds();
    int32_t hichainRet =
        lightAccountVerifier->startLightAccountAuth(accountId, requestId, serviceId, &g_hichainCallback);
    if (hichainRet != HC_SUCCESS) {
        uint32_t authErrCode = SOFTBUS_AUTH_HICHAIN_AUTH_FAIL;
        GetSoftbusHichainAuthErrorCode(hichainRet, &authErrCode);
        AUTH_LOGE(AUTH_CONN, "hichain start light account auth failed, errcode=%{public}d", authErrCode);
        DeleteAccountAuthInstance(requestId);
        AuthRemoveMsgFromLooper(requestId);
        return authErrCode;
    }
    return SOFTBUS_OK;
}

int32_t ProcessGroupAccountAuth(const char *pkgName, int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    AUTH_LOGI(AUTH_CONN, "process account auth, requestId=%{public}" PRId64, requestId);
    AUTH_CHECK_AND_RETURN_RET_LOGE(pkgName != NULL && data != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN,
        "param is invalid");
    const LightAccountVerifier *lightAccountVerifier = GetLightAccountInstance();
    AUTH_CHECK_AND_RETURN_RET_LOGE(lightAccountVerifier != NULL, SOFTBUS_AUTH_GET_LIGHT_ACCOUNT_FAIL, AUTH_CONN,
        "light account verifier is not initialized");
    AUTH_CHECK_AND_RETURN_RET_LOGE(lightAccountVerifier->processLightAccountAuth != NULL,
        SOFTBUS_AUTH_GET_LIGHT_ACCOUNT_FAIL, AUTH_CONN, "processLightAccountAuth is not initialized");
    AUTH_CHECK_AND_RETURN_RET_LOGE(g_isAccountAuthCbInited, SOFTBUS_NO_INIT, AUTH_CONN,
        "auth account group manager is not initialized");
    int32_t ret = CreateAccountAuthInstance(requestId);
    if (ret != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "create account auth instance fail");
        return ret;
    }
    int32_t accountId = JudgeDeviceTypeAndGetOsAccountIds();
    DataBuff inMsg = { .data = (uint8_t *)data, .length = dataLen };
    int32_t hichainRet =
        lightAccountVerifier->processLightAccountAuth(accountId, requestId, &inMsg, &g_hichainCallback);
    if (hichainRet != HC_SUCCESS) {
        uint32_t authErrCode = SOFTBUS_AUTH_HICHAIN_AUTH_FAIL;
        GetSoftbusHichainAuthErrorCode(hichainRet, &authErrCode);
        AUTH_LOGE(AUTH_CONN, "hichain process light account auth failed, errcode=%{public}d", authErrCode);
        DeleteAccountAuthInstance(requestId);
        AuthRemoveMsgFromLooper(requestId);
        return authErrCode;
    }
    return SOFTBUS_OK;
}
