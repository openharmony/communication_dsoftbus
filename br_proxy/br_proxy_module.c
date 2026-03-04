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
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "br_proxy.h"
#include "br_proxy_session_manager.h"
#include "comm_log.h"
#include "hilog/log.h"
#include "napi/native_api.h"
#include "securec.h"
#include "softbus_error_code.h"
#include "softbus_napi_utils.h"
#include "trans_log.h"

#define ARGS_SIZE_1         1
#define ARGS_SIZE_2         2
#define ARGS_SIZE_3         3
#define ARGS_INDEX_0        0
#define ARGS_INDEX_1        1
#define ARGS_INDEX_2        2
#define FUNC_NAME_MAX_LEN   22

typedef struct {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    BrProxyChannelInfo channelInfo;
    int32_t channelId;
    int32_t openResult;
    int32_t ret;
    int32_t sessionId;
} AsyncOpenChannelData;

static void OnDataReceived(int32_t channelId, const char* data, uint32_t dataLen);
static void OnChannelStatusChanged(int32_t channelId, int32_t state);
static int32_t ChannelOpened(int32_t sessionId, int32_t channelId, int32_t result)
{
    TRANS_LOGI(TRANS_SDK, "[br_proxy] sessionId:%{public}d.", sessionId);
    int32_t ret = UpdateListBySessionId(sessionId, channelId, result);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGI(TRANS_SDK, "[br_proxy] ret:%{public}d.", ret);
        return ret;
    }

    return BrProxyPostCond(sessionId);
}

static void OpenProxyChannelExecute(napi_env env, void* data)
{
    BrProxyChannelInfo channelInfo;
    AsyncOpenChannelData* asyncData = (AsyncOpenChannelData*)data;
    if (memcpy_s(channelInfo.peerBRMacAddr, sizeof(channelInfo.peerBRMacAddr),
        asyncData->channelInfo.peerBRMacAddr, sizeof(asyncData->channelInfo.peerBRMacAddr)) != EOK ||
        memcpy_s(channelInfo.peerBRUuid, sizeof(channelInfo.peerBRUuid),
            asyncData->channelInfo.peerBRUuid, sizeof(asyncData->channelInfo.peerBRUuid)) != EOK) {
        asyncData->ret = SOFTBUS_MEM_ERR;
        return;
    }
    channelInfo.recvPri = asyncData->channelInfo.recvPri;
    IBrProxyListener listener = {
        .onChannelOpened = ChannelOpened,
        .onDataReceived = OnDataReceived,
        .onChannelStatusChanged = OnChannelStatusChanged,
    };
    int32_t ret = AddSessionToList(asyncData->sessionId);
    if (ret != SOFTBUS_OK) {
        asyncData->ret = ret;
        return;
    }
    ret = OpenBrProxy(asyncData->sessionId, &channelInfo, &listener);
    asyncData->ret = ret;
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] openBrProxy failed! ret:%{public}d.", ret);
        return;
    }
    ret = BrProxyWaitCond(asyncData->sessionId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] BrProxyWaitCond failed! ret:%{public}d.", ret);
        asyncData->ret = ret;
        return;
    }
    SessionInfo info;
    ret = GetSessionInfoBySessionId(asyncData->sessionId, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] GetSessionInfoBySessionId failed! ret:%{public}d.", ret);
        asyncData->ret = ret;
        return;
    }
    asyncData->channelId = info.channelId;
    asyncData->openResult = info.openResult;
}

static void OpenProxyChannelComplete(napi_env env, napi_status status, void* data)
{
    AsyncOpenChannelData* asyncData = (AsyncOpenChannelData*)data;
    napi_status napiStatus;
    napi_value channelIdValue;
    int32_t ret = asyncData->ret;
    int32_t openResult = asyncData->openResult;
    int32_t sessionId = asyncData->sessionId;

    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] open channel failed, ret=%{public}d.", ret);
        napi_reject_deferred(env, asyncData->deferred, GetBusinessError(env, ret));
        goto exit;
    }

    if (openResult != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] openResult=%{public}d.", openResult);
        napi_reject_deferred(env, asyncData->deferred, GetBusinessError(env, openResult));
        goto exit;
    }

    napiStatus = napi_create_int32(env, asyncData->channelId, &channelIdValue);
    if (napiStatus != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] create channelId failed.");
        goto cleanup;
    }

    napiStatus = napi_resolve_deferred(env, asyncData->deferred, channelIdValue);
cleanup:
    if (napiStatus != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] resolve promise failed.");
        napi_reject_deferred(env, asyncData->deferred, NULL);
    }
exit:
    DeleteSessionById(sessionId);
    napi_delete_async_work(env, asyncData->work);
    SoftBusFree(asyncData);
}

static int32_t GetChannelInfoParam(napi_env env, napi_value arg, AsyncOpenChannelData *asyncData)
{
    napi_status status;
    napi_value peerBRMacAddrValue;
    napi_value peerBRUuidValue;
    size_t strLen;
    size_t macLen;
    size_t uuidLen;
    napi_value linkTypeValue;
    status = napi_get_named_property(env, arg, "linkType", &linkTypeValue);
    if (status != napi_ok) {
        goto EXIT;
    }
    status = napi_get_value_int32(env, linkTypeValue, &asyncData->channelInfo.linktype);
    if (status != napi_ok) {
        goto EXIT;
    }
    if (napi_get_named_property(env, arg, "peerDevAddr", &peerBRMacAddrValue) != napi_ok ||
        napi_get_named_property(env, arg, "peerUuid", &peerBRUuidValue) != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] get peerDevAddr/peerUuid failed.");
        goto EXIT;
    }
    if (napi_get_value_string_utf8(env, peerBRMacAddrValue, NULL, 0, &macLen) != napi_ok ||
        napi_get_value_string_utf8(env, peerBRUuidValue, NULL, 0, &uuidLen) != napi_ok) {
        goto EXIT;
    }
    if (macLen < MAC_MIN_LENGTH || (macLen > MAC_MAX_LENGTH && macLen != MAC_SHA256_LEN)) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] mac len is wrong, macLen:%{public}zu", macLen);
        goto EXIT;
    }
    if (uuidLen != UUID_STD_LENGTH && uuidLen != UUID_NO_HYPHEN_LENGTH) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] uuid len is wrong, uuidLen:%{public}zu", uuidLen);
        goto EXIT;
    }
    if (napi_get_value_string_utf8(env, peerBRMacAddrValue, asyncData->channelInfo.peerBRMacAddr,
        sizeof(asyncData->channelInfo.peerBRMacAddr), &strLen) != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] get peerDevAddr failed.");
        goto EXIT;
    }
    if (napi_get_value_string_utf8(env, peerBRUuidValue, asyncData->channelInfo.peerBRUuid,
        sizeof(asyncData->channelInfo.peerBRUuid), &strLen) != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] get peerUuid failed.");
        goto EXIT;
    }
    return SOFTBUS_OK;
EXIT:
    TRANS_LOGE(TRANS_SDK, "[br_proxy] get channel info param failed.");
    ThrowErrFromC2Js(env, SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM);
    return SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM;
}

static int32_t StartWork(napi_env env, AsyncOpenChannelData *asyncData)
{
    napi_value resourceName;
    napi_status status = napi_create_string_utf8(env, "OpenProxyChannelAsyncWork", NAPI_AUTO_LENGTH, &resourceName);
    if (status != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] create string failed.");
        napi_reject_deferred(env, asyncData->deferred, NULL);
        return SOFTBUS_NO_INIT;
    }

    status = napi_create_async_work(env, NULL, resourceName, OpenProxyChannelExecute, OpenProxyChannelComplete,
        asyncData, &asyncData->work);
    if (status != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] create async work failed.");
        napi_reject_deferred(env, asyncData->deferred, NULL);
        return SOFTBUS_NO_INIT;
    }
    status = napi_queue_async_work(env, asyncData->work);
    if (status != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] queue async work failed.");
        napi_reject_deferred(env, asyncData->deferred, NULL);
        napi_delete_async_work(env, asyncData->work);
        return SOFTBUS_NO_INIT;
    }
    return SOFTBUS_OK;
}

napi_value NapiOpenProxyChannel(napi_env env, napi_callback_info info)
{
    TRANS_LOGI(TRANS_SDK, "[br_proxy] enter.");
    size_t argc = ARGS_SIZE_1;
    napi_value args[ARGS_SIZE_1];
    napi_value thisArg;
    void* data;
    napi_status status = napi_get_cb_info(env, info, &argc, args, &thisArg, &data);
    if (status != napi_ok || argc < ARGS_SIZE_1) {
        napi_throw_error(env, NULL, "Invalid arguments");
        return NULL;
    }
    napi_valuetype valuetype;
    status = napi_typeof(env, args[0], &valuetype);
    if (status != napi_ok || valuetype != napi_object) {
        napi_throw_error(env, NULL, "Argument must be an object");
        return NULL;
    }
    AsyncOpenChannelData* asyncData = (AsyncOpenChannelData*)SoftBusCalloc(sizeof(AsyncOpenChannelData));
    if (asyncData == NULL) {
        napi_throw_error(env, NULL, "Memory allocation failed");
        return NULL;
    }
    asyncData->env = env;

    if (GetChannelInfoParam(env, args[0], asyncData) != SOFTBUS_OK || SessionInit() != SOFTBUS_OK) {
        goto EXIT;
    }
    int32_t sessionId = GetSessionId();
    if (sessionId <= 0) {
        goto EXIT;
    }
    asyncData->sessionId = sessionId;
    napi_value promise;
    status = napi_create_promise(env, &asyncData->deferred, &promise);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to create promise");
        goto EXIT;
    }
    int32_t ret = StartWork(env, asyncData);
    if (ret != SOFTBUS_OK) {
        goto EXIT;
    }
    TRANS_LOGI(TRANS_SDK, "[br_proxy] open success, sessionId=%{public}d.", sessionId);
    return promise;
EXIT:
    TRANS_LOGE(TRANS_SDK, "[br_proxy] open proxy failed");
    SoftBusFree(asyncData);
    return NULL;
}

napi_value ChannelStateEnumInit(napi_env env, napi_value exports)
{
    napi_status status;
    napi_value typeEnum;
    status = napi_create_object(env, &typeEnum);
    if (status != napi_ok) {
        return NULL;
    }

    napi_value typeValue;
    if (napi_create_int32(env, CHANNEL_WAIT_RESUME, &typeValue) != napi_ok ||
        napi_set_named_property(env, typeEnum, "CHANNEL_WAIT_RESUME", typeValue)) {
        return NULL;
    }

    if (napi_create_int32(env, CHANNEL_RESUME, &typeValue) != napi_ok ||
        napi_set_named_property(env, typeEnum, "CHANNEL_RESUME", typeValue) != napi_ok) {
        return NULL;
    }

    if (napi_create_int32(env, CHANNEL_EXCEPTION_SOFTWARE_FAILED, &typeValue) != napi_ok ||
        napi_set_named_property(env, typeEnum, "CHANNEL_EXCEPTION_SOFTWARE_FAILED", typeValue) != napi_ok) {
        return NULL;
    }

    if (napi_create_int32(env, CHANNEL_BR_NO_PAIRED, &typeValue) != napi_ok ||
        napi_set_named_property(env, typeEnum, "CHANNEL_BR_NO_PAIRED", typeValue) != napi_ok) {
        return NULL;
    }

    status = napi_set_named_property(env, exports, "ChannelState", typeEnum);
    if (status != napi_ok) {
        return NULL;
    }

    return exports;
}

napi_value NapiCloseProxyChannel(napi_env env, napi_callback_info info)
{
    TRANS_LOGI(TRANS_SDK, "[br_proxy] enter.");
    size_t argc = ARGS_SIZE_1;
    napi_value args[ARGS_SIZE_1];
    napi_value thisArg;
    void* data;
    napi_status status = napi_get_cb_info(env, info, &argc, args, &thisArg, &data);
    if (status != napi_ok || argc < ARGS_SIZE_1) {
        ThrowErrFromC2Js(env, SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM);
        return NULL;
    }
    napi_valuetype valuetype;
    status = napi_typeof(env, args[0], &valuetype);
    if (status != napi_ok || valuetype != napi_number) {
        ThrowErrFromC2Js(env, SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM);
        return NULL;
    }
    int32_t channelId;
    status = napi_get_value_int32(env, args[0], &channelId);
    if (status != napi_ok) {
        ThrowErrFromC2Js(env, SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM);
        return NULL;
    }
    double value;
    status = napi_get_value_double(env, args[0], &value);
    if (status != napi_ok) {
        ThrowErrFromC2Js(env, SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM);
        return NULL;
    }
    int32_t intValue = (int32_t)value;
    bool isInteger = (double)intValue == value;
    if (!isInteger) {
        ThrowErrFromC2Js(env, SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM);
        return NULL;
    }
    int32_t ret = CloseBrProxy(channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] close failed, ret=%{public}d.", ret);
        ThrowErrFromC2Js(env, ret);
        return NULL;
    }
    napi_value undefined;
    status = napi_get_undefined(env, &undefined);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to get undefined value.");
        return NULL;
    }
    TRANS_LOGI(TRANS_SDK, "[br_proxy] close success, channelId=%{public}d.", channelId);
    return undefined;
}

typedef struct {
    napi_env env;
    napi_async_work work;
    napi_deferred deferred;
    int32_t channelId;
    char* data;
    size_t dataLength;
    int32_t ret;
} AsyncSendData;

typedef struct QueueNode {
    AsyncSendData* data;
    struct QueueNode* next;
} QueueNode;

typedef struct {
    QueueNode* head;
    QueueNode* tail;
    pthread_mutex_t mutex;
    bool isProcessing;
} TaskQueue;

// 初始化全局队列
static TaskQueue g_taskQueue = {
    .head = NULL,
    .tail = NULL,
    .isProcessing = false
};

void InitTaskQueue()
{
    pthread_mutex_init(&g_taskQueue.mutex, NULL);
    g_taskQueue.head = g_taskQueue.tail = NULL;
    g_taskQueue.isProcessing = false;
}

static void AsyncWorkComplete(napi_env env, napi_status status, void* data);
static void AsyncWorkExecute(napi_env env, void* data);

static void ProcessTaskQueue()
{
    bool shouldExit = false;
    while (!shouldExit) {
        pthread_mutex_lock(&g_taskQueue.mutex);
        if (g_taskQueue.head == NULL || g_taskQueue.isProcessing) {
            shouldExit = true;
            pthread_mutex_unlock(&g_taskQueue.mutex);
            return;
        }
        g_taskQueue.isProcessing = true;
        QueueNode* node = g_taskQueue.head;
        g_taskQueue.head = g_taskQueue.head->next;
        if (g_taskQueue.head == NULL) {
            shouldExit = true;
            g_taskQueue.tail = NULL;
        }
        pthread_mutex_unlock(&g_taskQueue.mutex);
        AsyncSendData* asyncData = node->data;
        SoftBusFree(node);

        napi_env env = asyncData->env;
        napi_value resourceName;
        napi_status status = napi_create_string_utf8(env, "SendDataAsyncWork", NAPI_AUTO_LENGTH, &resourceName);
        if (status != napi_ok) {
            napi_reject_deferred(env, asyncData->deferred, NULL);
            goto cleanup;
        }

        status = napi_create_async_work(env, NULL, resourceName, AsyncWorkExecute, AsyncWorkComplete,
            asyncData, &asyncData->work);
        if (status != napi_ok) {
            napi_reject_deferred(env, asyncData->deferred, NULL);
            goto cleanup;
        }
        status = napi_queue_async_work(env, asyncData->work);
        if (status != napi_ok) {
            napi_reject_deferred(env, asyncData->deferred, NULL);
            napi_delete_async_work(env, asyncData->work);
            goto cleanup;
        }
        continue;
    cleanup:
        TRANS_LOGE(TRANS_SDK, "[br_proxy] process task failed.");
        SoftBusFree(asyncData->data);
        SoftBusFree(asyncData);
        pthread_mutex_lock(&g_taskQueue.mutex);
        g_taskQueue.isProcessing = false;
        pthread_mutex_unlock(&g_taskQueue.mutex);
    }
}

static void AsyncWorkExecute(napi_env env, void* data)
{
    AsyncSendData* asyncData = (AsyncSendData*)data;
    int32_t ret = SendBrProxyData(asyncData->channelId, asyncData->data, asyncData->dataLength);
    asyncData->ret = ret;
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] send data failed, ret=%{public}d.", ret);
    }
}

static void AsyncWorkComplete(napi_env env, napi_status status, void* data)
{
    AsyncSendData* asyncData = (AsyncSendData*)data;
    napi_status napiStatus;

    if (asyncData->ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] send data failed, ret=%{public}d.", asyncData->ret);
        napi_reject_deferred(env, asyncData->deferred, GetBusinessError(env, asyncData->ret));
        goto cleanup;
    }

    napi_value undefined;
    napiStatus = napi_get_undefined(env, &undefined);
    if (napiStatus != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] get undefined failed.");
        napi_reject_deferred(env, asyncData->deferred, NULL);
        goto cleanup;
    }
    napiStatus = napi_resolve_deferred(env, asyncData->deferred, undefined);
    if (napiStatus != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] resolve promise failed.");
        napi_reject_deferred(env, asyncData->deferred, NULL);
    }
cleanup:
    SoftBusFree(asyncData->data);
    napi_delete_async_work(env, asyncData->work);
    SoftBusFree(asyncData);

    pthread_mutex_lock(&g_taskQueue.mutex);
    g_taskQueue.isProcessing = false;
    pthread_mutex_unlock(&g_taskQueue.mutex);
    ProcessTaskQueue();  // 处理队列中的下一个任务
}

static bool ChanneIdIsInt(napi_env env, napi_value *args)
{
    double value;
    napi_status status = napi_get_value_double(env, args[0], &value);
    if (status != napi_ok) {
        return false;
    }
    int32_t intValue = (int32_t)value;
    bool isInteger = (double)intValue == value;
    return isInteger;
}

static int32_t GetSendParam(napi_env env, napi_callback_info info, AsyncSendData *asyncData)
{
    size_t argc = ARGS_SIZE_2;
    napi_value args[ARGS_SIZE_2];
    napi_value thisArg;
    void* data;
    napi_status status = napi_get_cb_info(env, info, &argc, args, &thisArg, &data);
    if (status != napi_ok || argc < ARGS_SIZE_2) {
        goto EXIT;
    }
    napi_valuetype valueTypeNum;
    status = napi_typeof(env, args[0], &valueTypeNum);
    if (status != napi_ok || valueTypeNum != napi_number) {
        goto EXIT;
    }
    status = napi_get_value_int32(env, args[0], &asyncData->channelId);
    if (status != napi_ok) {
        goto EXIT;
    }
    if (!ChanneIdIsInt(env, args)) {
        goto EXIT;
    }
    napi_valuetype valueTypeBuffer;
    status = napi_typeof(env, args[1], &valueTypeBuffer);
    if (status != napi_ok) {
        goto EXIT;
    }
    void* bufferData;
    status = napi_get_arraybuffer_info(env, args[1], &bufferData, &asyncData->dataLength);
    if (status != napi_ok || asyncData->dataLength == 0) {
        goto EXIT;
    }
    asyncData->data = (char*)SoftBusCalloc(asyncData->dataLength);
    if (asyncData->data == NULL) {
        ThrowErrFromC2Js(env, SOFTBUS_MEM_ERR);
        return SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM;
    }
    if (memcpy_s(asyncData->data, asyncData->dataLength, bufferData, asyncData->dataLength) != EOK) {
        SoftBusFree(asyncData->data);
        ThrowErrFromC2Js(env, SOFTBUS_MEM_ERR);
        return SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM;
    }
    return SOFTBUS_OK;
EXIT:
    TRANS_LOGE(TRANS_SDK, "[br_proxy] get send param failed.");
    ThrowErrFromC2Js(env, SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM);
    return SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM;
}

napi_value SendDataAsync(napi_env env, napi_callback_info info)
{
    napi_value promise;
    AsyncSendData* asyncData = (AsyncSendData*)SoftBusCalloc(sizeof(AsyncSendData));
    if (asyncData == NULL) {
        napi_throw_error(env, NULL, "Memory allocation failed");
        return NULL;
    }
    asyncData->env = env;

    int32_t ret = GetSendParam(env, info, asyncData);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] get param failed.");
        SoftBusFree(asyncData);
        return NULL;
    }

    napi_status status = napi_create_promise(env, &asyncData->deferred, &promise);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to create promise");
        goto cleanup;
    }
    TRANS_LOGI(TRANS_SDK, "[br_proxy] channelId=%{public}d.", asyncData->channelId);
    pthread_mutex_lock(&g_taskQueue.mutex);
    QueueNode* node = (QueueNode*)SoftBusCalloc(sizeof(QueueNode));
    if (node == NULL) {
        pthread_mutex_unlock(&g_taskQueue.mutex);
        napi_throw_error(env, NULL, "Memory allocation failed");
        goto cleanup;
    }
    node->data = asyncData;
    node->next = NULL;
    if (g_taskQueue.tail == NULL) {
        g_taskQueue.head = g_taskQueue.tail = node;
    } else {
        g_taskQueue.tail->next = node;
        g_taskQueue.tail = node;
    }
    pthread_mutex_unlock(&g_taskQueue.mutex);

    ProcessTaskQueue();
    return promise;
cleanup:
    TRANS_LOGE(TRANS_SDK, "[br_proxy] send data failed.");
    SoftBusFree(asyncData->data);
    SoftBusFree(asyncData);
    return NULL;
}

static napi_threadsafe_function tsfn_data_received = NULL;
static napi_threadsafe_function tsfn_channel_status = NULL;

typedef struct {
    int32_t channelId;
    char* data;
    uint32_t dataLen;
} DataReceiveArgs;

typedef struct {
    int32_t channelId;
    int32_t status;
} ChannelStatusArgs;

static void DataReceivedCallback(napi_env env, napi_value callback, void *context, void *data)
{
    DataReceiveArgs* args = (DataReceiveArgs*)data;
    napi_value dataInfo;
    napi_status status = napi_create_object(env, &dataInfo);
    if (status != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] create object failed.");
        goto cleanup;
    }

    napi_value channelIdValue;
    status = napi_create_int32(env, args->channelId, &channelIdValue);
    if (status != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] create channelId failed.");
        goto cleanup;
    }

    status = napi_set_named_property(env, dataInfo, "channelId", channelIdValue);
    if (status != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] set channelId failed.");
        goto cleanup;
    }

    napi_value arrayBuffer;
    void *dataBuffer;
    status = napi_create_arraybuffer(env, args->dataLen, &dataBuffer, &arrayBuffer);
    if (status != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] create arraybuffer failed.");
        goto cleanup;
    }
    if (memcpy_s(dataBuffer, args->dataLen, args->data, args->dataLen) != EOK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] memcpy data failed.");
        goto cleanup;
    }
    status = napi_set_named_property(env, dataInfo, "data", arrayBuffer);
    if (status != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] set data property failed.");
        goto cleanup;
    }
    napi_value result;
    napi_value args_array[1] = {dataInfo};
    status = napi_call_function(env, NULL, callback, 1, args_array, &result);
cleanup:
    SoftBusFree(args->data);
    SoftBusFree(args);
}

static void ChannelStatusCallback(napi_env env, napi_value callback, void *context, void *data)
{
    ChannelStatusArgs* args = (ChannelStatusArgs*)data;

    napi_value statusInfo;
    napi_status status = napi_create_object(env, &statusInfo);
    if (status != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] create object failed.");
        goto cleanup;
    }

    napi_value channelIdValue;
    status = napi_create_int32(env, args->channelId, &channelIdValue);
    if (status != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] create channelId failed.");
        goto cleanup;
    }

    status = napi_set_named_property(env, statusInfo, "channelId", channelIdValue);
    if (status != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] set channelId failed.");
        goto cleanup;
    }

    napi_value statusValue;
    status = napi_create_int32(env, args->status, &statusValue);
    if (status != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] create status failed.");
        goto cleanup;
    }

    status = napi_set_named_property(env, statusInfo, "state", statusValue);
    if (status != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] set state failed.");
        goto cleanup;
    }

    napi_value result;
    napi_value args_array[1] = {statusInfo};
    status = napi_call_function(env, NULL, callback, 1, args_array, &result);
cleanup:
    SoftBusFree(args);
}

static void OnDataReceived(int32_t channelId, const char* data, uint32_t dataLen)
{
    if (data == NULL || dataLen == 0 || dataLen > BR_PROXY_SEND_MAX_LEN) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] data is null or invalid dataLen=%{public}u", dataLen);
        return;
    }
    if (tsfn_data_received == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] tsfn_data_received is null.");
        return;
    }

    DataReceiveArgs* args = (DataReceiveArgs*)SoftBusCalloc(sizeof(DataReceiveArgs));
    if (args == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] alloc args failed.");
        return;
    }
    args->channelId = channelId;
    args->dataLen = dataLen;
    args->data = (char *)SoftBusCalloc(dataLen);
    if (args->data == NULL) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] alloc data failed.");
        SoftBusFree(args);
        return;
    }

    if (memcpy_s(args->data, dataLen, data, dataLen) != EOK) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] memcpy failed.");
        SoftBusFree(args->data);
        SoftBusFree(args);
        return;
    }

    napi_status status = napi_call_threadsafe_function(tsfn_data_received, args, napi_tsfn_nonblocking);
    if (status != napi_ok) {
        TRANS_LOGE(TRANS_SVC, "[br_proxy] call threadsafe failed.");
        SoftBusFree(args->data);
        SoftBusFree(args);
    }
}

static void OnChannelStatusChanged(int32_t channelId, int32_t status)
{
    if (tsfn_channel_status == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] tsfn_channel_status is null.");
        return;
    }

    ChannelStatusArgs* args = (ChannelStatusArgs*)SoftBusCalloc(sizeof(ChannelStatusArgs));
    if (args == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] alloc args failed.");
        return;
    }

    args->channelId = channelId;
    args->status = status;

    napi_status ret = napi_call_threadsafe_function(tsfn_channel_status, args, napi_tsfn_nonblocking);
    if (ret != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] call threadsafe function failed.");
        SoftBusFree(args);
    }
}

static void SetCallbackInternal(napi_env env, napi_value callback, int32_t channelId, ListenerType type)
{
    int32_t ret;
    switch (type) {
        case DATA_RECEIVE:
            if (tsfn_data_received != NULL) {
                napi_release_threadsafe_function(tsfn_data_received, napi_tsfn_abort);
                tsfn_data_received = NULL;
            }
            napi_create_threadsafe_function(
                env, callback, NULL, "DataReceived",
                0, 1, NULL, NULL, NULL,
                DataReceivedCallback, &tsfn_data_received);
            ret = SetListenerState(channelId, DATA_RECEIVE, true);
            if (ret != SOFTBUS_OK) {
                TRANS_LOGE(TRANS_SDK, "[br_proxy] set receive listener failed, ret=%{public}d.", ret);
                napi_release_threadsafe_function(tsfn_data_received, napi_tsfn_abort);
                tsfn_data_received = NULL;
            }
            ThrowErrFromC2Js(env, ret);
            break;
        case CHANNEL_STATE:
            if (tsfn_channel_status != NULL) {
                napi_release_threadsafe_function(tsfn_channel_status, napi_tsfn_abort);
                tsfn_channel_status = NULL;
            }
            napi_create_threadsafe_function(
                env, callback, NULL, "ChannelStatus",
                0, 1, NULL, NULL, NULL,
                ChannelStatusCallback, &tsfn_channel_status);
            ret = SetListenerState(channelId, CHANNEL_STATE, true);
            if (ret != SOFTBUS_OK) {
                TRANS_LOGE(TRANS_SDK, "[br_proxy] set state listener failed, ret=%{public}d.", ret);
                napi_release_threadsafe_function(tsfn_channel_status, napi_tsfn_abort);
                tsfn_channel_status = NULL;
            }
            ThrowErrFromC2Js(env, ret);
            break;
        default:
            break;
    }
}

napi_value On(napi_env env, napi_callback_info info)
{
    TRANS_LOGI(TRANS_SDK, "[br_proxy] enter.");
    size_t argc = ARGS_SIZE_3;
    napi_value args[ARGS_SIZE_3];
    napi_status status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
    if (status != napi_ok || argc != ARGS_SIZE_3) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] invalid args.");
        goto EXIT;
    }
    char type[FUNC_NAME_MAX_LEN];
    size_t typeLen;
    status = napi_get_value_string_utf8(env, args[ARGS_INDEX_0], type, sizeof(type), &typeLen);
    if (status != napi_ok) {
        goto EXIT;
    }
    int32_t channelId;
    status = napi_get_value_int32(env, args[ARGS_INDEX_1], &channelId);
    if (status != napi_ok) {
        goto EXIT;
    }
    double value;
    status = napi_get_value_double(env, args[ARGS_INDEX_1], &value);
    if (status != napi_ok) {
        goto EXIT;
    }
    int32_t intValue = (int32_t)value;
    bool isInteger = (double)intValue == value;
    if (!isInteger) {
        goto EXIT;
    }
    napi_valuetype funcType;
    status = napi_typeof(env, args[ARGS_INDEX_2], &funcType);
    if (status != napi_ok || funcType != napi_function) {
        goto EXIT;
    }
    if (strcmp(type, "receiveData") == 0) {
        SetCallbackInternal(env, args[ARGS_INDEX_2], channelId, DATA_RECEIVE);
    } else if (strcmp(type, "channelStateChange") == 0) {
        SetCallbackInternal(env, args[ARGS_INDEX_2], channelId, CHANNEL_STATE);
    } else {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] unknown type=%{public}s.", type);
        goto EXIT;
    }
    TRANS_LOGI(TRANS_SDK, "[br_proxy] on success, type=%{public}s, channelId=%{public}d.", type, channelId);
    return NULL;
EXIT:
    ThrowErrFromC2Js(env, SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM);
    return NULL;
}

static int32_t GetOffParam(napi_env env, napi_value *args, size_t argc, int32_t *channelId)
{
    if (channelId == NULL) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] channelId is null.");
        return SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM;
    }

    napi_status status = napi_get_value_int32(env, args[ARGS_INDEX_1], channelId);
    if (status != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] get channelId failed.");
        return SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM;
    }
    double value;
    status = napi_get_value_double(env, args[ARGS_INDEX_1], &value);
    if (status != napi_ok) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] get double failed.");
        return SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM;
    }
    int32_t intValue = (int32_t)value;
    bool isInteger = (double)intValue == value;
    if (!isInteger) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] not integer.");
        return SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM;
    }
    if (argc != ARGS_SIZE_3) {
        return SOFTBUS_OK;
    }
    napi_valuetype funcType;
    status = napi_typeof(env, args[ARGS_INDEX_2], &funcType);
    if (status != napi_ok || funcType != napi_function) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] callback not function.");
        return SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

napi_value Off(napi_env env, napi_callback_info info)
{
    TRANS_LOGI(TRANS_SDK, "[br_proxy] enter.");
    size_t argc = ARGS_SIZE_3;
    napi_value args[ARGS_SIZE_3];
    napi_status status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
    if (status != napi_ok || argc < ARGS_SIZE_2) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] invalid args.");
        goto EXIT;
    }
    char type[FUNC_NAME_MAX_LEN];
    size_t typeLen;
    status = napi_get_value_string_utf8(env, args[ARGS_INDEX_0], type, sizeof(type), &typeLen);
    if (status != napi_ok) {
        goto EXIT;
    }
    int32_t channelId = 0;
    int32_t ret = GetOffParam(env, args, argc, &channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] get off param failed.");
        goto EXIT;
    }

    if (strcmp(type, "receiveData") == 0) {
        if (tsfn_data_received != NULL) {
            napi_release_threadsafe_function(tsfn_data_received, napi_tsfn_abort);
            tsfn_data_received = NULL;
        }
        ret = SetListenerState(channelId, DATA_RECEIVE, false);
        ThrowErrFromC2Js(env, ret);
    } else if (strcmp(type, "channelStateChange") == 0) {
        if (tsfn_channel_status != NULL) {
            napi_release_threadsafe_function(tsfn_channel_status, napi_tsfn_abort);
            tsfn_channel_status = NULL;
        }
        ret = SetListenerState(channelId, CHANNEL_STATE, false);
        ThrowErrFromC2Js(env, ret);
    } else {
        TRANS_LOGE(TRANS_SDK, "[br_proxy] unknown type=%{public}s.", type);
        goto EXIT;
    }
    TRANS_LOGI(TRANS_SDK, "[br_proxy] off success, type=%{public}s, channelId=%{public}d.", type, channelId);
    return NULL;
EXIT:
    ThrowErrFromC2Js(env, SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM);
    return NULL;
}

napi_value LinkTypeEnumInit(napi_env env, napi_value exports)
{
    napi_status status;
    napi_value typeEnum;
    status = napi_create_object(env, &typeEnum);
    if (status != napi_ok) {
        return NULL;
    }

    napi_value typeValue;
    status = napi_create_int32(env, LINK_BR, &typeValue);
    if (status != napi_ok) {
        return NULL;
    }
    status = napi_set_named_property(env, typeEnum, "LINK_BR", typeValue);
    if (status != napi_ok) {
        return NULL;
    }
    status = napi_set_named_property(env, exports, "LinkType", typeEnum);
    if (status != napi_ok) {
        return NULL;
    }

    return exports;
}

static napi_value NapiSoftbusTransInit(napi_env env, napi_value exports)
{
    napi_status status;
    napi_value fn;
    status = napi_create_function(env, NULL, NAPI_AUTO_LENGTH, NapiOpenProxyChannel, NULL, &fn);
    if (status != napi_ok) {
        return NULL;
    }
    status = napi_set_named_property(env, exports, "openProxyChannel", fn);
    if (status != napi_ok) {
        return NULL;
    }
    status = napi_create_function(env, NULL, NAPI_AUTO_LENGTH, NapiCloseProxyChannel, NULL, &fn);
    if (status != napi_ok) {
        return NULL;
    }
    status = napi_set_named_property(env, exports, "closeProxyChannel", fn);
    if (status != napi_ok) {
        return NULL;
    }
    status = napi_create_function(env, NULL, NAPI_AUTO_LENGTH, SendDataAsync, NULL, &fn);
    if (status != napi_ok) {
        return NULL;
    }
    status = napi_set_named_property(env, exports, "sendData", fn);
    if (status != napi_ok) {
        return NULL;
    }
    if (ChannelStateEnumInit(env, exports) == NULL || LinkTypeEnumInit(env, exports) == NULL) {
        return NULL;
    }
    status = napi_create_function(env, NULL, NAPI_AUTO_LENGTH, On, NULL, &fn);
    if (status != napi_ok) {
        return NULL;
    }
    status = napi_set_named_property(env, exports, "on", fn);
    if (status != napi_ok) {
        return NULL;
    }
    status = napi_create_function(env, NULL, NAPI_AUTO_LENGTH, Off, NULL, &fn);
    if (status != napi_ok) {
        return NULL;
    }
    status = napi_set_named_property(env, exports, "off", fn);
    if (status != napi_ok) {
        return NULL;
    }
    return exports;
}

/*
 * Module definition
 */
static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = "distributedsched.proxyChannelManager",
    .nm_register_func = NapiSoftbusTransInit,
    .nm_modname = "distributedsched.proxyChannelManager",
    .nm_priv = ((void *)0),
    .reserved = { 0 }
};

/*
 * Module registration
 */
__attribute__((constructor)) void RegisterSoftbusTransModule(void)
{
    InitTaskQueue();
    napi_module_register(&g_module);
}

__attribute__((destructor)) void DestructSoftbusTransModule(void)
{
    if (tsfn_data_received != NULL) {
        napi_release_threadsafe_function(tsfn_data_received, napi_tsfn_abort);
        tsfn_data_received = NULL;
    }
    
    if (tsfn_channel_status != NULL) {
        napi_release_threadsafe_function(tsfn_channel_status, napi_tsfn_abort);
        tsfn_channel_status = NULL;
    }
}