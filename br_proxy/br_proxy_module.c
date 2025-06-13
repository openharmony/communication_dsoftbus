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
#include <semaphore.h>
#include <stdio.h>

#include "br_proxy.h"
#include "comm_log.h"
#include "hilog/log.h"
#include "napi/native_api.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
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
} AsyncOpenChannelData;

static bool g_sem_inited = false;
static sem_t g_sem;
static int32_t g_channelId = 0;
static int32_t g_openResult = 0;

static void OnDataReceived(int32_t channelId, const char* data, uint32_t dataLen);
static void OnChannelStatusChanged(int32_t channelId, int32_t state);
static int32_t ChannelOpened(int32_t channelId, int32_t result)
{
    g_channelId = channelId;
    g_openResult = result;
    sem_post(&g_sem);
    return SOFTBUS_OK;
}

static void OpenProxyChannelExecute(napi_env env, void* data)
{
    BrProxyChannelInfo channelInfo;
    AsyncOpenChannelData* asyncData = (AsyncOpenChannelData*)data;
    if (memcpy_s(channelInfo.peerBRMacAddr, sizeof(channelInfo.peerBRMacAddr),
        asyncData->channelInfo.peerBRMacAddr, sizeof(asyncData->channelInfo.peerBRMacAddr)) != EOK ||
        memcpy_s(channelInfo.peerBRUuid, sizeof(channelInfo.peerBRUuid),
            asyncData->channelInfo.peerBRUuid, sizeof(asyncData->channelInfo.peerBRUuid)) != EOK) {
        return;
    }
    channelInfo.recvPri = asyncData->channelInfo.recvPri;
    IBrProxyListener listener = {
        .onChannelOpened = ChannelOpened,
        .onDataReceived = OnDataReceived,
        .onChannelStatusChanged = OnChannelStatusChanged,
    };
    int32_t ret = OpenBrProxy(&channelInfo, &listener);
    asyncData->ret = ret;
    if (ret != SOFTBUS_OK) {
        return;
    }
    sem_wait(&g_sem);
    asyncData->channelId = g_channelId;
    asyncData->openResult = g_openResult;
}

static void OpenProxyChannelComplete(napi_env env, napi_status status, void* data)
{
    AsyncOpenChannelData* asyncData = (AsyncOpenChannelData*)data;
    napi_status napiStatus;
    napi_value channelIdValue;
    int32_t ret = asyncData->ret;
    int32_t openResult = asyncData->openResult;

    if (ret != SOFTBUS_OK) {
        napi_reject_deferred(env, asyncData->deferred, GetBusinessError(env, ret));
        goto exit;
    }

    if (openResult != SOFTBUS_OK) {
        napi_reject_deferred(env, asyncData->deferred, GetBusinessError(env, openResult));
        goto exit;
    }

    napiStatus = napi_create_int32(env, asyncData->channelId, &channelIdValue);
    if (napiStatus != napi_ok) {
        goto cleanup;
    }

    napiStatus = napi_resolve_deferred(env, asyncData->deferred, channelIdValue);
cleanup:
    if (napiStatus != napi_ok) {
        napi_reject_deferred(env, asyncData->deferred, NULL);
    }
exit:
    napi_delete_async_work(env, asyncData->work);
    SoftBusFree(asyncData);
}

static int32_t GetChannelInfoParam(napi_env env, napi_value arg, AsyncOpenChannelData *asyncData)
{
    napi_status status;
    napi_value peerBRMacAddrValue;
    napi_value peerBRUuidValue;
    size_t strLen;
    napi_value linkTypeValue;
    status = napi_get_named_property(env, arg, "linkType", &linkTypeValue);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to get linkType property");
        return SOFTBUS_INVALID_PARAM;
    }
    status = napi_get_value_int32(env, linkTypeValue, &asyncData->channelInfo.linktype);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to convert linkType to integer");
        return SOFTBUS_INVALID_PARAM;
    }
    if (napi_get_named_property(env, arg, "peerDevAddr", &peerBRMacAddrValue) != napi_ok ||
        napi_get_value_string_utf8(env, peerBRMacAddrValue, asyncData->channelInfo.peerBRMacAddr,
            sizeof(asyncData->channelInfo.peerBRMacAddr), &strLen) != napi_ok) {
        napi_throw_error(env, NULL, "Failed to get peerBRMacAddr");
        return SOFTBUS_INVALID_PARAM;
    }

    if (napi_get_named_property(env, arg, "peerUuid", &peerBRUuidValue) != napi_ok ||
        napi_get_value_string_utf8(env, peerBRUuidValue, asyncData->channelInfo.peerBRUuid,
            sizeof(asyncData->channelInfo.peerBRUuid), &strLen) != napi_ok) {
        napi_throw_error(env, NULL, "Failed to get peerUuid");
        return SOFTBUS_INVALID_PARAM;
    }

    napi_value recvPriValue;
    status = napi_get_named_property(env, arg, "recvPri", &recvPriValue);
    if (status == napi_ok) {
        status = napi_get_value_int32(env, recvPriValue, &asyncData->channelInfo.recvPri);
        if (status != napi_ok) {
            napi_throw_error(env, NULL, "Failed to get recvPri");
            return SOFTBUS_INVALID_PARAM;
        }
        asyncData->channelInfo.recvPriSet = true;
    }
    return SOFTBUS_OK;
}

static int32_t StartWork(napi_env env, AsyncOpenChannelData *asyncData)
{
    napi_status status;
    napi_value resourceName;
    status = napi_create_string_utf8(env, "OpenProxyChannelAsyncWork", NAPI_AUTO_LENGTH, &resourceName);
    if (status != napi_ok) {
        napi_reject_deferred(env, asyncData->deferred, NULL);
        SoftBusFree(asyncData);
        return SOFTBUS_NO_INIT;
    }

    status = napi_create_async_work(env, NULL, resourceName, OpenProxyChannelExecute, OpenProxyChannelComplete,
        asyncData, &asyncData->work);
    if (status != napi_ok) {
        napi_reject_deferred(env, asyncData->deferred, NULL);
        SoftBusFree(asyncData);
        return SOFTBUS_NO_INIT;
    }
    status = napi_queue_async_work(env, asyncData->work);
    if (status != napi_ok) {
        napi_reject_deferred(env, asyncData->deferred, NULL);
        napi_delete_async_work(env, asyncData->work);
        SoftBusFree(asyncData);
        return SOFTBUS_NO_INIT;
    }
    return SOFTBUS_OK;
}

napi_value NapiOpenProxyChannel(napi_env env, napi_callback_info info)
{
    napi_status status;
    size_t argc = ARGS_SIZE_1;
    napi_value args[ARGS_SIZE_1];
    napi_value thisArg;
    void* data;
    status = napi_get_cb_info(env, info, &argc, args, &thisArg, &data);
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
    asyncData->channelInfo.recvPriSet = false;
    
    int32_t ret = GetChannelInfoParam(env, args[0], asyncData);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(asyncData);
        return NULL;
    }
    if (!g_sem_inited) {
        sem_init(&g_sem, 0, 0);
        g_sem_inited = true;
    }
    napi_value promise;
    status = napi_create_promise(env, &asyncData->deferred, &promise);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to create promise");
        SoftBusFree(asyncData);
        return NULL;
    }

    ret = StartWork(env, asyncData);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(asyncData);
        return NULL;
    }
    return promise;
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

    status = napi_set_named_property(env, exports, "ChannelState", typeEnum);
    if (status != napi_ok) {
        return NULL;
    }

    return exports;
}

napi_value NapiCloseProxyChannel(napi_env env, napi_callback_info info)
{
    napi_status status;
    size_t argc = ARGS_SIZE_1;
    napi_value args[ARGS_SIZE_1];
    napi_value thisArg;
    void* data;
    status = napi_get_cb_info(env, info, &argc, args, &thisArg, &data);
    if (status != napi_ok || argc < ARGS_SIZE_1) {
        napi_throw_error(env, NULL, "Invalid arguments: Expected one argument.");
        return NULL;
    }
    napi_valuetype valuetype;
    status = napi_typeof(env, args[0], &valuetype);
    if (status != napi_ok || valuetype != napi_number) {
        napi_throw_type_error(env, NULL, "Invalid argument type: Expected a number.");
        return NULL;
    }
    int32_t channelId;
    status = napi_get_value_int32(env, args[0], &channelId);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to get argument value.");
        return NULL;
    }

    int32_t ret = CloseBrProxy(channelId);
    if (ret != SOFTBUS_OK) {
        ThrowErrFromC2Js(env, ret);
        return NULL;
    }
    napi_value undefined;
    status = napi_get_undefined(env, &undefined);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to get undefined value.");
        return NULL;
    }
    if (g_sem_inited) {
        g_sem_inited = false;
        sem_destroy(&g_sem);
    }
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

static void AsyncWorkExecute(napi_env env, void* data)
{
    AsyncSendData* asyncData = (AsyncSendData*)data;
    int32_t ret = SendBrProxyData(asyncData->channelId, asyncData->data, asyncData->dataLength);
    asyncData->ret = ret;
}

static void AsyncWorkComplete(napi_env env, napi_status status, void* data)
{
    AsyncSendData* asyncData = (AsyncSendData*)data;
    napi_status napiStatus;

    if (asyncData->ret != SOFTBUS_OK) {
        napi_reject_deferred(env, asyncData->deferred, GetBusinessError(env, asyncData->ret));
        goto cleanup;
    }

    napi_value undefined;
    napiStatus = napi_get_undefined(env, &undefined);
    if (napiStatus != napi_ok) {
        napi_reject_deferred(env, asyncData->deferred, NULL);
        goto cleanup;
    }
    napiStatus = napi_resolve_deferred(env, asyncData->deferred, undefined);
    if (napiStatus != napi_ok) {
        napi_reject_deferred(env, asyncData->deferred, NULL);
    }
cleanup:
    SoftBusFree(asyncData->data);
    napi_delete_async_work(env, asyncData->work);
    SoftBusFree(asyncData);
}

static int32_t GetSendParam(napi_env env, napi_callback_info info, AsyncSendData *asyncData)
{
    size_t argc = ARGS_SIZE_2;
    napi_value args[ARGS_SIZE_2];
    napi_value thisArg;
    void* data;
    napi_status status = napi_get_cb_info(env, info, &argc, args, &thisArg, &data);
    if (status != napi_ok || argc < ARGS_SIZE_2) {
        napi_throw_error(env, NULL, "Invalid arguments: Expected two arguments.");
        return SOFTBUS_INVALID_PARAM;
    }
    napi_valuetype valueTypeNum;
    status = napi_typeof(env, args[0], &valueTypeNum);
    if (status != napi_ok || valueTypeNum != napi_number) {
        napi_throw_type_error(env, NULL, "Invalid argument type: First argument must be a number.");
        return SOFTBUS_INVALID_PARAM;
    }
    status = napi_get_value_int32(env, args[0], &asyncData->channelId);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to get channel ID argument value.");
        return SOFTBUS_INVALID_PARAM;
    }
    napi_valuetype valueTypeBuffer;
    status = napi_typeof(env, args[1], &valueTypeBuffer);
    if (status != napi_ok) {
        napi_throw_type_error(env, NULL, "Invalid argument type: Second argument must be an ArrayBuffer.");
        return SOFTBUS_INVALID_PARAM;
    }
    void* bufferData;
    status = napi_get_arraybuffer_info(env, args[1], &bufferData, &asyncData->dataLength);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to get ArrayBuffer info.");
        return SOFTBUS_INVALID_PARAM;
    }
    asyncData->data = (char*)SoftBusCalloc(asyncData->dataLength);
    if (asyncData->data == NULL) {
        napi_throw_error(env, NULL, "Memory allocation for data failed");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(asyncData->data, asyncData->dataLength, bufferData, asyncData->dataLength) != EOK) {
        SoftBusFree(asyncData->data);
        napi_throw_error(env, NULL, "Memory allocation for data failed");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

napi_value SendDataAsync(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value promise;
    AsyncSendData* asyncData = (AsyncSendData*)SoftBusCalloc(sizeof(AsyncSendData));
    if (asyncData == NULL) {
        napi_throw_error(env, NULL, "Memory allocation failed");
        return NULL;
    }
    asyncData->env = env;
    
    int32_t ret = GetSendParam(env, info, asyncData);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(asyncData);
        return NULL;
    }

    status = napi_create_promise(env, &asyncData->deferred, &promise);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to create promise");
        goto cleanup;
    }

    napi_value resourceName;
    status = napi_create_string_utf8(env, "SendDataAsyncWork", NAPI_AUTO_LENGTH, &resourceName);
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
    return promise;
cleanup:
    SoftBusFree(asyncData->data);
    SoftBusFree(asyncData);
    return NULL;
}

napi_env global_env = NULL;
napi_ref receiveDataCallbackRef = NULL;
napi_ref receiveChannelStatusCallbackRef = NULL;

typedef struct {
    napi_async_work work;
    napi_env env;
    napi_ref callback_ref;
    int32_t channelId;
    char* data;
    uint32_t dataLen;
} AsyncRecvData;

typedef struct {
    napi_async_work work;
    napi_env env;
    napi_ref callback_ref;
    int32_t channelId;
    int32_t state;
} AsyncChannelStatus;

void AsyncDataExecute(napi_env env, void* data)
{
}

void AsyncDataComplete(napi_env env, napi_status res, void* data)
{
    AsyncRecvData* asyncData = (AsyncRecvData*)data;

    if (asyncData->callback_ref == NULL) {
        goto cleanup;
    }

    napi_value callback;
    napi_status status = napi_get_reference_value(env, asyncData->callback_ref, &callback);
    if (status != napi_ok) {
        goto cleanup;
    }

    napi_value dataInfo;
    status = napi_create_object(env, &dataInfo);
    if (status != napi_ok) {
        goto cleanup;
    }

    napi_value channelIdValue;
    status = napi_create_int32(env, asyncData->channelId, &channelIdValue);
    if (status != napi_ok) {
        goto cleanup;
    }
    status = napi_set_named_property(env, dataInfo, "channelId", channelIdValue);
    if (status != napi_ok) {
        goto cleanup;
    }
    napi_value arrayBuffer;
    void *dataBuffer;
    status = napi_create_arraybuffer(env, asyncData->dataLen, &dataBuffer, &arrayBuffer);
    if (status != napi_ok) {
        goto cleanup;
    }
    for (uint32_t i = 0; i < asyncData->dataLen; i++) {
        ((char *)dataBuffer)[i] = asyncData->data[i];
    }
    status = napi_set_named_property(env, dataInfo, "data", arrayBuffer);
    if (status != napi_ok) {
        goto cleanup;
    }
    napi_value result;
    napi_value args[ARGS_SIZE_1] = {dataInfo};
    napi_call_function(env, NULL, callback, ARGS_SIZE_1, args, &result);
cleanup:
    SoftBusFree(asyncData->data);
    SoftBusFree(asyncData);
}

static void AsyncChannelStatusExecute(napi_env env, void* data)
{
}

static void AsyncChannelStatusComplete(napi_env env, napi_status res, void* data)
{
    AsyncChannelStatus* asyncStatus = (AsyncChannelStatus*)data;
    if (asyncStatus->callback_ref == NULL) {
        goto cleanup;
    }
    napi_value callback;
    napi_status status = napi_get_reference_value(env, asyncStatus->callback_ref, &callback);
    if (status != napi_ok) {
        goto cleanup;
    }
    napi_value channelStateInfo;
    status = napi_create_object(env, &channelStateInfo);
    if (status != napi_ok) {
        goto cleanup;
    }
    napi_value value;
    if (napi_create_int32(env, asyncStatus->channelId, &value) != napi_ok ||
        napi_set_named_property(env, channelStateInfo, "channelId", value) != napi_ok) {
        goto cleanup;
    }
    status = napi_create_int32(env, asyncStatus->state, &value);
    if (status != napi_ok) {
        goto cleanup;
    }
    status = napi_set_named_property(env, channelStateInfo, "state", value);
    if (status != napi_ok) {
        goto cleanup;
    }

    napi_value result;
    napi_value args[ARGS_SIZE_1] = {channelStateInfo};
    napi_call_function(env, NULL, callback, ARGS_SIZE_1, args, &result);
cleanup:
    SoftBusFree(asyncStatus);
}

static void OnDataReceived(int32_t channelId, const char* data, uint32_t dataLen)
{
    if (global_env == NULL || receiveDataCallbackRef == NULL) {
        return;
    }

    AsyncRecvData* asyncData = (AsyncRecvData*)SoftBusCalloc(sizeof(AsyncRecvData));
    if (asyncData == NULL) {
        return;
    }
    asyncData->env = global_env;
    asyncData->callback_ref = receiveDataCallbackRef;
    asyncData->channelId = channelId;
    asyncData->data = (char*)SoftBusCalloc(dataLen);
    if (asyncData->data == NULL) {
        SoftBusFree(asyncData);
        return;
    }
    if (memcpy_s(asyncData->data, dataLen, data, dataLen) != EOK) {
        goto cleanup;
    }
    asyncData->dataLen = dataLen;

    napi_value resource_name;
    napi_status status = napi_create_string_utf8(global_env, "DataReceivedAsync", NAPI_AUTO_LENGTH, &resource_name);
    if (status != napi_ok) {
        goto cleanup;
    }
    status = napi_create_async_work(global_env, NULL, resource_name, AsyncDataExecute, AsyncDataComplete,
        asyncData, &asyncData->work);
    if (status != napi_ok) {
        goto cleanup;
    }
    status = napi_queue_async_work(global_env, asyncData->work);
    if (status != napi_ok) {
        goto cleanup;
    }
    return;
cleanup:
    SoftBusFree(asyncData->data);
    SoftBusFree(asyncData);
}

static void OnChannelStatusChanged(int32_t channelId, int32_t state)
{
    if (global_env == NULL || receiveChannelStatusCallbackRef == NULL) {
        return;
    }

    AsyncChannelStatus* asyncStatus = (AsyncChannelStatus*)SoftBusCalloc(sizeof(AsyncChannelStatus));
    if (asyncStatus == NULL) {
        return;
    }
    asyncStatus->env = global_env;
    asyncStatus->callback_ref = receiveChannelStatusCallbackRef;
    asyncStatus->channelId = channelId;
    asyncStatus->state = state;

    napi_value resource_name;
    napi_status status = napi_create_string_utf8(global_env, "ChannelStatusChangedAsync",
        NAPI_AUTO_LENGTH, &resource_name);
    if (status != napi_ok) {
        goto cleanup;
    }
    status = napi_create_async_work(global_env, NULL, resource_name,
        AsyncChannelStatusExecute, AsyncChannelStatusComplete, asyncStatus, &asyncStatus->work);
    if (status != napi_ok) {
        goto cleanup;
    }
    status = napi_queue_async_work(global_env, asyncStatus->work);
    if (status != napi_ok) {
        goto cleanup;
    }
    return;
cleanup:
    SoftBusFree(asyncStatus);
}

napi_value On(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_3;
    napi_value args[ARGS_SIZE_3];
    napi_status status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
    if (status != napi_ok || argc != ARGS_SIZE_3) {
        napi_throw_type_error(env, NULL, "Expected 3 arguments");
        return NULL;
    }

    char type[FUNC_NAME_MAX_LEN];
    size_t typeLen;
    status = napi_get_value_string_utf8(env, args[ARGS_INDEX_0], type, sizeof(type), &typeLen);
    if (status != napi_ok) {
        napi_throw_type_error(env, NULL, "get string failed");
        return NULL;
    }

    int32_t channelId;
    status = napi_get_value_int32(env, args[ARGS_INDEX_1], &channelId);
    if (status != napi_ok) {
        napi_throw_type_error(env, NULL, "get channelId failed");
        return NULL;
    }

    if (strcmp(type, "receiveData") == 0) {
        napi_create_reference(env, args[ARGS_INDEX_2], 1, &receiveDataCallbackRef);
        int32_t ret = SetListenerState(channelId, DATA_RECEIVE, true);
        ThrowErrFromC2Js(env, ret);
    } else if (strcmp(type, "channelStateChange") == 0) {
        napi_create_reference(env, args[ARGS_INDEX_2], 1, &receiveChannelStatusCallbackRef);
        int32_t ret = SetListenerState(channelId, CHANNEL_STATE, true);
        ThrowErrFromC2Js(env, ret);
    } else {
        napi_throw_type_error(env, NULL, "Invalid event type");
        return NULL;
    }
    global_env = env;
    return NULL;
}

napi_value Off(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_2;
    napi_value args[ARGS_SIZE_2];
    napi_status status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
    if (status != napi_ok || argc < ARGS_SIZE_2) {
        napi_throw_type_error(env, NULL, "Expected at least 2 arguments");
        return NULL;
    }

    char type[FUNC_NAME_MAX_LEN];
    size_t typeLen;
    status = napi_get_value_string_utf8(env, args[ARGS_INDEX_0], type, sizeof(type), &typeLen);
    if (status != napi_ok) {
        napi_throw_type_error(env, NULL, "get string failed");
        return NULL;
    }

    int32_t channelId;
    status = napi_get_value_int32(env, args[ARGS_INDEX_1], &channelId);
    if (status != napi_ok) {
        napi_throw_type_error(env, NULL, "get channelId failed");
        return NULL;
    }
    if (strcmp(type, "receiveData") == 0) {
        if (receiveDataCallbackRef != NULL) {
            napi_delete_reference(env, receiveDataCallbackRef);
            receiveDataCallbackRef = NULL;
        }
        int32_t ret = SetListenerState(channelId, DATA_RECEIVE, false);
        ThrowErrFromC2Js(env, ret);
    } else if (strcmp(type, "channelStateChange") == 0) {
        if (receiveChannelStatusCallbackRef != NULL) {
            napi_delete_reference(env, receiveChannelStatusCallbackRef);
            receiveChannelStatusCallbackRef = NULL;
        }
        int32_t ret = SetListenerState(channelId, CHANNEL_STATE, false);
        ThrowErrFromC2Js(env, ret);
    } else {
        napi_throw_type_error(env, NULL, "Invalid event type");
        return NULL;
    }

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
    napi_module_register(&g_module);
}

__attribute__((destructor)) void DestructSoftbusTransModule(void)
{
}