/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
 
#include "napi_agent_communication.h"

#include <cstring>
#include <mutex>
#include "securec.h"
#include <dlfcn.h>

#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_agent_communication.h"
#include "napi_agent_communication_error_code.h"

namespace Communication {
namespace OHOS::Softbus {

static napi_threadsafe_function g_dataTsfn = nullptr;
static std::mutex g_callbackMutex;
#define ARGC_ONE 1
#define ARGC_TWO 2
#define ARGC_THREE 3

static void CallDataJsCallback(napi_env env, napi_value jsCallback, void *context, void *rawData)
{
    DataCallbackData *cb = static_cast<DataCallbackData *>(rawData);
 
    if (env == nullptr || jsCallback == nullptr || cb == nullptr) {
        delete cb;
        return;
    }

    napi_handle_scope scope;
    napi_open_handle_scope(env, &scope);

    napi_value networkId;
    napi_create_string_utf8(env, cb->deviceId.c_str(), NAPI_AUTO_LENGTH, &networkId);

    napi_value msg;
    napi_create_arraybuffer(env, cb->dataLen, nullptr, &msg);
    void *msgData = nullptr;
    napi_get_arraybuffer_info(env, msg, &msgData, nullptr);
    if (msgData != nullptr && cb->data != nullptr) {
        memcpy_s(msgData, cb->dataLen, cb->data, cb->dataLen);
    }
 
    napi_value argv[2];
    argv[0] = networkId;
    argv[1] = msg;

    napi_value global;
    napi_get_global(env, &global);

    napi_status status = napi_call_function(env, global, jsCallback, 2, argv, nullptr);
    COMM_LOGI(COMM_SDK, "CallDataJsCallback status=%{public}d", status);
    napi_close_handle_scope(env, scope);

    delete[] cb->data;
    delete cb;
}

static void FillConversationBusiness(ConversationBusiness &business, const std::string &bundleName,
                                     const std::string &abilityName)
{
    business = {};

    const size_t bundleLen = std::min(bundleName.size(), sizeof(business.bundleName) - 1);
    std::copy_n(bundleName.c_str(), bundleLen, business.bundleName);
    const size_t abilityLen = std::min(abilityName.size(), sizeof(business.abilityName) - 1);
    std::copy_n(abilityName.c_str(), abilityLen, business.abilityName);
}

static void ExecuteSendMsg(napi_env env, void *data)
{
    COMM_LOGI(COMM_SDK, "ExecuteSendMsg start");

    SendMsgContext *ctx = static_cast<SendMsgContext *>(data);
    FillConversationBusiness(ctx->business, ctx->bundleName, ctx->abilityName);
    int32_t ret = PostConversationData(ctx->deviceId.c_str(), &ctx->business,
                                        reinterpret_cast<char *>(ctx->msg), ctx->msgLen);
    ctx->resultCode = ConvertToJsErrcode(ret);
    COMM_LOGI(COMM_SDK, "ExecuteSendMsg finish result=%{public}d", ctx->resultCode);
 
    delete[] ctx->msg;
}

static void CompleteSendMsg(napi_env env, napi_status status, void *data)
{
    COMM_LOGI(COMM_SDK, "CompleteSendMsg");

    SendMsgContext *ctx = static_cast<SendMsgContext *>(data);
    if (ctx->resultCode != CONVERSATION_OK) {
        napi_reject_deferred(env, ctx->deferred, nullptr);
    } else {
        napi_value result;
        napi_get_undefined(env, &result);
        napi_resolve_deferred(env, ctx->deferred, result);
    }

    napi_delete_async_work(env, ctx->work);

    delete ctx;
}

static napi_value NapiGetTrustedDevicesSync(napi_env env, napi_value thisVar)
{
    napi_value resultArray;
    napi_create_array(env, &resultArray);

    DeviceNodeInfo *list = nullptr;
    int32_t nums = 0;
    int32_t resultCode = ConvertToJsErrcode(GetTrustedDevices(&list, &nums));
    if (resultCode == 0 && nums > 0) {
        for (int i = 0; i < nums; ++i) {
            napi_value jsDevice;
            napi_create_object(env, &jsDevice);

            napi_value networkId;
            napi_create_string_utf8(env, list[i].networkId, NAPI_AUTO_LENGTH, &networkId);
            napi_set_named_property(env, jsDevice, "networkId", networkId);

            napi_value deviceName;
            napi_create_string_utf8(env, list[i].deviceName, NAPI_AUTO_LENGTH, &deviceName);
            napi_set_named_property(env, jsDevice, "deviceName", deviceName);

            napi_value deviceTypeId;
            napi_create_int32(env, list[i].deviceTypeId, &deviceTypeId);
            napi_set_named_property(env, jsDevice, "deviceTypeId", deviceTypeId);

            napi_value nearby;
            napi_get_boolean(env, list[i].nearby, &nearby);
            napi_set_named_property(env, jsDevice, "nearby", nearby);

            napi_value udid;
            napi_create_string_utf8(env, list[i].udid, NAPI_AUTO_LENGTH, &udid);
            napi_set_named_property(env, jsDevice, "udid", udid);

            napi_set_element(env, resultArray, i, jsDevice);
        }
    }

    if (list != nullptr) {
        FreeDeviceNodeInfo(list);
    }

    return resultArray;
}

static napi_value NapiGetTrustedDevicesWrapper(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    return NapiGetTrustedDevicesSync(env, thisVar);
}

static napi_value NapiPostConversationDataAsync(napi_env env, napi_callback_info info)
{
    napi_value promise;
    auto *ctx = new SendMsgContext();
    ctx->env = env;
    size_t argc = SEND_ARGS_SIZE;
    napi_value argv[SEND_ARGS_SIZE];
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (argc < SEND_ARGS_SIZE) {
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        delete ctx;
        return nullptr;
    }
    if (!ParseString(env, ctx->deviceId, argv[0]) || !ParseString(env, ctx->bundleName, argv[1]) ||
        !ParseString(env, ctx->abilityName, argv[2])) {
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        delete ctx;
        return nullptr;
    }
 
    napi_valuetype valueType;
    napi_typeof(env, argv[3], &valueType);
    if (valueType != napi_object) {
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        delete ctx;
        return nullptr;
    }
 
    bool isArrayBuffer = false;
    napi_is_arraybuffer(env, argv[3], &isArrayBuffer);
    if (!isArrayBuffer) {
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        delete ctx;
        return nullptr;
    }
 
    void *data = nullptr;
    size_t byteLen = 0;
    napi_get_arraybuffer_info(env, argv[3], &data, &byteLen);
    if (data == nullptr || byteLen == 0) {
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        delete ctx;
        return nullptr;
    }
 
    ctx->msg = new uint8_t[byteLen];
    if (ctx->msg == nullptr) {
        ThrowBusinessError(env, CONVERSATION_INTERNAL_ERR);
        delete ctx;
        return nullptr;
    }
    ctx->msgLen = static_cast<uint32_t>(byteLen);
    if (memcpy_s(ctx->msg, ctx->msgLen, data, byteLen) != 0) {
        delete[] ctx->msg;
        ctx->msg = nullptr;
        ThrowBusinessError(env, CONVERSATION_INTERNAL_ERR);
        delete ctx;
        return nullptr;
    }

    napi_create_promise(env, &ctx->deferred, &promise);
    napi_value resourceName;
    napi_create_string_utf8(env, "SendMsgAsync", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(env, nullptr, resourceName, ExecuteSendMsg, CompleteSendMsg, ctx, &ctx->work);
    napi_queue_async_work(env, ctx->work);
    return promise;
}

static void OnDataRecvCallback(const char *deviceId, const char *data, uint32_t length)
{
    std::lock_guard<std::mutex> lock(g_callbackMutex);

    if (g_dataTsfn == nullptr) {
        COMM_LOGE(COMM_SDK, "tsfn is null");
        return;
    }
    DataCallbackData *cb = new DataCallbackData();
    if (deviceId != nullptr) {
        cb->deviceId = deviceId;
    }
    if (data != nullptr && length > 0) {
        cb->data = new uint8_t[length];
        if (cb->data != nullptr) {
            cb->dataLen = length;
            if (memcpy_s(cb->data, cb->dataLen, data, length) != 0) {
                delete[] cb->data;
                cb->data = nullptr;
                cb->dataLen = 0;
                delete cb;
                return;
            }
        }
    }
    napi_status status = napi_call_threadsafe_function(g_dataTsfn, cb, napi_tsfn_nonblocking);
    if (status != napi_ok) {
        COMM_LOGE(COMM_SDK, "napi_call_threadsafe_function failed");
        delete[] cb->data;
        delete cb;
    }
}

static napi_value NapiRegisterConversationListenerSync(napi_env env, size_t argc, napi_value *argv)
{
    if (argc < ARGC_THREE) {
        COMM_LOGE(COMM_SDK, "Need bundleName, abilityName, dataCallback");
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        return nullptr;
    }

    std::string bundleName;
    std::string abilityName;
 
    if (!ParseString(env, bundleName, argv[0]) || !ParseString(env, abilityName, argv[1])) {
        COMM_LOGE(COMM_SDK, "Invalid business args");
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        return nullptr;
    }
 
    napi_value dataCallback = argv[2];

    napi_valuetype dataType;
    napi_typeof(env, dataCallback, &dataType);

    if (dataType != napi_function) {
        COMM_LOGE(COMM_SDK, "dataCallback must be function");
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        return nullptr;
    }

    ConversationBusiness business;
    FillConversationBusiness(business, bundleName, abilityName);
    {
        std::lock_guard<std::mutex> lock(g_callbackMutex);

        if (g_dataTsfn != nullptr) {
            napi_release_threadsafe_function(g_dataTsfn, napi_tsfn_release);
            g_dataTsfn = nullptr;
        }

        napi_value dataResourceName;
        napi_create_string_utf8(env, "CloudDataCallback", NAPI_AUTO_LENGTH, &dataResourceName);
        napi_status status = napi_create_threadsafe_function(env, dataCallback, nullptr,
            dataResourceName, 0, 1, nullptr, nullptr, nullptr, CallDataJsCallback, &g_dataTsfn);
        if (status != napi_ok) {
            COMM_LOGE(COMM_SDK, "create data tsfn failed");
            hrowBusinessError(env, CONVERSATION_INTERNAL_ERR);
            return nullptr;
        }
    }

    static ConversationListener listener = {.OnDataReceived = OnDataRecvCallback};
    int32_t result = ConvertToJsErrcode(RegisterConversationListener(&business, &listener));
    if (result != CONVERSATION_OK) {
        ThrowBusinessError(env, result);
        return nullptr;
    }
    return nullptr;
}

static napi_value NapiRegisterConversationListenerWarpper(napi_env env, napi_callback_info info)
{
    size_t argc = REGISTER_ARGS_SIZE;
    napi_value argv[REGISTER_ARGS_SIZE];
    napi_value thisVar;

    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    return NapiRegisterConversationListenerSync(env, argc, argv);
}

static napi_value NapiunRegisterConversationListenerSync(napi_env env, size_t argc, napi_value *argv)
{
    napi_value ret;
    if (argc < ARGC_TWO) {
        COMM_LOGE(COMM_SDK, "Need bundleName, abilityName");
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        return nullptr;
    }

    std::string bundleName;
    std::string abilityName;

    if (!ParseString(env, bundleName, argv[0]) || !ParseString(env, abilityName, argv[1])) {
        COMM_LOGE(COMM_SDK, "Invalid business args");
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        return nullptr;
    }

    ConversationBusiness business;

    FillConversationBusiness(business, bundleName, abilityName);

    UnregisterConversationListener(&business);
    {
        std::lock_guard<std::mutex> lock(g_callbackMutex);
        if (g_dataTsfn != nullptr) {
            napi_release_threadsafe_function(g_dataTsfn, napi_tsfn_release);
            g_dataTsfn = nullptr;
        }
    }

    return nullptr;
}

static napi_value NapiUnregisterConversationListenerWarpper(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO];
    napi_value thisVar;

    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    return NapiunRegisterConversationListenerSync(env, argc, argv);
}

EXTERN_C_START
static napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("getTrustedDevices", NapiGetTrustedDevicesWrapper),
        DECLARE_NAPI_FUNCTION("postConversationData", NapiPostConversationDataAsync),
        DECLARE_NAPI_FUNCTION("registerConversationListener", NapiRegisterConversationListenerWarpper),
        DECLARE_NAPI_FUNCTION("unregisterConversationListener", NapiUnregisterConversationListenerWarpper)
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    return exports;
}
EXTERN_C_END

static napi_module demoModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "distributedSoftBus.conversation",
    .nm_priv = ((void *)0),
    .reserved = {0},
};

extern "C" __attribute__((constructor)) void RegisterNativeApplicationModule(void)
{
    napi_module_register(&demoModule);
}
} // namespace Softbus
} // namespace Communication