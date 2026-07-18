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
#include <map>
#include <mutex>
#include <string>
#include "securec.h"
#include <dlfcn.h>

#include "accesstoken_kit.h"
#include "access_token.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "anonymizer.h"
#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_agent_communication.h"
#include "napi_agent_communication_error_code.h"

namespace Communication {
namespace OHOS::Softbus {

static std::map<std::string, napi_threadsafe_function> g_dataTsfnMap;
static std::mutex g_callbackMutex;
#define ARGC_ONE 1
#define ARGC_TWO 2
#define ARGC_THREE 3

static void LogBusinessParam(const char *funcName, const std::string &deviceId,
    const std::string &bundleName, const std::string &abilityName, uint32_t dataLen)
{
    char *anonyDeviceId = nullptr;
    char *anonyBundleName = nullptr;
    char *anonyAbilityName = nullptr;
    Anonymize(deviceId.c_str(), &anonyDeviceId);
    Anonymize(bundleName.c_str(), &anonyBundleName);
    Anonymize(abilityName.c_str(), &anonyAbilityName);
    COMM_LOGI(COMM_SDK, "%{public}s, deviceId=%{public}s, bundleName=%{public}s, abilityName=%{public}s, "
        "dataLen=%{public}u", funcName, AnonymizeWrapper(anonyDeviceId), AnonymizeWrapper(anonyBundleName),
        AnonymizeWrapper(anonyAbilityName), dataLen);
    AnonymizeFree(anonyDeviceId);
    AnonymizeFree(anonyBundleName);
    AnonymizeFree(anonyAbilityName);
}

static void LogListenerParam(const char *funcName, const std::string &bundleName,
    const std::string &abilityName)
{
    char *anonyBundleName = nullptr;
    char *anonyAbilityName = nullptr;
    Anonymize(bundleName.c_str(), &anonyBundleName);
    Anonymize(abilityName.c_str(), &anonyAbilityName);
    COMM_LOGI(COMM_SDK, "%{public}s, bundleName=%{public}s, abilityName=%{public}s",
        funcName, AnonymizeWrapper(anonyBundleName), AnonymizeWrapper(anonyAbilityName));
    AnonymizeFree(anonyBundleName);
    AnonymizeFree(anonyAbilityName);
}

static void LogRecvCallbackParam(const char *deviceId, const char *abilityName, uint32_t length)
{
    char *anonyDeviceId = nullptr;
    char *anonyAbilityName = nullptr;
    Anonymize(deviceId, &anonyDeviceId);
    Anonymize(abilityName, &anonyAbilityName);
    COMM_LOGI(COMM_SDK, "OnDataRecvCallback, deviceId=%{public}s, abilityName=%{public}s, length=%{public}u",
        AnonymizeWrapper(anonyDeviceId), AnonymizeWrapper(anonyAbilityName), length);
    AnonymizeFree(anonyDeviceId);
    AnonymizeFree(anonyAbilityName);
}

static bool IsSystemApp(void)
{
    uint64_t tokenId = ::OHOS::IPCSkeleton::GetSelfTokenID();
    return ::OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId);
}

static bool CheckPermission(void)
{
    uint32_t tokenId = ::OHOS::IPCSkeleton::GetCallingTokenID();
    if (::OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(
        tokenId, OHOS_PERMISSION_SEC_ACCESS_UDID) != ::OHOS::Security::AccessToken::PERMISSION_GRANTED) {
        COMM_LOGE(COMM_SVC, "permission %{public}s denied.", OHOS_PERMISSION_SEC_ACCESS_UDID);
        return false;
    }
    if (::OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(
        tokenId, OHOS_PERMISSION_DISTRIBUTED_DATASYNC) != ::OHOS::Security::AccessToken::PERMISSION_GRANTED) {
        COMM_LOGE(COMM_SVC, "permission %{public}s denied.", OHOS_PERMISSION_DISTRIBUTED_DATASYNC);
        return false;
    }
    return true;
}

static void DelDataCallbackData(DataCallbackData *cb)
{
    if (cb != nullptr && cb->data != nullptr) {
        delete[] cb->data;
    }
    if (cb != nullptr) {
        delete cb;
    }
}

static void CallDataJsCallback(napi_env env, napi_value jsCallback, void *context, void *rawData)
{
    DataCallbackData *cb = static_cast<DataCallbackData *>(rawData);

    if (env == nullptr || jsCallback == nullptr || cb == nullptr) {
        COMM_LOGE(COMM_SDK, "invalid param");
        DelDataCallbackData(cb);
        return;
    }

    napi_handle_scope scope;
    napi_status statu = napi_open_handle_scope(env, &scope);
    if (statu != napi_ok || scope == nullptr) {
        COMM_LOGE(COMM_SDK, "open handle scope failed");
        DelDataCallbackData(cb);
        return;
    }
    napi_value networkId;
    napi_create_string_utf8(env, cb->deviceId.c_str(), NAPI_AUTO_LENGTH, &networkId);

    napi_value msg;
    void *msgData;
    napi_status status = napi_create_arraybuffer(env, cb->dataLen, &msgData, &msg);
    if (status != napi_ok) {
        COMM_LOGE(COMM_SDK, "create arraybuffer failed");
        napi_close_handle_scope(env, scope);
        DelDataCallbackData(cb);
        return;
    }
    if (memcpy_s(msgData, cb->dataLen, cb->data, cb->dataLen) != EOK) {
        COMM_LOGE(COMM_SDK, "memcpy data failed");
        napi_close_handle_scope(env, scope);
        DelDataCallbackData(cb);
        return;
    }

    napi_value argv[ARGC_TWO];
    argv[0] = networkId;
    argv[ARGC_ONE] = msg;

    napi_value global;
    napi_get_global(env, &global);

    status = napi_call_function(env, global, jsCallback, ARGC_TWO, argv, nullptr);
    if (status != napi_ok) {
        COMM_LOGE(COMM_SDK, "call js callback failed");
    }
    napi_close_handle_scope(env, scope);
    DelDataCallbackData(cb);
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
    COMM_LOGI(COMM_SDK, "start");

    SendMsgContext *ctx = static_cast<SendMsgContext *>(data);
    FillConversationBusiness(ctx->business, ctx->bundleName, ctx->abilityName);
    int32_t ret = PostConversationData(ctx->deviceId.c_str(), &ctx->business,
                                        reinterpret_cast<char *>(ctx->msg), ctx->msgLen);
    ctx->resultCode = ConvertToJsErrcode(ret);
    COMM_LOGI(COMM_SDK, "ret=%{public}d, resultCode=%{public}d", ret, ctx->resultCode);
 
    delete[] ctx->msg;
}

static void CompleteSendMsg(napi_env env, napi_status status, void *data)
{
    SendMsgContext *ctx = static_cast<SendMsgContext *>(data);
    if (ctx->resultCode != CONVERSATION_OK) {
        napi_value error = CreateBusinessErrorValue(env, ctx->resultCode);
        napi_reject_deferred(env, ctx->deferred, error);
        COMM_LOGE(COMM_SDK, "reject resultCode=%{public}d", ctx->resultCode);
    } else {
        napi_value result;
        napi_get_undefined(env, &result);
        napi_resolve_deferred(env, ctx->deferred, result);
        COMM_LOGI(COMM_SDK, "resolve success");
    }

    napi_delete_async_work(env, ctx->work);

    delete ctx;
}

static void FillJsDeviceNode(napi_env env, napi_value &jsDevice, const DeviceNodeInfo *node)
{
    napi_create_object(env, &jsDevice);
    napi_value networkId;
    napi_create_string_utf8(env, node->networkId, NAPI_AUTO_LENGTH, &networkId);
    napi_set_named_property(env, jsDevice, "networkId", networkId);
    napi_value deviceName;
    napi_create_string_utf8(env, node->deviceName, NAPI_AUTO_LENGTH, &deviceName);
    napi_set_named_property(env, jsDevice, "deviceName", deviceName);
    napi_value deviceTypeId;
    napi_create_int32(env, node->deviceTypeId, &deviceTypeId);
    napi_set_named_property(env, jsDevice, "deviceTypeId", deviceTypeId);
    napi_value nearby;
    napi_get_boolean(env, node->nearby, &nearby);
    napi_set_named_property(env, jsDevice, "nearby", nearby);
    napi_value udid;
    napi_create_string_utf8(env, node->udid, NAPI_AUTO_LENGTH, &udid);
    napi_set_named_property(env, jsDevice, "udid", udid);
}

static napi_value NapiGetTrustedDevicesSync(napi_env env, napi_value thisVar)
{
    COMM_LOGI(COMM_SDK, "start");
    napi_value resultArray;
    napi_create_array(env, &resultArray);

    if (!IsSystemApp()) {
        COMM_LOGE(COMM_SDK, "not system app");
        ThrowBusinessError(env, CONVERSATION_PERMISSION_SYSTEMAPI_ERR);
        return resultArray;
    }
    if (!CheckPermission()) {
        COMM_LOGE(COMM_SDK, "permission denied");
        ThrowBusinessError(env, CONVERSATION_PERMISSION_ERR);
        return resultArray;
    }

    DeviceNodeInfo *list = nullptr;
    int32_t nums = 0;
    int32_t resultCode = ConvertToJsErrcode(GetTrustedDevices(&list, &nums));
    if (resultCode != CONVERSATION_OK) {
        if (list != nullptr) {
            FreeDeviceNodeInfo(list);
        }
        COMM_LOGE(COMM_SDK, "resultCode=%{public}d", resultCode);
        ThrowBusinessError(env, resultCode);
        return resultArray;
    } else if (nums > 0) {
        for (int i = 0; i < nums; ++i) {
            napi_value jsDevice;
            FillJsDeviceNode(env, jsDevice, &list[i]);
            napi_set_element(env, resultArray, i, jsDevice);
        }
    }

    if (list != nullptr) {
        FreeDeviceNodeInfo(list);
    }

    COMM_LOGI(COMM_SDK, "nums=%{public}d", nums);
    return resultArray;
}

static napi_value NapiGetTrustedDevicesWrapper(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    return NapiGetTrustedDevicesSync(env, thisVar);
}
static bool ParseMsgArrayBuffer(napi_env env, napi_value arg, SendMsgContext *ctx)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_object) {
        COMM_LOGE(COMM_SDK, "arg is not object");
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        return false;
    }
    bool isArrayBuffer = false;
    napi_is_arraybuffer(env, arg, &isArrayBuffer);
    if (!isArrayBuffer) {
        COMM_LOGE(COMM_SDK, "arg is not arraybuffer");
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        return false;
    }
    void *data = nullptr;
    size_t byteLen = 0;
    napi_get_arraybuffer_info(env, arg, &data, &byteLen);
    if (data == nullptr || byteLen == 0) {
        COMM_LOGE(COMM_SDK, "invalid arraybuffer, byteLen=%{public}zu", byteLen);
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        return false;
    }
    ctx->msg = new uint8_t[byteLen];
    if (ctx->msg == nullptr) {
        COMM_LOGE(COMM_SDK, "alloc msg failed");
        ThrowBusinessError(env, CONVERSATION_INTERNAL_ERR);
        return false;
    }
    ctx->msgLen = static_cast<uint32_t>(byteLen);
    if (memcpy_s(ctx->msg, ctx->msgLen, data, byteLen) != 0) {
        COMM_LOGE(COMM_SDK, "memcpy msg failed");
        delete[] ctx->msg;
        ctx->msg = nullptr;
        ThrowBusinessError(env, CONVERSATION_INTERNAL_ERR);
        return false;
    }
    return true;
}

static bool ParseSendMsgParams(napi_env env, size_t argc, napi_value *argv, SendMsgContext *ctx)
{
    if (argc < SEND_ARGS_SIZE) {
        COMM_LOGE(COMM_SDK, "invalid argc=%{public}zu", argc);
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        return false;
    }
    if (!ParseString(env, ctx->deviceId, argv[0]) ||
        !ParseString(env, ctx->bundleName, argv[ARGC_ONE]) ||
        !ParseString(env, ctx->abilityName, argv[ARGC_TWO])) {
        COMM_LOGE(COMM_SDK, "parse string args failed");
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        return false;
    }
    if (ctx->bundleName.empty() || ctx->abilityName.empty() ||
        ctx->bundleName.size() >= BUNDLE_NAME_LEN || ctx->abilityName.size() >= ABILITY_NAME_LEN) {
        COMM_LOGE(COMM_SDK, "invalid business args, bundleName size=%{public}zu, abilityName size=%{public}zu",
            ctx->bundleName.size(), ctx->abilityName.size());
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        return false;
    }
    return ParseMsgArrayBuffer(env, argv[ARGC_THREE], ctx);
}

static napi_value NapiPostConversationDataAsync(napi_env env, napi_callback_info info)
{
    COMM_LOGI(COMM_SDK, "start");
    if (!IsSystemApp()) {
        COMM_LOGE(COMM_SDK, "not system app");
        ThrowBusinessError(env, CONVERSATION_PERMISSION_SYSTEMAPI_ERR);
        return nullptr;
    }
    if (!CheckPermission()) {
        COMM_LOGE(COMM_SDK, "permission denied");
        ThrowBusinessError(env, CONVERSATION_PERMISSION_ERR);
        return nullptr;
    }

    auto *ctx = new SendMsgContext();
    ctx->env = env;
    size_t argc = SEND_ARGS_SIZE;
    napi_value argv[SEND_ARGS_SIZE];
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    if (!ParseSendMsgParams(env, argc, argv, ctx)) {
        COMM_LOGE(COMM_SDK, "parse params failed");
        delete ctx;
        return nullptr;
    }
    LogBusinessParam("NapiPostConversationData", ctx->deviceId, ctx->bundleName, ctx->abilityName, ctx->msgLen);

    napi_value promise;
    napi_create_promise(env, &ctx->deferred, &promise);
    napi_value resourceName;
    napi_create_string_utf8(env, "SendMsgAsync", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(env, nullptr, resourceName, ExecuteSendMsg, CompleteSendMsg, ctx, &ctx->work);
    napi_queue_async_work(env, ctx->work);
    return promise;
}

static void OnDataRecvCallback(const char *deviceId, const char *data, uint32_t length, const char *abilityName)
{
    LogRecvCallbackParam(deviceId, abilityName, length);
    std::string abilityKey = (abilityName != nullptr) ? abilityName : "";
    napi_threadsafe_function tsfn = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_callbackMutex);
        auto it = g_dataTsfnMap.find(abilityKey);
        if (it != g_dataTsfnMap.end()) {
            tsfn = it->second;
        }
    }
    if (tsfn == nullptr) {
        COMM_LOGE(COMM_SDK, "tsfn not found");
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
                COMM_LOGE(COMM_SDK, "memcpy data failed");
                delete[] cb->data;
                cb->data = nullptr;
                cb->dataLen = 0;
                delete cb;
                return;
            }
        }
    }
    napi_status status = napi_call_threadsafe_function(tsfn, cb, napi_tsfn_nonblocking);
    if (status != napi_ok) {
        COMM_LOGE(COMM_SDK, "napi_call_threadsafe_function failed");
        delete[] cb->data;
        delete cb;
    }
}

static void RemoveTsfnFromMap(const std::string &abilityName)
{
    std::lock_guard<std::mutex> lock(g_callbackMutex);
    auto it = g_dataTsfnMap.find(abilityName);
    if (it != g_dataTsfnMap.end()) {
        if (it->second != nullptr) {
            napi_release_threadsafe_function(it->second, napi_tsfn_release);
        }
        g_dataTsfnMap.erase(it);
    }
}

static bool StoreTsfn(napi_env env, napi_value dataCallback, const std::string &abilityName, bool &isExisting)
{
    napi_value dataResourceName;
    napi_create_string_utf8(env, "CloudDataCallback", NAPI_AUTO_LENGTH, &dataResourceName);
    napi_threadsafe_function tsfn = nullptr;
    napi_status status = napi_create_threadsafe_function(env, dataCallback, nullptr,
        dataResourceName, 0, 1, nullptr, nullptr, nullptr, CallDataJsCallback, &tsfn);
    if (status != napi_ok) {
        COMM_LOGE(COMM_SDK, "create data tsfn failed");
        ThrowBusinessError(env, CONVERSATION_INTERNAL_ERR);
        napi_release_threadsafe_function(tsfn, napi_tsfn_release);
        tsfn = nullptr;
        return false;
    }
    std::lock_guard<std::mutex> lock(g_callbackMutex);
    if (g_dataTsfnMap.find(abilityName) != g_dataTsfnMap.end()) {
        COMM_LOGI(COMM_SDK, "conversation listener already exist");
        if (g_dataTsfnMap[abilityName] != nullptr) {
            napi_release_threadsafe_function(g_dataTsfnMap[abilityName], napi_tsfn_release);
        }
        g_dataTsfnMap[abilityName] = tsfn;
        isExisting = true;
        return true;
    }
    g_dataTsfnMap[abilityName] = tsfn;
    isExisting = false;
    return true;
}

static napi_value NapiRegisterConversationListenerSync(napi_env env, size_t argc, napi_value *argv)
{
    if (argc < ARGC_THREE) {
        COMM_LOGE(COMM_SDK, "invalid argc=%{public}zu", argc);
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        return nullptr;
    }

    std::string bundleName;
    std::string abilityName;
    if (!ParseString(env, bundleName, argv[0]) || !ParseString(env, abilityName, argv[1]) ||
        bundleName.size() >= BUNDLE_NAME_LEN || abilityName.size() >= ABILITY_NAME_LEN ||
        bundleName.empty() || abilityName.empty()) {
        COMM_LOGE(COMM_SDK, "invalid business args");
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        return nullptr;
    }
    LogListenerParam("RegisterConversationListener start", bundleName, abilityName);

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
    bool isExisting = false;
    if (!StoreTsfn(env, dataCallback, abilityName, isExisting)) {
        COMM_LOGE(COMM_SDK, "store tsfn failed");
        return nullptr;
    }

    static ConversationListener listener = {.OnDataReceived = OnDataRecvCallback};
    int32_t result = ConvertToJsErrcode(RegisterConversationListener(&business, &listener));
    if (result != CONVERSATION_OK) {
        if (!isExisting) {
            RemoveTsfnFromMap(abilityName);
        }
        COMM_LOGE(COMM_SDK, "result=%{public}d", result);
        ThrowBusinessError(env, result);
        return nullptr;
    }
    COMM_LOGI(COMM_SDK, "success");
    return nullptr;
}

static napi_value NapiRegisterConversationListenerWarpper(napi_env env, napi_callback_info info)
{
    COMM_LOGI(COMM_SDK, "start");
    if (!IsSystemApp()) {
        COMM_LOGE(COMM_SDK, "not system app");
        ThrowBusinessError(env, CONVERSATION_PERMISSION_SYSTEMAPI_ERR);
        return nullptr;
    }
    if (!CheckPermission()) {
        COMM_LOGE(COMM_SDK, "permission denied");
        ThrowBusinessError(env, CONVERSATION_PERMISSION_ERR);
        return nullptr;
    }
    size_t argc = REGISTER_ARGS_SIZE;
    napi_value argv[REGISTER_ARGS_SIZE];
    napi_value thisVar;

    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    return NapiRegisterConversationListenerSync(env, argc, argv);
}

static napi_value NapiunRegisterConversationListenerSync(napi_env env, size_t argc, napi_value *argv)
{
    if (argc < ARGC_TWO) {
        COMM_LOGE(COMM_SDK, "invalid argc=%{public}zu", argc);
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        return nullptr;
    }

    std::string bundleName;
    std::string abilityName;

    if (!ParseString(env, bundleName, argv[0]) || !ParseString(env, abilityName, argv[1]) ||
        bundleName.size() >= BUNDLE_NAME_LEN || abilityName.size() >= ABILITY_NAME_LEN ||
        bundleName.empty() || abilityName.empty()) {
        COMM_LOGE(COMM_SDK, "invalid business args");
        ThrowBusinessError(env, CONVERSATION_INVALID_PARAM);
        return nullptr;
    }
    LogListenerParam("UnregisterConversationListener start", bundleName, abilityName);

    ConversationBusiness business;
    FillConversationBusiness(business, bundleName, abilityName);

    int32_t result = ConvertToJsErrcode(UnregisterConversationListener(&business));
    RemoveTsfnFromMap(abilityName);
    if (result != CONVERSATION_OK) {
        COMM_LOGE(COMM_SDK, "result=%{public}d", result);
        ThrowBusinessError(env, result);
        return nullptr;
    }

    COMM_LOGI(COMM_SDK, "success");
    return nullptr;
}

static napi_value NapiUnregisterConversationListenerWarpper(napi_env env, napi_callback_info info)
{
    COMM_LOGI(COMM_SDK, "start");
    if (!IsSystemApp()) {
        COMM_LOGE(COMM_SDK, "not system app");
        ThrowBusinessError(env, CONVERSATION_PERMISSION_SYSTEMAPI_ERR);
        return nullptr;
    }
    if (!CheckPermission()) {
        COMM_LOGE(COMM_SDK, "permission denied");
        ThrowBusinessError(env, CONVERSATION_PERMISSION_ERR);
        return nullptr;
    }
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