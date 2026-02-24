/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "napi_link_enhance_utils.h"

#include <regex>
#include "napi_link_enhance_error_code.h"
#include "securec.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

namespace Communication {
namespace OHOS::Softbus {
using namespace std;

static constexpr const char *THREAD_NAME = "linkEnhance";

static std::map<int32_t, std::string> napiErrMsgMap {
    {LINK_ENHANCE_PERMISSION_DENIED, "Permission denied."},
    {LINK_ENHANCE_CONNECT_TIMEOUT, "Connect timeout."},
    {LINK_ENHANCE_CONNECT_PEER_NOT_START_SERVICE, "Peer server is not started."},
    {LINK_ENHANCE_SERVERS_EXCEEDS, "The number of servers exceeds the limit."},
    {LINK_ENHANCE_DUPLICATE_SERVER_NAME, "Duplicate server name."},
    {LINK_ENHANCE_CONNECTIONS_EXCEEDS, "The number of connection exceeds the limit."},
    {LINK_ENHANCE_CONNECTION_NOT_READY, "Connection is not ready."},
    {LINK_ENHANCE_PARAMETER_INVALID, "Invalid parameter."},
    {LINK_ENHANCE_INTERNAL_ERR, "Internal error."},
};

int32_t DoInJsMainThread(napi_env env, std::function<void(void)> func)
{
    if (napi_send_event(env, func, napi_eprio_high, THREAD_NAME) != napi_ok) {
        COMM_LOGE(COMM_SDK, "send event fail");
        return -1;
    }
    return 0;
}

bool ParseString(napi_env env, string &param, napi_value args)
{
    napi_valuetype valuetype;
    napi_typeof(env, args, &valuetype);

    if (valuetype != napi_string) {
        COMM_LOGE(COMM_SDK, "Wrong argument type(%{public}d). String expected.", valuetype);
        return false;
    }
    size_t size = 0;
    if (napi_get_value_string_utf8(env, args, nullptr, 0, &size) != napi_ok) {
        COMM_LOGE(COMM_SDK, "can not get string size");
        return false;
    }
    param.reserve(size + 1);
    param.resize(size);
    if (napi_get_value_string_utf8(env, args, param.data(), (size + 1), &size) != napi_ok) {
        COMM_LOGE(COMM_SDK, "can not get string value");
        return false;
    }
    return true;
}

bool ParseInt32(napi_env env, int32_t &param, napi_value args)
{
    napi_valuetype valuetype;
    napi_typeof(env, args, &valuetype);
    if (valuetype != napi_number) {
        COMM_LOGE(COMM_SDK, "Wrong argument type(%{public}d). Int32 expected.", valuetype);
        return false;
    }
    if (napi_get_value_int32(env, args, &param) != napi_ok) {
        COMM_LOGE(COMM_SDK, "napi_get_value_int32 failed");
        return false;
    }
    return true;
}

bool ParseUInt32(napi_env env, uint32_t &param, napi_value args)
{
    napi_valuetype valuetype;
    napi_typeof(env, args, &valuetype);
    if (valuetype != napi_number) {
        COMM_LOGE(COMM_SDK, "Wrong argument type(%{public}d). Int32 expected.", valuetype);
        return false;
    }
    if (napi_get_value_uint32(env, args, &param) != napi_ok) {
        COMM_LOGE(COMM_SDK, "napi_get_value_uint32 fail");
        return false;
    }
    return true;
}

napi_value NapiGetUndefinedRet(napi_env env)
{
    napi_value ret = nullptr;
    napi_get_undefined(env, &ret);
    return ret;
}

napi_value NapiGetStringRet(napi_env env, std::string string)
{
    napi_value result = nullptr;
    napi_create_string_utf8(env, string.c_str(), string.size(), &result);
    return result;
}

napi_value NapiGetInt32Ret(napi_env env, int32_t res)
{
    napi_value ret = nullptr;
    napi_create_int32(env, res, &ret);
    return ret;
}

void SetNamedPropertyByInteger(napi_env env, napi_value dstObj, int32_t objName, const char *propName)
{
    napi_value prop = nullptr;
    if (napi_create_int32(env, objName, &prop) == napi_ok) {
        napi_set_named_property(env, dstObj, propName, prop);
    }
}

napi_value ConnectionStateTypeInit(napi_env env)
{
    napi_value connectionStateTypeObj = nullptr;
    napi_create_object(env, &connectionStateTypeObj);
    SetNamedPropertyByInteger(
        env, connectionStateTypeObj, static_cast<int32_t>(ConnectionState::STATE_DISCONNECTED), "STATE_DISCONNECTED");
    SetNamedPropertyByInteger(
        env, connectionStateTypeObj, static_cast<int32_t>(ConnectionState::STATE_CONNECTED), "STATE_CONNECTED");
    return connectionStateTypeObj;
}

napi_value PropertyInit(napi_env env, napi_value exports)
{
    napi_value connectionStateTypeObj = ConnectionStateTypeInit(env);

    napi_property_descriptor exportFuncs[] = {
        DECLARE_NAPI_PROPERTY("ConnectionState", connectionStateTypeObj),
    };

    napi_define_properties(env, exports, sizeof(exportFuncs) / sizeof(*exportFuncs), exportFuncs);

    return exports;
}

void NapiCallFunction(napi_env env, napi_ref callbackRef, napi_value *argv, size_t argc)
{
    napi_value undefined = nullptr;
    napi_value callRet = nullptr;
    napi_value callback = nullptr;
    if (callbackRef == nullptr) {
        COMM_LOGE(COMM_SDK, "callbackRef is null");
        return;
    }
    auto status = napi_get_reference_value(env, callbackRef, &callback);
    if (status != napi_ok) {
        COMM_LOGE(COMM_SDK, "napi_get_reference_value fail, status: %{public}d", status);
        return;
    }

    status = napi_call_function(env, undefined, callback, argc, argv, &callRet);
    if (status != napi_ok) {
        COMM_LOGE(COMM_SDK, "napi_call_function fail, status: %{public}d", status);
    }

    // Check whether the JS application triggers an exception in callback. If it is, clear it.
    bool isExist = false;
    status = napi_is_exception_pending(env, &isExist);
    COMM_LOGD(COMM_SDK, "napi_is_exception_pending status: %{public}d, isExist: %{public}d", status, isExist);
    if (isExist) {
        COMM_LOGE(COMM_SDK, "Clear JS application's exception");
        napi_value exception = nullptr;
        status = napi_get_and_clear_last_exception(env, &exception);
        COMM_LOGD(
            COMM_SDK, "napi_get_and_clear_last_exception status: %{public}d", status);
    }
}

int32_t ConvertToJsErrcode(int32_t err)
{
    switch (err) {
        case SOFTBUS_ACCESS_TOKEN_DENIED:
            return LINK_ENHANCE_PERMISSION_DENIED;
        case SOFTBUS_CONN_GENERAL_CREATE_CLIENT_MAX:
            return LINK_ENHANCE_CONNECTIONS_EXCEEDS;
        case SOFTBUS_CONN_GENERAL_CONNECT_TIMEOUT:
            return LINK_ENHANCE_CONNECT_TIMEOUT;
        case SOFTBUS_CONN_GENERAL_SERVER_NOT_OPENED:
            return LINK_ENHANCE_CONNECT_PEER_NOT_START_SERVICE;
        case SOFTBUS_CONN_GENERAL_DUPLICATE_SERVER:
            return LINK_ENHANCE_DUPLICATE_SERVER_NAME;
        case SOFTBUS_CONN_GENERAL_CONNECTION_NOT_READY:
            return LINK_ENHANCE_CONNECTION_NOT_READY;
        case SOFTBUS_INVALID_PARAM:
            return LINK_ENHANCE_PARAMETER_INVALID;
        case SOFTBUS_CONN_GENERAL_CREATE_SERVER_MAX:
            return LINK_ENHANCE_SERVERS_EXCEEDS;
        default:
            return LINK_ENHANCE_INTERNAL_ERR;
    }
}

void HandleSyncErr(const napi_env &env, int32_t errCode)
{
    if (errCode == SOFTBUS_OK) {
        return;
    }
    std::string errMsg = "";
    auto iter = napiErrMsgMap.find(errCode);
    if (iter != napiErrMsgMap.end()) {
        errMsg = iter->second;
    }
    
    if (errMsg != "") {
        napi_throw_error(env, std::to_string(errCode).c_str(), errMsg.c_str());
    }
}

bool CheckAccessToken(void)
{
    bool isAccessToken = SoftBusCheckIsAccess();
    if (!isAccessToken) {
        COMM_LOGW(COMM_SDK, "no access token");
    }
    return isAccessToken;
}
} // namespace Softbus
} // namespace Communication
