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
 
#include "napi_agent_communication_utils.h"
 
#include <map>
#include <regex>
#include "securec.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "napi_agent_communication_error_code.h"
 
namespace Communication {
namespace OHOS::Softbus {
 
static std::map<int32_t, std::string> napiErrMsgMap {
    {CONVERSATION_PERMISSION_ERR, "Permission denied."},
    {CONVERSATION_PERMISSION_SYSTEMAPI_ERR, "Permission denied. A non-system application calls a system API."},
    {CONVERSATION_INVALID_PARAM, "Invalid argument."},
    {CONVERSATION_INTERNAL_ERR, "Internal error."},
    {CONVERSATION_INTERNAL_REMOTE_NOT_SUPPORT, "Remote not support."},
    {CONVERSATION_DUPLICATE_CALLS, "Duplicate calls, previous call still in progress."},
    {CONVERSATION_SEND_DATA_FAILED, "Send data failed."},
    {CONVERSATION_WAIT_ACK_TIMEOUT, "Wait remote ack timeout."}
};
 
bool ParseString(napi_env env, std::string &param, napi_value args)
{
    napi_valuetype valuetype;
    napi_status status = napi_typeof(env, args, &valuetype);
    if (status != napi_ok || valuetype != napi_string) {
        COMM_LOGE(COMM_SDK, "Wrong argument type. String expected.");
        return false;
    }
    size_t size = 0;
    status = napi_get_value_string_utf8(env, args, nullptr, 0, &size);
    if (status != napi_ok) {
        COMM_LOGE(COMM_SDK, "Can not get string size.");
        return false;
    }
    param.reserve(size + 1);
    param.resize(size);
    size_t copied = 0;
    status = napi_get_value_string_utf8(env, args, &param[0], size + 1, &copied);
    if (status != napi_ok) {
        COMM_LOGE(COMM_SDK, "Can not get string value");
        return false;
    }
    return true;
}
 
int32_t ConvertToJsErrcode(int32_t err)
{
    switch (err) {
        case SOFTBUS_OK:
            return CONVERSATION_OK;
        case SOFTBUS_INVALID_PARAM:
            return CONVERSATION_INVALID_PARAM;
        case SOFTBUS_PERMISSION_DENIED:
            return CONVERSATION_PERMISSION_ERR;
        case SOFTBUS_NETWORK_NOT_SUPPORT:
            return CONVERSATION_INTERNAL_REMOTE_NOT_SUPPORT;
        case SOFTBUS_AGENT_BUSY:
            return CONVERSATION_DUPLICATE_CALLS;
        case SOFTBUS_CLOUD_SEND_FAIL:
            return CONVERSATION_SEND_DATA_FAILED;
        case SOFTBUS_TIMOUT:
            return CONVERSATION_WAIT_ACK_TIMEOUT;
        default:
            return CONVERSATION_INTERNAL_ERR;
    }
}
 
void ThrowBusinessError(const napi_env &env, int32_t errCode)
{
    if (errCode == CONVERSATION_OK) {
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

napi_value CreateBusinessErrorValue(napi_env env, int32_t errCode)
{
    if (errCode == CONVERSATION_OK) {
        napi_value undefined;
        napi_get_undefined(env, &undefined);
        return undefined;
    }
    std::string errMsg = "";
    auto iter = napiErrMsgMap.find(errCode);
    if (iter != napiErrMsgMap.end()) {
        errMsg = iter->second;
    }
    napi_value code;
    napi_create_int32(env, errCode, &code);
    napi_value msg;
    napi_create_string_utf8(env, errMsg.c_str(), errMsg.size(), &msg);
    napi_value error;
    napi_create_error(env, code, msg, &error);
    return error;
}
 
} // namespace Softbus
} // namespace Communication