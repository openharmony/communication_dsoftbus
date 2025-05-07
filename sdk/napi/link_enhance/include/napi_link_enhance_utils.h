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

#ifndef NAPI_SOFTBUS_LINK_ENHANCE_UTILS_H_
#define NAPI_SOFTBUS_LINK_ENHANCE_UTILS_H_

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "comm_log.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "uv.h"
#include "securec.h"
#include "softbus_adapter_mem.h"

namespace Communication {
namespace OHOS::Softbus {

constexpr size_t ARGS_SIZE_ZERO = 0;
constexpr size_t ARGS_SIZE_ONE = 1;
constexpr size_t ARGS_SIZE_TWO = 2;
constexpr size_t ARGS_SIZE_THREE = 3;
constexpr size_t ARGS_TYPE_MAX_LEN = 25;
constexpr int32_t PARAM0 = 0;
constexpr int32_t PARAM1 = 1;
constexpr int32_t PARAM2 = 2;

static const std::string PKG_NAME = "ohos.distributedschedule.dms";

#define NAPI_SOFTBUS_CALL_RETURN(func)                                             \
    do {                                                                           \
        napi_status ret = (func);                                                  \
        if (ret != napi_ok) {                                                      \
            COMM_LOGE(COMM_SDK, "napi call function failed. ret:%{public}d", ret); \
            return ret;                                                            \
        }                                                                          \
    } while (0)

#define NAPI_SOFTBUS_RETURN_IF(condition, msg, ret) \
    do {                                            \
        if ((condition)) {                          \
            COMM_LOGE(COMM_SDK, msg);               \
            return (ret);                           \
        }                                           \
    } while (0)

enum class ConnectionState {
    STATE_BASE = 0,
    STATE_CONNECTING = 1,
    STATE_CONNECTED = 2,
    STATE_DISCONNECTED = 3,
};

int DoInJsMainThread(napi_env env, std::function<void(void)> func);

bool ParseString(napi_env env, std::string &param, napi_value args);
bool ParseInt32(napi_env env, int32_t &param, napi_value args);
bool ParseUInt32(napi_env env, uint32_t &param, napi_value args);

bool IsValidAddress(std::string bdaddr);

napi_value NapiGetNull(napi_env env);
napi_value NapiGetUndefinedRet(napi_env env);
napi_value NapiGetStringRet(napi_env env, std::string string);
napi_value NapiGetInt32Ret(napi_env, int32_t res);

void SetNamedPropertyByInteger(napi_env env, napi_value dstObj, int32_t objName, const char *propName);
void SetNamedPropertyByString(napi_env env, napi_value dstObj, const std::string &strValue, const char *propName);

napi_value PropertyInit(napi_env env, napi_value exports);

void NapiCallFunction(napi_env env, napi_ref callbackRef, napi_value *argv, size_t argc);
int32_t ConvertToJsErrcode(int32_t err);
void HandleSyncErr(const napi_env &env, int32_t errCode, std::string errMsg);

} // namespace Softbus
} // namespace Communication
#endif /* NAPI_SOFTBUS_LINK_ENHANCE_UTILS_H_ */