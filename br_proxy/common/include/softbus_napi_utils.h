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
#ifndef SOFTBUS_NAPI_UTILS_H
#define SOFTBUS_NAPI_UTILS_H
#include "napi/native_api.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
typedef enum {
    COMMON_ACCESS_TOKEN_DENIED = 201,
    COMMON_INVALID_PARAM = 401,

    NAPI_SOFTBUS_LINK_DISABLED = 32390001,
    NAPI_SOFTBUS_DEVICE_NOT_PAIRED = 32390002,
    NAPI_SOFTBUS_PROFILE_NOT_SUPPORT = 32390003,
    NAPI_SOFTBUS_CHANNEL_UNAVAILABLE = 32390004,
    NAPI_SOFTBUS_INTERNAL_ERROR = 32390100,
    NAPI_SOFTBUS_CALL_IS_RESTRICTED = 32390101,
    NAPI_SOFTBUS_OPEN_OPERATION_FAILED = 32390102,
    NAPI_SOFTBUS_DATA_TOO_LONG = 32390103,
    NAPI_SOFTBUS_SEND_OPERATION_FAILED = 32390104,
    NAPI_SOFTBUS_UNKNOWN_ERR = 30200000,
} SoftbusJsErrCode;

void ThrowErrFromC2Js(napi_env env, int32_t ret);
napi_value GetBusinessError(napi_env env, int32_t errCode);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // SOFTBUS_NAPI_UTILS_H