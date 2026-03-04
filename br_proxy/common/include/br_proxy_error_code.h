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
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef BR_PROXY_TAIHE_ERROR_CODE_H
#define BR_PROXY_TAIHE_ERROR_CODE_H
#include <stdint.h>
#include "softbus_error_code.h"

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
    NAPI_SOFTBUS_CHANNEL_REOPEN = 32390005,
    NAPI_SOFTBUS_INVALID_PARAM = 32390006,
    NAPI_SOFTBUS_INTERNAL_ERROR = 32390100,
    NAPI_SOFTBUS_CALL_IS_RESTRICTED = 32390101,
    NAPI_SOFTBUS_OPEN_OPERATION_FAILED = 32390102,
    NAPI_SOFTBUS_DATA_TOO_LONG = 32390103,
    NAPI_SOFTBUS_SEND_OPERATION_FAILED = 32390104,
    NAPI_SOFTBUS_UNKNOWN_ERR = 30200000,
} SoftbusJsErrCode;

const char *GetErrMsgByErrCode(int32_t errCode);
int32_t NapiTransConvertErr(int32_t err);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // BR_PROXY_TAIHE_ERROR_CODE_H
