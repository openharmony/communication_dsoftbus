/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include <securec.h>
#include <stdio.h>
#include "br_proxy_error_code.h"
#include "softbus_napi_utils.h"

static napi_value CreateBusinessError(napi_env env, int32_t errCode)
{
    const char *commMsg = GetErrMsgByErrCode(errCode);
    napi_value result = NULL;
    if (commMsg == NULL) {
        napi_get_undefined(env, &result);
        return result;
    }

    napi_value message = NULL;
    napi_create_string_utf8(env, commMsg, NAPI_AUTO_LENGTH, &message);

    napi_value code = NULL;
    napi_create_int32(env, errCode, &code);

    napi_value businessError = NULL;
    napi_create_object(env, &businessError);
    napi_set_named_property(env, businessError, "code", code);
    napi_set_named_property(env, businessError, "message", message);
    return businessError;
}

static void ThrowBusinessError(napi_env env, int32_t errCode, bool isThrow)
{
    #define MAX_ERROR_CODE_LEN 50
    const char *commMsg = GetErrMsgByErrCode(errCode);
    char str[MAX_ERROR_CODE_LEN] = {0};
    int32_t ret = sprintf_s(str, sizeof(str), "%d", errCode);
    if (ret < 0) {
        return;
    }
    napi_throw_error(env, str, commMsg);
}

void ThrowErrFromC2Js(napi_env env, int32_t err)
{
    if (err == SOFTBUS_OK) {
        return;
    }
    int32_t jsRet = NapiTransConvertErr(err);
    ThrowBusinessError(env, jsRet, true);
}

napi_value GetBusinessError(napi_env env, int32_t errCode)
{
    napi_value businessError = NULL;
    int32_t jsRet = NapiTransConvertErr(errCode);
    businessError = CreateBusinessError(env, jsRet);
    return businessError;
}
