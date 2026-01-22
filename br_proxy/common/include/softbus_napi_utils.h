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
#ifndef SOFTBUS_NAPI_UTILS_H
#define SOFTBUS_NAPI_UTILS_H
#include "napi/native_api.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void ThrowErrFromC2Js(napi_env env, int32_t ret);
napi_value GetBusinessError(napi_env env, int32_t errCode);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // SOFTBUS_NAPI_UTILS_H