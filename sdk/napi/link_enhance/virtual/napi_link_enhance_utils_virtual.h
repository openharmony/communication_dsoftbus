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

#ifndef NAPI_LINK_ENHANCE_UTILS_VIRTUAL_H
#define NAPI_LINK_ENHANCE_UTILS_VIRTUAL_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#define LINK_ENHANCE_DEVICE_NOT_SUPPORT "801"
#define LINK_ENHANCE_NOT_SUPPORT_DESCRIPTION        "device not support"
namespace Communication {
namespace OHOS::Softbus {

enum class ConnectionState {
    STATE_BASE = 0,
    STATE_CONNECTING = 1,
    STATE_CONNECTED = 2,
    STATE_DISCONNECTED = 3,
};
napi_value NapiGetUndefinedRet(napi_env env);
napi_value PropertyInit(napi_env env, napi_value exports);
} // namespace Softbus
} // namespace Communication
#endif /* NAPI_LINK_ENHANCE_UTILS_VIRTUAL_H */