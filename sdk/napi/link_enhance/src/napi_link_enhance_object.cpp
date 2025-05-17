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

#include "napi_link_enhance_object.h"

namespace Communication {
namespace OHOS::Softbus {

napi_value NapiConnectionChangeState::ToNapiValue(napi_env env)
{
    napi_value result = nullptr;
    napi_create_object(env, &result);

    napi_value deviceId = nullptr;
    napi_create_string_utf8(env, deviceId_.c_str(), deviceId_.size(), &deviceId);
    napi_set_named_property(env, result, "deviceId", deviceId);

    napi_value success = nullptr;
    napi_get_boolean(env, success_, &success);
    napi_set_named_property(env, result, "success", success);

    napi_value reason = nullptr;
    napi_create_int32(env, reason_, &reason);
    napi_set_named_property(env, result, "reason", reason);

    return result;
}
} // namespace Softbus
} // namespace Communication