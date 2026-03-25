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

#include "napi_link_enhance_utils_virtual.h"

namespace Communication {
namespace OHOS::Softbus {
using namespace std;

napi_value NapiGetUndefinedRet(napi_env env)
{
    napi_value ret = nullptr;
    napi_get_undefined(env, &ret);
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
} // namespace Softbus
} // namespace Communication
