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

#include "napi_agent_communication_utils_virtual.h"

namespace Communication {
namespace OHOS::Softbus {

static napi_value GetTrustedDevicesVirtual(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, AGENT_COMM_DEVICE_NOT_SUPPORT, AGENT_COMM_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

static napi_value PostConversationDataVirtual(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, AGENT_COMM_DEVICE_NOT_SUPPORT, AGENT_COMM_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

static napi_value RegisterConversationListenerVirtual(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, AGENT_COMM_DEVICE_NOT_SUPPORT, AGENT_COMM_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

static napi_value UnregisterConversationListenerVirtual(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, AGENT_COMM_DEVICE_NOT_SUPPORT, AGENT_COMM_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

EXTERN_C_START
/*
 * Module initialization function
 */
static napi_value Init(napi_env env, napi_value exports)
{
    PropertyInit(env, exports);
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("getTrustedDevices", GetTrustedDevicesVirtual),
        DECLARE_NAPI_FUNCTION("postConversationData", PostConversationDataVirtual),
        DECLARE_NAPI_FUNCTION("registerConversationListener", RegisterConversationListenerVirtual),
        DECLARE_NAPI_FUNCTION("unregisterConversationListener", UnregisterConversationListenerVirtual),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    return exports;
}
EXTERN_C_END
/*
 * Module define
 */
static napi_module agentCommModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "distributedSoftBus.conversation",
    .nm_priv = ((void *)0),
    .reserved = { 0 }
};
/*
 * Module register function
 */
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&agentCommModule);
}

} // namespace Softbus
} // namespace Communication