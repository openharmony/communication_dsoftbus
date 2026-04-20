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

#include "napi/native_api.h"

#define DEVICE_NOT_SUPPORT "801"

napi_value NapiOpenProxyChannel(napi_env env, napi_callback_info info)
{
    (void)info;
    napi_throw_error(env, DEVICE_NOT_SUPPORT, "device not support");
    return NULL;
}

napi_value NapiCloseProxyChannel(napi_env env, napi_callback_info info)
{
    (void)info;
    napi_throw_error(env, DEVICE_NOT_SUPPORT, "device not support");
    return NULL;
}

napi_value SendDataAsync(napi_env env, napi_callback_info info)
{
    (void)info;
    napi_throw_error(env, DEVICE_NOT_SUPPORT, "device not support");
    return NULL;
}

napi_value On(napi_env env, napi_callback_info info)
{
    (void)env;
    (void)info;
    return NULL;
}

napi_value Off(napi_env env, napi_callback_info info)
{
    (void)env;
    (void)info;
    return NULL;
}

static napi_value NapiSoftbusTransInit(napi_env env, napi_value exports)
{
    napi_status status;
    napi_value fn;
    status = napi_create_function(env, NULL, NAPI_AUTO_LENGTH, NapiOpenProxyChannel, NULL, &fn);
    if (status != napi_ok) {
        return NULL;
    }
    status = napi_set_named_property(env, exports, "openProxyChannel", fn);
    if (status != napi_ok) {
        return NULL;
    }
    status = napi_create_function(env, NULL, NAPI_AUTO_LENGTH, NapiCloseProxyChannel, NULL, &fn);
    if (status != napi_ok) {
        return NULL;
    }
    status = napi_set_named_property(env, exports, "closeProxyChannel", fn);
    if (status != napi_ok) {
        return NULL;
    }
    status = napi_create_function(env, NULL, NAPI_AUTO_LENGTH, SendDataAsync, NULL, &fn);
    if (status != napi_ok) {
        return NULL;
    }
    status = napi_set_named_property(env, exports, "sendData", fn);
    if (status != napi_ok) {
        return NULL;
    }
    status = napi_create_function(env, NULL, NAPI_AUTO_LENGTH, On, NULL, &fn);
    if (status != napi_ok) {
        return NULL;
    }
    status = napi_set_named_property(env, exports, "on", fn);
    if (status != napi_ok) {
        return NULL;
    }
    status = napi_create_function(env, NULL, NAPI_AUTO_LENGTH, Off, NULL, &fn);
    if (status != napi_ok) {
        return NULL;
    }
    status = napi_set_named_property(env, exports, "off", fn);
    if (status != napi_ok) {
        return NULL;
    }
    return exports;
}

/*
 * Module definition
 */
static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = "distributedsched.proxyChannelManager",
    .nm_register_func = NapiSoftbusTransInit,
    .nm_modname = "distributedsched.proxyChannelManager",
    .nm_priv = ((void *)0),
    .reserved = { 0 }
};

/*
 * Module registration
 */
__attribute__((constructor)) void RegisterSoftbusTransModule(void)
{
    napi_module_register(&g_module);
}
