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
#include "napi_link_enhance_server_virtual.h"
#include "napi_link_enhance_utils_virtual.h"

namespace Communication {
namespace OHOS::Softbus {

thread_local napi_ref NapiLinkEnhanceServer::consRef_ = nullptr;

std::unordered_map<std::string, NapiLinkEnhanceServer *> NapiLinkEnhanceServer::enhanceServerMap_;
std::mutex NapiLinkEnhanceServer::serverMapMutex_;

napi_value NapiLinkEnhanceServer::Create(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

void NapiLinkEnhanceServer::DefineJSClass(napi_env env)
{
    napi_property_descriptor serverDesc[] = {
        DECLARE_NAPI_FUNCTION("start", Start),
        DECLARE_NAPI_FUNCTION("stop", Stop),
        DECLARE_NAPI_FUNCTION("close", Close),
        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("off", Off),
    };

    napi_value constructor = nullptr;
    napi_define_class(env, "Server", NAPI_AUTO_LENGTH, Constructor, nullptr,
        sizeof(serverDesc) / sizeof(serverDesc[0]), serverDesc, &constructor);
    napi_create_reference(env, constructor, 1, &consRef_);
}

napi_value NapiLinkEnhanceServer::Constructor(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceServer::On(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceServer::Off(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceServer::Start(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceServer::Stop(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceServer::Close(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

bool NapiLinkEnhanceServer::IsAcceptedEnable()
{
    return false;
}

bool NapiLinkEnhanceServer::IsStopEnable()
{
    return false;
}
} // namespace SoftBus
} // namespace Communication