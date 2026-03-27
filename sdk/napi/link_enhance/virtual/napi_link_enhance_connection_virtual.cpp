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
#include "napi_link_enhance_connection_virtual.h"

namespace Communication {
namespace OHOS::Softbus {

thread_local napi_ref NapiLinkEnhanceConnection::consRef_ = nullptr;

std::vector<NapiLinkEnhanceConnection *> NapiLinkEnhanceConnection::connectionList_;
std::mutex NapiLinkEnhanceConnection::connectionListMutex_;

napi_value NapiLinkEnhanceConnection::Create(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

void NapiLinkEnhanceConnection::DefineJSClass(napi_env env)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("connect", Connect),
        DECLARE_NAPI_FUNCTION("disconnect", Disconnect),
        DECLARE_NAPI_FUNCTION("close", Close),
        DECLARE_NAPI_FUNCTION("getPeerDeviceId", GetPeerDeviceId),
        DECLARE_NAPI_FUNCTION("sendData", SendData),

        DECLARE_NAPI_FUNCTION("on", On),
        DECLARE_NAPI_FUNCTION("off", Off),
    };

    napi_value constructor = nullptr;
    napi_define_class(env, "Connection", NAPI_AUTO_LENGTH, Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    napi_create_reference(env, constructor, 1, &consRef_);
}

napi_value NapiLinkEnhanceConnection::Constructor(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceConnection::On(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceConnection::Off(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceConnection::Connect(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceConnection::Disconnect(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceConnection::Close(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceConnection::GetPeerDeviceId(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

napi_value NapiLinkEnhanceConnection::SendData(napi_env env, napi_callback_info info)
{
    napi_throw_error(env, LINK_ENHANCE_DEVICE_NOT_SUPPORT, LINK_ENHANCE_NOT_SUPPORT_DESCRIPTION);
    return NapiGetUndefinedRet(env);
}

bool NapiLinkEnhanceConnection::IsConnectResultEnable()
{
    return false;
}

bool NapiLinkEnhanceConnection::IsDataReceiveEnable()
{
    return false;
}

bool NapiLinkEnhanceConnection::IsDisconnectEnable()
{
    return false;
}

} // namespace Softbus
} // namespace Communication
