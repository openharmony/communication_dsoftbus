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

#include "ohos.distributedSoftBus.conversation.proj.hpp"
#include "ohos.distributedSoftBus.conversation.impl.hpp"
#include "taihe/runtime.hpp"
#include "agent_communication_utils_taihe.h"

#define CONVERSATION_DEVICE_NOT_SUPPORT 801
#define CONVERSATION_DESCRIPTION       "device not support"

namespace Communication {
namespace OHOS::Softbus {

static void ThrowNotSupport(void)
{
    taihe::set_business_error(CONVERSATION_DEVICE_NOT_SUPPORT, CONVERSATION_DESCRIPTION);
}

::taihe::array<::ohos::distributedSoftBus::conversation::DeviceNodeInfo> GetTrustedDevice()
{
    ThrowNotSupport();
    return ::taihe::array<::ohos::distributedSoftBus::conversation::DeviceNodeInfo>({});
}

void PostConversationDataAsync(::taihe::string_view deviceId,
    ::taihe::string_view bundleName, ::taihe::string_view abilityName,
    ::taihe::array_view<uint8_t> msg)
{
    (void)deviceId;
    (void)bundleName;
    (void)abilityName;
    (void)msg;
    ThrowNotSupport();
}

void RegisterConversationListener(::taihe::string_view bundleName, ::taihe::string_view abilityName,
    ::taihe::callback_view<void(::taihe::string_view networkId, ::taihe::array_view<uint8_t> msg)> callback)
{
    (void)bundleName;
    (void)abilityName;
    (void)callback;
    ThrowNotSupport();
}

void UnregisterConversationListener(::taihe::string_view bundleName, ::taihe::string_view abilityName)
{
    (void)bundleName;
    (void)abilityName;
    ThrowNotSupport();
}

} // namespace Softbus
} // namespace Communication

TH_EXPORT_CPP_API_GetTrustedDevices(Communication::OHOS::Softbus::GetTrustedDevice);
TH_EXPORT_CPP_API_PostConversationDataAsync(Communication::OHOS::Softbus::PostConversationDataAsync);
TH_EXPORT_CPP_API_RegisterConversationListener(Communication::OHOS::Softbus::RegisterConversationListener);
TH_EXPORT_CPP_API_UnregisterConversationListener(Communication::OHOS::Softbus::UnregisterConversationListener);
