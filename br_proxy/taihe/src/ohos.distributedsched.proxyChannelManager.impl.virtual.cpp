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

#include "ohos.distributedsched.proxyChannelManager.proj.hpp"
#include "ohos.distributedsched.proxyChannelManager.impl.hpp"
#include "stdexcept"
#include "taihe/runtime.hpp"

namespace {
// To be implemented.

#define DEVICE_NOT_SUPPORT 801

static void ThrowBusinessException(int32_t err)
{
    if (err == 0) {
        return;
    }
    taihe::set_business_error(err, "device not support");
}

int32_t OpenProxyChannelAsync(::ohos::distributedsched::proxyChannelManager::ChannelInfo const& channelInfo)
{
    (void)channelInfo;
    ThrowBusinessException(DEVICE_NOT_SUPPORT);
    return DEVICE_NOT_SUPPORT;
}

void CloseProxyChannel(int32_t channelId)
{
    (void)channelId;
    ThrowBusinessException(DEVICE_NOT_SUPPORT);
    return;
}

void SendDataAsync(int32_t channelId, ::taihe::array_view<uint8_t> data)
{
    (void)channelId;
    (void)data;
    ThrowBusinessException(DEVICE_NOT_SUPPORT);
    return;
}

void OnReceiveData(int32_t channelId,
    ::taihe::callback_view<void(::ohos::distributedsched::proxyChannelManager::DataInfo const& dataInfo)> callback)
{
    (void)channelId;
    (void)callback;
    return;
}

void OffReceiveData(int32_t channelId, ::taihe::optional_view<
    ::taihe::callback<void(::ohos::distributedsched::proxyChannelManager::DataInfo const& dataInfo)>> callback)
{
    (void)channelId;
    (void)callback;
    return;
}

void OnChannelStateChange(int32_t channelId, ::taihe::callback_view<
    void(::ohos::distributedsched::proxyChannelManager::ChannelStateInfo const& stateInfo)> callback)
{
    (void)channelId;
    (void)callback;
    return;
}

void OffChannelStateChange(int32_t channelId, ::taihe::optional_view<
    ::taihe::callback<void(::ohos::distributedsched::proxyChannelManager::ChannelStateInfo const& stateInfo)>> callback)
{
    (void)channelId;
    (void)callback;
    return;
}
} // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_OpenProxyChannelAsync(OpenProxyChannelAsync);
TH_EXPORT_CPP_API_CloseProxyChannel(CloseProxyChannel);
TH_EXPORT_CPP_API_SendDataAsync(SendDataAsync);
TH_EXPORT_CPP_API_OnReceiveData(OnReceiveData);
TH_EXPORT_CPP_API_OffReceiveData(OffReceiveData);
TH_EXPORT_CPP_API_OnChannelStateChange(OnChannelStateChange);
TH_EXPORT_CPP_API_OffChannelStateChange(OffChannelStateChange);
// NOLINTEND
