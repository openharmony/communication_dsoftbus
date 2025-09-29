/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "p2p_v1_mock.h"

#include "softbus_error_code.h"

namespace OHOS::SoftBus {
WifiDirectP2pAdapterMock::WifiDirectP2pAdapterMock()
{
    mock.store(this);
}

WifiDirectP2pAdapterMock::~WifiDirectP2pAdapterMock()
{
    mock.store(nullptr);
}

void WifiDirectP2pAdapter::Init() { }

WifiDirectP2pAdapter *WifiDirectP2pAdapter::GetInstance()
{
    static WifiDirectP2pAdapterMock instance;
    return &instance;
}

int32_t WifiDirectP2pAdapter::ConnCreateGoOwner(const char *pkgName, const struct GroupOwnerConfig *config,
    struct GroupOwnerResult *result, GroupOwnerDestroyListener listener)
{
    (void)pkgName;
    (void)config;
    (void)result;
    (void)listener;
    return SOFTBUS_OK;
}

void WifiDirectP2pAdapter::ConnDestroyGoOwner(const char *pkgName)
{
    (void)pkgName;
}
} // namespace OHOS::SoftBus
// namespace OHOS::SoftBus
