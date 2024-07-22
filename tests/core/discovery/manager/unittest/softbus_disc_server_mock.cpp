/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "softbus_disc_server_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
DiscMock::DiscMock()
{
    mock.store(this);
}

DiscMock::~DiscMock()
{
    mock.store(nullptr);
}

extern "C" {
int32_t DiscPublishService(const char *packageName, const PublishInfo *info)
{
    return DiscMock::GetDiscMockInterface()->DiscPublishService(packageName, info);
}

int32_t DiscUnPublishService(const char *packageName, int32_t publishId)
{
    return DiscMock::GetDiscMockInterface()->DiscUnPublishService(packageName, publishId);
}

int32_t DiscStartDiscovery(const char *packageName, const SubscribeInfo *info, const IServerDiscInnerCallback *cb)
{
    return DiscMock::GetDiscMockInterface()->DiscStartDiscovery(packageName, info, cb);
}

int32_t DiscStopDiscovery(const char *packageName, int32_t subscribeId)
{
    return DiscMock::GetDiscMockInterface()->DiscStopDiscovery(packageName, subscribeId);
}

int32_t ClientIpcOnPublishFail(const char *pkgName, int publishId, int reason)
{
    return DiscMock::GetDiscMockInterface()->ClientIpcOnPublishFail(pkgName, publishId, reason);
}

int32_t ClientIpcOnPublishSuccess(const char *pkgName, int publishId)
{
    return DiscMock::GetDiscMockInterface()->ClientIpcOnPublishSuccess(pkgName, publishId);
}

int32_t ClientIpcOnDiscoverFailed(const char *pkgName, int subscribeId, int failReason)
{
    return DiscMock::GetDiscMockInterface()->ClientIpcOnDiscoverFailed(pkgName, subscribeId, failReason);
}

int32_t ClientIpcDiscoverySuccess(const char *pkgName, int subscribeId)
{
    return DiscMock::GetDiscMockInterface()->ClientIpcDiscoverySuccess(pkgName, subscribeId);
}

int32_t SoftbusReportDiscFault(SoftBusDiscMedium medium, int32_t errCode)
{
    return DiscMock::GetDiscMockInterface()->SoftbusReportDiscFault(medium, errCode);
}

int32_t ClientIpcOnDeviceFound(const char *pkgName, const DeviceInfo *device, const InnerDeviceInfoAddtions *additions)
{
    return DiscMock::GetDiscMockInterface()->ClientIpcOnDeviceFound(pkgName, device, additions);
}
}
} // namespace OHOS