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

#ifndef SOFTBUS_DISC_SERVER_MOCK_H
#define SOFTBUS_DISC_SERVER_MOCK_H

#include <atomic>

#include "disc_manager.h"
#include "gmock/gmock.h"
#include "softbus_common.h"
#include "softbus_hisysevt_discreporter.h"

namespace OHOS {
class DiscMockInterface {
public:
    DiscMockInterface() {}
    virtual ~DiscMockInterface() {}

    virtual int32_t DiscPublishService(const char *packageName, const PublishInfo *info) = 0;
    virtual int32_t DiscUnPublishService(const char *packageName, int32_t publishId) = 0;
    virtual int32_t DiscStartDiscovery(const char *packageName, const SubscribeInfo *info,
                                       const IServerDiscInnerCallback *cb) = 0;
    virtual int32_t DiscStopDiscovery(const char *packageName, int32_t subscribeId) = 0;
    virtual int32_t ClientIpcOnPublishFail(const char *pkgName, int32_t publishId, int32_t reason) = 0;
    virtual int32_t ClientIpcOnPublishSuccess(const char *pkgName, int32_t publishId) = 0;
    virtual int32_t ClientIpcOnDiscoverFailed(const char *pkgName, int32_t subscribeId, int32_t failReason) = 0;
    virtual int32_t ClientIpcDiscoverySuccess(const char *pkgName, int32_t subscribeId) = 0;
    virtual int32_t SoftbusReportDiscFault(SoftBusDiscMedium medium, int32_t errCode) = 0;
    virtual int32_t ClientIpcOnDeviceFound(const char *pkgName, const DeviceInfo *device,
                                           const InnerDeviceInfoAddtions *additions) = 0;
};

class DiscMock : public DiscMockInterface {
public:
    static DiscMock* GetDiscMockInterface()
    {
        return mock.load();
    }
    DiscMock();
    ~DiscMock() override;

    MOCK_METHOD(int32_t, DiscPublishService, (const char *packageName, const PublishInfo *info), (override));
    MOCK_METHOD(int32_t, DiscUnPublishService, (const char *packageName, int32_t publishId), (override));
    MOCK_METHOD(int32_t, DiscStartDiscovery,
               (const char *packageName, const SubscribeInfo *info, const IServerDiscInnerCallback *cb), (override));
    MOCK_METHOD(int32_t, DiscStopDiscovery, (const char *packageName, int32_t subscribeId), (override));
    MOCK_METHOD(int32_t, ClientIpcOnPublishFail, (const char *pkgName, int32_t publishId, int32_t reason), (override));
    MOCK_METHOD(int32_t, ClientIpcOnPublishSuccess, (const char *pkgName, int32_t publishId), (override));
    MOCK_METHOD(int32_t, ClientIpcOnDiscoverFailed,
               (const char *pkgName, int32_t subscribeId, int32_t failReason), (override));
    MOCK_METHOD(int32_t, ClientIpcDiscoverySuccess, (const char *pkgName, int32_t subscribeId), (override));
    MOCK_METHOD(int32_t, SoftbusReportDiscFault, (SoftBusDiscMedium medium, int32_t errCode), (override));
    MOCK_METHOD(int32_t, ClientIpcOnDeviceFound,
               (const char *pkgName, const DeviceInfo *device, const InnerDeviceInfoAddtions *additions), (override));

private:
    static inline std::atomic<DiscMock*> mock = nullptr;
};
} // namespace OHOS
#endif // SOFTBUS_DISC_SERVER_MOCK_H