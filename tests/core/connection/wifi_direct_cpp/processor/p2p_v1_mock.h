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

#ifndef P2P_V1_MOCK_H
#define P2P_V1_MOCK_H

#include <gmock/gmock.h>

#include "softbus_bus_center.h"

namespace OHOS::SoftBus {
class WifiDirectP2pAdapter {
public:
    WifiDirectP2pAdapter() = default;
    virtual ~WifiDirectP2pAdapter() = default;

    virtual void Init() = 0;
    virtual WifiDirectP2pAdapter *GetInstance() = 0;
    virtual int32_t ConnCreateGoOwner(const char *pkgName, const struct GroupOwnerConfig *config,
        struct GroupOwnerResult *result, GroupOwnerDestroyListener listener) = 0;
    virtual void ConnDestroyGoOwner(const char *pkgName) = 0;
};

class WifiDirectP2pAdapterMock : public WifiDirectP2pAdapter {
public:
    static WifiDirectP2pAdapterMock *GetMock()
    {
        return mock.load();
    }

    WifiDirectP2pAdapterMock();
    ~WifiDirectP2pAdapterMock() override;

    MOCK_METHOD(void, Init, (), (override));
    MOCK_METHOD(WifiDirectP2pAdapter *, GetInstance, (), (override));
    MOCK_METHOD(int32_t, ConnCreateGoOwner, (const char *, const struct GroupOwnerConfig *,
        struct GroupOwnerResult *, GroupOwnerDestroyListener), (override));
    MOCK_METHOD(void, ConnDestroyGoOwner, (const char *), (override));

private:
    static inline std::atomic<WifiDirectP2pAdapterMock *> mock = nullptr;
};
} // namespace OHOS::SoftBus
#endif // P2P_V1_MOCK_H
