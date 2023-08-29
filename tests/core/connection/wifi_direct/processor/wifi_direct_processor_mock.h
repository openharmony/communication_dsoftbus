/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef WIFI_PROCESSOR_MOCK_H
#define WIFI_PROCESSOR_MOCK_H

#include <atomic>
#include <gmock/gmock.h>
#include <wifi_direct_utils.h>
#include "interface_info.h"
#include "wifi_direct_p2p_adapter.h"
#include "wifi_direct_negotiator.h"
#include "channel/default_negotiate_channel.h"

namespace OHOS {
class WifiProcessorInterface {
public:
    virtual struct InterfaceInfo *GetInterfaceInfo(const char *interface) = 0;
    virtual int GetDeviceId(struct WifiDirectNegotiateChannel *base, char *deviceId, size_t deviceIdSize) = 0;
    virtual bool IsThreeVapConflict() = 0;
    virtual bool IsInterfaceAvailable(const char *interface) = 0;
    virtual int RequstGcIp(const char *macString, char *ipString, size_t ipStringSize) = 0;
    virtual enum WifiDirectRole TransferModeToRole(enum WifiDirectApiRole role) = 0;
};

class WifiProcessorMock : public WifiProcessorInterface {
public:
    static WifiProcessorMock* GetMock()
    {
        return mock.load();
    }

    WifiProcessorMock();
    ~WifiProcessorMock();

    MOCK_METHOD(struct InterfaceInfo *, GetInterfaceInfo, (const char *interface), (override));
    MOCK_METHOD(int, GetDeviceId, (struct WifiDirectNegotiateChannel *base, char *deviceId,
        size_t deviceIdSize), (override));
    MOCK_METHOD(bool, IsThreeVapConflict, (), (override));
    MOCK_METHOD(bool, IsInterfaceAvailable, (const char *interface), (override));
    MOCK_METHOD(int, RequstGcIp, (const char *macString, char *ipString, size_t ipStringSize), (override));
    MOCK_METHOD(enum WifiDirectRole, TransferModeToRole, (enum WifiDirectApiRole role), (override));

    void SetupSuccessStub();
    static struct InterfaceInfo *ActionOfGetInterfaceInfo(const char *interface);
    static int ActionOfGetDeviceId(struct WifiDirectNegotiateChannel *base, char *deviceId, size_t deviceIdSize);
    static bool ActionOfIsInterfaceAvailable(const char *interface);
private:
    static inline std::atomic<WifiProcessorMock*> mock = nullptr;
};
}
#endif