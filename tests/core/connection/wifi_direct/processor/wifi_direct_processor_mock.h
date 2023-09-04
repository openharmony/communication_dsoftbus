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
    virtual struct InterfaceInfo * GetInterfaceInfo(const char *interface) = 0;
    virtual bool IsThreeVapConflict() = 0;
    virtual bool IsInterfaceAvailable(const char *interface) = 0;
    virtual int RequstGcIp(const char *macString, char *ipString, size_t ipStringSize) = 0;
    virtual enum WifiDirectRole TransferModeToRole(enum WifiDirectApiRole role) = 0;
    virtual int AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size) = 0;
    virtual int ProcessConnetRequest1(struct NegotiateMessage *msg) = 0;
    virtual int ProcessConnetRequest2(struct NegotiateMessage *msg) = 0;
    virtual int ProcessConnetRequest3(struct NegotiateMessage *msg) = 0;
    virtual int ProcessConnetResponse1(struct NegotiateMessage *msg) = 0;
    virtual int ProcessConnetResponse2(struct NegotiateMessage *msg) = 0;
    virtual int ProcessConnetResponse3(struct NegotiateMessage *msg) = 0;
    virtual int ProcessDisConnetRequest(struct NegotiateMessage *msg) = 0;
};

class WifiProcessorMock : public WifiProcessorInterface {
public:
    struct WifiDirectNegoChannelMock
    {
        WIFI_DIRECT_NEGOTIATE_CHANNEL_BASE;
    };
    
    static WifiProcessorMock *GetMock() {
        return mock.load();
    }

    WifiProcessorMock();
    ~WifiProcessorMock();

    MOCK_METHOD3(AuthGetDeviceUuid, int (int64_t, char*, uint16_t));
    MOCK_METHOD(struct InterfaceInfo *, GetInterfaceInfo, (const char *interface), (override));
    MOCK_METHOD(bool, IsThreeVapConflict, (), (override));
    MOCK_METHOD(bool, IsInterfaceAvailable, (const char *interface), (override));
    MOCK_METHOD(int, RequstGcIp, (const char *macString, char *ipString, size_t ipStringSize), (override));
    MOCK_METHOD(enum WifiDirectRole, TransferModeToRole, (enum WifiDirectApiRole role), (override));
    MOCK_METHOD(int, ProcessConnetRequest1, (struct NegotiateMessage *msg), (override));
    MOCK_METHOD(int, ProcessConnetRequest2, (struct NegotiateMessage *msg), (override));
    MOCK_METHOD(int, ProcessConnetRequest3, (struct NegotiateMessage *msg), (override));
    MOCK_METHOD(int, ProcessConnetResponse1, (struct NegotiateMessage *msg), (override));
    MOCK_METHOD(int, ProcessConnetResponse2, (struct NegotiateMessage *msg), (override));
    MOCK_METHOD(int, ProcessConnetResponse3, (struct NegotiateMessage *msg), (override));
    MOCK_METHOD(int, ProcessDisConnetRequest, (struct NegotiateMessage *msg), (override));

    void SetupSuccessStub();
    static int ActionOfAuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size);
    static struct InterfaceInfo *ActionOfGetInterfaceInfo(const char *interface);
    static bool ActionOfIsInterfaceAvailable(const char *interface);
    static bool ActionOfIsThreeVapConflict();
    static int ActionOfProcessConnetRequest1(struct NegotiateMessage *msg);
    static int ActionOfProcessConnetRequest2(struct NegotiateMessage *msg);
    static int ActionOfProcessConnetRequest3(struct NegotiateMessage *msg);
    static int ActionOfProcessConnetResponse1(struct NegotiateMessage *msg);
    static int ActionOfProcessConnetResponse2(struct NegotiateMessage *msg);
    static int ActionOfProcessConnetResponse3(struct NegotiateMessage *msg);
    static int ActionOfProcessDisConnetRequest(struct NegotiateMessage *msg);
    static void WifiDirectNegoChannelMockConstructor(struct WifiDirectNegoChannelMock *self, int64_t authId);
    static void WifiDirectNegoChannelMockDestructor(struct WifiDirectNegoChannelMock *self);
    static void WifiDirectNegoChannelMockDelete(struct WifiDirectNegoChannelMock *self);

private:
    static inline std::atomic<WifiProcessorMock*> mock = nullptr;
};
}
#endif