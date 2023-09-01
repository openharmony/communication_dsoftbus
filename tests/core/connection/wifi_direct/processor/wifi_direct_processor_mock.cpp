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
#include <cstdio>
#include <cstring>
#include <securec.h>
#include "wifi_direct_processor_mock.h"
#include "softbus_log.h"
#include "softbus_error_code.h"

 
using testing::Return;
using testing::NotNull;
using namespace std;
namespace OHOS {
extern "C" {
struct InterfaceInfo *GetInterfaceInfo(const char *interface)
{
    return WifiProcessorMock::GetMock()->GetInterfaceInfo(interface);
}

bool IsInterfaceAvailable(const char *interface)
{
    return WifiProcessorMock::GetMock()->IsInterfaceAvailable(interface);
}

bool IsThreeVapConflict()
{
   return WifiProcessorMock::GetMock()->IsThreeVapConflict();
}

WifiProcessorMock::WifiProcessorMock()
{
    mock.store(this);
}
 
WifiProcessorMock::~WifiProcessorMock()
{
    mock.store(nullptr);
}

bool WifiProcessorMock::ActionOfIsInterfaceAvailable(const char *interface)
{
    return true;
}

int WifiProcessorMock::ActionOfAuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    return SOFTBUS_OK;
}

bool WifiProcessorMock::ActionOfIsThreeVapConflict()
{
    return true;
}

InterfaceInfo *WifiProcessorMock::ActionOfGetInterfaceInfo(const char *interface)
{
    return nullptr;
}

int WifiProcessorMock::ActionOfProcessConnetRequest1(struct NegotiateMessage *msg)
{
    return SOFTBUS_OK;
}

int WifiProcessorMock::ActionOfProcessConnetRequest2(struct NegotiateMessage *msg)
{
    return SOFTBUS_OK;
}

int WifiProcessorMock::ActionOfProcessConnetRequest3(struct NegotiateMessage *msg)
{
    return SOFTBUS_OK;
}

int WifiProcessorMock::ActionOfProcessConnetResponse1(struct NegotiateMessage *msg)
{
    return SOFTBUS_OK;
}

int WifiProcessorMock::ActionOfProcessConnetResponse2(struct NegotiateMessage *msg)
{
    return SOFTBUS_OK;
}

int WifiProcessorMock::ActionOfProcessConnetResponse3(struct NegotiateMessage *msg)
{
    return SOFTBUS_OK;
}

int WifiProcessorMock::ActionOfProcessDisConnetRequest(struct NegotiateMessage *msg)
{
    return SOFTBUS_OK;
}

void WifiProcessorMock::SetupSuccessStub()
{
    EXPECT_CALL(*this, GetInterfaceInfo).WillRepeatedly(WifiProcessorMock::ActionOfGetInterfaceInfo);
    EXPECT_CALL(*this, AuthGetDeviceUuid).WillRepeatedly(WifiProcessorMock::ActionOfAuthGetDeviceUuid);
    EXPECT_CALL(*this, IsInterfaceAvailable).WillRepeatedly(WifiProcessorMock::ActionOfIsInterfaceAvailable);
    EXPECT_CALL(*this, IsThreeVapConflict).WillRepeatedly(WifiProcessorMock::ActionOfIsThreeVapConflict);
    EXPECT_CALL(*this, ProcessConnetRequest1).WillRepeatedly(WifiProcessorMock::ActionOfProcessConnetRequest1);
    EXPECT_CALL(*this, ProcessConnetRequest2).WillRepeatedly(WifiProcessorMock::ActionOfProcessConnetRequest2);
    EXPECT_CALL(*this, ProcessConnetRequest3).WillRepeatedly(WifiProcessorMock::ActionOfProcessConnetRequest3);
    EXPECT_CALL(*this, ProcessConnetResponse1).WillRepeatedly(WifiProcessorMock::ActionOfProcessConnetResponse1);
    EXPECT_CALL(*this, ProcessConnetResponse2).WillRepeatedly(WifiProcessorMock::ActionOfProcessConnetResponse2);
    EXPECT_CALL(*this, ProcessConnetResponse3).WillRepeatedly(WifiProcessorMock::ActionOfProcessConnetResponse3);
    EXPECT_CALL(*this, ProcessDisConnetRequest).WillRepeatedly(WifiProcessorMock::ActionOfProcessDisConnetRequest);
}

static void Destructor(struct WifiDirectNegotiateChannel *base)
{
    WifiProcessorMock::GetMock()->WifiDirectNegoChannelMockDelete((struct WifiProcessorMock::WifiDirectNegoChannelMock *)base);
}

int GetDeviceId(struct WifiDirectNegotiateChannel *base, char *deviceId, size_t deviceIdSize)
{
    return SOFTBUS_OK;
}

void WifiProcessorMock::WifiDirectNegoChannelMockConstructor(struct WifiDirectNegoChannelMock *self, int64_t authId)
{
    (void)memset_s(self, sizeof(*self), 0, sizeof(*self));
    self->getDeviceId = GetDeviceId;
    self->destructor = Destructor;
}

void WifiProcessorMock::WifiDirectNegoChannelMockDestructor(struct WifiDirectNegoChannelMock *self)
{
}

void WifiProcessorMock::WifiDirectNegoChannelMockDelete(struct WifiDirectNegoChannelMock *self)
{
    WifiDirectNegoChannelMockDestructor(self);
}
}
}