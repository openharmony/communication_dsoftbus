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

int GetDeviceId(struct WifiDirectNegotiateChannel *base, char *deviceId, size_t deviceIdSize)
{
    return WifiProcessorMock::GetMock()->GetDeviceId(base, deviceId, deviceIdSize);
}

bool IsInterfaceAvailable(const char *interface)
{
    return WifiProcessorMock::GetMock()->IsInterfaceAvailable(interface);
}

WifiProcessorMock::WifiProcessorMock()
{
    mock.store(this);
}
 
WifiProcessorMock::~WifiProcessorMock()
{
    mock.store(nullptr);
}

int WifiProcessorMock::ActionOfGetDeviceId(struct WifiDirectNegotiateChannel *base, char *deviceId, size_t deviceIdSize)
{
    return SOFTBUS_OK;
}

bool WifiProcessorMock::ActionOfIsInterfaceAvailable(const char *interface)
{
    return true;
}

struct InterfaceInfo *WifiProcessorMock::ActionOfGetInterfaceInfo(const char *interface)
{
    struct InterfaceInfo interfaceInfo;
    InterfaceInfoConstructor(&interfaceInfo);
    return &interfaceInfo;
}

void WifiProcessorMock::SetupSuccessStub()
{
    EXPECT_CALL(*this, GetInterfaceInfo).WillRepeatedly(WifiProcessorMock::ActionOfGetInterfaceInfo);
    EXPECT_CALL(*this, GetDeviceId).WillRepeatedly(WifiProcessorMock::ActionOfGetDeviceId);
    EXPECT_CALL(*this, IsInterfaceAvailable).WillRepeatedly(WifiProcessorMock::ActionOfIsInterfaceAvailable);
}
}
}