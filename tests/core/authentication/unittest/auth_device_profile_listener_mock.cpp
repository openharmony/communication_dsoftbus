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

#include "auth_device_profile_listener_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_authLaneInterface;
AuthDeviceProfileListenerInterfaceMock::AuthDeviceProfileListenerInterfaceMock()
{
    g_authLaneInterface = reinterpret_cast<void *>(this);
}

AuthDeviceProfileListenerInterfaceMock::~AuthDeviceProfileListenerInterfaceMock()
{
    g_authLaneInterface = nullptr;
}

static AuthDeviceProfileListenerInterfaceMock *GetInterface()
{
    return reinterpret_cast<AuthDeviceProfileListenerInterfaceMock *>(g_authLaneInterface);
}

extern "C" {
void DelNotTrustDevice(const char *udid)
{
    return GetInterface()->DelNotTrustDevice(udid);
}

bool IsHeartbeatEnable(void)
{
    return GetInterface()->IsHeartbeatEnable();
}

void RestartCoapDiscovery(void)
{
    return GetInterface()->RestartCoapDiscovery();
}

int32_t LnnStartHbByTypeAndStrategy(
    LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType, bool isRelay)
{
    return GetInterface()->LnnStartHbByTypeAndStrategy(hbType, strategyType, isRelay);
}

void LnnUpdateOhosAccount(bool isNeedUpdateHeartbeat)
{
    return GetInterface()->LnnUpdateOhosAccount(isNeedUpdateHeartbeat);
}

void NotifyRemoteDevOffLineByUserId(int32_t userId, const char *udid)
{
    return GetInterface()->NotifyRemoteDevOffLineByUserId(userId, udid);
}
}
} // namespace OHOS