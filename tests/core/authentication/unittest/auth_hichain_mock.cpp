/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "auth_hichain_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_hichainInterface;
AuthHichainInterfaceMock::AuthHichainInterfaceMock()
{
    g_hichainInterface = reinterpret_cast<void *>(this);
}

AuthHichainInterfaceMock::~AuthHichainInterfaceMock()
{
    g_hichainInterface = nullptr;
}

int32_t AuthHichainInterfaceMock::InvokeAuthDevice(int32_t osAccountId, int64_t authReqId, const char *authParams,
    const DeviceAuthCallback *gaCallback)
{
    return 0;
}

int32_t AuthHichainInterfaceMock::InvokeDataChangeListener(const char *appId, const DataChangeListener *listener)
{
    return 0;
}

static AuthHichainInterface *GetHichainInterface()
{
    return reinterpret_cast<AuthHichainInterfaceMock *>(g_hichainInterface);
}

extern "C" {
int32_t InitDeviceAuthService(void)
{
    return GetHichainInterface()->InitDeviceAuthService();
}

void DestroyDeviceAuthService(void)
{
    return GetHichainInterface()->DestroyDeviceAuthService();
}

const GroupAuthManager *GetGaInstance(void)
{
    return GetHichainInterface()->GetGaInstance();
}

const DeviceGroupManager *GetGmInstance(void)
{
    return GetHichainInterface()->GetGmInstance();
}
}
}