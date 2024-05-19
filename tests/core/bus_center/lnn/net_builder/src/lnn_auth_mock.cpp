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

#include "lnn_auth_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_authInterface;
LnnAuthtInterfaceMock::LnnAuthtInterfaceMock()
{
    g_authInterface = reinterpret_cast<void *>(this);
}

LnnAuthtInterfaceMock::~LnnAuthtInterfaceMock()
{
    g_authInterface = nullptr;
}

static LnnAuthInterface *GetAuthInterface()
{
    return reinterpret_cast<LnnAuthInterface *>(g_authInterface);
}

extern "C" {
int32_t AuthStartVerify(const AuthConnInfo *connInfo, uint32_t requestId, const AuthVerifyCallback *callback,
    AuthVerifyModule module, bool isFastAuth)
{
    return GetAuthInterface()->AuthStartVerify(connInfo, requestId, callback, module, isFastAuth);
}

int32_t AuthGetVersion(int64_t authId, SoftBusVersion *version)
{
    return GetAuthInterface()->AuthGetVersion(authId, version);
}

int32_t RegGroupChangeListener(const GroupChangeListener *listener)
{
    return GetAuthInterface()->RegGroupChangeListener(listener);
}
}
}