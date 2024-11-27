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

#include "auth_lane_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_authLaneInterface;
AuthLaneInterfaceMock::AuthLaneInterfaceMock()
{
    g_authLaneInterface = reinterpret_cast<void *>(this);
}

AuthLaneInterfaceMock::~AuthLaneInterfaceMock()
{
    g_authLaneInterface = nullptr;
}

static AuthLaneInterface *GetAuthLaneMockInterface()
{
    return reinterpret_cast<AuthLaneInterfaceMock *>(g_authLaneInterface);
}

extern "C" {
int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    return GetAuthLaneMockInterface()->LnnGetRemoteStrInfo(networkId, key, info, len);
}
}
} // namespace OHOS
