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

#include "br_proxy_server_manager_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_brProxyServerManagerInterfaceMock;
BrProxyServerManagerInterfaceMock::BrProxyServerManagerInterfaceMock()
{
    g_brProxyServerManagerInterfaceMock = reinterpret_cast<void *>(this);
}

BrProxyServerManagerInterfaceMock::~BrProxyServerManagerInterfaceMock()
{
    g_brProxyServerManagerInterfaceMock = nullptr;
}

static BrProxyServerManagerInterface *GetBrProxyServerManagerInterface()
{
    return reinterpret_cast<BrProxyServerManagerInterface *>(g_brProxyServerManagerInterfaceMock);
}

extern "C" {
int32_t PullUpHap(const char *bundleName, const char *abilityName, int32_t appIndex)
{
    return GetBrProxyServerManagerInterface()->PullUpHap(bundleName, abilityName, appIndex);
}

int32_t GetCallerHapInfo(char *bundleName, uint32_t bundleNamelen,
    char *abilityName, uint32_t abilityNameLen, int32_t *appIndex)
{
    return GetBrProxyServerManagerInterface()->GetCallerHapInfo(bundleName, bundleNamelen,
        abilityName, abilityNameLen, appIndex);
}

pid_t GetCallerPid()
{
    return GetBrProxyServerManagerInterface()->GetCallerPid();
}

pid_t GetCallerUid()
{
    return GetBrProxyServerManagerInterface()->GetCallerUid();
}

uint32_t GetCallerTokenId()
{
    return GetBrProxyServerManagerInterface()->GetCallerTokenId();
}

int32_t CheckPushPermission()
{
    return GetBrProxyServerManagerInterface()->CheckPushPermission();
}
}
}