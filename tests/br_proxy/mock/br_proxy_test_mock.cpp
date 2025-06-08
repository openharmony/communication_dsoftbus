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

#include "br_proxy_test_mock.h"


using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_brProxyInterfaceMock;
BrProxyInterfaceMock::BrProxyInterfaceMock()
{
    g_brProxyInterfaceMock = reinterpret_cast<void *>(this);
}

BrProxyInterfaceMock::~BrProxyInterfaceMock()
{
    g_brProxyInterfaceMock = nullptr;
}

static BrProxyInterface *GetBrProxyInterface()
{
    return reinterpret_cast<BrProxyInterface *>(g_brProxyInterfaceMock);
}

extern "C" {
int32_t ClientIpcBrProxyOpened(const char *pkgName, int32_t channelId, const char *brMac, int32_t reason)
{
    return GetBrProxyInterface()->ClientIpcBrProxyOpened(pkgName, channelId, brMac, reason);
}

int32_t ConnectPeerDevice(BrProxyChannelInfo *channelInfo, uint32_t *requestId)
{
    return GetBrProxyInterface()->ConnectPeerDevice(channelInfo, requestId);
}
}
}