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

#include "br_proxy_ext_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_brProxyExtInterfaceMock;
BrProxyExtInterfaceMock::BrProxyExtInterfaceMock()
{
    g_brProxyExtInterfaceMock = reinterpret_cast<void *>(this);
}

BrProxyExtInterfaceMock::~BrProxyExtInterfaceMock()
{
    g_brProxyExtInterfaceMock = nullptr;
}

static BrProxyExtInterface *GetBrProxyExtInterface()
{
    return reinterpret_cast<BrProxyExtInterface *>(g_brProxyExtInterfaceMock);
}

extern "C" {
SoftBusList *CreateSoftBusList(void)
{
    return GetBrProxyExtInterface()->CreateSoftBusList();
}

void DestroySoftBusList(SoftBusList *list)
{
    return GetBrProxyExtInterface()->DestroySoftBusList(list);
}

int32_t ClientStubInit(void)
{
    return GetBrProxyExtInterface()->ClientStubInit();
}

int32_t ClientRegisterBrProxyService(const char *pkgName)
{
    return GetBrProxyExtInterface()->ClientRegisterBrProxyService(pkgName);
}

int32_t ServerIpcOpenBrProxy(const char *brMac, const char *uuid)
{
    return GetBrProxyExtInterface()->ServerIpcOpenBrProxy(brMac, uuid);
}

int32_t ServerIpcIsProxyChannelEnabled(int32_t uid, bool *isEnable)
{
    return GetBrProxyExtInterface()->ServerIpcIsProxyChannelEnabled(uid, isEnable);
}

int32_t ServerIpcSendBrProxyData(int32_t channelId, char *data, uint32_t dataLen)
{
    return GetBrProxyExtInterface()->ServerIpcSendBrProxyData(channelId, data, dataLen);
}

int32_t ServerIpcCloseBrProxy(int32_t channelId)
{
    return GetBrProxyExtInterface()->ServerIpcCloseBrProxy(channelId);
}

int32_t ServerIpcSetListenerState(int32_t channelId, int32_t type, bool CbEnabled)
{
    return GetBrProxyExtInterface()->ServerIpcSetListenerState(channelId, type, CbEnabled);
}

int32_t ServerIpcRegisterPushHook(void)
{
    return GetBrProxyExtInterface()->ServerIpcRegisterPushHook();
}

int ClientRegisterService(const char *pkgName)
{
    return GetBrProxyExtInterface()->ClientRegisterService(pkgName);
}
}
}