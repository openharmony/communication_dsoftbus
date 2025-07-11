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

#include "trans_tcp_direct_listener_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
static void *g_transTcpDirectListenerInterface;
TransTcpDirectListenerInterfaceMock::TransTcpDirectListenerInterfaceMock()
{
    g_transTcpDirectListenerInterface = reinterpret_cast<void *>(this);
}

TransTcpDirectListenerInterfaceMock::~TransTcpDirectListenerInterfaceMock()
{
    g_transTcpDirectListenerInterface = nullptr;
}

static TransTcpDirectListenerInterface *GetTransTcpDirectListenerInterface()
{
    return reinterpret_cast<TransTcpDirectListenerInterface *>(g_transTcpDirectListenerInterface);
}

extern "C" {
char *PackRequest(const AppInfo *appInfo, int64_t requestId)
{
    return GetTransTcpDirectListenerInterface()->PackRequest(appInfo, requestId);
}

int32_t TransTdcPostBytes(int32_t channelId, TdcPacketHead *packetHead, const char *data)
{
    return GetTransTcpDirectListenerInterface()->TransTdcPostBytes(channelId, packetHead, data);
}

int32_t AuthGetServerSide(int64_t authId, bool *isServer)
{
    return GetTransTcpDirectListenerInterface()->AuthGetServerSide(authId, isServer);
}

int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo)
{
    return GetTransTcpDirectListenerInterface()->AuthGetConnInfo(authHandle, connInfo);
}
}
}

