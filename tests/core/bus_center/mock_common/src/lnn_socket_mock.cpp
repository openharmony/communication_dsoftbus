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

#include "lnn_socket_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_socketInterface;
LnnSocketInterfaceMock::LnnSocketInterfaceMock()
{
    g_socketInterface = reinterpret_cast<void *>(this);
}

LnnSocketInterfaceMock::~LnnSocketInterfaceMock()
{
    g_socketInterface = nullptr;
}

static LnnSocketInterface *GetSocketMockInterface()
{
    return reinterpret_cast<LnnSocketInterfaceMock *>(g_socketInterface);
}

extern "C" {
int32_t ConnOpenClientSocket(const ConnectOption *option, const char *bindAddr, bool isNonBlock)
{
    return GetSocketMockInterface()->ConnOpenClientSocket(option, bindAddr, isNonBlock);
}

const SocketInterface *GetSocketInterface(ProtocolType protocolType)
{
    return GetSocketMockInterface()->GetSocketInterface(protocolType);
}

int32_t RegistSocketProtocol(const SocketInterface *interface)
{
    return GetSocketMockInterface()->RegistSocketProtocol(interface);
}

ssize_t ConnSendSocketData(int32_t fd, const char *buf, size_t len, int32_t timeout)
{
    return GetSocketMockInterface()->ConnSendSocketData(fd, buf, len, timeout);
}

void ConnShutdownSocket(int32_t fd)
{
    return GetSocketMockInterface()->ConnShutdownSocket(fd);
}

int32_t ConnSetTcpKeepalive(int32_t fd, int32_t seconds, int32_t keepAliveIntvl, int32_t keepAliveCount)
{
    return GetSocketMockInterface()->ConnSetTcpKeepalive(fd, seconds, keepAliveIntvl, keepAliveCount);
}

int32_t ConnSetTcpUserTimeOut(int32_t fd, uint32_t millSec)
{
    return GetSocketMockInterface()->ConnSetTcpUserTimeOut(fd, millSec);
}

int32_t ConnToggleNonBlockMode(int32_t fd, bool isNonBlock)
{
    return GetSocketMockInterface()->ConnToggleNonBlockMode(fd, isNonBlock);
}

int32_t ConnGetSocketError(int32_t fd)
{
    return GetSocketMockInterface()->ConnGetSocketError(fd);
}

int32_t ConnGetLocalSocketPort(int32_t fd)
{
    return GetSocketMockInterface()->ConnGetLocalSocketPort(fd);
}

int32_t ConnGetPeerSocketAddr(int32_t fd, SocketAddr *socketAddr)
{
    return GetSocketMockInterface()->ConnGetPeerSocketAddr(fd, socketAddr);
}
}
} // namespace OHOS