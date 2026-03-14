/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "softbus_conn_manager_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_connectionManagerInterface;
ConnectionManagerInterfaceMock::ConnectionManagerInterfaceMock()
{
    g_connectionManagerInterface = reinterpret_cast<void *>(this);
}

ConnectionManagerInterfaceMock::~ConnectionManagerInterfaceMock()
{
    g_connectionManagerInterface = nullptr;
}

static ConnectionManagerInterface *GetConnectionManagerInterface()
{
    return reinterpret_cast<ConnectionManagerInterface *>(g_connectionManagerInterface);
}

extern "C" {
int32_t ConnInitSockets(void)
{
    return GetConnectionManagerInterface()->ConnInitSockets();
}

int32_t InitBaseListener(void)
{
    return GetConnectionManagerInterface()->InitBaseListener();
}

void DeinitBaseListener(void)
{
    GetConnectionManagerInterface()->DeinitBaseListener();
}

int32_t InitGeneralConnection(void)
{
    return GetConnectionManagerInterface()->InitGeneralConnection();
}

void ClearGeneralConnection(const char *pkgName, int32_t pid)
{
    GetConnectionManagerInterface()->ClearGeneralConnection(pkgName, pid);
}

int32_t ProxyChannelManagerInit(void)
{
    return GetConnectionManagerInterface()->ProxyChannelManagerInit();
}

int32_t ConnGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info)
{
    return GetConnectionManagerInterface()->ConnGetConnectionInfo(connectionId, info);
}

int32_t TcpConnSetKeepalive(int32_t fd, bool needKeepalive)
{
    return GetConnectionManagerInterface()->TcpConnSetKeepalive(fd, needKeepalive);
}

int32_t SoftbusGetConfig(int32_t key, unsigned char *val, int32_t len)
{
    return GetConnectionManagerInterface()->SoftbusGetConfig(key, val, len);
}

ConnectFuncInterface *ConnInitTcp(const ConnectCallback *callback)
{
    return GetConnectionManagerInterface()->ConnInitTcp(callback);
}

ConnectFuncInterface *ConnInitBr(const ConnectCallback *callback)
{
    return GetConnectionManagerInterface()->ConnInitBr(callback);
}

ConnectFuncInterface *ConnInitBle(const ConnectCallback *callback)
{
    return GetConnectionManagerInterface()->ConnInitBle(callback);
}

ConnectFuncInterface *ConnSleInitPacked(const ConnectCallback *callback)
{
    return GetConnectionManagerInterface()->ConnSleInitPacked(callback);
}
}    
}
