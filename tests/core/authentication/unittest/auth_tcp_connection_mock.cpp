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

#include "auth_tcp_connection_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_authTcpConnetionInterface;
AuthTcpConnectionInterfaceMock::AuthTcpConnectionInterfaceMock()
{
    g_authTcpConnetionInterface = reinterpret_cast<void *>(this);
}

AuthTcpConnectionInterfaceMock::~AuthTcpConnectionInterfaceMock()
{
    g_authTcpConnetionInterface = nullptr;
}

static AuthTcpConnetionInterface *GetAuthTcpConnetionInterface()
{
    return reinterpret_cast<AuthTcpConnectionInterfaceMock *>(g_authTcpConnetionInterface);
}

extern "C" {
int32_t SetSocketCallback(const SocketCallback *cb)
{
    return GetAuthTcpConnetionInterface()->SetSocketCallback(cb);
}

void UnsetSocketCallback(void)
{
    return GetAuthTcpConnetionInterface()->UnsetSocketCallback();
}

int32_t SocketConnectDeviceWithAllIp(const char *localIp, const char *remoteIp, int32_t port, bool isBlockMode)
{
    return GetAuthTcpConnetionInterface()->SocketConnectDeviceWithAllIp(localIp, remoteIp, port, isBlockMode);
}

int32_t SocketSetDevice(int32_t fd, bool isBlockMode)
{
    return GetAuthTcpConnetionInterface()->SocketSetDevice(fd, isBlockMode);
}

void StopSessionKeyListening(int32_t fd)
{
    return GetAuthTcpConnetionInterface()->StopSessionKeyListening(fd);
}

int32_t NipSocketConnectDevice(ListenerModule module, const char *addr, int32_t port, bool isBlockMode)
{
    return GetAuthTcpConnetionInterface()->NipSocketConnectDevice(module, addr, port, isBlockMode);
}

void SocketDisconnectDevice(ListenerModule module, int32_t fd)
{
    return GetAuthTcpConnetionInterface()->SocketDisconnectDevice(module, fd);
}

int32_t SocketPostBytes(int32_t fd, const AuthDataHead *head, const uint8_t *data)
{
    return GetAuthTcpConnetionInterface()->SocketPostBytes(fd, head, data);
}

int32_t SocketGetConnInfo(int32_t fd, AuthConnInfo *connInfo, bool *isServer, int32_t ifnameIdx)
{
    return GetAuthTcpConnetionInterface()->SocketGetConnInfo(fd, connInfo, isServer, ifnameIdx);
}

int32_t StartSocketListening(ListenerModule module, const LocalListenerInfo *info)
{
    return GetAuthTcpConnetionInterface()->StartSocketListening(module, info);
}

void StopSocketListening(ListenerModule moduleId)
{
    return GetAuthTcpConnetionInterface()->StopSocketListening(moduleId);
}

int32_t AuthSetTcpKeepaliveOption(int32_t fd, ModeCycle cycle)
{
    return GetAuthTcpConnetionInterface()->AuthSetTcpKeepaliveOption(fd, cycle);
}

bool IsExistAuthTcpConnFdItemByConnId(int32_t fd)
{
    return GetAuthTcpConnetionInterface()->IsExistAuthTcpConnFdItemByConnId(fd);
}

void DeleteAuthTcpConnFdItemByConnId(int32_t fd)
{
    return GetAuthTcpConnetionInterface()->DeleteAuthTcpConnFdItemByConnId(fd);
}

int32_t TryDeleteAuthTcpConnFdItemByConnId(int32_t fd)
{
    return GetAuthTcpConnetionInterface()->TryDeleteAuthTcpConnFdItemByConnId(fd);
}

int32_t AuthTcpConnFdLockInit(void)
{
    return GetAuthTcpConnetionInterface()->AuthTcpConnFdLockInit();
}

void AuthTcpConnFdLockDeinit(void)
{
    return GetAuthTcpConnetionInterface()->AuthTcpConnFdLockDeinit();
}

bool RequireAuthTcpConnFdListLock(void)
{
    return GetAuthTcpConnetionInterface()->RequireAuthTcpConnFdListLock();
}

void ReleaseAuthTcpConnFdListLock(void)
{
    return GetAuthTcpConnetionInterface()->ReleaseAuthTcpConnFdListLock();
}

int32_t SocketConnectDevice(const char *ip, int32_t port, bool isBlockMode, int32_t ifnameIdx)
{
    return GetAuthTcpConnetionInterface()->SocketConnectDevice(ip, port, isBlockMode, ifnameIdx);
}
}
} // namespace OHOS