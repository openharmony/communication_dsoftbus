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

#ifndef AUTH_TCP_CONNECTION_MOCK_H
#define AUTH_TCP_CONNECTION_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_tcp_connection.h"

namespace OHOS {
class AuthTcpConnetionInterface {
public:
    AuthTcpConnetionInterface() {};
    virtual ~AuthTcpConnetionInterface() {};

    virtual int32_t SetSocketCallback(const SocketCallback *cb) = 0;
    virtual void UnsetSocketCallback(void) = 0;
    virtual int32_t SocketConnectDeviceWithAllIp(const char *localIp, const char *remoteIp,
        int32_t port, bool isBlockMode) = 0;
    virtual int32_t SocketSetDevice(int32_t fd, bool isBlockMode) = 0;
    virtual void StopSessionKeyListening(int32_t fd) = 0;
    virtual int32_t NipSocketConnectDevice(ListenerModule module, const char *addr, int32_t port, bool isBlockMode) = 0;
    virtual void SocketDisconnectDevice(ListenerModule module, int32_t fd) = 0;
    virtual int32_t SocketPostBytes(int32_t fd, const AuthDataHead *head, const uint8_t *data) = 0;
    virtual int32_t SocketGetConnInfo(int32_t fd, AuthConnInfo *connInfo, bool *isServer, int32_t ifnameIdx) = 0;
    virtual int32_t StartSocketListening(ListenerModule module, const LocalListenerInfo *info) = 0;
    virtual void StopSocketListening(ListenerModule moduleId) = 0;
    virtual int32_t AuthSetTcpKeepaliveOption(int32_t fd, ModeCycle cycle) = 0;
    virtual bool IsExistAuthTcpConnFdItemByConnId(int32_t fd) = 0;
    virtual void DeleteAuthTcpConnFdItemByConnId(int32_t fd) = 0;
    virtual int32_t TryDeleteAuthTcpConnFdItemByConnId(int32_t fd) = 0;
    virtual int32_t AuthTcpConnFdLockInit(void) = 0;
    virtual void AuthTcpConnFdLockDeinit(void) = 0;
    virtual bool RequireAuthTcpConnFdListLock(void) = 0;
    virtual void ReleaseAuthTcpConnFdListLock(void) = 0;
    virtual int32_t SocketConnectDevice(const char *ip, int32_t port, bool isBlockMode, int32_t ifnameIdx) = 0;
};
class AuthTcpConnectionInterfaceMock : public AuthTcpConnetionInterface {
public:
    AuthTcpConnectionInterfaceMock();
    ~AuthTcpConnectionInterfaceMock() override;

    MOCK_METHOD1(SetSocketCallback, int32_t(const SocketCallback *));
    MOCK_METHOD0(UnsetSocketCallback, void());
    MOCK_METHOD4(SocketConnectDeviceWithAllIp, int32_t(const char *, const char *, int32_t, bool));
    MOCK_METHOD2(SocketSetDevice, int32_t(int32_t, bool));
    MOCK_METHOD1(StopSessionKeyListening, void(int32_t));
    MOCK_METHOD4(NipSocketConnectDevice, int32_t(ListenerModule, const char *, int32_t, bool));
    MOCK_METHOD2(SocketDisconnectDevice, void(ListenerModule, int32_t));
    MOCK_METHOD3(SocketPostBytes, int32_t(int32_t, const AuthDataHead *, const uint8_t *));
    MOCK_METHOD4(SocketGetConnInfo, int32_t(int32_t, AuthConnInfo *, bool *, int32_t));
    MOCK_METHOD2(StartSocketListening, int32_t(ListenerModule, const LocalListenerInfo *));
    MOCK_METHOD1(StopSocketListening, void(ListenerModule));
    MOCK_METHOD2(AuthSetTcpKeepaliveOption, int32_t(int32_t, ModeCycle));
    MOCK_METHOD1(IsExistAuthTcpConnFdItemByConnId, bool(int32_t));
    MOCK_METHOD1(DeleteAuthTcpConnFdItemByConnId, void(int32_t));
    MOCK_METHOD1(TryDeleteAuthTcpConnFdItemByConnId, int32_t(int32_t));
    MOCK_METHOD0(AuthTcpConnFdLockInit, int32_t());
    MOCK_METHOD0(AuthTcpConnFdLockDeinit, void());
    MOCK_METHOD0(RequireAuthTcpConnFdListLock, bool());
    MOCK_METHOD0(ReleaseAuthTcpConnFdListLock, void());
    MOCK_METHOD4(SocketConnectDevice, int32_t(const char *, int32_t, bool, int32_t));
};
} // namespace OHOS
#endif // AUTH_TCP_CONNECTION_MOCK_H