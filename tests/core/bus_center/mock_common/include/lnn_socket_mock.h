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

#ifndef DSOFTBUS_LNN_SOCKET_MOCK_H
#define DSOFTBUS_LNN_SOCKET_MOCK_H

#include <gmock/gmock.h>

#include "auth_tcp_connection.h"
#include "softbus_socket.h"

namespace OHOS {
class LnnSocketInterface {
public:
    LnnSocketInterface() {};
    virtual ~LnnSocketInterface() {};
    virtual const SocketInterface *GetSocketInterface(ProtocolType protocolType) = 0;
    virtual int32_t RegistSocketProtocol(const SocketInterface *interface) = 0;
    virtual int32_t ConnOpenClientSocket(const ConnectOption *option, const char *bindAddr, bool isNonBlock) = 0;
    virtual ssize_t ConnSendSocketData(int32_t fd, const char *buf, size_t len, int32_t timeout) = 0;
    virtual void ConnShutdownSocket(int32_t fd) = 0;
    virtual int32_t ConnSetTcpKeepalive(
        int32_t fd, int32_t seconds, int32_t keepAliveIntvl, int32_t keepAliveCount) = 0;
    virtual int32_t ConnSetTcpUserTimeOut(int32_t fd, uint32_t millSec) = 0;
    virtual int32_t ConnToggleNonBlockMode(int32_t fd, bool isNonBlock) = 0;
    virtual int32_t ConnGetSocketError(int32_t fd) = 0;
    virtual int32_t ConnGetLocalSocketPort(int32_t fd) = 0;
    virtual int32_t ConnGetPeerSocketAddr(int32_t fd, SocketAddr *socketAddr) = 0;
};

class LnnSocketInterfaceMock : public LnnSocketInterface {
public:
    LnnSocketInterfaceMock();
    ~LnnSocketInterfaceMock() override;

    MOCK_METHOD1(GetSocketInterface, const SocketInterface *(ProtocolType));
    MOCK_METHOD1(RegistSocketProtocol, int32_t(const SocketInterface *));
    MOCK_METHOD3(ConnOpenClientSocket, int32_t(const ConnectOption *, const char *, bool));
    MOCK_METHOD4(ConnSendSocketData, ssize_t(int32_t, const char *, size_t, int32_t));
    MOCK_METHOD1(ConnShutdownSocket, void(int32_t));
    MOCK_METHOD4(ConnSetTcpKeepalive, int32_t(int32_t, int32_t, int32_t, int32_t));
    MOCK_METHOD2(ConnSetTcpUserTimeOut, int32_t(int32_t, uint32_t));
    MOCK_METHOD2(ConnToggleNonBlockMode, int32_t(int32_t, bool));
    MOCK_METHOD1(ConnGetSocketError, int32_t(int32_t));
    MOCK_METHOD1(ConnGetLocalSocketPort, int32_t(int32_t));
    MOCK_METHOD2(ConnGetPeerSocketAddr, int32_t(int32_t, SocketAddr *));
};
} // namespace OHOS
#endif // DSOFTBUS_LNN_SOCKET_MOCK_H