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

#ifndef CONNECTION_MANAGER_MOCK_H
#define CONNECTION_MANAGER_MOCK_H

#include <gmock/gmock.h>
#include "softbus_conn_interface_struct.h"
#include "softbus_conn_manager_struct.h"

namespace OHOS {
class ConnectionManagerInterface {
public:
    ConnectionManagerInterface() {};
    virtual ~ConnectionManagerInterface() {};
    virtual int32_t ConnInitSockets(void) = 0;
    virtual int32_t InitBaseListener(void) = 0;
    virtual void DeinitBaseListener(void) = 0;
    virtual int32_t InitGeneralConnection(void) = 0;
    virtual void ClearGeneralConnection(const char *pkgName, int32_t pid) = 0;
    virtual int32_t ProxyChannelManagerInit(void) = 0;
    virtual int32_t ConnGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info) = 0;
    virtual int32_t TcpConnSetKeepalive(int32_t fd, bool needKeepalive) = 0;
    virtual int32_t SoftbusGetConfig(int32_t key, unsigned char *val, int32_t len) = 0;
    virtual ConnectFuncInterface *ConnInitTcp(const ConnectCallback *callback) = 0;
    virtual ConnectFuncInterface *ConnInitBr(const ConnectCallback *callback) = 0;
    virtual ConnectFuncInterface *ConnInitBle(const ConnectCallback *callback) = 0;
    virtual ConnectFuncInterface *ConnSleInitPacked(const ConnectCallback *callback) = 0;
};

class ConnectionManagerInterfaceMock : public ConnectionManagerInterface {
public:
    ConnectionManagerInterfaceMock();
    ~ConnectionManagerInterfaceMock() override;
    MOCK_METHOD0(ConnInitSockets, int32_t ());
    MOCK_METHOD0(InitBaseListener, int32_t ());
    MOCK_METHOD0(DeinitBaseListener, void ());
    MOCK_METHOD0(InitGeneralConnection, int32_t ());
    MOCK_METHOD2(ClearGeneralConnection, void (const char *, int32_t));
    MOCK_METHOD0(ProxyChannelManagerInit, int32_t ());
    MOCK_METHOD2(ConnGetConnectionInfo, int32_t (uint32_t, ConnectionInfo *));
    MOCK_METHOD2(TcpConnSetKeepalive, int32_t (int32_t, bool));
    MOCK_METHOD3(SoftbusGetConfig, int32_t (int32_t, unsigned char *, int32_t));
    MOCK_METHOD1(ConnInitTcp, ConnectFuncInterface * (const ConnectCallback *));
    MOCK_METHOD1(ConnInitBr, ConnectFuncInterface * (const ConnectCallback *));
    MOCK_METHOD1(ConnInitBle, ConnectFuncInterface * (const ConnectCallback *));
    MOCK_METHOD1(ConnSleInitPacked, ConnectFuncInterface * (const ConnectCallback *));
};
} // namespace OHOS
#endif // CONNECTION_MANAGER_MOCK_H
