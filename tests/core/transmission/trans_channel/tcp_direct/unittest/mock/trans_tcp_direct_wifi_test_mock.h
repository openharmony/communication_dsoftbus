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

#ifndef TRANS_TCP_DIRECT_WIFI_TEST_MOCK_H
#define TRANS_TCP_DIRECT_WIFI_TEST_MOCK_H

#include <gmock/gmock.h>

#include "auth_interface.h"
#include "lnn_network_manager.h"
#include "softbus_conn_interface.h"
#include "trans_tcp_direct_sessionconn.h"

namespace OHOS {
class TransTcpDirectWifiInterface {
public:
    TransTcpDirectWifiInterface() {};
    virtual ~TransTcpDirectWifiInterface() {};
    virtual SessionConn *CreateNewSessinConn(ListenerModule module, bool isServerSid) = 0;
    virtual ListenerModule LnnGetProtocolListenerModule(ProtocolType protocol, ListenerMode mode) = 0;
    virtual void AuthGetLatestIdByUuid(const char *uuid, AuthLinkType type, bool isMeta, AuthHandle *authHandle) = 0;
    virtual ListenerModule GetModuleByHmlIp(const char *ip) = 0;
    virtual int32_t TransSrvAddDataBufNode(int32_t channelId, int32_t fd) = 0;
    virtual int32_t TransTdcAddSessionConn(SessionConn *conn) = 0;
    virtual int32_t ConnOpenClientSocket(const ConnectOption *option, const char *bindAddr, bool isNonBlock) = 0;
    virtual int32_t AddTrigger(ListenerModule module, int32_t fd, TriggerType trigger) = 0;
};

class TransTcpDirectWifiInterfaceMock : public TransTcpDirectWifiInterface {
public:
    TransTcpDirectWifiInterfaceMock();
    ~TransTcpDirectWifiInterfaceMock() override;
    MOCK_METHOD2(CreateNewSessinConn, SessionConn * (ListenerModule module, bool isServerSid));
    MOCK_METHOD2(LnnGetProtocolListenerModule, ListenerModule (ProtocolType protocol, ListenerMode mode));
    MOCK_METHOD4(AuthGetLatestIdByUuid, void (const char *uuid, AuthLinkType type, bool isMeta,
        AuthHandle *authHandle));
    MOCK_METHOD1(GetModuleByHmlIp, ListenerModule (const char *ip));
    MOCK_METHOD2(TransSrvAddDataBufNode, int32_t (int32_t channelId, int32_t fd));
    MOCK_METHOD1(TransTdcAddSessionConn, int32_t (SessionConn *conn));
    MOCK_METHOD3(ConnOpenClientSocket, int32_t (const ConnectOption *option, const char *bindAddr, bool isNonBlock));
    MOCK_METHOD3(AddTrigger, int32_t (ListenerModule module, int32_t fd, TriggerType trigger));
};
} // namespace OHOS
#endif // TRANS_TCP_DIRECT_WIFI_TEST_MOCK_H
