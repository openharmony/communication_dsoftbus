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

#ifndef TRANS_CONN_MOCK_H
#define TRANS_CONN_MOCK_H

#include <gmock/gmock.h>

#include "softbus_conn_interface.h"
#include "lnn_node_info.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_network_manager.h"

namespace OHOS {
class TransConnInterface {
public:
    TransConnInterface() {};
    virtual ~TransConnInterface() {};

    virtual int32_t ConnConnectDevice(const ConnectOption *option, uint32_t requestId,
        const ConnectResult *result) = 0;
    virtual int32_t ConnDisconnectDevice(uint32_t connectionId) = 0;

    virtual int32_t ConnPostBytes(uint32_t connectionId, ConnPostData *data) = 0;
    virtual int32_t ConnGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info) = 0;

    virtual int32_t ConnTypeIsSupport(ConnectType type) = 0;
    virtual uint32_t ConnGetNewRequestId(ConnModule moduleId) = 0;
    virtual int32_t ConnDisconnectDeviceAllConn(const ConnectOption *option) = 0;
    virtual int32_t ConnStartLocalListening(const LocalListenerInfo *info) = 0;
    virtual int32_t ConnStopLocalListening(const LocalListenerInfo *info) = 0;
    virtual bool CheckActiveConnection(const ConnectOption *option, bool needOccupy) = 0;
    virtual int32_t ConnSetConnectCallback(ConnModule moduleId, const ConnectCallback *callback) = 0;
    virtual uint32_t ConnGetHeadSize(void) = 0;
    virtual void NipRecvDataFromBr(uint32_t connId, const char *buf) = 0;
    virtual void NipConnectDevice(uint32_t connId, const char *mac) = 0;
    virtual void NipDisconnectDevice(uint32_t connId) = 0;
    virtual ListenerModule LnnGetProtocolListenerModule(ProtocolType protocol, ListenerMode mode) = 0;
    virtual NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type) = 0;
    virtual bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type) = 0;
};

class TransConnInterfaceMock : public TransConnInterface {
public:
    TransConnInterfaceMock();
    ~TransConnInterfaceMock() override;

    MOCK_METHOD3(ConnConnectDevice, int32_t (const ConnectOption *, uint32_t, const ConnectResult *));
    MOCK_METHOD1(ConnDisconnectDevice, int32_t (uint32_t));
    MOCK_METHOD2(ConnPostBytes, int32_t (uint32_t, ConnPostData *));
    MOCK_METHOD2(ConnGetConnectionInfo, int32_t (uint32_t, ConnectionInfo *));

    MOCK_METHOD1(ConnTypeIsSupport, int32_t (ConnectType));
    MOCK_METHOD1(ConnGetNewRequestId, uint32_t (ConnModule));
    MOCK_METHOD1(ConnDisconnectDeviceAllConn, int32_t (const ConnectOption *));
    MOCK_METHOD1(ConnStartLocalListening, int32_t (const LocalListenerInfo *));
    MOCK_METHOD1(ConnStopLocalListening, int32_t (const LocalListenerInfo *));
    MOCK_METHOD2(CheckActiveConnection, bool (const ConnectOption *, bool));

    MOCK_METHOD0(ConnGetHeadSize, uint32_t (void));
    MOCK_METHOD2(ConnSetConnectCallback, int32_t (ConnModule, const ConnectCallback *));
    MOCK_METHOD2(NipRecvDataFromBr, void (uint32_t, const char *));
    MOCK_METHOD2(NipConnectDevice, void (uint32_t, const char *));
    MOCK_METHOD1(NipDisconnectDevice, void (uint32_t));
    MOCK_METHOD2(LnnGetProtocolListenerModule, ListenerModule (ProtocolType, ListenerMode));
    MOCK_METHOD2(LnnGetNodeInfoById, NodeInfo* (const char *, IdCategory));
    MOCK_METHOD2(LnnHasDiscoveryType, bool (const NodeInfo *, DiscoveryType));
};

} // namespace OHOS
#endif // TRANS_CONN_MOCK_H