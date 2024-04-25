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

#ifndef CONNECTION_BR_MOCK_H
#define CONNECTION_BR_MOCK_H

#include "softbus_conn_br_connection.h"
#include "softbus_conn_br_manager.h"
#include "softbus_conn_br_trans.h"

#include <gmock/gmock.h>
#include "cJSON.h"

#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_thread.h"
#include "softbus_config_type.h"
#include "softbus_def.h"

#include "softbus_conn_ble_connection.h"
#include "softbus_conn_common.h"

namespace OHOS {
class ConnectionBrInterface {
public:
    ConnectionBrInterface() {};
    virtual ~ConnectionBrInterface() {};
    virtual int SoftBusGetBtMacAddr(SoftBusBtAddr *mac) = 0;
    virtual void LnnDCReportConnectException(const ConnectOption *option, int32_t errorCode) = 0;
    virtual int32_t SoftBusThreadCreate(
        SoftBusThread *thread, SoftBusThreadAttr *threadAttr, void *(*threadEntry) (void *), void *arg) = 0;
    virtual int SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len) = 0;
    virtual SppSocketDriver *InitSppSocketDriver() = 0;
    virtual int SoftBusAddBtStateListener(const SoftBusBtStateListener *listener) = 0;
    virtual uint32_t ConnGetHeadSize(void) = 0;
    virtual int32_t ConnBrOnAckRequest(ConnBrConnection *connection, const cJSON *json) = 0;
    virtual int32_t ConnBrOnAckResponse(ConnBrConnection *connection, const cJSON *json) = 0;
    virtual ConnBleConnection *ConnBleGetConnectionByAddr(
        const char *addr, ConnSideType side, BleProtocolType protocol) = 0;
    virtual void ConnBleReturnConnection(ConnBleConnection **connection) = 0;
    virtual void LnnDCClearConnectException(const ConnectOption *option) = 0;
    virtual int32_t ConnBrEnqueueNonBlock(const void *msg) = 0;
    virtual int32_t ConnBrDequeueBlock(void **msg) = 0;
    virtual int32_t ConnBrCreateBrPendingPacket(uint32_t id, int64_t seq) = 0;
    virtual void ConnBrDelBrPendingPacket(uint32_t id, int64_t seq) = 0;
    virtual int32_t ConnBrGetBrPendingPacket(uint32_t id, int64_t seq, uint32_t waitMillis, void **data) = 0;
    virtual int32_t ConnBrInnerQueueInit(void) = 0;
    virtual int32_t ConnBrInitBrPendingPacket(void) = 0;
    virtual uint32_t ConnGetNewRequestId(ConnModule moduleId) = 0;
    virtual int32_t ConnBleKeepAlive(uint32_t connectionId, uint32_t requestId, uint32_t time) = 0;
    virtual int32_t ConnBleRemoveKeepAlive(uint32_t connectionId, uint32_t requestId) = 0;
};

class ConnectionBrInterfaceMock : public ConnectionBrInterface {
public:
    ConnectionBrInterfaceMock();
    ~ConnectionBrInterfaceMock() override;
    MOCK_METHOD1(SoftBusGetBtMacAddr, int (SoftBusBtAddr *));
    MOCK_METHOD2(LnnDCReportConnectException, void(const ConnectOption*, int32_t));
    MOCK_METHOD4(SoftBusThreadCreate, int32_t(SoftBusThread *, SoftBusThreadAttr *, void *(void *), void *));
    MOCK_METHOD3(SoftbusGetConfig, int(ConfigType, unsigned char *, uint32_t));
    MOCK_METHOD0(InitSppSocketDriver, SppSocketDriver*());
    MOCK_METHOD1(SoftBusAddBtStateListener, int(const SoftBusBtStateListener *));
    MOCK_METHOD0(ConnGetHeadSize, uint32_t());
    MOCK_METHOD2(ConnBrOnAckRequest, int32_t(ConnBrConnection *, const cJSON *));
    MOCK_METHOD2(ConnBrOnAckResponse, int32_t(ConnBrConnection *, const cJSON *));
    MOCK_METHOD3(ConnBleGetConnectionByAddr, ConnBleConnection *(const char *, ConnSideType, BleProtocolType));
    MOCK_METHOD1(ConnBleReturnConnection, void(ConnBleConnection **));
    MOCK_METHOD1(LnnDCClearConnectException, void(const ConnectOption *));
    MOCK_METHOD1(ConnBrEnqueueNonBlock, int32_t(const void *));
    MOCK_METHOD1(ConnBrDequeueBlock, int32_t(void **));
    MOCK_METHOD2(ConnBrCreateBrPendingPacket, int32_t(uint32_t, int64_t));
    MOCK_METHOD2(ConnBrDelBrPendingPacket, void(uint32_t, int64_t));
    MOCK_METHOD4(ConnBrGetBrPendingPacket, int32_t(uint32_t, int64_t, uint32_t, void **));
    MOCK_METHOD0(ConnBrInnerQueueInit, int32_t());
    MOCK_METHOD0(ConnBrInitBrPendingPacket, int32_t());
    MOCK_METHOD1(ConnGetNewRequestId, uint32_t(ConnModule));
    MOCK_METHOD3(ConnBleKeepAlive, int32_t(uint32_t, uint32_t, uint32_t));
    MOCK_METHOD2(ConnBleRemoveKeepAlive, int32_t(uint32_t, uint32_t));

    static int32_t ActionOfSoftbusGetConfig1(ConfigType type, unsigned char *val, uint32_t len);
    static int32_t ActionOfSoftbusGetConfig2(ConfigType type, unsigned char *val, uint32_t len);
};
} // namespace OHOS
#endif // CONNECTION_BR_MOCK_H
