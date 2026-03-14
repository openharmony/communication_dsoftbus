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

#ifndef SOFTBUS_CONN_BR_MANAGER_TEST_MOCK_H
#define SOFTBUS_CONN_BR_MANAGER_TEST_MOCK_H

#include <atomic>
#include <gmock/gmock.h>

#include "cJSON.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_thread.h"
#include "softbus_config_type.h"
#include "softbus_conn_br_connection.h"
#include "softbus_conn_br_manager.h"
#include "softbus_conn_br_trans.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_common.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "wrapper_br_interface.h"
#include "softbus_conn_br_connection_struct.h"
#include "softbus_conn_br_snapshot.h"

#define HEAD_SIZE         8

namespace OHOS {
class BrManagerTestInterface {
public:
    virtual ~BrManagerTestInterface() = default;
    virtual int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac) = 0;
    virtual void LnnDCReportConnectException(const ConnectOption *option, int32_t errorCode) = 0;
    virtual int32_t SoftBusThreadCreate(
        SoftBusThread *thread, SoftBusThreadAttr *threadAttr, void *(*threadEntry)(void *), void *arg) = 0;
    virtual int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len) = 0;
    virtual SppSocketDriver *InitSppSocketDriver(void) = 0;
    virtual int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener, int32_t *listenerId) = 0;
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
    virtual void ConnBrInnerQueueDeinit(void) = 0;
    virtual int32_t ConnBrInitBrPendingPacket(void) = 0;
    virtual uint32_t ConnGetNewRequestId(ConnModule moduleId) = 0;
    virtual int32_t ConnBleKeepAlive(uint32_t connectionId, uint32_t requestId, uint32_t time) = 0;
    virtual int32_t ConnBleRemoveKeepAlive(uint32_t connectionId, uint32_t requestId) = 0;
    virtual int32_t BrHiDumperRegister(void) = 0;
    virtual int32_t ConnBrConnectionMuduleInit(
        SoftBusLooper *looper, SppSocketDriver *driver, ConnBrEventListener *listener) = 0;
    virtual int32_t ConnBrTransMuduleInit(SppSocketDriver *driver, ConnBrTransEventListener *listener) = 0;
    virtual int32_t ConnBrPostBytes(uint32_t connectionId, uint8_t *data, uint32_t len, int32_t pid, int32_t flag,
        int64_t seq) = 0;
    
    virtual ConnBrConnection *ActionOfConnBrCreateConnection(const char *addr,
                                                             ConnSideType side, int32_t socketHandle) = 0;
    virtual int32_t ActionOfConnBrUpdateConnectionRc(ConnBrConnection *connection, int32_t delta) = 0;
    virtual int32_t ActionOfConnBrOnReferenceRequest(ConnBrConnection *connection, const cJSON *json) = 0;
    virtual int32_t ActionOfConnBrOnReferenceResponse(ConnBrConnection *connection, const cJSON *json) = 0;
    virtual int32_t ActionOfConnBrConnect(ConnBrConnection *connection) = 0;
    virtual int32_t ActionOfConnBrDisconnectNow(ConnBrConnection *connection) = 0;
    virtual int32_t ActionOfConnBrStartServer(void) = 0;
    virtual int32_t ActionOfConnBrStopServer(void) = 0;
    virtual void ActionOfConnBrRefreshIdleTimeout(ConnBrConnection *connection) = 0;
    virtual int32_t ActionOfConnBrSetIdleCheck(ConnBrConnection *connection, bool enableIdleCheck) = 0;
    virtual void ActionOfConnBrOccupy(ConnBrConnection *connection) = 0;
    virtual ConnBrConnectionSnapshot *ConnBrCreateConnectionSnapshot(const ConnBrConnection *connection) = 0;
    virtual int32_t ConnBrConnect(ConnBrConnection *connection) = 0;
};

class BrManagerTestMock : public BrManagerTestInterface {
public:
    BrManagerTestMock();
    ~BrManagerTestMock() override;

    MOCK_METHOD(int32_t, SoftBusGetBtMacAddr, (SoftBusBtAddr *), (override));
    MOCK_METHOD(void, LnnDCReportConnectException, (const ConnectOption *, int32_t), (override));
    MOCK_METHOD(int32_t, SoftBusThreadCreate,
        (SoftBusThread *, SoftBusThreadAttr *, void *(*)(void *), void *), (override));
    MOCK_METHOD(int32_t, SoftbusGetConfig, (ConfigType, unsigned char *, uint32_t), (override));
    MOCK_METHOD(SppSocketDriver *, InitSppSocketDriver, (), (override));
    MOCK_METHOD(int32_t, SoftBusAddBtStateListener, (const SoftBusBtStateListener *, int32_t *), (override));
    MOCK_METHOD(uint32_t, ConnGetHeadSize, (), (override));
    MOCK_METHOD(int32_t, ConnBrOnAckRequest, (ConnBrConnection *, const cJSON *), (override));
    MOCK_METHOD(int32_t, ConnBrOnAckResponse, (ConnBrConnection *, const cJSON *), (override));
    MOCK_METHOD(ConnBleConnection *, ConnBleGetConnectionByAddr,
        (const char *, ConnSideType, BleProtocolType), (override));
    MOCK_METHOD(void, ConnBleReturnConnection, (ConnBleConnection **), (override));
    MOCK_METHOD(void, LnnDCClearConnectException, (const ConnectOption *), (override));
    MOCK_METHOD(int32_t, ConnBrEnqueueNonBlock, (const void *), (override));
    MOCK_METHOD(int32_t, ConnBrDequeueBlock, (void **), (override));
    MOCK_METHOD(int32_t, ConnBrCreateBrPendingPacket, (uint32_t, int64_t), (override));
    MOCK_METHOD(void, ConnBrDelBrPendingPacket, (uint32_t, int64_t), (override));
    MOCK_METHOD(int32_t, ConnBrGetBrPendingPacket, (uint32_t, int64_t, uint32_t, void **), (override));
    MOCK_METHOD(int32_t, ConnBrInnerQueueInit, (), (override));
    MOCK_METHOD(void, ConnBrInnerQueueDeinit, (), (override));
    MOCK_METHOD(int32_t, ConnBrInitBrPendingPacket, (), (override));
    MOCK_METHOD(uint32_t, ConnGetNewRequestId, (ConnModule), (override));
    MOCK_METHOD(int32_t, ConnBleKeepAlive, (uint32_t, uint32_t, uint32_t), (override));
    MOCK_METHOD(int32_t, ConnBleRemoveKeepAlive, (uint32_t, uint32_t), (override));
    MOCK_METHOD(int32_t, BrHiDumperRegister, (), (override));
    MOCK_METHOD(int32_t, ConnBrConnectionMuduleInit,
        (SoftBusLooper *, SppSocketDriver *, ConnBrEventListener *), (override));
    MOCK_METHOD(int32_t, ConnBrTransMuduleInit, (SppSocketDriver *, ConnBrTransEventListener *), (override));
    MOCK_METHOD(int32_t, ConnBrPostBytes,
        (uint32_t, uint8_t *, uint32_t, int32_t, int32_t, int64_t), (override));
    
    MOCK_METHOD(ConnBrConnection *, ActionOfConnBrCreateConnection, (const char *, ConnSideType, int32_t), (override));
    MOCK_METHOD(int32_t, ActionOfConnBrUpdateConnectionRc, (ConnBrConnection *, int32_t), (override));
    MOCK_METHOD(int32_t, ActionOfConnBrOnReferenceRequest, (ConnBrConnection *, const cJSON *), (override));
    MOCK_METHOD(int32_t, ActionOfConnBrOnReferenceResponse, (ConnBrConnection *, const cJSON *), (override));
    MOCK_METHOD(int32_t, ActionOfConnBrConnect, (ConnBrConnection *), (override));
    MOCK_METHOD(int32_t, ActionOfConnBrDisconnectNow, (ConnBrConnection *), (override));
    MOCK_METHOD(int32_t, ActionOfConnBrStartServer, (), (override));
    MOCK_METHOD(int32_t, ActionOfConnBrStopServer, (), (override));
    MOCK_METHOD(void, ActionOfConnBrRefreshIdleTimeout, (ConnBrConnection *), (override));
    MOCK_METHOD(int32_t, ActionOfConnBrSetIdleCheck, (ConnBrConnection *, bool), (override));
    MOCK_METHOD(void, ActionOfConnBrOccupy, (ConnBrConnection *), (override));
    MOCK_METHOD(ConnBrConnectionSnapshot *, ConnBrCreateConnectionSnapshot, (const ConnBrConnection *), (override));
    MOCK_METHOD(int32_t, ConnBrConnect, (ConnBrConnection *connection), (override));

    static BrManagerTestMock *GetMock()
    {
        return g_mock.load();
    }

    static int32_t DefaultActionOfSoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
    {
        (void)type;
        (void)val;
        (void)len;
        return SOFTBUS_OK;
    }

    static SppSocketDriver *DefaultActionOfInitSppSocketDriver()
    {
        return reinterpret_cast<SppSocketDriver *>(1);
    }

    static int32_t DefaultActionOfAddBtStateListener(const SoftBusBtStateListener *listener, int32_t *listenerId)
    {
        (void)listener;
        *listenerId = 1;
        return SOFTBUS_OK;
    }

    static uint32_t DefaultActionOfConnGetHeadSize()
    {
        return HEAD_SIZE;
    }

    static uint32_t DefaultActionOfConnGetNewRequestId(ConnModule moduleId)
    {
        (void)moduleId;
        static uint32_t requestId = 1;
        return requestId++;
    }

    static int32_t DefaultActionOfConnBrConnectionMuduleInit(
        SoftBusLooper *looper, SppSocketDriver *driver, ConnBrEventListener *listener)
    {
        (void)looper;
        (void)driver;
        (void)listener;
        return SOFTBUS_OK;
    }

    static int32_t DefaultActionOfConnBrTransMuduleInit(SppSocketDriver *driver, ConnBrTransEventListener *listener)
    {
        (void)driver;
        (void)listener;
        return SOFTBUS_OK;
    }

    static int32_t DefaultActionOfBrHiDumperRegister()
    {
        return SOFTBUS_OK;
    }

    static ConnBrConnection *DefaultActionOfConnBrCreateConnection(const char *addr,
        ConnSideType side, int32_t socketHandle)
    {
        (void)addr;
        (void)side;
        (void)socketHandle;
        return nullptr;
    }

    static void SetCreateConnectionResult(ConnBrConnection *conn)
    {
        g_createConnectionResult = conn;
    }

    static void SetBrGetConnectionInfoResult(int32_t code)
    {
        g_brGetConnectionInfoResult = code;
    }

    static void SetBrGetConnectionInfoData(const ConnectionInfo &info)
    {
        g_brGetConnectionInfoData = info;
    }

    static void ResetMockState()
    {
        g_createConnectionResult = nullptr;
        g_brGetConnectionInfoResult = SOFTBUS_OK;
    }

    static ConnBrConnection *ActionOfConnBrCreateConnectionImpl(
        const char *addr, ConnSideType side, int32_t socketHandle);
    static int32_t ActionOfConnBrUpdateConnectionRcImpl(ConnBrConnection *connection, int32_t delta);
    static int32_t ActionOfConnBrConnectImpl(ConnBrConnection *connection);
    static int32_t ActionOfConnBrDisconnectNowImpl(ConnBrConnection *connection);
    static int32_t ActionOfBrGetConnectionInfoImpl(uint32_t connectionId, ConnectionInfo *info);

    static void SetOnConnectedCallback(void (*callback)(uint32_t));
    static void SetOnDisconnectedCallback(void (*callback)(uint32_t, int32_t));
    static void SetOnDataReceivedCallback(void (*callback)(uint32_t, uint8_t *, uint32_t));
    static void SetOnServerAcceptedCallback(void (*callback)(uint32_t));
    static void SetOnClientConnectFailedCallback(void (*callback)(uint32_t, int32_t));
    static void SetOnConnectionResumeCallback(void (*callback)(uint32_t));
    static void TriggerOnConnected(uint32_t connectionId);
    static void TriggerOnDisconnected(uint32_t connectionId, int32_t error);
    static void TriggerOnDataReceived(uint32_t connectionId, uint8_t *data, uint32_t dataLen);
    static void TriggerOnServerAccepted(uint32_t connectionId);
    static void TriggerOnClientConnectFailed(uint32_t connectionId, int32_t error);
    static void TriggerOnConnectionResume(uint32_t connectionId);

private:
    static inline std::atomic<BrManagerTestMock *> g_mock = nullptr;
    static inline ConnBrConnection *g_createConnectionResult = nullptr;
    static inline int32_t g_brGetConnectionInfoResult = SOFTBUS_OK;
    static inline ConnectionInfo g_brGetConnectionInfoData = {};
    static inline void (*g_onConnectedCallbackV1)(uint32_t) = nullptr;
    static inline void (*g_onDisconnectedCallbackV2)(uint32_t, int32_t) = nullptr;
    static inline void (*g_onDataReceivedCallbackV3)(uint32_t, uint8_t *, uint32_t) = nullptr;
    static inline void (*g_onServerAcceptedCallback)(uint32_t) = nullptr;
    static inline void (*g_onClientConnectFailedCallback)(uint32_t, int32_t) = nullptr;
    static inline void (*g_onConnectionResumeCallback)(uint32_t) = nullptr;
};
} // namespace OHOS

#endif // SOFTBUS_CONN_BR_MANAGER_TEST_MOCK_H
