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

#include "softbus_conn_br_manager_test_mock.h"

#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_conn_br_connection.h"
#include "softbus_error_code.h"
#include "wrapper_br_interface.h"
#include "softbus_conn_br_connection_struct.h"

using namespace testing;
using namespace testing::ext;

extern "C" {
namespace OHOS {
BrManagerTestMock::BrManagerTestMock()
{
    g_mock.store(this);
}

BrManagerTestMock::~BrManagerTestMock()
{
    g_mock.store(nullptr);
}

ConnBrConnection *BrManagerTestMock::ActionOfConnBrCreateConnectionImpl(
    const char *addr, ConnSideType side, int32_t socketHandle)
{
    if (g_createConnectionResult != nullptr) {
        return g_createConnectionResult;
    }
    ConnBrConnection *conn = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    if (conn != nullptr) {
        static uint32_t g_connectionId = 1;
        conn->connectionId = g_connectionId++;
        conn->side = side;
        conn->socketHandle = socketHandle;
        if (addr != nullptr) {
            (void)memcpy_s(conn->addr, BT_MAC_LEN, addr, BT_MAC_LEN);
        }
        SoftBusMutexInit(&conn->lock, nullptr);
        ListInit(&conn->node);
        conn->connectionRc = 1;
    }
    return conn;
}

int32_t BrManagerTestMock::ActionOfConnBrUpdateConnectionRcImpl(ConnBrConnection *connection, int32_t delta)
{
    if (connection != nullptr) {
        connection->connectionRc += delta;
    }
    return SOFTBUS_OK;
}

int32_t BrManagerTestMock::ActionOfConnBrConnectImpl(ConnBrConnection *connection)
{
    if (connection != nullptr) {
        connection->state = BR_CONNECTION_STATE_CONNECTING;
    }
    return SOFTBUS_OK;
}

int32_t BrManagerTestMock::ActionOfConnBrDisconnectNowImpl(ConnBrConnection *connection)
{
    if (connection != nullptr) {
        connection->state = BR_CONNECTION_STATE_CLOSING;
    }
    return SOFTBUS_OK;
}

int32_t BrManagerTestMock::ActionOfBrGetConnectionInfoImpl(uint32_t connectionId, ConnectionInfo *info)
{
    (void)connectionId;
    if (info != nullptr) {
        if (g_brGetConnectionInfoData.type != CONNECT_TYPE_MAX) {
            *info = g_brGetConnectionInfoData;
        }
        return g_brGetConnectionInfoResult;
    }
    return g_brGetConnectionInfoResult;
}

__attribute__((weak)) ConnBrConnection *ConnBrCreateConnection(
    const char *addr, ConnSideType side, int32_t socketHandle)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ActionOfConnBrCreateConnection(addr, side, socketHandle);
    }
    return BrManagerTestMock::ActionOfConnBrCreateConnectionImpl(addr, side, socketHandle);
}

__attribute__((weak)) void ConnBrFreeConnection(ConnBrConnection *connection)
{
    if (connection != nullptr) {
        SoftBusMutexDestroy(&connection->lock);
        SoftBusFree(connection);
    }
}

__attribute__((weak)) int32_t ConnBrUpdateConnectionRc(ConnBrConnection *connection, int32_t delta)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ActionOfConnBrUpdateConnectionRc(connection, delta);
    }
    return BrManagerTestMock::ActionOfConnBrUpdateConnectionRcImpl(connection, delta);
}

__attribute__((weak)) int32_t ConnBrOnReferenceRequest(ConnBrConnection *connection, const cJSON *json)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ActionOfConnBrOnReferenceRequest(connection, json);
    }
    return SOFTBUS_OK;
}

__attribute__((weak)) int32_t ConnBrOnReferenceResponse(ConnBrConnection *connection, const cJSON *json)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ActionOfConnBrOnReferenceResponse(connection, json);
    }
    return SOFTBUS_OK;
}

__attribute__((weak)) int32_t ConnBrConnect(ConnBrConnection *connection)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ActionOfConnBrConnect(connection);
    }
    return BrManagerTestMock::ActionOfConnBrConnectImpl(connection);
}

__attribute__((weak)) int32_t ConnBrDisconnectNow(ConnBrConnection *connection)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ActionOfConnBrDisconnectNow(connection);
    }
    return BrManagerTestMock::ActionOfConnBrDisconnectNowImpl(connection);
}

__attribute__((weak)) int32_t ConnBrStartServer(void)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ActionOfConnBrStartServer();
    }
    return SOFTBUS_OK;
}

__attribute__((weak)) int32_t ConnBrStopServer(void)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ActionOfConnBrStopServer();
    }
    return SOFTBUS_OK;
}

__attribute__((weak)) void ConnBrRefreshIdleTimeout(ConnBrConnection *connection)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        mock->ActionOfConnBrRefreshIdleTimeout(connection);
    }
}

__attribute__((weak)) int32_t ConnBrSetIdleCheck(ConnBrConnection *connection, bool enableIdleCheck)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ActionOfConnBrSetIdleCheck(connection, enableIdleCheck);
    }
    return SOFTBUS_OK;
}

__attribute__((weak)) void ConnBrOccupy(ConnBrConnection *connection)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        mock->ActionOfConnBrOccupy(connection);
    }
}

ConnBrConnectionSnapshot *ConnBrCreateConnectionSnapshot(const ConnBrConnection *connection)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ConnBrCreateConnectionSnapshot(connection);
    }
    return nullptr;
}

int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SoftBusGetBtMacAddr(mac);
    }
    return SOFTBUS_OK;
}

void LnnDCReportConnectException(const ConnectOption *option, int32_t errorCode)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        mock->LnnDCReportConnectException(option, errorCode);
    }
}

int32_t SoftBusThreadCreate(
    SoftBusThread *thread, SoftBusThreadAttr *threadAttr, void *(*threadEntry)(void *), void *arg)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SoftBusThreadCreate(thread, threadAttr, threadEntry, arg);
    }
    return SOFTBUS_OK;
}

int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SoftbusGetConfig(type, val, len);
    }
    return BrManagerTestMock::DefaultActionOfSoftbusGetConfig(type, val, len);
}

SppSocketDriver *InitSppSocketDriver(void)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->InitSppSocketDriver();
    }
    return BrManagerTestMock::DefaultActionOfInitSppSocketDriver();
}

int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener, int32_t *listenerId)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->SoftBusAddBtStateListener(listener, listenerId);
    }
    return BrManagerTestMock::DefaultActionOfAddBtStateListener(listener, listenerId);
}

uint32_t ConnGetHeadSize(void)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ConnGetHeadSize();
    }
    return BrManagerTestMock::DefaultActionOfConnGetHeadSize();
}

int32_t ConnBrOnAckRequest(ConnBrConnection *connection, const cJSON *json)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ConnBrOnAckRequest(connection, json);
    }
    return SOFTBUS_OK;
}

int32_t ConnBrOnAckResponse(ConnBrConnection *connection, const cJSON *json)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ConnBrOnAckResponse(connection, json);
    }
    return SOFTBUS_OK;
}

ConnBleConnection *ConnBleGetConnectionByAddr(
    const char *addr, ConnSideType side, BleProtocolType protocol)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ConnBleGetConnectionByAddr(addr, side, protocol);
    }
    return nullptr;
}

void ConnBleReturnConnection(ConnBleConnection **connection)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        mock->ConnBleReturnConnection(connection);
    }
}

void LnnDCClearConnectException(const ConnectOption *option)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        mock->LnnDCClearConnectException(option);
    }
}

int32_t ConnBrEnqueueNonBlock(const void *msg)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ConnBrEnqueueNonBlock(msg);
    }
    return SOFTBUS_OK;
}

int32_t ConnBrDequeueBlock(void **msg)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ConnBrDequeueBlock(msg);
    }
    return SOFTBUS_OK;
}

int32_t ConnBrCreateBrPendingPacket(uint32_t id, int64_t seq)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ConnBrCreateBrPendingPacket(id, seq);
    }
    return SOFTBUS_OK;
}

void ConnBrDelBrPendingPacket(uint32_t id, int64_t seq)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        mock->ConnBrDelBrPendingPacket(id, seq);
    }
}

int32_t ConnBrGetBrPendingPacket(uint32_t id, int64_t seq, uint32_t waitMillis, void **data)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ConnBrGetBrPendingPacket(id, seq, waitMillis, data);
    }
    return SOFTBUS_OK;
}

int32_t ConnBrInnerQueueInit(void)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ConnBrInnerQueueInit();
    }
    return SOFTBUS_OK;
}

void ConnBrInnerQueueDeinit(void)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        mock->ConnBrInnerQueueDeinit();
    }
}

int32_t ConnBrInitBrPendingPacket(void)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ConnBrInitBrPendingPacket();
    }
    return SOFTBUS_OK;
}

uint32_t ConnGetNewRequestId(ConnModule moduleId)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ConnGetNewRequestId(moduleId);
    }
    return BrManagerTestMock::DefaultActionOfConnGetNewRequestId(moduleId);
}

int32_t ConnBleKeepAlive(uint32_t connectionId, uint32_t requestId, uint32_t time)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ConnBleKeepAlive(connectionId, requestId, time);
    }
    return SOFTBUS_OK;
}

int32_t ConnBleRemoveKeepAlive(uint32_t connectionId, uint32_t requestId)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ConnBleRemoveKeepAlive(connectionId, requestId);
    }
    return SOFTBUS_OK;
}

int32_t BrHiDumperRegister(void)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->BrHiDumperRegister();
    }
    return BrManagerTestMock::DefaultActionOfBrHiDumperRegister();
}

int32_t ConnBrConnectionMuduleInit(SoftBusLooper *looper, SppSocketDriver *driver, ConnBrEventListener *listener)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ConnBrConnectionMuduleInit(looper, driver, listener);
    }
    if (listener != nullptr) {
        BrManagerTestMock::SetOnConnectedCallback(listener->onClientConnected);
        BrManagerTestMock::SetOnDisconnectedCallback(listener->onConnectionException);
        BrManagerTestMock::SetOnDataReceivedCallback(listener->onDataReceived);
    }
    return BrManagerTestMock::DefaultActionOfConnBrConnectionMuduleInit(looper, driver, listener);
}

void BrManagerTestMock::SetOnConnectedCallback(void (*callback)(uint32_t))
{
    g_onConnectedCallbackV1 = callback;
}

void BrManagerTestMock::SetOnDisconnectedCallback(void (*callback)(uint32_t, int32_t))
{
    g_onDisconnectedCallbackV2 = callback;
}

void BrManagerTestMock::SetOnDataReceivedCallback(void (*callback)(uint32_t, uint8_t *, uint32_t))
{
    g_onDataReceivedCallbackV3 = callback;
}

void BrManagerTestMock::SetOnServerAcceptedCallback(void (*callback)(uint32_t))
{
    g_onServerAcceptedCallback = callback;
}

void BrManagerTestMock::SetOnClientConnectFailedCallback(void (*callback)(uint32_t, int32_t))
{
    g_onClientConnectFailedCallback = callback;
}

void BrManagerTestMock::SetOnConnectionResumeCallback(void (*callback)(uint32_t))
{
    g_onConnectionResumeCallback = callback;
}

void BrManagerTestMock::TriggerOnConnected(uint32_t connectionId)
{
    if (g_onConnectedCallbackV1 != nullptr) {
        g_onConnectedCallbackV1(connectionId);
    }
}

void BrManagerTestMock::TriggerOnDisconnected(uint32_t connectionId, int32_t error)
{
    if (g_onDisconnectedCallbackV2 != nullptr) {
        g_onDisconnectedCallbackV2(connectionId, error);
    }
}

void BrManagerTestMock::TriggerOnDataReceived(uint32_t connectionId, uint8_t *data, uint32_t dataLen)
{
    if (g_onDataReceivedCallbackV3 != nullptr) {
        g_onDataReceivedCallbackV3(connectionId, data, dataLen);
    }
}

void BrManagerTestMock::TriggerOnServerAccepted(uint32_t connectionId)
{
    if (g_onServerAcceptedCallback != nullptr) {
        g_onServerAcceptedCallback(connectionId);
    }
}

void BrManagerTestMock::TriggerOnClientConnectFailed(uint32_t connectionId, int32_t error)
{
    if (g_onClientConnectFailedCallback != nullptr) {
        g_onClientConnectFailedCallback(connectionId, error);
    }
}

void BrManagerTestMock::TriggerOnConnectionResume(uint32_t connectionId)
{
    if (g_onConnectionResumeCallback != nullptr) {
        g_onConnectionResumeCallback(connectionId);
    }
}

int32_t ConnBrTransMuduleInit(SppSocketDriver *driver, ConnBrTransEventListener *listener)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ConnBrTransMuduleInit(driver, listener);
    }
    return BrManagerTestMock::DefaultActionOfConnBrTransMuduleInit(driver, listener);
}

int32_t ConnBrPostBytes(uint32_t connectionId, uint8_t *data, uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ConnBrPostBytes(connectionId, data, len, pid, flag, seq);
    }
    return SOFTBUS_OK;
}

int32_t ConnBrTransConfigPostLimit(const LimitConfiguration *config)
{
    auto mock = BrManagerTestMock::GetMock();
    if (mock != nullptr) {
        return mock->ConnBrTransConfigPostLimit(config);
    }
    return SOFTBUS_OK;
}
}
}
