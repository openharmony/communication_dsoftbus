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

#include "br_mock.h"
#include "softbus_conn_br_connection.h"
#include "softbus_conn_br_manager.h"
#include "softbus_conn_br_trans.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "common_list.h"
#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_errcode.h"
#include "wrapper_br_interface.h"

#include "softbus_conn_br_pending_packet.h"
#include "softbus_conn_br_send_queue.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"

using namespace testing::ext;
using namespace testing;
using namespace std;

namespace OHOS {
extern "C" {
void OnConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
    return;
}

void OnReusedConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
    return;
}

void OnDisconnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
    return;
}

void OnDataReceived(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len)
{
    (void)connectionId;
    (void)moduleId;
    (void)seq;
    (void)data;
    (void)len;
    return;
}

void Init(const struct tagSppSocketDriver *sppDriver)
{
    (void)sppDriver;
    return;
}

int32_t Read(int32_t clientFd, uint8_t *buf, const int32_t length)
{
    (void)clientFd;
    (void)buf;
    if (length <= 0) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t Write(int32_t clientFd, const uint8_t *buf, const int32_t length)
{
    (void)clientFd;
    (void)buf;
    if (length <= 0) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void OnPostByteFinshed(
    uint32_t connectionId, uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq, int32_t error)
{
    (void)connectionId;
    (void)len;
    (void)pid;
    (void)flag;
    (void)module;
    (void)seq;
    (void)error;
    return;
}

void OnConnectSuccessed(uint32_t requestId, uint32_t connectionId, const ConnectionInfo *info)
{
    (void)requestId;
    (void)connectionId;
    (void)info;
    return;
}

void OnConnectFailed(uint32_t requestId, int32_t reason)
{
    (void)requestId;
    (void)reason;
    return;
}
}
class ConnectionBrConnectionTest : public testing::Test {
public:
    ConnectionBrConnectionTest() { }
    ~ConnectionBrConnectionTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ConnectionBrConnectionTest::SetUpTestCase(void){ }

void ConnectionBrConnectionTest::TearDownTestCase(void) { }

void ConnectionBrConnectionTest::SetUp(void) { }

void ConnectionBrConnectionTest::TearDown(void) { }

SppSocketDriver g_sppDriver = {
    .Init = Init,
    .Read = Read,
    .Write = Write,
};

ConnBrTransEventListener g_transEventlistener = {
    .onPostByteFinshed = OnPostByteFinshed,
};

ConnectFuncInterface *connectFuncInterface = NULL;
ConnectFuncInterface *g_connectFuncInterface = NULL;

ConnectFuncInterface *ConnInit(void)
{
    ConnectCallback callback = {
        .OnConnected = OnConnected,
        .OnDisconnected = OnDisconnected,
        .OnDataReceived = OnDataReceived,
    };
    NiceMock<ConnectionBrInterfaceMock>brMock;

    EXPECT_CALL(brMock, InitSppSocketDriver).WillOnce(Return(&g_sppDriver));
    EXPECT_CALL(brMock, SoftbusGetConfig)
        .WillOnce(ConnectionBrInterfaceMock::ActionOfSoftbusGetConfig1)
        .WillOnce(ConnectionBrInterfaceMock::ActionOfSoftbusGetConfig2);
    EXPECT_CALL(brMock, ConnBrInnerQueueInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftBusThreadCreate)
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftBusAddBtStateListener).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, ConnBrInitBrPendingPacket)
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK));

    connectFuncInterface = ConnInitBr(&callback);
    return connectFuncInterface;
}

HWTEST_F(ConnectionBrConnectionTest, BrManagerTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnInitBr1, Start");

    ConnectCallback callback = {
        .OnConnected = OnConnected,
        .OnDisconnected = OnDisconnected,
        .OnDataReceived = OnDataReceived,
    };
    NiceMock<ConnectionBrInterfaceMock>brMock;

    EXPECT_CALL(brMock, InitSppSocketDriver).WillOnce(Return(&g_sppDriver));
    EXPECT_CALL(brMock, SoftbusGetConfig).WillOnce(Return(SOFTBUS_ERR));
    ConnectFuncInterface *ret = ConnInitBr(&callback);
    EXPECT_EQ(NULL, ret);

    EXPECT_CALL(brMock, InitSppSocketDriver).WillOnce(Return(&g_sppDriver));
    EXPECT_CALL(brMock, SoftbusGetConfig).WillOnce(Return(SOFTBUS_OK));
    ret = ConnInitBr(&callback);
    EXPECT_EQ(NULL, ret);

    EXPECT_CALL(brMock, InitSppSocketDriver).WillOnce(Return(&g_sppDriver));
    EXPECT_CALL(brMock, SoftbusGetConfig)
        .WillOnce(ConnectionBrInterfaceMock::ActionOfSoftbusGetConfig1)
        .WillOnce(Return(SOFTBUS_ERR));
    ret = ConnInitBr(&callback);
    EXPECT_EQ(NULL, ret);
}

HWTEST_F(ConnectionBrConnectionTest, BrManagerTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnInitBr2, Start");

    ConnectCallback callback = {
        .OnConnected = OnConnected,
        .OnDisconnected = OnDisconnected,
        .OnDataReceived = OnDataReceived,
    };
    NiceMock<ConnectionBrInterfaceMock>brMock;

    EXPECT_CALL(brMock, InitSppSocketDriver).WillOnce(Return(&g_sppDriver));
    EXPECT_CALL(brMock, SoftbusGetConfig)
        .WillOnce(ConnectionBrInterfaceMock::ActionOfSoftbusGetConfig1)
        .WillOnce(ConnectionBrInterfaceMock::ActionOfSoftbusGetConfig2);
    EXPECT_CALL(brMock, ConnBrInnerQueueInit).WillOnce(Return(SOFTBUS_ERR));
    ConnectFuncInterface *ret = ConnInitBr(&callback);
    EXPECT_EQ(NULL, ret);

    EXPECT_CALL(brMock, InitSppSocketDriver).WillOnce(Return(&g_sppDriver));
    EXPECT_CALL(brMock, SoftbusGetConfig)
        .WillOnce(ConnectionBrInterfaceMock::ActionOfSoftbusGetConfig1)
        .WillOnce(ConnectionBrInterfaceMock::ActionOfSoftbusGetConfig2);
    EXPECT_CALL(brMock, ConnBrInnerQueueInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(brMock, SoftBusThreadCreate)
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_ERR));
    ret = ConnInitBr(&callback);
    EXPECT_EQ(NULL, ret);
}

HWTEST_F(ConnectionBrConnectionTest, BrManagerTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnInitBr3, Start");

    NiceMock<ConnectionBrInterfaceMock>brMock;
    ConnectOption *option = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    option->type = CONNECT_BR;
    (void)strcpy_s(option->brOption.brMac, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    uint32_t requestId = 1;
    ConnectResult result = {
        .OnConnectSuccessed = OnConnectSuccessed,
        .OnConnectFailed = OnConnectFailed,
    };

    g_connectFuncInterface = ConnInit();
    int32_t ret = g_connectFuncInterface->ConnectDevice(option, requestId, &result);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, BrManagerTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnInitBr4, Start");

    NiceMock<ConnectionBrInterfaceMock>brMock;
    uint32_t connectionId = 1;
    uint8_t *data1 = (uint8_t *)SoftBusCalloc(sizeof(uint8_t));
    (void)memset_s(data1, sizeof(uint8_t), 0, sizeof(uint8_t));
    int32_t pid = 1;
    int32_t flag = 1;
    int64_t seq = 1;
    int32_t ret = g_connectFuncInterface->PostBytes(connectionId, data1, 0, pid, flag, MODULE_BLE_CONN, seq);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    uint8_t *data2 = (uint8_t *)SoftBusCalloc(sizeof(uint8_t));
    (void)memset_s(data2, sizeof(uint8_t), 0, sizeof(uint8_t));
    ConnBrDevice *device = (ConnBrDevice *)SoftBusCalloc(sizeof(ConnBrDevice));
    (void)strcpy_s(device->addr, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    ret = g_connectFuncInterface->PostBytes(connectionId, data2, 3, pid, flag, MODULE_BLE_CONN, seq);
    EXPECT_EQ(SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR, ret);

    uint8_t *data3 = (uint8_t *)SoftBusCalloc(sizeof(uint8_t));
    (void)memset_s(data3, sizeof(uint8_t), 0, sizeof(uint8_t));
    ConnBrConnection *connection = ConnBrCreateConnection(device->addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ConnBrSaveConnection(connection);
    ret = g_connectFuncInterface->PostBytes(connection->connectionId, data3, 3, pid, flag, MODULE_BLE_CONN, seq);
    EXPECT_EQ(SOFTBUS_CONN_BR_CONNECTION_NOT_READY_ERR, ret);

    uint8_t *data4 = (uint8_t *)SoftBusCalloc(sizeof(uint8_t));
    (void)memset_s(data4, sizeof(uint8_t), 0, sizeof(uint8_t));
    EXPECT_CALL(brMock, ConnBrEnqueueNonBlock).WillOnce(Return(SOFTBUS_OK));
    ret = g_connectFuncInterface->PostBytes(connection->connectionId, data4, 3, pid, flag, MODULE_CONNECTION, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, BrManagerTest005, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnInitBr5, Start");

    ConnBrDevice *device = (ConnBrDevice *)SoftBusCalloc(sizeof(ConnBrDevice));
    (void)strcpy_s(device->addr, BT_MAC_LEN, "24:DA:33:6A:06:EC");

    g_connectFuncInterface = ConnInit();
    ConnBrConnection *connection = ConnBrCreateConnection(device->addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ConnBrSaveConnection(connection);
    int32_t ret = g_connectFuncInterface->DisconnectDevice(connection->connectionId);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, BrManagerTest006, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnInitBr6, Start");

    ConnectOption *option = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    option->type = CONNECT_BR;
    option->brOption.sideType = CONN_SIDE_ANY;
    (void)strcpy_s(option->brOption.brMac, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    ConnBrDevice *device = (ConnBrDevice *)SoftBusCalloc(sizeof(ConnBrDevice));
    (void)strcpy_s(device->addr, BT_MAC_LEN, "24:DA:33:6A:06:EC");

    g_connectFuncInterface = ConnInit();
    ConnBrConnection *connection = ConnBrCreateConnection(device->addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ConnBrSaveConnection(connection);
    int32_t ret = g_connectFuncInterface->DisconnectDeviceNow(option);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, BrManagerTest007, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnInitBr7, Start");

    ConnBrDevice *device = (ConnBrDevice *)SoftBusCalloc(sizeof(ConnBrDevice));
    (void)strcpy_s(device->addr, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    ConnectionInfo *info = (ConnectionInfo *)SoftBusCalloc(sizeof(ConnectionInfo));
    (void)strcpy_s(info->brInfo.brMac, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    
    g_connectFuncInterface = ConnInit();
    ConnBrConnection *connection = ConnBrCreateConnection(device->addr, CONN_SIDE_CLIENT, INVALID_SOCKET_HANDLE);
    ConnBrSaveConnection(connection);
    int32_t ret = g_connectFuncInterface->GetConnectionInfo(connection->connectionId, info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, BrManagerTest008, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnInitBr8, Start");

    NiceMock<ConnectionBrInterfaceMock>brMock;
    LocalListenerInfo *info = (LocalListenerInfo *)SoftBusCalloc(sizeof(LocalListenerInfo));
    info->type = CONNECT_BR;
    EXPECT_CALL(brMock, SoftBusThreadCreate).WillOnce(Return(SOFTBUS_ERR));
    int32_t ret = g_connectFuncInterface->StartLocalListening(info);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    EXPECT_CALL(brMock, SoftBusThreadCreate).WillOnce(Return(SOFTBUS_OK));
    ret = g_connectFuncInterface->StartLocalListening(info);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = g_connectFuncInterface->StopLocalListening(info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, BrManagerTest009, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnInitBr9, Start");

    ConnectOption *option = (ConnectOption *)SoftBusCalloc(sizeof(ConnectOption));
    option->type = CONNECT_BR;
    option->brOption.sideType = CONN_SIDE_ANY;
    (void)strcpy_s(option->brOption.brMac, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    uint32_t time = 1;
    
    int32_t ret = g_connectFuncInterface->PreventConnection(option, time);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
}