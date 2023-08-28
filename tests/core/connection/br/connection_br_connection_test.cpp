/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "connection_br_mock.h"
#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_br_pending_packet.h"
#include "softbus_conn_br_connection.c"
#include "softbus_conn_br_manager.c"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_conn_br_send_queue.h"
#include "softbus_feature_config.c"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
int32_t GetRemoteDeviceInfo(int32_t clientFd, const BluetoothRemoteDevice* device)
{
    (void)device;
    return clientFd;
}

void OnConnectFailed(uint32_t requestId, int32_t reason)
{
    (void)requestId;
    (void)reason;
    return;
}

void OnConnectSuccessed(uint32_t requestId, uint32_t connectionId, const ConnectionInfo *info)
{
    (void)requestId;
    (void)connectionId;
    (void)info;
    return;
}

void PostMessageDelay(const SoftBusLooper *looper, SoftBusMessage *msg, uint64_t delayMillis)
{
    (void)looper;
    (void)msg;
    (void)delayMillis;
    return;
}

int32_t DeviceAction(ConnBrDevice *device, const char *anomizeAddress)
{
    return (int32_t)(device->state);
}

void OnConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
    return;
}

class ConnectionBrConnectionTest : public testing::Test {
public:
    ConnectionBrConnectionTest()
    {}
    ~ConnectionBrConnectionTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ConnectionBrConnectionTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    ConnServerInit();
}

void ConnectionBrConnectionTest::TearDownTestCase(void)
{}

void ConnectionBrConnectionTest::SetUp(void)
{}

void ConnectionBrConnectionTest::TearDown(void)
{}

HWTEST_F(ConnectionBrConnectionTest, testBrConnection001, TestSize.Level1)
{
    int ret;
    ConnBrConnection connection;
    const cJSON *json =nullptr;
    NiceMock<ConnectionBrInterfaceMock> brMock;

    EXPECT_CALL(brMock, GetJsonObjectSignedNumberItem).WillRepeatedly(Return(false));
    ret = ConnBrOnReferenceRequest(&connection, json);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    EXPECT_CALL(brMock, GetJsonObjectSignedNumberItem).WillRepeatedly(Return(true));
    connection.connectionRc = 0;
    SoftBusMutexInit(&connection.lock, nullptr);
    ret = ConnBrOnReferenceRequest(&connection, json);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(brMock, GetJsonObjectSignedNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(brMock, AddNumberToJsonObject).WillRepeatedly(Return(false));
    connection.connectionRc = 1;
    SoftBusMutexInit(&connection.lock, nullptr);
    ret = ConnBrOnReferenceRequest(&connection, json);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);

    EXPECT_CALL(brMock, GetJsonObjectSignedNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(brMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(brMock, AddNumber64ToJsonObject).WillRepeatedly(Return(true));
    connection.connectionRc = 1;
    connection.connectionId = 1;
    SoftBusMutexInit(&connection.lock, nullptr);
    ret = ConnBrOnReferenceRequest(&connection, json);
    EXPECT_EQ(SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrConnection002, TestSize.Level1)
{
    int ret;
    ConnBrConnection connection;
    int32_t delta;
    NiceMock<ConnectionBrInterfaceMock> brMock;

    EXPECT_CALL(brMock, AddNumberToJsonObject).WillRepeatedly(Return(false));
    connection.connectionId = 1;
    connection.connectionRc = 0;
    delta = 0;
    SoftBusMutexInit(&connection.lock, nullptr);
    ret = ConnBrUpdateConnectionRc(&connection, delta);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);

    EXPECT_CALL(brMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    connection.connectionId = 1;
    connection.connectionRc = 0;
    delta = 0;
    SoftBusMutexInit(&connection.lock, nullptr);
    ret = ConnBrUpdateConnectionRc(&connection, delta);
    EXPECT_EQ(SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrConnection003, TestSize.Level1)
{
    int ret;
    ConnBrConnection connection;

    connection.socketHandle = MAX_BR_READ_BUFFER_CAPACITY;
    ret = ConnBrDisconnectNow(&connection);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrConnection004, TestSize.Level1)
{
    const char *addr = "24:DA:33:6A:06:EC";
    int32_t result = 0;
    int32_t status = 0;

    BrConnectStatusCallback(addr, result, status);
}

HWTEST_F(ConnectionBrConnectionTest, testBrConnection005, TestSize.Level1)
{
    int ret;
    ConnBrConnection connection;
    const cJSON *json = nullptr;
    NiceMock<ConnectionBrInterfaceMock> brMock;

    EXPECT_CALL(brMock, GetJsonObjectSignedNumberItem).WillRepeatedly(Return(false));
    ret = ConnBrOnReferenceResponse(&connection, json);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    EXPECT_CALL(brMock, GetJsonObjectSignedNumberItem).WillRepeatedly(Return(true));
    SoftBusMutexInit(&connection.lock, nullptr);
    ret = ConnBrOnReferenceResponse(&connection, json);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrConnection006, TestSize.Level1)
{
    int ret;
    ServerState serverState;

    g_serverState = &serverState;
    ret = ConnBrStartServer();
    EXPECT_EQ(SOFTBUS_OK, ret);

    g_serverState = nullptr;
    ret = ConnBrStartServer();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrConnection007, TestSize.Level1)
{
    int ret;

    g_serverState->serverId = 1;
    ret = ConnBrStopServer();
    EXPECT_EQ(SOFTBUS_OK, ret);

    g_serverState = nullptr;
    ret = ConnBrStopServer();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrConnection008, TestSize.Level1)
{
    SoftBusMessage msg;

    msg.what = MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT;
    BrConnectionMsgHandler(&msg);
    msg.what = MSG_CONNECTION_RETRY_NOTIFY_REFERENCE;
    BrConnectionMsgHandler(&msg);
    msg.what = MSG_CONNECTION_RETRY_NOTIFY_REFERENCE + 1;
    BrConnectionMsgHandler(&msg);
}

HWTEST_F(ConnectionBrConnectionTest, testBrConnection009, TestSize.Level1)
{
    int ret;
    SoftBusMessage msg;
    SoftBusMessage args;

    msg.what = MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT;
    args.what = MSG_CONNECTION_RETRY_NOTIFY_REFERENCE;
    ret = BrCompareConnectionLooperEventFunc(&msg, (void *)(&args));
    EXPECT_EQ(COMPARE_FAILED, ret);

    msg.what = MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT;
    args.what = MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT;
    msg.arg1 = 10;
    args.arg1 = 10;
    ret = BrCompareConnectionLooperEventFunc(&msg, (void *)(&args));
    EXPECT_EQ(COMPARE_SUCCESS, ret);

    msg.what = MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT;
    args.what = MSG_CONNECTION_WAIT_NEGOTIATION_CLOSING_TIMEOUT;
    msg.arg1 = 9;
    args.arg1 = 10;
    ret = BrCompareConnectionLooperEventFunc(&msg, (void *)(&args));
    EXPECT_EQ(COMPARE_FAILED, ret);

    msg.what = MSG_CONNECTION_RETRY_NOTIFY_REFERENCE;
    args.what = MSG_CONNECTION_RETRY_NOTIFY_REFERENCE;
    msg.arg1 = 9;
    args.arg1 = 10;
    ret = BrCompareConnectionLooperEventFunc(&msg, (void *)(&args));
    EXPECT_EQ(COMPARE_FAILED, ret);

    msg.what = MSG_CONNECTION_RETRY_NOTIFY_REFERENCE;
    args.what = MSG_CONNECTION_RETRY_NOTIFY_REFERENCE;
    args.arg1 = 0;
    args.arg2 = 0;
    args.obj = nullptr;
    ret = BrCompareConnectionLooperEventFunc(&msg, (void *)(&args));
    EXPECT_EQ(COMPARE_SUCCESS, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrConnection010, TestSize.Level1)
{
    void *ret = nullptr;
    ServerServeContext *ctx = nullptr;

    g_sppDriver->GetRemoteDeviceInfo = GetRemoteDeviceInfo;
    ctx = (ServerServeContext *)SoftBusCalloc(sizeof(*ctx));
    ctx->socketHandle = -1;
    ret = StartServerServe((void *)(ctx));
    EXPECT_EQ(nullptr, ret);

    g_sppDriver->GetRemoteDeviceInfo = GetRemoteDeviceInfo;
    ctx = (ServerServeContext *)SoftBusCalloc(sizeof(*ctx));
    ctx->socketHandle = 0;
    ret = StartServerServe((void *)(ctx));
    EXPECT_EQ(nullptr, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrConnection011, TestSize.Level1)
{
    ConnBrConnection *connection;

    connection = (ConnBrConnection *)SoftBusCalloc(sizeof(*connection));
    connection->connectProcessStatus = nullptr;
    ConnBrFreeConnection(connection);
}

HWTEST_F(ConnectionBrConnectionTest, testBrConnection012, TestSize.Level1)
{
    void *ret;
    ServerState *serverState;

    serverState = (ServerState *)SoftBusCalloc(sizeof(*serverState));
    serverState->available = 0;
    serverState->traceId = 0;
    serverState->serverId = 1;
    SoftBusMutexInit(&serverState->mutex, nullptr);
    ret = ListenTask((void *)serverState);
    EXPECT_EQ(nullptr, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrConnection013, TestSize.Level1)
{
    int ret;
    int val;
    int mtu;

    g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len = 0;
    ret = InitProperty();
    EXPECT_EQ(SOFTBUS_ERR, ret);

    val = MAX_BR_READ_BUFFER_CAPACITY + 1;
    g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len = 4;
    memcpy_s((void*)(g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].val),
        g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len, (void *)(&val), sizeof(int));
    ret = InitProperty();
    EXPECT_EQ(SOFTBUS_ERR, ret);

    val = MAX_BR_READ_BUFFER_CAPACITY;
    g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len = 4;
    memcpy_s((void*)(g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].val),
        g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len, (void *)(&val), sizeof(int));
    g_configItems[SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN].len = 0;
    ret = InitProperty();
    EXPECT_EQ(SOFTBUS_ERR, ret);

    val = MAX_BR_READ_BUFFER_CAPACITY;
    g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len = 4;
    memcpy_s((void*)(g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].val),
        g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len, (void *)(&val), sizeof(int));
    mtu = MAX_BR_MTU_SIZE + 1;
    g_configItems[SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN].len = 4;
    memcpy_s((void*)(g_configItems[SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN].val),
        g_configItems[SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN].len, (void *)(&mtu), sizeof(int));
    ret = InitProperty();
    EXPECT_EQ(SOFTBUS_ERR, ret);

    val = MAX_BR_READ_BUFFER_CAPACITY;
    g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len = 4;
    memcpy_s((void*)(g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].val),
        g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len, (void *)(&val), sizeof(int));
    mtu = MAX_BR_MTU_SIZE;
    g_configItems[SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN].len = 4;
    memcpy_s((void*)(g_configItems[SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN].val),
        g_configItems[SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN].len, (void *)(&mtu), sizeof(int));
    ret = InitProperty();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager001, TestSize.Level1)
{
    uint32_t reqId = 0;
    uint32_t pId = 0;
    ConnBrDevice *device = nullptr;
    ConnectStatistics statistics;
    int32_t reason = 0;

    DfxRecordBrConnectFail(reqId, pId, device, nullptr, reason);
    DfxRecordBrConnectFail(reqId, pId, device, &statistics, reason);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager002, TestSize.Level1)
{
    uint32_t pId = 0;
    ConnBrConnection *connection = nullptr;
    ConnectStatistics statistics;

    DfxRecordBrConnectSuccess(pId, connection, nullptr);
    DfxRecordBrConnectSuccess(pId, connection, &statistics);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager003, TestSize.Level1)
{
    ConnBrDevice device;
    ConnBrConnection connection;
    bool isReuse = false;
    int32_t reason = 0;
    ConnBrRequest request;


    request.requestId = 0;
    request.requestId = 0;
    request.result.OnConnectFailed = OnConnectFailed;
    (void)strcpy_s(device.addr, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    ListInit(&device.requests);
    ListAdd(&device.requests, &request.node);
    NotifyDeviceConnectResult(&device, nullptr, isReuse, reason);


    (void)strcpy_s(device.addr, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    ListInit(&device.requests);
    NotifyDeviceConnectResult(&device, &connection, isReuse, reason);

    request.requestId = 0;
    request.requestId = 0;
    request.result.OnConnectFailed = OnConnectFailed;
    request.result.OnConnectSuccessed = OnConnectSuccessed;
    (void)strcpy_s(device.addr, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    ListInit(&device.requests);
    ListAdd(&device.requests, &request.node);
    reason = 1;
    isReuse = true;
    NotifyDeviceConnectResult(&device, &connection, isReuse, reason);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager004, TestSize.Level1)
{
    BrPending *ret = nullptr;
    BrPending pending;
    const char *addr = "24:DA:33:6A:06:EC";
    ConnBrPendInfo info;

    ListInit(&(g_brManager.pendings->list));
    ListAdd(&(g_brManager.pendings->list), &(pending.node));
    (void)strcpy_s(info.addr, BT_MAC_LEN, addr);
    pending.pendInfo = &info;
    ret = GetBrPending(addr);
    EXPECT_NE(nullptr, ret);

    addr = "ABC";
    ret = GetBrPending(addr);
    EXPECT_EQ(nullptr, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager005, TestSize.Level1)
{
    const char *addr = "24:DA:33:6A:06:EC";
    ConnBrPendInfo info;
    BrPending pending;

    ListInit(&(g_brManager.pendings->list));
    ProcessBleDisconnectedEvent((char *)addr);

    ListAdd(&(g_brManager.pendings->list), &(pending.node));
    (void)strcpy_s(info.addr, BT_MAC_LEN, addr);
    pending.pendInfo = &info;
    SoftBusMutexInit(&g_brManager.pendings->lock, nullptr);
    g_brManagerAsyncHandler.handler.looper->PostMessageDelay = PostMessageDelay;
    ProcessBleDisconnectedEvent((char *)addr);

    info.firstStartTimestamp = 0xfffffffffffffff;
    info.firstDuration = 0x1;
    ProcessBleDisconnectedEvent((char *)addr);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager006, TestSize.Level1)
{
    int32_t listenerId = 0;
    SoftBusBtAddr addr;
    int32_t aclState = SOFTBUS_ACL_STATE_LE_DISCONNECTED;
    int32_t hciReason = 0;
    const char *addrress = "123";

    (void)strcpy_s((char *)(addr.addr), BT_ADDR_LEN, addrress);
    ListInit(&(g_brManager.pendings->list));
    OnAclStateChanged(listenerId, &addr, aclState, hciReason);

    (void)strcpy_s((char *)(addr.addr), BT_ADDR_LEN, addrress);
    aclState = SOFTBUS_ACL_STATE_LE_CONNECTED;
    OnAclStateChanged(listenerId, &addr, aclState, hciReason);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager007, TestSize.Level1)
{
    int ret;
    ConnBrDevice device;
    const char *anomizeAddress;

    (void)strcpy_s(device.addr, BT_MAC_LEN, "abc");
    anomizeAddress = "123";
    SoftBusMutexDestroy(&g_brManager.connections->lock);
    ret = ConnectDeviceDirectly(&device, anomizeAddress);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    (void)strcpy_s(device.addr, BT_MAC_LEN, "abc");
    anomizeAddress = "123";
    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    ret = ConnectDeviceDirectly(&device, anomizeAddress);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager008, TestSize.Level1)
{
    int ret;
    ConnBrDevice *device;
    const char *anomizeAddress;
    ConnBrDevice conn;
    ConnBrDevice  connBr;

    device = (ConnBrDevice *)SoftBusCalloc(sizeof(*device));
    device->state = BR_DEVICE_STATE_INIT;
    ListInit(&device->requests);
    (void)strcpy_s(device->addr, BT_MAC_LEN, "abc");
    (void)strcpy_s(conn.addr, BT_MAC_LEN, "abc");
    ListInit(&conn.requests);
    g_brManager.connecting = &conn;
    anomizeAddress = "abc";
    ListInit(&g_brManager.waitings);
    ret = PendingDevice(device, anomizeAddress);
    EXPECT_EQ(SOFTBUS_OK, ret);

    device = (ConnBrDevice *)SoftBusCalloc(sizeof(*device));
    device->state = BR_DEVICE_STATE_INIT;
    ListInit(&device->requests);
    (void)strcpy_s(device->addr, BT_MAC_LEN, "abc");
    (void)strcpy_s(conn.addr, BT_MAC_LEN, "abcd");
    ListInit(&conn.requests);
    g_brManager.connecting = &conn;
    anomizeAddress = "abc";
    ListInit(&g_brManager.waitings);
    ret = PendingDevice(device, anomizeAddress);
    EXPECT_EQ(SOFTBUS_OK, ret);

    device->state = BR_DEVICE_STATE_INIT;
    ListInit(&device->requests);
    (void)strcpy_s(device->addr, BT_MAC_LEN, "abc");
    (void)strcpy_s(conn.addr, BT_MAC_LEN, "abcd");
    (void)strcpy_s(connBr.addr, BT_MAC_LEN, "abc");
    ListInit(&conn.requests);
    g_brManager.connecting = &conn;
    anomizeAddress = "abc";
    ListInit(&g_brManager.waitings);
    ListTailInsert(&g_brManager.waitings, &connBr.node);
    ret = PendingDevice(device, anomizeAddress);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager009, TestSize.Level1)
{
    bool ret;
    ConnBrConnection connection;
    ConnBrDevice device;

    connection.state = BR_CONNECTION_STATE_EXCEPTION;
    SoftBusMutexInit(&connection.lock, nullptr);
    connection.connectionId = 1;
    ret = BrReuseConnection(&device, &connection);
    EXPECT_EQ(false, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager010, TestSize.Level1)
{
    bool ret;
    const char *addr = "abc";
    BrPending pending;
    ConnBrPendInfo pendInfo;

    SoftBusMutexInit(&g_brManager.pendings->lock, nullptr);
    ListInit(&g_brManager.pendings->list);
    (void)strcpy_s(pendInfo.addr, BT_MAC_LEN, "abc");
    pending.pendInfo = &pendInfo;
    ListTailInsert(&g_brManager.pendings->list, &pending.node);
    ret = CheckPending(addr);
    EXPECT_EQ(true, ret);

    (void)strcpy_s(pendInfo.addr, BT_MAC_LEN, "abcd");
    ret = CheckPending(addr);
    EXPECT_EQ(false, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager011, TestSize.Level1)
{
    ConnBrDevice *device;
    BrPending pending;
    ConnBrPendInfo pendInfo;

    device = (ConnBrDevice *)SoftBusCalloc(sizeof(*device));
    (void)strcpy_s(device->addr, BT_MAC_LEN, "abcde");
    SoftBusMutexDestroy(&g_brManager.connections->lock);

    SoftBusMutexInit(&g_brManager.pendings->lock, nullptr);
    ListInit(&g_brManager.pendings->list);
    (void)strcpy_s(pendInfo.addr, BT_MAC_LEN, "abcde");
    (void)strcpy_s(g_brManager.connecting->addr, BT_MAC_LEN, "abcd");
    pending.pendInfo = &pendInfo;
    ListTailInsert(&g_brManager.pendings->list, &pending.node);
    AttempReuseConnect(device, DeviceAction);

    SoftBusMutexDestroy(&g_brManager.pendings->lock);
    ListInit(&device->requests);
    AttempReuseConnect(device, DeviceAction);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager012, TestSize.Level1)
{
    uint32_t connectionId = 0;
    ConnBrConnection *target;
    ConnBrDevice conn;

    target = (ConnBrConnection *)SoftBusCalloc(sizeof(*target));
    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    (void)strcpy_s(target->addr, BT_MAC_LEN, "abcde");
    target->connectionId = 0;
    SoftBusMutexInit(&target->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    ListTailInsert(&g_brManager.connections->list, &target->node);
    g_connectCallback.OnConnected = OnConnected;
    (void)strcpy_s(conn.addr, BT_MAC_LEN, "abcde");
    g_brManager.connecting = &conn;
    ServerAccepted(connectionId);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager013, TestSize.Level1)
{
    uint32_t connectionId = 0;
    ConnBrConnection *target;
    ConnBrDevice *it;

    target = (ConnBrConnection *)SoftBusCalloc(sizeof(*target));
    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    (void)strcpy_s(target->addr, BT_MAC_LEN, "abcde");
    target->connectionId = 0;
    SoftBusMutexInit(&target->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    ListTailInsert(&g_brManager.connections->list, &target->node);
    g_connectCallback.OnConnected = OnConnected;
    g_brManager.connecting = nullptr;

    it = (ConnBrDevice *)SoftBusCalloc(sizeof(*it ));
    ListInit(&g_brManager.waitings);
    (void)strcpy_s(it->addr, BT_MAC_LEN, "abcde");
    ListTailInsert(&g_brManager.waitings, &it->node);
    ServerAccepted(connectionId);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager014, TestSize.Level1)
{
    uint32_t connectionId = 0;
    ConnBrConnection *target;
    NiceMock<ConnectionBrInterfaceMock> brMock;

    SoftBusMutexDestroy(&g_brManager.connections->lock);
    ClientConnected(connectionId);

    EXPECT_CALL(brMock, AddNumberToJsonObject).WillRepeatedly(Return(false));
    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    target = (ConnBrConnection *)SoftBusCalloc(sizeof(*target));
    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    (void)strcpy_s(target->addr, BT_MAC_LEN, "abcde");
    target->connectionId = 0;
    target->connectionRc = 10;
    SoftBusMutexInit(&target->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    ListTailInsert(&g_brManager.connections->list, &target->node);
    g_brManager.connecting = nullptr;
    ClientConnected(connectionId);
}
}
