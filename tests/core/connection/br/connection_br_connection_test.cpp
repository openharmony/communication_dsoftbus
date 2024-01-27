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

#include "common_list.h"
#include "connection_br_mock.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_br_connection.c"
#include "softbus_conn_br_manager.c"
#include "softbus_conn_br_pending_packet.h"
#include "softbus_conn_br_send_queue.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.c"
#include "softbus_feature_config.h"

#define SOFTBUS_CHARA_CONN_UUID "00002B01-0000-1000-8000-00805F9B34FB"
#define DATASIZE                256

using namespace testing::ext;
using namespace testing;

namespace OHOS {
int32_t GetRemoteDeviceInfo(int32_t clientFd, const BluetoothRemoteDevice *device)
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

void OnDisconnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
    return;
}

void MessageDelay(const SoftBusLooper *looper, SoftBusMessage *msg, uint64_t delayMillis)
{
    (void)looper;
    (void)msg;
    (void)delayMillis;
    return;
}

void RvMessageCustom(const SoftBusLooper *looper, const SoftBusHandler *handler,
    int32_t (*customFunc)(const SoftBusMessage *, void *), void *args)
{
    (void)looper;
    (void)handler;
    (void)customFunc;
    (void)args;
    return;
}

void handlePendingRequest(void)
{
    return;
}

void connectRequest(const ConnBrConnectRequestContext *ctx)
{
    (void)ctx;
    return;
}

void clientConnected(uint32_t connectionId)
{
    (void)connectionId;
    return;
}

void clientConnectTimeout(uint32_t connectionId, const char *address)
{
    (void)connectionId;
    (void)address;
    return;
}

void clientConnectFailed(uint32_t connectionId, int32_t error)
{
    (void)connectionId;
    (void)error;
    return;
}

void serverAccepted(uint32_t connectionId)
{
    (void)connectionId;
    return;
}

void dataReceived(ConnBrDataReceivedContext *ctx)
{
    (void)ctx;
    return;
}

void connectionException(uint32_t connectionId, int32_t error)
{
    (void)connectionId;
    (void)error;
    return;
}

void connectionResume(uint32_t connectionId)
{
    (void)connectionId;
    return;
}

void disconnectRequest(uint32_t connectionId)
{
    (void)connectionId;
    return;
}
void Unpend(const char *addr)
{
    (void)addr;
    return;
}

void reset(int32_t reason)
{
    (void)reason;
    return;
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

void ConnectionBrConnectionTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    ConnServerInit();
}

void ConnectionBrConnectionTest::TearDownTestCase(void) { }

void ConnectionBrConnectionTest::SetUp(void) { }

void ConnectionBrConnectionTest::TearDown(void) { }

HWTEST_F(ConnectionBrConnectionTest, testBrConnection001, TestSize.Level1)
{
    int ret;
    ConnBrConnection connection;
    const cJSON *json = nullptr;
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
    int32_t result = 0;
    int32_t status = 0;

    BdAddr addr = {
        .addr = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
    };
    BtUuid uuid = {
        .uuid = (char *)SOFTBUS_CHARA_CONN_UUID,
        .uuidLen = strlen(SOFTBUS_CHARA_CONN_UUID),
    };
    BrConnectStatusCallback(&addr, uuid, result, status);
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
    memcpy_s((void *)(g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].val),
        g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len, (void *)(&val), sizeof(int));
    ret = InitProperty();
    EXPECT_EQ(SOFTBUS_ERR, ret);

    val = MAX_BR_READ_BUFFER_CAPACITY;
    g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len = 4;
    memcpy_s((void *)(g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].val),
        g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len, (void *)(&val), sizeof(int));
    g_configItems[SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN].len = 0;
    ret = InitProperty();
    EXPECT_EQ(SOFTBUS_ERR, ret);

    val = MAX_BR_READ_BUFFER_CAPACITY;
    g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len = 4;
    memcpy_s((void *)(g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].val),
        g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len, (void *)(&val), sizeof(int));
    mtu = MAX_BR_MTU_SIZE + 1;
    g_configItems[SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN].len = 4;
    memcpy_s((void *)(g_configItems[SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN].val),
        g_configItems[SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN].len, (void *)(&mtu), sizeof(int));
    ret = InitProperty();
    EXPECT_EQ(SOFTBUS_ERR, ret);

    val = MAX_BR_READ_BUFFER_CAPACITY;
    g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len = 4;
    memcpy_s((void *)(g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].val),
        g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len, (void *)(&val), sizeof(int));
    mtu = MAX_BR_MTU_SIZE;
    g_configItems[SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN].len = 4;
    memcpy_s((void *)(g_configItems[SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN].val),
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
    ConnBrConnection *connection = static_cast<ConnBrConnection *>(SoftBusMalloc(sizeof(ConnBrConnection)));
    if (connection == nullptr) {
        return;
    }
    connection->connectionId = 1;

    ConnectStatistics statistics;
    (void)memset_s(&statistics, sizeof(statistics), 0, sizeof(statistics));

    DfxRecordBrConnectSuccess(pId, connection, nullptr);
    DfxRecordBrConnectSuccess(pId, connection, &statistics);
    SoftBusFree(connection);
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
    ConnBrDevice connBr;

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

    it = (ConnBrDevice *)SoftBusCalloc(sizeof(*it));
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

HWTEST_F(ConnectionBrConnectionTest, testBrManager015, TestSize.Level1)
{
    uint32_t connectionId = 0;
    int32_t error = 0;
    ConnBrConnection *target;

    SoftBusMutexDestroy(&g_brManager.connections->lock);
    ClientConnectFailed(connectionId, error);

    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    target = reinterpret_cast<ConnBrConnection *>(SoftBusCalloc(sizeof(*target)));
    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    (void)strcpy_s(target->addr, BT_MAC_LEN, "abcde");
    target->connectionId = 1;
    target->connectionRc = 10;
    SoftBusMutexInit(&target->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    ListTailInsert(&g_brManager.connections->list, &target->node);
    g_brManager.connecting = nullptr;
    ClientConnectFailed(connectionId, error);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager016, TestSize.Level1)
{
    uint32_t connectionId = 0;
    int32_t error = 0;
    ConnBrConnection *target;
    ConnBrDevice *connectingDevice;

    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    target = reinterpret_cast<ConnBrConnection *>(SoftBusCalloc(sizeof(*target)));
    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    (void)strcpy_s(target->addr, BT_MAC_LEN, "abcde");
    target->connectionId = 0;
    target->connectionRc = 10;
    target->side = CONN_SIDE_SERVER;
    target->state = BR_CONNECTION_STATE_EXCEPTION;
    target->objectRc = 1;
    SoftBusMutexInit(&target->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    ListTailInsert(&g_brManager.connections->list, &target->node);
    connectingDevice = reinterpret_cast<ConnBrDevice *>(SoftBusCalloc(sizeof(*connectingDevice)));
    (void)strcpy_s(connectingDevice->addr, BT_MAC_LEN, "abcde");
    ListInit(&connectingDevice->requests);
    g_brManager.connecting = connectingDevice;
    ClientConnectFailed(connectionId, error);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager017, TestSize.Level1)
{
    uint32_t connectionId = 0;
    const char *address = "abc";
    ConnBrConnection *target;

    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    target = reinterpret_cast<ConnBrConnection *>(SoftBusCalloc(sizeof(*target)));
    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    (void)strcpy_s(target->addr, BT_MAC_LEN, "abc");
    target->connectionId = 0;
    target->objectRc = 1;
    SoftBusMutexInit(&target->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    ListTailInsert(&g_brManager.connections->list, &target->node);
    g_brManager.connecting = nullptr;
    ClientConnectTimeoutOnConnectingState(connectionId, address);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager018, TestSize.Level1)
{
    uint32_t connectionId = 0;
    const char *address = "abc";
    ConnBrDevice *connectingDevice;

    SoftBusMutexDestroy(&g_brManager.connections->lock);
    connectingDevice = reinterpret_cast<ConnBrDevice *>(SoftBusCalloc(sizeof(*connectingDevice)));
    (void)strcpy_s(connectingDevice->addr, BT_MAC_LEN, "abc");
    ListInit(&connectingDevice->requests);
    g_brManager.connecting = connectingDevice;
    ClientConnectTimeoutOnConnectingState(connectionId, address);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager019, TestSize.Level1)
{
    ConnBrDataReceivedContext ctx;
    ConnPktHead *head;

    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    head = reinterpret_cast<ConnPktHead *>(SoftBusCalloc(sizeof(*head)));
    head->flag = 0;
    head->module = 0;
    head->seq = 0;
    ctx.data = (uint8_t *)head;
    ctx.connectionId = 0;
    DataReceived(&ctx);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager020, TestSize.Level1)
{
    ConnBrDataReceivedContext ctx;
    ConnPktHead *head;
    ConnBrConnection *target;
    NiceMock<ConnectionBrInterfaceMock> brMock;

    EXPECT_CALL(brMock, cJSON_ParseWithLength).WillRepeatedly(Return(nullptr));
    SoftBusMutexDestroy(&g_brManager.connections->lock);
    target = reinterpret_cast<ConnBrConnection *>(SoftBusCalloc(sizeof(*target)));
    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    (void)strcpy_s(target->addr, BT_MAC_LEN, "abc");
    target->connectionId = 0;
    target->objectRc = 1;
    SoftBusMutexInit(&target->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    ListTailInsert(&g_brManager.connections->list, &target->node);

    head = reinterpret_cast<ConnPktHead *>(SoftBusCalloc(sizeof(*head)));
    head->flag = 0;
    head->module = MODULE_CONNECTION;
    head->seq = 0;
    ctx.data = (uint8_t *)head;
    ctx.connectionId = 0;
    DataReceived(&ctx);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager021, TestSize.Level1)
{
    ConnBrDataReceivedContext ctx;
    ConnPktHead *head;
    ConnBrConnection *target;

    SoftBusMutexDestroy(&g_brManager.connections->lock);
    target = reinterpret_cast<ConnBrConnection *>(SoftBusCalloc(sizeof(*target)));
    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    (void)strcpy_s(target->addr, BT_MAC_LEN, "abc");
    target->connectionId = 0;
    target->objectRc = 1;
    SoftBusMutexInit(&target->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    ListTailInsert(&g_brManager.connections->list, &target->node);

    head = reinterpret_cast<ConnPktHead *>(SoftBusCalloc(sizeof(*head)));
    head->flag = 0;
    head->module = MODULE_NIP_BR_CHANNEL;
    head->seq = (int64_t)BR_NIP_SEQ;
    ctx.data = (uint8_t *)head;
    ctx.connectionId = 0;
    DataReceived(&ctx);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager022, TestSize.Level1)
{
    ConnBrDataReceivedContext ctx;
    ConnPktHead *head;
    ConnBrConnection *target;

    SoftBusMutexDestroy(&g_brManager.connections->lock);
    target = reinterpret_cast<ConnBrConnection *>(SoftBusCalloc(sizeof(*target)));
    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    (void)strcpy_s(target->addr, BT_MAC_LEN, "abc");
    target->connectionId = 0;
    target->objectRc = 1;
    SoftBusMutexInit(&target->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    ListTailInsert(&g_brManager.connections->list, &target->node);

    head = reinterpret_cast<ConnPktHead *>(SoftBusCalloc(sizeof(*head)));
    head->flag = 0;
    head->module = MODULE_OLD_NEARBY;
    head->seq = (int64_t)BR_NIP_SEQ;
    ctx.data = (uint8_t *)head;
    ctx.connectionId = 0;
    DataReceived(&ctx);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager023, TestSize.Level1)
{
    ConnBrConnection *connection = static_cast<ConnBrConnection *>(SoftBusMalloc(sizeof(ConnBrConnection)));
    if (connection == nullptr) {
        return;
    }
    connection->connectionId = 0;
    char data[DATASIZE] = { "{\
            \"ESSION_KEY\": \"sdadad\",\
            \"ENCRYPT\": 30,\
            \"MY_HANDLE_ID\": 22,\
            \"PEER_HANDLE_ID\": 25,\
        }" };
    NiceMock<ConnectionBrInterfaceMock> brMock;

    ReceivedControlData(connection, NULL, 0);

    EXPECT_CALL(brMock, GetJsonObjectNumberItem).WillRepeatedly(Return(false));
    ReceivedControlData(connection, (uint8_t *)data, DATASIZE);

    EXPECT_CALL(brMock, GetJsonObjectNumberItem).WillRepeatedly(Return(true));
    ReceivedControlData(connection, (uint8_t *)data, DATASIZE);
    SoftBusFree(connection);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager024, TestSize.Level1)
{
    uint32_t connectionId = 0;
    int32_t error = 0;
    ConnBrConnection *target;
    ConnBrDevice it;

    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    target = reinterpret_cast<ConnBrConnection *>(SoftBusCalloc(sizeof(*target)));
    (void)strcpy_s(target->addr, BT_MAC_LEN, "abc");
    target->connectionId = 0;
    target->objectRc = 10;
    SoftBusMutexInit(&target->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    ListTailInsert(&g_brManager.connections->list, &target->node);

    ListInit(&g_brManager.waitings);
    (void)strcpy_s(it.addr, BT_MAC_LEN, "abc");
    ListTailInsert(&g_brManager.waitings, &it.node);
    g_connectCallback.OnDisconnected = OnDisconnected;
    g_brManagerAsyncHandler.handler.looper->PostMessageDelay = MessageDelay;
    ConnectionException(connectionId, error);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager025, TestSize.Level1)
{
    uint32_t connectionId = 0;
    ConnBrConnection *target;
    ConnBrDevice *it;

    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    target = reinterpret_cast<ConnBrConnection *>(SoftBusCalloc(sizeof(*target)));
    (void)strcpy_s(target->addr, BT_MAC_LEN, "abc");
    target->connectionId = 0;
    target->objectRc = 10;
    target->state = BR_CONNECTION_STATE_CONNECTED;
    SoftBusMutexInit(&target->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    ListTailInsert(&g_brManager.connections->list, &target->node);

    it = reinterpret_cast<ConnBrDevice *>(SoftBusCalloc(sizeof(*it)));
    (void)strcpy_s(it->addr, BT_MAC_LEN, "abc");
    ListInit(&g_brManager.waitings);
    ListTailInsert(&g_brManager.waitings, &it->node);
    ListInit(&it->requests);
    ConnectionResume(connectionId);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager026, TestSize.Level1)
{
    ConnBrPendInfo unpendInfo;

    SoftBusMutexInit(&g_brManager.pendings->lock, nullptr);
    (void)strcpy_s(unpendInfo.addr, BT_MAC_LEN, "abc");
    ListInit(&g_brManager.pendings->list);
    g_brManagerAsyncHandler.handler.looper->RemoveMessageCustom = RvMessageCustom;
    UnpendConnection(unpendInfo.addr);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager027, TestSize.Level1)
{
    enum BrServerState target = BR_STATE_AVAILABLE;

    TransitionToState(target);
    TransitionToState(target);
    target = BR_STATE_CONNECTING;
    TransitionToState(target);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager028, TestSize.Level1)
{
    SoftBusMessage msg;
    ErrorContext obj;

    g_brManager.state->handlePendingRequest = handlePendingRequest;
    g_brManager.state->connectRequest = connectRequest;
    g_brManager.state->clientConnected = clientConnected;
    g_brManager.state->clientConnectTimeout = clientConnectTimeout;
    g_brManager.state->clientConnectFailed = clientConnectFailed;
    g_brManager.state->serverAccepted = serverAccepted;
    g_brManager.state->dataReceived = dataReceived;
    g_brManager.state->connectionException = connectionException;
    g_brManager.state->connectionResume = connectionResume;
    g_brManager.state->disconnectRequest = disconnectRequest;
    g_brManager.state->unpend = Unpend;
    g_brManager.state->reset = reset;

    obj.connectionId = 0;
    obj.error = 0;
    msg.obj = &obj;

    msg.what = MSG_NEXT_CMD;
    BrManagerMsgHandler(&msg);

    msg.what = MSG_CONNECT_REQUEST;
    BrManagerMsgHandler(&msg);

    msg.what = MSG_CONNECT_SUCCESS;
    BrManagerMsgHandler(&msg);

    msg.what = MSG_CONNECT_TIMEOUT;
    BrManagerMsgHandler(&msg);

    msg.what = MSG_CONNECT_FAIL;
    BrManagerMsgHandler(&msg);

    msg.what = MSG_SERVER_ACCEPTED;
    BrManagerMsgHandler(&msg);

    msg.what = MSG_DATA_RECEIVED;
    BrManagerMsgHandler(&msg);

    msg.what = MSG_CONNECTION_EXECEPTION;
    BrManagerMsgHandler(&msg);

    msg.what = MSG_CONNECTION_RESUME;
    BrManagerMsgHandler(&msg);

    msg.what = MGR_DISCONNECT_REQUEST;
    BrManagerMsgHandler(&msg);

    msg.what = MSG_UNPEND;
    BrManagerMsgHandler(&msg);

    msg.what = MSG_RESET;
    BrManagerMsgHandler(&msg);

    msg.what = MSG_RESET + 1;
    BrManagerMsgHandler(&msg);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager029, TestSize.Level1)
{
    int ret;
    SoftBusMessage msg;
    SoftBusMessage args;
    ConnBrPendInfo msgInfo;
    ConnBrPendInfo ctxInfo;

    msg.what = MSG_CONNECT_TIMEOUT;
    args.what = MSG_UNPEND;
    ret = BrCompareManagerLooperEventFunc(&msg, &args);
    EXPECT_EQ(COMPARE_FAILED, ret);

    msg.what = MSG_CONNECT_TIMEOUT;
    args.what = MSG_CONNECT_TIMEOUT;
    msg.arg1 = 1;
    args.arg1 = 1;
    ret = BrCompareManagerLooperEventFunc(&msg, &args);
    EXPECT_EQ(COMPARE_SUCCESS, ret);

    msg.what = MSG_CONNECT_TIMEOUT;
    args.what = MSG_CONNECT_TIMEOUT;
    msg.arg1 = 0;
    args.arg1 = 1;
    ret = BrCompareManagerLooperEventFunc(&msg, &args);
    EXPECT_EQ(COMPARE_FAILED, ret);

    msg.what = MSG_UNPEND;
    args.what = MSG_UNPEND;
    msg.obj = nullptr;
    args.obj = nullptr;
    ret = BrCompareManagerLooperEventFunc(&msg, &args);
    EXPECT_EQ(COMPARE_SUCCESS, ret);

    msg.what = MSG_UNPEND;
    args.what = MSG_UNPEND;
    (void)strcpy_s(msgInfo.addr, BT_MAC_LEN, "abc");
    (void)strcpy_s(ctxInfo.addr, BT_MAC_LEN, "abc");
    msg.obj = &msgInfo;
    args.obj = &ctxInfo;
    ret = BrCompareManagerLooperEventFunc(&msg, &args);
    EXPECT_EQ(COMPARE_SUCCESS, ret);

    msg.what = MSG_UNPEND;
    args.what = MSG_UNPEND;
    (void)strcpy_s(msgInfo.addr, BT_MAC_LEN, "abcd");
    (void)strcpy_s(ctxInfo.addr, BT_MAC_LEN, "abc");
    msg.obj = &msgInfo;
    args.obj = &ctxInfo;
    ret = BrCompareManagerLooperEventFunc(&msg, &args);
    EXPECT_EQ(COMPARE_FAILED, ret);

    msg.what = MSG_CONNECT_REQUEST;
    args.what = MSG_CONNECT_REQUEST;
    args.arg1 = 1;
    ret = BrCompareManagerLooperEventFunc(&msg, &args);
    EXPECT_EQ(COMPARE_FAILED, ret);

    msg.what = MSG_CONNECT_REQUEST;
    args.what = MSG_CONNECT_REQUEST;
    args.arg1 = 0;
    args.arg2 = 0;
    args.obj = nullptr;
    ret = BrCompareManagerLooperEventFunc(&msg, &args);
    EXPECT_EQ(COMPARE_SUCCESS, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager030, TestSize.Level1)
{
    uint32_t connectionId = 0;
    uint32_t len = 0;
    int32_t pid = 0;
    int32_t flag = 0;
    int32_t module = 0;
    int64_t seq = 0;
    int32_t error = 1;

    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    OnPostByteFinshed(connectionId, len, pid, flag, module, seq, error);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager031, TestSize.Level1)
{
    int ret;
    ConnBrConnection it;

    ListInit(&g_brManager.connections->list);
    it.connectionId = (CONNECT_BR << CONNECT_TYPE_SHIFT) + 3;
    ListTailInsert(&g_brManager.connections->list, &it.node);
    ret = AllocateConnectionIdUnsafe();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager032, TestSize.Level1)
{
    int ret;
    ConnBrConnection it;

    ListInit(&g_brManager.connections->list);
    it.connectionId = 0;
    ListTailInsert(&g_brManager.connections->list, &it.node);
    ret = AllocateConnectionIdUnsafe();
    EXPECT_NE(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager033, TestSize.Level1)
{
    ConnBrConnection *connection;
    ConnBrConnection target;

    connection = reinterpret_cast<ConnBrConnection *>(SoftBusCalloc(sizeof(*connection)));
    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    connection->connectionId = 0;
    target.connectionId = 0;
    ListTailInsert(&g_brManager.connections->list, &target.node);
    ConnBrRemoveConnection(connection);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager034, TestSize.Level1)
{
    ConnBrConnection *connection;
    ConnBrConnection target;

    connection = reinterpret_cast<ConnBrConnection *>(SoftBusCalloc(sizeof(*connection)));
    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    connection->connectionId = 0;
    target.connectionId = 1;
    ListTailInsert(&g_brManager.connections->list, &target.node);
    ConnBrRemoveConnection(connection);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager035, TestSize.Level1)
{
    int ret;
    ConnectOption option;
    uint32_t time = 10;
    BrPending it;
    ConnBrPendInfo pendInfo;

    SoftBusMutexInit(&g_brManager.pendings->lock, nullptr);
    option.type = CONNECT_BR;
    (void)strcpy_s(option.brOption.brMac, BT_MAC_LEN, "abc");
    ListInit(&g_brManager.pendings->list);
    (void)strcpy_s(pendInfo.addr, BT_MAC_LEN, "abc");
    pendInfo.startTimestamp = 1;
    pendInfo.duration = 1;
    pendInfo.firstDuration = 1;
    pendInfo.firstStartTimestamp = 1;
    it.pendInfo = &pendInfo;
    ListTailInsert(&g_brManager.pendings->list, &it.node);
    g_brManagerAsyncHandler.handler.looper->RemoveMessageCustom = RvMessageCustom;
    g_brManagerAsyncHandler.handler.looper->PostMessageDelay = PostMessageDelay;
    ret = BrPendConnection(&option, time);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager036, TestSize.Level1)
{
    int ret;
    ConnectOption option;
    uint32_t time = 10;
    BrPending it;
    ConnBrPendInfo pendInfo;

    SoftBusMutexInit(&g_brManager.pendings->lock, nullptr);
    option.type = CONNECT_BR;
    (void)strcpy_s(option.brOption.brMac, BT_MAC_LEN, "abc");
    ListInit(&g_brManager.pendings->list);
    (void)strcpy_s(pendInfo.addr, BT_MAC_LEN, "abc");
    pendInfo.startTimestamp = 0xffffffff;
    pendInfo.duration = 0xffffffff;
    pendInfo.firstDuration = 1;
    pendInfo.firstStartTimestamp = 1;
    it.pendInfo = &pendInfo;
    ListTailInsert(&g_brManager.pendings->list, &it.node);
    g_brManagerAsyncHandler.handler.looper->RemoveMessageCustom = RvMessageCustom;
    g_brManagerAsyncHandler.handler.looper->PostMessageDelay = PostMessageDelay;
    ret = BrPendConnection(&option, time);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager037, TestSize.Level1)
{
    int ret;
    ConnectOption option;
    uint32_t time = 10;
    BrPending it;
    ConnBrPendInfo pendInfo;

    SoftBusMutexInit(&g_brManager.pendings->lock, nullptr);
    option.type = CONNECT_BR;
    (void)strcpy_s(option.brOption.brMac, BT_MAC_LEN, "abc");
    ListInit(&g_brManager.pendings->list);
    (void)strcpy_s(pendInfo.addr, BT_MAC_LEN, "abce");
    it.pendInfo = &pendInfo;
    ListTailInsert(&g_brManager.pendings->list, &it.node);
    g_brManagerAsyncHandler.handler.looper->PostMessageDelay = PostMessageDelay;
    ret = BrPendConnection(&option, time);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager038, TestSize.Level1)
{
    NiceMock<ConnectionBrInterfaceMock> brMock;

    EXPECT_CALL(brMock, SoftBusGetBtMacAddr).WillRepeatedly(Return(SOFTBUS_ERR));
    DumpLocalBtMac();

    EXPECT_CALL(brMock, SoftBusGetBtMacAddr).WillRepeatedly(Return(SOFTBUS_OK));
    DumpLocalBtMac();
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager039, TestSize.Level1)
{
    int listenerId = 0;
    int state = SOFTBUS_BR_STATE_TURN_ON;
    NiceMock<ConnectionBrInterfaceMock> brMock;

    EXPECT_CALL(brMock, SoftBusGetBtMacAddr).WillRepeatedly(Return(SOFTBUS_ERR));
    OnBtStateChanged(listenerId, state);

    state = SOFTBUS_BR_STATE_TURN_OFF;
    OnBtStateChanged(listenerId, state);
}
} // namespace OHOS
