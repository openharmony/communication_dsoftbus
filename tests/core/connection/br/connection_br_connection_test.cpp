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
#include "softbus_error_code.h"
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

void OnReusedConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    (void)connectionId;
    (void)info;
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

void OnDataReceived(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len)
{
    (void)connectionId;
    (void)moduleId;
    (void)seq;
    (void)data;
    (void)len;
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

void BuildParam(ConnBrManager *manager)
{
    manager->state->handlePendingRequest = handlePendingRequest;
    manager->state->connectRequest = connectRequest;
    manager->state->clientConnected = clientConnected;
    manager->state->clientConnectTimeout = clientConnectTimeout;
    manager->state->clientConnectFailed = clientConnectFailed;
    manager->state->serverAccepted = serverAccepted;
    manager->state->dataReceived = dataReceived;
    manager->state->connectionException = connectionException;
    manager->state->connectionResume = connectionResume;
    manager->state->disconnectRequest = disconnectRequest;
    manager->state->unpend = Unpend;
    manager->state->reset = reset;
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
    LooperInit();
    SoftbusConfigInit();
    ConnServerInit();
}

void ConnectionBrConnectionTest::TearDownTestCase(void)
{
    LooperDeinit();
}

void ConnectionBrConnectionTest::SetUp(void) { }

void ConnectionBrConnectionTest::TearDown(void) { }

HWTEST_F(ConnectionBrConnectionTest, testBrConnection001, TestSize.Level1)
{
    int32_t ret;
    char mac[BT_MAC_LEN] = { 0 };
    int32_t socketHandle = 111;
    ConnBrConnection *connection = ConnBrCreateConnection(mac, CONN_SIDE_SERVER, socketHandle);
    ConnBrSaveConnection(connection);
    const cJSON *json = nullptr;
    NiceMock<ConnectionBrInterfaceMock> brMock;

    EXPECT_CALL(brMock, GetJsonObjectSignedNumberItem).WillRepeatedly(Return(false));
    ret = ConnBrOnReferenceRequest(connection, json);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);

    EXPECT_CALL(brMock, GetJsonObjectSignedNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(brMock, AddNumberToJsonObject).WillRepeatedly(Return(false));
    ret = ConnBrOnReferenceRequest(connection, json);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);

    EXPECT_CALL(brMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(brMock, AddNumber64ToJsonObject).WillRepeatedly(Return(true));
    ret = ConnBrOnReferenceRequest(connection, json);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrConnection002, TestSize.Level1)
{
    int32_t ret;
    char mac[BT_MAC_LEN] = { 0 };
    int32_t socketHandle = 222;
    ConnBrConnection *connection = ConnBrCreateConnection(mac, CONN_SIDE_SERVER, socketHandle);
    ConnBrSaveConnection(connection);
    int32_t delta;
    NiceMock<ConnectionBrInterfaceMock> brMock;

    EXPECT_CALL(brMock, AddNumberToJsonObject).WillRepeatedly(Return(false));
    delta = 0;
    ret = ConnBrUpdateConnectionRc(connection, delta);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);

    EXPECT_CALL(brMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    delta = 0;
    ret = ConnBrUpdateConnectionRc(connection, delta);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrConnection003, TestSize.Level1)
{
    int32_t ret;
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
    int32_t ret;
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
    int32_t ret;
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
    int32_t ret;

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
    int32_t ret;
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
    ASSERT_NE(nullptr, ctx);
    ctx->socketHandle = 0;
    ret = StartServerServe((void *)(ctx));
    EXPECT_EQ(nullptr, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrConnection011, TestSize.Level1)
{
    ConnBrConnection *connection;

    connection = (ConnBrConnection *)SoftBusCalloc(sizeof(*connection));
    ASSERT_NE(nullptr, connection);
    connection->connectProcessStatus = nullptr;
    ConnBrFreeConnection(connection);
}

HWTEST_F(ConnectionBrConnectionTest, testBrConnection012, TestSize.Level1)
{
    void *ret;
    ServerState *serverState;

    serverState = (ServerState *)SoftBusCalloc(sizeof(*serverState));
    ASSERT_NE(nullptr, serverState);
    serverState->available = 0;
    serverState->traceId = 0;
    serverState->serverId = 1;
    SoftBusMutexInit(&serverState->mutex, nullptr);
    ret = ListenTask((void *)serverState);
    EXPECT_EQ(nullptr, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrConnection013, TestSize.Level1)
{
    int32_t ret;
    int32_t val;
    int32_t mtu;

    g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len = 0;
    ret = InitProperty();
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    val = MAX_BR_READ_BUFFER_CAPACITY + 1;
    g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len = 4;
    memcpy_s((void *)(g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].val),
        g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len, (void *)(&val), sizeof(int));
    ret = InitProperty();
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    val = MAX_BR_READ_BUFFER_CAPACITY;
    g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len = 4;
    memcpy_s((void *)(g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].val),
        g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len, (void *)(&val), sizeof(int));
    g_configItems[SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN].len = 0;
    ret = InitProperty();
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    val = MAX_BR_READ_BUFFER_CAPACITY;
    g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len = 4;
    memcpy_s((void *)(g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].val),
        g_configItems[SOFTBUS_INT_CONN_BR_MAX_DATA_LENGTH].len, (void *)(&val), sizeof(int));
    mtu = MAX_BR_MTU_SIZE + 1;
    g_configItems[SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN].len = 4;
    memcpy_s((void *)(g_configItems[SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN].val),
        g_configItems[SOFTBUS_INT_CONN_RFCOM_SEND_MAX_LEN].len, (void *)(&mtu), sizeof(int));
    ret = InitProperty();
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

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

/*
* @tc.name: testBrManager002
* @tc.desc: test DfxRecordBrConnectSuccess when NotifyDeviceConnectResult
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBrConnectionTest, testBrManager002, TestSize.Level1)
{
    ConnBrConnection *connection = static_cast<ConnBrConnection *>(SoftBusMalloc(sizeof(ConnBrConnection)));
    ASSERT_NE(nullptr, connection);
    connection->connectionId = 1;

    ConnBrDevice device;
    ConnBrRequest request;
    request.requestId = 0;
    request.result.OnConnectSuccessed = OnConnectSuccessed;
    (void)strcpy_s(device.addr, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    ListInit(&device.requests);
    ListAdd(&device.requests, &request.node);
    NotifyDeviceConnectResult(&device, connection, true, 1);
    ConnBrRequest *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &device.requests, ConnBrRequest, node) {
        EXPECT_EQ(it->statistics.reuse, true);
    }
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

HWTEST_F(ConnectionBrConnectionTest, testBrManager005, TestSize.Level1)
{
    const char *addr = "24:DA:33:6A:06:EC";
    ConnBrPendInfo info;
    BrPending pending;

    ListInit(&(g_brManager.pendings->list));
    ListAdd(&(g_brManager.pendings->list), &(pending.node));
    (void)strcpy_s(info.addr, BT_MAC_LEN, addr);
    pending.pendInfo = &info;
    SoftBusMutexInit(&g_brManager.pendings->lock, nullptr);
    g_brManagerAsyncHandler.handler.looper->PostMessageDelay = PostMessageDelay;

    info.firstStartTimestamp = 0xfffffffffffffff;
    info.firstDuration = 0x1;
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager006, TestSize.Level1)
{
    const char *addrress = "42:AD:54:6A:06:EC";
    BrPending pending;
    ConnBrPendInfo pendInfo;
    ListInit(&(g_brManager.pendings->list));
    (void)strcpy_s(pendInfo.addr, BT_MAC_LEN, "24:DA:33:6A:06:EC");
    pending.pendInfo = &pendInfo;
    ListAdd(&(g_brManager.pendings->list), &(pending.node));
    bool ret = CheckPending(addrress);
    EXPECT_EQ(false, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager007, TestSize.Level1)
{
    int32_t ret;
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
    int32_t ret;
    ConnBrDevice *device;
    const char *anomizeAddress;
    ConnBrDevice conn;
    ConnBrDevice connBr;

    device = (ConnBrDevice *)SoftBusCalloc(sizeof(*device));
    ASSERT_NE(nullptr, device);
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
    ASSERT_NE(nullptr, device);
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
    EXPECT_EQ(false, ret);

    (void)strcpy_s(pendInfo.addr, BT_MAC_LEN, "abcd");
    ret = CheckPending(addr);
    EXPECT_EQ(false, ret);
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
    ASSERT_NE(nullptr, target);
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
    ASSERT_NE(nullptr, target);
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
    ASSERT_NE(nullptr, target);
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
    ASSERT_NE(nullptr, connectingDevice);
    (void)strcpy_s(connectingDevice->addr, BT_MAC_LEN, "abcde");
    ListInit(&connectingDevice->requests);
    g_brManager.connecting = connectingDevice;
    SoftBusList *list = CreateSoftBusList();
    ConnBrConnection *connection = ConnBrGetConnectionById(connectionId);
    connection->connectProcessStatus = list;
    ClientConnectFailed(connectionId, error);
    ConnBrReturnConnection(&connection);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager017, TestSize.Level1)
{
    uint32_t connectionId = 0;
    const char *address = "abc";
    ConnBrConnection *target;

    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    target = reinterpret_cast<ConnBrConnection *>(SoftBusCalloc(sizeof(*target)));
    ASSERT_NE(nullptr, target);
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
    ASSERT_NE(nullptr, connectingDevice);
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
    ASSERT_NE(nullptr, head);
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
    ASSERT_NE(nullptr, target);
    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    (void)strcpy_s(target->addr, BT_MAC_LEN, "abc");
    target->connectionId = 0;
    target->objectRc = 1;
    SoftBusMutexInit(&target->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    ListTailInsert(&g_brManager.connections->list, &target->node);

    head = reinterpret_cast<ConnPktHead *>(SoftBusCalloc(sizeof(*head)));
    ASSERT_NE(nullptr, head);
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
    ASSERT_NE(nullptr, target);
    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    (void)strcpy_s(target->addr, BT_MAC_LEN, "abc");
    target->connectionId = 0;
    target->objectRc = 1;
    SoftBusMutexInit(&target->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    ListTailInsert(&g_brManager.connections->list, &target->node);

    head = reinterpret_cast<ConnPktHead *>(SoftBusCalloc(sizeof(*head)));
    ASSERT_NE(nullptr, head);
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
    ASSERT_NE(nullptr, target);
    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    (void)strcpy_s(target->addr, BT_MAC_LEN, "abc");
    target->connectionId = 0;
    target->objectRc = 1;
    SoftBusMutexInit(&target->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    ListTailInsert(&g_brManager.connections->list, &target->node);

    head = reinterpret_cast<ConnPktHead *>(SoftBusCalloc(sizeof(*head)));
    ASSERT_NE(nullptr, head);
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
    ASSERT_NE(nullptr, connection);
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
    ASSERT_NE(nullptr, target);
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
    ASSERT_NE(nullptr, target);
    (void)strcpy_s(target->addr, BT_MAC_LEN, "abc");
    target->connectionId = 0;
    target->objectRc = 10;
    target->state = BR_CONNECTION_STATE_CONNECTED;
    SoftBusMutexInit(&target->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    ListTailInsert(&g_brManager.connections->list, &target->node);

    it = reinterpret_cast<ConnBrDevice *>(SoftBusCalloc(sizeof(*it)));
    ASSERT_NE(nullptr, it);
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
    EXPECT_NE(g_brManager.state, nullptr);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager028, TestSize.Level1)
{
    SoftBusMessage msg;
    ErrorContext obj;

    BuildParam(&g_brManager);
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
    int32_t ret;
    SoftBusMessage msg;
    SoftBusMessage args;
    ConnBrPendInfo msgInfo;
    ConnBrPendInfo ctxInfo;

    msg.what = MSG_CONNECT_TIMEOUT;
    args.what = MSG_UNPEND;
    ret = BrCompareManagerLooperEventFunc(&msg, &args);
    EXPECT_EQ(COMPARE_FAILED, ret);

    args.what = MSG_CONNECT_TIMEOUT;
    msg.arg1 = 1;
    args.arg1 = 1;
    ret = BrCompareManagerLooperEventFunc(&msg, &args);
    EXPECT_EQ(COMPARE_SUCCESS, ret);

    msg.arg1 = 0;
    ret = BrCompareManagerLooperEventFunc(&msg, &args);
    EXPECT_EQ(COMPARE_FAILED, ret);

    msg.what = MSG_UNPEND;
    args.what = MSG_UNPEND;
    msg.obj = nullptr;
    args.obj = nullptr;
    ret = BrCompareManagerLooperEventFunc(&msg, &args);
    EXPECT_EQ(COMPARE_FAILED, ret);

    msg.what = MSG_UNPEND;
    args.what = MSG_UNPEND;
    (void)strcpy_s(msgInfo.addr, BT_MAC_LEN, "abc");
    (void)strcpy_s(ctxInfo.addr, BT_MAC_LEN, "abc");
    msg.obj = &msgInfo;
    args.obj = &ctxInfo;
    ret = BrCompareManagerLooperEventFunc(&msg, &args);
    EXPECT_EQ(COMPARE_SUCCESS, ret);

    (void)strcpy_s(msgInfo.addr, BT_MAC_LEN, "abcd");
    (void)strcpy_s(ctxInfo.addr, BT_MAC_LEN, "abc");
    msg.obj = &msgInfo;
    args.obj = &ctxInfo;
    ret = BrCompareManagerLooperEventFunc(&msg, &args);
    EXPECT_EQ(COMPARE_FAILED, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager030, TestSize.Level1)
{
    SoftBusMessage msg;
    SoftBusMessage args;

    msg.what = MSG_CONNECT_REQUEST;
    args.what = MSG_CONNECT_REQUEST;
    args.arg1 = 1;
    int32_t ret = BrCompareManagerLooperEventFunc(&msg, &args);
    EXPECT_EQ(COMPARE_FAILED, ret);

    args.arg1 = 0;
    args.arg2 = 0;
    args.obj = nullptr;
    ret = BrCompareManagerLooperEventFunc(&msg, &args);
    EXPECT_EQ(COMPARE_SUCCESS, ret);
}


HWTEST_F(ConnectionBrConnectionTest, testBrManager031, TestSize.Level1)
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

HWTEST_F(ConnectionBrConnectionTest, testBrManager032, TestSize.Level1)
{
    int32_t ret;
    char mac[BT_MAC_LEN] = { 0 };
    int32_t socketHandle = 333;
    ConnBrConnection *connection = ConnBrCreateConnection(mac, CONN_SIDE_SERVER, socketHandle);
    ConnBrSaveConnection(connection);
    connection->connectionId = (CONNECT_BR << CONNECT_TYPE_SHIFT) + 6;
    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    ListTailInsert(&g_brManager.connections->list, &connection->node);
    ret = AllocateConnectionIdUnsafe();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager033, TestSize.Level1)
{
    int32_t ret;
    ConnBrConnection it;

    ListInit(&g_brManager.connections->list);
    it.connectionId = 0;
    ListTailInsert(&g_brManager.connections->list, &it.node);
    ret = AllocateConnectionIdUnsafe();
    EXPECT_NE(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager034, TestSize.Level1)
{
    ConnBrConnection *connection;
    ConnBrConnection target;

    connection = reinterpret_cast<ConnBrConnection *>(SoftBusCalloc(sizeof(*connection)));
    ASSERT_NE(nullptr, connection);
    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    connection->connectionId = 0;
    target.connectionId = 0;
    ListTailInsert(&g_brManager.connections->list, &target.node);
    ConnBrRemoveConnection(connection);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager035, TestSize.Level1)
{
    ConnBrConnection *connection;
    ConnBrConnection target;

    connection = reinterpret_cast<ConnBrConnection *>(SoftBusCalloc(sizeof(*connection)));
    ASSERT_NE(nullptr, connection);
    SoftBusMutexInit(&g_brManager.connections->lock, nullptr);
    ListInit(&g_brManager.connections->list);
    connection->connectionId = 0;
    target.connectionId = 1;
    ListTailInsert(&g_brManager.connections->list, &target.node);
    ConnBrRemoveConnection(connection);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager036, TestSize.Level1)
{
    int32_t ret;
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

HWTEST_F(ConnectionBrConnectionTest, testBrManager037, TestSize.Level1)
{
    int32_t ret;
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

HWTEST_F(ConnectionBrConnectionTest, testBrManager038, TestSize.Level1)
{
    int32_t ret;
    ConnectOption option;
    uint32_t time = 10;
    BrPending it;
    ConnBrPendInfo pendInfo;

    SoftBusMutexInit(&g_brManager.pendings->lock, nullptr);
    option.type = CONNECT_BR;
    (void)strcpy_s(option.brOption.brMac, BT_MAC_LEN, "abc");
    ListInit(&g_brManager.pendings->list);
    ListInit(&g_brManager.connections->list);
    (void)strcpy_s(pendInfo.addr, BT_MAC_LEN, "abce");
    it.pendInfo = &pendInfo;
    ListTailInsert(&g_brManager.pendings->list, &it.node);
    g_brManagerAsyncHandler.handler.looper->PostMessageDelay = PostMessageDelay;
    ret = BrPendConnection(&option, time);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager039, TestSize.Level1)
{
    NiceMock<ConnectionBrInterfaceMock> brMock;

    EXPECT_CALL(brMock, SoftBusGetBtMacAddr).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    DumpLocalBtMac();

    EXPECT_CALL(brMock, SoftBusGetBtMacAddr).WillRepeatedly(Return(SOFTBUS_OK));
    DumpLocalBtMac();
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager040, TestSize.Level1)
{
    int32_t listenerId = 0;
    int32_t state = SOFTBUS_BR_STATE_TURN_ON;
    NiceMock<ConnectionBrInterfaceMock> brMock;

    EXPECT_CALL(brMock, SoftBusGetBtMacAddr).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    OnBtStateChanged(listenerId, state);

    state = SOFTBUS_BR_STATE_TURN_OFF;
    OnBtStateChanged(listenerId, state);
}

HWTEST_F(ConnectionBrConnectionTest, testBrManager041, TestSize.Level1)
{
    const char *addr = "11:22:33:44:55:66";
    InitBrManager();
    ConnBrConnection *connection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, -1);
    ASSERT_TRUE(connection != NULL);
    int32_t ret = ConnBrSaveConnection(connection);
    EXPECT_EQ(SOFTBUS_OK, ret);
    int32_t error = SOFTBUS_CONN_BR_UNDERLAY_CONNECT_FAIL;
    bool isWait = IsNeedWaitCallbackError(connection->connectionId, &error);
    EXPECT_EQ(true, isWait);

    BrUnderlayerStatus *callbackStatus = (BrUnderlayerStatus *)SoftBusCalloc(sizeof(BrUnderlayerStatus));
    ASSERT_NE(nullptr, callbackStatus);
    ASSERT_TRUE(callbackStatus != NULL);
    ListInit(&callbackStatus->node);
    callbackStatus->status = 0;
    callbackStatus->result = 4;
    ListAdd(&connection->connectProcessStatus->list, &callbackStatus->node);
    isWait = IsNeedWaitCallbackError(connection->connectionId, &error);
    EXPECT_EQ(false, isWait);

    BrUnderlayerStatus *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &connection->connectProcessStatus->list, BrUnderlayerStatus, node) {
        if (it->result == 4) {
            it->result = CONN_BR_CONNECT_UNDERLAYER_ERROR_UNDEFINED + 1;
        }
    }
    isWait = IsNeedWaitCallbackError(connection->connectionId, &error);
    EXPECT_EQ(true, isWait);
}

HWTEST_F(ConnectionBrConnectionTest, BrReuseConnection, TestSize.Level1)
{
    const char *mac = "11:22:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(mac, CONN_SIDE_CLIENT, 1);
    ASSERT_NE(nullptr, connection);
    connection->state = BR_CONNECTION_STATE_CONNECTED;
    ASSERT_EQ(SOFTBUS_OK, ConnBrSaveConnection(connection));
    ConnectCallback callback = {
        .OnConnected = OnConnected,
        .OnReusedConnected = OnReusedConnected,
        .OnDisconnected = OnDisconnected,
        .OnDataReceived = OnDataReceived,
    };
    ClientConnected(1);
    ConnectFuncInterface *bleInterface = ConnInitBle(&callback);
    ASSERT_NE(nullptr, bleInterface);

    ConnBrDevice device = {
        .bleKeepAliveInfo.keepAliveBleConnectionId = 1,
        .bleKeepAliveInfo.keepAliveBleRequestId = 1,
    };
    EXPECT_EQ(EOK, memcpy_s(device.addr, BT_MAC_LEN, mac, BT_MAC_LEN));
    bool ret = BrReuseConnection(&device, connection);
    EXPECT_EQ(true, ret);
    ServerAccepted(1);
    ConnBrDevice *device1 = (ConnBrDevice *)SoftBusCalloc(sizeof(ConnBrDevice));
    ASSERT_NE(nullptr, device1);
    ClientConnectFailed(1, SOFTBUS_CONN_BR_INTERNAL_ERR);
    EXPECT_EQ(EOK, memcpy_s(device1->addr, BT_MAC_LEN, mac, BT_MAC_LEN));
    AttempReuseConnect(device1, ConnectDeviceDirectly);
}

HWTEST_F(ConnectionBrConnectionTest, BrOnOccupyRelease, TestSize.Level1)
{
    InitBrManager();
    const char *mac = "11:00:33:44:55:66";
    ConnBrConnection *connection = ConnBrCreateConnection(mac, CONN_SIDE_CLIENT, 1);
    ASSERT_NE(nullptr, connection);
    connection->isOccupied = true;
    int32_t ret = ConnBrSaveConnection(connection);
    ASSERT_EQ(SOFTBUS_OK, ret);

    SoftBusMessage msg = {
        .what = MSG_CONNECTION_OCCUPY_RELEASE,
        .arg1 = connection->connectionId,
    };
    BrConnectionMsgHandler(&msg);
    msg.what = MSG_CONNECTION_UPDATE_PEER_RC + 1;
    BrConnectionMsgHandler(&msg);
    EXPECT_EQ(false, connection->isOccupied);

    connection->state = BR_CONNECTION_STATE_EXCEPTION;
    ret = ConnBrSaveConnection(connection);
    ASSERT_EQ(SOFTBUS_OK, ret);
}

HWTEST_F(ConnectionBrConnectionTest, WaitNegotiationClosingTimeoutHandler, TestSize.Level1)
{
    InitBrManager();
    const char *mac = "11:00:33:44:55:77";
    ConnBrConnection *connection = ConnBrCreateConnection(mac, CONN_SIDE_CLIENT, 0);
    ASSERT_NE(nullptr, connection);
    connection->state = BR_CONNECTION_STATE_EXCEPTION;
    int32_t ret = ConnBrSaveConnection(connection);
    ASSERT_EQ(SOFTBUS_OK, ret);
    WaitNegotiationClosingTimeoutHandler(connection->connectionId);

    const char *addr = "11:00:33:44:55:22";
    ConnBrConnection *brConnection = ConnBrCreateConnection(addr, CONN_SIDE_CLIENT, 0);
    ASSERT_NE(nullptr, brConnection);
    brConnection->state = BR_CONNECTION_STATE_NEGOTIATION_CLOSING;
    brConnection->socketHandle = INVALID_SOCKET_HANDLE;
    ret = ConnBrSaveConnection(brConnection);
    ASSERT_EQ(SOFTBUS_OK, ret);
    WaitNegotiationClosingTimeoutHandler(brConnection->connectionId);
    EXPECT_EQ(BR_CONNECTION_STATE_CLOSED, brConnection->state);
}
} // namespace OHOS
