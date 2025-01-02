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

#include <cstdio>
#include <cstring>
#include "conn_log.h"
#include <gtest/gtest.h>
#include <securec.h>
#include "softbus_error_code.h"
#include "softbus_conn_ble_trans.h"
#include "softbus_conn_ble_trans_mock.h"
#include "softbus_conn_ble_send_queue.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_adapter_mem.h"

using namespace testing::ext;
using namespace testing;
static ConnBleTransEventListener g_transEventListener = { 0 };
static const size_t BLE_TRANS_HEADER_SIZE = sizeof(BleTransHeader);
void OnPostBytesFinished(
    uint32_t connectionId, uint32_t len, int32_t pid, int32_t flag, int32_t module, int64_t seq, int32_t error)
{
    (void)connectionId;
    (void)len;
    (void)pid;
    (void)flag;
    (void)module;
    (void)seq;
    (void)error;
}

extern "C" {
void ConnBleReturnConnection(ConnBleConnection **connection)
{
    (void)connection;
}

void cJSON_Delete(cJSON *json)
{
    (void)json;
}

void cJSON_free(void *object)
{
    (void)object;
}

void ConnBleRefreshIdleTimeout(ConnBleConnection *connection)
{
    (void)connection;
}
}
namespace OHOS {
class ConnectionBleTransTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override {}
    void TearDown() override {}
};

void ConnectionBleTransTest::SetUpTestCase()
{
    LooperInit();
    g_transEventListener.onPostBytesFinished = OnPostBytesFinished;
    int32_t ret = ConnBleInitTransModule(&g_transEventListener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

void ConnectionBleTransTest::TearDownTestCase()
{
    LooperDeinit();
}

/*
* @tc.name: TransRecv
* @tc.desc: Test ConnCocTransRecv.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTransTest, TransRecv, TestSize.Level1)
{
    uint32_t connectionId = 1;
    LimitedBuffer buffer = {0};
    int32_t *outLen = nullptr;
    uint8_t *data = nullptr;

    ConnPktHead head = {0};
    head.magic = MAGIC_NUMBER + 1;
    head.len = sizeof(ConnPktHead);
    buffer.capacity = 140;
    buffer.length = sizeof(ConnPktHead) - 1;
    buffer.buffer = (uint8_t *)(&head);
    outLen = (int32_t *)SoftBusCalloc(sizeof(ConnPktHead));
    ASSERT_NE(nullptr, outLen);
    data = ConnCocTransRecv(connectionId, &buffer, outLen);
    EXPECT_EQ(nullptr, data);

    buffer.length = sizeof(ConnPktHead);
    data = ConnCocTransRecv(connectionId, &buffer, outLen);
    EXPECT_EQ(nullptr, data);

    head.magic = MAGIC_NUMBER;
    buffer.capacity = sizeof(ConnPktHead) + sizeof(ConnPktHead) - 1;
    buffer.length = sizeof(ConnPktHead) + 1;
    data = ConnCocTransRecv(connectionId, &buffer, outLen);
    EXPECT_EQ(nullptr, data);

    buffer.length = sizeof(ConnPktHead) + 1;
    buffer.capacity = sizeof(ConnPktHead) + sizeof(ConnPktHead) + 1;
    data = ConnCocTransRecv(connectionId, &buffer, outLen);
    EXPECT_EQ(nullptr, data);

    buffer.length = head.len + sizeof(ConnPktHead) + 1;
    buffer.capacity = sizeof(ConnPktHead) + sizeof(ConnPktHead) + 1;
    data = ConnCocTransRecv(connectionId, &buffer, outLen);
    EXPECT_NE(nullptr, data);
}

/*
* @tc.name: TransPackMsg
* @tc.desc: Test ConnBlePackCtlMessage.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTransTest, TransPackMsg, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx;
    ctx.connectionId = 10;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.challengeCode = 0;
    ctx.referenceRequest.referenceNumber = 2;
    ctx.referenceRequest.delta = 1;
    uint8_t *data = NULL;
    uint32_t dataLen = 0;
    NiceMock<ConnectionBleTransInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, cJSON_CreateObject).WillOnce(Return(nullptr));
    int64_t ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);

    cJSON json = {0};
    EXPECT_CALL(bleMock, cJSON_CreateObject).WillOnce(Return(&json));
    EXPECT_CALL(bleMock, AddNumberToJsonObject).WillOnce(Return(false));
    ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);

    EXPECT_CALL(bleMock, cJSON_CreateObject).WillRepeatedly(Return(&json));
    ctx.method = (BleCtlMessageMethod)0;
    ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_EQ(SOFTBUS_CONN_BLE_INTERNAL_ERR, ret);

    ctx.method = METHOD_NOTIFY_REQUEST;
    EXPECT_CALL(bleMock, cJSON_CreateObject).WillRepeatedly(Return(&json));
    EXPECT_CALL(bleMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(bleMock, AddNumber16ToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(bleMock, cJSON_PrintUnformatted).WillOnce(Return(nullptr));
    ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);

    const char *val = "test001";
    char value[7] = {0};
    strcpy_s(value, sizeof(value), val);
    EXPECT_CALL(bleMock, cJSON_PrintUnformatted).WillOnce(Return(value));
    ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: TransPostBytesInner
* @tc.desc: Test ConnBlePackCtlMessage.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTransTest, TransPostBytesInner, TestSize.Level1)
{
    uint32_t connectionId = 10;
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t));
    uint32_t dataLen = sizeof(uint8_t);
    int32_t pid = 0;
    int32_t flag = 2;
    int32_t module = MODULE_CONNECTION;
    int64_t seq = 10;
    int32_t ret = ConnBlePostBytesInner(connectionId, data, 0, pid, flag, module, seq, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    uint8_t *value = (uint8_t *)malloc(sizeof(uint8_t));
    ret = ConnBlePostBytesInner(connectionId, value, MAX_DATA_LEN + 1, pid, flag, module, seq, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    NiceMock<ConnectionBleTransInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, ConnBleGetConnectionById).WillOnce(Return(nullptr));
    uint8_t *value1 = (uint8_t *)malloc(sizeof(uint8_t));
    ret = ConnBlePostBytesInner(connectionId, value1, dataLen, pid, flag, module, seq, NULL);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_EXIST_ERR, ret);

    ConnBleConnection *connection = (ConnBleConnection *)SoftBusCalloc(sizeof(ConnBleConnection));
    ASSERT_NE(nullptr, connection);
    connection->state = BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO;
    SoftBusMutexInit(&connection->lock, NULL);
    EXPECT_CALL(bleMock, ConnBleGetConnectionById).WillOnce(Return(connection));
    uint8_t *value2 = (uint8_t *)malloc(sizeof(uint8_t));
    ret = ConnBlePostBytesInner(connectionId, value2, dataLen, pid, flag, MODULE_AUTH_MSG, seq, NULL);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);

    uint8_t *value3 = (uint8_t *)malloc(sizeof(uint8_t));
    ConnBleConnection *bleConnectionconnection = (ConnBleConnection *)SoftBusCalloc(sizeof(ConnBleConnection));
    ASSERT_NE(nullptr, connection);
    EXPECT_CALL(bleMock, ConnBleGetConnectionById).WillRepeatedly(Return(bleConnectionconnection));
    SoftBusMutexInit(&bleConnectionconnection->lock, NULL);
    bleConnectionconnection->state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;

    ret = ConnBlePostBytesInner(connectionId, value3, dataLen, pid, flag, MODULE_AUTH_MSG, seq, NULL);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(1000);
}

/*
* @tc.name: GattTransRecv001
* @tc.desc: Test ConnGattTransRecv001.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTransTest, GattTransRecv001, TestSize.Level1)
{
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t));
    uint32_t dataLen = sizeof(uint8_t) + sizeof(BleTransHeader);
    ConnBleReadBuffer buffer;
    uint32_t outLen = 0;
    uint32_t connectionId = 1;
    uint8_t *value = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE - 1, &buffer, &outLen);
    EXPECT_EQ(nullptr, value);

    BleTransHeader tmp;
    tmp.seq = 100000;
    tmp.size = 0x01;
    tmp.offset = 0;
    tmp.total = 0x10;

    data = (uint8_t *)&tmp;
    value = ConnGattTransRecv(connectionId, data, dataLen, &buffer, &outLen);
    EXPECT_EQ(nullptr, value);

    tmp.size = 0x11;
    data = (uint8_t *)&tmp;
    value = ConnGattTransRecv(connectionId, data, dataLen, &buffer, &outLen);
    EXPECT_EQ(nullptr, value);
}

/*
* @tc.name: GattTransRecv002
* @tc.desc: Test ConnGattTransRecv002.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTransTest, GattTransRecv002, TestSize.Level1)
{
    uint8_t *data = (uint8_t *)malloc(sizeof(uint8_t));
    uint32_t dataLen = sizeof(uint8_t) + sizeof(BleTransHeader);
    ConnBleReadBuffer buffer;
    uint32_t outLen = 0;
    uint32_t connectionId = 1;
    uint32_t received[3] = {0, 1000, 1};
    BleTransHeader tmp;
    NiceMock<ConnectionBleTransInterfaceMock> bleMock;
    tmp.seq = 100000;
    tmp.size = dataLen - sizeof(BleTransHeader) + 1;
    tmp.total = tmp.size;
    tmp.offset = tmp.total - tmp.size + 1;
    buffer.seq = 100001;
    buffer.total = tmp.total + 1;
    data = (uint8_t *)&tmp;
    uint8_t *value = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE - 1, &buffer, &outLen);
    EXPECT_EQ(nullptr, value);

    tmp.total = tmp.size + 1;
    data = (uint8_t *)&tmp;
    value = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE - 1, &buffer, &outLen);
    EXPECT_EQ(nullptr, value);

    for (uint32_t i = 0; i < sizeof(received) / sizeof(received[0]); i++) {
        buffer.received = received[i];
        value = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE - 1, &buffer, &outLen);
        EXPECT_EQ(nullptr, value);
    }

    value = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE - 1, &buffer, &outLen);
    EXPECT_EQ(nullptr, value);
}

/*
* @tc.name: ConnBleTransConfigPostLimit
* @tc.desc: Test ConnBleTransConfigPostLimit.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTransTest, ConnBleTransConfigPostLimit, TestSize.Level1)
{
    LimitConfiguration configuration;
    configuration.type = CONNECT_TCP;
    int32_t ret = ConnBleTransConfigPostLimit(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = ConnBleTransConfigPostLimit(&configuration);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    configuration.type = CONNECT_BLE;
    configuration.active = false;
    ret = ConnBleTransConfigPostLimit(&configuration);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);
    configuration.active = true;
    ret = ConnBleTransConfigPostLimit(&configuration);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
* @tc.name: QueueBlock
* @tc.desc: Test ConnBleDequeueBlock, ConnBleEnqueueNonBlock
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTransTest, QueueBlock, TestSize.Level1)
{
    int32_t ret = ConnBleInitSendQueue();
    EXPECT_EQ(SOFTBUS_OK, ret);

    SendQueueNode queueNode;
    queueNode.flag = CONN_HIGH;
    queueNode.pid = 0;
    ret = ConnBleEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBleDequeueBlock(NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    void *msg = nullptr;
    queueNode.flag = CONN_LOW;
    queueNode.pid = 1;
    ret = ConnBleEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ConnBleDequeueBlock(&msg);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ConnBleDeinitSendQueue();
}
}
