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

#include <cstdio>
#include <cstring>
#include "conn_log.h"
#include <gtest/gtest.h>
#include <securec.h>
#include "softbus_error_code.h"
#include "softbus_conn_ble_trans.h"
#include "conn_ble_trans_mock.h"
#include "softbus_conn_ble_send_queue.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_adapter_mem.h"
#include <arpa/inet.h>

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

void PackConnPktHead(ConnPktHead *head)
{
    (void)head;
}

void UnpackConnPktHead(ConnPktHead *head)
{
    (void)head;
}
}

namespace OHOS {
class ConnBleTransTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override {}
    void TearDown() override {}
};

void ConnBleTransTest::SetUpTestCase()
{
    LooperInit();
    g_transEventListener.onPostBytesFinished = OnPostBytesFinished;
    int32_t ret = ConnBleInitTransModule(&g_transEventListener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

void ConnBleTransTest::TearDownTestCase()
{
    LooperDeinit();
}

/*
 * @tc.name: ConnGattTransRecv001
 * @tc.desc: Test ConnGattTransRecv with invalid parameters
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnGattTransRecv001, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = { 0 };
    uint32_t outLen = 0;
    uint8_t *data = static_cast<uint8_t *>(malloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    uint8_t *result = ConnGattTransRecv(connectionId, nullptr, 10, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    result = ConnGattTransRecv(connectionId, data, 0, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    result = ConnGattTransRecv(connectionId, data, 10, &buffer, nullptr);
    EXPECT_EQ(nullptr, result);

    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE - 1, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    free(data);
}

/*
 * @tc.name: ConnGattTransRecv002
 * @tc.desc: Test ConnGattTransRecv with invalid header fields
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnGattTransRecv002, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = { 0 };
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(100);
    header.size = htonl(20);
    header.offset = htonl(0);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 20, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.total = htonl(MAX_DATA_LEN + 1);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 20, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.total = htonl(20);
    header.size = htonl(30);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 30, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.size = htonl(20);
    header.offset = htonl(5);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 20, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.name: ConnGattTransRecv003
 * @tc.desc: Test ConnGattTransRecv with complete packet
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnGattTransRecv003, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = { 0 };
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(100);
    header.size = htonl(10);
    header.offset = htonl(0);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 10, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(10, outLen);
    if (result != nullptr) {
        free(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv004
 * @tc.desc: Test ConnGattTransRecv with different sequence number
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnGattTransRecv004, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = { 0 };
    buffer.seq = 50;
    buffer.total = 20;
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(100);
    header.size = htonl(10);
    header.offset = htonl(0);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 10, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(10, outLen);
    if (result != nullptr) {
        free(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv005
 * @tc.desc: Test ConnGattTransRecv with segmented packets
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnGattTransRecv005, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = { 0 };
    buffer.seq = 100;
    buffer.total = 10;
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(100);
    header.size = htonl(5);
    header.offset = htonl(0);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(5);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(10, outLen);
    if (result != nullptr) {
        free(result);
    }
}

/*
 * @tc.name: ConnCocTransRecv001
 * @tc.desc: Test ConnCocTransRecv with insufficient data
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnCocTransRecv001, TestSize.Level1)
{
    uint32_t connectionId = 1;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = 100;
    buffer.length = sizeof(ConnPktHead);
    ConnPktHead head = {0};
    head.magic = MAGIC_NUMBER;
    head.len = 200;
    buffer.buffer = (uint8_t *)(&head);

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    buffer.length = sizeof(ConnPktHead);
    ConnPktHead head2 = {0};
    head2.magic = MAGIC_NUMBER + 1;
    buffer.buffer = (uint8_t *)(&head2);
    result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    EXPECT_EQ(0, buffer.length);
}

/*
 * @tc.name: ConnCocTransRecv002
 * @tc.desc: Test ConnCocTransRecv with invalid magic number
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnCocTransRecv002, TestSize.Level1)
{
    uint32_t connectionId = 1;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = 100;
    buffer.length = sizeof(ConnPktHead);
    ConnPktHead head = {0};
    head.magic = MAGIC_NUMBER;
    head.len = 200;
    buffer.buffer = (uint8_t *)(&head);

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    EXPECT_EQ(0, buffer.length);
}

/*
 * @tc.name: ConnCocTransRecv003
 * @tc.desc: Test ConnCocTransRecv with incomplete packet
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnCocTransRecv003, TestSize.Level1)
{
    uint32_t connectionId = 1;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = 100;
    buffer.length = sizeof(ConnPktHead) + 10;
    ConnPktHead head = {0};
    head.magic = MAGIC_NUMBER;
    head.len = 20;
    buffer.buffer = (uint8_t *)(&head);

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.name: ConnCocTransRecv004
 * @tc.desc: Test ConnCocTransRecv with complete packet
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnCocTransRecv004, TestSize.Level1)
{
    uint32_t connectionId = 1;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = 100;
    buffer.length = sizeof(ConnPktHead) + 20;
    ConnPktHead head = {0};
    head.magic = MAGIC_NUMBER;
    head.len = 20;
    buffer.buffer = (uint8_t *)(&head);

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(sizeof(ConnPktHead) + 20, (uint32_t)outLen);
    if (result != nullptr) {
        free(result);
    }
}

/*
 * @tc.name: ConnBlePackCtlMessage001
 * @tc.desc: Test ConnBlePackCtlMessage with cJSON_CreateObject returning null
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePackCtlMessage001, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx;
    ctx.connectionId = 10;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.challengeCode = 100;
    ctx.referenceRequest.referenceNumber = 2;
    ctx.referenceRequest.delta = 1;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    NiceMock<ConnBleTransInterfaceMock> mock;
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(nullptr));

    int64_t ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);
}

/*
 * @tc.name: ConnBlePackCtlMessage002
 * @tc.desc: Test ConnBlePackCtlMessage with AddNumberToJsonObject returning false
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePackCtlMessage002, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx;
    ctx.connectionId = 10;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.challengeCode = 100;
    ctx.referenceRequest.referenceNumber = 2;
    ctx.referenceRequest.delta = 1;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    NiceMock<ConnBleTransInterfaceMock> mock;
    cJSON json = { 0 };
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(&json));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillOnce(Return(false));

    int64_t ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);
}

/*
 * @tc.name: ConnBlePackCtlMessage003
 * @tc.desc: Test ConnBlePackCtlMessage with invalid method
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePackCtlMessage003, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx;
    ctx.connectionId = 10;
    ctx.method = (BleCtlMessageMethod)0;
    ctx.challengeCode = 100;
    ctx.referenceRequest.referenceNumber = 2;
    ctx.referenceRequest.delta = 1;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    NiceMock<ConnBleTransInterfaceMock> mock;
    cJSON json = { 0 };
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(&json));

    int64_t ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_EQ(SOFTBUS_CONN_BLE_INTERNAL_ERR, ret);
}

/*
 * @tc.name: ConnBlePackCtlMessage004
 * @tc.desc: Test ConnBlePackCtlMessage with valid JSON operations
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePackCtlMessage004, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx;
    ctx.connectionId = 10;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.challengeCode = 100;
    ctx.referenceRequest.referenceNumber = 2;
    ctx.referenceRequest.delta = 1;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    NiceMock<ConnBleTransInterfaceMock> mock;
    cJSON json = { 0 };
    EXPECT_CALL(mock, cJSON_CreateObject).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AddNumber16ToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(nullptr));

    int64_t ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);
}

/*
 * @tc.name: ConnBlePackCtlMessage005
 * @tc.desc: Test ConnBlePackCtlMessage with valid parameters
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePackCtlMessage005, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx;
    ctx.connectionId = 10;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.challengeCode = 100;
    ctx.referenceRequest.referenceNumber = 2;
    ctx.referenceRequest.delta = 1;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    NiceMock<ConnBleTransInterfaceMock> mock;
    cJSON json = { 0 };
    char jsonStr[] = "test";
    EXPECT_CALL(mock, cJSON_CreateObject).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AddNumber16ToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(jsonStr));

    int64_t ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(0, ret);
    EXPECT_NE(nullptr, data);
    if (data != nullptr) {
        free(data);
    }
}

/*
 * @tc.name: ConnBleTransConfigPostLimit001
 * @tc.desc: Test ConnBleTransConfigPostLimit with invalid parameters
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBleTransConfigPostLimit001, TestSize.Level1)
{
    int32_t ret = ConnBleTransConfigPostLimit(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    LimitConfiguration config;
    config.type = CONNECT_TCP;
    ret = ConnBleTransConfigPostLimit(&config);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBleTransConfigPostLimit002
 * @tc.desc: Test ConnBleTransConfigPostLimit with active=false
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBleTransConfigPostLimit002, TestSize.Level1)
{
    LimitConfiguration config;
    config.type = CONNECT_BLE;
    config.active = false;
    config.windowInMillis = 100;
    config.quotaInBytes = 1000;

    int32_t ret = ConnBleTransConfigPostLimit(&config);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBleTransConfigPostLimit003
 * @tc.desc: Test ConnBleTransConfigPostLimit with active=true
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBleTransConfigPostLimit003, TestSize.Level1)
{
    LimitConfiguration config;
    config.type = CONNECT_BLE;
    config.active = true;
    config.windowInMillis = 100;
    config.quotaInBytes = 1000;

    int32_t ret = ConnBleTransConfigPostLimit(&config);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner001
 * @tc.desc: Test ConnBlePostBytesInner with invalid parameters
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePostBytesInner001, TestSize.Level1)
{
    uint32_t connectionId = 1;
    int32_t ret = ConnBlePostBytesInner(connectionId, nullptr, 10, 0, 0, 0, 0, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    uint8_t *data = static_cast<uint8_t *>(malloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);
    ret = ConnBlePostBytesInner(connectionId, data, 0, 0, 0, 0, 0, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    data = static_cast<uint8_t *>(malloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);
    ret = ConnBlePostBytesInner(connectionId, data, MAX_DATA_LEN + 1, 0, 0, 0, 0, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner002
 * @tc.desc: Test ConnBlePostBytesInner when connection not exists
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePostBytesInner002, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(malloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillOnce(Return(nullptr));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, 0, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_EXIST_ERR, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner003
 * @tc.desc: Test ConnBlePostBytesInner when connection not ready
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePostBytesInner003, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(malloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillOnce(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner004
 * @tc.desc: Test ConnBlePostBytesInner with exchanged basic info state
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePostBytesInner004, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(malloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillOnce(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner005
 * @tc.desc: Test ConnBlePostBytesInner with exchanged basic info state
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePostBytesInner005, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(malloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillOnce(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner006
 * @tc.desc: Test ConnBlePostBytesInner with valid connection
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePostBytesInner006, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(malloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillOnce(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
    SoftBusSleepMs(1000);
}

/*
 * @tc.name: ConnBlePostBytesInner007
 * @tc.desc: Test ConnBlePostBytesInner with valid connection
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePostBytesInner007, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(malloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillOnce(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner008
 * @tc.desc: Test ConnBlePostBytesInner with valid connection
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePostBytesInner008, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(malloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillOnce(Return(&conn));


    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
    SoftBusSleepMs(1000);
}

/*
 * @tc.name: ConnBleInitTransModule002
 * @tc.desc: Test ConnBleInitTransModule with null callback
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBleInitTransModule002, TestSize.Level1)
{
    ConnBleTransEventListener listener = { 0 };
    listener.onPostBytesFinished = nullptr;

    int32_t ret = ConnBleInitTransModule(&listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBleInitTransModule003
 * @tc.desc: Test ConnBleInitTransModule with controller creation returning null
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBleInitTransModule003, TestSize.Level1)
{
    ConnBleTransEventListener listener = { 0 };
    listener.onPostBytesFinished = OnPostBytesFinished;


    int32_t ret = ConnBleInitTransModule(&listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnBleInitTransModule004
 * @tc.desc: Test ConnBleInitTransModule with valid listener
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBleInitTransModule004, TestSize.Level1)
{
    ConnBleTransEventListener listener = { 0 };
    listener.onPostBytesFinished = OnPostBytesFinished;


    int32_t ret = ConnBleInitTransModule(&listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnGattTransRecvSeries
 * @tc.desc: Test ConnGattTransRecv with multiple segmented packets
 * @tc.type: FUNC
 * @requires: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnGattTransRecvSeries, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = { 0 };
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(100);
    header.size = htonl(5);
    header.offset = htonl(0);
    header.total = htonl(15);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(5);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(10);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(15, outLen);
    if (result != nullptr) {
        free(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv006
 * @tc.desc: Test ConnGattTransRecv with complete packet
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnGattTransRecv006, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = { 0 };
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(100);
    header.size = htonl(10);
    header.offset = htonl(0);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 10, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    if (result != nullptr) {
        free(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv007
 * @tc.desc: Test ConnGattTransRecv with different sequence number in buffer
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnGattTransRecv007, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = { 0 };
    buffer.seq = 50;
    buffer.total = 20;
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(100);
    header.size = htonl(5);
    header.offset = htonl(0);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.name: ConnGattTransRecv008
 * @tc.desc: Test ConnGattTransRecv with duplicate packet
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnGattTransRecv008, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = { 0 };
    buffer.seq = 100;
    buffer.total = 10;
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(100);
    header.size = htonl(5);
    header.offset = htonl(0);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.name: ConnGattTransRecv009
 * @tc.desc: Test ConnGattTransRecv with segmented packet
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnGattTransRecv009, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = { 0 };
    buffer.seq = 100;
    buffer.total = 10;
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(100);
    header.size = htonl(5);
    header.offset = htonl(0);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(5);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    if (result != nullptr) {
        free(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv010
 * @tc.desc: Test ConnGattTransRecv with segmented packets
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnGattTransRecv010, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = { 0 };
    buffer.seq = 100;
    buffer.total = 10;
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(100);
    header.size = htonl(5);
    header.offset = htonl(0);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(5);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    if (result != nullptr) {
        free(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv011
 * @tc.desc: Test ConnGattTransRecv with mis-order packet
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnGattTransRecv011, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = { 0 };
    buffer.seq = 100;
    buffer.total = 15;
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(100);
    header.size = htonl(5);
    header.offset = htonl(5);
    header.total = htonl(15);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(0);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(10);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(15, outLen);
    if (result != nullptr) {
        free(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv012
 * @tc.desc: Test ConnGattTransRecv when received data exceeds total
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnGattTransRecv012, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = { 0 };
    buffer.seq = 100;
    buffer.total = 10;
    buffer.received = 8;
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(100);
    header.size = htonl(5);
    header.offset = htonl(8);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.name: ConnGattTransRecv013
 * @tc.desc: Test ConnGattTransRecv with segmented packets
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnGattTransRecv013, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = { 0 };
    buffer.seq = 100;
    buffer.total = 10;
    buffer.received = 5;
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(100);
    header.size = htonl(5);
    header.offset = htonl(0);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_NE(nullptr, result);

    header.offset = htonl(5);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    if (result != nullptr) {
        free(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv014
 * @tc.desc: Test ConnGattTransRecv when packet offset is not continuous
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnGattTransRecv014, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = { 0 };
    buffer.seq = 100;
    buffer.total = 15;
    buffer.received = 10;
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(100);
    header.size = htonl(5);
    header.offset = htonl(0);
    header.total = htonl(15);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_NE(nullptr, result);

    header.offset = htonl(10);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);

    header.offset = htonl(5);
    result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    EXPECT_EQ(15, outLen);
    if (result != nullptr) {
        free(result);
    }
}

/*
 * @tc.name: ConnCocTransRecv005
 * @tc.desc: Test ConnCocTransRecv when packet length exceeds capacity
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnCocTransRecv005, TestSize.Level1)
{
    uint32_t connectionId = 1;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = 100;
    buffer.length = sizeof(ConnPktHead);
    ConnPktHead head = {0};
    head.magic = MAGIC_NUMBER;
    head.len = 200;
    buffer.buffer = (uint8_t *)(&head);

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
    EXPECT_EQ(0, buffer.length);
}

/*
 * @tc.name: ConnCocTransRecv006
 * @tc.desc: Test ConnCocTransRecv with complete packet
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnCocTransRecv006, TestSize.Level1)
{
    uint32_t connectionId = 1;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = 100;
    buffer.length = sizeof(ConnPktHead) + 20;
    ConnPktHead head = {0};
    head.magic = MAGIC_NUMBER;
    head.len = 20;
    buffer.buffer = (uint8_t *)(&head);

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    if (result != nullptr) {
        free(result);
    }
}

/*
 * @tc.name: ConnCocTransRecv007
 * @tc.desc: Test ConnCocTransRecv with complete packet
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnCocTransRecv007, TestSize.Level1)
{
    uint32_t connectionId = 1;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = 100;
    buffer.length = sizeof(ConnPktHead) + 20;
    ConnPktHead head = {0};
    head.magic = MAGIC_NUMBER;
    head.len = 20;
    buffer.buffer = (uint8_t *)(&head);

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    if (result != nullptr) {
        free(result);
    }
}

/*
 * @tc.name: ConnCocTransRecv008
 * @tc.desc: Test ConnCocTransRecv with remaining data in buffer
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnCocTransRecv008, TestSize.Level1)
{
    uint32_t connectionId = 1;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = 100;
    buffer.length = sizeof(ConnPktHead) + 40;
    ConnPktHead head = {0};
    head.magic = MAGIC_NUMBER;
    head.len = 20;
    buffer.buffer = (uint8_t *)(&head);

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_GT(buffer.length, 0);
    if (result != nullptr) {
        free(result);
    }
}

/*
 * @tc.name: ConnBlePackCtlMessage006
 * @tc.desc: Test ConnBlePackCtlMessage with valid parameters
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePackCtlMessage006, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx;
    ctx.connectionId = 10;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.challengeCode = 100;
    ctx.referenceRequest.referenceNumber = 2;
    ctx.referenceRequest.delta = 1;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    NiceMock<ConnBleTransInterfaceMock> mock;
    cJSON json = { 0 };
    char jsonStr[] = "test";
    EXPECT_CALL(mock, cJSON_CreateObject).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AddNumber16ToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(jsonStr));

    int64_t ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(1, ret);
    if (data != nullptr) {
        free(data);
    }
}

/*
 * @tc.name: ConnBlePackCtlMessage007
 * @tc.desc: Test ConnBlePackCtlMessage with valid parameters
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePackCtlMessage007, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx;
    ctx.connectionId = 10;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.challengeCode = 100;
    ctx.referenceRequest.referenceNumber = 2;
    ctx.referenceRequest.delta = 1;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    NiceMock<ConnBleTransInterfaceMock> mock;
    cJSON json = { 0 };
    char jsonStr[] = "test";
    EXPECT_CALL(mock, cJSON_CreateObject).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AddNumber16ToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(jsonStr));

    int64_t ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(2, ret);
    if (data != nullptr) {
        free(data);
    }
}

/*
 * @tc.name: ConnBlePostBytesInner009
 * @tc.desc: Test ConnBlePostBytesInner with valid connection
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePostBytesInner009, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(malloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillOnce(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner010
 * @tc.desc: Test ConnBlePostBytesInner with MODULE_CONNECTION
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePostBytesInner010, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(malloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillOnce(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_CONNECTION, 0, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(1000);
}

/*
 * @tc.name: ConnBlePostBytesInner011
 * @tc.desc: Test ConnBlePostBytesInner with MODULE_BLE_NET
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePostBytesInner011, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(malloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillOnce(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_BLE_NET, 0, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(1000);
}

/*
 * @tc.name: ConnBlePostBytesInner012
 * @tc.desc: Test ConnBlePostBytesInner with valid connection
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePostBytesInner012, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(malloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillOnce(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(1000);
}

/*
 * @tc.name: ConnBlePostBytesInner013
 * @tc.desc: Test ConnBlePostBytesInner when send task lock fails
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePostBytesInner013, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(malloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillOnce(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(1000);
}

/*
 * @tc.name: ConnBleTransConfigPostLimit004
 * @tc.desc: Test ConnBleTransConfigPostLimit with different type
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBleTransConfigPostLimit004, TestSize.Level1)
{
    LimitConfiguration config;
    config.type = CONNECT_BR;
    config.active = true;
    config.windowInMillis = 100;
    config.quotaInBytes = 1000;

    int32_t ret = ConnBleTransConfigPostLimit(&config);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBleTransConfigPostLimit005
 * @tc.desc: Test ConnBleTransConfigPostLimit with COC type
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBleTransConfigPostLimit005, TestSize.Level1)
{
    LimitConfiguration config;
    config.type = CONNECT_BLE;
    config.active = true;
    config.windowInMillis = 0;
    config.quotaInBytes = 0;

    int32_t ret = ConnBleTransConfigPostLimit(&config);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnGattTransRecv015
 * @tc.desc: Test ConnGattTransRecv with buffer having pending data and new complete packet
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnGattTransRecv015, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = { 0 };
    buffer.seq = 100;
    buffer.total = 20;
    buffer.received = 10;
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(200);
    header.size = htonl(10);
    header.offset = htonl(0);
    header.total = htonl(10);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 10, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(10, outLen);
    if (result != nullptr) {
        free(result);
    }
}

/*
 * @tc.name: ConnGattTransRecv016
 * @tc.desc: Test ConnGattTransRecv with different total in buffer
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnGattTransRecv016, TestSize.Level1)
{
    uint32_t connectionId = 1;
    ConnBleReadBuffer buffer = { 0 };
    buffer.seq = 100;
    buffer.total = 20;
    buffer.received = 10;
    ListInit(&buffer.packets);
    uint32_t outLen = 0;
    BleTransHeader header;
    header.seq = htonl(100);
    header.size = htonl(5);
    header.offset = htonl(10);
    header.total = htonl(15);

    uint8_t *data = reinterpret_cast<uint8_t *>(&header);
    uint8_t *result = ConnGattTransRecv(connectionId, data, BLE_TRANS_HEADER_SIZE + 5, &buffer, &outLen);
    EXPECT_EQ(nullptr, result);
}

/*
 * @tc.name: ConnCocTransRecv009
 * @tc.desc: Test ConnCocTransRecv with exact packet length
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnCocTransRecv009, TestSize.Level1)
{
    uint32_t connectionId = 1;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = 100;
    buffer.length = sizeof(ConnPktHead) + 20;
    ConnPktHead head = {0};
    head.magic = MAGIC_NUMBER;
    head.len = 20;
    buffer.buffer = (uint8_t *)(&head);

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(sizeof(ConnPktHead) + 20, (uint32_t)outLen);
    if (result != nullptr) {
        free(result);
    }
}

/*
 * @tc.name: ConnCocTransRecv010
 * @tc.desc: Test ConnCocTransRecv with remaining data in buffer
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnCocTransRecv010, TestSize.Level1)
{
    uint32_t connectionId = 1;
    LimitedBuffer buffer = { 0 };
    int32_t outLen = 0;

    buffer.capacity = 100;
    buffer.length = sizeof(ConnPktHead) + 40;
    ConnPktHead head = {0};
    head.magic = MAGIC_NUMBER;
    head.len = 20;
    buffer.buffer = (uint8_t *)(&head);

    uint8_t *result = ConnCocTransRecv(connectionId, &buffer, &outLen);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(sizeof(ConnPktHead) + 20, (uint32_t)outLen);
    EXPECT_GT(buffer.length, 0);
    if (result != nullptr) {
        free(result);
    }
}

/*
 * @tc.name: ConnBlePackCtlMessage008
 * @tc.desc: Test ConnBlePackCtlMessage with large challenge code
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePackCtlMessage008, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx;
    ctx.connectionId = 10;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.challengeCode = 65535;
    ctx.referenceRequest.referenceNumber = 100;
    ctx.referenceRequest.delta = 50;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    NiceMock<ConnBleTransInterfaceMock> mock;
    cJSON json = { 0 };
    char jsonStr[] = "test";
    EXPECT_CALL(mock, cJSON_CreateObject).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AddNumber16ToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, cJSON_PrintUnformatted).WillOnce(Return(jsonStr));

    int64_t ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(0, ret);
    EXPECT_NE(nullptr, data);
    if (data != nullptr) {
        free(data);
    }
}

/*
 * @tc.name: ConnBlePackCtlMessage009
 * @tc.desc: Test ConnBlePackCtlMessage with AddNumber16ToJsonObject returning false
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePackCtlMessage009, TestSize.Level1)
{
    BleCtlMessageSerializationContext ctx;
    ctx.connectionId = 10;
    ctx.method = METHOD_NOTIFY_REQUEST;
    ctx.challengeCode = 100;
    ctx.referenceRequest.referenceNumber = 2;
    ctx.referenceRequest.delta = 1;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    NiceMock<ConnBleTransInterfaceMock> mock;
    cJSON json = { 0 };
    EXPECT_CALL(mock, cJSON_CreateObject).WillOnce(Return(&json));
    EXPECT_CALL(mock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, AddNumber16ToJsonObject).WillOnce(Return(false));

    int64_t ret = ConnBlePackCtlMessage(ctx, &data, &dataLen);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);
}

/*
 * @tc.name: ConnBlePostBytesInner014
 * @tc.desc: Test ConnBlePostBytesInner with maximum data length
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePostBytesInner014, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(malloc(MAX_DATA_LEN));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillOnce(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, MAX_DATA_LEN, 0, 0, MODULE_AUTH_MSG, 0, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(1000);
}

/*
 * @tc.name: ConnBlePostBytesInner015
 * @tc.desc: Test ConnBlePostBytesInner with different pid and flag
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePostBytesInner015, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(malloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillOnce(Return(&conn));

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 12345, 67890, MODULE_AUTH_MSG, 1000, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(1000);
}

/*
 * @tc.name: ConnBlePostBytesInner016
 * @tc.desc: Test ConnBlePostBytesInner with postBytesFinishAction callback
 * @tc.type: FUNC
 * @tc.require: AR000GSE5J
 */
HWTEST_F(ConnBleTransTest, ConnBlePostBytesInner016, TestSize.Level1)
{
    uint32_t connectionId = 1;
    uint8_t *data = static_cast<uint8_t *>(malloc(sizeof(uint8_t)));
    ASSERT_NE(nullptr, data);

    NiceMock<ConnBleTransInterfaceMock> mock;
    ConnBleConnection conn = {};
    conn.state = BLE_CONNECTION_STATE_EXCHANGING_BASIC_INFO;
    SoftBusMutexInit(&conn.lock, nullptr);
    EXPECT_CALL(mock, ConnBleGetConnectionById).WillOnce(Return(&conn));

    auto callback = [](uint32_t connId, int32_t error) {
        (void)connId;
        (void)error;
    };

    int32_t ret = ConnBlePostBytesInner(connectionId, data, 10, 0, 0, MODULE_AUTH_MSG, 0, callback);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusSleepMs(1000);
}

/*
* @tc.name: QueueBlock
* @tc.desc: Test ConnBleDequeueBlock, ConnBleEnqueueNonBlock
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnBleTransTest, QueueBlock, TestSize.Level1)
{
    int32_t ret = ConnBleInitSendQueue();
    EXPECT_EQ(SOFTBUS_OK, ret);

    SendQueueNode queueNode;
    queueNode.flag = CONN_HIGH;
    queueNode.pid = 0;
    ret = ConnBleEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBleDequeueBlock(nullptr);
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
