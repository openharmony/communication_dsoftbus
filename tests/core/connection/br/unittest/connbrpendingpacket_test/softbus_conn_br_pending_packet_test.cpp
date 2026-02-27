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

#include "softbus_conn_br_pending_packet_mock.h"
#include "softbus_conn_br_pending_packet.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "common_list.h"
#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;
using namespace std;

namespace OHOS {
class ConnBrPendingPacketTest : public testing::Test {
public:
    ConnBrPendingPacketTest() {}
    ~ConnBrPendingPacketTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ConnBrPendingPacketTest::SetUpTestCase(void) {}

void ConnBrPendingPacketTest::TearDownTestCase(void) {}

void ConnBrPendingPacketTest::SetUp(void) {}

void ConnBrPendingPacketTest::TearDown(void) {}

HWTEST_F(ConnBrPendingPacketTest, ConnBrInitBrPendingPacketTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrInitBrPendingPacket, Start");
    int32_t ret = ConnBrInitBrPendingPacket();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnBrCreateBrPendingPacketTest001
 * @tc.desc: test create br pending packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrCreateBrPendingPacketTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrCreateBrPendingPacket001, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 1;
    int64_t seq = 1;
    int32_t ret = ConnBrCreateBrPendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ConnBrDelBrPendingPacket(id, seq);
}

/*
 * @tc.name: ConnBrCreateBrPendingPacketTest002
 * @tc.desc: test create duplicate br pending packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrCreateBrPendingPacketTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrCreateBrPendingPacket002, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 2;
    int64_t seq = 2;
    int32_t ret = ConnBrCreateBrPendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrCreateBrPendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_ALREADY_EXISTED, ret);
    
    ConnBrDelBrPendingPacket(id, seq);
}

/*
 * @tc.name: ConnBrCreateBrPendingPacketTest003
 * @tc.desc: test create br pending packet with different id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrCreateBrPendingPacketTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrCreateBrPendingPacket003, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 3;
    int64_t seq = 3;
    int32_t ret = ConnBrCreateBrPendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrCreateBrPendingPacket(id + 1, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ConnBrDelBrPendingPacket(id, seq);
    ConnBrDelBrPendingPacket(id + 1, seq);
}

/*
 * @tc.name: ConnBrCreateBrPendingPacketTest004
 * @tc.desc: test create br pending packet with different seq
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrCreateBrPendingPacketTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrCreateBrPendingPacket004, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 4;
    int64_t seq = 4;
    int32_t ret = ConnBrCreateBrPendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrCreateBrPendingPacket(id, seq + 1);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ConnBrDelBrPendingPacket(id, seq);
    ConnBrDelBrPendingPacket(id, seq + 1);
}

/*
 * @tc.name: ConnBrDelBrPendingPacketTest001
 * @tc.desc: test delete non-existent br pending packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrDelBrPendingPacketTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrDelBrPendingPacket001, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 5;
    int64_t seq = 5;
    ConnBrDelBrPendingPacket(id, seq);
}

/*
 * @tc.name: ConnBrDelBrPendingPacketTest002
 * @tc.desc: test delete existing br pending packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrDelBrPendingPacketTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrDelBrPendingPacket002, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 6;
    int64_t seq = 6;
    int32_t ret = ConnBrCreateBrPendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ConnBrDelBrPendingPacket(id, seq);
}

/*
 * @tc.name: ConnBrDelBrPendingPacketTest003
 * @tc.desc: test delete br pending packet twice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrDelBrPendingPacketTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrDelBrPendingPacket003, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 7;
    int64_t seq = 7;
    int32_t ret = ConnBrCreateBrPendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ConnBrDelBrPendingPacket(id, seq);
    ConnBrDelBrPendingPacket(id, seq);
}

/*
 * @tc.name: ConnBrDelBrPendingPacketByIdTest001
 * @tc.desc: test delete br pending packet by id with non-existent id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrDelBrPendingPacketByIdTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrDelBrPendingPacketById001, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 8;
    ConnBrDelBrPendingPacketById(id);
}

/*
 * @tc.name: ConnBrDelBrPendingPacketByIdTest002
 * @tc.desc: test delete br pending packet by id with existing id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrDelBrPendingPacketByIdTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrDelBrPendingPacketById002, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 9;
    int64_t seq1 = 9;
    int64_t seq2 = 10;
    int32_t ret = ConnBrCreateBrPendingPacket(id, seq1);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrCreateBrPendingPacket(id, seq2);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ConnBrDelBrPendingPacketById(id);
}

/*
 * @tc.name: ConnBrDelBrPendingPacketByIdTest003
 * @tc.desc: test delete br pending packet by id twice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrDelBrPendingPacketByIdTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrDelBrPendingPacketById003, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 10;
    int64_t seq1 = 11;
    int64_t seq2 = 12;
    int32_t ret = ConnBrCreateBrPendingPacket(id, seq1);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrCreateBrPendingPacket(id, seq2);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ConnBrDelBrPendingPacketById(id);
    ConnBrDelBrPendingPacketById(id);
}

/*
 * @tc.name: ConnBrDelBrPendingPacketByIdTest004
 * @tc.desc: test delete multiple br pending packets by id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrDelBrPendingPacketByIdTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrDelBrPendingPacketById004, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id1 = 11;
    uint32_t id2 = 12;
    int64_t seq1 = 13;
    int64_t seq2 = 14;
    int32_t ret = ConnBrCreateBrPendingPacket(id1, seq1);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrCreateBrPendingPacket(id2, seq2);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ConnBrDelBrPendingPacketById(id1);
    ConnBrDelBrPendingPacketById(id2);
}

/*
 * @tc.name: ConnBrGetBrPendingPacketTest001
 * @tc.desc: test get non-existent br pending packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrGetBrPendingPacketTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrGetBrPendingPacket001, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 15;
    int64_t seq = 15;
    void *data = nullptr;
    uint32_t waitMillis = 100;
    
    int32_t ret = ConnBrGetBrPendingPacket(id, seq, waitMillis, &data);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/*
 * @tc.name: ConnBrGetBrPendingPacketTest002
 * @tc.desc: test get br pending packet with timeout
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrGetBrPendingPacketTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrGetBrPendingPacket002, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 16;
    int64_t seq = 16;
    void *data = nullptr;
    uint32_t waitMillis = 100;
    
    int32_t ret = ConnBrCreateBrPendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrGetBrPendingPacket(id, seq, waitMillis, &data);
    EXPECT_EQ(SOFTBUS_TIMOUT, ret);
}

/*
 * @tc.name: ConnBrGetBrPendingPacketTest003
 * @tc.desc: test get br pending packet with data already set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrGetBrPendingPacketTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrGetBrPendingPacket003, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 17;
    int64_t seq = 17;
    void *data = nullptr;
    uint32_t waitMillis = 100;
    
    int32_t ret = ConnBrCreateBrPendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrSetBrPendingPacket(id, seq, NULL);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrGetBrPendingPacket(id, seq, waitMillis, &data);
    EXPECT_EQ(SOFTBUS_ALREADY_TRIGGERED, ret);
    EXPECT_EQ(NULL, data);
}

/*
 * @tc.name: ConnBrGetBrPendingPacketTest004
 * @tc.desc: test get br pending packet with zero wait time
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrGetBrPendingPacketTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrGetBrPendingPacket004, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 18;
    int64_t seq = 18;
    void *data = nullptr;
    uint32_t waitMillis = 0;
    
    int32_t ret = ConnBrCreateBrPendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrGetBrPendingPacket(id, seq, waitMillis, &data);
    EXPECT_EQ(SOFTBUS_TIMOUT, ret);
}

/*
 * @tc.name: ConnBrGetBrPendingPacketTest005
 * @tc.desc: test get br pending packet with null data pointer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrGetBrPendingPacketTest005, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrGetBrPendingPacket005, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 19;
    int64_t seq = 19;
    uint32_t waitMillis = 100;
    
    int32_t ret = ConnBrGetBrPendingPacket(id, seq, waitMillis, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrSetBrPendingPacketTest001
 * @tc.desc: test set br pending packet with non-existent packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrSetBrPendingPacketTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrSetBrPendingPacket001, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 20;
    int64_t seq = 20;
    
    int32_t ret = ConnBrSetBrPendingPacket(id, seq, NULL);
    EXPECT_EQ(SOFTBUS_CONN_BR_SET_PENDING_PACKET_ERR, ret);
}

/*
 * @tc.name: ConnBrSetBrPendingPacketTest002
 * @tc.desc: test set br pending packet with existing packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrSetBrPendingPacketTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrSetBrPendingPacket002, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 21;
    int64_t seq = 21;
    
    int32_t ret = ConnBrCreateBrPendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrSetBrPendingPacket(id, seq, NULL);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ConnBrDelBrPendingPacket(id, seq);
}

/*
 * @tc.name: ConnBrSetBrPendingPacketTest003
 * @tc.desc: test set br pending packet twice
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrSetBrPendingPacketTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrSetBrPendingPacket003, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 22;
    int64_t seq = 22;
    
    int32_t ret = ConnBrCreateBrPendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrSetBrPendingPacket(id, seq, NULL);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrSetBrPendingPacket(id, seq, NULL);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ConnBrDelBrPendingPacket(id, seq);
}

/*
 * @tc.name: ConnBrSetBrPendingPacketTest004
 * @tc.desc: test set br pending packet with null data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrSetBrPendingPacketTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrSetBrPendingPacket004, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 23;
    int64_t seq = 23;
    void *data = nullptr;
    
    int32_t ret = ConnBrCreateBrPendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrSetBrPendingPacket(id, seq, data);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ConnBrDelBrPendingPacket(id, seq);
}

/*
 * @tc.name: ConnBrOnAckRequestTest001
 * @tc.desc: test on ack request with null parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrOnAckRequestTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrOnAckRequest001, Start");
    NiceMock<ConnectionBrPendingPacketMock> pendingMock;
    
    int32_t ret = ConnBrOnAckRequest(nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrOnAckRequestTest002
 * @tc.desc: test on ack request with parse json error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrOnAckRequestTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrOnAckRequest002, Start");
    NiceMock<ConnectionBrPendingPacketMock> pendingMock;
    
    ConnBrConnection *connection = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    ASSERT_NE(nullptr, connection);
    connection->connectionId = 1;
    connection->window = 10;
    (void)SoftBusMutexInit(&connection->lock, NULL);
    
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    cJSON_AddNumberToObject(json, KEY_WINDOWS, 20);
    cJSON_AddNumberToObject(json, KEY_ACK_SEQ_NUM, 100);
    
    EXPECT_CALL(pendingMock, GetJsonObjectSignedNumberItem).WillOnce(Return(false));
    
    int32_t ret = ConnBrOnAckRequest(connection, json);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    
    cJSON_Delete(json);
    SoftBusMutexDestroy(&connection->lock);
    SoftBusFree(connection);
}

/*
 * @tc.name: ConnBrOnAckRequestTest003
 * @tc.desc: test on ack request with get json number64 item error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrOnAckRequestTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrOnAckRequest003, Start");
    NiceMock<ConnectionBrPendingPacketMock> pendingMock;
    
    ConnBrConnection *connection = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    ASSERT_NE(nullptr, connection);
    connection->connectionId = 1;
    connection->window = 10;
    (void)SoftBusMutexInit(&connection->lock, NULL);
    
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    cJSON_AddNumberToObject(json, KEY_WINDOWS, 20);
    cJSON_AddNumberToObject(json, KEY_ACK_SEQ_NUM, 100);
    
    EXPECT_CALL(pendingMock, GetJsonObjectSignedNumberItem).WillOnce(Return(true));
    EXPECT_CALL(pendingMock, GetJsonObjectNumber64Item).WillOnce(Return(false));
    
    int32_t ret = ConnBrOnAckRequest(connection, json);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    
    cJSON_Delete(json);
    SoftBusMutexDestroy(&connection->lock);
    SoftBusFree(connection);
}

/*
 * @tc.name: ConnBrOnAckRequestTest004
 * @tc.desc: test on ack request with pack control message error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrOnAckRequestTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrOnAckRequest004, Start");
    NiceMock<ConnectionBrPendingPacketMock> pendingMock;
    
    ConnBrConnection *connection = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    ASSERT_NE(nullptr, connection);
    connection->connectionId = 1;
    connection->window = 10;
    (void)SoftBusMutexInit(&connection->lock, NULL);
    
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    cJSON_AddNumberToObject(json, KEY_WINDOWS, 20);
    cJSON_AddNumberToObject(json, KEY_ACK_SEQ_NUM, 100);
    
    EXPECT_CALL(pendingMock, GetJsonObjectSignedNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(pendingMock, GetJsonObjectNumber64Item).WillRepeatedly(Return(true));
    EXPECT_CALL(pendingMock, ConnBrPackCtlMessage).WillOnce(Return(-1));
    
    int32_t ret = ConnBrOnAckRequest(connection, json);
    EXPECT_EQ(-1, ret);
    
    cJSON_Delete(json);
    SoftBusMutexDestroy(&connection->lock);
    SoftBusFree(connection);
}

/*
 * @tc.name: ConnBrOnAckRequestTest005
 * @tc.desc: test on ack request with success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrOnAckRequestTest005, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrOnAckRequest005, Start");
    NiceMock<ConnectionBrPendingPacketMock> pendingMock;
    
    ConnBrConnection *connection = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    ASSERT_NE(nullptr, connection);
    connection->connectionId = 1;
    connection->window = 10;
    (void)SoftBusMutexInit(&connection->lock, NULL);
    
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    cJSON_AddNumberToObject(json, KEY_WINDOWS, 20);
    cJSON_AddNumberToObject(json, KEY_ACK_SEQ_NUM, 100);
    
    uint8_t *testData = (uint8_t *)SoftBusCalloc(10);
    ASSERT_NE(nullptr, testData);
    
    EXPECT_CALL(pendingMock, GetJsonObjectSignedNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(pendingMock, GetJsonObjectNumber64Item).WillRepeatedly(Return(true));
    EXPECT_CALL(pendingMock, ConnBrPackCtlMessage).WillOnce(DoAll(SetArgPointee<1>(testData),
        SetArgPointee<2>(10), Return(1)));
    EXPECT_CALL(pendingMock, ConnBrPostBytes).WillOnce(Return(SOFTBUS_OK));

    int32_t ret = ConnBrOnAckRequest(connection, json);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    cJSON_Delete(json);
    SoftBusMutexDestroy(&connection->lock);
    SoftBusFree(connection);
    SoftBusFree(testData);
}

/*
 * @tc.name: ConnBrOnAckResponseTest001
 * @tc.desc: test on ack response with null parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrOnAckResponseTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrOnAckResponse001, Start");
    NiceMock<ConnectionBrPendingPacketMock> pendingMock;
    
    int32_t ret = ConnBrOnAckResponse(nullptr, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrOnAckResponseTest002
 * @tc.desc: test on ack response with parse json error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrOnAckResponseTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrOnAckResponse002, Start");
    NiceMock<ConnectionBrPendingPacketMock> pendingMock;
    
    ConnBrConnection *connection = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    ASSERT_NE(nullptr, connection);
    connection->connectionId = 1;
    (void)SoftBusMutexInit(&connection->lock, NULL);
    
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    cJSON_AddNumberToObject(json, KEY_WINDOWS, 20);
    cJSON_AddNumberToObject(json, KEY_ACK_SEQ_NUM, 100);
    
    EXPECT_CALL(pendingMock, GetJsonObjectSignedNumberItem).WillOnce(Return(false));
    
    int32_t ret = ConnBrOnAckResponse(connection, json);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    
    cJSON_Delete(json);
    SoftBusMutexDestroy(&connection->lock);
    SoftBusFree(connection);
}

/*
 * @tc.name: ConnBrOnAckResponseTest003
 * @tc.desc: test on ack response with get json number64 item error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrOnAckResponseTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrOnAckResponse003, Start");
    NiceMock<ConnectionBrPendingPacketMock> pendingMock;
    
    ConnBrConnection *connection = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    ASSERT_NE(nullptr, connection);
    connection->connectionId = 1;
    (void)SoftBusMutexInit(&connection->lock, NULL);
    
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    cJSON_AddNumberToObject(json, KEY_WINDOWS, 20);
    cJSON_AddNumberToObject(json, KEY_ACK_SEQ_NUM, 100);
    
    EXPECT_CALL(pendingMock, GetJsonObjectSignedNumberItem).WillOnce(Return(true));
    EXPECT_CALL(pendingMock, GetJsonObjectNumber64Item).WillOnce(Return(false));
    
    int32_t ret = ConnBrOnAckResponse(connection, json);
    EXPECT_EQ(SOFTBUS_PARSE_JSON_ERR, ret);
    
    cJSON_Delete(json);
    SoftBusMutexDestroy(&connection->lock);
    SoftBusFree(connection);
}

/*
 * @tc.name: ConnBrOnAckResponseTest004
 * @tc.desc: test on ack response with set pending packet error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrOnAckResponseTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrOnAckResponse004, Start");
    NiceMock<ConnectionBrPendingPacketMock> pendingMock;
    
    ConnBrConnection *connection = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    ASSERT_NE(nullptr, connection);
    connection->connectionId = 1;
    (void)SoftBusMutexInit(&connection->lock, NULL);
    
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    cJSON_AddNumberToObject(json, KEY_WINDOWS, 20);
    cJSON_AddNumberToObject(json, KEY_ACK_SEQ_NUM, 100);
    
    EXPECT_CALL(pendingMock, GetJsonObjectSignedNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(pendingMock, GetJsonObjectNumber64Item).WillRepeatedly(Return(true));
    
    int32_t ret = ConnBrOnAckResponse(connection, json);
    EXPECT_EQ(SOFTBUS_CONN_BR_SET_PENDING_PACKET_ERR, ret);
    
    cJSON_Delete(json);
    SoftBusMutexDestroy(&connection->lock);
    SoftBusFree(connection);
}

/*
 * @tc.name: ConnBrOnAckResponseTest005
 * @tc.desc: test on ack response with set pending packet error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrOnAckResponseTest005, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrOnAckResponse005, Start");
    NiceMock<ConnectionBrPendingPacketMock> pendingMock;
    
    ConnBrConnection *connection = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    ASSERT_NE(nullptr, connection);
    connection->connectionId = 1;
    (void)SoftBusMutexInit(&connection->lock, NULL);
    
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    cJSON_AddNumberToObject(json, KEY_WINDOWS, 20);
    cJSON_AddNumberToObject(json, KEY_ACK_SEQ_NUM, 100);
    
    EXPECT_CALL(pendingMock, GetJsonObjectSignedNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(pendingMock, GetJsonObjectNumber64Item).WillRepeatedly(Return(true));
    
    int32_t ret = ConnBrOnAckResponse(connection, json);
    EXPECT_EQ(SOFTBUS_CONN_BR_SET_PENDING_PACKET_ERR, ret);
    
    cJSON_Delete(json);
    SoftBusMutexDestroy(&connection->lock);
    SoftBusFree(connection);
}

/*
 * @tc.name: ConnBrOnAckResponseTest006
 * @tc.desc: test on ack response with success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrOnAckResponseTest006, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrOnAckResponse006, Start");
    NiceMock<ConnectionBrPendingPacketMock> pendingMock;
    
    ConnBrConnection *connection = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    ASSERT_NE(nullptr, connection);
    connection->connectionId = 1;
    (void)SoftBusMutexInit(&connection->lock, NULL);
    
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    cJSON_AddNumberToObject(json, KEY_WINDOWS, 20);
    cJSON_AddNumberToObject(json, KEY_ACK_SEQ_NUM, 100);
    
    EXPECT_CALL(pendingMock, GetJsonObjectSignedNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(pendingMock, GetJsonObjectNumber64Item).WillRepeatedly(Return(true));
    
    int32_t ret = ConnBrCreateBrPendingPacket(1, 100);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrOnAckResponse(connection, json);
    EXPECT_EQ(SOFTBUS_CONN_BR_SET_PENDING_PACKET_ERR, ret);
    
    cJSON_Delete(json);
    SoftBusMutexDestroy(&connection->lock);
    SoftBusFree(connection);
}

/*
 * @tc.name: ConnBrOnAckRequestTest006
 * @tc.desc: test on ack request with post bytes error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrOnAckRequestTest006, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrOnAckRequest006, Start");
    NiceMock<ConnectionBrPendingPacketMock> pendingMock;
    
    ConnBrConnection *connection = (ConnBrConnection *)SoftBusCalloc(sizeof(ConnBrConnection));
    ASSERT_NE(nullptr, connection);
    connection->connectionId = 1;
    connection->window = 10;
    (void)SoftBusMutexInit(&connection->lock, NULL);
    
    cJSON *json = cJSON_CreateObject();
    ASSERT_NE(nullptr, json);
    cJSON_AddNumberToObject(json, KEY_WINDOWS, 20);
    cJSON_AddNumberToObject(json, KEY_ACK_SEQ_NUM, 100);
    
    uint8_t *testData = (uint8_t *)SoftBusCalloc(10);
    ASSERT_NE(nullptr, testData);
    
    EXPECT_CALL(pendingMock, GetJsonObjectSignedNumberItem).WillRepeatedly(Return(true));
    EXPECT_CALL(pendingMock, GetJsonObjectNumber64Item).WillRepeatedly(Return(true));
    EXPECT_CALL(pendingMock, ConnBrPackCtlMessage).WillOnce(DoAll(SetArgPointee<1>(testData),
        SetArgPointee<2>(10), Return(1)));
    
    int32_t ret = ConnBrOnAckRequest(connection, json);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    cJSON_Delete(json);
    SoftBusMutexDestroy(&connection->lock);
    SoftBusFree(connection);
    SoftBusFree(testData);
}

/*
 * @tc.name: ConnBrGetBrPendingPacketTest006
 * @tc.desc: test get br pending packet after set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrGetBrPendingPacketTest006, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrGetBrPendingPacket006, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 30;
    int64_t seq = 30;
    void *data = nullptr;
    uint32_t waitMillis = 100;
    
    int32_t ret = ConnBrCreateBrPendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrSetBrPendingPacket(id, seq, NULL);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrGetBrPendingPacket(id, seq, waitMillis, &data);
    EXPECT_EQ(SOFTBUS_ALREADY_TRIGGERED, ret);
    EXPECT_EQ(NULL, data);
}

/*
 * @tc.name: ConnBrCreateBrPendingPacketTest005
 * @tc.desc: test create multiple pending packets
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrCreateBrPendingPacketTest005, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrCreateBrPendingPacket005, Start");
    ConnBrInitBrPendingPacket();
    
    for (int i = 0; i < 10; i++) {
        uint32_t id = 100 + i;
        int64_t seq = 100 + i;
        int32_t ret = ConnBrCreateBrPendingPacket(id, seq);
        EXPECT_EQ(SOFTBUS_OK, ret);
    }
    
    for (int i = 0; i < 10; i++) {
        uint32_t id = 100 + i;
        int64_t seq = 100 + i;
        ConnBrDelBrPendingPacket(id, seq);
    }
}

/*
 * @tc.name: ConnBrDelBrPendingPacketByIdTest005
 * @tc.desc: test delete pending packet by id with multiple seqs
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrDelBrPendingPacketByIdTest005, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrDelBrPendingPacketById005, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 200;
    
    for (int i = 0; i < 5; i++) {
        int64_t seq = 200 + i;
        int32_t ret = ConnBrCreateBrPendingPacket(id, seq);
        EXPECT_EQ(SOFTBUS_OK, ret);
    }
    
    ConnBrDelBrPendingPacketById(id);
}

/*
 * @tc.name: ConnBrSetBrPendingPacketTest005
 * @tc.desc: test set pending packet with different data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrSetBrPendingPacketTest005, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrSetBrPendingPacket005, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 300;
    int64_t seq = 300;
    
    int32_t ret = ConnBrCreateBrPendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBrSetBrPendingPacket(id, seq, NULL);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrSetBrPendingPacket(id, seq, NULL);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrSetBrPendingPacket(id, seq, NULL);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ConnBrDelBrPendingPacket(id, seq);
}

/*
 * @tc.name: ConnBrGetBrPendingPacketTest007
 * @tc.desc: test get pending packet with very long wait time
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrPendingPacketTest, ConnBrGetBrPendingPacketTest007, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrGetBrPendingPacket007, Start");
    ConnBrInitBrPendingPacket();
    uint32_t id = 400;
    int64_t seq = 400;
    void *data = nullptr;
    uint32_t waitMillis = 10;
    
    int32_t ret = ConnBrCreateBrPendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    
    ret = ConnBrGetBrPendingPacket(id, seq, waitMillis, &data);
    EXPECT_EQ(SOFTBUS_TIMOUT, ret);
}
}
