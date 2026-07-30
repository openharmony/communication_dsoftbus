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

#include "softbus_conn_br_trans_mock.h"
#include "softbus_conn_br_trans.h"
#include "softbus_conn_flow_control.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;
using namespace std;

namespace OHOS {
class ConnBrTransTest : public testing::Test {
public:
    ConnBrTransTest() {}
    ~ConnBrTransTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ConnBrTransTest::SetUpTestCase(void) {}

void ConnBrTransTest::TearDownTestCase(void) {}

void ConnBrTransTest::SetUp(void) {}

void ConnBrTransTest::TearDown(void) {}

/*
 * @tc.name: ConnBrTransConfigPostLimitTest001
 * @tc.desc: test config post limit with null configuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransConfigPostLimitTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransConfigPostLimit001, Start");
    int32_t ret = ConnBrTransConfigPostLimit(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrTransConfigPostLimitTest002
 * @tc.desc: test config post limit with invalid type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransConfigPostLimitTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransConfigPostLimit002, Start");
    LimitConfiguration config = {0};
    config.type = CONNECT_TCP;
    int32_t ret = ConnBrTransConfigPostLimit(&config);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrTransMuduleInitTest001
 * @tc.desc: test module init with null spp driver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransMuduleInitTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransMuduleInit001, Start");
    ConnBrTransEventListener listener = {0};
    int32_t ret = ConnBrTransMuduleInit(nullptr, &listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrTransMuduleInitTest002
 * @tc.desc: test module init with null listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransMuduleInitTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransMuduleInit002, Start");
    SppSocketDriver driver = {0};
    int32_t ret = ConnBrTransMuduleInit(&driver, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrTransMuduleInitTest003
 * @tc.desc: test module init with null read function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransMuduleInitTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransMuduleInit003, Start");
    SppSocketDriver driver = {0};
    ConnBrTransEventListener listener = {0};
    int32_t ret = ConnBrTransMuduleInit(&driver, &listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrTransMuduleInitTest004
 * @tc.desc: test module init with null write function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransMuduleInitTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransMuduleInit004, Start");
    SppSocketDriver driver = {0};
    driver.Read = [](int32_t, uint8_t*, int32_t) -> int32_t { return 0; };
    ConnBrTransEventListener listener = {0};
    int32_t ret = ConnBrTransMuduleInit(&driver, &listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrTransMuduleInitTest005
 * @tc.desc: test module init with null callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransMuduleInitTest005, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransMuduleInit005, Start");
    SppSocketDriver driver = {0};
    driver.Read = [](int32_t, uint8_t*, int32_t) -> int32_t { return 0; };
    driver.Write = [](int32_t, const uint8_t*, int32_t) -> int32_t { return 0; };
    ConnBrTransEventListener listener = {0};
    int32_t ret = ConnBrTransMuduleInit(&driver, &listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrTransMuduleInitTest006
 * @tc.desc: test module init with queue init fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransMuduleInitTest006, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransMuduleInit006, Start");
    NiceMock<ConnectionBrTransMock> transMock;
    
    SppSocketDriver driver = {0};
    driver.Read = [](int32_t, uint8_t*, int32_t) -> int32_t { return 0; };
    driver.Write = [](int32_t, const uint8_t*, int32_t) -> int32_t { return 0; };
    
    ConnBrTransEventListener listener = {0};
    listener.onPostByteFinshed = [](uint32_t, uint32_t, int32_t, int32_t, int32_t, int64_t, int32_t) -> void {};
    
    EXPECT_CALL(transMock, ConnBrInnerQueueInit).WillOnce(Return(SOFTBUS_ERR));
    
    int32_t ret = ConnBrTransMuduleInit(&driver, &listener);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
 * @tc.name: ConnBrTransMuduleInitTest007
 * @tc.desc: test module init with flow controller new fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransMuduleInitTest007, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransMuduleInit007, Start");
    NiceMock<ConnectionBrTransMock> transMock;
    
    SppSocketDriver driver = {0};
    driver.Read = [](int32_t, uint8_t*, int32_t) -> int32_t { return 0; };
    driver.Write = [](int32_t, const uint8_t*, int32_t) -> int32_t { return 0; };
    
    ConnBrTransEventListener listener = {0};
    listener.onPostByteFinshed = [](uint32_t, uint32_t, int32_t, int32_t, int32_t, int64_t, int32_t) -> void {};
    
    EXPECT_CALL(transMock, ConnBrInnerQueueInit).WillOnce(Return(SOFTBUS_OK));
    
    int32_t ret = ConnBrTransMuduleInit(&driver, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnBrTransMuduleInitTest008
 * @tc.desc: test module init with mutex init fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransMuduleInitTest008, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransMuduleInit008, Start");
    NiceMock<ConnectionBrTransMock> transMock;
    
    SppSocketDriver driver = {0};
    driver.Read = [](int32_t, uint8_t*, int32_t) -> int32_t { return 0; };
    driver.Write = [](int32_t, const uint8_t*, int32_t) -> int32_t { return 0; };
    
    ConnBrTransEventListener listener = {0};
    listener.onPostByteFinshed = [](uint32_t, uint32_t, int32_t, int32_t, int32_t, int64_t, int32_t) -> void {};
    
    EXPECT_CALL(transMock, ConnBrInnerQueueInit).WillOnce(Return(SOFTBUS_OK));
    
    int32_t ret = ConnBrTransMuduleInit(&driver, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnBrTransMuduleInitTest009
 * @tc.desc: test module init success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransMuduleInitTest009, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransMuduleInit009, Start");
    NiceMock<ConnectionBrTransMock> transMock;
    
    SppSocketDriver driver = {0};
    driver.Read = [](int32_t, uint8_t*, int32_t) -> int32_t { return 0; };
    driver.Write = [](int32_t, const uint8_t*, int32_t) -> int32_t { return 0; };
    
    ConnBrTransEventListener listener = {0};
    listener.onPostByteFinshed = [](uint32_t, uint32_t, int32_t, int32_t, int32_t, int64_t, int32_t) -> void {};

    EXPECT_CALL(transMock, ConnBrInnerQueueInit).WillOnce(Return(SOFTBUS_OK));
    
    int32_t ret = ConnBrTransMuduleInit(&driver, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnBrPackCtlMessageTest001
 * @tc.desc: test pack control message with notify request
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPackCtlMessageTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPackCtlMessage001, Start");
    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 1;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_NOTIFY_REQUEST;
    ctx.referenceRequest.delta = 10;
    ctx.referenceRequest.referenceNumber = 20;
    
    uint8_t *data = nullptr;
    uint32_t dataLen = {0};
    
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
    EXPECT_NE(data, nullptr);
    EXPECT_GT(dataLen, 0);
    
    if (data != nullptr) {
        SoftBusFree(data);
    }
}

/*
 * @tc.name: ConnBrPackCtlMessageTest002
 * @tc.desc: test pack control message with notify response
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPackCtlMessageTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPackCtlMessage002, Start");
    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 2;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_NOTIFY_RESPONSE;
    ctx.referenceResponse.referenceNumber = 30;
    
    uint8_t *data = nullptr;
    uint32_t dataLen = {0};
    
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
    EXPECT_NE(data, nullptr);
    EXPECT_GT(dataLen, 0);
    
    if (data != nullptr) {
        SoftBusFree(data);
    }
}

/*
 * @tc.name: ConnBrPackCtlMessageTest003
 * @tc.desc: test pack control message with notify ack
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPackCtlMessageTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPackCtlMessage003, Start");
    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 3;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_NOTIFY_ACK;
    ctx.ackRequestResponse.window = 20;
    ctx.ackRequestResponse.seq = 100;
    
    uint8_t *data = nullptr;
    uint32_t dataLen = {0};
    
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
    EXPECT_NE(data, nullptr);
    EXPECT_GT(dataLen, 0);
    
    if (data != nullptr) {
        SoftBusFree(data);
    }
}

/*
 * @tc.name: ConnBrPackCtlMessageTest004
 * @tc.desc: test pack control message with ack response
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPackCtlMessageTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPackCtlMessage004, Start");
    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 4;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_ACK_RESPONSE;
    ctx.ackRequestResponse.window = 20;
    ctx.ackRequestResponse.seq = 200;
    
    uint8_t *data = nullptr;
    uint32_t dataLen = {0};
    
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
    EXPECT_NE(data, nullptr);
    EXPECT_GT(dataLen, 0);
    
    if (data != nullptr) {
        SoftBusFree(data);
    }
}

/*
 * @tc.name: ConnBrPackCtlMessageTest005
 * @tc.desc: test pack control message with invalid method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPackCtlMessageTest005, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPackCtlMessage005, Start");
    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 5;
    ctx.flag = CONN_HIGH;
    ctx.method = (enum BrCtlMessageMethod)999;
    
    uint8_t *data = nullptr;
    uint32_t dataLen = {0};
    
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_LT(seq, 0);
    EXPECT_EQ(data, nullptr);
}

/*
 * @tc.name: ConnBrPackCtlMessageTest006
 * @tc.desc: test pack control message with malloc fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPackCtlMessageTest006, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPackCtlMessage006, Start");
    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 6;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_NOTIFY_REQUEST;
    ctx.referenceRequest.delta = 10;
    ctx.referenceRequest.referenceNumber = 20;
    
    uint8_t *data = nullptr;
    uint32_t dataLen = {0};
    
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
    
    if (data != nullptr) {
        SoftBusFree(data);
    }
}

/*
 * @tc.name: ConnBrPostBytesTest001
 * @tc.desc: test post bytes with null data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPostBytesTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPostBytes001, Start");
    int32_t ret = ConnBrPostBytes(1, nullptr, 100, 0, CONN_HIGH, MODULE_CONNECTION, 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrPostBytesTest002
 * @tc.desc: test post bytes with zero length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPostBytesTest002, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPostBytes002, Start");
    uint8_t *data = (uint8_t *)SoftBusCalloc(100);
    ASSERT_NE(data, nullptr);
    
    int32_t ret = ConnBrPostBytes(2, data, 0, 0, CONN_HIGH, MODULE_CONNECTION, 2);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrPostBytesTest003
 * @tc.desc: test post bytes with connection not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPostBytesTest003, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPostBytes003, Start");
    NiceMock<ConnectionBrTransMock> transMock;
    
    uint8_t *data = (uint8_t *)SoftBusCalloc(100);
    ASSERT_NE(data, nullptr);
    
    EXPECT_CALL(transMock, ConnBrGetConnectionById).WillOnce(Return(nullptr));
    
    int32_t ret = ConnBrPostBytes(3, data, 100, 0, CONN_HIGH, MODULE_CONNECTION, 3);
    EXPECT_EQ(SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR, ret);
}

/*
 * @tc.name: ConnBrPostBytesTest004
 * @tc.desc: test post bytes with lock fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPostBytesTest004, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPostBytes004, Start");
    NiceMock<ConnectionBrTransMock> transMock;
    
    uint8_t *data = (uint8_t *)SoftBusCalloc(100);
    ASSERT_NE(data, nullptr);
    
    ConnBrConnection connection = {};
    connection.connectionId = 4;
    connection.state = BR_CONNECTION_STATE_CONNECTED;
    
    EXPECT_CALL(transMock, ConnBrGetConnectionById).WillOnce(Return(&connection));
    EXPECT_CALL(transMock, ConnBrRefreshIdleTimeout).WillOnce(Return());
    EXPECT_CALL(transMock, ConnBrReturnConnection).WillOnce(Return());
    
    int32_t ret = ConnBrPostBytes(4, data, 100, 0, CONN_HIGH, MODULE_CONNECTION, 4);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
}

/*
 * @tc.name: BrTransSendTest001
 * @tc.desc: test br trans send with zero length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, BrTransSendTest001, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "BrTransSend001, Start");
    uint8_t data[100] = {0};
    
    int32_t ret = BrTransSend(1, 1, 1024, data, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnBrTransConfigPostLimitTest005
 * @tc.desc: test config post limit with valid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransConfigPostLimitTest005, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransConfigPostLimit005, Start");
    LimitConfiguration config = {0};
    config.type = CONNECT_BR;
    config.active = true;
    config.windowInMillis = 500;
    config.quotaInBytes = 2048;
    
    int32_t ret = ConnBrTransConfigPostLimit(&config);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrPackCtlMessageTest007
 * @tc.desc: test pack control message sequence increment
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPackCtlMessageTest007, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPackCtlMessage007, Start");
    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 7;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_NOTIFY_ACK;
    ctx.ackRequestResponse.window = 20;
    ctx.ackRequestResponse.seq = 300;
    
    uint8_t *data1 = nullptr;
    uint32_t dataLen1 = {0};
    uint8_t *data2 = nullptr;
    uint32_t dataLen2 = {0};
    
    int64_t seq1 = ConnBrPackCtlMessage(ctx, &data1, &dataLen1);
    int64_t seq2 = ConnBrPackCtlMessage(ctx, &data2, &dataLen2);
    
    EXPECT_EQ(seq2, seq1 + 1);
    
    if (data1 != nullptr) {
        SoftBusFree(data1);
    }
    if (data2 != nullptr) {
        SoftBusFree(data2);
    }
}

/*
 * @tc.name: ConnBrPackCtlMessageTest008
 * @tc.desc: test pack control message with invalid method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPackCtlMessageTest008, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPackCtlMessage008, Start");
    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 8;
    ctx.flag = CONN_HIGH;
    ctx.method = (enum BrCtlMessageMethod)999;
    
    uint8_t *data = nullptr;
    uint32_t dataLen = {0};
    
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_LT(seq, 0);
    EXPECT_EQ(data, nullptr);
}

/*
 * @tc.name: ConnBrPackCtlMessageTest010
 * @tc.desc: test pack control message with notify request
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPackCtlMessageTest010, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPackCtlMessage010, Start");
    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 10;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_NOTIFY_REQUEST;
    ctx.referenceRequest.delta = 50;
    ctx.referenceRequest.referenceNumber = 100;
    
    uint8_t *data = nullptr;
    uint32_t dataLen = {0};
    
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
    EXPECT_NE(data, nullptr);
    EXPECT_GT(dataLen, 0);
    
    if (data != nullptr) {
        SoftBusFree(data);
    }
}

/*
 * @tc.name: ConnBrPackCtlMessageTest011
 * @tc.desc: test pack control message with notify response
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPackCtlMessageTest011, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPackCtlMessage011, Start");
    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 11;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_NOTIFY_RESPONSE;
    ctx.referenceResponse.referenceNumber = 150;
    
    uint8_t *data = nullptr;
    uint32_t dataLen = {0};
    
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
    EXPECT_NE(data, nullptr);
    EXPECT_GT(dataLen, 0);
    
    if (data != nullptr) {
        SoftBusFree(data);
    }
}

/*
 * @tc.name: ConnBrPackCtlMessageTest012
 * @tc.desc: test pack control message with different flags
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPackCtlMessageTest012, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPackCtlMessage012, Start");
    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 12;
    ctx.flag = CONN_LOW;
    ctx.method = BR_METHOD_NOTIFY_ACK;
    ctx.ackRequestResponse.window = 30;
    ctx.ackRequestResponse.seq = 500;
    
    uint8_t *data = nullptr;
    uint32_t dataLen = {0};
    
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
    EXPECT_NE(data, nullptr);
    EXPECT_GT(dataLen, 0);
    
    if (data != nullptr) {
        SoftBusFree(data);
    }
}

/*
 * @tc.name: ConnBrTransMuduleInitTest014
 * @tc.desc: test module init with mutex init fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransMuduleInitTest014, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransMuduleInit014, Start");
    NiceMock<ConnectionBrTransMock> transMock;
    
    SppSocketDriver driver = {0};
    driver.Read = [](int32_t, uint8_t*, int32_t) -> int32_t { return 0; };
    driver.Write = [](int32_t, const uint8_t*, int32_t) -> int32_t { return 0; };
    
    ConnBrTransEventListener listener = {0};
    listener.onPostByteFinshed = [](uint32_t, uint32_t, int32_t, int32_t, int32_t, int64_t, int32_t) -> void {};
    
    
    EXPECT_CALL(transMock, ConnBrInnerQueueInit).WillOnce(Return(SOFTBUS_OK));
    
    int32_t ret = ConnBrTransMuduleInit(&driver, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnBrTransMuduleInitTest015
 * @tc.desc: test module init with all valid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransMuduleInitTest015, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransMuduleInit015, Start");
    NiceMock<ConnectionBrTransMock> transMock;
    
    SppSocketDriver driver = {0};
    driver.Read = [](int32_t, uint8_t*, int32_t) -> int32_t { return 0; };
    driver.Write = [](int32_t, const uint8_t*, int32_t) -> int32_t { return 0; };
    
    ConnBrTransEventListener listener = {0};
    listener.onPostByteFinshed = [](uint32_t, uint32_t, int32_t, int32_t, int32_t, int64_t, int32_t) -> void {};
    
    int32_t ret = ConnBrTransMuduleInit(&driver, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnBrPackCtlMessageTest013
 * @tc.desc: test pack control message with large window value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPackCtlMessageTest013, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPackCtlMessage013, Start");
    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 13;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_NOTIFY_ACK;
    ctx.ackRequestResponse.window = MAX_WINDOW;
    ctx.ackRequestResponse.seq = 600;
    
    uint8_t *data = nullptr;
    uint32_t dataLen = {0};
    
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
    EXPECT_NE(data, nullptr);
    EXPECT_GT(dataLen, 0);
    
    if (data != nullptr) {
        SoftBusFree(data);
    }
}

/*
 * @tc.name: ConnBrPackCtlMessageTest014
 * @tc.desc: test pack control message with min window value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPackCtlMessageTest014, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPackCtlMessage014, Start");
    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 14;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_ACK_RESPONSE;
    ctx.ackRequestResponse.window = MIN_WINDOW;
    ctx.ackRequestResponse.seq = 700;
    
    uint8_t *data = nullptr;
    uint32_t dataLen = {0};
    
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
    EXPECT_NE(data, nullptr);
    EXPECT_GT(dataLen, 0);
    
    if (data != nullptr) {
        SoftBusFree(data);
    }
}

/*
 * @tc.name: ConnBrTransConfigPostLimitTest008
 * @tc.desc: test config post limit with edge cases
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransConfigPostLimitTest008, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransConfigPostLimit008, Start");
    LimitConfiguration config = {0};
    config.type = CONNECT_BR;
    config.active = true;
    config.windowInMillis = MIN_WINDOW_IN_MILLIS;
    config.quotaInBytes = MIN_QUOTA_IN_BYTES;
    
    int32_t ret = ConnBrTransConfigPostLimit(&config);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnBrTransConfigPostLimitTest009
 * @tc.desc: test config post limit with max values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransConfigPostLimitTest009, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransConfigPostLimit009, Start");
    LimitConfiguration config = {0};
    config.type = CONNECT_BR;
    config.active = true;
    config.windowInMillis = MAX_WINDOW_IN_MILLIS;
    config.quotaInBytes = MAX_QUOTA_IN_BYTES;
    
    int32_t ret = ConnBrTransConfigPostLimit(&config);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnBrPackCtlMessageTest015
 * @tc.desc: test pack control message with zero sequence
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPackCtlMessageTest015, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPackCtlMessage015, Start");
    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 15;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_NOTIFY_ACK;
    ctx.ackRequestResponse.window = 20;
    ctx.ackRequestResponse.seq = 0;
    
    uint8_t *data = nullptr;
    uint32_t dataLen = {0};
    
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
    EXPECT_NE(data, nullptr);
    EXPECT_GT(dataLen, 0);
    
    if (data != nullptr) {
        SoftBusFree(data);
    }
}

/*
 * @tc.name: ConnBrPackCtlMessageTest016
 * @tc.desc: test pack control message with negative sequence
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPackCtlMessageTest016, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPackCtlMessage016, Start");
    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 16;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_ACK_RESPONSE;
    ctx.ackRequestResponse.window = 20;
    ctx.ackRequestResponse.seq = -100;
    
    uint8_t *data = nullptr;
    uint32_t dataLen = {0};
    
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
    EXPECT_NE(data, nullptr);
    EXPECT_GT(dataLen, 0);
    
    if (data != nullptr) {
        SoftBusFree(data);
    }
}

/*
 * @tc.name: ConnBrTransConfigPostLimitTest010
 * @tc.desc: test config post limit toggle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransConfigPostLimitTest010, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransConfigPostLimit010, Start");
    LimitConfiguration config1 = {0};
    config1.type = CONNECT_BR;
    config1.active = true;
    config1.windowInMillis = 1000;
    config1.quotaInBytes = 1024;
    
    LimitConfiguration config2 = {0};
    config2.type = CONNECT_BR;
    config2.active = false;
    
    int32_t ret1 = ConnBrTransConfigPostLimit(&config1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret1);
    
    int32_t ret2 = ConnBrTransConfigPostLimit(&config2);
    EXPECT_EQ(SOFTBUS_OK, ret2);
}

/*
 * @tc.name: ConnBrTransMuduleInitTest017
 * @tc.desc: test module init with null write function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransMuduleInitTest017, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransMuduleInit017, Start");
    SppSocketDriver driver = {0};
    driver.Read = [](int32_t, uint8_t*, int32_t) -> int32_t { return 0; };
    
    ConnBrTransEventListener listener = {0};
    listener.onPostByteFinshed = [](uint32_t, uint32_t, int32_t, int32_t, int32_t, int64_t, int32_t) -> void {};
    
    int32_t ret = ConnBrTransMuduleInit(&driver, &listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrTransMuduleInitTest018
 * @tc.desc: test module init with null read function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransMuduleInitTest018, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransMuduleInit018, Start");
    SppSocketDriver driver = {0};
    driver.Write = [](int32_t, const uint8_t*, int32_t) -> int32_t { return 0; };
    
    ConnBrTransEventListener listener = {0};
    listener.onPostByteFinshed = [](uint32_t, uint32_t, int32_t, int32_t, int32_t, int64_t, int32_t) -> void {};
    
    int32_t ret = ConnBrTransMuduleInit(&driver, &listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrPackCtlMessageTest017
 * @tc.desc: test pack control message with default window
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPackCtlMessageTest017, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPackCtlMessage017, Start");
    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 17;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_NOTIFY_ACK;
    ctx.ackRequestResponse.window = DEFAULT_WINDOW;
    ctx.ackRequestResponse.seq = 800;
    
    uint8_t *data = nullptr;
    uint32_t dataLen = {0};
    
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
    EXPECT_NE(data, nullptr);
    EXPECT_GT(dataLen, 0);
    
    if (data != nullptr) {
        SoftBusFree(data);
    }
}

/*
 * @tc.name: ConnBrTransConfigPostLimitTest011
 * @tc.desc: test config post limit with invalid window
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransConfigPostLimitTest011, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransConfigPostLimit011, Start");
    LimitConfiguration config = {0};
    config.type = CONNECT_BR;
    config.active = true;
    config.windowInMillis = 50;
    config.quotaInBytes = 1024;
    
    int32_t ret = ConnBrTransConfigPostLimit(&config);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrPackCtlMessageTest018
 * @tc.desc: test pack control message stress test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrPackCtlMessageTest018, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrPackCtlMessage018, Start");
    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 18;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_NOTIFY_ACK;
    ctx.ackRequestResponse.window = 20;
    ctx.ackRequestResponse.seq = 900;
    
    for (int i = 0; i < 5; i++) {
        uint8_t *data = nullptr;
        uint32_t dataLen = {0};
        
        int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
        EXPECT_GE(seq, 0);
        EXPECT_NE(data, nullptr);
        EXPECT_GT(dataLen, 0);
        
        if (data != nullptr) {
            SoftBusFree(data);
        }
    }
}

/*
 * @tc.name: ConnBrTransConfigPostLimitTest012
 * @tc.desc: test config post limit stress test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransConfigPostLimitTest012, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransConfigPostLimit012, Start");
    LimitConfiguration config = {0};
    config.type = CONNECT_BR;
    config.active = true;
    config.windowInMillis = 1000;
    config.quotaInBytes = 1024;
    
    for (int i = 0; i < 5; i++) {
        int32_t ret = ConnBrTransConfigPostLimit(&config);
        EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    }
}

/*
 * @tc.name: ConnBrTransMuduleInitTest020
 * @tc.desc: test module init with all null driver functions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransTest, ConnBrTransMuduleInitTest020, TestSize.Level1)
{
    CONN_LOGI(CONN_BR, "ConnBrTransMuduleInit020, Start");
    SppSocketDriver driver = {0};
    
    ConnBrTransEventListener listener = {0};
    listener.onPostByteFinshed = [](uint32_t, uint32_t, int32_t, int32_t, int32_t, int64_t, int32_t) -> void {};
    
    int32_t ret = ConnBrTransMuduleInit(&driver, &listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}
} // namespace OHOS
