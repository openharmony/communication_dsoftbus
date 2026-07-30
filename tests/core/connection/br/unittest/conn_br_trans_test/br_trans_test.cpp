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

#include "br_trans_mock.h"
#include "softbus_conn_br_trans.h"
#include "softbus_conn_flow_control.h"
#include "softbus_conn_common.h"
#include "softbus_datahead_transform.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "softbus_conn_br_send_queue.h"
#include "softbus_conn_br_pending_packet.h"
#include "softbus_conn_br_connection.h"
#include "softbus_conn_manager_struct.h"

using namespace testing::ext;
using namespace testing;
using namespace std;

namespace OHOS {
static int32_t g_sppReadRetVal = 0;
static int32_t g_sppWriteRetVal = 0;
static int32_t g_sppWriteCallCount = 0;
static int32_t g_flowCtrlApplyRetVal = 0;

static int32_t MockSppRead(int32_t socketHandle, uint8_t *buf, int32_t len)
{
    return g_sppReadRetVal;
}

static int32_t MockSppWrite(int32_t socketHandle, const uint8_t *data, int32_t len)
{
    g_sppWriteCallCount++;
    return g_sppWriteRetVal;
}

static int32_t MockFlowCtrlApply(struct ConnSlideWindowController *self, int32_t expect)
{
    return g_flowCtrlApplyRetVal > 0 ? g_flowCtrlApplyRetVal : expect;
}

static void MockOnPostByteFinished(uint32_t connectionId, uint32_t len, int32_t pid,
    int32_t flag, int32_t module, int64_t seq, int32_t error)
{
}

class ConnBrTransUnitTest : public testing::Test {
public:
    ConnBrTransUnitTest() {}
    ~ConnBrTransUnitTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static SppSocketDriver g_sppDriver;
    static ConnBrTransEventListener g_listener;
    static ConnSlideWindowController g_flowController;
};

SppSocketDriver ConnBrTransUnitTest::g_sppDriver = {0};
ConnBrTransEventListener ConnBrTransUnitTest::g_listener = {0};
ConnSlideWindowController ConnBrTransUnitTest::g_flowController = {0};

void ConnBrTransUnitTest::SetUpTestCase(void)
{
    g_sppDriver.Read = MockSppRead;
    g_sppDriver.Write = MockSppWrite;
    g_listener.onPostByteFinshed = MockOnPostByteFinished;
    g_flowController.apply = MockFlowCtrlApply;
    g_flowController.active = true;
}

void ConnBrTransUnitTest::TearDownTestCase(void) {}

void ConnBrTransUnitTest::SetUp(void)
{
    g_sppReadRetVal = 0;
    g_sppWriteRetVal = 0;
    g_sppWriteCallCount = 0;
    g_flowCtrlApplyRetVal = 0;
}

void ConnBrTransUnitTest::TearDown(void) {}

static int32_t InitTransModuleForTest(NiceMock<ConnBrTransTestMock> &mock)
{
    EXPECT_CALL(mock, ConnBrInnerQueueInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnSlideWindowControllerNew).WillOnce(Return(&ConnBrTransUnitTest::g_flowController));
    return ConnBrTransMuduleInit(&ConnBrTransUnitTest::g_sppDriver, &ConnBrTransUnitTest::g_listener);
}

/*
 * @tc.name: ConnBrTransMuduleInitTest001
 * @tc.desc: test module init with null spp driver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrTransMuduleInitTest001, TestSize.Level1)
{
    int32_t ret = ConnBrTransMuduleInit(nullptr, &ConnBrTransUnitTest::g_listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrTransMuduleInitTest002
 * @tc.desc: test module init with null listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrTransMuduleInitTest002, TestSize.Level1)
{
    int32_t ret = ConnBrTransMuduleInit(&ConnBrTransUnitTest::g_sppDriver, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrTransMuduleInitTest003
 * @tc.desc: test module init with null read in spp driver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrTransMuduleInitTest003, TestSize.Level1)
{
    SppSocketDriver driver = {0};
    driver.Write = MockSppWrite;
    int32_t ret = ConnBrTransMuduleInit(&driver, &ConnBrTransUnitTest::g_listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrTransMuduleInitTest004
 * @tc.desc: test module init with null write in spp driver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrTransMuduleInitTest004, TestSize.Level1)
{
    SppSocketDriver driver = {0};
    driver.Read = MockSppRead;
    int32_t ret = ConnBrTransMuduleInit(&driver, &ConnBrTransUnitTest::g_listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrTransMuduleInitTest005
 * @tc.desc: test module init with null onPostByteFinshed callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrTransMuduleInitTest005, TestSize.Level1)
{
    SppSocketDriver driver = {0};
    driver.Read = MockSppRead;
    driver.Write = MockSppWrite;
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
HWTEST_F(ConnBrTransUnitTest, ConnBrTransMuduleInitTest006, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    SppSocketDriver driver = {0};
    driver.Read = MockSppRead;
    driver.Write = MockSppWrite;
    ConnBrTransEventListener listener = {0};
    listener.onPostByteFinshed = MockOnPostByteFinished;

    EXPECT_CALL(mock, ConnBrInnerQueueInit).WillOnce(Return(SOFTBUS_ERR));

    int32_t ret = ConnBrTransMuduleInit(&driver, &listener);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
 * @tc.name: ConnBrTransMuduleInitTest007
 * @tc.desc: test module init with flow controller new fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrTransMuduleInitTest007, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    SppSocketDriver driver = {0};
    driver.Read = MockSppRead;
    driver.Write = MockSppWrite;
    ConnBrTransEventListener listener = {0};
    listener.onPostByteFinshed = MockOnPostByteFinished;

    EXPECT_CALL(mock, ConnBrInnerQueueInit).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnSlideWindowControllerNew).WillOnce(Return(nullptr));
    EXPECT_CALL(mock, ConnBrInnerQueueDeinit).WillOnce(Return());

    int32_t ret = ConnBrTransMuduleInit(&driver, &listener);
    EXPECT_EQ(SOFTBUS_CONN_BR_INTERNAL_ERR, ret);
}

/*
 * @tc.name: ConnBrTransMuduleInitTest008
 * @tc.desc: test module init success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrTransMuduleInitTest008, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    int32_t ret = InitTransModuleForTest(mock);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: BrTransSendTest001
 * @tc.desc: test BrTransSend with zero dataLen (no data to send)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, BrTransSendTest001, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    int32_t ret = InitTransModuleForTest(mock);

    uint8_t data[10] = {0};
    g_sppWriteRetVal = 0;
    ret = BrTransSend(1, 1, 1024, data, 0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: BrTransSendTest002
 * @tc.desc: test BrTransSend success with data less than mtu
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, BrTransSendTest002, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    int32_t ret = InitTransModuleForTest(mock);

    uint8_t data[100] = {0};
    g_sppWriteRetVal = 100;
    g_flowCtrlApplyRetVal = 0;
    ret = BrTransSend(1, 1, 1024, data, 100);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(g_sppWriteCallCount, 1);
}

/*
 * @tc.name: BrTransSendTest003
 * @tc.desc: test BrTransSend with data larger than mtu (multiple writes needed)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, BrTransSendTest003, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    int32_t ret = InitTransModuleForTest(mock);

    uint32_t dataLen = 2048;
    uint8_t *data = (uint8_t *)SoftBusCalloc(dataLen);
    ASSERT_NE(data, nullptr);

    g_sppWriteRetVal = 1024;
    g_flowCtrlApplyRetVal = 0;
    ret = BrTransSend(1, 1, 1024, data, dataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_GE(g_sppWriteCallCount, 2);
    SoftBusFree(data);
}

/*
 * @tc.name: BrTransSendTest004
 * @tc.desc: test BrTransSend with write fail (general error)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, BrTransSendTest004, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    int32_t ret = InitTransModuleForTest(mock);

    uint8_t data[100] = {0};
    g_sppWriteRetVal = -1;
    g_flowCtrlApplyRetVal = 0;
    ret = BrTransSend(1, 1, 1024, data, 100);
    EXPECT_EQ(SOFTBUS_CONN_BR_UNDERLAY_WRITE_FAIL, ret);
}

/*
 * @tc.name: BrTransSendTest005
 * @tc.desc: test BrTransSend with retry on queue full error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, BrTransSendTest005, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    int32_t ret = InitTransModuleForTest(mock);

    uint8_t data[100] = {0};
    g_flowCtrlApplyRetVal = 0;
    g_sppWriteCallCount = 0;
    g_sppWriteRetVal = CONN_BR_SEND_DATA_FAIL_UNDERLAYER_ERR_QUEUE_FULL;
    ret = BrTransSend(1, 1, 1024, data, 100);
    EXPECT_EQ(SOFTBUS_CONN_BR_UNDERLAY_WRITE_FAIL, ret);
}

/*
 * @tc.name: BrTransSendTest006
 * @tc.desc: test BrTransSend with retry on interruption error then success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, BrTransSendTest006, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    int32_t ret = InitTransModuleForTest(mock);

    uint8_t data[100] = {0};
    g_flowCtrlApplyRetVal = 0;
    g_sppWriteCallCount = 0;
    g_sppWriteRetVal = CONN_BR_SEND_DATA_FAIL_UNDERLAYER_ERR_INTERRUPTION;
    ret = BrTransSend(1, 1, 1024, data, 100);
    EXPECT_EQ(SOFTBUS_CONN_BR_UNDERLAY_WRITE_FAIL, ret);
}

/*
 * @tc.name: BrTransSendTest007
 * @tc.desc: test BrTransSend with partial write success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, BrTransSendTest007, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    int32_t ret = InitTransModuleForTest(mock);

    uint32_t dataLen = 200;
    uint8_t *data = (uint8_t *)SoftBusCalloc(dataLen);
    ASSERT_NE(data, nullptr);

    g_flowCtrlApplyRetVal = 0;
    g_sppWriteCallCount = 0;
    g_sppWriteRetVal = 50;
    ret = BrTransSend(1, 1, 1024, data, dataLen);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_GE(g_sppWriteCallCount, 4);
    SoftBusFree(data);
}

/*
 * @tc.name: ConnBrTransReadOneFrameTest001
 * @tc.desc: test ConnBrTransReadOneFrame with buffer not enough for header
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrTransReadOneFrameTest001, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    EXPECT_CALL(mock, UnpackConnPktHead).WillRepeatedly(Return());
    EXPECT_CALL(mock, ConnBrDelBrPendingPacketById).WillRepeatedly(Return());

    int32_t ret = InitTransModuleForTest(mock);

    uint32_t connectionId = 1;
    int32_t socketHandle = 0;
    uint8_t *outData = nullptr;

    uint8_t bufferData[10] = {0};
    LimitedBuffer buffer = {0};
    buffer.buffer = bufferData;
    buffer.capacity = 10;
    buffer.length = 5;

    g_sppReadRetVal = -1;
    ret = ConnBrTransReadOneFrame(connectionId, socketHandle, &buffer, &outData);
    EXPECT_EQ(SOFTBUS_CONN_BR_UNDERLAY_READ_FAIL, ret);
}

/*
 * @tc.name: ConnBrTransReadOneFrameTest002
 * @tc.desc: test ConnBrTransReadOneFrame with invalid magic number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrTransReadOneFrameTest002, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    EXPECT_CALL(mock, UnpackConnPktHead).WillRepeatedly(Return());
    EXPECT_CALL(mock, ConnBrDelBrPendingPacketById).WillRepeatedly(Return());

    int32_t ret = InitTransModuleForTest(mock);

    uint32_t connectionId = 1;
    int32_t socketHandle = 0;
    uint8_t *outData = nullptr;

    ConnPktHead head = {0};
    head.magic = MAGIC_NUMBER + 1;
    head.len = 10;
    head.module = 0;
    head.seq = 0;
    head.flag = 0;

    LimitedBuffer buffer = {0};
    buffer.buffer = (uint8_t *)&head;
    buffer.capacity = sizeof(ConnPktHead) + 10;
    buffer.length = sizeof(ConnPktHead) + 10;

    g_sppReadRetVal = -1;
    ret = ConnBrTransReadOneFrame(connectionId, socketHandle, &buffer, &outData);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnBrTransReadOneFrameTest003
 * @tc.desc: test ConnBrTransReadOneFrame with socket closed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrTransReadOneFrameTest003, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    EXPECT_CALL(mock, UnpackConnPktHead).WillRepeatedly(Return());
    EXPECT_CALL(mock, ConnBrDelBrPendingPacketById).WillRepeatedly(Return());

    int32_t ret = InitTransModuleForTest(mock);

    uint32_t connectionId = 1;
    int32_t socketHandle = 0;
    uint8_t *outData = nullptr;

    uint8_t bufferData[100] = {0};
    LimitedBuffer buffer = {0};
    buffer.buffer = bufferData;
    buffer.capacity = 100;
    buffer.length = 5;

    g_sppReadRetVal = BR_READ_SOCKET_CLOSED;
    ret = ConnBrTransReadOneFrame(connectionId, socketHandle, &buffer, &outData);
    EXPECT_EQ(SOFTBUS_CONN_BR_UNDERLAY_SOCKET_CLOSED, ret);
}

/*
 * @tc.name: ConnBrTransReadOneFrameTest004
 * @tc.desc: test ConnBrTransReadOneFrame with data too big
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrTransReadOneFrameTest004, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    EXPECT_CALL(mock, UnpackConnPktHead).WillRepeatedly(Return());
    EXPECT_CALL(mock, ConnBrDelBrPendingPacketById).WillRepeatedly(Return());

    int32_t ret = InitTransModuleForTest(mock);

    uint32_t connectionId = 1;
    int32_t socketHandle = 0;
    uint8_t *outData = nullptr;

    ConnPktHead head = {0};
    head.magic = MAGIC_NUMBER;
    head.len = 200;
    head.module = 0;
    head.seq = 0;
    head.flag = 0;

    LimitedBuffer buffer = {0};
    buffer.buffer = (uint8_t *)&head;
    buffer.capacity = 100;
    buffer.length = sizeof(ConnPktHead) + 50;

    g_sppReadRetVal = -1;
    ret = ConnBrTransReadOneFrame(connectionId, socketHandle, &buffer, &outData);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnBrTransReadOneFrameTest005
 * @tc.desc: test ConnBrTransReadOneFrame with incomplete packet
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrTransReadOneFrameTest005, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    EXPECT_CALL(mock, UnpackConnPktHead).WillRepeatedly(Return());
    EXPECT_CALL(mock, ConnBrDelBrPendingPacketById).WillRepeatedly(Return());

    int32_t ret = InitTransModuleForTest(mock);

    uint32_t connectionId = 1;
    int32_t socketHandle = 0;
    uint8_t *outData = nullptr;

    ConnPktHead head = {0};
    head.magic = MAGIC_NUMBER;
    head.len = 50;
    head.module = 0;
    head.seq = 0;
    head.flag = 0;

    LimitedBuffer buffer = {0};
    buffer.buffer = (uint8_t *)&head;
    buffer.capacity = 200;
    buffer.length = sizeof(ConnPktHead) + 10;

    g_sppReadRetVal = -1;
    ret = ConnBrTransReadOneFrame(connectionId, socketHandle, &buffer, &outData);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnBrPackCtlMessageTest001
 * @tc.desc: test pack control message with notify request method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPackCtlMessageTest001, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    EXPECT_CALL(mock, PackConnPktHead).WillRepeatedly(Return());

    (void)InitTransModuleForTest(mock);

    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 1;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_NOTIFY_REQUEST;
    ctx.referenceRequest.delta = 10;
    ctx.referenceRequest.referenceNumber = 20;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
}

/*
 * @tc.name: ConnBrPackCtlMessageTest002
 * @tc.desc: test pack control message with notify response method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPackCtlMessageTest002, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    EXPECT_CALL(mock, PackConnPktHead).WillRepeatedly(Return());

    (void)InitTransModuleForTest(mock);

    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 2;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_NOTIFY_RESPONSE;
    ctx.referenceResponse.referenceNumber = 30;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
}

/*
 * @tc.name: ConnBrPackCtlMessageTest003
 * @tc.desc: test pack control message with notify ack method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPackCtlMessageTest003, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    EXPECT_CALL(mock, PackConnPktHead).WillRepeatedly(Return());

    (void)InitTransModuleForTest(mock);

    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 3;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_NOTIFY_ACK;
    ctx.ackRequestResponse.window = 20;
    ctx.ackRequestResponse.seq = 100;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
}

/*
 * @tc.name: ConnBrPackCtlMessageTest004
 * @tc.desc: test pack control message with ack response method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPackCtlMessageTest004, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    EXPECT_CALL(mock, PackConnPktHead).WillRepeatedly(Return());

    (void)InitTransModuleForTest(mock);

    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 4;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_ACK_RESPONSE;
    ctx.ackRequestResponse.window = 20;
    ctx.ackRequestResponse.seq = 200;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
}

/*
 * @tc.name: ConnBrPackCtlMessageTest005
 * @tc.desc: test pack control message with invalid method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPackCtlMessageTest005, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    (void)InitTransModuleForTest(mock);

    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 5;
    ctx.flag = CONN_HIGH;
    ctx.method = (enum BrCtlMessageMethod)999;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_LT(seq, 0);
    EXPECT_EQ(static_cast<int32_t>(seq), SOFTBUS_CONN_BR_INTERNAL_ERR);
}

/*
 * @tc.name: ConnBrPackCtlMessageTest006
 * @tc.desc: test pack control message with cJSON_CreateObject fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPackCtlMessageTest006, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    (void)InitTransModuleForTest(mock);

    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 6;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_NOTIFY_REQUEST;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
    EXPECT_EQ(static_cast<int32_t>(seq), 5);
}

/*
 * @tc.name: ConnBrPackCtlMessageTest007
 * @tc.desc: test pack control message with AddNumberToJsonObject fail for notify request
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPackCtlMessageTest007, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    (void)InitTransModuleForTest(mock);

    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 7;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_NOTIFY_REQUEST;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
    EXPECT_EQ(static_cast<int32_t>(seq), 6);
}

/*
 * @tc.name: ConnBrPackCtlMessageTest008
 * @tc.desc: test pack control message with cJSON_PrintUnformatted fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPackCtlMessageTest008, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    (void)InitTransModuleForTest(mock);

    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 8;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_NOTIFY_ACK;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
    EXPECT_EQ(static_cast<int32_t>(seq), 7);
}

/*
 * @tc.name: ConnBrPackCtlMessageTest009
 * @tc.desc: test pack control message with SoftBusCalloc fail (simulated by mock)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPackCtlMessageTest009, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    (void)InitTransModuleForTest(mock);

    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 9;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_NOTIFY_ACK;
    ctx.ackRequestResponse.window = 20;
    ctx.ackRequestResponse.seq = 100;

    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    int64_t seq = ConnBrPackCtlMessage(ctx, &data, &dataLen);
    EXPECT_GE(seq, 0);
}

/*
 * @tc.name: ConnBrPackCtlMessageTest010
 * @tc.desc: test sequence increment in ConnBrPackCtlMessage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPackCtlMessageTest010, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    EXPECT_CALL(mock, PackConnPktHead).WillRepeatedly(Return());

    (void)InitTransModuleForTest(mock);

    BrCtlMessageSerializationContext ctx = {0};
    ctx.connectionId = 10;
    ctx.flag = CONN_HIGH;
    ctx.method = BR_METHOD_NOTIFY_ACK;
    ctx.ackRequestResponse.window = 20;
    ctx.ackRequestResponse.seq = 100;

    uint8_t *data1 = nullptr;
    uint32_t dataLen1 = 0;
    uint8_t *data2 = nullptr;
    uint32_t dataLen2 = 0;

    int64_t seq1 = ConnBrPackCtlMessage(ctx, &data1, &dataLen1);
    int64_t seq2 = ConnBrPackCtlMessage(ctx, &data2, &dataLen2);
    EXPECT_EQ(seq2, seq1 + 1);
}

/*
 * @tc.name: ConnBrPostBytesTest001
 * @tc.desc: test ConnBrPostBytes with null data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPostBytesTest001, TestSize.Level1)
{
    int32_t ret = ConnBrPostBytes(1, nullptr, 100, 0, CONN_HIGH, MODULE_CONNECTION, 1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrPostBytesTest002
 * @tc.desc: test ConnBrPostBytes with zero length
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPostBytesTest002, TestSize.Level1)
{
    uint8_t *data = (uint8_t *)SoftBusCalloc(100);
    ASSERT_NE(data, nullptr);
    int32_t ret = ConnBrPostBytes(2, data, 0, 0, CONN_HIGH, MODULE_CONNECTION, 2);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrPostBytesTest003
 * @tc.desc: test ConnBrPostBytes with data length exceeding MAX_DATA_LEN
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPostBytesTest003, TestSize.Level1)
{
    uint32_t len = MAX_DATA_LEN + 1;
    uint8_t *data = (uint8_t *)SoftBusCalloc(len);
    ASSERT_NE(data, nullptr);
    int32_t ret = ConnBrPostBytes(3, data, len, 0, CONN_HIGH, MODULE_CONNECTION, 3);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrPostBytesTest004
 * @tc.desc: test ConnBrPostBytes with connection not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPostBytesTest004, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    int32_t ret = InitTransModuleForTest(mock);

    uint8_t *data = (uint8_t *)SoftBusCalloc(100);
    ASSERT_NE(data, nullptr);

    EXPECT_CALL(mock, ConnBrGetConnectionById).WillOnce(Return(nullptr));

    ret = ConnBrPostBytes(4, data, 100, 0, CONN_HIGH, MODULE_CONNECTION, 4);
    EXPECT_EQ(SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR, ret);
}

/*
 * @tc.name: ConnBrPostBytesTest005
 * @tc.desc: test ConnBrPostBytes with connection not ready (state not connected)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPostBytesTest005, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    int32_t ret = InitTransModuleForTest(mock);

    uint8_t *data = (uint8_t *)SoftBusCalloc(100);
    ASSERT_NE(data, nullptr);

    ConnBrConnection connection = {};
    connection.connectionId = 5;
    connection.state = BR_CONNECTION_STATE_CLOSED;
    SoftBusMutexInit(&connection.lock, nullptr);

    EXPECT_CALL(mock, ConnBrGetConnectionById).WillOnce(Return(&connection));
    EXPECT_CALL(mock, ConnBrRefreshIdleTimeout).WillOnce(Return());
    EXPECT_CALL(mock, ConnBrReturnConnection).WillOnce(Return());

    ret = ConnBrPostBytes(5, data, 100, 0, CONN_HIGH, MODULE_TRUST_ENGINE, 5);
    EXPECT_EQ(SOFTBUS_CONN_BR_CONNECTION_NOT_READY_ERR, ret);
}

/*
 * @tc.name: ConnBrPostBytesTest006
 * @tc.desc: test ConnBrPostBytes with lock fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPostBytesTest006, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    int32_t ret = InitTransModuleForTest(mock);

    uint8_t *data = (uint8_t *)SoftBusCalloc(100);
    ASSERT_NE(data, nullptr);

    ConnBrConnection connection = {};
    connection.connectionId = 6;
    connection.state = BR_CONNECTION_STATE_CONNECTED;

    EXPECT_CALL(mock, ConnBrGetConnectionById).WillOnce(Return(&connection));
    EXPECT_CALL(mock, ConnBrRefreshIdleTimeout).WillOnce(Return());
    EXPECT_CALL(mock, ConnBrReturnConnection).WillOnce(Return());

    ret = ConnBrPostBytes(6, data, 100, 0, CONN_HIGH, MODULE_CONNECTION, 6);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
}

/*
 * @tc.name: ConnBrPostBytesTest007
 * @tc.desc: test ConnBrPostBytes with connection state connected and MODULE_CONNECTION
 *          (should bypass state check for MODULE_CONNECTION)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPostBytesTest007, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    int32_t ret = InitTransModuleForTest(mock);

    uint8_t *data = (uint8_t *)SoftBusCalloc(100);
    ASSERT_NE(data, nullptr);

    ConnBrConnection connection = {};
    connection.connectionId = 7;
    connection.state = BR_CONNECTION_STATE_NEGOTIATION_CLOSING;
    SoftBusMutexInit(&connection.lock, nullptr);

    EXPECT_CALL(mock, ConnBrGetConnectionById).WillOnce(Return(&connection));
    EXPECT_CALL(mock, ConnBrRefreshIdleTimeout).WillOnce(Return());
    EXPECT_CALL(mock, ConnBrReturnConnection).WillOnce(Return());
    EXPECT_CALL(mock, ConnBrEnqueueNonBlock).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnStartActionAsync).WillOnce(Return(SOFTBUS_OK));

    ret = ConnBrPostBytes(7, data, 100, 0, CONN_HIGH, MODULE_CONNECTION, 7);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnBrPostBytesTest008
 * @tc.desc: test ConnBrPostBytes with calloc node fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPostBytesTest008, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    int32_t ret = InitTransModuleForTest(mock);

    uint8_t *data = (uint8_t *)SoftBusCalloc(100);
    ASSERT_NE(data, nullptr);

    ConnBrConnection connection = {};
    connection.connectionId = 8;
    connection.state = BR_CONNECTION_STATE_CONNECTED;
    SoftBusMutexInit(&connection.lock, nullptr);

    EXPECT_CALL(mock, ConnBrGetConnectionById).WillOnce(Return(&connection));
    EXPECT_CALL(mock, ConnBrRefreshIdleTimeout).WillOnce(Return());
    EXPECT_CALL(mock, ConnBrReturnConnection).WillOnce(Return());

    ret = ConnBrPostBytes(8, data, 100, 0, CONN_HIGH, MODULE_TRUST_ENGINE, 8);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnBrPostBytesTest009
 * @tc.desc: test ConnBrPostBytes with enqueue fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPostBytesTest009, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    int32_t ret = InitTransModuleForTest(mock);

    uint8_t *data = (uint8_t *)SoftBusCalloc(100);
    ASSERT_NE(data, nullptr);

    ConnBrConnection connection = {};
    connection.connectionId = 9;
    connection.state = BR_CONNECTION_STATE_CONNECTED;
    SoftBusMutexInit(&connection.lock, nullptr);

    EXPECT_CALL(mock, ConnBrGetConnectionById).WillOnce(Return(&connection));
    EXPECT_CALL(mock, ConnBrRefreshIdleTimeout).WillOnce(Return());
    EXPECT_CALL(mock, ConnBrReturnConnection).WillRepeatedly(Return());
    EXPECT_CALL(mock, ConnBrEnqueueNonBlock).WillOnce(Return(SOFTBUS_ERR));

    ret = ConnBrPostBytes(9, data, 100, 0, CONN_HIGH, MODULE_CONNECTION, 9);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnBrPostBytesTest010
 * @tc.desc: test ConnBrPostBytes with start action async fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrPostBytesTest010, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    int32_t ret = InitTransModuleForTest(mock);

    uint8_t *data = (uint8_t *)SoftBusCalloc(100);
    ASSERT_NE(data, nullptr);

    ConnBrConnection connection = {};
    connection.connectionId = 10;
    connection.state = BR_CONNECTION_STATE_CONNECTED;
    SoftBusMutexInit(&connection.lock, nullptr);

    EXPECT_CALL(mock, ConnBrGetConnectionById).WillOnce(Return(&connection));
    EXPECT_CALL(mock, ConnBrRefreshIdleTimeout).WillOnce(Return());
    EXPECT_CALL(mock, ConnBrReturnConnection).WillRepeatedly(Return());

    ret = ConnBrPostBytes(10, data, 100, 0, CONN_HIGH, MODULE_CONNECTION, 10);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: ConnBrTransConfigPostLimitTest001
 * @tc.desc: test config post limit with null configuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrTransConfigPostLimitTest001, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    int32_t ret = InitTransModuleForTest(mock);

    ret = ConnBrTransConfigPostLimit(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: ConnBrTransConfigPostLimitTest002
 * @tc.desc: test config post limit with non-BR type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnBrTransUnitTest, ConnBrTransConfigPostLimitTest002, TestSize.Level1)
{
    NiceMock<ConnBrTransTestMock> mock;
    int32_t ret = InitTransModuleForTest(mock);

    LimitConfiguration config = {0};
    config.type = CONNECT_TCP;
    ret = ConnBrTransConfigPostLimit(&config);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

} // namespace OHOS
