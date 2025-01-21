/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>
#include <securec.h>
#include "softbus_conn_ble_connection_mock.h"
#include "common_list.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_ble_send_queue.h"
#include "softbus_conn_ble_trans.h"
#include "ble_protocol_interface_factory.h"

using namespace testing::ext;
using namespace testing;
namespace OHOS {
static uint32_t g_connId;

void ConnectedCB(unsigned int connectionId, const ConnectionInfo *info)
{
    if (info->type == CONNECT_BLE) {
        g_connId = connectionId;
    }
}
void DisConnectedCB(unsigned int connectionId, const ConnectionInfo *info) {}
void DataReceivedCB(unsigned int connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len) {}
class ConnectionBleTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override {}
    void TearDown() override {}
};

void ConnectionBleTest::SetUpTestCase()
{
    LooperInit();
    SoftbusConfigInit();
    ConnServerInit();
}

void ConnectionBleTest::TearDownTestCase()
{
    LooperDeinit();
}

/*
* @tc.name: TransTest001
* @tc.desc: Test ConnBlePackCtlMessage.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTest, TransTest001, TestSize.Level1)
{
    int64_t ret;
    uint8_t *outData = nullptr;
    uint32_t outLen;
    BleCtlMessageSerializationContext ctx;
    NiceMock<ConnectionBleInterfaceMock> bleMock;

    ctx.connectionId = 1;
    ctx.method = METHOD_NOTIFY_REQUEST;
    EXPECT_CALL(bleMock, AddNumberToJsonObject).WillRepeatedly(Return(true));
    ret = ConnBlePackCtlMessage(ctx, &outData, &outLen);
    EXPECT_EQ(SOFTBUS_OK, ret);

    EXPECT_CALL(bleMock, AddNumberToJsonObject).WillRepeatedly(Return(false));
    ret = ConnBlePackCtlMessage(ctx, &outData, &outLen);
    EXPECT_EQ(SOFTBUS_CREATE_JSON_ERR, ret);
}

/*
* @tc.name: TransTest002
* @tc.desc: Test ConnGattTransRecv.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTest, TransTest002, TestSize.Level1)
{
    uint8_t *value;
    uint32_t connectionId = 1;
    uint8_t *data = nullptr;
    uint32_t dataLen = 0;
    ConnBleReadBuffer buffer;
    uint32_t *outLen = nullptr;
    BleTransHeader tmp;

    value = ConnGattTransRecv(connectionId, data, dataLen, &buffer, outLen);
    ASSERT_TRUE(value == nullptr);

    uint32_t len = sizeof(ConnBleReadBuffer) - 1;
    value = ConnGattTransRecv(connectionId, data, len, &buffer, outLen);
    ASSERT_TRUE(value == nullptr);

    tmp.total = MAX_DATA_LEN + 1;
    dataLen = 17;
    data = (uint8_t *)(&tmp);
    outLen = (uint32_t *)SoftBusCalloc(buffer.total);
    value = ConnGattTransRecv(connectionId, data, dataLen, &buffer, outLen);
    ASSERT_TRUE(value == nullptr);

    tmp.seq = 1;
    tmp.size = 2;
    tmp.offset = 0;
    tmp.total = MAX_DATA_LEN + 1;
    data = (uint8_t *)(&tmp);
    buffer.seq = 1;
    outLen = (uint32_t *)SoftBusCalloc(buffer.total);
    value = ConnGattTransRecv(connectionId, data, dataLen, &buffer, outLen);
    ASSERT_TRUE(value == nullptr);
}

/*
* @tc.name: TransTest003
* @tc.desc: Test ConnCocTransRecv.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTest, TransTest003, TestSize.Level1)
{
    uint8_t *value;
    uint32_t connectionId;
    LimitedBuffer buffer;
    int32_t *outLen = nullptr;
    ConnPktHead head;

    head.magic = MAGIC_NUMBER;
    head.len = 70;
    buffer.capacity = 140;
    buffer.length = 100;
    buffer.buffer = (uint8_t *)(&head);
    connectionId = 1;
    outLen = (int32_t *)SoftBusCalloc(head.len + sizeof(ConnPktHead));
    value = ConnCocTransRecv(connectionId, &buffer, outLen);
    ASSERT_TRUE(value != nullptr);

    head.magic = MAGIC_NUMBER + 1;
    head.len = 70;
    buffer.capacity = 140;
    buffer.length = 100;
    buffer.buffer = (uint8_t *)(&head);
    connectionId = 1;
    value = ConnCocTransRecv(connectionId, &buffer, outLen);
    ASSERT_TRUE(value == nullptr);
}

/*
* @tc.name: QueueTest001
* @tc.desc: Test ConnBleEnqueueNonBlock.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTest, QueueTest001, TestSize.Level1)
{
    int32_t ret;
    SendQueueNode queueNode;

    ret = ConnBleInitSendQueue();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBleEnqueueNonBlock(NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    queueNode.flag = CONN_HIGH;
    queueNode.pid = 0;
    ret = ConnBleEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_MIDDLE;
    queueNode.pid = 1;
    ret = ConnBleEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_LOW;
    queueNode.pid = 1;
    ret = ConnBleEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBleDeinitSendQueue();
}

/*
* @tc.name: QueueTest002
* @tc.desc: Test ConnBleEnqueueNonBlock.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTest, QueueTest002, TestSize.Level1)
{
    int32_t ret;
    void *msg = nullptr;
    SendQueueNode queueNode;

    ret = ConnBleInitSendQueue();
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_LOW;
    queueNode.pid = 1;
    ret = ConnBleEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ConnBleDequeueBlock(&msg);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBleDequeueBlock(NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ConnBleDeinitSendQueue();
}

/*
* @tc.name: ManagerTest001
* @tc.desc: Test ConnTypeIsSupport.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTest, ManagerTest001, TestSize.Level1)
{
    int32_t ret;
    ret = ConnTypeIsSupport(CONNECT_BLE);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: ManagerTest002
* @tc.desc: Test invalid param.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTest, ManagerTest002, TestSize.Level1)
{
    int32_t ret = ConnSetConnectCallback(static_cast<ConnModule>(0), nullptr);
    ASSERT_TRUE(ret != SOFTBUS_OK);
    ret = ConnConnectDevice(nullptr, 0, nullptr);
    ASSERT_TRUE(ret != SOFTBUS_OK);
    ret = ConnDisconnectDevice(0);
    ASSERT_TRUE(ret != SOFTBUS_OK);
    ret = ConnPostBytes(0, nullptr);
    ASSERT_TRUE(ret != SOFTBUS_OK);
    ret = ConnStartLocalListening(nullptr);
    ASSERT_TRUE(ret != SOFTBUS_OK);
    ret = ConnStopLocalListening(nullptr);
    ASSERT_TRUE(ret != SOFTBUS_OK);
}
/*
* @tc.name: ManagerTest003
* @tc.desc: Test Start stop listening.
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: NonZero
* @tc.type: FUNC
* @tc.require:The ConnStartLocalListening and ConnStopLocalListening operates normally.
*/
HWTEST_F(ConnectionBleTest, ManagerTest003, TestSize.Level1)
{
    ConnectCallback connCb;
    connCb.OnConnected = ConnectedCB;
    connCb.OnDisconnected = DisConnectedCB;
    connCb.OnDataReceived = DataReceivedCB;
    int32_t ret = ConnSetConnectCallback(MODULE_TRUST_ENGINE, &connCb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<ConnectionBleInterfaceMock> bleMock;
    EXPECT_CALL(bleMock, BleGattsAddService).WillRepeatedly(Return(SOFTBUS_OK));
    LocalListenerInfo info;
    info.type = CONNECT_BLE;
    ret = ConnStartLocalListening(&info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = ConnStopLocalListening(&info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ConnUnSetConnectCallback(MODULE_TRUST_ENGINE);
}

/*
* @tc.name: InterFaceFactoryTest
* @tc.desc: Test ConnBleGetUnifyInterface
* @tc.in: Test module, Test number, Test Levels.
* @tc.out: Zero
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionBleTest, InterFaceFactoryTest001, TestSize.Level1)
{
    const BleUnifyInterface *ret = ConnBleGetUnifyInterface(BLE_PROTOCOL_MAX);
    EXPECT_EQ(nullptr, ret);
    ret = ConnBleGetUnifyInterface(BLE_GATT);
    EXPECT_NE(nullptr, ret);
}
}