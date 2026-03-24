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

#include "softbus_conn_br_send_queue_mock.h"
#include "softbus_conn_br_send_queue.h"

#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "conn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_conn_interface_struct.h"

using namespace testing::ext;
using namespace testing;
using namespace std;

namespace OHOS {
class ConnBrSendQueueTest : public testing::Test {
public:
    ConnBrSendQueueTest() { }
    ~ConnBrSendQueueTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ConnBrSendQueueTest::SetUpTestCase(void) { }

void ConnBrSendQueueTest::TearDownTestCase(void) { }

void ConnBrSendQueueTest::SetUp(void) { }

void ConnBrSendQueueTest::TearDown(void) { }

/*
 * @tc.name: ConnBrEnqueueNonBlockTest001
 * @tc.desc: Test ConnBrEnqueueNonBlock with null parameter
 * @tc.type: FUNC
 * @tc.require: Verify that passing null message returns SOFTBUS_INVALID_PARAM
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrEnqueueNonBlockTest001, TestSize.Level1)
{
    int32_t ret;

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    ret = ConnBrEnqueueNonBlock(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrEnqueueNonBlockTest002
 * @tc.desc: Test enqueue to inner queue with HIGH priority (pid=0, isInner=1)
 * @tc.type: FUNC
 * @tc.require: Verify that enqueuing to inner queue with HIGH priority succeeds
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrEnqueueNonBlockTest002, TestSize.Level1)
{
    int32_t ret;
    SendBrQueueNode queueNode;

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_HIGH;
    queueNode.pid = 0;
    queueNode.isInner = 1;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrEnqueueNonBlockTest003
 * @tc.desc: Test enqueue to inner queue with MIDDLE priority (pid=0, isInner=1)
 * @tc.type: FUNC
 * @tc.require: Verify that enqueuing to inner queue with MIDDLE priority succeeds
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrEnqueueNonBlockTest003, TestSize.Level1)
{
    int32_t ret;
    SendBrQueueNode queueNode;

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_MIDDLE;
    queueNode.pid = 0;
    queueNode.isInner = 1;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrEnqueueNonBlockTest004
 * @tc.desc: Test enqueue to inner queue with LOW priority (pid=0, isInner=1)
 * @tc.type: FUNC
 * @tc.require: Verify that enqueuing to inner queue with LOW priority succeeds
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrEnqueueNonBlockTest004, TestSize.Level1)
{
    int32_t ret;
    SendBrQueueNode queueNode;

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_LOW;
    queueNode.pid = 0;
    queueNode.isInner = 1;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrEnqueueNonBlockTest005
 * @tc.desc: Test enqueue to inner queue with invalid priority (defaults to LOW)
 * @tc.type: FUNC
 * @tc.require: Verify that invalid priority defaults to LOW priority
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrEnqueueNonBlockTest005, TestSize.Level1)
{
    int32_t ret;
    SendBrQueueNode queueNode;

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = 99;
    queueNode.pid = 0;
    queueNode.isInner = 1;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrEnqueueNonBlockTest006
 * @tc.desc: Test enqueue to external queue with HIGH priority (pid=1, isInner=0)
 * @tc.type: FUNC
 * @tc.require: Verify that enqueuing to external queue with HIGH priority succeeds and creates new queue
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrEnqueueNonBlockTest006, TestSize.Level1)
{
    int32_t ret;
    SendBrQueueNode queueNode;

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_HIGH;
    queueNode.pid = 1;
    queueNode.isInner = 0;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrEnqueueNonBlockTest007
 * @tc.desc: Test enqueue to external queue with MIDDLE priority (pid=1, isInner=0)
 * @tc.type: FUNC
 * @tc.require: Verify that enqueuing to external queue with MIDDLE priority succeeds
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrEnqueueNonBlockTest007, TestSize.Level1)
{
    int32_t ret;
    SendBrQueueNode queueNode;

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_MIDDLE;
    queueNode.pid = 1;
    queueNode.isInner = 0;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrEnqueueNonBlockTest008
 * @tc.desc: Test enqueue to external queue with LOW priority (pid=1, isInner=0)
 * @tc.type: FUNC
 * @tc.require: Verify that enqueuing to external queue with LOW priority succeeds
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrEnqueueNonBlockTest008, TestSize.Level1)
{
    int32_t ret;
    SendBrQueueNode queueNode;

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_LOW;
    queueNode.pid = 1;
    queueNode.isInner = 0;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrEnqueueNonBlockTest009
 * @tc.desc: Test enqueue to external queue with invalid priority (defaults to LOW)
 * @tc.type: FUNC
 * @tc.require: Verify that invalid priority defaults to LOW priority for external queue
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrEnqueueNonBlockTest009, TestSize.Level1)
{
    int32_t ret;
    SendBrQueueNode queueNode;

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = 99;
    queueNode.pid = 1;
    queueNode.isInner = 0;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrEnqueueNonBlockTest010
 * @tc.desc: Test enqueue to same external queue pid multiple times
 * @tc.type: FUNC
 * @tc.require: Verify that reusing existing queue for same pid works correctly
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrEnqueueNonBlockTest010, TestSize.Level1)
{
    int32_t ret;
    SendBrQueueNode queueNode;

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_HIGH;
    queueNode.pid = 1;
    queueNode.isInner = 0;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_MIDDLE;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_LOW;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrEnqueueNonBlockTest011
 * @tc.desc: Test enqueue to multiple external queues with different pids
 * @tc.type: FUNC
 * @tc.require: Verify that multiple external queues can be created and used
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrEnqueueNonBlockTest011, TestSize.Level1)
{
    int32_t ret;
    SendBrQueueNode queueNode;

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_HIGH;
    queueNode.pid = 1;
    queueNode.isInner = 0;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.pid = 2;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.pid = 3;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrEnqueueNonBlockTest012
 * @tc.desc: Test enqueue with pid=0 but isInner=0 (treated as external queue)
 * @tc.type: FUNC
 * @tc.require: Verify that pid=0 with isInner=0 uses external queue path
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrEnqueueNonBlockTest012, TestSize.Level1)
{
    int32_t ret;
    SendBrQueueNode queueNode;

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_HIGH;
    queueNode.pid = 0;
    queueNode.isInner = 0;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrEnqueueNonBlockTest013
 * @tc.desc: Test enqueue with pid!=0 but isInner=1 (treated as external queue)
 * @tc.type: FUNC
 * @tc.require: Verify that pid!=0 with isInner=1 uses external queue path
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrEnqueueNonBlockTest013, TestSize.Level1)
{
    int32_t ret;
    SendBrQueueNode queueNode;

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_HIGH;
    queueNode.pid = 1;
    queueNode.isInner = 1;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrDequeueBlockTest001
 * @tc.desc: Test ConnBrDequeueBlock with null parameter
 * @tc.type: FUNC
 * @tc.require: Verify that passing null msg pointer returns SOFTBUS_INVALID_PARAM
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrDequeueBlockTest001, TestSize.Level1)
{
    int32_t ret;

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    ret = ConnBrDequeueBlock(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrDequeueBlockTest002
 * @tc.desc: Test dequeue after enqueue to inner queue
 * @tc.type: FUNC
 * @tc.require: Verify that dequeue retrieves message enqueued to inner queue
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrDequeueBlockTest002, TestSize.Level1)
{
    int32_t ret;
    void *msg = nullptr;
    SendBrQueueNode queueNode;

    NiceMock<ConnectionBrSendQueueInterfaceMock> mock;
    EXPECT_CALL(mock, GetMsg).WillOnce(Return(SOFTBUS_OK));

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_LOW;
    queueNode.pid = 0;
    queueNode.isInner = 1;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBrDequeueBlock(&msg);
    EXPECT_EQ(SOFTBUS_OK, (ret));
    EXPECT_EQ(nullptr, msg);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrDequeueBlockTest003
 * @tc.desc: Test dequeue after enqueue to external queue
 * @tc.type: FUNC
 * @tc.require: Verify that dequeue retrieves message enqueued to external queue
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrDequeueBlockTest003, TestSize.Level1)
{
    int32_t ret;
    void *msg = nullptr;
    SendBrQueueNode queueNode;

    NiceMock<ConnectionBrSendQueueInterfaceMock> mock;
    EXPECT_CALL(mock, GetMsg).WillOnce(Return(SOFTBUS_OK));

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_LOW;
    queueNode.pid = 1;
    queueNode.isInner = 0;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBrDequeueBlock(&msg);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(nullptr, msg);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrDequeueBlockTest004
 * @tc.desc: Test dequeue with multiple messages in inner queue
 * @tc.type: FUNC
 * @tc.require: Verify that multiple messages can be dequeued from inner queue
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrDequeueBlockTest004, TestSize.Level1)
{
    int32_t ret;
    void *msg = nullptr;
    SendBrQueueNode queueNode;

    NiceMock<ConnectionBrSendQueueInterfaceMock> mock;
    EXPECT_CALL(mock, GetMsg).WillOnce(Return(SOFTBUS_OK));

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.pid = 0;
    queueNode.isInner = 1;

    queueNode.flag = CONN_HIGH;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_MIDDLE;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_LOW;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBrDequeueBlock(&msg);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(nullptr, msg);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrDequeueBlockTest005
 * @tc.desc: Test dequeue with multiple messages in external queue
 * @tc.type: FUNC
 * @tc.require: Verify that multiple messages can be dequeued from external queue
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrDequeueBlockTest005, TestSize.Level1)
{
    int32_t ret;
    void *msg = nullptr;
    SendBrQueueNode queueNode;

    NiceMock<ConnectionBrSendQueueInterfaceMock> mock;
    EXPECT_CALL(mock, GetMsg).WillRepeatedly(Return(SOFTBUS_OK));

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.pid = 1;
    queueNode.isInner = 0;

    queueNode.flag = CONN_HIGH;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_MIDDLE;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_LOW;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBrDequeueBlock(&msg);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(nullptr, msg);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrDequeueBlockTest006
 * @tc.desc: Test dequeue with messages in both inner and external queues
 * @tc.type: FUNC
 * @tc.require: Verify that dequeue handles messages from both queue types correctly
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrDequeueBlockTest006, TestSize.Level1)
{
    int32_t ret;
    void *msg = nullptr;
    SendBrQueueNode queueNode;

    NiceMock<ConnectionBrSendQueueInterfaceMock> mock;
    EXPECT_CALL(mock, GetMsg).WillRepeatedly(Return(SOFTBUS_OK));

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_LOW;
    queueNode.pid = 0;
    queueNode.isInner = 1;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_LOW;
    queueNode.pid = 1;
    queueNode.isInner = 0;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBrDequeueBlock(&msg);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(nullptr, msg);

    ret = ConnBrDequeueBlock(&msg);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(nullptr, msg);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrDequeueBlockTest007
 * @tc.desc: Test dequeue with messages in multiple external queues
 * @tc.type: FUNC
 * @tc.require: Verify that dequeue handles messages from multiple external queues
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrDequeueBlockTest007, TestSize.Level1)
{
    int32_t ret;
    void *msg = nullptr;
    SendBrQueueNode queueNode;

    NiceMock<ConnectionBrSendQueueInterfaceMock> mock;
    EXPECT_CALL(mock, GetMsg).WillRepeatedly(Return(SOFTBUS_OK));

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_LOW;
    queueNode.isInner = 0;

    queueNode.pid = 1;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.pid = 2;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.pid = 3;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnBrDequeueBlock(&msg);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(nullptr, msg);

    ret = ConnBrDequeueBlock(&msg);
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(nullptr, msg);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrDequeueBlockTest008
 * @tc.desc: Test dequeue timeout when queue is empty
 * @tc.type: FUNC
 * @tc.require: Verify that dequeue returns SOFTBUS_TIMOUT when queue is empty and time retrieval succeeds
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrDequeueBlockTest008, TestSize.Level1)
{
    int32_t ret;
    void *msg = nullptr;

    NiceMock<ConnectionBrSendQueueInterfaceMock> mock;
    EXPECT_CALL(mock, SoftBusGetTime).WillOnce(Return(SOFTBUS_OK));

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    ret = ConnBrDequeueBlock(&msg);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrDequeueBlockTest009
 * @tc.desc: Test dequeue when SoftBusCondWait fails
 * @tc.type: FUNC
 * @tc.require: Verify that dequeue returns SOFTBUS_CONN_COND_WAIT_FAIL when condition wait fails
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrDequeueBlockTest009, TestSize.Level1)
{
    int32_t ret;
    void *msg = nullptr;

    NiceMock<ConnectionBrSendQueueInterfaceMock> mock;
    EXPECT_CALL(mock, SoftBusGetTime).WillOnce(Return(SOFTBUS_OK));

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    ret = ConnBrDequeueBlock(&msg);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrDequeueBlockTest010
 * @tc.desc: Test dequeue when SoftBusGetTime fails
 * @tc.type: FUNC
 * @tc.require: Verify that dequeue returns SOFTBUS_INVALID_PARAM when getting time fails
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrDequeueBlockTest010, TestSize.Level1)
{
    int32_t ret;
    void *msg = nullptr;

    NiceMock<ConnectionBrSendQueueInterfaceMock> mock;
    EXPECT_CALL(mock, SoftBusGetTime).WillOnce(Return(SOFTBUS_INVALID_PARAM));

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    ret = ConnBrDequeueBlock(&msg);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrEnqueueDequeueTest001
 * @tc.desc: Test enqueue and dequeue with all priority levels
 * @tc.type: FUNC
 * @tc.require: Verify that all priority levels work correctly in enqueue/dequeue cycle
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrEnqueueDequeueTest001, TestSize.Level1)
{
    int32_t ret;
    void *msg = nullptr;
    SendBrQueueNode queueNode;

    NiceMock<ConnectionBrSendQueueInterfaceMock> mock;
    EXPECT_CALL(mock, GetMsg).WillRepeatedly(Return(SOFTBUS_OK));

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.pid = 0;
    queueNode.isInner = 1;

    queueNode.flag = CONN_HIGH;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_MIDDLE;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_LOW;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    for (int i = 0; i < 3; i++) {
        ret = ConnBrDequeueBlock(&msg);
        EXPECT_EQ(SOFTBUS_OK, ret);
        EXPECT_EQ(nullptr, msg);
    }

    ConnBrInnerQueueDeinit();
}

/*
 * @tc.name: ConnBrEnqueueDequeueTest002
 * @tc.desc: Test enqueue and dequeue with mixed inner and external queues
 * @tc.type: FUNC
 * @tc.require: Verify that mixed queue operations work correctly
 */
HWTEST_F(ConnBrSendQueueTest, ConnBrEnqueueDequeueTest002, TestSize.Level1)
{
    int32_t ret;
    void *msg = nullptr;
    SendBrQueueNode queueNode;

    NiceMock<ConnectionBrSendQueueInterfaceMock> mock;
    EXPECT_CALL(mock, GetMsg).WillRepeatedly(Return(SOFTBUS_OK));

    ret = ConnBrInnerQueueInit();
    ASSERT_EQ(SOFTBUS_OK, ret);

    queueNode.flag = CONN_LOW;

    queueNode.pid = 0;
    queueNode.isInner = 1;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.pid = 1;
    queueNode.isInner = 0;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.pid = 0;
    queueNode.isInner = 1;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    queueNode.pid = 2;
    queueNode.isInner = 0;
    ret = ConnBrEnqueueNonBlock(&queueNode);
    EXPECT_EQ(SOFTBUS_OK, ret);

    for (int i = 0; i < 4; i++) {
        ret = ConnBrDequeueBlock(&msg);
        EXPECT_EQ(SOFTBUS_OK, ret);
        EXPECT_EQ(nullptr, msg);
    }

    ConnBrInnerQueueDeinit();
}
} // namespace OHOS
