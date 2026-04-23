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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <securec.h>
#include <thread>

#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_connection_fsm.h"
#include "lnn_device_info.h"
#include "lnn_heartbeat_ctrl.c"
#include "lnn_heartbeat_constraint_mock.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_node_info.h"
#include "message_handler.h"
#include "softbus_adapter_bt_common_struct.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

NodeInfo nodeinfo1;

class LnnHeartBeatConstraintTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    std::shared_ptr<LnnHeartbeatConstraintInterfaceMock> constraintMock_;
};

void LnnHeartBeatConstraintTest::SetUpTestCase()
{
}

void LnnHeartBeatConstraintTest::TearDownTestCase()
{
}

void LnnHeartBeatConstraintTest::SetUp()
{
    constraintMock_ = std::make_shared<LnnHeartbeatConstraintInterfaceMock>();
}

void LnnHeartBeatConstraintTest::TearDown()
{
    constraintMock_.reset();
}

/*
 * @tc.name: HbConstraintStateChangeHandlerTest001
 * @tc.desc: use abnormal parameter
 *           Test whether the function HbConstraintStateChangeHandler correctly handles
 *           null pointer and wrong event type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnHeartBeatConstraintTest, HbConstraintStateChangeHandlerTest001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(HbConstraintStateChangeHandler(nullptr));

    LnnConstraintChangeEvent *event =
        reinterpret_cast<LnnConstraintChangeEvent *>(SoftBusCalloc(sizeof(LnnConstraintChangeEvent)));
    ASSERT_TRUE(event != nullptr);
    event->basic.event = LNN_EVENT_TYPE_MAX;
    event->isConstraint = true;
    EXPECT_NO_FATAL_FAILURE(HbConstraintStateChangeHandler(&event->basic));
    SoftBusFree(event);
}

/*
 * @tc.name: HbConstraintStateChangeHandlerTest002
 * @tc.desc: Test constraint enabled triggers LnnClearAllNode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnHeartBeatConstraintTest, HbConstraintStateChangeHandlerTest002, TestSize.Level1)
{
    LnnConstraintChangeEvent *event =
        reinterpret_cast<LnnConstraintChangeEvent *>(SoftBusCalloc(sizeof(LnnConstraintChangeEvent)));
    ASSERT_TRUE(event != nullptr);

    event->basic.event = LNN_EVENT_CONSTRAINT_ENABLE;
    event->isConstraint = true;
    EXPECT_CALL(*constraintMock_, LnnRequestLeaveByAddrType(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(HbConstraintStateChangeHandler(&event->basic));

    SoftBusFree(event);
}

/*
 * @tc.name: HbConstraintStateChangeHandlerTest003
 * @tc.desc: Test constraint disabled does not trigger LnnClearAllNode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnHeartBeatConstraintTest, HbConstraintStateChangeHandlerTest003, TestSize.Level1)
{
    LnnConstraintChangeEvent *event =
        reinterpret_cast<LnnConstraintChangeEvent *>(SoftBusCalloc(sizeof(LnnConstraintChangeEvent)));
    ASSERT_TRUE(event != nullptr);

    event->basic.event = LNN_EVENT_CONSTRAINT_ENABLE;
    event->isConstraint = false;
    EXPECT_NO_FATAL_FAILURE(HbConstraintStateChangeHandler(&event->basic));

    SoftBusFree(event);
}

/*
 * @tc.name: HbConstraintStateChangeHandlerTest004
 * @tc.desc: Test constraint enabled with successful LnnClearAllNode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnHeartBeatConstraintTest, HbConstraintStateChangeHandlerTest004, TestSize.Level1)
{
    LnnConstraintChangeEvent *event =
        reinterpret_cast<LnnConstraintChangeEvent *>(SoftBusCalloc(sizeof(LnnConstraintChangeEvent)));
    ASSERT_TRUE(event != nullptr);

    event->basic.event = LNN_EVENT_CONSTRAINT_ENABLE;
    event->isConstraint = true;
    EXPECT_CALL(*constraintMock_, LnnRequestLeaveByAddrType(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(HbConstraintStateChangeHandler(&event->basic));

    SoftBusFree(event);
}

/*
 * @tc.name: LnnClearAllNode_Success_001
 * @tc.desc: Test LnnClearAllNode calls LnnRequestLeaveByAddrType successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnHeartBeatConstraintTest, LnnClearAllNode_Success_001, TestSize.Level1)
{
    EXPECT_CALL(*constraintMock_, LnnRequestLeaveByAddrType(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(SOFTBUS_OK));
    int32_t ret = LnnClearAllNode();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LnnClearAllNode_Fail_001
 * @tc.desc: Test LnnClearAllNode when LnnRequestLeaveByAddrType fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnHeartBeatConstraintTest, LnnClearAllNode_Fail_001, TestSize.Level1)
{
    EXPECT_CALL(*constraintMock_, LnnRequestLeaveByAddrType(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR));
    int32_t ret = LnnClearAllNode();
    EXPECT_EQ(ret, SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR);
}

/*
 * @tc.name: HbConstraintStateChangeHandlerTest007
 * @tc.desc: Test constraint enabled then disabled in sequence
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LnnHeartBeatConstraintTest, HbConstraintStateChangeHandlerTest007, TestSize.Level1)
{
    LnnConstraintChangeEvent *event =
        reinterpret_cast<LnnConstraintChangeEvent *>(SoftBusCalloc(sizeof(LnnConstraintChangeEvent)));
    ASSERT_TRUE(event != nullptr);

    event->basic.event = LNN_EVENT_CONSTRAINT_ENABLE;
    event->isConstraint = true;
    EXPECT_CALL(*constraintMock_, LnnRequestLeaveByAddrType(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(HbConstraintStateChangeHandler(&event->basic));

    event->isConstraint = false;
    EXPECT_NO_FATAL_FAILURE(HbConstraintStateChangeHandler(&event->basic));

    event->isConstraint = true;
    EXPECT_CALL(*constraintMock_, LnnRequestLeaveByAddrType(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(HbConstraintStateChangeHandler(&event->basic));

    SoftBusFree(event);
}
}  // namespace OHOS
