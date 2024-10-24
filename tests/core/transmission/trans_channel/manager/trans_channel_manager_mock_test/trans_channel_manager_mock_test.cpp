/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "disc_event_manager.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_feature_config.h"
#include "trans_channel_manager.h"
#include "trans_manager_test_mock.h"
#include "trans_session_service.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
class TransChannelManagerMockTest : public testing::Test {
public:
    TransChannelManagerMockTest()
    {}
    ~TransChannelManagerMockTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransChannelManagerMockTest::SetUpTestCase(void)
{
    SoftbusConfigInit();
    LooperInit();
    ConnServerInit();
    AuthInit();
    BusCenterServerInit();
    TransServerInit();
    DiscEventManagerInit();
}

void TransChannelManagerMockTest::TearDownTestCase(void)
{
    LooperDeinit();
    ConnServerDeinit();
    AuthDeinit();
    TransServerDeinit();
    DiscEventManagerDeinit();
}

/**
 * @tc.name: TransStreamStats test
 * @tc.desc: TransStreamStats002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerMockTest, TransStreamStats002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelType = 1;
    StreamSendStats *data = (StreamSendStats *)SoftBusCalloc(sizeof(StreamSendStats));
    ASSERT_TRUE(data != nullptr);
    TransManagerTestInterfaceMock mock;
    EXPECT_CALL(mock, TransGetLaneHandleByChannelId).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransStreamStats(channelId, channelType, data);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(data);
}

/**
 * @tc.name: TransStreamStats test
 * @tc.desc: TransStreamStats003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerMockTest, TransStreamStats003, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t channelType = 1;
    StreamSendStats *data = (StreamSendStats *)SoftBusCalloc(sizeof(StreamSendStats));
    ASSERT_TRUE(data != nullptr);
    TransManagerTestInterfaceMock mock;
    EXPECT_CALL(mock, TransGetLaneHandleByChannelId).WillOnce(Return(SOFTBUS_TRANS_NODE_NOT_FOUND));
    int32_t ret = TransStreamStats(channelId, channelType, data);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    SoftBusFree(data);
}

/**
 * @tc.name: TransRequestQos test
 * @tc.desc: TransRequestQos003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerMockTest, TransRequestQos003, TestSize.Level1)
{
    TransManagerTestInterfaceMock mock;
    EXPECT_CALL(mock, TransGetLaneHandleByChannelId).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransRequestQos(1, 1, 1, QOS_RECOVER);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransRequestQos test
 * @tc.desc: TransRequestQos004
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerMockTest, TransRequestQos004, TestSize.Level1)
{
    TransManagerTestInterfaceMock mock;
    EXPECT_CALL(mock, TransGetLaneHandleByChannelId).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransRequestQos(1, 1, 1, -1);
    EXPECT_EQ(SOFTBUS_TRANS_REQUEST_QOS_FAILED, ret);
}

/**
 * @tc.name: TransRequestQos test
 * @tc.desc: TransRequestQos005
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerMockTest, TransRequestQos005, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t chanType = 1;
    int32_t appType = 1;
    TransManagerTestInterfaceMock mock;
    EXPECT_CALL(mock, TransGetLaneHandleByChannelId).WillOnce(Return(SOFTBUS_TRANS_NODE_NOT_FOUND));
    int32_t ret = TransRequestQos(channelId, chanType, appType, QOS_IMPROVE);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
}

/**
 * @tc.name: TransRippleStats test
 * @tc.desc: TransRippleStats002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerMockTest, TransRippleStats002, TestSize.Level1)
{
    TrafficStats *trafficStats = (TrafficStats *)SoftBusCalloc(sizeof(TrafficStats));
    ASSERT_TRUE(trafficStats != nullptr);
    trafficStats->stats[0] = 't';
    trafficStats->stats[1] = 'e';
    TransManagerTestInterfaceMock mock;
    EXPECT_CALL(mock, TransGetLaneHandleByChannelId).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransRippleStats(1, 1, trafficStats);
    EXPECT_EQ(SOFTBUS_OK, ret);
    SoftBusFree(trafficStats);
}

/**
 * @tc.name: TransRippleStats test
 * @tc.desc: TransRippleStats003
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerMockTest, TransRippleStats003, TestSize.Level1)
{
    TrafficStats *trafficStats = (TrafficStats *)SoftBusCalloc(sizeof(TrafficStats));
    ASSERT_TRUE(trafficStats != nullptr);
    trafficStats->stats[0] = 't';
    trafficStats->stats[1] = 'e';
    TransManagerTestInterfaceMock mock;
    EXPECT_CALL(mock, TransGetLaneHandleByChannelId).WillOnce(Return(SOFTBUS_TRANS_NODE_NOT_FOUND));
    int32_t ret = TransRippleStats(1, 1, trafficStats);
    EXPECT_EQ(SOFTBUS_TRANS_NODE_NOT_FOUND, ret);
    SoftBusFree(trafficStats);
}

/**
 * @tc.name: TransGetAndComparePidBySession test
 * @tc.desc: TransGetAndComparePidBySession001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerMockTest, TransGetAndComparePidBySession001, TestSize.Level1)
{
    const char *sessionName = "test_name";
    TransManagerTestInterfaceMock mock;
    EXPECT_CALL(mock, TransGetPidFromSocketChannelInfoBySession).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = TransGetAndComparePidBySession(1, sessionName, 1);
    EXPECT_EQ(SOFTBUS_TRANS_CHECK_PID_ERROR, ret);
}

/**
 * @tc.name: TransGetAndComparePidBySession test
 * @tc.desc: TransGetAndComparePidBySession002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerMockTest, TransGetAndComparePidBySession002, TestSize.Level1)
{
    const char *sessionName = "test_name";
    TransManagerTestInterfaceMock mock;
    EXPECT_CALL(mock, TransGetPidFromSocketChannelInfoBySession).WillOnce(Return(SOFTBUS_NOT_FIND));
    int32_t ret = TransGetAndComparePidBySession(1, sessionName, 1);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/**
 * @tc.name: TransRequestQos test
 * @tc.desc: TransRequestQos002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransChannelManagerMockTest, TransRequestQos002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t chanType = 1;
    int32_t appType = 1;
    TransManagerTestInterfaceMock mock;
    EXPECT_CALL(mock, TransGetLaneHandleByChannelId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnRequestQosOptimization).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = TransRequestQos(channelId, chanType, appType, QOS_IMPROVE);
    EXPECT_EQ(SOFTBUS_TRANS_REQUEST_QOS_FAILED, ret);
}
} // OHOS
