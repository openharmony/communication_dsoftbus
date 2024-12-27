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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>
#include <thread>

#include "lnn_lane_hub_deps_mock.h"
#include "lnn_lane_hub.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class LNNLaneHubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneHubTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneHubTest start";
}

void LNNLaneHubTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneHubTest end";
}

void LNNLaneHubTest::SetUp()
{
}

void LNNLaneHubTest::TearDown()
{
}

/*
* @tc.name: LNN_INIT_LANE_HUB_TEST_001
* @tc.desc: LnnInitLaneHub test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneHubTest, LNN_INIT_LANE_HUB_TEST_001, TestSize.Level1)
{
    NiceMock<LaneHubDepsInterfaceMock> laneHubMock;
    EXPECT_CALL(laneHubMock, InitLane).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(laneHubMock, LnnInitQos).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(laneHubMock, LnnInitTimeSync).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(laneHubMock, LnnInitHeartbeat).WillOnce(Return(SOFTBUS_OK));

    int32_t ret = LnnInitLaneHub();
    EXPECT_EQ(SOFTBUS_OK, ret);
    LnnDeinitLaneHub();
}

/*
* @tc.name: LNN_INIT_LANE_HUB_TEST_002
* @tc.desc: LnnInitLaneHub test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneHubTest, LNN_INIT_LANE_HUB_TEST_002, TestSize.Level1)
{
    NiceMock<LaneHubDepsInterfaceMock> laneHubMock;
    EXPECT_CALL(laneHubMock, InitLane).WillOnce(Return(SOFTBUS_NO_INIT));

    int32_t ret = LnnInitLaneHub();
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
* @tc.name: LNN_INIT_LANE_HUB_TEST_003
* @tc.desc: LnnInitLaneHub test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneHubTest, LNN_INIT_LANE_HUB_TEST_003, TestSize.Level1)
{
    NiceMock<LaneHubDepsInterfaceMock> laneHubMock;
    EXPECT_CALL(laneHubMock, InitLane).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(laneHubMock, LnnInitQos).WillOnce(Return(SOFTBUS_NO_INIT));

    int32_t ret = LnnInitLaneHub();
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
* @tc.name: LNN_INIT_LANE_HUB_TEST_004
* @tc.desc: LnnInitLaneHub test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneHubTest, LNN_INIT_LANE_HUB_TEST_004, TestSize.Level1)
{
    NiceMock<LaneHubDepsInterfaceMock> laneHubMock;
    EXPECT_CALL(laneHubMock, InitLane).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(laneHubMock, LnnInitQos).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(laneHubMock, LnnInitTimeSync).WillOnce(Return(SOFTBUS_LOOPER_ERR));

    int32_t ret = LnnInitLaneHub();
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
* @tc.name: LNN_INIT_LANE_HUB_TEST_005
* @tc.desc: LnnInitLaneHub test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneHubTest, LNN_INIT_LANE_HUB_TEST_005, TestSize.Level1)
{
    NiceMock<LaneHubDepsInterfaceMock> laneHubMock;
    EXPECT_CALL(laneHubMock, InitLane).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(laneHubMock, LnnInitQos).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(laneHubMock, LnnInitTimeSync).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(laneHubMock, LnnInitHeartbeat).WillOnce(Return(SOFTBUS_NETWORK_HB_INIT_STRATEGY_FAIL));

    int32_t ret = LnnInitLaneHub();
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

/*
* @tc.name: LNN_INIT_LANE_HUB_DELAY_TEST_001
* @tc.desc: LnnInitLaneHubDelay test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneHubTest, LNN_INIT_LANE_HUB_DELAY_TEST_001, TestSize.Level1)
{
    NiceMock<LaneHubDepsInterfaceMock> laneHubMock;
    EXPECT_CALL(laneHubMock, LnnStartHeartbeatFrameDelay).WillOnce(Return(SOFTBUS_OK));

    int32_t ret = LnnInitLaneHubDelay();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: LNN_INIT_LANE_HUB_DELAY_TEST_002
* @tc.desc: LnnInitLaneHubDelay test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneHubTest, LNN_INIT_LANE_HUB_DELAY_TEST_002, TestSize.Level1)
{
    NiceMock<LaneHubDepsInterfaceMock> laneHubMock;
    EXPECT_CALL(laneHubMock, LnnStartHeartbeatFrameDelay).WillOnce(Return(SOFTBUS_NO_INIT));

    int32_t ret = LnnInitLaneHubDelay();
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);
}

} // namespace OHOS