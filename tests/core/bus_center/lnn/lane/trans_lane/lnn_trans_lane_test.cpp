/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <thread>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_lane_common.h"
#include "lnn_lane_deps_mock.h"
#include "lnn_trans_lane_deps_mock.h"
#include "lnn_lane_interface.h"
#include "lnn_trans_lane.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class LNNTransLaneMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNTransLaneMockTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LNNTransLaneMockTest start";
    LnnInitLaneLooper();
}

void LNNTransLaneMockTest::TearDownTestCase()
{
    LnnDeinitLaneLooper();
    GTEST_LOG_(INFO) << "LNNTransLaneMockTest end";
}

void LNNTransLaneMockTest::SetUp()
{
}

void LNNTransLaneMockTest::TearDown()
{
}

/*
* @tc.name: LNN_TRANS_LANE_001
* @tc.desc: Init
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_TRANS_LANE_001, TestSize.Level1)
{
    LaneDepsInterfaceMock mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->Init(nullptr);

    uint32_t laneId = 1;
    int32_t ret = transObj->AllocLane(laneId, nullptr, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    LaneRequestOption request;
    request.type = LANE_TYPE_BUTT;
    ret = transObj->AllocLane(laneId, (const LaneRequestOption *)&request, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    transObj->Deinit();
}

/*
* @tc.name: LNN_TRANS_LANE_002
* @tc.desc: Callback process
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_TRANS_LANE_002, TestSize.Level1)
{
    LaneDepsInterfaceMock mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    TransLaneDepsInterfaceMock laneMock;
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->Init(nullptr);
    uint32_t laneId = 1;
    LaneRequestOption request;
    request.type = LANE_TYPE_TRANS;
    EXPECT_CALL(laneMock, SelectLane).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = transObj->AllocLane(laneId, (const LaneRequestOption *)&request, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    /*
    auto laneSelect = [](LaneLinkType **list, uint32_t *num) {
        uint32_t laneNum = 2; // means two phy-channels are available
        *list = (LaneLinkType *)SoftBusMalloc(sizeof(LaneLinkType) * laneNum);
        EXPECT_TRUE(*list != nullptr);
        (*list)[0] = LANE_P2P;
        (*list)[1] = LANE_WLAN_5G;
        *num = laneNum;
    };
    auto linkFail = [](const LaneLinkCb *cb) { cb->OnLaneLinkFail(1, SOFTBUS_ERR); };
    EXPECT_CALL(laneMock, SelectLane)
        .WillOnce(DoAll(WithArgs<2, 3>(laneSelect), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink)
        .WillRepeatedly(DoAll(WithArg<2>(linkFail), Return(SOFTBUS_OK)));
    ILaneListener listener = {
        .OnLaneRequestSuccess = LaneRequestSuccess,
        .OnLaneRequestFail = LaneRequestFail,
        .OnLaneStateChange = LaneStateChange,
    };
    ret = transObj->AllocLane(laneId, (const LaneRequestOption *)&request, &listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    */
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    transObj->Deinit();
}

/*
* @tc.name: LNN_TRANS_LANE_003
* @tc.desc: Callback process
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_TRANS_LANE_003, TestSize.Level1)
{
    LaneDepsInterfaceMock mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    TransLaneDepsInterfaceMock laneMock;
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->Init(nullptr);
    uint32_t laneId = 1;
    LaneRequestOption request;
    request.type = LANE_TYPE_TRANS;
    EXPECT_CALL(laneMock, SelectExpectLanesByQos).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = transObj->allocLaneByQos(laneId, (const LaneRequestOption *)&request, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    transObj->Deinit();
}
} // namespace OHOS