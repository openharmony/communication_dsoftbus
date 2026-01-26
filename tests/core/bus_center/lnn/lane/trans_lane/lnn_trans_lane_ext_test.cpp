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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>
#include <thread>

#include "lnn_trans_free_lane.c"
#include "lnn_trans_free_lane.h"
#include "lnn_trans_lane_ext_mock.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr uint64_t TEST_TIME_1 = 1;
constexpr uint64_t TEST_TIME_2 = 2;
constexpr uint32_t REQ_ID = 268435455;
constexpr uint64_t LANE_ID = 1773343659161363072;
constexpr const char NODE_NETWORK_ID[] = "123456789";
static bool g_freeLaneNotified;

class LNNTransLaneExtTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNTransLaneExtTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LNNTransLaneExtTest start";
}

void LNNTransLaneExtTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "LNNTransLaneExtTest end";
}

void LNNTransLaneExtTest::SetUp()
{
}

void LNNTransLaneExtTest::TearDown()
{
}

static void OnLaneFreeSuccess(uint32_t laneHandle)
{
    (void)laneHandle;
    g_freeLaneNotified = true;
    GTEST_LOG_(INFO) << "free lane success, laneReqId=" << laneHandle;
}

static void OnLaneFreeFail(uint32_t laneHandle, int32_t errCode)
{
    (void)laneHandle;
    (void)errCode;
    g_freeLaneNotified = true;
    GTEST_LOG_(INFO) << "free lane failed, laneReqId=" << laneHandle << ", errCode=" << errCode;
}

/*
 * @tc.name: LNN_TRANS_LANE_EXT_001
 * @tc.desc: HandelNotifyFreeLaneResult
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneExtTest, LNN_TRANS_LANE_EXT_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(HandelNotifyFreeLaneResult(nullptr));
    EXPECT_NO_FATAL_FAILURE(ReportLaneEventWithFreeLinkInfo(REQ_ID, SOFTBUS_INVALID_PARAM));
}

/*
 * @tc.name: LNN_TRANS_LANE_EXT_002
 * @tc.desc: GetCostTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneExtTest, LNN_TRANS_LANE_EXT_002, TestSize.Level1)
{
    NiceMock<TransLaneExtInterfaceMock> transMock;
    EXPECT_CALL(transMock, SoftBusGetSysTimeMs).WillRepeatedly(Return(TEST_TIME_1));
    uint64_t ret = GetCostTime(TEST_TIME_2);
    EXPECT_EQ(ret, 0);
}

/*
 * @tc.name: LNN_TRANS_LANE_EXT_003
 * @tc.desc: NotifyFreeLaneResult
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneExtTest, LNN_TRANS_LANE_EXT_003, TestSize.Level1)
{
    TransReqInfo reqInfo = {
        .notifyFree = false,
        .isWithQos = false,
        .hasNotifiedFree = false,
        .listener.onLaneFreeSuccess = OnLaneFreeSuccess,
        .listener.onLaneFreeFail = OnLaneFreeFail,
    };
    NiceMock<TransLaneExtInterfaceMock> transMock;
    EXPECT_CALL(transMock, GetTransReqInfoByLaneReqId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(reqInfo), Return(SOFTBUS_OK)));
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(INVALID_LANE_REQ_ID, SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(REQ_ID, SOFTBUS_OK));

    reqInfo.notifyFree = true;
    reqInfo.isWithQos = true;
    EXPECT_CALL(transMock, GetTransReqInfoByLaneReqId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(reqInfo), Return(SOFTBUS_OK)));
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(REQ_ID, SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(REQ_ID, SOFTBUS_OK));
}

/*
 * @tc.name: LNN_TRANS_LANE_EXT_004
 * @tc.desc: AsyncNotifyWhenDelayFree
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneExtTest, LNN_TRANS_LANE_EXT_004, TestSize.Level1)
{
    TransReqInfo reqInfo = {
        .isWithQos = false,
        .listener.onLaneFreeSuccess = nullptr,
    };
    LaneResource resourceItem = {
        .link.type = LANE_HML,
    };

    NiceMock<TransLaneExtInterfaceMock> transMock;
    EXPECT_CALL(transMock, GetTransReqInfoByLaneReqId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(reqInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(transMock, FindLaneResourceByLaneId).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(AsyncNotifyWhenDelayFree(REQ_ID));

    EXPECT_CALL(transMock, FindLaneResourceByLaneId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(resourceItem), Return(SOFTBUS_OK)));
    EXPECT_NO_FATAL_FAILURE(AsyncNotifyWhenDelayFree(REQ_ID));

    reqInfo.isWithQos = true;
    reqInfo.listener.onLaneFreeSuccess = OnLaneFreeSuccess;
    EXPECT_CALL(transMock, GetTransReqInfoByLaneReqId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(reqInfo), Return(SOFTBUS_OK)));
    EXPECT_NO_FATAL_FAILURE(AsyncNotifyWhenDelayFree(REQ_ID));

    resourceItem.link.type = LANE_P2P;
    reqInfo.isWithQos = false;
    reqInfo.listener.onLaneFreeSuccess = nullptr;
    EXPECT_CALL(transMock, GetTransReqInfoByLaneReqId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(reqInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(transMock, FindLaneResourceByLaneId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(resourceItem), Return(SOFTBUS_OK)));
    EXPECT_NO_FATAL_FAILURE(AsyncNotifyWhenDelayFree(REQ_ID));
}

/*
 * @tc.name: LNN_TRANS_LANE_EXT_005
 * @tc.desc: HandleDelayDestroyLink
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneExtTest, LNN_TRANS_LANE_EXT_005, TestSize.Level1)
{
    SoftBusMessage msg = {
        .arg1 = REQ_ID,
        .arg2 = LANE_ID,
    };
    LaneResource resourceItem = {
        .link.type = LANE_P2P,
        .clientRef = 1,
    };
    NiceMock<TransLaneExtInterfaceMock> transMock;
    EXPECT_CALL(transMock, FindLaneResourceByLaneId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(resourceItem), Return(SOFTBUS_OK)));
    EXPECT_CALL(transMock, LnnGetNetworkIdByUdid).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transMock, DestroyLink).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(HandleDelayDestroyLink(nullptr));
    EXPECT_NO_FATAL_FAILURE(HandleDelayDestroyLink(&msg));
}

/*
 * @tc.name: LNN_TRANS_LANE_EXT_006
 * @tc.desc: GetAuthType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneExtTest, LNN_TRANS_LANE_EXT_006, TestSize.Level1)
{
    NiceMock<TransLaneExtInterfaceMock> transMock;
    EXPECT_CALL(transMock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    bool ret = GetAuthType(NODE_NETWORK_ID);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: LNN_TRANS_LANE_EXT_007
 * @tc.desc: IsNeedDelayFreeLane
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneExtTest, LNN_TRANS_LANE_EXT_007, TestSize.Level1)
{
    bool isDelayFree = false;
    LaneResource resourceItem = {
        .link.type = LANE_HML,
        .clientRef = 1,
    };
    NiceMock<TransLaneExtInterfaceMock> transMock;
    EXPECT_CALL(transMock, FindLaneResourceByLaneId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(resourceItem), Return(SOFTBUS_OK)));
    EXPECT_CALL(transMock, LnnConvertDlId).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(transMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<2>(1 << ONLINE_HICHAIN), Return(SOFTBUS_INVALID_PARAM)));
    EXPECT_CALL(transMock, HaveConcurrencyPreLinkNodeByLaneReqIdPacked).WillRepeatedly(Return(false));
    EXPECT_CALL(transMock, CheckLinkConflictByReleaseLink).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(transMock, CheckVirtualLinkByLaneReqId).WillRepeatedly(Return(true));
    EXPECT_NO_FATAL_FAILURE(IsNeedDelayFreeLane(REQ_ID, LANE_ID, &isDelayFree));

    EXPECT_CALL(transMock, CheckVirtualLinkByLaneReqId).WillRepeatedly(Return(false));
    EXPECT_CALL(transMock, PostDelayDestroyMessage).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(IsNeedDelayFreeLane(REQ_ID, LANE_ID, &isDelayFree));

    EXPECT_CALL(transMock, PostDelayDestroyMessage).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(IsNeedDelayFreeLane(REQ_ID, LANE_ID, &isDelayFree));
}

/*
 * @tc.name: LNN_TRANS_LANE_EXT_008
 * @tc.desc: FreeLink
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneExtTest, LNN_TRANS_LANE_EXT_008, TestSize.Level1)
{
    LaneResource resourceItem = {
        .link.type = LANE_HML,
        .clientRef = 1,
    };
    NiceMock<TransLaneExtInterfaceMock> transMock;
    EXPECT_CALL(transMock, FindLaneResourceByLaneId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(resourceItem), Return(SOFTBUS_OK)));
    EXPECT_CALL(transMock, LnnConvertDlId).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(transMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<2>(1 << ONLINE_HICHAIN), Return(SOFTBUS_INVALID_PARAM)));
    EXPECT_CALL(transMock, HaveConcurrencyPreLinkNodeByLaneReqIdPacked).WillRepeatedly(Return(false));
    EXPECT_CALL(transMock, CheckLinkConflictByReleaseLink).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(transMock, CheckVirtualLinkByLaneReqId).WillRepeatedly(Return(false));
    EXPECT_CALL(transMock, PostDelayDestroyMessage).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = FreeLink(REQ_ID, LANE_ID, LANE_TYPE_TRANS);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: LNN_TRANS_LANE_EXT_009
 * @tc.desc: FreeLane
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneExtTest, LNN_TRANS_LANE_EXT_009, TestSize.Level1)
{
    LaneResource resourceItem = {
        .link.type = LANE_HML,
        .clientRef = 1,
    };
    TransReqInfo transReqInfo = {
        .laneId = LANE_ID,
    };
    NiceMock<TransLaneExtInterfaceMock> transMock;
    EXPECT_CALL(transMock, FindLaneResourceByLaneId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(resourceItem), Return(SOFTBUS_OK)));
    EXPECT_CALL(transMock, LnnConvertDlId).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(transMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<2>(1 << ONLINE_HICHAIN), Return(SOFTBUS_INVALID_PARAM)));
    EXPECT_CALL(transMock, HaveConcurrencyPreLinkNodeByLaneReqIdPacked).WillRepeatedly(Return(false));
    EXPECT_CALL(transMock, CheckLinkConflictByReleaseLink).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(transMock, CheckVirtualLinkByLaneReqId).WillRepeatedly(Return(false));
    EXPECT_CALL(transMock, PostDelayDestroyMessage).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));

    int32_t ret = FreeLane(INVALID_LANE_REQ_ID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(transMock, UpdateAndGetReqInfoByFree).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(transMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = FreeLane(INVALID_LANE_REQ_ID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(transMock, GetTransReqInfoByLaneReqId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(transReqInfo), Return(SOFTBUS_OK)));
    ret = FreeLane(INVALID_LANE_REQ_ID);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_TRANS_LANE_EXT_010
 * @tc.desc: FreeUnusedLink
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneExtTest, LNN_TRANS_LANE_EXT_010, TestSize.Level1)
{
    LaneLinkInfo linkInfo = {
        .type = LANE_BR,
    };
    EXPECT_NO_FATAL_FAILURE(FreeUnusedLink(REQ_ID, &linkInfo));
}

/*
 * @tc.name: LNN_NOTIFY_FREE_LANE_RESULT_001
 * @tc.desc: NotifyFreeLaneResult test isWithQos and hasNotifiedFree
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneExtTest, LNN_NOTIFY_FREE_LANE_RESULT_001, TestSize.Level1)
{
    TransReqInfo reqInfo = {
        .notifyFree = true,
        .isWithQos = false,
        .hasNotifiedFree = false,
        .isCanceled = false,
        .listener.onLaneFreeSuccess = OnLaneFreeSuccess,
        .listener.onLaneFreeFail = OnLaneFreeFail,
    };
    NiceMock<TransLaneExtInterfaceMock> transMock;
    EXPECT_CALL(transMock, GetTransReqInfoByLaneReqId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(reqInfo), Return(SOFTBUS_OK)));
    g_freeLaneNotified = false;
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(REQ_ID, SOFTBUS_OK));
    EXPECT_FALSE(g_freeLaneNotified);
    g_freeLaneNotified = false;
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(REQ_ID, SOFTBUS_LANE_ALLOC_NOT_COMPLETED));
    EXPECT_FALSE(g_freeLaneNotified);

    reqInfo.isWithQos = true;
    EXPECT_CALL(transMock, GetTransReqInfoByLaneReqId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(reqInfo), Return(SOFTBUS_OK)));
    g_freeLaneNotified = false;
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(REQ_ID, SOFTBUS_OK));
    EXPECT_TRUE(g_freeLaneNotified);
    g_freeLaneNotified = false;
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(REQ_ID, SOFTBUS_LANE_ALLOC_NOT_COMPLETED));
    EXPECT_TRUE(g_freeLaneNotified);

    reqInfo.hasNotifiedFree = true;
    EXPECT_CALL(transMock, GetTransReqInfoByLaneReqId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(reqInfo), Return(SOFTBUS_OK)));
    g_freeLaneNotified = false;
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(REQ_ID, SOFTBUS_OK));
    EXPECT_FALSE(g_freeLaneNotified);
    g_freeLaneNotified = false;
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(REQ_ID, SOFTBUS_LANE_ALLOC_NOT_COMPLETED));
    EXPECT_FALSE(g_freeLaneNotified);
}

/*
 * @tc.name: LNN_NOTIFY_FREE_LANE_RESULT_002
 * @tc.desc: NotifyFreeLaneResult test notifyFree
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneExtTest, LNN_NOTIFY_FREE_LANE_RESULT_002, TestSize.Level1)
{
    TransReqInfo reqInfo = {
        .notifyFree = false,
        .isWithQos = true,
        .hasNotifiedFree = false,
        .isCanceled = true,
        .listener.onLaneFreeSuccess = OnLaneFreeSuccess,
        .listener.onLaneFreeFail = OnLaneFreeFail,
    };
    NiceMock<TransLaneExtInterfaceMock> transMock;
    EXPECT_CALL(transMock, GetTransReqInfoByLaneReqId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(reqInfo), Return(SOFTBUS_OK)));
    g_freeLaneNotified = false;
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(REQ_ID, SOFTBUS_OK));
    EXPECT_FALSE(g_freeLaneNotified);
    g_freeLaneNotified = false;
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(REQ_ID, SOFTBUS_LANE_ALLOC_NOT_COMPLETED));
    EXPECT_FALSE(g_freeLaneNotified);

    reqInfo.listener.onLaneFreeSuccess = nullptr;
    reqInfo.listener.onLaneFreeFail = nullptr;
    EXPECT_CALL(transMock, GetTransReqInfoByLaneReqId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(reqInfo), Return(SOFTBUS_OK)));
    g_freeLaneNotified = false;
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(REQ_ID, SOFTBUS_OK));
    EXPECT_FALSE(g_freeLaneNotified);
    g_freeLaneNotified = false;
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(REQ_ID, SOFTBUS_LANE_ALLOC_NOT_COMPLETED));
    EXPECT_FALSE(g_freeLaneNotified);

    reqInfo.isCanceled = false;
    EXPECT_CALL(transMock, GetTransReqInfoByLaneReqId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(reqInfo), Return(SOFTBUS_OK)));
    g_freeLaneNotified = false;
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(REQ_ID, SOFTBUS_OK));
    EXPECT_FALSE(g_freeLaneNotified);

    reqInfo.isWithQos = false;
    EXPECT_CALL(transMock, GetTransReqInfoByLaneReqId)
        .WillRepeatedly(DoAll(SetArgPointee<1>(reqInfo), Return(SOFTBUS_OK)));
    g_freeLaneNotified = false;
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(REQ_ID, SOFTBUS_OK));
    EXPECT_FALSE(g_freeLaneNotified);
}
} // namespace OHOS