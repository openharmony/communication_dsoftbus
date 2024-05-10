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

#include "lnn_trans_lane.h"

#include "lnn_lane_deps_mock.h"
#include "lnn_lane_score_virtual.c"
#include "lnn_trans_lane_deps_mock.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr uint32_t LANE_REQ_ID = 111;
constexpr int32_t CHANNEL_ID = 5;
constexpr int32_t INTERVAL = 2;
constexpr uint32_t LIST_SIZE = 10;
const char PEER_UDID[] = "111122223333abcdef";
const char PEER_IP[] = "127.30.0.1";
static int32_t g_errCode = 0;

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

static void OnLaneAllocSuccess(uint32_t laneHandle, const LaneConnInfo *info)
{
    (void)laneHandle;
    ASSERT_NE(info, nullptr) << "invalid connInfo";
    GTEST_LOG_(INFO) << "alloc lane successful, linkType=" << info->type;
    EXPECT_EQ(info->type, LANE_P2P);
}

static void OnLaneAllocFail(uint32_t laneHandle, int32_t errCode)
{
    GTEST_LOG_(INFO) << "alloc lane failed, laneReqId=" << laneHandle << ", errCode=" << errCode;
    EXPECT_NE(errCode, SOFTBUS_OK);
    g_errCode = errCode;
    const LnnLaneManager *laneManager = GetLaneManager();
    (void)laneManager->lnnFreeLane(laneHandle);
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
    transObj->init(nullptr);

    uint32_t laneReqId = 1;
    int32_t ret = transObj->allocLane(laneReqId, nullptr, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    LaneRequestOption request;
    request.type = LANE_TYPE_BUTT;
    ret = transObj->allocLane(laneReqId, (const LaneRequestOption *)&request, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    transObj->deinit();
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
    transObj->init(nullptr);
    uint32_t laneReqId = 1;
    LaneRequestOption request;
    request.type = LANE_TYPE_TRANS;
    EXPECT_CALL(laneMock, SelectLane).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = transObj->allocLane(laneReqId, (const LaneRequestOption *)&request, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    transObj->deinit();
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
    transObj->init(nullptr);
    uint32_t laneReqId = 1;
    LaneAllocInfo allocInfo;
    allocInfo.type = LANE_TYPE_TRANS;
    EXPECT_CALL(laneMock, SelectExpectLaneByParameter).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(laneMock, SelectExpectLanesByQos).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_LANE_SELECT_FAIL);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    transObj->deinit();
}

/*
* @tc.name: LNN_TRANS_LANE_004
* @tc.desc: Callback process errCode
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_TRANS_LANE_004, TestSize.Level1)
{
    LaneDepsInterfaceMock mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    TransLaneDepsInterfaceMock laneMock;
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->init(nullptr);

    uint32_t laneReqId = 1;
    LaneAllocInfo allocInfo;
    allocInfo.type = LANE_TYPE_TRANS;
    LaneAllocListener listenerCb = {
        .onLaneAllocSuccess = OnLaneAllocSuccess,
        .onLaneAllocFail = OnLaneAllocFail,
    };
    LanePreferredLinkList recommendLinkList;
    (void)memset_s(&recommendLinkList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_WLAN_2P4G;
    EXPECT_CALL(laneMock, SelectExpectLaneByParameter).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(laneMock, SelectExpectLanesByQos).
        WillRepeatedly(DoAll(SetArgPointee<2>(recommendLinkList), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink(_, _, NotNull())).WillRepeatedly(laneMock.ActionOfLaneLinkSuccess);
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    EXPECT_EQ(g_errCode, SOFTBUS_LANE_TRIGGER_LINK_FAIL);
    transObj->deinit();
}

/*
* @tc.name: LNN_TRANS_LANE_005
* @tc.desc: Callback process errCode
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_TRANS_LANE_005, TestSize.Level1)
{
    LaneDepsInterfaceMock mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    TransLaneDepsInterfaceMock laneMock;
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->init(nullptr);

    uint32_t laneReqId = 1;
    LaneAllocInfo allocInfo;
    allocInfo.type = LANE_TYPE_TRANS;
    LaneAllocListener listenerCb = {
        .onLaneAllocSuccess = OnLaneAllocSuccess,
        .onLaneAllocFail = OnLaneAllocFail,
    };
    LanePreferredLinkList recommendLinkList;
    (void)memset_s(&recommendLinkList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_WLAN_2P4G;
    EXPECT_CALL(laneMock, SelectExpectLaneByParameter).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(laneMock, SelectExpectLanesByQos).
        WillRepeatedly(DoAll(SetArgPointee<2>(recommendLinkList), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink(_, _, NotNull())).WillRepeatedly(laneMock.ActionOfLaneLinkFail);
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    EXPECT_EQ(g_errCode, SOFTBUS_LANE_ID_GENERATE_FAIL);
    transObj->deinit();
}

/*
* @tc.name: LNN_TRANS_LANE_006
* @tc.desc: Callback process errCode
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_TRANS_LANE_006, TestSize.Level1)
{
    LaneDepsInterfaceMock mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    TransLaneDepsInterfaceMock laneMock;
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->init(nullptr);

    uint32_t laneReqId = 1;
    LaneAllocInfo allocInfo;
    allocInfo.type = LANE_TYPE_TRANS;
    LaneAllocListener listenerCb = {
        .onLaneAllocSuccess = OnLaneAllocSuccess,
        .onLaneAllocFail = OnLaneAllocFail,
    };
    LanePreferredLinkList recommendLinkList;
    (void)memset_s(&recommendLinkList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_WLAN_2P4G;
    EXPECT_CALL(laneMock, SelectExpectLaneByParameter).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(laneMock, SelectExpectLanesByQos)
        .WillRepeatedly(DoAll(SetArgPointee<2>(recommendLinkList), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink).WillRepeatedly(Return(SOFTBUS_LANE_DETECT_FAIL));
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    EXPECT_EQ(g_errCode, SOFTBUS_LANE_DETECT_FAIL);
    transObj->deinit();
}

/*
* @tc.name: LNN_LANE_SCORE_VIRTUAL_001
* @tc.desc: lnn_lane_score_virtual.c
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_LANE_SCORE_VIRTUAL_001, TestSize.Level1)
{
    uint32_t listSize = LIST_SIZE;
    int32_t ret = LnnInitScore();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDeinitScore();
    ret = LnnGetWlanLinkedInfo(nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = LnnGetCurrChannelScore(CHANNEL_ID);
    EXPECT_TRUE(ret == VIRTUAL_DEFAULT_SCORE);
    ret = LnnStartScoring(INTERVAL);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnStopScoring();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnGetAllChannelScore(nullptr, &listSize);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_POST_LANE_STATE_CHANGE_MESSAGE_001
* @tc.desc: PostLaneStateChangeMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_LANE_POST_LANE_STATE_CHANGE_MESSAGE_001, TestSize.Level1)
{
    LaneLinkInfo laneLinkInfo;
    (void)memset_s(&laneLinkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    laneLinkInfo.type = LANE_HML;
    (void)strncpy_s(laneLinkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP, IP_LEN);

    LaneDepsInterfaceMock laneMock;
    EXPECT_CALL(laneMock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    TransLaneDepsInterfaceMock transLaneMock;
    EXPECT_CALL(transLaneMock, LaneLinkupNotify).WillRepeatedly(Return(SOFTBUS_OK));
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->init(nullptr);
    int32_t ret = PostLaneStateChangeMessage(LANE_STATE_LINKUP, PEER_UDID, &laneLinkInfo);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    transObj->deinit();
}

/*
* @tc.name: LNN_LANE_POST_LANE_STATE_CHANGE_MESSAGE_002
* @tc.desc: PostLaneStateChangeMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_LANE_POST_LANE_STATE_CHANGE_MESSAGE_002, TestSize.Level1)
{
    LaneLinkInfo laneLinkInfo;
    (void)memset_s(&laneLinkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    laneLinkInfo.type = LANE_HML;
    (void)strncpy_s(laneLinkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP, IP_LEN);

    LaneDepsInterfaceMock laneMock;
    EXPECT_CALL(laneMock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    TransLaneDepsInterfaceMock transLaneMock;
    EXPECT_CALL(transLaneMock, LaneLinkdownNotify).WillRepeatedly(Return(SOFTBUS_OK));
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->init(nullptr);
    int32_t ret = PostLaneStateChangeMessage(LANE_STATE_LINKDOWN, PEER_UDID, &laneLinkInfo);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    transObj->deinit();
}

/*
* @tc.name: LNN_LANE_DELETE_LANE_BUSINESS_INFO_001
* @tc.desc: DeleteLaneBusinessInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_LANE_DELETE_LANE_BUSINESS_INFO_001, TestSize.Level1)
{
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    LaneDepsInterfaceMock laneMock;
    EXPECT_CALL(laneMock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    transObj->init(nullptr);
    TransLaneDepsInterfaceMock transLaneMock;
    EXPECT_CALL(transLaneMock, DelLaneBusinessInfoItem).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = transObj->freeLane(LANE_REQ_ID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    transObj->deinit();
}
} // namespace OHOS