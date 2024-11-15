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

#include "lnn_lane_deps_mock.h"
#include "lnn_lane_score_virtual.c"
#include "lnn_trans_lane.h"
#include "lnn_trans_lane_deps_mock.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr uint32_t LANE_REQ_ID = 111;
constexpr uint32_t NEW_LANE_REQ_ID = 112;
constexpr int32_t CHANNEL_ID = 5;
constexpr int32_t INTERVAL = 2;
constexpr uint32_t LIST_SIZE = 10;
constexpr char PEER_UDID[] = "111122223333abcdef";
constexpr char PEER_IP[] = "127.30.0.1";
constexpr char NODE_NETWORK_ID[] = "123456789";
constexpr uint64_t LANE_ID_BASE = 1122334455667788;
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
    LnnInitLnnLooper();
}

void LNNTransLaneMockTest::TearDownTestCase()
{
    LnnDeinitLnnLooper();
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
    LaneInterface *transObj = TransLaneGetInstance();
    (void)transObj->freeLane(laneHandle);
}

static void OnLaneFreeSuccess(uint32_t laneHandle)
{
    GTEST_LOG_(INFO) << "free lane success, laneReqId=" << laneHandle;
}

static void OnLaneFreeFail(uint32_t laneHandle, int32_t errCode)
{
    GTEST_LOG_(INFO) << "free lane failed, laneReqId=" << laneHandle << ", errCode=" << errCode;
}

static void OnLaneRequestSuccess(uint32_t laneReqId, const LaneConnInfo *info)
{
    (void)info;
    GTEST_LOG_(INFO) << "onLaneRequestSuccess enter, laneReqId=" << laneReqId;
}

static void OnLaneRequestFail(uint32_t laneReqId, int32_t errCode)
{
    GTEST_LOG_(INFO) << "onLaneRequestFail enter, laneReqId=" << laneReqId << ", errCode=" << errCode;
}

static void OnLaneAllocSuccessHml(uint32_t laneHandle, const LaneConnInfo *info)
{
    (void)laneHandle;
    ASSERT_NE(info, nullptr) << "invalid connInfo";
    GTEST_LOG_(INFO) << "alloc lane successful, linkType=" << info->type;
    EXPECT_EQ(info->type, LANE_HML);
}

static LaneAllocListener g_listenerCb = {
    .onLaneAllocSuccess = OnLaneAllocSuccess,
    .onLaneAllocFail = OnLaneAllocFail,
    .onLaneFreeSuccess = OnLaneFreeSuccess,
    .onLaneFreeFail = OnLaneFreeFail,
};

/*
* @tc.name: LNN_TRANS_LANE_001
* @tc.desc: Init
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_TRANS_LANE_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
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
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
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
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->init(nullptr);
    uint32_t laneReqId = 1;
    LaneAllocInfo allocInfo;
    allocInfo.type = LANE_TYPE_TRANS;
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);
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
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->init(nullptr);

    uint32_t laneReqId = 1;
    LaneAllocInfo allocInfo;
    allocInfo.type = LANE_TYPE_TRANS;
    LanePreferredLinkList recommendLinkList;
    (void)memset_s(&recommendLinkList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_WLAN_2P4G;
    EXPECT_CALL(laneMock, SelectExpectLanesByQos).
        WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(recommendLinkList), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink(_, _, NotNull())).WillRepeatedly(laneMock.ActionOfLaneLinkSuccess);
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    EXPECT_EQ(g_errCode, SOFTBUS_LANE_ID_GENERATE_FAIL);
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
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->init(nullptr);

    uint32_t laneReqId = 1;
    LaneAllocInfo allocInfo;
    allocInfo.type = LANE_TYPE_TRANS;
    LanePreferredLinkList recommendLinkList;
    (void)memset_s(&recommendLinkList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_WLAN_2P4G;
    EXPECT_CALL(laneMock, SelectExpectLanesByQos).
        WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(recommendLinkList), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink(_, _, NotNull())).WillRepeatedly(laneMock.ActionOfLaneLinkFail);
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    EXPECT_EQ(g_errCode, SOFTBUS_LANE_TRIGGER_LINK_FAIL);
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
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->init(nullptr);

    uint32_t laneReqId = 1;
    LaneAllocInfo allocInfo;
    allocInfo.type = LANE_TYPE_TRANS;
    LanePreferredLinkList recommendLinkList;
    (void)memset_s(&recommendLinkList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_WLAN_2P4G;
    EXPECT_CALL(laneMock, SelectExpectLanesByQos)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(recommendLinkList), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink).WillRepeatedly(Return(SOFTBUS_LANE_DETECT_FAIL));
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    EXPECT_EQ(g_errCode, SOFTBUS_LANE_DETECT_FAIL);
    transObj->deinit();
}

/*
* @tc.name: LNN_TRANS_LANE_007
* @tc.desc: test alloc lane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_TRANS_LANE_007, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->init(nullptr);
    uint32_t laneReqId = 1;
    LaneRequestOption request = {};
    request.type = LANE_TYPE_TRANS;
    LanePreferredLinkList recommendLinkList = {};
    recommendLinkList.linkTypeNum = 1;
    recommendLinkList.linkType[0] = LANE_BR;
    EXPECT_CALL(laneMock, SelectLane)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(recommendLinkList), Return(SOFTBUS_OK)));
    ILaneListener listener = {
        .onLaneRequestSuccess = OnLaneRequestSuccess,
        .onLaneRequestFail = OnLaneRequestFail,
    };
    int32_t ret = transObj->allocLane(laneReqId, (const LaneRequestOption *)&request, &listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
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
    EXPECT_EQ(ret, SOFTBUS_LANE_SELECT_FAIL);
    ret = LnnGetCurrChannelScore(CHANNEL_ID);
    EXPECT_EQ(ret, VIRTUAL_DEFAULT_SCORE);
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

    NiceMock<LaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(laneMock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransLaneDepsInterfaceMock> transLaneMock;
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

    NiceMock<LaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(laneMock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransLaneDepsInterfaceMock> transLaneMock;
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
    NiceMock<LaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(laneMock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    transObj->init(nullptr);
    NiceMock<TransLaneDepsInterfaceMock> transLaneMock;
    EXPECT_CALL(transLaneMock, DelLaneBusinessInfoItem).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = transObj->freeLane(LANE_REQ_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
    transObj->deinit();
}

/*
* @tc.name: ALLOC_TARGET_LANE_TEST_001
* @tc.desc: AllocTargetLane test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, ALLOC_TARGET_LANE_TEST_001, TestSize.Level1)
{
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    NiceMock<LaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(laneMock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    transObj->init(nullptr);
    LaneAllocInfoExt allocInfo = { .type = LANE_TYPE_TRANS, .linkList.linkTypeNum = LANE_HML_RAW, };
    EXPECT_EQ(EOK, strcpy_s(allocInfo.commInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));
    LaneAllocListener listener;
    (void)memset_s(&listener, sizeof(LaneAllocListener), 0, sizeof(LaneAllocListener));
    int32_t ret = transObj->allocTargetLane(LANE_REQ_ID, nullptr, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = transObj->allocTargetLane(LANE_REQ_ID, &allocInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = transObj->allocTargetLane(INVALID_LANE_REQ_ID, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    allocInfo.linkList.linkTypeNum = LANE_LINK_TYPE_BUTT;
    ret = transObj->allocTargetLane(LANE_REQ_ID, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    allocInfo.type = LANE_TYPE_CTRL;
    ret = transObj->allocTargetLane(LANE_REQ_ID, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    transObj->deinit();
}

/*
* @tc.name: ALLOC_LANE_BY_QOS_TEST_001
* @tc.desc: AllocLaneByQos test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, ALLOC_LANE_BY_QOS_TEST_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->init(nullptr);
    uint32_t laneReqId = 1;
    LaneAllocInfo allocInfo = {
        .type = LANE_TYPE_TRANS,
        .extendInfo.isSpecifiedLink = true,
        .extendInfo.linkType = LANE_LINK_TYPE_WIFI_WLAN,
    };
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));
    LanePreferredLinkList recommendLinkList;
    (void)memset_s(&recommendLinkList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_WLAN_2P4G;
    EXPECT_CALL(laneMock, SelectExpectLanesByQos)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(recommendLinkList), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink).WillRepeatedly(Return(SOFTBUS_LANE_DETECT_FAIL));
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    allocInfo.extendInfo.linkType = LANE_LINK_TYPE_WIFI_P2P;
    ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    allocInfo.extendInfo.linkType = LANE_LINK_TYPE_BR;
    ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    allocInfo.extendInfo.linkType = LANE_LINK_TYPE_COC_DIRECT;
    ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    allocInfo.extendInfo.linkType = LANE_LINK_TYPE_BLE_DIRECT;
    ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    allocInfo.extendInfo.linkType = LANE_LINK_TYPE_HML;
    ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    transObj->deinit();
}

/*
* @tc.name: ALLOC_RAW_LANE_TEST_001
* @tc.desc: AllocRawLane test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, ALLOC_RAW_LANE_TEST_001, TestSize.Level1)
{
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    NiceMock<LaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(laneMock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    RawLaneAllocInfo allocInfo = { .type = LANE_TYPE_TRANS };
    LaneAllocListener listener;
    (void)memset_s(&listener, sizeof(LaneAllocListener), 0, sizeof(LaneAllocListener));
    int32_t ret = transObj->allocRawLane(LANE_REQ_ID, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    ret = transObj->allocRawLane(LANE_REQ_ID, &allocInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = transObj->allocRawLane(LANE_REQ_ID, nullptr, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    allocInfo.type = LANE_TYPE_CTRL;
    ret = transObj->allocRawLane(LANE_REQ_ID, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UpdateReqListLaneId(LANE_REQ_ID, NEW_LANE_REQ_ID);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
    NotifyFreeLaneResult(LANE_REQ_ID, SOFTBUS_LOCK_ERR);
    NotifyFreeLaneResult(NEW_LANE_REQ_ID, SOFTBUS_LOCK_ERR);
    transObj->deinit();
}

/*
* @tc.name: LNN_FREE_LANE_DELAY_DESTROY_TEST_001
* @tc.desc: freeLane delay destroy test -> checkLinkConflict
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_FREE_LANE_DELAY_DESTROY_TEST_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->init(nullptr);
    LaneAllocInfo allocInfo = {
        .type = LANE_TYPE_TRANS,
        .extendInfo.linkType = LANE_LINK_TYPE_HML,
    };
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));
    LanePreferredLinkList recommendLinkList = {};
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_HML;
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(laneMock, SelectExpectLanesByQos)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(recommendLinkList), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink(_, _, NotNull())).WillRepeatedly(laneMock.ActionOfLaneLinkSuccess);
    EXPECT_CALL(laneMock, DestroyLink).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, DelLaneBusinessInfoItem).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, AddLaneBusinessInfoItem).WillRepeatedly(Return(SOFTBUS_OK));
    LaneResource resourceItem = {};
    resourceItem.link.type = LANE_HML;
    resourceItem.clientRef = 1;
    EXPECT_CALL(laneMock, FindLaneResourceByLaneId)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(resourceItem), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, DelLaneResourceByLaneId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, AddLaneResourceToPool).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, GenerateLaneId).WillRepeatedly(Return(LANE_ID_BASE));
    EXPECT_CALL(laneMock, CheckLinkConflictByReleaseLink).WillRepeatedly(Return(SOFTBUS_OK));
    g_listenerCb.onLaneAllocSuccess = OnLaneAllocSuccessHml;
    uint32_t laneReqId = 11;
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = transObj->freeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    laneReqId = 12;
    ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = transObj->freeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(3500)); // delay 3500ms for looper completion.
    transObj->deinit();
}

/*
* @tc.name: LNN_FREE_LANE_DELAY_DESTROY_TEST_002
* @tc.desc: freeLane delay destroy test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_FREE_LANE_DELAY_DESTROY_TEST_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->init(nullptr);
    LaneAllocInfo allocInfo = {
        .type = LANE_TYPE_TRANS,
        .extendInfo.linkType = LANE_LINK_TYPE_HML,
    };
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));
    LanePreferredLinkList recommendLinkList = {};
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_HML;
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(laneMock, SelectExpectLanesByQos)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(recommendLinkList), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink(_, _, NotNull())).WillRepeatedly(laneMock.ActionOfLaneLinkSuccess);
    EXPECT_CALL(laneMock, DestroyLink).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, DelLaneBusinessInfoItem).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, AddLaneBusinessInfoItem).WillRepeatedly(Return(SOFTBUS_OK));
    LaneResource resourceItem = {};
    resourceItem.link.type = LANE_HML;
    resourceItem.clientRef = 1;
    EXPECT_CALL(laneMock, FindLaneResourceByLaneId)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(resourceItem), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, DelLaneResourceByLaneId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, AddLaneResourceToPool).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, GenerateLaneId).WillRepeatedly(Return(LANE_ID_BASE));
    EXPECT_CALL(laneMock, CheckLinkConflictByReleaseLink).WillRepeatedly(Return(SOFTBUS_OK));
    g_listenerCb.onLaneAllocSuccess = OnLaneAllocSuccessHml;
    uint32_t laneReqId = 21;
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = transObj->freeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    laneReqId = 22;
    ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = transObj->freeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 3500ms for looper completion.
    transObj->deinit();
}

/*
* @tc.name: LNN_FREE_LANE_DELAY_DESTROY_TEST_003
* @tc.desc: freeLane remove delay destroy test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_FREE_LANE_DELAY_DESTROY_TEST_003, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->init(nullptr);
    uint32_t laneReqId = 31;
    LaneAllocInfo allocInfo = {
        .type = LANE_TYPE_TRANS,
        .extendInfo.linkType = LANE_LINK_TYPE_HML,
    };
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));
    LanePreferredLinkList recommendLinkList = {};
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_HML;
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(laneMock, SelectExpectLanesByQos)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(recommendLinkList), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink(_, _, NotNull())).WillRepeatedly(laneMock.ActionOfLaneLinkSuccess);
    EXPECT_CALL(laneMock, DestroyLink).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, DelLaneBusinessInfoItem).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, AddLaneBusinessInfoItem).WillRepeatedly(Return(SOFTBUS_OK));
    LaneResource resourceItem = {};
    resourceItem.link.type = LANE_HML;
    resourceItem.clientRef = 1;
    resourceItem.laneId = LANE_ID_BASE;
    EXPECT_CALL(laneMock, FindLaneResourceByLaneId)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(resourceItem), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, DelLaneResourceByLaneId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, AddLaneResourceToPool).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, GenerateLaneId).WillRepeatedly(Return(LANE_ID_BASE));
    EXPECT_CALL(laneMock, CheckLinkConflictByReleaseLink).WillRepeatedly(Return(SOFTBUS_OK));
    g_listenerCb.onLaneAllocSuccess = OnLaneAllocSuccessHml;
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    ret = transObj->freeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RemoveDelayDestroyMessage(LANE_ID_BASE);
    ret = UpdateReqListLaneId(LANE_ID_BASE, LANE_ID_BASE + 1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelLogicAndLaneRelationship(LANE_ID_BASE + 1);
    transObj->deinit();
}
} // namespace OHOS