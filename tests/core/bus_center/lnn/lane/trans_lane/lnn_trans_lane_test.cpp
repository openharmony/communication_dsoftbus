/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "g_enhance_lnn_func_pack.h"
#include "lnn_lane_deps_mock.h"
#include "lnn_trans_free_lane.h"
#include "lnn_trans_lane.h"
#include "lnn_trans_lane_deps_mock.h"
#include "lnn_wifi_adpter_mock.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr uint32_t LANE_REQ_ID_ONE = 111;
constexpr uint32_t LANE_REQ_ID_TWO = 222;
constexpr uint32_t LANE_REQ_ID_THREE = 333;
constexpr uint32_t SLEEP_FOR_LOOP_COMPLETION_MS = 50;
constexpr uint32_t VIRTUAL_LINK_LANE_REQ_ID = 10;
constexpr char PEER_UDID[] = "111122223333abcdef";
constexpr char PEER_IP[] = "127.30.0.1";
constexpr char NODE_NETWORK_ID[] = "123456789";
constexpr char NODE_NETWORK_ID_C[] = "CCCCCCCCCC";
constexpr uint64_t LANE_ID_BASE = 1122334455667788;
static int32_t g_errCode = 0;
static SoftBusCond g_cond = {0};
static SoftBusMutex g_lock = {0};
static bool g_isNeedCondWait = true;
static bool g_qosEvent[MAX_LANE_REQ_ID_NUM];
constexpr int32_t QOS_BW_10K = 10 * 1024;

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
    (void)InitLaneEvent();
}

void LNNTransLaneMockTest::TearDownTestCase()
{
    DeinitLaneEvent();
    LnnDeinitLnnLooper();
    GTEST_LOG_(INFO) << "LNNTransLaneMockTest end";
}

void LNNTransLaneMockTest::SetUp()
{
    (void)SoftBusMutexInit(&g_lock, nullptr);
    (void)SoftBusCondInit(&g_cond);
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->init(nullptr);
}

void LNNTransLaneMockTest::TearDown()
{
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->deinit();
    (void)SoftBusCondDestroy(&g_cond);
    (void)SoftBusMutexDestroy(&g_lock);
}

static void CondSignal(void)
{
    if (SoftBusMutexLock(&g_lock) != SOFTBUS_OK) {
        GTEST_LOG_(INFO) << "CondSignal SoftBusMutexLock failed";
        return;
    }
    if (SoftBusCondSignal(&g_cond) != SOFTBUS_OK) {
        GTEST_LOG_(INFO) << "CondSignal SoftBusCondSignal failed";
        (void)SoftBusMutexUnlock(&g_lock);
        return;
    }
    g_isNeedCondWait = false;
    (void)SoftBusMutexUnlock(&g_lock);
}

static void ComputeWaitForceDownTime(uint32_t waitMillis, SoftBusSysTime *outtime)
{
#define USECTONSEC 1000
    SoftBusSysTime now;
    (void)SoftBusGetTime(&now);
    int64_t time = now.sec * USECTONSEC * USECTONSEC + now.usec + (int64_t)waitMillis * USECTONSEC;
    outtime->sec = time / USECTONSEC / USECTONSEC;
    outtime->usec = time % (USECTONSEC * USECTONSEC);
}

static void CondWait(void)
{
    if (SoftBusMutexLock(&g_lock) != SOFTBUS_OK) {
        GTEST_LOG_(INFO) << "CondWait SoftBusMutexLock failed";
        return;
    }
    if (!g_isNeedCondWait) {
        GTEST_LOG_(INFO) << "Doesn't need CondWait, g_isNeedCondWait = " << g_isNeedCondWait;
        (void)SoftBusMutexUnlock(&g_lock);
        return;
    }
    SoftBusSysTime waitTime = {0};
    uint32_t condWaitTimeout = 3000;
    ComputeWaitForceDownTime(condWaitTimeout, &waitTime);
    if (SoftBusCondWait(&g_cond, &g_lock, &waitTime) != SOFTBUS_OK) {
        GTEST_LOG_(INFO) << "CondWait Timeout end";
        (void)SoftBusMutexUnlock(&g_lock);
        return;
    }
    (void)SoftBusMutexUnlock(&g_lock);
}

void UpdateLocalDeviceInfoToMlps(const NodeInfo *localInfo)
{
    (void)localInfo;
    return;
}

bool IsDeviceHasRiskFactor(void)
{
    return true;
}

bool LnnIsSupportLpSparkFeature(void)
{
    return true;
}

bool IsFeatureSupportDetail(void)
{
    return true;
}

int32_t InitControlPlane(void)
{
    return SOFTBUS_OK;
}

void DeinitControlPlane(void)
{
}

void TriggerClearSparkGroup(void)
{
}

static void SetIsNeedCondWait(void)
{
    if (SoftBusMutexLock(&g_lock) != SOFTBUS_OK) {
        GTEST_LOG_(INFO) << "SetIsNeedCondWait SoftBusMutexLock failed";
        return;
    }
    g_isNeedCondWait = true;
    (void)SoftBusMutexUnlock(&g_lock);
}

static void OnLaneAllocSuccess(uint32_t laneHandle, const LaneConnInfo *info)
{
    (void)laneHandle;
    ASSERT_NE(info, nullptr) << "invalid connInfo";
    GTEST_LOG_(INFO) << "alloc lane successful, linkType=" << info->type;
    EXPECT_EQ(info->type, LANE_P2P);
    CondSignal();
}

static void OnLaneAllocFail(uint32_t laneHandle, int32_t errCode)
{
    GTEST_LOG_(INFO) << "alloc lane failed, laneReqId=" << laneHandle << ", errCode=" << errCode;
    EXPECT_NE(errCode, SOFTBUS_OK);
    g_errCode = errCode;
    CondSignal();
}

static void OnLaneFreeSuccess(uint32_t laneHandle)
{
    GTEST_LOG_(INFO) << "free lane success, laneReqId=" << laneHandle;
    CondSignal();
}

static void OnLaneFreeFail(uint32_t laneHandle, int32_t errCode)
{
    GTEST_LOG_(INFO) << "free lane failed, laneReqId=" << laneHandle << ", errCode=" << errCode;
    CondSignal();
}

static void OnLaneRequestSuccess(uint32_t laneReqId, const LaneConnInfo *info)
{
    (void)info;
    GTEST_LOG_(INFO) << "onLaneRequestSuccess enter, laneReqId=" << laneReqId;
    CondSignal();
}

static void OnLaneRequestFail(uint32_t laneReqId, int32_t errCode)
{
    GTEST_LOG_(INFO) << "onLaneRequestFail enter, laneReqId=" << laneReqId << ", errCode=" << errCode;
    CondSignal();
}

static void OnLaneAllocSuccessHml(uint32_t laneHandle, const LaneConnInfo *info)
{
    (void)laneHandle;
    ASSERT_NE(info, nullptr) << "invalid connInfo";
    GTEST_LOG_(INFO) << "alloc lane successful, linkType=" << info->type;
    EXPECT_EQ(info->type, LANE_HML);
    CondSignal();
}

static void OnLaneAllocSuccessBr(uint32_t laneHandle, const LaneConnInfo *info)
{
    (void)laneHandle;
    ASSERT_NE(info, nullptr) << "invalid connInfo";
    GTEST_LOG_(INFO) << "alloc lane successful, linkType=" << info->type;
    EXPECT_EQ(info->type, LANE_BR);
    CondSignal();
}

static void OnLaneAllocSuccessWlan5G(uint32_t laneHandle, const LaneConnInfo *info)
{
    (void)laneHandle;
    ASSERT_NE(info, nullptr) << "invalid connInfo";
    GTEST_LOG_(INFO) << "alloc lane successful, linkType=" << info->type;
    EXPECT_EQ(info->type, LANE_WLAN_5G);
    CondSignal();
}

static void OnLaneQosEvent(uint32_t laneHandle, LaneOwner laneOwner, LaneQosEvent qosEvent)
{
    GTEST_LOG_(INFO) << "received qos event, laneHandle=" << laneHandle;
    EXPECT_EQ(laneOwner, LANE_OWNER_OTHER);
    EXPECT_EQ(qosEvent, LANE_QOS_BW_HIGH);
    g_qosEvent[laneHandle] = true;
}

static void MockAllocLaneByQos(NiceMock<LaneDepsInterfaceMock> &mock, NiceMock<TransLaneDepsInterfaceMock> &laneMock,
    LaneResource resourceItem)
{
    static LnnEnhanceFuncList lnnEnhanceFunc = { nullptr };
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&lnnEnhanceFunc));
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetNetworkIdByUdid).WillRepeatedly(LaneDepsInterfaceMock::ActionOfLnnGetNetworkIdByUdid);

    LanePreferredLinkList recommendLinkList = {};
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = resourceItem.link.type;
    EXPECT_CALL(laneMock, SelectExpectLanesByQos)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(recommendLinkList), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink(_, _, NotNull())).WillRepeatedly(laneMock.ActionOfBuildLinkSuccess);
    EXPECT_CALL(laneMock, DestroyLink).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, DelLaneBusinessInfoItem).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, AddLaneBusinessInfoItem).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, FindLaneResourceByLaneId)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(resourceItem), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, DelLaneResourceByLaneId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, AddLaneResourceToPool).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, GenerateLaneId).WillRepeatedly(Return(LANE_ID_BASE));
    EXPECT_CALL(laneMock, CheckLinkConflictByReleaseLink).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, FreeLaneReqId).WillRepeatedly(Return());
}

bool ActionOfHaveConcurrencyPreLinkNode(uint32_t laneReqId, bool isCheckPreLink)
{
    (void)laneReqId;
    (void)isCheckPreLink;
    return true;
}

bool IsSupportLowLatency(const TransReqInfo *reqInfo, const LaneLinkInfo *laneLinkInfo)
{
    (void)reqInfo;
    (void)laneLinkInfo;
    return true;
}

static void ResetQosEventResult()
{
    for (uint32_t i = 0; i < MAX_LANE_REQ_ID_NUM; i++) {
        g_qosEvent[i] = false;
    }
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

    uint32_t laneReqId = 1;
    int32_t ret = transObj->allocLane(laneReqId, nullptr, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    LaneRequestOption request;
    request.type = LANE_TYPE_BUTT;
    ret = transObj->allocLane(laneReqId, (const LaneRequestOption *)&request, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);
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
    uint32_t laneReqId = 1;
    LaneRequestOption request;
    request.type = LANE_TYPE_TRANS;
    EXPECT_CALL(laneMock, SelectLane).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = transObj->allocLane(laneReqId, (const LaneRequestOption *)&request, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);
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
    uint32_t laneReqId = 1;
    LaneAllocInfo allocInfo;
    allocInfo.type = LANE_TYPE_TRANS;
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);
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

    uint32_t laneReqId = 1;
    LaneAllocInfo allocInfo;
    allocInfo.type = LANE_TYPE_TRANS;
    LanePreferredLinkList recommendLinkList;
    (void)memset_s(&recommendLinkList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_WLAN_2P4G;
    EXPECT_CALL(laneMock, SelectExpectLanesByQos).
        WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(recommendLinkList), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink(_, _, NotNull())).WillRepeatedly(laneMock.ActionOfBuildLinkSuccess);
    SetIsNeedCondWait();
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    EXPECT_EQ(g_errCode, SOFTBUS_LANE_ID_GENERATE_FAIL);
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

    uint32_t laneReqId = 1;
    LaneAllocInfo allocInfo;
    allocInfo.type = LANE_TYPE_TRANS;
    LanePreferredLinkList recommendLinkList;
    (void)memset_s(&recommendLinkList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_WLAN_2P4G;
    EXPECT_CALL(laneMock, SelectExpectLanesByQos).
        WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(recommendLinkList), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink(_, _, NotNull())).WillRepeatedly(laneMock.ActionOfBuildLinkFail);
    SetIsNeedCondWait();
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    EXPECT_EQ(g_errCode, SOFTBUS_LANE_TRIGGER_LINK_FAIL);
    SetIsNeedCondWait();
    ret = transObj->allocLaneByQos(LANE_REQ_ID_ONE, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = transObj->freeLane(LANE_REQ_ID_ONE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(LANE_REQ_ID_ONE, SOFTBUS_OK));
    CondWait();
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_FOR_LOOP_COMPLETION_MS));
    EXPECT_EQ(g_errCode, SOFTBUS_LANE_TRIGGER_LINK_FAIL);
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(LANE_REQ_ID_ONE, SOFTBUS_OK));
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
    SetIsNeedCondWait();
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    EXPECT_EQ(g_errCode, SOFTBUS_LANE_DETECT_FAIL);
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
    uint32_t laneReqId = 1;
    LaneRequestOption request = {};
    request.type = LANE_TYPE_TRANS;
    LanePreferredLinkList recommendLinkList = {};
    recommendLinkList.linkTypeNum = 1;
    recommendLinkList.linkType[0] = LANE_BR;
    EXPECT_CALL(laneMock, SelectLane)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(recommendLinkList), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink(_, _, NotNull())).WillRepeatedly(laneMock.ActionOfBuildLinkSuccess);
    ILaneListener listener = {
        .onLaneRequestSuccess = OnLaneRequestSuccess,
        .onLaneRequestFail = OnLaneRequestFail,
    };
    SetIsNeedCondWait();
    int32_t ret = transObj->allocLane(laneReqId, (const LaneRequestOption *)&request, &listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
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
    int32_t ret = PostLaneStateChangeMessage(LANE_STATE_LINKUP, PEER_UDID, &laneLinkInfo);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
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
    int32_t ret = PostLaneStateChangeMessage(LANE_STATE_LINKDOWN, PEER_UDID, &laneLinkInfo);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
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
    NiceMock<TransLaneDepsInterfaceMock> transLaneMock;
    EXPECT_CALL(transLaneMock, DelLaneBusinessInfoItem).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = transObj->freeLane(LANE_REQ_ID_ONE);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
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
    LaneAllocInfoExt allocInfo = { .type = LANE_TYPE_TRANS, .linkList.linkTypeNum = LANE_HML_RAW, };
    EXPECT_EQ(EOK, strcpy_s(allocInfo.commInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));
    LaneAllocListener listener;
    (void)memset_s(&listener, sizeof(LaneAllocListener), 0, sizeof(LaneAllocListener));
    int32_t ret = transObj->allocTargetLane(LANE_REQ_ID_ONE, nullptr, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = transObj->allocTargetLane(LANE_REQ_ID_ONE, &allocInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = transObj->allocTargetLane(INVALID_LANE_REQ_ID, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    allocInfo.linkList.linkTypeNum = LANE_LINK_TYPE_BUTT;
    ret = transObj->allocTargetLane(LANE_REQ_ID_ONE, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    allocInfo.type = LANE_TYPE_CTRL;
    ret = transObj->allocTargetLane(LANE_REQ_ID_ONE, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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
    SetIsNeedCondWait();
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    allocInfo.extendInfo.linkType = LANE_LINK_TYPE_WIFI_P2P;
    SetIsNeedCondWait();
    ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    allocInfo.extendInfo.linkType = LANE_LINK_TYPE_BR;
    SetIsNeedCondWait();
    ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    allocInfo.extendInfo.linkType = LANE_LINK_TYPE_COC_DIRECT;
    SetIsNeedCondWait();
    ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: ALLOC_LANE_BY_QOS_TEST_002
* @tc.desc: AllocLaneByQos test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, ALLOC_LANE_BY_QOS_TEST_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
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
    SetIsNeedCondWait();
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    allocInfo.extendInfo.linkType = LANE_LINK_TYPE_BLE_DIRECT;
    SetIsNeedCondWait();
    ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    allocInfo.extendInfo.linkType = LANE_LINK_TYPE_HML;
    SetIsNeedCondWait();
    ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
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
    int32_t ret = transObj->allocRawLane(LANE_REQ_ID_ONE, &allocInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = transObj->allocRawLane(LANE_REQ_ID_ONE, nullptr, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    allocInfo.type = LANE_TYPE_CTRL;
    ret = transObj->allocRawLane(LANE_REQ_ID_ONE, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UpdateReqListLaneId(LANE_ID_BASE, LANE_ID_BASE + 1);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
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
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    LaneAllocInfo allocInfo = {
        .type = LANE_TYPE_TRANS,
    };
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LnnEnhanceFuncList lnnEnhanceFunc = { nullptr };
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&lnnEnhanceFunc));
    LaneResource resourceItem = {};
    resourceItem.link.type = LANE_HML;
    resourceItem.clientRef = 1;
    MockAllocLaneByQos(mock, laneMock, resourceItem);
    g_listenerCb.onLaneAllocSuccess = OnLaneAllocSuccessHml;
    SetIsNeedCondWait();
    int32_t ret = transObj->allocLaneByQos(LANE_REQ_ID_ONE, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = transObj->freeLane(LANE_REQ_ID_ONE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(LANE_REQ_ID_ONE, SOFTBUS_OK));
    CondWait();
    SetIsNeedCondWait();
    ret = transObj->allocLaneByQos(LANE_REQ_ID_TWO, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = transObj->freeLane(LANE_REQ_ID_TWO);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(LANE_REQ_ID_TWO, SOFTBUS_OK));
    CondWait();
}

/*
* @tc.name: LNN_FREE_LANE_DELAY_DESTROY_TEST_002
* @tc.desc: freeLane delay destroy test haveConcurrencyPreLinkNode
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_FREE_LANE_DELAY_DESTROY_TEST_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    LaneAllocInfo allocInfo = {
        .type = LANE_TYPE_TRANS,
    };
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LaneResource resourceItem = {};
    resourceItem.link.type = LANE_HML;
    resourceItem.clientRef = 1;
    MockAllocLaneByQos(mock, laneMock, resourceItem);
    g_listenerCb.onLaneAllocSuccess = OnLaneAllocSuccessHml;
    SetIsNeedCondWait();
    int32_t ret = transObj->allocLaneByQos(LANE_REQ_ID_ONE, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = transObj->freeLane(LANE_REQ_ID_ONE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(LANE_REQ_ID_ONE, SOFTBUS_OK));
    CondWait();
    SetIsNeedCondWait();
    LnnEnhanceFuncList *lnnEnhanceFunc = LnnEnhanceFuncListGet();
    lnnEnhanceFunc->haveConcurrencyPreLinkNodeByLaneReqId = ActionOfHaveConcurrencyPreLinkNode;
    ret = transObj->allocLaneByQos(LANE_REQ_ID_TWO, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = transObj->freeLane(LANE_REQ_ID_TWO);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(LANE_REQ_ID_TWO, SOFTBUS_OK));
    CondWait();
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
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    LaneAllocInfo allocInfo = {
        .type = LANE_TYPE_TRANS,
    };
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LnnEnhanceFuncList lnnEnhanceFunc = { nullptr };
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&lnnEnhanceFunc));
    LaneResource resourceItem = {};
    resourceItem.link.type = LANE_HML;
    resourceItem.clientRef = 1;
    resourceItem.laneId = LANE_ID_BASE;
    MockAllocLaneByQos(mock, laneMock, resourceItem);
    g_listenerCb.onLaneAllocSuccess = OnLaneAllocSuccessHml;
    SetIsNeedCondWait();
    int32_t ret = transObj->allocLaneByQos(LANE_REQ_ID_ONE, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = transObj->freeLane(LANE_REQ_ID_ONE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    RemoveDelayDestroyMessage(LANE_ID_BASE);
    ret = UpdateReqListLaneId(LANE_ID_BASE, LANE_ID_BASE + 1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelLogicAndLaneRelationship(LANE_ID_BASE + 1);
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(LANE_REQ_ID_ONE, SOFTBUS_OK));
    CondWait();
}

/*
* @tc.name: LNN_FREE_LANE_DELAY_DESTROY_TEST_004
* @tc.desc: test notifyFree is true
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_FREE_LANE_DELAY_DESTROY_TEST_004, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    LaneAllocInfo allocInfo = {
        .type = LANE_TYPE_TRANS,
    };
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LaneResource resourceItem = {};
    resourceItem.link.type = LANE_HML;
    resourceItem.clientRef = 1;
    MockAllocLaneByQos(mock, laneMock, resourceItem);
    g_listenerCb.onLaneAllocSuccess = OnLaneAllocSuccessHml;
    SetIsNeedCondWait();
    int32_t ret = transObj->allocLaneByQos(LANE_REQ_ID_ONE, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = transObj->freeLane(LANE_REQ_ID_ONE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(LANE_REQ_ID_ONE, SOFTBUS_LANE_ALLOC_NOT_COMPLETED));
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_FOR_LOOP_COMPLETION_MS));
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(LANE_REQ_ID_ONE, SOFTBUS_OK));
    CondWait();
}

/*
* @tc.name: LNN_HANDLE_LANE_QOS_CHANGE_TEST_001
* @tc.desc: handle lane qos change test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_HANDLE_LANE_QOS_CHANGE_TEST_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetNetworkIdByUdid).WillRepeatedly(Return(SOFTBUS_OK));
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);

    int32_t ret = HandleLaneQosChange(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    LaneLinkInfo info;
    (void)memset_s(&info, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    info.type = LANE_BLE;
    ret = HandleLaneQosChange(&info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.type = LANE_P2P;
    ret = HandleLaneQosChange(&info);
    EXPECT_EQ(ret, SOFTBUS_OK);
    info.type = LANE_HML;
    ret = HandleLaneQosChange(&info);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_HANDLE_LANE_QOS_CHANGE_TEST_002
* @tc.desc: notify qos event only when new link is p2p/HML and BW of old link is DB_MAGIC
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_HANDLE_LANE_QOS_CHANGE_TEST_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LaneResource resourceItem = {};
    resourceItem.link.type = LANE_BR;
    MockAllocLaneByQos(mock, laneMock, resourceItem);
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);

    LaneAllocInfo allocInfo = {};
    allocInfo.type = LANE_TYPE_TRANS;
    allocInfo.qosRequire.minBW = DB_MAGIC_NUMBER;
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));
    g_listenerCb.onLaneAllocSuccess = OnLaneAllocSuccessBr;
    g_listenerCb.onLaneQosEvent = OnLaneQosEvent;
    SetIsNeedCondWait();
    int32_t ret = transObj->allocLaneByQos(LANE_REQ_ID_ONE, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();

    SetIsNeedCondWait();
    allocInfo.qosRequire.minBW = QOS_BW_10K;
    ret = transObj->allocLaneByQos(LANE_REQ_ID_TWO, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();

    LaneLinkInfo info = {
        .type = LANE_WLAN_5G,
    };
    ResetQosEventResult();
    EXPECT_EQ(HandleLaneQosChange(&info), SOFTBUS_OK);
    EXPECT_EQ(g_qosEvent[LANE_REQ_ID_ONE], false);
    EXPECT_EQ(g_qosEvent[LANE_REQ_ID_TWO], false);
    info.type = LANE_P2P;
    EXPECT_EQ(HandleLaneQosChange(&info), SOFTBUS_OK);
    EXPECT_EQ(g_qosEvent[LANE_REQ_ID_ONE], true);
    EXPECT_EQ(g_qosEvent[LANE_REQ_ID_TWO], false);
    info.type = LANE_HML;
    EXPECT_EQ(HandleLaneQosChange(&info), SOFTBUS_OK);
    EXPECT_EQ(g_qosEvent[LANE_REQ_ID_ONE], true);
    EXPECT_EQ(g_qosEvent[LANE_REQ_ID_TWO], false);

    EXPECT_EQ(transObj->freeLane(LANE_REQ_ID_ONE), SOFTBUS_OK);
    EXPECT_EQ(transObj->freeLane(LANE_REQ_ID_TWO), SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(LANE_REQ_ID_ONE, SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(LANE_REQ_ID_TWO, SOFTBUS_OK));
}

/*
* @tc.name: LNN_HANDLE_LANE_QOS_CHANGE_TEST_003
* @tc.desc: test multiple devices and multiple links
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_HANDLE_LANE_QOS_CHANGE_TEST_003, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LaneResource resourceItem = {};
    resourceItem.link.type = LANE_BR;
    MockAllocLaneByQos(mock, laneMock, resourceItem);
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);

    LaneAllocInfo allocInfo = {};
    allocInfo.type = LANE_TYPE_TRANS;
    allocInfo.qosRequire.minBW = DB_MAGIC_NUMBER;
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));
    g_listenerCb.onLaneAllocSuccess = OnLaneAllocSuccessBr;
    g_listenerCb.onLaneQosEvent = OnLaneQosEvent;
    SetIsNeedCondWait();
    int32_t ret = transObj->allocLaneByQos(LANE_REQ_ID_ONE, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();

    SetIsNeedCondWait();
    ret = transObj->allocLaneByQos(LANE_REQ_ID_TWO, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID_C));
    ret = transObj->allocLaneByQos(LANE_REQ_ID_THREE, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();

    LaneLinkInfo info = {
        .type = LANE_HML,
    };
    ResetQosEventResult();
    EXPECT_EQ(HandleLaneQosChange(&info), SOFTBUS_OK);
    EXPECT_EQ(g_qosEvent[LANE_REQ_ID_ONE], true);
    EXPECT_EQ(g_qosEvent[LANE_REQ_ID_TWO], true);
    EXPECT_EQ(g_qosEvent[LANE_REQ_ID_THREE], false);

    EXPECT_EQ(transObj->freeLane(LANE_REQ_ID_ONE), SOFTBUS_OK);
    EXPECT_EQ(transObj->freeLane(LANE_REQ_ID_TWO), SOFTBUS_OK);
    EXPECT_EQ(transObj->freeLane(LANE_REQ_ID_THREE), SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(LANE_REQ_ID_ONE, SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(LANE_REQ_ID_TWO, SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(LANE_REQ_ID_THREE, SOFTBUS_OK));
}

/*
* @tc.name: LNN_HANDLE_LANE_QOS_CHANGE_TEST_004
* @tc.desc: not report qos event when old link is not BR
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_HANDLE_LANE_QOS_CHANGE_TEST_004, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LaneResource resourceItem = {};
    resourceItem.link.type = LANE_WLAN_5G;
    MockAllocLaneByQos(mock, laneMock, resourceItem);
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);

    LaneAllocInfo allocInfo = {};
    allocInfo.type = LANE_TYPE_TRANS;
    allocInfo.qosRequire.minBW = DB_MAGIC_NUMBER;
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));
    g_listenerCb.onLaneAllocSuccess = OnLaneAllocSuccessWlan5G;
    g_listenerCb.onLaneQosEvent = OnLaneQosEvent;
    SetIsNeedCondWait();
    int32_t ret = transObj->allocLaneByQos(LANE_REQ_ID_ONE, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();

    SetIsNeedCondWait();
    allocInfo.qosRequire.minBW = QOS_BW_10K;
    ret = transObj->allocLaneByQos(LANE_REQ_ID_TWO, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();

    LaneLinkInfo info = {
        .type = LANE_P2P,
    };
    ResetQosEventResult();
    EXPECT_EQ(HandleLaneQosChange(&info), SOFTBUS_OK);
    EXPECT_EQ(g_qosEvent[LANE_REQ_ID_ONE], false);
    EXPECT_EQ(g_qosEvent[LANE_REQ_ID_TWO], false);

    EXPECT_EQ(transObj->freeLane(LANE_REQ_ID_ONE), SOFTBUS_OK);
    EXPECT_EQ(transObj->freeLane(LANE_REQ_ID_TWO), SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(LANE_REQ_ID_ONE, SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(NotifyFreeLaneResult(LANE_REQ_ID_TWO, SOFTBUS_OK));
}

/*
* @tc.name: LNN_HANDLE_LANE_FREE_UNUSED_LINK_001
* @tc.desc: free unused link with nullptr info and invalid lane reqId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_HANDLE_LANE_FREE_UNUSED_LINK_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(FreeUnusedLink(INVALID_LANE_REQ_ID, nullptr));
}

/*
* @tc.name: LNN_HANDLE_LANE_FREE_UNUSED_LINK_002
* @tc.desc: free unused link with invalid lane reqId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_HANDLE_LANE_FREE_UNUSED_LINK_002, TestSize.Level1)
{
    LaneLinkInfo info = {
        .type = LANE_P2P,
    };
    EXPECT_NO_FATAL_FAILURE(FreeUnusedLink(INVALID_LANE_REQ_ID, &info));
}

/*
* @tc.name: LNN_HANDLE_LANE_FREE_UNUSED_LINK_003
* @tc.desc: free unused link with nullptr info
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_HANDLE_LANE_FREE_UNUSED_LINK_003, TestSize.Level1)
{
    uint32_t laneReqId = 1;
    EXPECT_NO_FATAL_FAILURE(FreeUnusedLink(laneReqId, nullptr));
}

/*
* @tc.name: LNN_HANDLE_LANE_FREE_UNUSED_LINK_004
* @tc.desc: free unused link with get networkid fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_HANDLE_LANE_FREE_UNUSED_LINK_004, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> laneMock;
    uint32_t laneReqId = 1;
    LaneLinkInfo info = {
        .type = LANE_P2P,
    };
    EXPECT_CALL(laneMock, LnnGetNetworkIdByUdid).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(FreeUnusedLink(laneReqId, &info));
}

/*
* @tc.name: LNN_HANDLE_LANE_FREE_UNUSED_LINK_005
* @tc.desc: free unused link with get networkid succ
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_HANDLE_LANE_FREE_UNUSED_LINK_005, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> laneMock;
    NiceMock<LnnWifiAdpterInterfaceMock> lnnMock;
    uint32_t laneReqId = 1;
    LaneLinkInfo info = {
        .type = LANE_HML,
    };
    EXPECT_CALL(laneMock, LnnGetNetworkIdByUdid).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnMock, LnnDisconnectP2p).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(FreeUnusedLink(laneReqId, &info));
}

/*
* @tc.name: LNN_HANDLE_LANE_IS_SUPPORT_LOW_LATENCY_TEST_001
* @tc.desc: is support low latency
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_HANDLE_LANE_IS_SUPPORT_LOW_LATENCY_TEST_001, TestSize.Level1)
{
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LnnEnhanceFuncList lnnEnhanceFunc = { nullptr };
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&lnnEnhanceFunc));
    EXPECT_EQ(false, IsSupportLowLatencyPacked(nullptr, nullptr));

    lnnEnhanceFunc.isSupportLowLatency = IsSupportLowLatency;
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&lnnEnhanceFunc));
    EXPECT_EQ(true, IsSupportLowLatencyPacked(nullptr, nullptr));
}

/*
* @tc.name: CHECK_VIRTUAL_LINK_BY_LANE_REQ_ID_TEST_001
* @tc.desc: check virtual link by lane req id test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, CHECK_VIRTUAL_LINK_BY_LANE_REQ_ID_TEST_001, TestSize.Level1)
{
    uint32_t laneReqId = INVALID_LANE_REQ_ID;
    bool ret = CheckVirtualLinkByLaneReqId(laneReqId);
    EXPECT_FALSE(ret);
    laneReqId = VIRTUAL_LINK_LANE_REQ_ID;
    ret = CheckVirtualLinkByLaneReqId(laneReqId);
    EXPECT_FALSE(ret);
}

/*
* @tc.name: CHECK_VIRTUAL_LINK_BY_LANE_REQ_ID_TEST_002
* @tc.desc: check virtual link by lane req id test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, CHECK_VIRTUAL_LINK_BY_LANE_REQ_ID_TEST_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    uint32_t laneReqId = VIRTUAL_LINK_LANE_REQ_ID;
    LaneAllocInfo allocInfo = {
        .type = LANE_TYPE_TRANS,
        .extendInfo.isSpecifiedLink = true,
        .extendInfo.linkType = LANE_LINK_TYPE_WIFI_WLAN,
        .extendInfo.isVirtualLink = true,
    };
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));
    LanePreferredLinkList recommendLinkList;
    (void)memset_s(&recommendLinkList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_WLAN_2P4G;
    EXPECT_CALL(laneMock, SelectExpectLanesByQos)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(recommendLinkList), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink(_, _, NotNull())).WillRepeatedly(laneMock.ActionOfBuildLinkSuccess);
    SetIsNeedCondWait();
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    bool isVirtualLink = CheckVirtualLinkByLaneReqId(laneReqId);
    EXPECT_FALSE(isVirtualLink);
}

/*
 * @tc.name: IS_DEVICE_HAS_RISK_TEST_001
 * @tc.desc: IsDeviceHasRiskFactorPacked func test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneMockTest, IS_DEVICE_HAS_RISK_TEST_001, TestSize.Level1)
{
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LnnEnhanceFuncList lnnEnhanceFunc = { nullptr };
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&lnnEnhanceFunc));
    bool ret = IsDeviceHasRiskFactorPacked();
    EXPECT_EQ(ret, false);

    lnnEnhanceFunc.isDeviceHasRiskFactor = IsDeviceHasRiskFactor;
    ret = IsDeviceHasRiskFactorPacked();
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: IS_SUPPORT_LP_SPARK_TEST_001
 * @tc.desc: LnnIsSupportLpSparkFeaturePacked func test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneMockTest, IS_SUPPORT_LP_SPARK_TEST_001, TestSize.Level1)
{
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(nullptr));
    bool ret = LnnIsSupportLpSparkFeaturePacked();
    EXPECT_EQ(ret, false);
    LnnEnhanceFuncList lnnEnhanceFunc = { nullptr };
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&lnnEnhanceFunc));
    ret = LnnIsSupportLpSparkFeaturePacked();
    EXPECT_EQ(ret, false);

    lnnEnhanceFunc.lnnIsSupportLpSparkFeature = LnnIsSupportLpSparkFeature;
    ret = LnnIsSupportLpSparkFeaturePacked();
    EXPECT_EQ(ret, true);
}

/*
 * @tc.name: IS_FEATURE_SUPPORT_DETAIL_TEST_001
 * @tc.desc: LnnIsFeatureSupportDetailPacked func test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneMockTest, IS_FEATURE_SUPPORT_DETAIL_TEST_001, TestSize.Level1)
{
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(nullptr));
    bool ret = LnnIsFeatureSupportDetailPacked();
    EXPECT_EQ(ret, false);
    LnnEnhanceFuncList lnnEnhanceFunc = { nullptr };
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&lnnEnhanceFunc));
    ret = LnnIsFeatureSupportDetailPacked();
    EXPECT_EQ(ret, false);

    lnnEnhanceFunc.isFeatureSupportDetail = IsFeatureSupportDetail;
    ret = LnnIsFeatureSupportDetailPacked();
    EXPECT_EQ(ret, true);
}

bool IsSupportMcuFeatureTest(void)
{
    return true;
}
/*
 * @tc.name: IS_SUPPORT_MCU_FEATURE_PACKED_TEST_001
 * @tc.desc: IsSupportMcuFeaturePacked func test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneMockTest, IS_SUPPORT_MCU_FEATURE_PACKED_TEST_001, TestSize.Level1)
{
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LnnEnhanceFuncList lnnEnhanceFunc = { nullptr };
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillOnce(Return(nullptr)).WillRepeatedly(Return(&lnnEnhanceFunc));
    bool ret = IsSupportMcuFeaturePacked();
    EXPECT_EQ(ret, false);

    ret = IsSupportMcuFeaturePacked();
    EXPECT_EQ(ret, false);

    lnnEnhanceFunc.isSupportMcuFeature = IsSupportMcuFeatureTest;
    ret = IsSupportMcuFeaturePacked();
    EXPECT_EQ(ret, true);
}

void LnnSendDeviceStateToMcuTest(void *para)
{
    SoftBusFree(para);
    return;
}
/*
 * @tc.name: LNN_SEND_DEVICE_STATE_TO_MCU_PACKED_TEST_001
 * @tc.desc: LnnSendDeviceStateToMcuPacked func test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneMockTest, LNN_SEND_DEVICE_STATE_TO_MCU_PACKED_TEST_001, TestSize.Level1)
{
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LnnEnhanceFuncList lnnEnhanceFunc = { nullptr };
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillOnce(Return(nullptr)).WillRepeatedly(Return(&lnnEnhanceFunc));
    LaneAllocInfo *info = (LaneAllocInfo *)SoftBusCalloc(sizeof(LaneAllocInfo));
    LnnSendDeviceStateToMcuPacked(info);
    info = (LaneAllocInfo *)SoftBusCalloc(sizeof(LaneAllocInfo));
    LnnSendDeviceStateToMcuPacked(info);

    info = (LaneAllocInfo *)SoftBusCalloc(sizeof(LaneAllocInfo));
    lnnEnhanceFunc.lnnSendDeviceStateToMcu = LnnSendDeviceStateToMcuTest;
    LnnSendDeviceStateToMcuPacked(info);
}

int32_t LnnInitMcuTest(void)
{
    return SOFTBUS_INVALID_PARAM;
}
/*
 * @tc.name: LNN_INIT_MCU_PACKED_TEST_001
 * @tc.desc: LnnInitMcuPacked func test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneMockTest, LNN_INIT_MCU_PACKED_TEST_001, TestSize.Level1)
{
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LnnEnhanceFuncList lnnEnhanceFunc = { nullptr };
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillOnce(Return(nullptr)).WillRepeatedly(Return(&lnnEnhanceFunc));

    int32_t ret = LnnInitMcuPacked();
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);

    ret = LnnInitMcuPacked();
    EXPECT_EQ(ret, SOFTBUS_OK);

    lnnEnhanceFunc.lnnInitMcu = LnnInitMcuTest;
    ret = LnnInitMcuPacked();
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: TRIGGER_SH_SPARK_GROUP_CLEAR_TEST_001
 * @tc.desc: TriggerClearSparkGroupPacked func test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneMockTest, TRIGGER_SH_SPARK_GROUP_CLEAR_TEST_001, TestSize.Level1)
{
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(nullptr));
    EXPECT_NO_FATAL_FAILURE(TriggerClearSparkGroupPacked());
    LnnEnhanceFuncList lnnEnhanceFunc = { nullptr };
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&lnnEnhanceFunc));
    EXPECT_NO_FATAL_FAILURE(TriggerClearSparkGroupPacked());

    lnnEnhanceFunc.triggerClearSparkGroup = TriggerClearSparkGroup;
    EXPECT_NO_FATAL_FAILURE(TriggerClearSparkGroupPacked());
}

/*
 * @tc.name: INIT_CONTROL_PLANE_TEST_001
 * @tc.desc: InitControlPlanePacked func test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNTransLaneMockTest, INIT_CONTROL_PLANE_TEST_001, TestSize.Level1)
{
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(nullptr));
    NodeInfo localInfo = {};
    EXPECT_NO_FATAL_FAILURE(UpdateLocalDeviceInfoToMlpsPacked(&localInfo));
    LnnEnhanceFuncList lnnEnhanceFunc = { nullptr };
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&lnnEnhanceFunc));
    int32_t ret = InitControlPlanePacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(DeinitControlPlanePacked());
    EXPECT_NO_FATAL_FAILURE(UpdateLocalDeviceInfoToMlpsPacked(&localInfo));

    ret = InitControlPlanePacked();
    lnnEnhanceFunc.initControlPlane = InitControlPlane;
    lnnEnhanceFunc.deinitControlPlane = DeinitControlPlane;
    lnnEnhanceFunc.updateLocalDeviceInfoToMlps = UpdateLocalDeviceInfoToMlps;
    ret = InitControlPlanePacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(DeinitControlPlanePacked());
    EXPECT_NO_FATAL_FAILURE(UpdateLocalDeviceInfoToMlpsPacked(&localInfo));
}

/*
* @tc.name: LNN_RELEASE_UNDELIVERABLE_LINK_001
* @tc.desc: ReleaseUndeliverableLink
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_RELEASE_UNDELIVERABLE_LINK_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> laneMock;
    NiceMock<TransLaneDepsInterfaceMock> transLaneMock;
    NiceMock<LnnWifiAdpterInterfaceMock> lnnMock;
    uint32_t laneReqId = 1;
    LaneResource resourceItem = {
        .link.type = LANE_HML_RAW,
    };
    EXPECT_CALL(transLaneMock, FindLaneResourceByLaneId)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(resourceItem), Return(SOFTBUS_OK)));
    EXPECT_CALL(transLaneMock, DestroyLink)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, LnnGetNetworkIdByUdid)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(LaneDepsInterfaceMock::ActionOfLnnGetNetworkIdByUdid);
    EXPECT_CALL(lnnMock, RemoveAuthSessionServer).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(ReleaseUndeliverableLink(laneReqId, LANE_ID_BASE));
    EXPECT_NO_FATAL_FAILURE(ReleaseUndeliverableLink(laneReqId, LANE_ID_BASE));
    EXPECT_NO_FATAL_FAILURE(ReleaseUndeliverableLink(INVALID_LANE_REQ_ID, INVALID_LANE_ID));
    EXPECT_NO_FATAL_FAILURE(ReleaseUndeliverableLink(laneReqId, INVALID_LANE_ID));
    EXPECT_NO_FATAL_FAILURE(ReleaseUndeliverableLink(INVALID_LANE_REQ_ID, LANE_ID_BASE));
}

/*
* @tc.name: LNN_DFX_REPORT_NO_CAP_ALLOC_LANE_TEST_001
* @tc.desc: lnn dfx report no cap alloc lane with hml
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_DFX_REPORT_NO_CAP_ALLOC_LANE_TEST_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LaneInterface *transObj = TransLaneGetInstance();
    ASSERT_TRUE(transObj != nullptr);
    LaneAllocInfo allocInfo = {
        .type = LANE_TYPE_TRANS,
    };
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LanePreferredLinkList recommendLinkList = {};
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_HML;
    EXPECT_CALL(laneMock, SelectExpectLanesByQos)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(recommendLinkList), Return(SOFTBUS_INVALID_PARAM)));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_INVALID_PARAM)));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = transObj->allocLaneByQos(LANE_REQ_ID_ONE, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = transObj->allocLaneByQos(LANE_REQ_ID_ONE, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = transObj->allocLaneByQos(LANE_REQ_ID_ONE, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_DFX_REPORT_NO_CAP_ALLOC_LANE_TEST_002
* @tc.desc: lnn dfx report no cap alloc lane with p2p
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, LNN_DFX_REPORT_NO_CAP_ALLOC_LANE_TEST_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LaneInterface *transObj = TransLaneGetInstance();
    ASSERT_TRUE(transObj != nullptr);
    LaneAllocInfo allocInfo = {
        .type = LANE_TYPE_TRANS,
    };
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LanePreferredLinkList recommendLinkList = {};
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_P2P;
    EXPECT_CALL(laneMock, SelectExpectLanesByQos)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(recommendLinkList), Return(SOFTBUS_INVALID_PARAM)));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_INVALID_PARAM)));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = transObj->allocLaneByQos(LANE_REQ_ID_ONE, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: ALLOC_LANE_BY_SPECIFIED_LINK_TEST_001
* @tc.desc: alloc lane by specified link fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneMockTest, ALLOC_LANE_BY_SPECIFIED_LINK_TEST_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, LnnGetOsTypeByNetworkId).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    LaneInterface *transObj = TransLaneGetInstance();
    ASSERT_TRUE(transObj != nullptr);
    uint32_t laneReqId = LANE_REQ_ID_ONE;
    LaneAllocInfo allocInfo = {
        .type = LANE_TYPE_TRANS,
        .extendInfo.isSpecifiedLink = true,
        .extendInfo.linkType = LANE_LINK_TYPE_MAX,
    };
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));
    int32_t ret = transObj->allocLaneByQos(laneReqId, &allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_LANE_SELECT_FAIL);
    EXPECT_CALL(mock, LnnGetOsTypeByNetworkId).WillRepeatedly(Return(SOFTBUS_OK));
    ret = transObj->allocLaneByQos(laneReqId, &allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_LANE_SELECT_FAIL);
}
} // namespace OHOS