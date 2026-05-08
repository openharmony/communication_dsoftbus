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
constexpr char NODE_NETWORK_ID[] = "123456789";
constexpr uint64_t LANE_ID_BASE = 1122334455667788;
static SoftBusCond g_cond = {0};
static SoftBusMutex g_lock = {0};
static bool g_isNeedCondWait = true;

class LNNTransLaneAsyncTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNTransLaneAsyncTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LNNTransLaneAsyncTest start";
    LnnInitLnnLooper();
    (void)InitLaneEvent();
}

void LNNTransLaneAsyncTest::TearDownTestCase()
{
    DeinitLaneEvent();
    LnnDeinitLnnLooper();
    GTEST_LOG_(INFO) << "LNNTransLaneAsyncTest end";
}

void LNNTransLaneAsyncTest::SetUp()
{
    (void)SoftBusMutexInit(&g_lock, nullptr);
    (void)SoftBusCondInit(&g_cond);
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    LaneInterface *transObj = TransLaneGetInstance();
    EXPECT_TRUE(transObj != nullptr);
    transObj->init(nullptr);
}

void LNNTransLaneAsyncTest::TearDown()
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
    int64_t time = now.sec * USECTONSEC * USECTONSEC + now.usec + static_cast<int64_t>(waitMillis) * USECTONSEC;
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

static void SetIsNeedCondWait(void)
{
    if (SoftBusMutexLock(&g_lock) != SOFTBUS_OK) {
        GTEST_LOG_(INFO) << "SetIsNeedCondWait SoftBusMutexLock failed";
        return;
    }
    g_isNeedCondWait = true;
    (void)SoftBusMutexUnlock(&g_lock);
}

static void OnLaneFreeSuccess(uint32_t laneHandle)
{
    GTEST_LOG_(INFO) << "free lane success, laneReqId=" << laneHandle;
    CondSignal();
}

static void OnLaneAllocSuccess(uint32_t laneHandle, const LaneConnInfo *info)
{
    (void)laneHandle;
    ASSERT_NE(info, nullptr) << "invalid connInfo";
    GTEST_LOG_(INFO) << "alloc lane successful, linkType=" << info->type;
    EXPECT_EQ(info->type, LANE_P2P);
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

static void OnLaneAllocSuccessWlan5G(uint32_t laneHandle, const LaneConnInfo *info)
{
    (void)laneHandle;
    ASSERT_NE(info, nullptr) << "invalid connInfo";
    GTEST_LOG_(INFO) << "alloc lane successful, linkType=" << info->type;
    EXPECT_EQ(info->type, LANE_WLAN_5G);
    CondSignal();
}

bool IsSupportLowLatency(const TransReqInfo *reqInfo, const LaneLinkInfo *laneLinkInfo)
{
    (void)reqInfo;
    (void)laneLinkInfo;
    return true;
}

static LaneAllocListener g_listenerCb = {
    .onLaneAllocSuccess = OnLaneAllocSuccess,
    .onLaneAllocFail = nullptr,
    .onLaneFreeSuccess = OnLaneFreeSuccess,
    .onLaneFreeFail = nullptr,
};

/*
* @tc.name: LNN_LANE_BUILD_RETRY_TEST_001
* @tc.desc: test check lane with same link type (not retry)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneAsyncTest, LNN_LANE_BUILD_RETRY_TEST_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    NiceMock<LnnWifiAdpterInterfaceMock> lnnMock;
    EXPECT_CALL(lnnMock, LnnDisconnectP2p).WillRepeatedly(Return(SOFTBUS_OK));
    LaneInterface *transObj = TransLaneGetInstance();
    ASSERT_TRUE(transObj != nullptr);

    uint32_t laneReqId = LANE_REQ_ID_ONE;
    LaneAllocInfo allocInfo = {
        .type = LANE_TYPE_TRANS,
    };
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));

    LanePreferredLinkList recommendLinkList = {};
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_WLAN_5G;
    g_listenerCb.onLaneAllocSuccess = OnLaneAllocSuccessWlan5G;

    EXPECT_CALL(laneMock, SelectExpectLanesByQos)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(recommendLinkList), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink(_, _, NotNull())).WillRepeatedly(laneMock.ActionOfBuildLinkSuccess);
    EXPECT_CALL(laneMock, DestroyLink).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, DelLaneBusinessInfoItem).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, AddLaneBusinessInfoItem).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, FindLaneResourceByLaneId).WillRepeatedly(Return(SOFTBUS_LANE_NOT_FOUND));
    EXPECT_CALL(laneMock, DelLaneResourceByLaneId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, AddLaneResourceToPool).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, GenerateLaneId).WillRepeatedly(Return(LANE_ID_BASE));
    EXPECT_CALL(laneMock, CheckLinkConflictByReleaseLink).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, FreeLaneReqId).WillRepeatedly(Return());
    LnnEnhanceFuncList lnnEnhanceFunc = { nullptr };
    lnnEnhanceFunc.isSupportLowLatency = IsSupportLowLatency;
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&lnnEnhanceFunc));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetNetworkIdByUdid).WillRepeatedly(LaneDepsInterfaceMock::ActionOfLnnGetNetworkIdByUdid);

    SetIsNeedCondWait();
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = transObj->freeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LNN_LANE_BUILD_RETRY_TEST_002
* @tc.desc: test lane build retry with HML and P2P link types (not retry)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneAsyncTest, LNN_LANE_BUILD_RETRY_TEST_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LaneInterface *transObj = TransLaneGetInstance();
    ASSERT_TRUE(transObj != nullptr);

    uint32_t laneReqId = LANE_REQ_ID_ONE;
    LaneAllocInfo allocInfo = {
        .type = LANE_TYPE_TRANS,
    };
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));

    LanePreferredLinkList recommendLinkList = {};
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_HML;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_P2P;
    g_listenerCb.onLaneAllocSuccess = OnLaneAllocSuccess;

    EXPECT_CALL(laneMock, SelectExpectLanesByQos)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(recommendLinkList), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink(_, _, NotNull()))
        .WillOnce(laneMock.ActionOfBuildLinkFail)
        .WillRepeatedly(laneMock.ActionOfBuildLinkSuccess);
    EXPECT_CALL(laneMock, DestroyLink).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, DelLaneBusinessInfoItem).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, AddLaneBusinessInfoItem).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, FindLaneResourceByLaneId).WillRepeatedly(Return(SOFTBUS_LANE_NOT_FOUND));
    EXPECT_CALL(laneMock, DelLaneResourceByLaneId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, AddLaneResourceToPool).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, GenerateLaneId).WillRepeatedly(Return(LANE_ID_BASE));
    EXPECT_CALL(laneMock, CheckLinkConflictByReleaseLink).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, FreeLaneReqId).WillRepeatedly(Return());
    LnnEnhanceFuncList lnnEnhanceFunc = { nullptr };
    lnnEnhanceFunc.isSupportLowLatency = IsSupportLowLatency;
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&lnnEnhanceFunc));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetNetworkIdByUdid).WillRepeatedly(LaneDepsInterfaceMock::ActionOfLnnGetNetworkIdByUdid);

    SetIsNeedCondWait();
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = transObj->freeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LNN_LANE_BUILD_RETRY_TEST_003
* @tc.desc: test lane build retry with different link types (is retry)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneAsyncTest, LNN_LANE_BUILD_RETRY_TEST_003, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LaneInterface *transObj = TransLaneGetInstance();
    ASSERT_TRUE(transObj != nullptr);

    uint32_t laneReqId = LANE_REQ_ID_ONE;
    LaneAllocInfo allocInfo = {
        .type = LANE_TYPE_TRANS,
    };
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));

    LanePreferredLinkList recommendLinkList = {};
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_WLAN_2P4G;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_HML;
    g_listenerCb.onLaneAllocSuccess = OnLaneAllocSuccessHml;

    EXPECT_CALL(laneMock, SelectExpectLanesByQos)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(recommendLinkList), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink(_, _, NotNull()))
        .WillOnce(laneMock.ActionOfBuildLinkFail)
        .WillRepeatedly(laneMock.ActionOfBuildLinkSuccess);
    EXPECT_CALL(laneMock, DestroyLink).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, DelLaneBusinessInfoItem).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, AddLaneBusinessInfoItem).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, FindLaneResourceByLaneId).WillRepeatedly(Return(SOFTBUS_LANE_NOT_FOUND));
    EXPECT_CALL(laneMock, DelLaneResourceByLaneId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, AddLaneResourceToPool).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, GenerateLaneId).WillRepeatedly(Return(LANE_ID_BASE));
    EXPECT_CALL(laneMock, CheckLinkConflictByReleaseLink).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, FreeLaneReqId).WillRepeatedly(Return());
    LnnEnhanceFuncList lnnEnhanceFunc = { nullptr };
    lnnEnhanceFunc.isSupportLowLatency = IsSupportLowLatency;
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&lnnEnhanceFunc));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetNetworkIdByUdid).WillRepeatedly(LaneDepsInterfaceMock::ActionOfLnnGetNetworkIdByUdid);

    SetIsNeedCondWait();
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = transObj->freeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LNN_LANE_BUILD_RETRY_TEST_004
* @tc.desc: test lane build retry with P2P and HML link types (not retry)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNTransLaneAsyncTest, LNN_LANE_BUILD_RETRY_TEST_004, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<TransLaneDepsInterfaceMock> laneMock;
    LaneInterface *transObj = TransLaneGetInstance();
    ASSERT_TRUE(transObj != nullptr);

    uint32_t laneReqId = LANE_REQ_ID_ONE;
    LaneAllocInfo allocInfo = {
        .type = LANE_TYPE_TRANS,
    };
    EXPECT_EQ(EOK, strcpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID));

    LanePreferredLinkList recommendLinkList = {};
    recommendLinkList.linkTypeNum = 0;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_P2P;
    recommendLinkList.linkType[(recommendLinkList.linkTypeNum)++] = LANE_HML;
    g_listenerCb.onLaneAllocSuccess = OnLaneAllocSuccessHml;

    EXPECT_CALL(laneMock, SelectExpectLanesByQos)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(recommendLinkList), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, BuildLink(_, _, NotNull()))
        .WillOnce(laneMock.ActionOfBuildLinkFail)
        .WillRepeatedly(laneMock.ActionOfBuildLinkSuccess);
    EXPECT_CALL(laneMock, DestroyLink).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, DelLaneBusinessInfoItem).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, AddLaneBusinessInfoItem).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, FindLaneResourceByLaneId).WillRepeatedly(Return(SOFTBUS_LANE_NOT_FOUND));
    EXPECT_CALL(laneMock, DelLaneResourceByLaneId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, AddLaneResourceToPool).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, GenerateLaneId).WillRepeatedly(Return(LANE_ID_BASE));
    EXPECT_CALL(laneMock, CheckLinkConflictByReleaseLink).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, FreeLaneReqId).WillRepeatedly(Return());
    LnnEnhanceFuncList lnnEnhanceFunc = { nullptr };
    lnnEnhanceFunc.isSupportLowLatency = IsSupportLowLatency;
    EXPECT_CALL(laneMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&lnnEnhanceFunc));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetNetworkIdByUdid).WillRepeatedly(LaneDepsInterfaceMock::ActionOfLnnGetNetworkIdByUdid);

    SetIsNeedCondWait();
    int32_t ret = transObj->allocLaneByQos(laneReqId, (const LaneAllocInfo *)&allocInfo, &g_listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = transObj->freeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}
} // namespace OHOS