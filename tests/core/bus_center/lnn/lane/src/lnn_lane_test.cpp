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

#include "bus_center_info_key.h"
#include "lnn_ctrl_lane.h"
#include "lnn_lane_common.h"
#include "lnn_lane_deps_mock.h"
#include "lnn_lane_def.h"
#include "lnn_lane.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_link.h"
#include "lnn_lane_model.h"
#include "lnn_lane_select.h"
#include "lnn_link_enabled_mock.h"
#include "lnn_select_rule.h"
#include "lnn_wifi_adpter_mock.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"
#include "softbus_wifi_api_adapter.h"
#include "lnn_lane_reliability.h"
#include "lnn_lane_reliability.c"
#include "utils/wifi_direct_utils.h"
#include "wifi_direct_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char NODE_NETWORK_ID[] = "111122223333abcdef";
constexpr char PEER_IP_HML[] = "127.30.0.1";
constexpr char PEER_UDID[] = "111122223333abcdef";
constexpr char LOCAL_UDID[] = "444455556666abcdef";
constexpr uint64_t LANE_ID_BASE = 1122334455667788;
constexpr uint32_t DEFAULT_SELECT_NUM = 4;
constexpr uint32_t DEFAULT_QOSINFO_MIN_BW = 10;
constexpr uint32_t DEFAULT_QOSINFO_MAX_LATENCY = 10000;
constexpr uint32_t DEFAULT_QOSINFO_MIN_LATENCY = 2500;
constexpr uint32_t DEFAULT_LANE_RESOURCE_LANE_REF = 0;
constexpr uint32_t LOW_BW = 384 * 1024;
constexpr uint32_t MID_BW = 30 * 1024 * 1024;
constexpr uint32_t HIGH_BW = 160 * 1024 * 1024;
constexpr uint32_t PORT_A = 22;
constexpr uint32_t PORT_B = 25;
constexpr uint32_t FD = 888;
constexpr uint32_t SLEEP_FOR_LOOP_COMPLETION_MS = 50;

static SoftBusCond g_cond = {0};
static SoftBusMutex g_lock = {0};

static void OnLaneAllocSuccess(uint32_t laneHandle, const LaneConnInfo *info);
static void OnLaneAllocFail(uint32_t laneHandle, int32_t errCode);

static int32_t g_errCode = 0;
static LaneAllocListener g_listener = {
    .onLaneAllocSuccess = OnLaneAllocSuccess,
    .onLaneAllocFail = OnLaneAllocFail,
};

static NodeInfo g_NodeInfo = {
    .p2pInfo.p2pRole = 1,
    .p2pInfo.p2pMac = "abc",
    .p2pInfo.goMac = "abc",
};

class LNNLaneMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneMockTest::SetUpTestCase()
{
    int32_t ret = LooperInit();
    LaneDepsInterfaceMock mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(LaneDepsInterfaceMock::ActionOfStartBaseClient);
    ret = InitLane();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    GTEST_LOG_(INFO) << "LNNLaneMockTest start";
}

void LNNLaneMockTest::TearDownTestCase()
{
    LnnWifiAdpterInterfaceMock wifiMock;
    EXPECT_CALL(wifiMock, LnnDestroyP2p).WillRepeatedly(Return());
    DeinitLane();
    LooperDeinit();
    GTEST_LOG_(INFO) << "LNNLaneMockTest end";
}

void LNNLaneMockTest::SetUp()
{
    (void)SoftBusMutexInit(&g_lock, nullptr);
    (void)SoftBusCondInit(&g_cond);
}

void LNNLaneMockTest::TearDown()
{
    (void)SoftBusCondDestroy(&g_cond);
    (void)SoftBusCondDestroy(&g_lock);
}

static void CondSignal(void)
{
    if (SoftBusMutexLock(&g_lock) != SOFTBUS_OK) {
        return;
    }
    if (SoftBusCondSignal(&g_cond) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_lock);
        return;
    }
    (void)SoftBusMutexUnlock(&g_lock);
}

static void CondWait(void)
{
    if (SoftBusMutexLock(&g_lock) != SOFTBUS_OK) {
        return;
    }
    if (SoftBusCondWait(&g_cond, &g_lock, nullptr) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_lock);
        return;
    }
    (void)SoftBusMutexUnlock(&g_lock);
}

static void OnLaneAllocSuccess(uint32_t laneHandle, const LaneConnInfo *info)
{
    ASSERT_NE(info, nullptr) << "invalid info";
    GTEST_LOG_(INFO) << "alloc lane successful, laneReqId=" << laneHandle << ", linkType=" << info->type;
    const LnnLaneManager *laneManager = GetLaneManager();
    int32_t ret = laneManager->lnnFreeLane(laneHandle);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    CondSignal();
}

static void OnLaneAllocFail(uint32_t laneHandle, int32_t errCode)
{
    GTEST_LOG_(INFO) << "alloc lane failed, laneReqId=" << laneHandle << ", errCode=" << errCode;
    EXPECT_NE(errCode, SOFTBUS_OK);
    g_errCode = errCode;
    const LnnLaneManager *laneManager = GetLaneManager();
    int32_t ret = laneManager->lnnFreeLane(laneHandle);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    CondSignal();
}

static void OnLaneLinkFail(uint32_t reqId, int32_t reason, LaneLinkType linkType)
{
    (void)reqId;
    (void)reason;
    (void)linkType;
    return;
}

static void OnLaneLinkSuccess(uint32_t reqId, LaneLinkType linkType, const LaneLinkInfo *linkInfo)
{
    (void)reqId;
    (void)linkType;
    (void)linkInfo;
    return;
}

static void OnLaneAllocSuccessForHml(uint32_t laneHandle, const LaneConnInfo *info)
{
    (void)laneHandle;
    ASSERT_NE(info, nullptr) << "invalid connInfo";
    GTEST_LOG_(INFO) << "alloc lane successful, linkType=" << info->type;
    EXPECT_EQ(info->type, LANE_HML);
}

static void OnLaneAllocSuccessForP2p(uint32_t laneHandle, const LaneConnInfo *info)
{
    (void)laneHandle;
    ASSERT_NE(info, nullptr) << "invalid connInfo";
    GTEST_LOG_(INFO) << "alloc lane successful, linkType=" << info->type;
    EXPECT_EQ(info->type, LANE_P2P);
}

static void OnLaneAllocSuccessForBr(uint32_t laneHandle, const LaneConnInfo *info)
{
    (void)laneHandle;
    ASSERT_NE(info, nullptr) << "invalid connInfo";
    GTEST_LOG_(INFO) << "alloc lane successful, linkType=" << info->type;
    EXPECT_EQ(info->type, LANE_BR);
}

static void OnLaneAllocSuccessForWlan5g(uint32_t laneHandle, const LaneConnInfo *info)
{
    (void)laneHandle;
    ASSERT_NE(info, nullptr) << "invalid connInfo";
    GTEST_LOG_(INFO) << "alloc lane successful, linkType=" << info->type;
    EXPECT_EQ(info->type, LANE_WLAN_5G);
}

static int32_t AddLaneResourceForAllocTest(LaneLinkType linkType)
{
    LaneLinkInfo linkInfo;
    if (memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo)) != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    linkInfo.type = linkType;
    if (strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML, strlen(PEER_IP_HML)) != EOK) {
        return SOFTBUS_STRCPY_ERR;
    }
    if (strncpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID, strlen(PEER_UDID)) != EOK) {
        return SOFTBUS_STRCPY_ERR;
    }
    return AddLaneResourceToPool(&linkInfo, LANE_ID_BASE, false);
}

static void CreateAllocInfoForAllocTest(LaneType laneType, LaneTransType transType, uint32_t minBW,
    LaneAllocInfo *allocInfo)
{
    ASSERT_NE(allocInfo, nullptr) << "invalid allocInfo";
    allocInfo->type = laneType;
    ASSERT_EQ(strncpy_s(allocInfo->networkId, NETWORK_ID_BUF_LEN,
        NODE_NETWORK_ID, strlen(NODE_NETWORK_ID)), EOK);
    allocInfo->transType = transType;
    allocInfo->qosRequire.minBW = minBW;
    allocInfo->qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    allocInfo->qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;
}

/*
* @tc.name: LANE_ALLOC_Test_001
* @tc.desc: lane request for Wlan2p4G MSG  HIGH BW
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(16), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(16), Return(SOFTBUS_OK)));
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    EXPECT_CALL(enabledMock, IsLinkEnabled).WillRepeatedly(Return(false));

    LaneAllocInfo allocInfo;
    (void)memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo));
    CreateAllocInfoForAllocTest(laneType, LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + HIGH_BW, &allocInfo);
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_Test_002
* @tc.desc: lane request for Wlan2p4G MSG  MID BW
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(16), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(16), Return(SOFTBUS_OK)));
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    EXPECT_CALL(enabledMock, IsLinkEnabled).WillRepeatedly(Return(false));

    LaneAllocInfo allocInfo;
    (void)memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo));
    CreateAllocInfoForAllocTest(laneType, LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + LOW_BW, &allocInfo);
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_Test_003
* @tc.desc: lane request for Wlan2p4G MSG  LOW BW
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_003, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(16), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(16), Return(SOFTBUS_OK)));
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    EXPECT_CALL(enabledMock, IsLinkEnabled).WillRepeatedly(Return(false));

    LaneAllocInfo allocInfo;
    (void)memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo));
    CreateAllocInfoForAllocTest(laneType, LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW, &allocInfo);
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_Test_004
* @tc.desc: lane request for Wlan5G byte  HIGH BW
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_004, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(32), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(32), Return(SOFTBUS_OK)));
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    EXPECT_CALL(enabledMock, IsLinkEnabled).WillRepeatedly(Return(false));

    LaneAllocInfo allocInfo;
    (void)memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo));
    CreateAllocInfoForAllocTest(laneType, LANE_T_BYTE, DEFAULT_QOSINFO_MIN_BW + HIGH_BW, &allocInfo);
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_Test_005
* @tc.desc: lane request for Wlan5G byte MID BW
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_005, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(32), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(32), Return(SOFTBUS_OK)));
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    EXPECT_CALL(enabledMock, IsLinkEnabled).WillRepeatedly(Return(false));

    LaneAllocInfo allocInfo;
    (void)memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo));
    CreateAllocInfoForAllocTest(laneType, LANE_T_BYTE, DEFAULT_QOSINFO_MIN_BW + LOW_BW, &allocInfo);
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_Test_006
* @tc.desc: lane request for Wlan5G byte  LOW BW
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_006, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(32), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(32), Return(SOFTBUS_OK)));
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    EXPECT_CALL(enabledMock, IsLinkEnabled).WillRepeatedly(Return(false));

    LaneAllocInfo allocInfo;
    (void)memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo));
    CreateAllocInfoForAllocTest(laneType, LANE_T_BYTE, DEFAULT_QOSINFO_MIN_BW, &allocInfo);
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_Test_007
* @tc.desc: lane request for Wlan5G RAW-STREAM  HIGH BW
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_007, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(32), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(32), Return(SOFTBUS_OK)));
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    EXPECT_CALL(enabledMock, IsLinkEnabled).WillRepeatedly(Return(false));

    LaneAllocInfo allocInfo;
    (void)memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo));
    CreateAllocInfoForAllocTest(laneType, LANE_T_RAW_STREAM, DEFAULT_QOSINFO_MIN_BW + HIGH_BW, &allocInfo);
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_Test_008
* @tc.desc: lane request for Wlan5G RAW-STREAM  MID BW
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_008, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(32), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(32), Return(SOFTBUS_OK)));
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    EXPECT_CALL(enabledMock, IsLinkEnabled).WillRepeatedly(Return(false));

    LaneAllocInfo allocInfo;
    (void)memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo));
    CreateAllocInfoForAllocTest(laneType, LANE_T_RAW_STREAM, DEFAULT_QOSINFO_MIN_BW + LOW_BW, &allocInfo);
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_Test_009
* @tc.desc: lane request for Wlan5G RAW-STREAM LOW BW
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_009, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(32), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(32), Return(SOFTBUS_OK)));
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    EXPECT_CALL(enabledMock, IsLinkEnabled).WillRepeatedly(Return(false));

    LaneAllocInfo allocInfo;
    (void)memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo));
    CreateAllocInfoForAllocTest(laneType, LANE_T_RAW_STREAM, DEFAULT_QOSINFO_MIN_BW, &allocInfo);
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_Test_010
* @tc.desc: lane request failue
* @tc.type: FAILUE
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_010, TestSize.Level1)
{
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    EXPECT_CALL(enabledMock, IsLinkEnabled).WillRepeatedly(Return(false));
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);
    LaneAllocInfo allocInfo;
    (void)memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo));
    allocInfo.type = LANE_TYPE_BUTT;
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = laneManager->lnnAllocLane(laneReqId, nullptr, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    laneReqId = 0xFFFFFFFF;
    ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    allocInfo.type = LANE_TYPE_BUTT;
    ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LANE_RE_ALLOC_Test_001
* @tc.desc: lane re alloc for invalid param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_RE_ALLOC_Test_001, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    int32_t ret = laneManager->lnnReAllocLane(laneReqId, LANE_ID_BASE, nullptr, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    LaneAllocInfo allocInfo;
    ASSERT_EQ(memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo)), EOK);
    allocInfo.type = LANE_TYPE_BUTT;

    ret = laneManager->lnnReAllocLane(laneReqId, LANE_ID_BASE, &allocInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = laneManager->lnnReAllocLane(laneReqId, LANE_ID_BASE, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = laneManager->lnnReAllocLane(INVALID_LANE_REQ_ID, LANE_ID_BASE, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = laneManager->lnnReAllocLane(laneReqId, INVALID_LANE_ID, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    allocInfo.type = LANE_TYPE_HDLC;
    ret = laneManager->lnnReAllocLane(laneReqId, INVALID_LANE_ID, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
* @tc.name: LANE_RE_ALLOC_Test_002
* @tc.desc: lane re alloc for MSG HIGH_BW
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_RE_ALLOC_Test_002, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    int32_t ret = AddLaneResourceForAllocTest(LANE_HML);
    EXPECT_EQ(ret, SOFTBUS_OK);

    LaneAllocListener listenerCb = {
        .onLaneAllocSuccess = OnLaneAllocSuccessForP2p,
        .onLaneAllocFail = OnLaneAllocFail,
    };
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    EXPECT_CALL(enabledMock, IsLinkEnabled).WillRepeatedly(Return(false));
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(63, 63, 8, 8);

    LaneAllocInfo allocInfo;
    ASSERT_EQ(memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo)), EOK);
    CreateAllocInfoForAllocTest(laneType, LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + HIGH_BW, &allocInfo);
    ret = laneManager->lnnReAllocLane(laneReqId, LANE_ID_BASE, &allocInfo, &listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_FOR_LOOP_COMPLETION_MS));
    ret = DelLaneResourceByLaneId(LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LANE_RE_ALLOC_Test_003
* @tc.desc: lane re alloc for MSG MID_HIGH_BW
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_RE_ALLOC_Test_003, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    int32_t ret = AddLaneResourceForAllocTest(LANE_HML);
    EXPECT_EQ(ret, SOFTBUS_OK);

    LaneAllocListener listenerCb = {
        .onLaneAllocSuccess = OnLaneAllocSuccessForWlan5g,
        .onLaneAllocFail = OnLaneAllocFail,
    };
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    SoftBusWifiLinkedInfo wlanInfo;
    wlanInfo.band = 0;
    wlanInfo.connState = SOFTBUS_API_WIFI_CONNECTED;
    EXPECT_CALL(wifiMock, SoftBusGetLinkedInfo)
        .WillRepeatedly(DoAll(SetArgPointee<0>(wlanInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    EXPECT_CALL(enabledMock, IsLinkEnabled).WillRepeatedly(Return(false));
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(63, 63, 8, 8);
    EXPECT_CALL(mock, AddTrigger).WillRepeatedly(LaneDepsInterfaceMock::ActionOfAddTrigger);
    char buf[] = "lanedetect";
    EXPECT_CALL(mock, ConnSendSocketData).WillRepeatedly(Return(sizeof(buf)));

    LaneAllocInfo allocInfo;
    ASSERT_EQ(memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo)), EOK);
    CreateAllocInfoForAllocTest(laneType, LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + MID_BW, &allocInfo);
    ret = laneManager->lnnReAllocLane(laneReqId, LANE_ID_BASE, &allocInfo, &listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_FOR_LOOP_COMPLETION_MS));
    ret = DelLaneResourceByLaneId(LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LANE_RE_ALLOC_Test_004
* @tc.desc: lane re alloc for MSG MID_LOW_BW
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_RE_ALLOC_Test_004, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    int32_t ret = AddLaneResourceForAllocTest(LANE_WLAN_5G);
    EXPECT_EQ(ret, SOFTBUS_OK);

    LaneAllocListener listenerCb = {
        .onLaneAllocSuccess = OnLaneAllocSuccessForHml,
        .onLaneAllocFail = OnLaneAllocFail,
    };
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    EXPECT_CALL(enabledMock, IsLinkEnabled).WillRepeatedly(Return(false));
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(63, 63, 8, 8);

    LaneAllocInfo allocInfo;
    ASSERT_EQ(memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo)), EOK);
    CreateAllocInfoForAllocTest(laneType, LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + LOW_BW, &allocInfo);
    ret = laneManager->lnnReAllocLane(laneReqId, LANE_ID_BASE, &allocInfo, &listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_FOR_LOOP_COMPLETION_MS));
    ret = DelLaneResourceByLaneId(LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LANE_RE_ALLOC_Test_005
* @tc.desc: lane re alloc for MSG LOW_BW
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_RE_ALLOC_Test_005, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    int32_t ret = AddLaneResourceForAllocTest(LANE_HML);
    EXPECT_EQ(ret, SOFTBUS_OK);

    LaneAllocListener listenerCb = {
        .onLaneAllocSuccess = OnLaneAllocSuccessForBr,
        .onLaneAllocFail = OnLaneAllocFail,
    };
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    EXPECT_CALL(enabledMock, IsLinkEnabled).WillRepeatedly(Return(false));
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(15, 15, 8, 8);

    LaneAllocInfo allocInfo;
    ASSERT_EQ(memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo)), EOK);
    CreateAllocInfoForAllocTest(laneType, LANE_T_MSG, LOW_BW - DEFAULT_QOSINFO_MIN_BW, &allocInfo);
    ret = laneManager->lnnReAllocLane(laneReqId, LANE_ID_BASE, &allocInfo, &listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_FOR_LOOP_COMPLETION_MS));
    ret = DelLaneResourceByLaneId(LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LANE_ALLOC_ErrTest_001
* @tc.desc: lane errcode test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_ERRTEST_001, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    LaneAllocListener listenerCb = {
        .onLaneAllocSuccess = OnLaneAllocSuccessForP2p,
        .onLaneAllocFail = OnLaneAllocFail,
    };
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfOnConnectP2pFail);
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    EXPECT_CALL(enabledMock, IsLinkEnabled).WillRepeatedly(Return(false));
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(63, 63, 0, 0);
    EXPECT_CALL(mock, ConnOpenClientSocket).WillRepeatedly(Return(SOFTBUS_CONN_FAIL));

    LaneAllocInfo allocInfo;
    ASSERT_EQ(memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo)), EOK);
    CreateAllocInfoForAllocTest(laneType, LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + HIGH_BW, &allocInfo);
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_FOR_LOOP_COMPLETION_MS));
    EXPECT_EQ(g_errCode, ERROR_WIFI_OFF);
    
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LANE_CANCEL_Test_001
* @tc.desc: lane cancel
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_CANCEL_Test_001, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    LaneAllocListener listenerCb = {
        .onLaneAllocSuccess = OnLaneAllocSuccessForP2p,
        .onLaneAllocFail = OnLaneAllocFail,
    };
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    EXPECT_CALL(enabledMock, IsLinkEnabled).WillRepeatedly(Return(false));
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(63, 63, 0, 0);

    LaneAllocInfo allocInfo;
    ASSERT_EQ(memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo)), EOK);
    CreateAllocInfoForAllocTest(laneType, LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + HIGH_BW, &allocInfo);
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_FOR_LOOP_COMPLETION_MS));
    ret = laneManager->lnnCancelLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LANE_CANCEL_Test_002
* @tc.desc: lane cancel
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_CANCEL_Test_002, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    LaneAllocListener listenerCb = {
        .onLaneAllocSuccess = OnLaneAllocSuccessForP2p,
        .onLaneAllocFail = OnLaneAllocFail,
    };
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    LnnWifiAdpterInterfaceMock::delayNotifyLinkSuccess = true;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    EXPECT_CALL(enabledMock, IsLinkEnabled).WillRepeatedly(Return(false));
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(63, 63, 0, 0);

    LaneAllocInfo allocInfo;
    ASSERT_EQ(memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo)), EOK);
    CreateAllocInfoForAllocTest(laneType, LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + HIGH_BW, &allocInfo);
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = laneManager->lnnCancelLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_FOR_LOOP_COMPLETION_MS * 2));
    LnnWifiAdpterInterfaceMock::delayNotifyLinkSuccess = false;
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LANE_CANCEL_Test_003
* @tc.desc: lane cancel
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_CANCEL_Test_003, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    LaneAllocListener listenerCb = {
        .onLaneAllocSuccess = OnLaneAllocSuccessForP2p,
        .onLaneAllocFail = OnLaneAllocFail,
    };
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    EXPECT_CALL(enabledMock, IsLinkEnabled).WillRepeatedly(Return(false));
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(63, 63, 0, 0);

    LaneAllocInfo allocInfo;
    ASSERT_EQ(memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo)), EOK);
    CreateAllocInfoForAllocTest(laneType, LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + HIGH_BW, &allocInfo);
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &listenerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_FOR_LOOP_COMPLETION_MS));
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = laneManager->lnnCancelLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
* @tc.name: LANE_FREE_001
* @tc.desc: lane free
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_FREE_001, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_BUTT;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    int32_t ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    laneType = LANE_TYPE_TRANS;
    laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_INFO_001
* @tc.desc: LaneInfoProcess BR
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_INFO_001, TestSize.Level1)
{
    LaneLinkInfo info;
    (void)memset_s(&info, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    info.type = LANE_BR;
    LaneConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    LaneProfile profile;
    (void)memset_s(&profile, sizeof(LaneProfile), 0, sizeof(LaneProfile));
    int32_t ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_INFO_002
* @tc.desc: LaneInfoProcess BLE
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_INFO_002, TestSize.Level1)
{
    LaneLinkInfo info;
    (void)memset_s(&info, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    info.type = LANE_BLE;
    LaneConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    LaneProfile profile;
    (void)memset_s(&profile, sizeof(LaneProfile), 0, sizeof(LaneProfile));
    int32_t ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_INFO_003
* @tc.desc: LaneInfoProcess P2P
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_INFO_003, TestSize.Level1)
{
    LaneLinkInfo info;
    (void)memset_s(&info, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    info.type = LANE_P2P;
    LaneConnInfo connInfo;
    (void)memset_s(&connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    LaneProfile profile;
    (void)memset_s(&profile, sizeof(LaneProfile), 0, sizeof(LaneProfile));
    int32_t ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_INFO_004
* @tc.desc: LaneInfoProcess fail
* @tc.type: FAILUE
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_INFO_004, TestSize.Level1)
{
    LaneLinkInfo info;
    (void)memset_s(&info, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    info.type = LANE_LINK_TYPE_BUTT;
    LaneConnInfo *connInfo = nullptr;
    LaneProfile *profile = nullptr;
    int32_t ret = LaneInfoProcess(nullptr, connInfo, profile);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = LaneInfoProcess(&info, nullptr, profile);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = LaneInfoProcess(&info, connInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = LaneInfoProcess(&info, connInfo, profile);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
* @tc.name: LANE_INFO_005
* @tc.desc: LaneInfoProcess 2.4G
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_INFO_005, TestSize.Level1)
{
    LaneLinkInfo info;
    LaneConnInfo connInfo;
    LaneProfile profile;
    (void)memset_s(&info, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    (void)memset_s(&connInfo, sizeof(LaneConnInfo), 0, sizeof(LaneConnInfo));
    (void)memset_s(&profile, sizeof(LaneProfile), 0, sizeof(LaneProfile));

    info.type = LANE_WLAN_2P4G;
    int32_t ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info.type = LANE_WLAN_5G;
    ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info.type = LANE_P2P_REUSE;
    ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info.type = LANE_BLE_DIRECT;
    ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info.type = LANE_COC;
    ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_DATA_001
* @tc.desc: LnnCreateData
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_DATA_001, TestSize.Level1)
{
    int32_t ret = LnnCreateData(nullptr, 32, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    LnnDeleteData(nullptr, 32);
}

/*
* @tc.name: LNN_LANE_PROFILE_001
* @tc.desc: BindLaneIdToProfile
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_PROFILE_001, TestSize.Level1)
{
    uint64_t laneId = 0x1000000000000001;
    int32_t ret = BindLaneIdToProfile(laneId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    LaneProfile profile;
    (void)memset_s(&profile, sizeof(LaneProfile), 0, sizeof(LaneProfile));
    ret = BindLaneIdToProfile(laneId, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    profile.linkType = LANE_P2P;
    profile.content = LANE_T_FILE;
    profile.priority = LANE_PRI_LOW;
    ret = BindLaneIdToProfile(laneId, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    LaneGenerateParam param;
    (void)memset_s(&param, sizeof(LaneGenerateParam), 0, sizeof(LaneGenerateParam));
    param.linkType = LANE_P2P;
    param.transType = LANE_T_FILE;
    param.priority = LANE_PRI_LOW;
    uint32_t profileId = GenerateLaneProfileId(&param);

    ret = GetLaneProfile(profileId, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = GetLaneProfile(profileId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    uint64_t *laneReqIdList = nullptr;
    uint32_t listSize = 0;
    ret = GetLaneIdList(profileId, &laneReqIdList, &listSize);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(laneReqIdList);

    (void)GetActiveProfileNum();

    (void)UnbindLaneIdFromProfile(laneId, profileId);

    (void)UnbindLaneIdFromProfile(0, profileId);
}

/*
* @tc.name: LNN_SELECT_LANE_001
* @tc.desc: SelectLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_SELECT_LANE_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LanePreferredLinkList *linkList = nullptr;
    uint32_t listNum = 0;
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = LANE_T_FILE;
    selectParam.expectedBw = 0;
    selectParam.list.linkTypeNum = 2;
    selectParam.list.linkType[0] = LANE_WLAN_5G;
    selectParam.list.linkType[1] = LANE_LINK_TYPE_BUTT;

    int32_t ret = SelectLane(NODE_NETWORK_ID, nullptr, linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(false));
    LnnWifiAdpterInterfaceMock wifiMock;
    wifiMock.SetDefaultResult();
    ret = SelectLane(NODE_NETWORK_ID, &selectParam, linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    ret = SelectLane(NODE_NETWORK_ID, &selectParam, linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    selectParam.transType = LANE_T_MIX;
    ret = SelectLane(NODE_NETWORK_ID, &selectParam, linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    SoftBusFree(linkList);
}

/*
* @tc.name: LNN_SELECT_LANE_002
* @tc.desc: SelectLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_SELECT_LANE_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LanePreferredLinkList *linkList = nullptr;
    uint32_t listNum = 0;
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = LANE_T_FILE;
    selectParam.expectedBw = 0;
    selectParam.list.linkTypeNum = DEFAULT_SELECT_NUM;
    selectParam.list.linkType[0] = LANE_BLE;
    selectParam.list.linkType[1] = LANE_WLAN_2P4G;
    selectParam.list.linkType[2] = LANE_WLAN_5G;
    selectParam.list.linkType[3] = LANE_BR;

    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    LnnWifiAdpterInterfaceMock wifiMock;
    wifiMock.SetDefaultResult();
    int32_t ret = SelectLane(NODE_NETWORK_ID, &selectParam, linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<2>(1), Return(SOFTBUS_OK)));
    ret = SelectLane(NODE_NETWORK_ID, &selectParam, linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    SoftBusFree(linkList);
}

/*
* @tc.name: LNN_SELECT_LANE_003
* @tc.desc: SelectLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_SELECT_LANE_003, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LanePreferredLinkList linkList;
    uint32_t listNum = 0;
    LaneSelectParam selectParam;
    NodeInfo node;

    LnnWifiAdpterInterfaceMock wifiMock;
    (void)memset_s(&linkList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    (void)memset_s(&node, sizeof(node), 0, sizeof(node));

    selectParam.transType = LANE_T_FILE;
    selectParam.expectedBw = 0;
    selectParam.list.linkTypeNum = 7;
    selectParam.list.linkType[0] = LANE_P2P;
    selectParam.list.linkType[1] = LANE_ETH;
    selectParam.list.linkType[2] = LANE_P2P_REUSE;
    selectParam.list.linkType[3] = LANE_BLE_DIRECT;
    selectParam.list.linkType[4] = LANE_BLE_REUSE;
    selectParam.list.linkType[5] = LANE_COC;
    selectParam.list.linkType[6] = LANE_COC_DIRECT;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumU64Info).WillRepeatedly(Return(SOFTBUS_ERR));
    wifiMock.SetDefaultResult();
    int32_t ret = SelectLane(NODE_NETWORK_ID, &selectParam, &linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    node.discoveryType = 3;
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById)
        .WillRepeatedly(DoAll(SetArgPointee<2>(node), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(1), Return(SOFTBUS_OK)));
    ret = SelectLane(NODE_NETWORK_ID, &selectParam, &linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
* @tc.name: LNN_SELECT_LANE_004
* @tc.desc: SelectLane, HmlIsExist == true
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_SELECT_LANE_004, TestSize.Level1)
{
    LaneSelectParam request;
    (void)memset_s(&request, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    request.transType = LANE_T_FILE;
    request.list.linkTypeNum = 0;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_BR;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_BLE;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_P2P;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_HML;

    LanePreferredLinkList recommendList;
    (void)memset_s(&recommendList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    uint32_t listNum = 0;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info).WillRepeatedly(DoAll(SetArgPointee<1>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU32Info).WillRepeatedly(DoAll(SetArgPointee<2>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(8), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(8), Return(SOFTBUS_OK)));

    int32_t ret = SelectLane(NODE_NETWORK_ID, &request, &recommendList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_SELECT_LANE_005
* @tc.desc: SelectLane, HmlIsExist == false && LaneAddHml
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_SELECT_LANE_005, TestSize.Level1)
{
    LaneSelectParam request;
    (void)memset_s(&request, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    request.transType = LANE_T_FILE;
    request.list.linkTypeNum = 0;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_BR;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_BLE;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_P2P;

    LanePreferredLinkList recommendList;
    (void)memset_s(&recommendList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    uint32_t listNum = 0;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info).WillRepeatedly(DoAll(SetArgPointee<1>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU32Info).WillRepeatedly(DoAll(SetArgPointee<2>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(8), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(8), Return(SOFTBUS_OK)));

    int32_t ret = SelectLane(NODE_NETWORK_ID, &request, &recommendList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_BUILD_LINK_001
* @tc.desc: BUILDLINK
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_BUILD_LINK_001, TestSize.Level1)
{
    LinkRequest reqInfo;
    (void)memset_s(&reqInfo, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    reqInfo.linkType = LANE_P2P;
    LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };
    int32_t ret;
    LnnWifiAdpterInterfaceMock wifiMock;
    EXPECT_CALL(wifiMock, LnnDisconnectP2p).WillRepeatedly(Return());
    EXPECT_CALL(wifiMock, LnnConnectP2p)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_TRUE(ret == SOFTBUS_ERR);

    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    cb.OnLaneLinkFail = nullptr;
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    cb.OnLaneLinkSuccess = nullptr;
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = BuildLink(&reqInfo, 0, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    reqInfo.linkType = LANE_BLE;
    ret = BuildLink(&reqInfo, 0, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    reqInfo.linkType = LANE_LINK_TYPE_BUTT;
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = BuildLink(nullptr, 0, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    DestroyLink(NODE_NETWORK_ID, 0, LANE_BLE);
    
    EXPECT_CALL(wifiMock, LnnDestroyP2p).WillRepeatedly(Return());
    DestroyLink(NODE_NETWORK_ID, 0, LANE_P2P);
    DestroyLink(nullptr, 0, LANE_P2P);
}

/*
* @tc.name: LNN_BUILD_LINK_002
* @tc.desc: BUILDLINK
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_BUILD_LINK_002, TestSize.Level1)
{
    LaneDepsInterfaceMock mock;
    LinkRequest reqInfo;
    (void)memset_s(&reqInfo, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    reqInfo.linkType = LANE_P2P;
    LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };
    int32_t ret;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    const char *udid = "testuuid";
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    EXPECT_CALL(mock, LnnConvertDLidToUdid).WillRepeatedly(Return(udid));
    EXPECT_CALL(mock, ConnBleGetClientConnectionByUdid).WillRepeatedly(Return(NULL));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_ERR));
    ON_CALL(wifiMock, LnnConnectP2p).WillByDefault(Return(SOFTBUS_ERR));
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: LNN_BUILD_LINK_003
* @tc.desc: BUILDLINK
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_BUILD_LINK_003, TestSize.Level1)
{
    LaneDepsInterfaceMock mock;
    LinkRequest reqInfo;
    (void)memset_s(&reqInfo, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    reqInfo.linkType = LANE_P2P;
    LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };
    int32_t ret;
    LnnWifiAdpterInterfaceMock wifiMock;
    
    ConnBleConnection *connection = (ConnBleConnection*)SoftBusCalloc(sizeof(ConnBleConnection));
    if (connection == NULL) {
        return;
    }
    const char *udid = "testuuid";
    NodeInfo *nodeInfo = (NodeInfo*)SoftBusCalloc(sizeof(NodeInfo));
    if (nodeInfo == NULL) {
        return;
    }
    connection->state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    EXPECT_CALL(mock, LnnConvertDLidToUdid).WillRepeatedly(Return(udid));
    EXPECT_CALL(mock, ConnBleGetClientConnectionByUdid).WillRepeatedly(Return(connection));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(wifiMock, LnnConnectP2p).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalNodeInfo).WillRepeatedly(Return(nodeInfo));
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusFree(connection);
    SoftBusFree(nodeInfo);
}

/*
* @tc.name: LNN_BUILD_LINK_004
* @tc.desc: BUILDLINK
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_BUILD_LINK_004, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LinkRequest reqInfo;
    int32_t ret;
    const char *udid = "testuuid";
    (void)memset_s(&reqInfo, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    reqInfo.linkType = LANE_BLE;
    EXPECT_CALL(mock, LnnConvertDLidToUdid).WillRepeatedly(Return(udid));
    EXPECT_CALL(mock, ConnBleGetClientConnectionByUdid).WillRepeatedly(Return(nullptr));
    ON_CALL(mock, LnnGetRemoteStrInfo).WillByDefault(Return(SOFTBUS_ERR));
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_NE(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    ON_CALL(mock, SoftBusGenerateStrHash).WillByDefault(Return(SOFTBUS_ERR));
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_NE(ret, SOFTBUS_OK);
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_BUILD_LINK_005
* @tc.desc: BUILDLINK
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_BUILD_LINK_005, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LinkRequest reqInfo;
    int32_t ret;
    const char *udid = "testuuid";
    LnnWifiAdpterInterfaceMock wifiMock;
    LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    (void)memset_s(&reqInfo, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    reqInfo.linkType = LANE_BLE;
    ConnBleConnection *connection = (ConnBleConnection *)SoftBusCalloc(sizeof(ConnBleConnection));
    if (connection == nullptr) {
        return;
    }
    connection->state = BLE_CONNECTION_STATE_INVALID;
    EXPECT_CALL(mock, LnnConvertDLidToUdid).WillRepeatedly(Return(udid));
    EXPECT_CALL(mock, ConnBleGetClientConnectionByUdid).WillRepeatedly(Return(connection));
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    ON_CALL(mock, LnnGetRemoteNodeInfoById).WillByDefault(Return(SOFTBUS_OK));
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_TRUE(ret == SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
    SoftBusFree(connection);
}

/*
* @tc.name: LNN_BUILD_LINK_006
* @tc.desc: BUILDLINK
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_BUILD_LINK_006, TestSize.Level1)
{
    uint32_t reqId = 0;
    const char *networkId = "testnetworkid123";
    const char *networkIdNotFound = "testnetworkid133";
    const char *ipAddr = "127.0.0.1";
    const char *ipAddrDiff = "127.0.0.2";
    uint16_t portA = 22;
    uint16_t portB = 33;
    LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };
    LaneDepsInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    LinkRequest *request = (LinkRequest *)SoftBusCalloc(sizeof(LinkRequest));
    if (request == nullptr) {
        return;
    }
    LaneAddP2pAddress(networkId, ipAddr, portA);
    LaneAddP2pAddress(networkId, ipAddr, portB);
    LaneAddP2pAddressByIp(ipAddr, portB);
    LaneAddP2pAddressByIp(ipAddrDiff, portB);
    request->linkType = LANE_P2P_REUSE;
    (void)strcpy_s(request->peerNetworkId, NETWORK_ID_BUF_LEN, networkId);
    int32_t ret = BuildLink(request, reqId, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    (void)strcpy_s(request->peerNetworkId, NETWORK_ID_BUF_LEN, networkIdNotFound);
    ret = BuildLink(request, reqId, &cb);
    EXPECT_TRUE(ret == SOFTBUS_NOT_FIND);
    SoftBusFree(request);
    LaneDeleteP2pAddress(networkId, true);
}

/*
* @tc.name: LNN_BUILD_LINK_007
* @tc.desc: BUILDLINK
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_BUILD_LINK_007, TestSize.Level1)
{
    LaneDepsInterfaceMock mock;
    uint32_t reqId = 0;
    LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };
    LinkRequest *request = (LinkRequest *)SoftBusCalloc(sizeof(LinkRequest));
    if (request == nullptr) {
        return;
    }
    NodeInfo *nodeInfo = (NodeInfo *)SoftBusCalloc(sizeof(NodeInfo));
    if (nodeInfo == nullptr) {
        SoftBusFree(request);
        return;
    }
    request->linkType = LANE_BLE_DIRECT;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetLocalNodeInfo).WillRepeatedly(Return(nodeInfo));

    int32_t ret = BuildLink(request, reqId, &cb);
    ret = BuildLink(request, reqId, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusFree(request);
    SoftBusFree(nodeInfo);
}

/*
* @tc.name: LNN_BUILD_LINK_008
* @tc.desc: BUILDLINK
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_BUILD_LINK_008, TestSize.Level1)
{
    LaneDepsInterfaceMock mock;
    LinkRequest reqInfo;
    int32_t ret;
    const char *udid = "testuuid";
    const char *bleMac = "127.1.1.1";
    (void)memset_s(&reqInfo, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    reqInfo.linkType = LANE_COC;
    if (strcpy_s(reqInfo.peerBleMac, MAX_MAC_LEN, bleMac) != EOK) {
        return;
    }
    EXPECT_CALL(mock, LnnConvertDLidToUdid).WillRepeatedly(Return(udid));
    EXPECT_CALL(mock, ConnBleGetClientConnectionByUdid).WillRepeatedly(Return(nullptr));
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_ERR));
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);

    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusGenerateStrHash)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(LaneDepsInterfaceMock::ActionOfGenerateStrHash);
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_BUILD_LINK_009
* @tc.desc: BUILDLINK
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_BUILD_LINK_009, TestSize.Level1)
{
    uint32_t reqId = 0;
    const char *networkId = "testnetworkid123";
    const char *networkIdNotFound = "testnetworkid133";
    LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };
    LaneDepsInterfaceMock mock;
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    LinkRequest *request = (LinkRequest *)SoftBusCalloc(sizeof(LinkRequest));
    if (request == nullptr) {
        return;
    }
    request->linkType = LANE_COC_DIRECT;
    if (strcpy_s(request->peerNetworkId, NETWORK_ID_BUF_LEN, networkId) != EOK) {
        return;
    }
    int32_t ret = BuildLink(request, reqId, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    if (strcpy_s(request->peerNetworkId, NETWORK_ID_BUF_LEN, networkIdNotFound) != EOK) {
        return;
    }
    ret = BuildLink(request, reqId, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusFree(request);
    LaneDeleteP2pAddress(networkId, true);
}

/*
* @tc.name: LNN_BUILD_LINK_010
* @tc.desc: BUILDLINK
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_BUILD_LINK_010, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LinkRequest reqInfo;
    int32_t ret;
    const char *udid = "testuuid";
    const char *bleMac = "127.1.1.1";
    (void)memset_s(&reqInfo, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };
    ConnBleConnection *connection = (ConnBleConnection *)SoftBusCalloc(sizeof(ConnBleConnection));
    if (connection == nullptr) {
        return;
    }
    connection->state = BLE_CONNECTION_STATE_EXCHANGED_BASIC_INFO;
    reqInfo.linkType = LANE_BLE_REUSE;
    if (strcpy_s(reqInfo.peerBleMac, MAX_MAC_LEN, bleMac) != EOK) {
        return;
    }
    ON_CALL(mock, ConnBleGetConnectionByUdid).WillByDefault(Return(connection));
    ON_CALL(mock, ConnBleReturnConnection).WillByDefault(Return());
    EXPECT_CALL(mock, LnnConvertDLidToUdid).WillRepeatedly(Return(udid));
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    EXPECT_CALL(mock, ConnBleGetConnectionByUdid).WillRepeatedly(Return(connection));
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusFree(connection);
}

/*
* @tc.name: LANE_ADD_P2P_ADDRESS_TEST_001
* @tc.desc: LANE ADD P2P ADDRESS TEST
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ADD_P2P_ADDRESS_TEST_001, TestSize.Level1)
{
    const char *networkId = "testnetworkid123";
    const char *ipAddr = "127.0.0.1";
    uint16_t port = 1022;
    LaneAddP2pAddress(networkId, ipAddr, port);
    LaneAddP2pAddressByIp(ipAddr, port);
    LaneUpdateP2pAddressByIp(ipAddr, networkId);
}

/*
* @tc.name: LNN_SELECT_EXPECT_LANES_BY_QOS_001
* @tc.desc: SelectExpectLanesByQos
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_SELECT_EXPECT_LANES_BY_QOS_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LanePreferredLinkList linkList;
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = LANE_T_FILE;
    selectParam.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW;
    selectParam.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    selectParam.qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;
    int32_t ret = SelectExpectLanesByQos(NODE_NETWORK_ID, nullptr, &linkList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    LnnWifiAdpterInterfaceMock wifiMock;
    wifiMock.SetDefaultResult();
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(false));
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NODE_OFFLINE);

    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_OK);


    selectParam.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW + LOW_BW;
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_OK);

    selectParam.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW + HIGH_BW;
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_OK);

    selectParam.transType = LANE_T_MIX;
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_SELECT_EXPECT_LANES_BY_QOS_002
* @tc.desc: SelectExpectLanesByQos
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_SELECT_EXPECT_LANES_BY_QOS_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LanePreferredLinkList linkList;
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = LANE_T_FILE;
    int32_t ret = SelectExpectLanesByQos(NODE_NETWORK_ID, nullptr, &linkList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(false));
    LnnWifiAdpterInterfaceMock wifiMock;
    wifiMock.SetDefaultResult();
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NODE_OFFLINE);

    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_OK);

    selectParam.transType = LANE_T_MIX;
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_SELECT_EXPECT_LANES_BY_QOS_003
* @tc.desc: SelectExpectLanesByQos
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_SELECT_EXPECT_LANES_BY_QOS_003, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LanePreferredLinkList linkList;
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    selectParam.transType = LANE_T_FILE;


    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    LnnWifiAdpterInterfaceMock wifiMock;
    wifiMock.SetDefaultResult();

    selectParam.qosRequire.rttLevel = LANE_RTT_LEVEL_LOW;
    int32_t ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_SELECT_EXPECT_LANE_BY_PARAMETER_001
* @tc.desc: SelectExpectLaneByParameter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_SELECT_EXPECT_LANE_BY_PARAMETER_001, TestSize.Level1)
{
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    int32_t ret = SelectExpectLaneByParameter(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_SELECT_EXPECT_LANE_BY_PARAMETER_002
* @tc.desc: SelectExpectLaneByParameter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_SELECT_EXPECT_LANE_BY_PARAMETER_002, TestSize.Level1)
{
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    LanePreferredLinkList linkList;

    EXPECT_CALL(enabledMock, IsLinkEnabled).WillOnce(Return(true));

    int32_t ret = SelectExpectLaneByParameter(&linkList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_SELECT_EXPECT_LANE_BY_PARAMETER_003
* @tc.desc: SelectExpectLaneByParameter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_SELECT_EXPECT_LANE_BY_PARAMETER_003, TestSize.Level1)
{
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    LanePreferredLinkList linkList;

    EXPECT_CALL(enabledMock, IsLinkEnabled).WillOnce(Return(false)).WillOnce(Return(true));

    int32_t ret = SelectExpectLaneByParameter(&linkList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_SELECT_EXPECT_LANE_BY_PARAMETER_004
* @tc.desc: SelectExpectLaneByParameter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_SELECT_EXPECT_LANE_BY_PARAMETER_004, TestSize.Level1)
{
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    LanePreferredLinkList linkList;

    EXPECT_CALL(enabledMock, IsLinkEnabled).WillOnce(Return(false)).WillOnce(Return(false)).
        WillOnce(Return(true));

    int32_t ret = SelectExpectLaneByParameter(&linkList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_SELECT_EXPECT_LANE_BY_PARAMETER_005
* @tc.desc: SelectExpectLaneByParameter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_SELECT_EXPECT_LANE_BY_PARAMETER_005, TestSize.Level1)
{
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    LanePreferredLinkList linkList;

    EXPECT_CALL(enabledMock, IsLinkEnabled).WillOnce(Return(false)).WillOnce(Return(false)).
        WillOnce(Return(false)).WillOnce(Return(true));

    int32_t ret = SelectExpectLaneByParameter(&linkList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_SELECT_EXPECT_LANE_BY_PARAMETER_006
* @tc.desc: SelectExpectLaneByParameter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_SELECT_EXPECT_LANE_BY_PARAMETER_006, TestSize.Level1)
{
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    LanePreferredLinkList linkList;

    EXPECT_CALL(enabledMock, IsLinkEnabled).WillOnce(Return(false)).WillOnce(Return(false)).
        WillOnce(Return(false)).WillOnce(Return(false)).WillOnce(Return(true));

    int32_t ret = SelectExpectLaneByParameter(&linkList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_SELECT_EXPECT_LANE_BY_PARAMETER_007
* @tc.desc: SelectExpectLaneByParameter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_SELECT_EXPECT_LANE_BY_PARAMETER_007, TestSize.Level1)
{
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    LanePreferredLinkList linkList;

    EXPECT_CALL(enabledMock, IsLinkEnabled).WillOnce(Return(false)).WillOnce(Return(false)).
        WillOnce(Return(false)).WillOnce(Return(false)).WillOnce(Return(false)).
        WillOnce(Return(false)).WillOnce(Return(true));

    int32_t ret = SelectExpectLaneByParameter(&linkList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_SELECT_EXPECT_LANE_BY_PARAMETER_008
* @tc.desc: SelectExpectLaneByParameter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_SELECT_EXPECT_LANE_BY_PARAMETER_008, TestSize.Level1)
{
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    LanePreferredLinkList linkList;

    EXPECT_CALL(enabledMock, IsLinkEnabled).WillOnce(Return(false)).WillOnce(Return(false)).
        WillOnce(Return(false)).WillOnce(Return(false)).WillOnce(Return(false)).
        WillOnce(Return(false)).WillOnce(Return(false));

    int32_t ret = SelectExpectLaneByParameter(&linkList);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
* @tc.name: LANE_FLOAD_EXPLORE_001
* @tc.desc: LANE FLOAD EXPLORE TEST
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_FLOAD_EXPLORE_001, TestSize.Level1)
{
    LaneResource resourceItem;
    (void)memset_s(&resourceItem, sizeof(LaneResource), 0, sizeof(LaneResource));
    resourceItem.clientRef = DEFAULT_LANE_RESOURCE_LANE_REF;
    int32_t ret = LaneDetectFload(&resourceItem);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_DECISION_MODELS_001
* @tc.desc: LANE DECISION MODELS TEST
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_DECISION_MODELS_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LaneSelectParam selectParam;
    (void)memset_s(&selectParam, sizeof(LaneSelectParam), 0, sizeof(LaneSelectParam));
    LanePreferredLinkList linkList;
    selectParam.transType = LANE_T_FILE;
    selectParam.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW;
    selectParam.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    selectParam.qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;

    LnnWifiAdpterInterfaceMock wifiMock;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, SoftBusGetLinkBand).WillRepeatedly(Return(BAND_5G));
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));

    int32_t ret = DecideAvailableLane(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_FIND_LANERESOURCE_BY_LINKADDR_001
* @tc.desc: LANE FIND LANERESOURCE BY LINK ADDR TEST
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_FIND_LANERESOURCE_BY_LINKADDR_001, TestSize.Level1)
{
    LaneLinkInfo linkInfo;
    ASSERT_EQ(memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo)), EOK);
    linkInfo.type = LANE_HML;
    ASSERT_EQ(strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML, strlen(PEER_IP_HML)), EOK);
    ASSERT_EQ(strncpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID, strlen(PEER_UDID)), EOK);

    LaneResource laneResourse;
    ASSERT_EQ(memset_s(&laneResourse, sizeof(LaneResource), 0, sizeof(LaneResource)), EOK);
    int32_t ret = FindLaneResourceByLinkAddr(nullptr, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = FindLaneResourceByLinkAddr(&linkInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = FindLaneResourceByLinkAddr(&linkInfo, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    uint64_t laneId = LANE_ID_BASE;
    uint32_t clientRef = 0;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    clientRef++;

    LaneLinkInfo linkInfoFind;
    ASSERT_EQ(memset_s(&linkInfoFind, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo)), EOK);
    linkInfoFind.type = LANE_HML;
    ret = FindLaneResourceByLinkAddr(&linkInfoFind, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ASSERT_EQ(strncpy_s(linkInfoFind.peerUdid, UDID_BUF_LEN, PEER_UDID, strlen(PEER_UDID)), EOK);
    ret = FindLaneResourceByLinkAddr(&linkInfoFind, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ASSERT_EQ(strncpy_s(linkInfoFind.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML, strlen(PEER_IP_HML)), EOK);
    ret = FindLaneResourceByLinkAddr(&linkInfoFind, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_FALSE(laneResourse.isServerSide);
    EXPECT_EQ(laneResourse.clientRef, clientRef);
    EXPECT_EQ(laneResourse.link.type, LANE_HML);
    EXPECT_EQ(laneResourse.laneId, LANE_ID_BASE);
    EXPECT_STREQ(laneResourse.link.linkInfo.p2p.connInfo.peerIp, PEER_IP_HML);
    EXPECT_STREQ(laneResourse.link.peerUdid, PEER_UDID);

    DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_FIND_LANERESOURCE_BY_LINKTYPE_001
* @tc.desc: LANE FIND LANERESOURCE BY LINK TYPE TEST
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_FIND_LANERESOURCE_BY_LINKTYPE_001, TestSize.Level1)
{
    LaneLinkInfo linkInfo;
    ASSERT_EQ(memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo)), EOK);
    linkInfo.type = LANE_HML;
    ASSERT_EQ(strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML, strlen(PEER_IP_HML)), EOK);
    ASSERT_EQ(strncpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID, strlen(PEER_UDID)), EOK);

    LaneResource laneResourse;
    ASSERT_EQ(memset_s(&laneResourse, sizeof(LaneResource), 0, sizeof(LaneResource)), EOK);
    int32_t ret = FindLaneResourceByLinkType(nullptr, LANE_HML, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = FindLaneResourceByLinkType(PEER_UDID, LANE_LINK_TYPE_BUTT, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = FindLaneResourceByLinkType(PEER_UDID, LANE_HML, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = FindLaneResourceByLinkType(PEER_UDID, LANE_HML, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    uint64_t laneId = LANE_ID_BASE;
    uint32_t clientRef = 0;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    clientRef++;

    ret = FindLaneResourceByLinkType(LOCAL_UDID, LANE_HML, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = FindLaneResourceByLinkType(PEER_UDID, LANE_P2P, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = FindLaneResourceByLinkType(PEER_UDID, LANE_HML, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_FALSE(laneResourse.isServerSide);
    EXPECT_EQ(laneResourse.clientRef, clientRef);
    EXPECT_EQ(laneResourse.link.type, LANE_HML);
    EXPECT_EQ(laneResourse.laneId, LANE_ID_BASE);
    EXPECT_STREQ(laneResourse.link.linkInfo.p2p.connInfo.peerIp, PEER_IP_HML);
    EXPECT_STREQ(laneResourse.link.peerUdid, PEER_UDID);

    DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_FIND_LANERESOURCE_BY_LANEID_001
* @tc.desc: LANE FIND LANERESOURCE BY LANEID TEST
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_FIND_LANERESOURCE_BY_LANEID_001, TestSize.Level1)
{
    LaneLinkInfo linkInfo;
    ASSERT_EQ(memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo)), EOK);
    linkInfo.type = LANE_HML;
    ASSERT_EQ(strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML, strlen(PEER_IP_HML)), EOK);
    ASSERT_EQ(strncpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID, strlen(PEER_UDID)), EOK);

    LaneResource laneResourse;
    ASSERT_EQ(memset_s(&laneResourse, sizeof(LaneResource), 0, sizeof(LaneResource)), EOK);
    uint64_t laneId = INVALID_LANE_ID;
    int32_t ret = FindLaneResourceByLaneId(laneId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    laneId = LANE_ID_BASE;
    uint32_t clientRef = 0;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    clientRef++;

    ret = FindLaneResourceByLaneId(INVALID_LANE_ID, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_FALSE(laneResourse.isServerSide);
    EXPECT_EQ(laneResourse.clientRef, clientRef);
    EXPECT_EQ(laneResourse.link.type, LANE_HML);
    EXPECT_EQ(laneResourse.laneId, LANE_ID_BASE);
    EXPECT_STREQ(laneResourse.link.linkInfo.p2p.connInfo.peerIp, PEER_IP_HML);
    EXPECT_STREQ(laneResourse.link.peerUdid, PEER_UDID);

    DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_DETECT_RELIABILITY_001
* @tc.desc: LANE DETECT RELIABILITY TEST
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_DETECT_RELIABILITY_001, TestSize.Level1)
{
    LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    LaneDepsInterfaceMock mock;
    EXPECT_CALL(mock, ConnOpenClientSocket).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AddTrigger).WillRepeatedly(Return(SOFTBUS_OK));

    LaneLinkInfo linkInfo;
    linkInfo.type = LANE_WLAN_2P4G;
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    int32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    uint64_t laneId = LANE_ID_BASE;
    int32_t ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = LaneDetectReliability(laneReqId, &linkInfo, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_DETECT_RELIABILITY_002
* @tc.desc: WLAN LANE DETECT RELIABILITY TEST
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_DETECT_RELIABILITY_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    int32_t events = 0;
    ListenerModule module = LANE;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    LaneLinkInfo linkInfo;
    linkInfo.type = LANE_WLAN_5G;
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    int32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    uint64_t laneId = LANE_ID_BASE;
    int32_t ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = LaneDetectOnDataEvent(module, events, FD);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    EXPECT_CALL(mock, ConnOpenClientSocket).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AddTrigger).WillRepeatedly(Return(SOFTBUS_OK));

    ret = LaneDetectReliability(laneReqId, &linkInfo, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    LaneDetectInfo requestItem;
    (void)memset_s(&requestItem, sizeof(LaneDetectInfo), 0, sizeof(LaneDetectInfo));
    if (GetLaneDetectInfoByWlanFd(SOFTBUS_OK, &requestItem) != SOFTBUS_OK) {
        return;
    }
    bool isSendSuc = true;
    ret = NotifyWlanDetectResult(&requestItem, isSendSuc);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = LaneDetectReliability(laneReqId, &linkInfo, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LaneDetectOnDataEvent(module, events, SOFTBUS_OK);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LaneDetectReliability(INVALID_LANE_REQ_ID, &linkInfo, &cb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_DETECT_RELIABILITY_003
* @tc.desc: WLAN LANE DETECT RELIABILITY TEST
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_DETECT_RELIABILITY_003, TestSize.Level1)
{
    const char *ipAddr = "127.0.0.1";
    LaneDepsInterfaceMock mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    LaneLinkInfo linkInfo;
    linkInfo.type = LANE_WLAN_5G;
    linkInfo.linkInfo.wlan.connInfo.port = PORT_A;
    if (strcpy_s(linkInfo.linkInfo.wlan.connInfo.addr, MAX_SOCKET_ADDR_LEN, ipAddr) != EOK) {
        return;
    }
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    int32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    uint64_t laneId = LANE_ID_BASE;
    int32_t ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, ConnOpenClientSocket)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AddTrigger).WillRepeatedly(Return(SOFTBUS_ERR));

    ret = LaneDetectReliability(laneReqId, &linkInfo, &cb);
    EXPECT_EQ(ret, SOFTBUS_CONN_FAIL);
    linkInfo.linkInfo.wlan.connInfo.port = PORT_B;

    ret = LaneDetectReliability(laneReqId, &linkInfo, &cb);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_INIT_RELIABLITY_001
* @tc.desc: LANE INIT RELIABLITY TEST
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_INIT_RELIABLITY_001, TestSize.Level1)
{
    LaneDepsInterfaceMock mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = InitLaneReliability();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_DEL_AND_ADD_LANERESOURCEITEM_001
* @tc.desc: LANE_DEL AND ADD LANERESOURCEITEM CLIENT
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_DEL_AND_ADD_LANERESOURCEITEM_001, TestSize.Level1)
{
    LaneLinkInfo linkInfo;
    ASSERT_EQ(memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo)), EOK);
    linkInfo.type = LANE_HML;
    ASSERT_EQ(strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML, strlen(PEER_IP_HML)), EOK);
    ASSERT_EQ(strncpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID, strlen(PEER_UDID)), EOK);

    uint64_t laneId = INVALID_LANE_ID;
    int32_t ret = AddLaneResourceToPool(nullptr, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = AddLaneResourceToPool(&linkInfo, INVALID_LANE_ID, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    laneId = LANE_ID_BASE;
    uint32_t clientRef = 0;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    clientRef++;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    clientRef++;

    LaneResource laneResourse;
    ASSERT_EQ(memset_s(&laneResourse, sizeof(LaneResource), 0, sizeof(LaneResource)), EOK);
    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_FALSE(laneResourse.isServerSide);
    EXPECT_EQ(laneResourse.clientRef, clientRef);

    ret = DelLaneResourceByLaneId(INVALID_LANE_ID, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(laneResourse.clientRef, clientRef);

    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    clientRef--;
    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(laneResourse.clientRef, clientRef);

    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
* @tc.name: LANE_DEL_AND_ADD_LANERESOURCEITEM_002
* @tc.desc: LANE_DEL AND ADD LANERESOURCEITEM SERVER
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_DEL_AND_ADD_LANERESOURCEITEM_002, TestSize.Level1)
{
    LaneLinkInfo linkInfo;
    ASSERT_EQ(memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo)), EOK);
    linkInfo.type = LANE_HML;
    ASSERT_EQ(strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML, strlen(PEER_IP_HML)), EOK);
    ASSERT_EQ(strncpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID, strlen(PEER_UDID)), EOK);

    uint64_t laneId = INVALID_LANE_ID;
    int32_t ret = AddLaneResourceToPool(nullptr, laneId, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = AddLaneResourceToPool(&linkInfo, laneId, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    laneId = LANE_ID_BASE;
    uint32_t serverRef = 0;
    ret = AddLaneResourceToPool(&linkInfo, laneId, true);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = AddLaneResourceToPool(&linkInfo, laneId, true);
    EXPECT_EQ(ret, SOFTBUS_LANE_TRIGGER_LINK_FAIL);

    LaneResource laneResourse;
    ASSERT_EQ(memset_s(&laneResourse, sizeof(LaneResource), 0, sizeof(LaneResource)), EOK);
    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(laneResourse.isServerSide);
    EXPECT_EQ(laneResourse.clientRef, serverRef);

    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_APPLY_LANE_ID_001
* @tc.desc: LANE APPLY LANE ID
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_APPLY_LANE_ID_001, TestSize.Level1)
{
    LaneDepsInterfaceMock laneMock;
    EXPECT_CALL(laneMock, SoftBusGenerateStrHash)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(LaneDepsInterfaceMock::ActionOfGenerateStrHash);

    uint64_t laneId = ApplyLaneId(LOCAL_UDID, PEER_UDID, LANE_HML);
    EXPECT_EQ(laneId, INVALID_LANE_ID);

    laneId = ApplyLaneId(LOCAL_UDID, PEER_UDID, LANE_HML);
    EXPECT_NE(laneId, INVALID_LANE_ID);
}

/*
* @tc.name: LNN_SELECT_AUTH_LANE_TEST_001
* @tc.desc: SelectAuthLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_SELECT_AUTH_LANE_TEST_001, TestSize.Level1)
{
    const char *networkId = "testnetworkid123";
    NiceMock<LaneDepsInterfaceMock> mock;
    LanePreferredLinkList recommendList;
    LanePreferredLinkList request;
    (void)memset_s(&recommendList, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));
    (void)memset_s(&request, sizeof(LanePreferredLinkList), 0, sizeof(LanePreferredLinkList));

    request.linkTypeNum = 4;
    request.linkType[0] = LANE_P2P;
    request.linkType[1] = LANE_BLE;
    request.linkType[2] = LANE_BR;
    request.linkType[3] = LANE_HML;

    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<2>(1), Return(SOFTBUS_OK)));
    int32_t ret = SelectAuthLane(nullptr, &recommendList, &request);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = SelectAuthLane(networkId, nullptr, &request);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = SelectAuthLane(networkId, &recommendList, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = SelectAuthLane(networkId, &recommendList, &request);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_AUTH_ALLOC_TEST_001
* @tc.desc: AuthAlloc
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_AUTH_ALLOC_TEST_001, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_CTRL;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<1>(16), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<2>(16), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<1>(16), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<2>(16), Return(SOFTBUS_OK)));

    LnnWifiAdpterInterfaceMock wifiMock;
    wifiMock.SetDefaultResult();
    NiceMock<IsLinkEnabledDepsInterfaceMock> enabledMock;
    EXPECT_CALL(enabledMock, IsLinkEnabled).WillRepeatedly(Return(false));

    LaneAllocInfo allocInfo;
    (void)memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo));
    allocInfo.type = laneType;
    (void)strncpy_s(allocInfo.networkId, NETWORK_ID_BUF_LEN,
        NODE_NETWORK_ID, strlen(NODE_NETWORK_ID));
    allocInfo.transType = LANE_T_BYTE;
    allocInfo.qosRequire.minBW = 0;
    allocInfo.qosRequire.maxLaneLatency = 0;
    allocInfo.qosRequire.minLaneLatency = 0;

    int32_t ret = laneManager->lnnAllocLane(laneReqId, nullptr, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = laneManager->lnnAllocLane(INVALID_LANE_REQ_ID, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    AuthLinkTypeList mockList;
    (void)memset_s(&mockList, sizeof(AuthLinkTypeList), 0, sizeof(AuthLinkTypeList));
    mockList.linkType[0] = AUTH_LINK_TYPE_WIFI;
    mockList.linkTypeNum = 1;
    EXPECT_CALL(mock, GetAuthLinkTypeList)
        .WillRepeatedly(DoAll(SetArgPointee<1>(mockList), Return(SOFTBUS_OK)));
    ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}
} // namespace OHOS
