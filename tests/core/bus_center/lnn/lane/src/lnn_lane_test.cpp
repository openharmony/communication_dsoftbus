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

#include "bus_center_info_key.h"
#include "lnn_ctrl_lane.h"
#include "lnn_feature_capability.h"
#include "lnn_lane.h"
#include "lnn_lane_common.h"
#include "lnn_lane_deps_mock.h"
#include "lnn_lane_def.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_link.h"
#include "lnn_lane_model.h"
#include "lnn_lane_select.h"
#include "lnn_select_rule.h"
#include "lnn_wifi_adpter_mock.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"
#include "softbus_wifi_api_adapter.h"
#include "lnn_lane_reliability.h"
#include "lnn_lane_reliability.c"
#include "wifi_direct_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char NODE_NETWORK_ID[] = "111122223333abcdef";
constexpr char PEER_IP_HML[] = "172.30.0.1";
constexpr char PEER_MAC[] = "a1:b2:c3:d4:e5:f6";
constexpr char PEER_UDID[] = "111122223333abcdef";
constexpr uint64_t LANE_ID_BASE = 1122334455667788;
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
constexpr uint32_t NET_CAP = 63;

static SoftBusCond g_cond = {0};
static SoftBusMutex g_lock = {0};
static int32_t g_errCode = 0;
static bool g_isNeedCondWait = true;

static void OnLaneAllocSuccess(uint32_t laneHandle, const LaneConnInfo *info);
static void OnLaneAllocFail(uint32_t laneHandle, int32_t errCode);
static void OnLaneFreeSuccess(uint32_t laneHandle);
static void OnLaneFreeFail(uint32_t laneHandle, int32_t errCode);

static LaneAllocListener g_listener = {
    .onLaneAllocSuccess = OnLaneAllocSuccess,
    .onLaneAllocFail = OnLaneAllocFail,
    .onLaneFreeSuccess = OnLaneFreeSuccess,
    .onLaneFreeFail = OnLaneFreeFail,
};

static void OnLaneRequestSuccess(uint32_t laneId, const LaneConnInfo *info)
{
    GTEST_LOG_(INFO) << "OnLaneRequestSuccess";
}

static void OnLaneRequestFail(uint32_t laneId, int32_t reason)
{
    GTEST_LOG_(INFO) << "OnLaneRequestFail";
}

static ILaneListener g_listener2 = {
    .onLaneRequestSuccess = OnLaneRequestSuccess,
    .onLaneRequestFail = OnLaneRequestFail,
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
    int32_t ret = LnnInitLnnLooper();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LooperInit();
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(LaneDepsInterfaceMock::ActionOfStartBaseClient);
    ret = InitLane();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    GTEST_LOG_(INFO) << "LNNLaneMockTest start";
}

void LNNLaneMockTest::TearDownTestCase()
{
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    EXPECT_CALL(wifiMock, LnnDestroyP2p).WillRepeatedly(Return());
    DeinitLane();
    LooperDeinit();
    LnnDeinitLnnLooper();
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
    if (SoftBusCondWait(&g_cond, &g_lock, nullptr) != SOFTBUS_OK) {
        GTEST_LOG_(INFO) << "CondWait SoftBusCondWait failed";
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

static void OnLaneLinkSuccessForDetect(uint32_t reqId, LaneLinkType linkType, const LaneLinkInfo *linkInfo)
{
    (void)reqId;
    (void)linkInfo;
    GTEST_LOG_(INFO) << "on laneLink success for detect";
    EXPECT_EQ(linkType, LANE_WLAN_5G);
}

static void OnLaneLinkFailForDetect(uint32_t reqId, int32_t reason, LaneLinkType linkType)
{
    (void)reqId;
    (void)linkType;
    GTEST_LOG_(INFO) << "on laneLink fail for detect";
    EXPECT_EQ(reason, SOFTBUS_LANE_DETECT_TIMEOUT);
    CondSignal();
}

static void OnLaneAllocSuccessForHml(uint32_t laneHandle, const LaneConnInfo *info)
{
    (void)laneHandle;
    ASSERT_NE(info, nullptr) << "invalid connInfo";
    GTEST_LOG_(INFO) << "alloc lane successful, linkType=" << info->type;
    EXPECT_EQ(info->type, LANE_HML);
    CondSignal();
}

static void OnLaneAllocSuccessForP2p(uint32_t laneHandle, const LaneConnInfo *info)
{
    (void)laneHandle;
    ASSERT_NE(info, nullptr) << "invalid connInfo";
    GTEST_LOG_(INFO) << "alloc lane successful, linkType=" << info->type;
    EXPECT_EQ(info->type, LANE_P2P);
    CondSignal();
}

static void OnLaneAllocSuccessForBr(uint32_t laneHandle, const LaneConnInfo *info)
{
    (void)laneHandle;
    ASSERT_NE(info, nullptr) << "invalid connInfo";
    GTEST_LOG_(INFO) << "alloc lane successful, linkType=" << info->type;
    EXPECT_EQ(info->type, LANE_BR);
    CondSignal();
}

static void OnLaneAllocSuccessForWlan5g(uint32_t laneHandle, const LaneConnInfo *info)
{
    (void)laneHandle;
    ASSERT_NE(info, nullptr) << "invalid connInfo";
    GTEST_LOG_(INFO) << "alloc lane successful, linkType=" << info->type;
    EXPECT_EQ(info->type, LANE_WLAN_5G);
    CondSignal();
}

static void OnLaneAllocSuccessForBle(uint32_t laneHandle, const LaneConnInfo *info)
{
    (void)laneHandle;
    ASSERT_NE(info, nullptr) << "invalid connInfo";
    GTEST_LOG_(INFO) << "alloc lane successful, linkType=" << info->type;
    EXPECT_EQ(info->type, LANE_BLE);
    CondSignal();
}

static void OnLaneAllocFailNoExcept(uint32_t laneHandle, int32_t errCode)
{
    GTEST_LOG_(INFO) << "alloc lane failed, laneReqId=" << laneHandle;
    EXPECT_EQ(errCode, SOFTBUS_LANE_SUCC_AFTER_CANCELED);
    CondSignal();
}

static void OnLaneAllocFailNoExcept2(uint32_t laneHandle, int32_t errCode)
{
    GTEST_LOG_(INFO) << "alloc lane failed, laneReqId=" << laneHandle;
    EXPECT_EQ(errCode, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
    CondSignal();
}

static LaneAllocListener g_listenerCbForHml = {
    .onLaneAllocSuccess = OnLaneAllocSuccessForHml,
    .onLaneAllocFail = OnLaneAllocFailNoExcept,
    .onLaneFreeSuccess = OnLaneFreeSuccess,
    .onLaneFreeFail = OnLaneFreeFail,
};

static LaneAllocListener g_listenerCbForP2p = {
    .onLaneAllocSuccess = OnLaneAllocSuccessForP2p,
    .onLaneAllocFail = OnLaneAllocFailNoExcept,
    .onLaneFreeSuccess = OnLaneFreeSuccess,
    .onLaneFreeFail = OnLaneFreeFail,
};

static LaneAllocListener g_listenerCbForBr2 = {
    .onLaneAllocSuccess = OnLaneAllocSuccessForBr,
    .onLaneAllocFail = OnLaneAllocFailNoExcept2,
    .onLaneFreeSuccess = OnLaneFreeSuccess,
    .onLaneFreeFail = OnLaneFreeFail,
};

static LaneAllocListener g_listenerCbForBr = {
    .onLaneAllocSuccess = OnLaneAllocSuccessForBr,
    .onLaneAllocFail = OnLaneAllocFailNoExcept,
    .onLaneFreeSuccess = OnLaneFreeSuccess,
    .onLaneFreeFail = OnLaneFreeFail,
};

static LaneAllocListener g_listenerCbForWlan5g = {
    .onLaneAllocSuccess = OnLaneAllocSuccessForWlan5g,
    .onLaneAllocFail = OnLaneAllocFailNoExcept,
    .onLaneFreeSuccess = OnLaneFreeSuccess,
    .onLaneFreeFail = OnLaneFreeFail,
};

static LaneAllocListener g_listenerCbForBle = {
    .onLaneAllocSuccess = OnLaneAllocSuccessForBle,
    .onLaneAllocFail = OnLaneAllocFailNoExcept,
    .onLaneFreeSuccess = OnLaneFreeSuccess,
    .onLaneFreeFail = OnLaneFreeFail,
};

static int32_t AddLaneResourceForAllocTest(LaneLinkType linkType)
{
    LaneLinkInfo linkInfo = {};
    linkInfo.type = linkType;
    if (strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML, strlen(PEER_IP_HML)) != EOK) {
        return SOFTBUS_STRCPY_ERR;
    }
    if (strncpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID, strlen(PEER_UDID)) != EOK) {
        return SOFTBUS_STRCPY_ERR;
    }
    return AddLaneResourceToPool(&linkInfo, LANE_ID_BASE, false);
}

static void CreateAllocInfoForAllocTest(LaneTransType transType, uint32_t minBW, uint32_t maxLaneLatency,
    uint32_t minLaneLatency, LaneAllocInfo *allocInfo)
{
    ASSERT_NE(allocInfo, nullptr) << "invalid allocInfo";
    allocInfo->type = LANE_TYPE_TRANS;
    ASSERT_EQ(strncpy_s(allocInfo->networkId, NETWORK_ID_BUF_LEN,
        NODE_NETWORK_ID, strlen(NODE_NETWORK_ID)), EOK);
    allocInfo->transType = transType;
    allocInfo->qosRequire.minBW = minBW;
    allocInfo->qosRequire.maxLaneLatency = maxLaneLatency;
    allocInfo->qosRequire.minLaneLatency = minLaneLatency;
}

static int32_t PrejudgeAvailability(const char *remoteNetworkId, enum WifiDirectLinkType connectType)
{
    (void)remoteNetworkId;
    (void)connectType;
    GTEST_LOG_(INFO) << "PrejudgeAvailability Enter";
    return SOFTBUS_OK;
}

static int32_t GetLocalAndRemoteMacByLocalIp(const char *localIp, char *localMac, size_t localMacSize,
    char *remoteMac, size_t remoteMacSize)
{
    (void)localIp;
    (void)localMac;
    (void)localMacSize;
    (void)remoteMac;
    (void)remoteMacSize;
    return SOFTBUS_OK;
}

static struct WifiDirectManager g_manager = {
    .prejudgeAvailability = PrejudgeAvailability,
    .getLocalAndRemoteMacByLocalIp = GetLocalAndRemoteMacByLocalIp,
};
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

    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfOnConnectP2pFail);
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(63, 63, 0, 0);
    EXPECT_CALL(mock, ConnOpenClientSocket).WillRepeatedly(Return(SOFTBUS_CONN_FAIL));
    EXPECT_CALL(mock, DeleteNetworkResourceByLaneId).WillRepeatedly(Return());

    LaneAllocInfo allocInfo = {};
    CreateAllocInfoForAllocTest(LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + HIGH_BW, DEFAULT_QOSINFO_MAX_LATENCY,
        DEFAULT_QOSINFO_MIN_LATENCY, &allocInfo);
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    EXPECT_EQ(g_errCode, ERROR_WIFI_OFF);
    
    (void)laneManager->lnnFreeLane(laneReqId);
}

/*
* @tc.name: LANE_ALLOC_Test_001
* @tc.desc: lane alloc by select default link for T_MSG (build wlan5g)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_001, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(1 << BIT_WIFI_5G, 1 << BIT_WIFI_5G, 0, 0);
    EXPECT_CALL(mock, AddTrigger).WillRepeatedly(LaneDepsInterfaceMock::ActionOfAddTrigger);
    char buf[] = "lanedetect";
    EXPECT_CALL(mock, ConnSendSocketData).WillRepeatedly(Return(sizeof(buf)));
    EXPECT_CALL(mock, DeleteNetworkResourceByLaneId).WillRepeatedly(Return());
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    SoftBusWifiLinkedInfo wlanInfo;
    wlanInfo.connState = SOFTBUS_API_WIFI_CONNECTED;
    EXPECT_CALL(wifiMock, SoftBusGetLinkedInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM1>(wlanInfo), Return(SOFTBUS_OK)));

    LaneAllocInfo allocInfo = {};
    CreateAllocInfoForAllocTest(LANE_T_MSG, 0, 0, 0, &allocInfo);
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForWlan5g);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_Test_002
* @tc.desc: lane alloc by select default link for T_BYTE (not enable wlan and br, build ble)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_002, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(1 << BIT_BLE, 1 << BIT_BLE, 0, 0);
    EXPECT_CALL(mock, DeleteNetworkResourceByLaneId).WillRepeatedly(Return());
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    LaneAllocInfo allocInfo = {};
    ASSERT_EQ(strncpy_s(allocInfo.extendInfo.peerBleMac, MAX_MAC_LEN,
        PEER_MAC, strlen(PEER_MAC)), EOK);
    CreateAllocInfoForAllocTest(LANE_T_BYTE, 0, 0, 0, &allocInfo);
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForBle);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_Test_003
* @tc.desc: lane alloc by select default link for T_FILE (not enable wlan and hml, build p2p)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_003, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(1 << BIT_WIFI_P2P, 1 << BIT_WIFI_P2P, 0, 0);
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);

    LaneAllocInfo allocInfo = {};
    CreateAllocInfoForAllocTest(LANE_T_FILE, 0, 0, 0, &allocInfo);
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();

    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_ALLOC_Test_004
* @tc.desc: lane alloc by select default link for T_RAW_STREAM (not enable wlan, build p2p)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_004, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(1 << BIT_WIFI_P2P, 1 << BIT_WIFI_P2P, 0, 0);
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);

    LaneAllocInfo allocInfo = {};
    CreateAllocInfoForAllocTest(LANE_T_RAW_STREAM, 0, 0, 0, &allocInfo);
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_ALLOC_Test_005
* @tc.desc: lane alloc by mesh link (not enable wlan, build br)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_005, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(1 << BIT_BR, 1 << BIT_BR, 0, 0);
    EXPECT_CALL(mock, DeleteNetworkResourceByLaneId).WillRepeatedly(Return());
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();

    LaneAllocInfo allocInfo = {};
    CreateAllocInfoForAllocTest(LANE_T_RAW_STREAM, MESH_MAGIC_NUMBER, 0, 0, &allocInfo);
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForBr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_Test_006
* @tc.desc: lane alloc by RTT link (not enable hml, build p2p)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_006, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(1 << BIT_WIFI_P2P, 1 << BIT_WIFI_P2P, 0, 0);
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);

    LaneAllocInfo allocInfo = {};
    allocInfo.qosRequire.rttLevel = LANE_RTT_LEVEL_LOW;
    CreateAllocInfoForAllocTest(LANE_T_RAW_STREAM, DEFAULT_QOSINFO_MIN_BW, 0, 0, &allocInfo);
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_ALLOC_Test_007
* @tc.desc: lane alloc by qos require (HIGH_BW, build hml)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_007, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(1 << BIT_WIFI_P2P, 1 << BIT_WIFI_P2P, 1 << BIT_WIFI_DIRECT_TLV_NEGOTIATION,
        1 << BIT_WIFI_DIRECT_TLV_NEGOTIATION);
    EXPECT_CALL(mock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);

    LaneAllocInfo allocInfo = {};
    CreateAllocInfoForAllocTest(LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + HIGH_BW, DEFAULT_QOSINFO_MAX_LATENCY,
        DEFAULT_QOSINFO_MIN_LATENCY, &allocInfo);
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForHml);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_ALLOC_Test_008
* @tc.desc: lane alloc by qos require (MID_HIGH_BW, not enable hml, build wlan5g)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_008, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(1 << BIT_WIFI_5G, 1 << BIT_WIFI_5G, 0, 0);
    EXPECT_CALL(mock, AddTrigger).WillRepeatedly(LaneDepsInterfaceMock::ActionOfAddTrigger);
    char buf[] = "lanedetect";
    EXPECT_CALL(mock, ConnSendSocketData).WillRepeatedly(Return(sizeof(buf)));
    EXPECT_CALL(mock, DeleteNetworkResourceByLaneId).WillRepeatedly(Return());
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    SoftBusWifiLinkedInfo wlanInfo;
    wlanInfo.band = 0;
    wlanInfo.connState = SOFTBUS_API_WIFI_CONNECTED;
    EXPECT_CALL(wifiMock, SoftBusGetLinkedInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM1>(wlanInfo), Return(SOFTBUS_OK)));

    LaneAllocInfo allocInfo = {};
    CreateAllocInfoForAllocTest(LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + MID_BW, DEFAULT_QOSINFO_MAX_LATENCY,
        DEFAULT_QOSINFO_MIN_LATENCY, &allocInfo);
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForWlan5g);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_Test_009
* @tc.desc: lane alloc by qos require (MID_LOW_BW, not enable wlan5g and hml, build wlan24g)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_009, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(1 << BIT_WIFI_5G, 1 << BIT_WIFI_5G, 0, 0);
    EXPECT_CALL(mock, AddTrigger).WillRepeatedly(LaneDepsInterfaceMock::ActionOfAddTrigger);
    char buf[] = "lanedetect";
    EXPECT_CALL(mock, ConnSendSocketData).WillRepeatedly(Return(sizeof(buf)));
    EXPECT_CALL(mock, DeleteNetworkResourceByLaneId).WillRepeatedly(Return());
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    SoftBusWifiLinkedInfo wlanInfo;
    wlanInfo.band = 1;
    wlanInfo.connState = SOFTBUS_API_WIFI_CONNECTED;
    EXPECT_CALL(wifiMock, SoftBusGetLinkedInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM1>(wlanInfo), Return(SOFTBUS_OK)));

    LaneAllocInfo allocInfo = {};
    CreateAllocInfoForAllocTest(LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + LOW_BW, DEFAULT_QOSINFO_MAX_LATENCY,
        DEFAULT_QOSINFO_MIN_LATENCY, &allocInfo);
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForWlan5g);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_Test_010
* @tc.desc: lane alloc by qos require (LOW_BW, not enable wlan5g\hml\br\p2p\coc_direct, build ble)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_010, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(1 << BIT_BLE, 1 << BIT_BLE, 0, 0);
    EXPECT_CALL(mock, DeleteNetworkResourceByLaneId).WillRepeatedly(Return());
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();

    LaneAllocInfo allocInfo = {};
    ASSERT_EQ(strncpy_s(allocInfo.extendInfo.peerBleMac, MAX_MAC_LEN,
        PEER_MAC, strlen(PEER_MAC)), EOK);
    CreateAllocInfoForAllocTest(LANE_T_MSG, LOW_BW - DEFAULT_QOSINFO_MIN_BW, DEFAULT_QOSINFO_MAX_LATENCY,
        DEFAULT_QOSINFO_MIN_LATENCY, &allocInfo);
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForBle);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_Test_011
* @tc.desc: lane alloc for exception deal before select link
* @tc.type: FAILUE
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_011, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(false));

    LaneAllocInfo allocInfo = {};
    int32_t ret = laneManager->lnnAllocLane(laneReqId, nullptr, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    allocInfo.type = LANE_TYPE_BUTT;
    ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    allocInfo.type = (LaneType)-1;
    ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = laneManager->lnnAllocLane(INVALID_LANE_REQ_ID, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    allocInfo.type = LANE_TYPE_HDLC;
    ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    allocInfo.type = laneType;
    ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NODE_OFFLINE);

    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
}

/*
* @tc.name: LANE_ALLOC_Test_012
* @tc.desc: lane alloc for continuous task(local is watch)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_012, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(11, 11, 0x2400, 0x2400);
    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillOnce(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(TYPE_WATCH_ID), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, DeleteNetworkResourceByLaneId).WillRepeatedly(Return());
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();

    LaneAllocInfo allocInfo = {};
    CreateAllocInfoForAllocTest(LANE_T_BYTE, LOW_BW - DEFAULT_QOSINFO_MIN_BW, DEFAULT_QOSINFO_MAX_LATENCY,
        DEFAULT_QOSINFO_MIN_LATENCY, &allocInfo);
    allocInfo.qosRequire.continuousTask = true;
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForBr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_Test_013
* @tc.desc: lane alloc for continuous task(remote is watch)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_013, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(11, 11, 0x2400, 0x2400);
    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillOnce(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(TYPE_PHONE_ID), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillOnce(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(TYPE_WATCH_ID), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, DeleteNetworkResourceByLaneId).WillRepeatedly(Return());
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();

    LaneAllocInfo allocInfo = {};
    CreateAllocInfoForAllocTest(LANE_T_BYTE, LOW_BW - DEFAULT_QOSINFO_MIN_BW, DEFAULT_QOSINFO_MAX_LATENCY,
        DEFAULT_QOSINFO_MIN_LATENCY, &allocInfo);
    allocInfo.qosRequire.continuousTask = true;
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForBr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_Test_014
* @tc.desc: lane alloc for MIDDLE_LOW_BW&not continuous task(local is watch)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_014, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(15, 15, 0x3F7EA, 0x3F7EA);
    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillOnce(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(TYPE_WATCH_ID), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(TYPE_WATCH_ID), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, DeleteNetworkResourceByLaneId).WillRepeatedly(Return());
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);

    LaneAllocInfo allocInfo = {};
    CreateAllocInfoForAllocTest(LANE_T_BYTE, DEFAULT_QOSINFO_MIN_BW + LOW_BW, DEFAULT_QOSINFO_MAX_LATENCY,
        DEFAULT_QOSINFO_MIN_LATENCY, &allocInfo);
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_Test_015
* @tc.desc: lane alloc for MIDDLE_HIGH_BW&not continuous task(remote is watch)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_015, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(15, 15, 0x3F7EA, 0x3F7EA);
    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillOnce(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(TYPE_PHONE_ID), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(TYPE_PHONE_ID), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillOnce(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(TYPE_WATCH_ID), Return(SOFTBUS_OK)))
        .WillOnce(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(TYPE_WATCH_ID), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, DeleteNetworkResourceByLaneId).WillRepeatedly(Return());
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);

    LaneAllocInfo allocInfo = {};
    CreateAllocInfoForAllocTest(LANE_T_BYTE, HIGH_BW - DEFAULT_QOSINFO_MIN_BW, DEFAULT_QOSINFO_MAX_LATENCY,
        DEFAULT_QOSINFO_MIN_LATENCY, &allocInfo);
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_Test_016
* @tc.desc: lane alloc for continuous task(lowBw and remote is hoos, expect link is br)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_ALLOC_Test_016, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(15, 15, 0x3F7EA, 0x3F7EA);
    EXPECT_CALL(mock, DeleteNetworkResourceByLaneId).WillRepeatedly(Return());
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();

    LaneAllocInfo allocInfo = {};
    ASSERT_EQ(strncpy_s(allocInfo.extendInfo.peerBleMac, MAX_MAC_LEN,
        PEER_MAC, strlen(PEER_MAC)), EOK);
    CreateAllocInfoForAllocTest(LANE_T_MSG, LOW_BW - DEFAULT_QOSINFO_MIN_BW, DEFAULT_QOSINFO_MAX_LATENCY,
        DEFAULT_QOSINFO_MIN_LATENCY, &allocInfo);
    allocInfo.qosRequire.continuousTask = true;
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForBr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
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

    int32_t ret = laneManager->lnnReAllocLane(laneReqId, LANE_ID_BASE, nullptr, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    LaneAllocInfo allocInfo;
    ASSERT_EQ(memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo)), EOK);
    allocInfo.type = LANE_TYPE_BUTT;

    ret = laneManager->lnnReAllocLane(laneReqId, LANE_ID_BASE, &allocInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = laneManager->lnnReAllocLane(laneReqId, LANE_ID_BASE, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = laneManager->lnnReAllocLane(INVALID_LANE_REQ_ID, LANE_ID_BASE, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = laneManager->lnnReAllocLane(laneReqId, INVALID_LANE_ID, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    allocInfo.type = LANE_TYPE_HDLC;
    ret = laneManager->lnnReAllocLane(laneReqId, INVALID_LANE_ID, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(63, 63, 8, 8);
    EXPECT_CALL(mock, DeleteNetworkResourceByLaneId).WillRepeatedly(Return());
    EXPECT_CALL(mock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    int32_t ret = AddLaneResourceForAllocTest(LANE_HML);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);

    LaneAllocInfo allocInfo;
    ASSERT_EQ(memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo)), EOK);
    CreateAllocInfoForAllocTest(LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + HIGH_BW, DEFAULT_QOSINFO_MAX_LATENCY,
        DEFAULT_QOSINFO_MIN_LATENCY, &allocInfo);
    SetIsNeedCondWait();
    ret = laneManager->lnnReAllocLane(laneReqId, LANE_ID_BASE, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
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

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(63, 63, 8, 8);
    EXPECT_CALL(mock, AddTrigger).WillRepeatedly(LaneDepsInterfaceMock::ActionOfAddTrigger);
    char buf[] = "lanedetect";
    EXPECT_CALL(mock, ConnSendSocketData).WillRepeatedly(Return(sizeof(buf)));
    EXPECT_CALL(mock, DeleteNetworkResourceByLaneId).WillRepeatedly(Return());
    EXPECT_CALL(mock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    int32_t ret = AddLaneResourceForAllocTest(LANE_HML);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    SoftBusWifiLinkedInfo wlanInfo;
    wlanInfo.band = 0;
    wlanInfo.connState = SOFTBUS_API_WIFI_CONNECTED;
    EXPECT_CALL(wifiMock, SoftBusGetLinkedInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM1>(wlanInfo), Return(SOFTBUS_OK)));

    LaneAllocInfo allocInfo;
    ASSERT_EQ(memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo)), EOK);
    CreateAllocInfoForAllocTest(LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + MID_BW, DEFAULT_QOSINFO_MAX_LATENCY,
        DEFAULT_QOSINFO_MIN_LATENCY, &allocInfo);
    SetIsNeedCondWait();
    ret = laneManager->lnnReAllocLane(laneReqId, LANE_ID_BASE, &allocInfo, &g_listenerCbForWlan5g);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    ret = DelLaneResourceByLaneId(LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    CondWait();
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

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(63, 63, 8, 8);
    EXPECT_CALL(mock, DeleteNetworkResourceByLaneId).WillRepeatedly(Return());
    EXPECT_CALL(mock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    int32_t ret = AddLaneResourceForAllocTest(LANE_WLAN_5G);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);

    LaneAllocInfo allocInfo;
    ASSERT_EQ(memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo)), EOK);
    CreateAllocInfoForAllocTest(LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + LOW_BW, DEFAULT_QOSINFO_MAX_LATENCY,
        DEFAULT_QOSINFO_MIN_LATENCY, &allocInfo);
    SetIsNeedCondWait();
    ret = laneManager->lnnReAllocLane(laneReqId, LANE_ID_BASE, &allocInfo, &g_listenerCbForHml);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
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

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(15, 15, 8, 8);
    EXPECT_CALL(mock, DeleteNetworkResourceByLaneId).WillRepeatedly(Return());
    EXPECT_CALL(mock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    int32_t ret = AddLaneResourceForAllocTest(LANE_HML);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();

    LaneAllocInfo allocInfo;
    ASSERT_EQ(memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo)), EOK);
    CreateAllocInfoForAllocTest(LANE_T_MSG, LOW_BW - DEFAULT_QOSINFO_MIN_BW, DEFAULT_QOSINFO_MAX_LATENCY,
        DEFAULT_QOSINFO_MIN_LATENCY, &allocInfo);
    SetIsNeedCondWait();
    ret = laneManager->lnnReAllocLane(laneReqId, LANE_ID_BASE, &allocInfo, &g_listenerCbForBr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    ret = DelLaneResourceByLaneId(LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_CANCEL_Test_001
* @tc.desc: lane cancel after notify
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_CANCEL_Test_001, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);
    EXPECT_CALL(wifiMock, LnnCancelWifiDirect).WillRepeatedly(Return());
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(63, 63, 0, 0);

    LaneAllocInfo allocInfo;
    ASSERT_EQ(memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo)), EOK);
    CreateAllocInfoForAllocTest(LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + HIGH_BW, DEFAULT_QOSINFO_MAX_LATENCY,
        DEFAULT_QOSINFO_MIN_LATENCY, &allocInfo);
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    ret = laneManager->lnnCancelLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LANE_CANCEL_Test_002
* @tc.desc: lane cancel before notify
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_CANCEL_Test_002, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    LnnWifiAdpterInterfaceMock::delayNotifyLinkSuccess = true;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);
    EXPECT_CALL(wifiMock, LnnCancelWifiDirect).WillRepeatedly(Return());
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(63, 63, 0, 0);

    LaneAllocInfo allocInfo;
    ASSERT_EQ(memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo)), EOK);
    CreateAllocInfoForAllocTest(LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + HIGH_BW, DEFAULT_QOSINFO_MAX_LATENCY,
        DEFAULT_QOSINFO_MIN_LATENCY, &allocInfo);
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = laneManager->lnnCancelLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    LnnWifiAdpterInterfaceMock::delayNotifyLinkSuccess = false;
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_FOR_LOOP_COMPLETION_MS));
}

/*
* @tc.name: LANE_CANCEL_Test_003
* @tc.desc: lane cancel after free
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_CANCEL_Test_003, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);
    EXPECT_CALL(wifiMock, LnnCancelWifiDirect).WillRepeatedly(Return());
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(63, 63, 0, 0);

    LaneAllocInfo allocInfo;
    ASSERT_EQ(memset_s(&allocInfo, sizeof(LaneAllocInfo), 0, sizeof(LaneAllocInfo)), EOK);
    CreateAllocInfoForAllocTest(LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + HIGH_BW, DEFAULT_QOSINFO_MAX_LATENCY,
        DEFAULT_QOSINFO_MIN_LATENCY, &allocInfo);
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = laneManager->lnnCancelLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    laneType = LANE_TYPE_TRANS;
    laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
}

/*
* @tc.name: LNN_BUILD_LINK_001
* @tc.desc: BUILDLINK
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_BUILD_LINK_001, TestSize.Level1)
{
    LinkRequest reqInfo = {};
    reqInfo.linkType = LANE_P2P;
    LaneLinkCb cb = {
        .onLaneLinkSuccess = OnLaneLinkSuccess,
        .onLaneLinkFail = OnLaneLinkFail,
    };
    int32_t ret;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    EXPECT_CALL(wifiMock, LnnDisconnectP2p).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(wifiMock, LnnConnectP2p)
        .WillOnce(Return(SOFTBUS_LANE_BUILD_LINK_FAIL))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_EQ(ret, SOFTBUS_LANE_BUILD_LINK_FAIL);

    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    cb.onLaneLinkFail = nullptr;
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    cb.onLaneLinkSuccess = nullptr;
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

    ret = DestroyLink(NODE_NETWORK_ID, 0, LANE_BLE);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    
    EXPECT_CALL(wifiMock, LnnDestroyP2p).WillRepeatedly(Return());
    ret = DestroyLink(NODE_NETWORK_ID, 0, LANE_P2P);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = DestroyLink(nullptr, 0, LANE_P2P);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_BUILD_LINK_002
* @tc.desc: BUILDLINK
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_BUILD_LINK_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LinkRequest reqInfo = {};
    reqInfo.linkType = LANE_P2P;
    LaneLinkCb cb = {
        .onLaneLinkSuccess = OnLaneLinkSuccess,
        .onLaneLinkFail = OnLaneLinkFail,
    };
    int32_t ret;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    const char *udid = "testuuid";
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    EXPECT_CALL(mock, LnnConvertDLidToUdid).WillRepeatedly(Return(udid));
    EXPECT_CALL(mock, ConnBleGetClientConnectionByUdid).WillRepeatedly(Return(NULL));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    ON_CALL(wifiMock, LnnConnectP2p).WillByDefault(Return(SOFTBUS_LANE_BUILD_LINK_FAIL));
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_EQ(ret, SOFTBUS_LANE_BUILD_LINK_FAIL);
}

/*
* @tc.name: LNN_BUILD_LINK_003
* @tc.desc: BUILDLINK
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_BUILD_LINK_003, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LinkRequest reqInfo = {};
    reqInfo.linkType = LANE_P2P;
    LaneLinkCb cb = {
        .onLaneLinkSuccess = OnLaneLinkSuccess,
        .onLaneLinkFail = OnLaneLinkFail,
    };
    int32_t ret;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;

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
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
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
    LinkRequest reqInfo = {};
    int32_t ret;
    const char *udid = "testuuid";
    LaneLinkCb cb = {
        .onLaneLinkSuccess = OnLaneLinkSuccess,
        .onLaneLinkFail = OnLaneLinkFail,
    };

    reqInfo.linkType = LANE_BLE;
    EXPECT_CALL(mock, LnnConvertDLidToUdid).WillRepeatedly(Return(udid));
    EXPECT_CALL(mock, ConnBleGetClientConnectionByUdid).WillRepeatedly(Return(nullptr));
    ON_CALL(mock, LnnGetRemoteStrInfo).WillByDefault(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_NE(ret, SOFTBUS_OK);

    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    ON_CALL(mock, SoftBusGenerateStrHash).WillByDefault(Return(SOFTBUS_ENCRYPT_ERR));
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
    LinkRequest reqInfo = {};
    int32_t ret;
    const char *udid = "testuuid";
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    LaneLinkCb cb = {
        .onLaneLinkSuccess = OnLaneLinkSuccess,
        .onLaneLinkFail = OnLaneLinkFail,
    };

    reqInfo.linkType = LANE_BLE;
    ConnBleConnection *connection = (ConnBleConnection *)SoftBusCalloc(sizeof(ConnBleConnection));
    if (connection == nullptr) {
        return;
    }
    connection->state = BLE_CONNECTION_STATE_INVALID;
    EXPECT_CALL(mock, LnnConvertDLidToUdid).WillRepeatedly(Return(udid));
    EXPECT_CALL(mock, ConnBleGetClientConnectionByUdid).WillRepeatedly(Return(connection));
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
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
        .onLaneLinkSuccess = OnLaneLinkSuccess,
        .onLaneLinkFail = OnLaneLinkFail,
    };
    NiceMock<LaneDepsInterfaceMock> mock;
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
    EXPECT_TRUE(ret == SOFTBUS_LANE_NOT_FOUND);
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
    NiceMock<LaneDepsInterfaceMock> mock;
    uint32_t reqId = 0;
    LaneLinkCb cb = {
        .onLaneLinkSuccess = OnLaneLinkSuccess,
        .onLaneLinkFail = OnLaneLinkFail,
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
    NiceMock<LaneDepsInterfaceMock> mock;
    LinkRequest reqInfo = {};
    int32_t ret;
    const char *udid = "testuuid";
    const char *bleMac = "127.1.1.1";
    LaneLinkCb cb = {
        .onLaneLinkSuccess = OnLaneLinkSuccess,
        .onLaneLinkFail = OnLaneLinkFail,
    };

    reqInfo.linkType = LANE_COC;
    if (strcpy_s(reqInfo.peerBleMac, MAX_MAC_LEN, bleMac) != EOK) {
        return;
    }
    EXPECT_CALL(mock, LnnConvertDLidToUdid).WillRepeatedly(Return(udid));
    EXPECT_CALL(mock, ConnBleGetClientConnectionByUdid).WillRepeatedly(Return(nullptr));
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);

    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusGenerateStrHash)
        .WillOnce(Return(SOFTBUS_ENCRYPT_ERR))
        .WillRepeatedly(LaneDepsInterfaceMock::ActionOfGenerateStrHash);
    ret = BuildLink(&reqInfo, 0, &cb);
    EXPECT_EQ(ret, SOFTBUS_ENCRYPT_ERR);
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
        .onLaneLinkSuccess = OnLaneLinkSuccess,
        .onLaneLinkFail = OnLaneLinkFail,
    };
    NiceMock<LaneDepsInterfaceMock> mock;
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
    const char *networkId = "testnetworkid123";
    const char *ipAddr = "127.0.0.1";
    uint16_t port = 1022;
    NiceMock<LaneDepsInterfaceMock> mock;
    LinkRequest reqInfo = {};
    int32_t ret;
    const char *udid = "testuuid";
    const char *bleMac = "127.1.1.1";
    LaneLinkCb cb = {
        .onLaneLinkSuccess = OnLaneLinkSuccess,
        .onLaneLinkFail = OnLaneLinkFail,
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
    LaneAddP2pAddress(networkId, ipAddr, port);
    LaneAddP2pAddressByIp(ipAddr, port);
    LaneUpdateP2pAddressByIp(ipAddr, networkId);
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
* @tc.name: LANE_FLOAD_EXPLORE_001
* @tc.desc: LANE FLOAD EXPLORE TEST
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_FLOAD_EXPLORE_001, TestSize.Level1)
{
    LaneResource resourceItem = {};
    resourceItem.clientRef = DEFAULT_LANE_RESOURCE_LANE_REF;
    int32_t ret = LaneDetectFload(&resourceItem);
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
        .onLaneLinkSuccess = OnLaneLinkSuccess,
        .onLaneLinkFail = OnLaneLinkFail,
    };

    NiceMock<LaneDepsInterfaceMock> mock;
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
        .onLaneLinkSuccess = OnLaneLinkSuccess,
        .onLaneLinkFail = OnLaneLinkFail,
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
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
    EXPECT_CALL(mock, ConnOpenClientSocket).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AddTrigger).WillRepeatedly(Return(SOFTBUS_OK));

    ret = LaneDetectReliability(laneReqId, &linkInfo, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    LaneDetectInfo requestItem = {};
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
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    LaneLinkCb cb = {
        .onLaneLinkSuccess = OnLaneLinkSuccess,
        .onLaneLinkFail = OnLaneLinkFail,
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
        .WillOnce(Return(SOFTBUS_TCPCONNECTION_SOCKET_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AddTrigger).WillRepeatedly(Return(SOFTBUS_LANE_DETECT_FAIL));

    ret = LaneDetectReliability(laneReqId, &linkInfo, &cb);
    EXPECT_EQ(ret, SOFTBUS_TCPCONNECTION_SOCKET_ERR);
    linkInfo.linkInfo.wlan.connInfo.port = PORT_B;

    ret = LaneDetectReliability(laneReqId, &linkInfo, &cb);
    EXPECT_EQ(ret, SOFTBUS_LANE_DETECT_FAIL);
    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_DETECT_RELIABILITY_004
* @tc.desc: WLAN LANE DETECT RELIABILITY TEST
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_DETECT_RELIABILITY_004, TestSize.Level1)
{
    const char *ipAddr = "127.0.0.1";
    LaneLinkCb cb = {
        .onLaneLinkSuccess = OnLaneLinkSuccessForDetect,
        .onLaneLinkFail = OnLaneLinkFailForDetect,
    };

    LaneLinkInfo linkInfo;
    linkInfo.type = LANE_WLAN_5G;
    linkInfo.linkInfo.wlan.connInfo.port = PORT_A;
    EXPECT_EQ(strcpy_s(linkInfo.linkInfo.wlan.connInfo.addr, MAX_SOCKET_ADDR_LEN, ipAddr), EOK);
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    int32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, ConnOpenClientSocket)
        .WillOnce(Return(SOFTBUS_TCPCONNECTION_SOCKET_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AddTrigger).WillOnce(Return(SOFTBUS_CONN_FAIL))
        .WillRepeatedly(LaneDepsInterfaceMock::ActionOfAddTrigger);
    char buf[] = "lanedetect";
    EXPECT_CALL(mock, ConnSendSocketData).WillRepeatedly(Return(sizeof(buf)));

    int32_t ret = LaneDetectReliability(laneReqId, &linkInfo, &cb);
    EXPECT_EQ(ret, SOFTBUS_TCPCONNECTION_SOCKET_ERR);

    ret = LaneDetectReliability(laneReqId, &linkInfo, &cb);
    EXPECT_EQ(ret, SOFTBUS_CONN_FAIL);

    ret = LaneDetectReliability(laneReqId, &linkInfo, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_DETECT_RELIABILITY_005
* @tc.desc: WLAN LANE DETECT RELIABILITY, SOFTBUS_SOCKET_EXCEPTION
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_DETECT_RELIABILITY_005, TestSize.Level1)
{
    const char *ipAddr = "127.0.0.1";
    LaneLinkCb cb = {
        .onLaneLinkSuccess = OnLaneLinkSuccessForDetect,
        .onLaneLinkFail = OnLaneLinkFailForDetect,
    };

    LaneLinkInfo linkInfo;
    linkInfo.type = LANE_WLAN_5G;
    linkInfo.linkInfo.wlan.connInfo.port = PORT_A;
    EXPECT_EQ(strcpy_s(linkInfo.linkInfo.wlan.connInfo.addr, MAX_SOCKET_ADDR_LEN, ipAddr), EOK);
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    int32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);
    LaneDepsInterfaceMock::socketEvent = SOFTBUS_SOCKET_EXCEPTION;
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, ConnOpenClientSocket).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AddTrigger).WillRepeatedly(LaneDepsInterfaceMock::ActionOfAddTrigger);
    char buf[] = "lanedetect";
    EXPECT_CALL(mock, ConnSendSocketData).WillRepeatedly(Return(sizeof(buf)));

    int32_t ret = LaneDetectReliability(laneReqId, &linkInfo, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_DETECT_RELIABILITY_006
* @tc.desc: WLAN LANE DETECT RELIABILITY TIMEOUT
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_DETECT_RELIABILITY_006, TestSize.Level1)
{
    const char *ipAddr = "127.0.0.1";
    LaneLinkCb cb = {
        .onLaneLinkSuccess = OnLaneLinkSuccessForDetect,
        .onLaneLinkFail = OnLaneLinkFailForDetect,
    };

    LaneLinkInfo linkInfo;
    linkInfo.type = LANE_WLAN_5G;
    linkInfo.linkInfo.wlan.connInfo.port = PORT_A;
    EXPECT_EQ(strcpy_s(linkInfo.linkInfo.wlan.connInfo.addr, MAX_SOCKET_ADDR_LEN, ipAddr), EOK);
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    int32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, ConnOpenClientSocket).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AddTrigger).WillRepeatedly(Return(SOFTBUS_OK));
    char buf[] = "lanedetect";
    EXPECT_CALL(mock, ConnSendSocketData).WillRepeatedly(Return(sizeof(buf)));
    SetIsNeedCondWait();
    int32_t ret = LaneDetectReliability(laneReqId, &linkInfo, &cb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_INIT_RELIABLITY_001
* @tc.desc: LANE INIT RELIABLITY TEST
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_INIT_RELIABLITY_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = InitLaneReliability();
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
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(16), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(16), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(16), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(16), Return(SOFTBUS_OK)));

    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();

    LaneAllocInfo allocInfo = {};
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

    AuthLinkTypeList mockList = {};
    mockList.linkType[0] = AUTH_LINK_TYPE_WIFI;
    mockList.linkTypeNum = 1;
    EXPECT_CALL(mock, GetAuthLinkTypeList)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(mockList), Return(SOFTBUS_OK)));
    ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
}

/*
* @tc.name: LNN_LANE_03
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_03, TestSize.Level1)
{
    uint32_t laneReqId = 0;
    LaneRequestOption request;
    ILaneListener listener;
    ILaneIdStateListener laneListener;

    RegisterLaneIdListener(nullptr);
    laneListener.OnLaneIdEnabled = nullptr;
    laneListener.OnLaneIdDisabled = nullptr;
    RegisterLaneIdListener(&laneListener);
    UnregisterLaneIdListener(nullptr);
    FreeLaneReqId(laneReqId);
    laneReqId = 0xfffffff;
    FreeLaneReqId(laneReqId);
    request.type = LANE_TYPE_BUTT;
    int32_t ret = LnnRequestLane(0, &request, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    request.type = (LaneType)-1;
    ret = LnnRequestLane(0, &request, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_LANE_04
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_04, TestSize.Level1)
{
    RawLaneAllocInfo allocInfo;
    LaneAllocListener listener;

    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneHandle = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneHandle != INVALID_LANE_REQ_ID);

    int32_t ret = laneManager->lnnAllocRawLane(laneHandle, nullptr, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = laneManager->lnnAllocRawLane(laneHandle, &allocInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = laneManager->lnnAllocRawLane(laneHandle, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    allocInfo.type = LANE_TYPE_BUTT;
    ret = laneManager->lnnAllocRawLane(laneHandle, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    allocInfo.type = (LaneType)-1;
    ret = laneManager->lnnAllocRawLane(laneHandle, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_LANE_05
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_05, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneHandle = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneHandle != INVALID_LANE_REQ_ID);

    EXPECT_CALL(wifiMock, LnnConnectP2p).WillRepeatedly(Return(SOFTBUS_OK));
    RawLaneAllocInfo allocInfo;
    allocInfo.type = LANE_TYPE_HDLC;
    LaneAllocListener listener;
    int32_t ret = laneManager->lnnAllocRawLane(laneHandle, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = laneManager->lnnFreeLane(laneHandle);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
}

/*
* @tc.name: LNN_LANE_06
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_06, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneHandle = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneHandle != INVALID_LANE_REQ_ID);

    EXPECT_CALL(wifiMock, LnnConnectP2p).WillRepeatedly(Return(SOFTBUS_OK));
    RawLaneAllocInfo allocInfo;
    allocInfo.type = LANE_TYPE_TRANS;
    LaneAllocListener listener = {
        .onLaneFreeSuccess = OnLaneFreeSuccess,
        .onLaneFreeFail = OnLaneFreeFail,
    };
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocRawLane(laneHandle, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = laneManager->lnnFreeLane(laneHandle);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LNN_LANE_07
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_07, TestSize.Level1)
{
    LaneAllocInfoExt allocInfo;
    LaneAllocListener listener;
    NiceMock<LaneDepsInterfaceMock> laneDepMock;

    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneHandle = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneHandle != INVALID_LANE_REQ_ID);

    int32_t ret = laneManager->lnnAllocTargetLane(laneHandle, &allocInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = laneManager->lnnAllocTargetLane(laneHandle, nullptr, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = laneManager->lnnAllocTargetLane(laneHandle, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = laneManager->lnnAllocTargetLane(INVALID_LANE_REQ_ID, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = laneManager->lnnAllocTargetLane(INVALID_LANE_REQ_ID, nullptr, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = laneManager->lnnAllocTargetLane(INVALID_LANE_REQ_ID, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    allocInfo.type = LANE_TYPE_BUTT;
    ret = laneManager->lnnAllocTargetLane(laneHandle, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    allocInfo.type = LANE_TYPE_TRANS;
    allocInfo.linkList.linkTypeNum = LANE_LINK_TYPE_BUTT;
    ret = laneManager->lnnAllocTargetLane(laneHandle, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_LANE_08
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_08, TestSize.Level1)
{
    LaneAllocInfoExt allocInfo;
    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneHandle = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneHandle != INVALID_LANE_REQ_ID);

    EXPECT_CALL(laneDepMock, DeleteNetworkResourceByLaneId).WillRepeatedly(Return());
    EXPECT_CALL(laneDepMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    laneDepMock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    laneDepMock.SetDefaultResultForAlloc(1 << BIT_WIFI_P2P, 1 << BIT_WIFI_P2P, 8, 8);
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneHandle, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);

    allocInfo.linkList.linkTypeNum = LANE_LINK_TYPE_BUTT - 1;
    allocInfo.type = LANE_TYPE_TRANS;
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocTargetLane(laneHandle, &allocInfo, &g_listenerCbForBr2);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneHandle);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LNN_LANE_12
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_12, TestSize.Level1)
{
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    const LnnLaneManager *laneManager = GetLaneManager();
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfOnConnectP2pFail);
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(63, 63, 0, 0);
    EXPECT_CALL(mock, ConnOpenClientSocket).WillRepeatedly(Return(SOFTBUS_CONN_FAIL));
    EXPECT_CALL(mock, DeleteNetworkResourceByLaneId).WillRepeatedly(Return());
    LaneAllocInfo allocInfo = {};
    CreateAllocInfoForAllocTest(LANE_T_MSG, DEFAULT_QOSINFO_MIN_BW + HIGH_BW, DEFAULT_QOSINFO_MAX_LATENCY,
        DEFAULT_QOSINFO_MIN_LATENCY, &allocInfo);
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LNN_LANE_13
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_13, TestSize.Level1)
{
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = ApplyLaneReqId(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(DoAll(SetArgPointee<1>(NET_CAP), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(NET_CAP), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    EXPECT_CALL(wifiMock, SoftBusGetLinkBand).WillRepeatedly(Return(BAND_5G));

    LaneRequestOption requestOption = {};
    requestOption.type = laneType;
    EXPECT_EQ(strncpy_s(requestOption.requestInfo.trans.networkId, NETWORK_ID_BUF_LEN,
        NODE_NETWORK_ID, strlen(NODE_NETWORK_ID)), EOK);
    requestOption.requestInfo.trans.transType = LANE_T_COMMON_VIDEO;
    requestOption.requestInfo.trans.expectedBw = 0;
    requestOption.requestInfo.trans.pid = 0;
    requestOption.requestInfo.trans.expectedLink.linkTypeNum = 1;
    requestOption.requestInfo.trans.expectedLink.linkType[0] = LANE_WLAN_5G;

    int32_t ret = LnnRequestLane(laneReqId, &requestOption, &g_listener2);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);
    ret = LnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
}
} // namespace OHOS
