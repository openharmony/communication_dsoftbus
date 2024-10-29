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
constexpr char PEER_WLAN_ADDR[] = "172.30.0.1";
constexpr char PEER_MAC[] = "a1:b2:c3:d4:e5:f6";
constexpr char LOCAL_MAC[] = "a2:b2:c3:d4:e5:f6";
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
constexpr uint32_t MESH_MAGIC_NUMBER = 0x5A5A5A5A;
constexpr uint32_t PORT_A = 22;
constexpr uint32_t PORT_B = 25;
constexpr uint32_t FD = 888;
constexpr uint32_t SLEEP_FOR_LOOP_COMPLETION_MS = 50;
constexpr uint32_t NET_CAP = 63;
constexpr uint32_t FREQUENCY_2G_FIRST = 2412;
constexpr uint32_t LOCAL_NUM = 8192;
constexpr uint32_t ROM_NUM = 8;
constexpr uint32_t ROM_NUM2 = 2;

static SoftBusCond g_cond = {0};
static SoftBusMutex g_lock = {0};
static int32_t g_errCode = 0;

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

static LaneAllocListener g_listenerCbForP2p2 = {
    .onLaneAllocSuccess = OnLaneAllocSuccessForP2p,
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
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listener);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_FOR_LOOP_COMPLETION_MS));
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
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForWlan5g);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
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
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForBle);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
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
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForBr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
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
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForWlan5g);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
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
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForWlan5g);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
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
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForBle);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
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
    ret = laneManager->lnnReAllocLane(laneReqId, LANE_ID_BASE, &allocInfo, &g_listenerCbForWlan5g);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    ret = DelLaneResourceByLaneId(LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
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
    ret = laneManager->lnnReAllocLane(laneReqId, LANE_ID_BASE, &allocInfo, &g_listenerCbForBr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    ret = DelLaneResourceByLaneId(LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
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
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = laneManager->lnnCancelLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
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
    int32_t ret = laneManager->lnnAllocLane(laneReqId, &allocInfo, &g_listenerCbForP2p);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_FOR_LOOP_COMPLETION_MS));
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
* @tc.name: LANE_INFO_001
* @tc.desc: LaneInfoProcess BR
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_INFO_001, TestSize.Level1)
{
    LaneLinkInfo info = {};
    info.type = LANE_BR;
    LaneConnInfo connInfo = {};
    LaneProfile profile = {};
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
    LaneLinkInfo info = {};
    info.type = LANE_BLE;
    LaneConnInfo connInfo = {};
    LaneProfile profile = {};
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
    LaneLinkInfo info = {};
    info.type = LANE_P2P;
    LaneConnInfo connInfo;
    LaneProfile profile = {};
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
    LaneLinkInfo info = {};
    info.type = LANE_LINK_TYPE_BUTT;
    LaneConnInfo *connInfo = nullptr;
    LaneProfile *profile = nullptr;
    int32_t ret = LaneInfoProcess(nullptr, connInfo, profile);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LaneInfoProcess(&info, nullptr, profile);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LaneInfoProcess(&info, connInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = LaneInfoProcess(&info, connInfo, profile);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LANE_INFO_005
* @tc.desc: LaneInfoProcess 2.4G
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_INFO_005, TestSize.Level1)
{
    LaneLinkInfo info = {};
    LaneConnInfo connInfo = {};
    LaneProfile profile = {};

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

    info.type = LANE_HML_RAW;
    ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    info.type = LANE_LINK_TYPE_BUTT;
    ret = LaneInfoProcess(&info, &connInfo, &profile);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

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
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    LaneProfile profile = {};
    ret = BindLaneIdToProfile(laneId, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    profile.linkType = LANE_P2P;
    profile.content = LANE_T_FILE;
    profile.priority = LANE_PRI_LOW;
    ret = BindLaneIdToProfile(laneId, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    LaneGenerateParam param = {};
    param.linkType = LANE_P2P;
    param.transType = LANE_T_FILE;
    param.priority = LANE_PRI_LOW;
    uint32_t profileId = GenerateLaneProfileId(&param);

    ret = GetLaneProfile(profileId, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = GetLaneProfile(profileId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

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
* @tc.name: LNN_LANE_PROFILE_002
* @tc.desc: BindLaneIdToProfile
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_PROFILE_002, TestSize.Level1)
{
    uint64_t laneId = 0x1000000000000002;
    uint32_t profileId = 111111;
    LaneProfile profile = {};
    int32_t ret = GetLaneProfile(profileId, &profile);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    uint64_t *laneReqIdList = nullptr;
    uint32_t listSize = 0;
    ret = GetLaneIdList(profileId, &laneReqIdList, &listSize);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    profile.linkType = LANE_P2P;
    profile.content = LANE_T_FILE;
    profile.priority = LANE_PRI_LOW;
    ret = BindLaneIdToProfile(laneId, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = BindLaneIdToProfile(laneId, &profile);
    EXPECT_EQ(ret, SOFTBUS_OK);

    (void)UnbindLaneIdFromProfile(laneId, profileId);
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
    LaneSelectParam selectParam = {};
    selectParam.transType = LANE_T_FILE;
    selectParam.expectedBw = 0;
    selectParam.list.linkTypeNum = 2;
    selectParam.list.linkType[0] = LANE_WLAN_5G;
    selectParam.list.linkType[1] = LANE_LINK_TYPE_BUTT;

    int32_t ret = SelectLane(NODE_NETWORK_ID, nullptr, linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(false));
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    ret = SelectLane(NODE_NETWORK_ID, &selectParam, linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    ret = SelectLane(NODE_NETWORK_ID, &selectParam, linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    selectParam.transType = LANE_T_MIX;
    ret = SelectLane(NODE_NETWORK_ID, &selectParam, linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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
    LaneSelectParam selectParam = {};
    selectParam.transType = LANE_T_FILE;
    selectParam.expectedBw = 0;
    selectParam.list.linkTypeNum = DEFAULT_SELECT_NUM;
    selectParam.list.linkType[0] = LANE_BLE;
    selectParam.list.linkType[1] = LANE_WLAN_2P4G;
    selectParam.list.linkType[2] = LANE_WLAN_5G;
    selectParam.list.linkType[3] = LANE_BR;

    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    int32_t ret = SelectLane(NODE_NETWORK_ID, &selectParam, linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    ret = SelectLane(NODE_NETWORK_ID, &selectParam, linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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
    LanePreferredLinkList linkList = {};
    uint32_t listNum = 0;
    LaneSelectParam selectParam = {};
    NodeInfo node = {};

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
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumU64Info).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    int32_t ret = SelectLane(NODE_NETWORK_ID, &selectParam, &linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    node.discoveryType = 3;
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(node), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    ret = SelectLane(NODE_NETWORK_ID, &selectParam, &linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);
}

/*
* @tc.name: LNN_SELECT_LANE_004
* @tc.desc: SelectLane, HmlIsExist == true
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_SELECT_LANE_004, TestSize.Level1)
{
    LaneSelectParam request = {};
    request.transType = LANE_T_FILE;
    request.list.linkTypeNum = 0;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_BR;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_BLE;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_P2P;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_HML;

    LanePreferredLinkList recommendList = {};
    uint32_t listNum = 0;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(8), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)\
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(8), Return(SOFTBUS_OK)));

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
    LaneSelectParam request = {};
    request.transType = LANE_T_FILE;
    request.list.linkTypeNum = 0;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_BR;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_BLE;
    request.list.linkType[(request.list.linkTypeNum)++] = LANE_P2P;

    LanePreferredLinkList recommendList = {};
    uint32_t listNum = 0;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(11), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(8), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(8), Return(SOFTBUS_OK)));

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
* @tc.name: LNN_SELECT_EXPECT_LANES_BY_QOS_001
* @tc.desc: SelectExpectLanesByQos
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_SELECT_EXPECT_LANES_BY_QOS_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LanePreferredLinkList linkList;
    LaneSelectParam selectParam = {};
    selectParam.transType = LANE_T_FILE;
    selectParam.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW;
    selectParam.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    selectParam.qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;
    int32_t ret = SelectExpectLanesByQos(NODE_NETWORK_ID, nullptr, &linkList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(false));
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NODE_OFFLINE);

    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    selectParam.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW + LOW_BW;
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    selectParam.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW + HIGH_BW;
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    selectParam.transType = LANE_T_MIX;
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);
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
    LaneSelectParam selectParam = {};
    selectParam.transType = LANE_T_FILE;
    int32_t ret = SelectExpectLanesByQos(NODE_NETWORK_ID, nullptr, &linkList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(false));
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NODE_OFFLINE);

    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    selectParam.transType = LANE_T_MIX;
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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
    LaneSelectParam selectParam = {};
    selectParam.transType = LANE_T_FILE;


    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();

    selectParam.qosRequire.rttLevel = LANE_RTT_LEVEL_LOW;
    int32_t ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);
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
* @tc.name: LANE_DECISION_MODELS_001
* @tc.desc: LANE DECISION MODELS TEST
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_DECISION_MODELS_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LaneSelectParam selectParam = {};
    LanePreferredLinkList linkList;
    selectParam.transType = LANE_T_FILE;
    selectParam.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW;
    selectParam.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    selectParam.qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;

    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, SoftBusGetLinkBand).WillRepeatedly(Return(BAND_5G));
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));

    int32_t ret = DecideAvailableLane(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);
}

/*
* @tc.name: LANE_FIND_LANERESOURCE_BY_LINKADDR_001
* @tc.desc: LANE FIND LANERESOURCE BY LINK ADDR TEST
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_FIND_LANERESOURCE_BY_LINKADDR_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
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
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    uint64_t laneId = LANE_ID_BASE;
    uint32_t clientRef = 0;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    clientRef++;

    LaneLinkInfo linkInfoFind;
    ASSERT_EQ(memset_s(&linkInfoFind, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo)), EOK);
    linkInfoFind.type = LANE_HML;
    ret = FindLaneResourceByLinkAddr(&linkInfoFind, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    ASSERT_EQ(strncpy_s(linkInfoFind.peerUdid, UDID_BUF_LEN, PEER_UDID, strlen(PEER_UDID)), EOK);
    ret = FindLaneResourceByLinkAddr(&linkInfoFind, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

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
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
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
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    uint64_t laneId = LANE_ID_BASE;
    uint32_t clientRef = 0;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    clientRef++;

    ret = FindLaneResourceByLinkType(LOCAL_UDID, LANE_HML, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    ret = FindLaneResourceByLinkType(PEER_UDID, LANE_P2P, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

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
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
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
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    laneId = LANE_ID_BASE;
    uint32_t clientRef = 0;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    clientRef++;

    ret = FindLaneResourceByLaneId(INVALID_LANE_ID, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

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
* @tc.name: LANE_DEL_AND_ADD_LANERESOURCEITEM_001
* @tc.desc: LANE_DEL AND ADD LANERESOURCEITEM CLIENT
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_DEL_AND_ADD_LANERESOURCEITEM_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
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
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);
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
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);
}

/*
* @tc.name: LANE_DEL_AND_ADD_LANERESOURCEITEM_002
* @tc.desc: LANE_DEL AND ADD LANERESOURCEITEM SERVER
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_DEL_AND_ADD_LANERESOURCEITEM_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
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

    ret = DelLaneResourceByLaneId(laneId, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_GENERATE_LANE_ID_001
* @tc.desc: LANE GENERATE LANE ID
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_GENERATE_LANE_ID_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> laneMock;
    EXPECT_CALL(laneMock, SoftBusGenerateStrHash)
        .WillOnce(Return(SOFTBUS_ENCRYPT_ERR))
        .WillRepeatedly(LaneDepsInterfaceMock::ActionOfGenerateStrHash);

    uint64_t laneId = GenerateLaneId(LOCAL_UDID, PEER_UDID, LANE_HML);
    EXPECT_EQ(laneId, INVALID_LANE_ID);

    laneId = GenerateLaneId(LOCAL_UDID, PEER_UDID, LANE_HML);
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
    LanePreferredLinkList recommendList = {};
    LanePreferredLinkList request = {};

    request.linkTypeNum = 4;
    request.linkType[0] = LANE_P2P;
    request.linkType[1] = LANE_BLE;
    request.linkType[2] = LANE_BR;
    request.linkType[3] = LANE_HML;

    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    int32_t ret = SelectAuthLane(nullptr, &recommendList, &request);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = SelectAuthLane(networkId, nullptr, &request);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = SelectAuthLane(networkId, &recommendList, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = SelectAuthLane(networkId, &recommendList, &request);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);
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
* @tc.name: LANE_CLEAR_LANE_RESOURCE_BYLANEID_001
* @tc.desc: ClearLaneResourceByLaneId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_CLEAR_LANE_RESOURCE_BYLANEID_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));

    uint64_t laneId = LANE_ID_BASE;
    int32_t ret = ClearLaneResourceByLaneId(laneId);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    LaneLinkInfo linkInfo = {};
    linkInfo.type = LANE_HML;
    EXPECT_EQ(strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML, strlen(PEER_IP_HML)), EOK);
    EXPECT_EQ(strncpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID, strlen(PEER_UDID)), EOK);
    uint32_t clientRef = 0;
    ret = AddLaneResourceToPool(&linkInfo, laneId, true);
    EXPECT_EQ(ret, SOFTBUS_OK);

    LaneResource laneResourse = {};
    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(laneResourse.isServerSide);
    EXPECT_EQ(laneResourse.clientRef, clientRef);

    ret = ClearLaneResourceByLaneId(laneId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);
}

/*
* @tc.name: LANE_PPOCESS_VAP_INFO_001
* @tc.desc: ProcessVapInfo hml
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_PPOCESS_VAP_INFO_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    LaneLinkInfo linkInfo = {};
    linkInfo.type = LANE_P2P;
    EXPECT_EQ(strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML, strlen(PEER_IP_HML)), EOK);
    EXPECT_EQ(strncpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID, strlen(PEER_UDID)), EOK);
    uint64_t laneId = LANE_ID_BASE;
    uint64_t laneIdExt = LANE_ID_BASE + 1;
    uint32_t clientRef = 0;
    int32_t ret = AddLaneResourceToPool(&linkInfo, laneId, true);
    EXPECT_EQ(ret, SOFTBUS_OK);

    linkInfo.type = LANE_HML;
    ret = AddLaneResourceToPool(&linkInfo, laneIdExt, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    clientRef++;

    ret = ClearLaneResourceByLaneId(laneId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    LaneResource laneResourse = {};
    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    ret = FindLaneResourceByLaneId(laneIdExt, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(!laneResourse.isServerSide);
    EXPECT_EQ(laneResourse.clientRef, clientRef);

    ret = DelLaneResourceByLaneId(laneIdExt, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LANE_PPOCESS_VAP_INFO_002
* @tc.desc: ProcessVapInfo p2p
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LANE_PPOCESS_VAP_INFO_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    LaneLinkInfo linkInfo = {};
    linkInfo.type = LANE_HML;
    EXPECT_EQ(strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML, strlen(PEER_IP_HML)), EOK);
    EXPECT_EQ(strncpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID, strlen(PEER_UDID)), EOK);
    uint64_t laneId = LANE_ID_BASE;
    uint64_t laneIdExt = LANE_ID_BASE + 1;
    uint32_t clientRef = 0;
    int32_t ret = AddLaneResourceToPool(&linkInfo, laneId, true);
    EXPECT_EQ(ret, SOFTBUS_OK);

    linkInfo.type = LANE_P2P;
    ret = AddLaneResourceToPool(&linkInfo, laneIdExt, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    clientRef++;

    ret = ClearLaneResourceByLaneId(laneId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    LaneResource laneResourse = {};
    ret = FindLaneResourceByLaneId(laneId, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);

    ret = FindLaneResourceByLaneId(laneIdExt, &laneResourse);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_TRUE(!laneResourse.isServerSide);
    EXPECT_EQ(laneResourse.clientRef, clientRef);

    ret = DelLaneResourceByLaneId(laneIdExt, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_SELECT_01
* @tc.desc: SelectLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_SELECT_01, TestSize.Level1)
{
    const char *networkId = "test";
    LaneLinkType linkType = LANE_LINK_TYPE_BUTT;
    int32_t ret = LaneCapCheck(networkId, linkType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_LANE_SELECT_02
* @tc.desc: SelectLane
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_SELECT_02, TestSize.Level1)
{
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    NiceMock<LaneDepsInterfaceMock> mock;

    EXPECT_CALL(wifiMock, SoftBusGetWifiState)
        .WillRepeatedly(Return(SOFTBUS_WIFI_STATE_INACTIVE));
    int32_t ret = GetErrCodeOfLink("networkId", LANE_WLAN_2P4G);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    ret = GetErrCodeOfLink("networkId", LANE_P2P_REUSE);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    ret = GetErrCodeOfLink("networkId", LANE_HML);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    EXPECT_CALL(wifiMock, SoftBusGetWifiState)
        .WillRepeatedly(Return(SOFTBUS_WIFI_STATE_DEACTIVATING));
    ret = GetErrCodeOfLink("networkId", LANE_HML);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    ret = GetErrCodeOfLink("networkId", LANE_P2P_REUSE);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    EXPECT_CALL(mock, SoftBusGetBtState)
        .WillRepeatedly(Return(0));
    EXPECT_EQ(GetErrCodeOfLink("networkId", LANE_BR), SOFTBUS_LANE_BT_OFF);
    EXPECT_EQ(GetErrCodeOfLink("networkId", LANE_BLE), SOFTBUS_LANE_BT_OFF);
    EXPECT_EQ(GetErrCodeOfLink("networkId", LANE_BLE_DIRECT), SOFTBUS_LANE_BT_OFF);
    EXPECT_EQ(GetErrCodeOfLink("networkId", LANE_BLE_REUSE), SOFTBUS_LANE_BT_OFF);

    EXPECT_CALL(mock, SoftBusGetBtState)
        .WillRepeatedly(Return(1));
    EXPECT_EQ(GetErrCodeOfLink("networkId", LANE_BR), SOFTBUS_LANE_LOCAL_NO_BR_CAP);
    EXPECT_EQ(GetErrCodeOfLink("networkId", LANE_BLE), SOFTBUS_LANE_LOCAL_NO_BLE_CAP);
    EXPECT_EQ(GetErrCodeOfLink("networkId", LANE_BLE_DIRECT), SOFTBUS_LANE_LOCAL_NO_BLE_CAP);
}

/*
* @tc.name: LNN_LANE_SELECT_RULE_01
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_SELECT_RULE_01, TestSize.Level1)
{
    LaneLinkType linkList;
    uint32_t listNum = 0;
    LanePreferredLinkList recommendList;
    int32_t ret = FinalDecideLinkType(nullptr, &linkList, listNum, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = FinalDecideLinkType(nullptr, nullptr, listNum, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = FinalDecideLinkType(nullptr, nullptr, listNum, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    listNum = LANE_LINK_TYPE_BUTT;
    ret = FinalDecideLinkType("test", &linkList, listNum, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_LANE_SELECT_RULE_02
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_SELECT_RULE_02, TestSize.Level1)
{
    LaneLinkType linkList[LANE_LINK_TYPE_BUTT];
    uint32_t listNum = 1;
    LanePreferredLinkList recommendList;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));

    linkList[0] = LANE_P2P;
    int32_t ret = FinalDecideLinkType("test", linkList, listNum, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_SELECT_RULE_03
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_SELECT_RULE_03, TestSize.Level1)
{
    LaneLinkType linkList;
    uint32_t listNum = 1;
    LanePreferredLinkList recommendList;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_ERR)));

    int32_t ret = FinalDecideLinkType("test", &linkList, listNum, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(-1), Return(SOFTBUS_OK)));
    ret = FinalDecideLinkType("test", &linkList, listNum, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_ERR)));
    ret = FinalDecideLinkType("test", &linkList, listNum, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(-1), Return(SOFTBUS_OK)));
    ret = FinalDecideLinkType("test", &linkList, listNum, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_SELECT_RULE_04
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_SELECT_RULE_04, TestSize.Level1)
{
    LaneSelectParam request;
    LanePreferredLinkList recommendList;
    int32_t ret = DecideAvailableLane("test", nullptr, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DecideAvailableLane("test", &request, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DecideAvailableLane("test", nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_LANE_SELECT_RULE_05
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_SELECT_RULE_05, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> linkMock;

    LnnWifiAdpterInterfaceMock wifiMock;
    LaneSelectParam request;
    LanePreferredLinkList recommendList;

    EXPECT_CALL(wifiMock, SoftBusGetLinkBand).WillRepeatedly(Return(BAND_5G));
    request.qosRequire.minLaneLatency = 0;
    EXPECT_CALL(linkMock, LnnGetRemoteNodeInfoById)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(wifiMock, SoftBusGetWifiState)
        .WillRepeatedly(Return(SOFTBUS_WIFI_STATE_INACTIVE));
    int32_t ret = DecideAvailableLane("test", &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    request.transType = LANE_T_FILE;
    request.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW;
    request.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    request.qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;

    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo)
        .WillRepeatedly(Return(SOFTBUS_ERR));
    ret = DecideAvailableLane(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    EXPECT_CALL(linkMock, LnnGetOsTypeByNetworkId)
        .WillRepeatedly(Return(SOFTBUS_ERR));
    ret = DecideAvailableLane(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    int32_t osType = OH_OS_TYPE;
    EXPECT_CALL(linkMock, LnnGetOsTypeByNetworkId)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(osType), Return(SOFTBUS_OK)));
    ret = DecideAvailableLane(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);

    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(linkMock, LnnGetOsTypeByNetworkId)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(osType), Return(SOFTBUS_OK)));
    ret = DecideAvailableLane(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_OFF);
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
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
    LaneAllocListener listener;
    int32_t ret = laneManager->lnnAllocRawLane(laneHandle, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = laneManager->lnnFreeLane(laneHandle);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
    EXPECT_CALL(laneDepMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));

    allocInfo.linkList.linkTypeNum = LANE_LINK_TYPE_BUTT - 1;
    allocInfo.type = LANE_TYPE_TRANS;
    int32_t ret = laneManager->lnnAllocTargetLane(laneHandle, &allocInfo, &g_listenerCbForP2p2);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = laneManager->lnnFreeLane(laneHandle);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

/*
* @tc.name: LNN_LANE_09
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_09, TestSize.Level1)
{
    LnnMacInfo macInfo;
    LaneLinkInfo linkInfo;
    linkInfo.type = LANE_P2P;
    NiceMock<LaneDepsInterfaceMock> laneDepMock;

    EXPECT_EQ(strncpy_s(linkInfo.linkInfo.p2p.connInfo.localIp, IP_LEN, PEER_IP_HML, strlen(PEER_IP_HML)), EOK);
    EXPECT_EQ(strcpy_s(macInfo.localMac, MAX_MAC_LEN, LOCAL_MAC), EOK);
    EXPECT_EQ(strcpy_s(macInfo.remoteMac, MAX_MAC_LEN, PEER_MAC), EOK);
    int32_t ret = AddLaneResourceToPool(&linkInfo, LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetMacInfoByLaneId(LANE_ID_BASE, &macInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    linkInfo.type = LANE_P2P_REUSE;
    ret = AddLaneResourceToPool(&linkInfo, LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetMacInfoByLaneId(LANE_ID_BASE, &macInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    linkInfo.type = LANE_HML;
    ret = AddLaneResourceToPool(&linkInfo, LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetMacInfoByLaneId(LANE_ID_BASE, &macInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    linkInfo.type = LANE_ETH;
    ret = AddLaneResourceToPool(&linkInfo, LANE_ID_BASE, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(laneDepMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    ret = GetMacInfoByLaneId(LANE_ID_BASE, &macInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_LANE_11
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_11, TestSize.Level1)
{
    LaneLinkInfo linkInfo;
    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    LnnMacInfo macInfo;
    ASSERT_EQ(memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo)), EOK);
    linkInfo.type = LANE_P2P;
    ASSERT_EQ(strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML, strlen(PEER_IP_HML)), EOK);
    ASSERT_EQ(strncpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID, strlen(PEER_UDID)), EOK);
    uint64_t laneId = LANE_ID_BASE;
    EXPECT_CALL(laneDepMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(laneDepMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    ret = GetMacInfoByLaneId(LANE_ID_BASE, &macInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
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

/*
* @tc.name: LNN_LANE_14
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_14, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    LaneSelectParam selectParam = {};
    LanePreferredLinkList linkList = {};
    selectParam.transType = LANE_T_RAW_STREAM;
    selectParam.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW;
    selectParam.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    selectParam.qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;

    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, SoftBusGetLinkBand).WillRepeatedly(Return(BAND_24G));
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVATING));
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));

    int32_t ret = DecideAvailableLane(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_WIFI_BAND_ERR);
}

/*
* @tc.name: LNN_LANE_15
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_15, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    LaneSelectParam selectParam = {};
    LanePreferredLinkList linkList = {};
    selectParam.transType = LANE_T_RAW_STREAM;
    selectParam.qosRequire.minBW = DEFAULT_QOSINFO_MIN_BW;
    selectParam.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    selectParam.qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;

    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, SoftBusGetLinkBand).WillRepeatedly(Return(BAND_5G));
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVATING));
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_ERR));
    int32_t ret = DecideAvailableLane(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
}

/*
* @tc.name: LNN_LANE_16
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_16, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    LaneSelectParam selectParam = {};
    LanePreferredLinkList linkList = {};
    selectParam.transType = LANE_T_RAW_STREAM;
    selectParam.qosRequire.minBW = HIGH_BW;
    selectParam.qosRequire.maxLaneLatency = DEFAULT_QOSINFO_MAX_LATENCY;
    selectParam.qosRequire.minLaneLatency = DEFAULT_QOSINFO_MIN_LATENCY;

    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, SoftBusGetLinkBand).WillRepeatedly(Return(BAND_5G));
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVATING));
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info).WillRepeatedly(Return(SOFTBUS_ERR));
    int32_t ret = DecideAvailableLane(NODE_NETWORK_ID, &selectParam, &linkList);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
}

/*
* @tc.name: LNN_LANE_17
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_17, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    uint32_t listNum = 0;
    LanePreferredLinkList linkList = {};
    LaneSelectParam selectParam = {};
    selectParam.transType = LANE_T_FILE;
    selectParam.expectedBw = 0;
    selectParam.list.linkTypeNum = 2;
    selectParam.list.linkType[0] = LANE_WLAN_2P4G;
    selectParam.list.linkType[1] = LANE_COC_DIRECT;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(16), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(16), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumU64Info).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    wifiMock.SetDefaultResult();
    SoftBusWifiLinkedInfo wlanInfo;
    wlanInfo.frequency = 1;
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVATING));
    EXPECT_CALL(wifiMock, SoftBusGetLinkedInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM1>(wlanInfo), Return(SOFTBUS_OK)));
    int32_t ret = SelectLane(NODE_NETWORK_ID, &selectParam, &linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_18
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_18, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    uint32_t listNum = 0;
    LanePreferredLinkList linkList = {};
    LaneSelectParam selectParam = {};
    selectParam.transType = LANE_T_FILE;
    selectParam.expectedBw = 0;
    selectParam.list.linkTypeNum = 2;
    selectParam.list.linkType[0] = LANE_WLAN_2P4G;
    selectParam.list.linkType[1] = LANE_COC_DIRECT;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(16), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(16), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetLocalNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnGetRemoteNumU64Info).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    EXPECT_CALL(mock, LnnHasDiscoveryType).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_OK));
    wifiMock.SetDefaultResult();
    SoftBusWifiLinkedInfo wlanInfo;
    wlanInfo.frequency = FREQUENCY_2G_FIRST + 1;
    EXPECT_CALL(wifiMock, SoftBusGetLinkedInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM1>(wlanInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVATING));
    int32_t ret = SelectLane(NODE_NETWORK_ID, &selectParam, &linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_19
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_19, TestSize.Level1)
{
    LaneLinkType linkType = LANE_COC_DIRECT;
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(1), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillOnce(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(ROM_NUM), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(LOCAL_NUM), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillOnce(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(ROM_NUM), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(LOCAL_NUM), Return(SOFTBUS_OK)));
    int32_t ret = LaneCapCheck(NODE_NETWORK_ID, linkType);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_COC_CAP);
}

/*
* @tc.name: LNN_LANE_20
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_20, TestSize.Level1)
{
    LaneLinkType linkType = LANE_P2P_REUSE;
    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_DEACTIVATING));
    int32_t ret = LaneCapCheck(NODE_NETWORK_ID, linkType);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_WIFI_DIRECT_CAP);
}

/*
* @tc.name: LNN_LANE_21
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_21, TestSize.Level1)
{
    LaneLinkType linkType = LANE_P2P_REUSE;
    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_SEMIACTIVATING));
    int32_t ret = LaneCapCheck(NODE_NETWORK_ID, linkType);
    EXPECT_EQ(ret, SOFTBUS_LANE_REMOTE_NO_WIFI_DIRECT_CAP);
}

/*
* @tc.name: LNN_LANE_22
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_22, TestSize.Level1)
{
    LaneLinkType linkType = LANE_P2P_REUSE;
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(ROM_NUM), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(ROM_NUM), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(0), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(0), Return(SOFTBUS_OK)));
    int32_t ret = LaneCapCheck(NODE_NETWORK_ID, linkType);
    EXPECT_EQ(ret, SOFTBUS_LANE_LOCAL_NO_WIFI_DIRECT_CAP);

    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(ROM_NUM2), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(ROM_NUM2), Return(SOFTBUS_OK)));
    ret = LaneCapCheck(NODE_NETWORK_ID, linkType);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_23
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_23, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LanePreferredLinkList linkList = {};
    uint32_t listNum = 0;
    LaneSelectParam selectParam = {};
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(false));
    int32_t ret = SelectLane(NODE_NETWORK_ID, &selectParam, &linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NODE_OFFLINE);

    ret = SelectLane(nullptr, &selectParam, &linkList, &listNum);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SelectLane(NODE_NETWORK_ID, &selectParam, &linkList, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_LANE_24
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_24, TestSize.Level1)
{
    LanePreferredLinkList recommendList = {};
    LaneSelectParam selectParam = {};
    int32_t ret = SelectExpectLanesByQos(nullptr, &selectParam, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &selectParam, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_LANE_25
* @tc.desc: SelectLaneRule
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_25, TestSize.Level1)
{
    LaneLinkType linkType = LANE_ETH;
    int32_t ret = LaneCapCheck(NODE_NETWORK_ID, linkType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_LANE_UPDATE_LANE_ID_001
* @tc.desc: test UpdateLaneResourceLaneId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_UPDATE_LANE_ID_001, TestSize.Level1)
{
    LaneLinkInfo linkInfo = {};
    linkInfo.type = LANE_HML;
    ASSERT_EQ(strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML, strlen(PEER_IP_HML)), EOK);
    ASSERT_EQ(strncpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID, strlen(PEER_UDID)), EOK);

    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    EXPECT_CALL(laneDepMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    uint64_t laneId = LANE_ID_BASE;
    uint64_t laneIdNew = LANE_ID_BASE + 1;
    int32_t ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateLaneResourceLaneId(laneId, laneIdNew, PEER_UDID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLaneResourceByLaneId(laneIdNew, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_DETECT_ENABLE_WIFI_DIRECT_001
* @tc.desc: test DetectEnableWifiDirectApply & DetectDisableWifiDirectApply
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_LANE_DETECT_DISABLE_WIFI_DIRECT_001, TestSize.Level1)
{
    LaneLinkInfo linkInfo = {};
    linkInfo.type = LANE_HML;
    linkInfo.linkInfo.p2p.bw = LANE_BW_160M;
    ASSERT_EQ(strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML, strlen(PEER_IP_HML)), EOK);
    ASSERT_EQ(strncpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID, strlen(PEER_UDID)), EOK);
    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    EXPECT_CALL(laneDepMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(laneDepMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));

    uint64_t laneId = LANE_ID_BASE;
    int32_t ret = AddLaneResourceToPool(&linkInfo, laneId, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
    linkInfo.type = LANE_HML_RAW;
    uint64_t laneIdNew = LANE_ID_BASE + 1;
    ret = AddLaneResourceToPool(&linkInfo, laneIdNew, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DetectDisableWifiDirectApply();
    ret = DelLaneResourceByLaneId(laneId, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLaneResourceByLaneId(laneIdNew, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_CHECK_LANE_RESOURCE_NUM_001
* @tc.desc: test CheckLaneResourceNumByLinkType
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_CHECK_LANE_RESOURCE_NUM_001, TestSize.Level1)
{
    LaneLinkInfo linkInfo = {};
    linkInfo.type = LANE_HML;
    ASSERT_EQ(strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML, strlen(PEER_IP_HML)), EOK);
    ASSERT_EQ(strncpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID, strlen(PEER_UDID)), EOK);
    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    EXPECT_CALL(laneDepMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));

    int32_t laneNum = 0;
    int32_t ret = CheckLaneResourceNumByLinkType(nullptr, LANE_HML, &laneNum);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CheckLaneResourceNumByLinkType(nullptr, LANE_LINK_TYPE_BUTT, &laneNum);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CheckLaneResourceNumByLinkType(PEER_UDID, LANE_HML, &laneNum);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    uint64_t laneId = LANE_ID_BASE;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CheckLaneResourceNumByLinkType(PEER_UDID, LANE_HML, &laneNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DelLaneResourceByLaneId(laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_ADD_LANE_IS_VALID_LINK_ADDR_001
* @tc.desc: test IsValidLinkAddr(hml/br/ble)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_ADD_LANE_IS_VALID_LINK_ADDR_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    EXPECT_CALL(laneDepMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));

    LaneLinkInfo linkInfo = {};
    linkInfo.type = LANE_HML;
    ASSERT_EQ(strncpy_s(linkInfo.linkInfo.p2p.connInfo.peerIp, IP_LEN, PEER_IP_HML, strlen(PEER_IP_HML)), EOK);
    ASSERT_EQ(strncpy_s(linkInfo.linkInfo.br.brMac, BT_MAC_LEN, PEER_MAC, strlen(PEER_MAC)), EOK);
    ASSERT_EQ(strncpy_s(linkInfo.linkInfo.ble.bleMac, BT_MAC_LEN, PEER_MAC, strlen(PEER_MAC)), EOK);
    ASSERT_EQ(strncpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID, strlen(PEER_UDID)), EOK);
    uint64_t laneId = LANE_ID_BASE;
    int32_t ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    linkInfo.type = LANE_BR;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    linkInfo.type = LANE_BLE;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = ClearLaneResourceByLaneId(laneId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: LNN_ADD_LANE_IS_VALID_LINK_ADDR_002
* @tc.desc: test IsValidLinkAddr(coc_direct/wlan)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneMockTest, LNN_ADD_LANE_IS_VALID_LINK_ADDR_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    EXPECT_CALL(laneDepMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));

    LaneLinkInfo linkInfo = {};
    linkInfo.type = LANE_COC_DIRECT;
    ASSERT_EQ(strncpy_s(linkInfo.linkInfo.wlan.connInfo.addr, MAX_SOCKET_ADDR_LEN,
        PEER_WLAN_ADDR, strlen(PEER_WLAN_ADDR)), EOK);
    ASSERT_EQ(strncpy_s(linkInfo.linkInfo.bleDirect.networkId, NETWORK_ID_BUF_LEN,
        NODE_NETWORK_ID, strlen(NODE_NETWORK_ID)), EOK);
    ASSERT_EQ(strncpy_s(linkInfo.peerUdid, UDID_BUF_LEN, PEER_UDID, strlen(PEER_UDID)), EOK);
    uint64_t laneId = LANE_ID_BASE;
    int32_t ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    linkInfo.type = LANE_WLAN_5G;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    linkInfo.type = LANE_LINK_TYPE_BUTT;
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddLaneResourceToPool(&linkInfo, laneId, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = ClearLaneResourceByLaneId(laneId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS
