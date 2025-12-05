/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "g_enhance_lnn_func.h"
#include "lnn_feature_capability.h"
#include "lnn_lane.h"
#include "lnn_lane_common.h"
#include "lnn_lane_def.h"
#include "lnn_lane_deps_mock.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_link.h"
#include "lnn_lane_model.h"
#include "lnn_lane_reliability.c"
#include "lnn_lane_reliability.h"
#include "lnn_lane_select.h"
#include "lnn_select_rule.h"
#include "lnn_wifi_adpter_mock.h"
#include "message_handler.h"
#include "meta_socket_struct.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"
#include "softbus_wifi_api_adapter.h"
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
constexpr uint32_t LOW_BW = 384 * 1024;
constexpr uint32_t MID_BW = 30 * 1024 * 1024;
constexpr uint32_t HIGH_BW = 160 * 1024 * 1024;
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

static NodeInfo g_NodeInfo = {
    .p2pInfo.p2pRole = 1,
    .p2pInfo.p2pMac = "abc",
    .p2pInfo.goMac = "abc",
};

class LNNLaneAllocTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneAllocTest::SetUpTestCase()
{
    (void)SoftBusMutexInit(&g_lock, nullptr);
    (void)SoftBusCondInit(&g_cond);
    int32_t ret = LnnInitLnnLooper();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LooperInit();
    NiceMock<LaneDepsInterfaceMock> mock;
    EXPECT_CALL(mock, StartBaseClient).WillRepeatedly(LaneDepsInterfaceMock::ActionOfStartBaseClient);
    ret = InitLane();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    GTEST_LOG_(INFO) << "LNNLaneAllocTest start";
}

void LNNLaneAllocTest::TearDownTestCase()
{
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    EXPECT_CALL(wifiMock, LnnDestroyP2p).WillRepeatedly(Return());
    DeinitLane();
    LooperDeinit();
    LnnDeinitLnnLooper();
    (void)SoftBusCondDestroy(&g_cond);
    (void)SoftBusMutexDestroy(&g_lock);
    GTEST_LOG_(INFO) << "LNNLaneAllocTest end";
}

void LNNLaneAllocTest::SetUp()
{
}

void LNNLaneAllocTest::TearDown()
{
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
    ASSERT_NE(laneManager, nullptr);
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
    ASSERT_NE(laneManager, nullptr);
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

static void OnLaneAllocSuccessForSoftApP2p(uint32_t laneHandle, const LaneConnInfo *info)
{
    (void)laneHandle;
    ASSERT_NE(info, nullptr) << "invalid connInfo";
    GTEST_LOG_(INFO) << "alloc lane successful, linkType=" << info->type;
    EXPECT_EQ(info->type, LANE_SOFTAP_P2P);
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

static void OnLaneAllocFailNoExcept3(uint32_t laneHandle, int32_t errCode)
{
    GTEST_LOG_(INFO) << "alloc lane failed, laneReqId=" << laneHandle;
    EXPECT_EQ(errCode, SOFTBUS_NOT_IMPLEMENT);
    CondSignal();
}

static LaneAllocListener g_listenerCbForHml = {
    .onLaneAllocSuccess = OnLaneAllocSuccessForHml,
    .onLaneAllocFail = OnLaneAllocFailNoExcept2,
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
    .onLaneAllocFail = OnLaneAllocFailNoExcept2,
    .onLaneFreeSuccess = OnLaneFreeSuccess,
    .onLaneFreeFail = OnLaneFreeFail,
};

static LaneAllocListener g_listenerCbForWlan5g = {
    .onLaneAllocSuccess = OnLaneAllocSuccessForWlan5g,
    .onLaneAllocFail = OnLaneAllocFailNoExcept2,
    .onLaneFreeSuccess = OnLaneFreeSuccess,
    .onLaneFreeFail = OnLaneFreeFail,
};

static LaneAllocListener g_listenerCbForBle = {
    .onLaneAllocSuccess = OnLaneAllocSuccessForBle,
    .onLaneAllocFail = OnLaneAllocFailNoExcept2,
    .onLaneFreeSuccess = OnLaneFreeSuccess,
    .onLaneFreeFail = OnLaneFreeFail,
};

static LaneAllocListener g_listenerCbForSoftApP2p = {
    .onLaneAllocSuccess = OnLaneAllocSuccessForSoftApP2p,
    .onLaneAllocFail = OnLaneAllocFailNoExcept3,
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
HWTEST_F(LNNLaneAllocTest, LANE_ALLOC_ERRTEST_001, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
* @tc.name: LANE_ALLOC_TEST_001
* @tc.desc: lane alloc by select default link for T_MSG (build wlan5g)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_ALLOC_TEST_001, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
    (void)memset_s(&wlanInfo, sizeof(SoftBusWifiLinkedInfo), 0, sizeof(SoftBusWifiLinkedInfo));
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
* @tc.name: LANE_ALLOC_TEST_002
* @tc.desc: lane alloc by select default link for T_BYTE (not enable wlan and br, build ble)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_ALLOC_TEST_002, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
* @tc.name: LANE_ALLOC_TEST_003
* @tc.desc: lane alloc by select default link for T_FILE (not enable wlan and hml, build p2p)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_ALLOC_TEST_003, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(1 << BIT_WIFI_P2P, 1 << BIT_WIFI_P2P, 0, 0);
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_ACTIVED));
    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfLnnConnectP2p);

    LaneAllocInfo allocInfo = {};
    CreateAllocInfoForAllocTest(LANE_T_FILE, 0, 0, 0, &allocInfo);
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
* @tc.name: LANE_ALLOC_TEST_004
* @tc.desc: lane alloc by select default link for T_RAW_STREAM (not enable wlan, build p2p)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_ALLOC_TEST_004, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_TEST_005
* @tc.desc: lane alloc by mesh link (not enable wlan, build br)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_ALLOC_TEST_005, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
* @tc.name: LANE_ALLOC_TEST_006
* @tc.desc: lane alloc by RTT link (not enable hml, build p2p)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_ALLOC_TEST_006, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_TEST_007
* @tc.desc: lane alloc by qos require (HIGH_BW, build hml)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_ALLOC_TEST_007, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(NET_CAP, NET_CAP, 1 << BIT_WIFI_DIRECT_ENHANCE_CAPABILITY,
        1 << BIT_WIFI_DIRECT_ENHANCE_CAPABILITY);
    EXPECT_CALL(mock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_ACTIVED));
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
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_TEST_008
* @tc.desc: lane alloc by qos require (MID_HIGH_BW, not enable hml, build wlan5g)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_ALLOC_TEST_008, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
    (void)memset_s(&wlanInfo, sizeof(SoftBusWifiLinkedInfo), 0, sizeof(SoftBusWifiLinkedInfo));
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
* @tc.name: LANE_ALLOC_TEST_009
* @tc.desc: lane alloc by qos require (MID_LOW_BW, not enable wlan5g and hml, build wlan24g)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_ALLOC_TEST_009, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
    (void)memset_s(&wlanInfo, sizeof(SoftBusWifiLinkedInfo), 0, sizeof(SoftBusWifiLinkedInfo));
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
* @tc.name: LANE_ALLOC_TEST_010
* @tc.desc: lane alloc by qos require (LOW_BW, not enable wlan5g\hml\br\p2p\coc_direct, build ble)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_ALLOC_TEST_010, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
* @tc.name: LANE_ALLOC_TEST_011
* @tc.desc: lane alloc for exception deal before select link
* @tc.type: FAILUE
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_ALLOC_TEST_011, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
* @tc.name: LANE_ALLOC_TEST_012
* @tc.desc: lane alloc for continuous task(local is watch)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_ALLOC_TEST_012, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
* @tc.name: LANE_ALLOC_TEST_013
* @tc.desc: lane alloc for continuous task(remote is watch)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_ALLOC_TEST_013, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
* @tc.name: LANE_ALLOC_TEST_014
* @tc.desc: lane alloc for MIDDLE_LOW_BW&not continuous task(local is watch)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_ALLOC_TEST_014, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(15, 15, 0x3137A, 0x3FFEA);
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
* @tc.name: LANE_ALLOC_TEST_015
* @tc.desc: lane alloc for MIDDLE_HIGH_BW&not continuous task(remote is watch)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_ALLOC_TEST_015, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(15, 15, 0x3FFEA, 0x3137A);
    EXPECT_CALL(mock, LnnGetRemoteNumInfo)
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
* @tc.name: LANE_ALLOC_TEST_016
* @tc.desc: lane alloc for continuous task(lowBw and remote is hoos, expect link is br)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_ALLOC_TEST_016, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
* @tc.name: LANE_RE_ALLOC_TEST_001
* @tc.desc: lane re alloc for invalid param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_RE_ALLOC_TEST_001, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
* @tc.name: LANE_RE_ALLOC_TEST_002
* @tc.desc: lane re alloc for MSG HIGH_BW
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_RE_ALLOC_TEST_002, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_RE_ALLOC_TEST_003
* @tc.desc: lane re alloc for MSG MID_HIGH_BW
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_RE_ALLOC_TEST_003, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(63, 63, 1 << BIT_WIFI_DIRECT_ENHANCE_CAPABILITY,
        1 << BIT_WIFI_DIRECT_ENHANCE_CAPABILITY);
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
    (void)memset_s(&wlanInfo, sizeof(SoftBusWifiLinkedInfo), 0, sizeof(SoftBusWifiLinkedInfo));
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
* @tc.name: LANE_RE_ALLOC_TEST_004
* @tc.desc: lane re alloc for MSG MID_LOW_BW
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_RE_ALLOC_TEST_004, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(NET_CAP, NET_CAP, 1 << BIT_WIFI_DIRECT_ENHANCE_CAPABILITY,
        1 << BIT_WIFI_DIRECT_ENHANCE_CAPABILITY);
    EXPECT_CALL(mock, DeleteNetworkResourceByLaneId).WillRepeatedly(Return());
    EXPECT_CALL(mock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    int32_t ret = AddLaneResourceForAllocTest(LANE_WLAN_5G);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    EXPECT_CALL(wifiMock, SoftBusGetWifiState).WillRepeatedly(Return(SOFTBUS_WIFI_STATE_ACTIVED));
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
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneReqId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_RE_ALLOC_TEST_005
* @tc.desc: lane re alloc for MSG LOW_BW
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_RE_ALLOC_TEST_005, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(15, 15, 1 << BIT_WIFI_DIRECT_ENHANCE_CAPABILITY,
        1 << BIT_WIFI_DIRECT_ENHANCE_CAPABILITY);
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
* @tc.name: LNN_AUTH_ALLOC_TEST_001
* @tc.desc: AuthAlloc
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LNN_AUTH_ALLOC_TEST_001, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
}

/*
* @tc.name: LNN_ALLOC_ROW_LANE_TEST_01
* @tc.desc: test lnnAllocRawLane invalid param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LNN_ALLOC_ROW_LANE_TEST_01, TestSize.Level1)
{
    RawLaneAllocInfo allocInfo;
    LaneAllocListener listener;

    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
* @tc.name: LNN_ALLOC_ROW_LANE_TEST_02
* @tc.desc: lnnAllocRawLane LANE_TYPE_HDLC
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LNN_ALLOC_ROW_LANE_TEST_02, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
* @tc.name: LNN_ALLOC_ROW_LANE_TEST_03
* @tc.desc: lnnAllocRawLane LANE_TYPE_TRANS
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LNN_ALLOC_ROW_LANE_TEST_03, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
    CondWait();
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneHandle);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LNN_ALLOC_TARGET_LANE_TEST_01
* @tc.desc: lnnAllocTargetLane invalid param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LNN_ALLOC_TARGET_LANE_TEST_01, TestSize.Level1)
{
    LaneAllocInfoExt allocInfo;
    LaneAllocListener listener;
    NiceMock<LaneDepsInterfaceMock> laneDepMock;

    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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
    allocInfo.linkList.linkTypeNum = 0;
    ret = laneManager->lnnAllocTargetLane(laneHandle, &allocInfo, &listener);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_ALLOC_TARGET_LANE_TEST_02
* @tc.desc: lnnAllocTargetLane LANE_TYPE_TRANS
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LNN_ALLOC_TARGET_LANE_TEST_02, TestSize.Level1)
{
    LaneAllocInfoExt allocInfo;
    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
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

static int32_t AuthMetaGetIpByMetaNodeId(const char *metaNodeId, char *ip, int32_t len)
{
    (void)metaNodeId;
    (void)ip;
    (void)len;
    return SOFTBUS_OK;
}

static int32_t AuthMetaGetLocalIpByMetaNodeId(const char *metaNodeId, char *localIp, int32_t len)
{
    (void)metaNodeId;
    (void)localIp;
    (void)len;
    return SOFTBUS_OK;
}

/*
* @tc.name: LNN_ALLOC_TARGET_LANE_TEST_03
* @tc.desc: lnnAllocTargetLane linkType LANE_SOFTAP_P2P get ip failed
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LNN_ALLOC_TARGET_LANE_TEST_03, TestSize.Level1)
{
    LaneAllocInfoExt allocInfo = {};
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
    uint32_t laneHandle = laneManager->lnnGetLaneHandle(LANE_TYPE_TRANS);
    EXPECT_NE(laneHandle, INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    EXPECT_CALL(laneDepMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    LnnEnhanceFuncList *pfnLnnEnhanceFuncList = LnnEnhanceFuncListGet();
    pfnLnnEnhanceFuncList->authMetaGetIpByMetaNodeId = nullptr;
    allocInfo.linkList.linkType[0] = LANE_SOFTAP_P2P;
    allocInfo.linkList.linkTypeNum = 1;
    allocInfo.type = LANE_TYPE_TRANS;
    SetIsNeedCondWait();
    int32_t ret = laneManager->lnnAllocTargetLane(laneHandle, &allocInfo, &g_listenerCbForSoftApP2p);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();

    pfnLnnEnhanceFuncList->authMetaGetIpByMetaNodeId = AuthMetaGetIpByMetaNodeId;
    pfnLnnEnhanceFuncList->authMetaGetLocalIpByMetaNodeId = nullptr;
    SetIsNeedCondWait();
    ret = laneManager->lnnAllocTargetLane(laneHandle, &allocInfo, &g_listenerCbForSoftApP2p);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();

    g_listenerCbForSoftApP2p.onLaneAllocFail = OnLaneAllocFailNoExcept2;
    EXPECT_CALL(laneDepMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    SetIsNeedCondWait();
    ret = laneManager->lnnAllocTargetLane(laneHandle, &allocInfo, &g_listenerCbForSoftApP2p);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    g_listenerCbForSoftApP2p.onLaneAllocFail = OnLaneAllocFailNoExcept3;
}

/*
* @tc.name: LNN_ALLOC_TARGET_LANE_TEST_04
* @tc.desc: lnnAllocTargetLane linkType LANE_SOFTAP_P2P success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LNN_ALLOC_TARGET_LANE_TEST_04, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> laneDepMock;
    LaneAllocInfoExt allocInfo = {};
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
    uint32_t laneHandle = laneManager->lnnGetLaneHandle(LANE_TYPE_TRANS);
    EXPECT_NE(laneHandle, INVALID_LANE_REQ_ID);

    LnnEnhanceFuncList *pfnLnnEnhanceFuncList = LnnEnhanceFuncListGet();
    pfnLnnEnhanceFuncList->authMetaGetIpByMetaNodeId = AuthMetaGetIpByMetaNodeId;
    pfnLnnEnhanceFuncList->authMetaGetLocalIpByMetaNodeId = AuthMetaGetLocalIpByMetaNodeId;
    EXPECT_CALL(laneDepMock, SoftBusGenerateStrHash).WillRepeatedly(LaneDepsInterfaceMock::ActionOfGenerateStrHash);
    allocInfo.linkList.linkType[0] = LANE_SOFTAP_P2P;
    allocInfo.linkList.linkTypeNum = 1;
    allocInfo.type = LANE_TYPE_TRANS;
    int32_t ret = strcpy_s(allocInfo.commInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(ret, EOK);
    SetIsNeedCondWait();
    ret = laneManager->lnnAllocTargetLane(laneHandle, &allocInfo, &g_listenerCbForSoftApP2p);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
    SetIsNeedCondWait();
    ret = laneManager->lnnFreeLane(laneHandle);
    EXPECT_EQ(ret, SOFTBUS_OK);
    CondWait();
}

/*
* @tc.name: LANE_ALLOC_TEST_017
* @tc.desc: lnnAllocLane with HIGH_BW
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_ALLOC_TEST_017, TestSize.Level1)
{
    NiceMock<LnnWifiAdpterInterfaceMock> wifiMock;
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    wifiMock.SetDefaultResult();
    EXPECT_CALL(wifiMock, LnnConnectP2p(NotNull(), laneReqId, NotNull()))
        .WillRepeatedly(LnnWifiAdpterInterfaceMock::ActionOfOnConnectP2pFail);
    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    mock.SetDefaultResultForAlloc(63, 63, 0, 0);
    EXPECT_CALL(mock, AuthMetaGetMetaTypeByMetaNodeIdPacked).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
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
* @tc.name: LANE_ALLOC_TEST_018
* @tc.desc: lnnAllocLane with meta sdk
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneAllocTest, LANE_ALLOC_TEST_018, TestSize.Level1)
{
    const LnnLaneManager *laneManager = GetLaneManager();
    ASSERT_NE(laneManager, nullptr);
    LaneType laneType = LANE_TYPE_TRANS;
    uint32_t laneReqId = laneManager->lnnGetLaneHandle(laneType);
    EXPECT_TRUE(laneReqId != INVALID_LANE_REQ_ID);

    NiceMock<LaneDepsInterfaceMock> mock;
    mock.SetDefaultResult(reinterpret_cast<NodeInfo *>(&g_NodeInfo));
    EXPECT_CALL(mock, AuthMetaGetMetaTypeByMetaNodeIdPacked)
        .WillRepeatedly(DoAll(SetArgPointee<1>(META_TYPE_SDK), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, SoftBusGenerateStrHash).WillRepeatedly(LaneDepsInterfaceMock::ActionOfGenerateStrHash);
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
}