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

#include "g_enhance_lnn_func_pack.h"
#include "lnn_lane_deps_mock.h"
#include "lnn_lane_link_deps_mock.h"
#include "lnn_lane_link_p2p.c"
#include "lnn_lane_link_p2p.h"
#include "lnn_lane_link_p2p_deps_mock.h"
#include "lnn_lane_net_capability_mock.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char NODE_NETWORK_ID[] = "123456789";
constexpr char REMOTE_NETWORK_ID[] = "234567890";
constexpr int32_t ASYNCSUCC = 3;
constexpr uint64_t DEFAULT_LINK_LATENCY = 30000;
constexpr int32_t REQID = 2;
constexpr int32_t LANEREQID = 12;
constexpr int32_t REASON = 2;
constexpr int32_t AUTHID = 2;
constexpr int32_t AUTHTYPE = 2;
constexpr int32_t AUTH_REQ_ID = 112;
constexpr int32_t REQUEST_ID = 1;
constexpr int32_t P2P_REQUEST_ID = 3;
constexpr int32_t ACTION_ADDR = 1;
constexpr int32_t GUIDE_TYPE_NUMBERS_ONE = 1;
constexpr int32_t GUIDE_TYPE_NUMBERS_TWO = 2;
constexpr int32_t GUIDE_TYPE_NUMBERS_THREE = 3;
constexpr int32_t LINK_ID_ZERO = 0;
constexpr int32_t LINK_ID_ONE = 1;
constexpr int32_t LANE_REQUEST_ID = 0;
constexpr uint32_t AUTH_REQUEST_ID = 1;
constexpr uint32_t P2P_REQ_ID = 0;
constexpr uint32_t NEW_P2P_REQ_ID = 1;

class LNNLaneLinkP2pTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneLinkP2pTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneLinkP2pTest start";
    LnnInitLnnLooper();
    EXPECT_EQ(LnnP2pInit(), SOFTBUS_OK);
}

void LNNLaneLinkP2pTest::TearDownTestCase()
{
    LnnDeinitLnnLooper();
    LnnDestroyP2pLinkInfo();
    GTEST_LOG_(INFO) << "LNNLaneLinkP2pTest end";
}

void LNNLaneLinkP2pTest::SetUp()
{
}

void LNNLaneLinkP2pTest::TearDown()
{
}

static int32_t DisconnectDevice(struct WifiDirectDisconnectInfo *info, struct WifiDirectDisconnectCallback *callback)
{
    (void)info;
    (void)callback;
    return SOFTBUS_OK;
}

static int32_t DisconnectDeviceFailed(
    struct WifiDirectDisconnectInfo *info, struct WifiDirectDisconnectCallback *callback)
{
    (void)info;
    (void)callback;
    return SOFTBUS_INVALID_PARAM;
}

static uint32_t GetRequestId(void)
{
    return REQUEST_ID;
}

static int32_t ConnectDevice(struct WifiDirectConnectInfo *info, struct WifiDirectConnectCallback *callback)
{
    (void)info;
    (void)callback;
    return SOFTBUS_OK;
}

static void TestLaneLinkSuccess(uint32_t reqId, LaneLinkType linkType, const LaneLinkInfo *linkInfo)
{
    (void)reqId;
    (void)linkType;
    (void)linkInfo;
}

static void TestLaneLinkFail(uint32_t reqId, int32_t reason, LaneLinkType linkType)
{
    (void)reqId;
    (void)linkType;
    (void)reason;
}

int32_t UpdateConcurrencyReuseLaneReqIdByUdidTest(const char *udidHash, uint32_t udidHashLen, uint32_t reuseLaneReqId,
    uint32_t connReqId)
{
    (void)udidHash;
    (void)udidHashLen;
    (void)reuseLaneReqId;
    (void)connReqId;
    return SOFTBUS_OK;
}

int32_t QueryControlPlaneNodeValidOk(const char *deviceId)
{
    (void)deviceId;
    return SOFTBUS_OK;
}

int32_t QueryControlPlaneNodeValidFail(const char *deviceId)
{
    (void)deviceId;
    return SOFTBUS_INVALID_PARAM;
}

bool HaveConcurrencyPreLinkReqIdByReuseConnReqIdOk(uint32_t connReqId, bool isCheckPreLink)
{
    (void)connReqId;
    (void)isCheckPreLink;
    return true;
}

bool HaveConcurrencyPreLinkReqIdByReuseConnReqIdFail(uint32_t connReqId, bool isCheckPreLink)
{
    (void)connReqId;
    (void)isCheckPreLink;
    return false;
}

int32_t GetConcurrencyLaneReqIdByConnReqIdOk(uint32_t connReqId, uint32_t *laneReqId)
{
    (void)connReqId;
    (void)laneReqId;
    return SOFTBUS_OK;
}

int32_t GetConcurrencyLaneReqIdByConnReqIdFail(uint32_t connReqId, uint32_t *laneReqId)
{
    (void)connReqId;
    (void)laneReqId;
    return SOFTBUS_INVALID_PARAM;
}

static struct WifiDirectManager g_manager = {
    .isNegotiateChannelNeeded = nullptr,
    .getRequestId = GetRequestId,
    .connectDevice = ConnectDevice,
    .cancelConnectDevice = nullptr,
    .disconnectDevice = DisconnectDevice,
    .supportHmlTwo = nullptr,
};

static struct WifiDirectManager g_manager1 = {
    .isNegotiateChannelNeeded = nullptr,
    .getRequestId = GetRequestId,
    .connectDevice = nullptr,
    .cancelConnectDevice = nullptr,
    .disconnectDevice = DisconnectDeviceFailed,
    .supportHmlTwo = nullptr,
};

/*
* @tc.name: TRY_CONCURRENCY_PRE_LINK_CONN_TEST_001
* @tc.desc: TryConcurrencyPreLinkConn test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, TRY_CONCURRENCY_PRE_LINK_CONN_TEST_001, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_HML;
    request.pid = ASYNCSUCC;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    request.actionAddr = ACTION_ADDR;

    WifiDirectConnectInfo connectInfo;
    (void)memset_s(&connectInfo, sizeof(WifiDirectConnectInfo), 0, sizeof(WifiDirectConnectInfo));
    connectInfo.bandWidth = 0;
    connectInfo.negoChannel.type = NEGO_CHANNEL_ACTION;
    connectInfo.connectType = WIFI_DIRECT_CONNECT_TYPE_BLE_TRIGGER_HML;
    EXPECT_EQ(strcpy_s(connectInfo.remoteNetworkId, sizeof(connectInfo.remoteNetworkId),
        REMOTE_NETWORK_ID), EOK);

    LnnEnhanceFuncList funcList = { nullptr };
    funcList.updateConcurrencyReuseLaneReqIdByUdid = nullptr;
    NiceMock<LaneLinkP2pDepsInterfaceMock> linkP2pMock;
    EXPECT_CALL(linkP2pMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&funcList));
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnConvertDlId).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, SoftBusGenerateStrHash).WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(TryConcurrencyPreLinkConn(&request, LANEREQID, &connectInfo));
    EXPECT_NO_FATAL_FAILURE(TryConcurrencyPreLinkConn(&request, LANEREQID, &connectInfo));
    EXPECT_NO_FATAL_FAILURE(TryConcurrencyPreLinkConn(&request, LANEREQID, &connectInfo));
    EXPECT_NO_FATAL_FAILURE(TryConcurrencyPreLinkConn(&request, LANEREQID, &connectInfo));
    funcList.updateConcurrencyReuseLaneReqIdByUdid = UpdateConcurrencyReuseLaneReqIdByUdidTest;
    EXPECT_NO_FATAL_FAILURE(TryConcurrencyPreLinkConn(&request, LANEREQID, &connectInfo));
}

/*
* @tc.name: ON_WIFI_DIRECT_CONNECT_SUCCESS_TEST_001
* @tc.desc: OnWifiDirectConnectSuccess test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, ON_WIFI_DIRECT_CONNECT_SUCCESS_TEST_001, TestSize.Level1)
{
    WifiDirectLink link;
    (void)memset_s(&link, sizeof(WifiDirectLink), 0, sizeof(WifiDirectLink));
    link.isReuse = true;

    LaneLinkInfo linkInfo;
    (void)memset_s(&linkInfo, sizeof(LaneLinkInfo), 0, sizeof(LaneLinkInfo));
    linkInfo.type = LANE_HML;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    NiceMock<LaneNetCapInterfaceMock> capMock;
    EXPECT_CALL(laneLinkMock, CreateWDLinkInfo).WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(linkInfo),
        Return(SOFTBUS_OK)));
    EXPECT_CALL(capMock, SetRemoteDynamicNetCap).WillRepeatedly(Return());
    EXPECT_CALL(laneLinkMock, LnnDeleteLinkLedgerInfo).WillRepeatedly(Return());
    EXPECT_CALL(laneLinkMock, TryDelPreLinkByConnReqId).WillRepeatedly(Return());
    EXPECT_NO_FATAL_FAILURE(OnWifiDirectConnectSuccess(REQID, &link));
    linkInfo.type = LANE_P2P_REUSE;
    EXPECT_NO_FATAL_FAILURE(OnWifiDirectConnectSuccess(REQID, &link));
    linkInfo.type = LANE_HML;
    link.isReuse = false;
    EXPECT_NO_FATAL_FAILURE(OnWifiDirectConnectSuccess(REQID, &link));
}

/*
* @tc.name: OPEN_BLE_TRIGGER_TO_CONN_TEST_001
* @tc.desc: OpenBleTriggerToConn test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, OPEN_BLE_TRIGGER_TO_CONN_TEST_001, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_HML;
    request.pid = ASYNCSUCC;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    request.actionAddr = ACTION_ADDR;
    LaneLinkCb cb = {
        .onLaneLinkSuccess = TestLaneLinkSuccess,
        .onLaneLinkFail = TestLaneLinkFail,
    };
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkP2pDepsInterfaceMock> linkP2pMock;
    LnnEnhanceFuncList funcList = { nullptr };
    funcList.updateConcurrencyReuseLaneReqIdByUdid = UpdateConcurrencyReuseLaneReqIdByUdidTest;
    EXPECT_CALL(linkP2pMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&funcList));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(laneLinkMock, CheckTransReqInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_EQ(OpenBleTriggerToConn(&request, LANEREQID, &cb), SOFTBUS_OK);
}

/*
* @tc.name: CONNECT_WIFI_DIRECT_WITH_REUSE_TEST_001
* @tc.desc: ConnectWifiDirectWithReuse test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, CONNECT_WIFI_DIRECT_WITH_REUSE_TEST_001, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_HML;
    request.pid = ASYNCSUCC;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    request.actionAddr = ACTION_ADDR;
    LaneLinkCb cb = {
        .onLaneLinkSuccess = TestLaneLinkSuccess,
        .onLaneLinkFail = TestLaneLinkFail,
    };
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkP2pDepsInterfaceMock> linkP2pMock;
    LnnEnhanceFuncList funcList = { nullptr };
    funcList.updateConcurrencyReuseLaneReqIdByUdid = UpdateConcurrencyReuseLaneReqIdByUdidTest;
    EXPECT_CALL(linkP2pMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&funcList));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(laneLinkMock, GetWifiDirectParamWithReuse).WillRepeatedly(Return(SOFTBUS_OK));

    EXPECT_EQ(ConnectWifiDirectWithReuse(&request, LANEREQID, &cb), SOFTBUS_OK);
}

/*
* @tc.name: ON_CONN_OPEN_FAILED_FOR_DISCONNECT_TEST_001
* @tc.desc: OnConnOpenFailedForDisconnect test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, ON_CONN_OPEN_FAILED_FOR_DISCONNECT_TEST_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_NO_FATAL_FAILURE(OnConnOpenFailedForDisconnect(REQID, REASON));
}

/*
* @tc.name: ON_CONN_OPENED_FOR_DISCONNECT_TEST_001
* @tc.desc: OnConnOpenedForDisconnect test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, ON_CONN_OPENED_FOR_DISCONNECT_TEST_001, TestSize.Level1)
{
    AuthHandle authHandle = {
        .authId = AUTHID,
        .type = AUTHTYPE,
    };
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_NO_FATAL_FAILURE(OnConnOpenedForDisconnect(REQID, authHandle));

    EXPECT_NO_FATAL_FAILURE(HandleGuideChannelRetry(LANEREQID, LANE_HML, AUTH_LINK_TYPE_MAX, REASON));
    EXPECT_EQ(InitGuideChannelLooper(), SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(HandleActionTriggerError(REQID));
}

/*
* @tc.name: ON_AUTH_CONN_OPENED_TEST_001
* @tc.desc: OnAuthConnOpened test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, ON_AUTH_CONN_OPENED_TEST_001, TestSize.Level1)
{
    AuthHandle authHandle = {
        .authId = AUTHID,
        .type = AUTHTYPE,
    };
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_NO_FATAL_FAILURE(OnAuthConnOpened(REQID, authHandle));
}

/*
* @tc.name: TRY_ADD_PRE_LINK_CONN_TEST_001
* @tc.desc: TryAddPreLinkConn test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, TRY_ADD_PRE_LINK_CONN_TEST_001, TestSize.Level1)
{
    uint32_t authReqId = AUTH_REQ_ID;
    WifiDirectConnectInfo connectInfo;
    (void)memset_s(&connectInfo, sizeof(WifiDirectConnectInfo), 0, sizeof(WifiDirectConnectInfo));
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    LaneLinkCb callback;
    (void)memset_s(&callback, sizeof(LaneLinkCb), 0, sizeof(LaneLinkCb));
    NiceMock<LaneLinkP2pDepsInterfaceMock> linkP2pMock;
    LnnEnhanceFuncList funcList = { nullptr };
    funcList.updateConcurrencyReuseLaneReqIdByUdid = UpdateConcurrencyReuseLaneReqIdByUdidTest;
    EXPECT_CALL(linkP2pMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&funcList));
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnConvertDlId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_NO_FATAL_FAILURE(TryAddPreLinkConn(authReqId, &connectInfo));
    AddP2pLinkReqItem(ASYNC_RESULT_AUTH, authReqId, LANEREQID, &request, &callback);
    EXPECT_NO_FATAL_FAILURE(TryAddPreLinkConn(authReqId, &connectInfo));
    EXPECT_NO_FATAL_FAILURE(TryAddPreLinkConn(authReqId, &connectInfo));
    DelP2pLinkReqByReqId(ASYNC_RESULT_AUTH, authReqId);
}

/*
* @tc.name: GET_HML_TWO_GUIDE_TYPE_TEST_001
* @tc.desc: GetHmlTwoGuideType test no availbe guide type
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, GET_HML_TWO_GUIDE_TYPE_TEST_001, TestSize.Level1)
{
    LinkRequest request = {};
    WdGuideType guideChannelList[LANE_CHANNEL_BUTT];
    (void)memset_s(guideChannelList, sizeof(guideChannelList), -1, sizeof(guideChannelList));
    uint32_t guideChannelNum = 0;

    NiceMock<LaneLinkP2pDepsInterfaceMock> linkP2pMock;
    LnnEnhanceFuncList funcList = { nullptr };
    funcList.queryControlPlaneNodeValid = QueryControlPlaneNodeValidFail;
    EXPECT_CALL(linkP2pMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&funcList));
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(linkMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));

    EXPECT_NO_FATAL_FAILURE(GetHmlTwoGuideType(&request, guideChannelList, &guideChannelNum));
    EXPECT_EQ(guideChannelNum, GUIDE_TYPE_NUMBERS_ONE);
    EXPECT_EQ(guideChannelList[0], LANE_BLE_TRIGGER);
}

/*
* @tc.name: GET_HML_TWO_GUIDE_TYPE_TEST_002
* @tc.desc: GetHmlTwoGuideType test LANE_SPARKLINK_TRIGGER
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, GET_HML_TWO_GUIDE_TYPE_TEST_002, TestSize.Level1)
{
    LinkRequest request = {};
    WdGuideType guideChannelList[LANE_CHANNEL_BUTT];
    (void)memset_s(guideChannelList, sizeof(guideChannelList), -1, sizeof(guideChannelList));
    uint32_t guideChannelNum = 0;

    NiceMock<LaneLinkP2pDepsInterfaceMock> linkP2pMock;
    LnnEnhanceFuncList funcList = { nullptr };
    funcList.queryControlPlaneNodeValid = QueryControlPlaneNodeValidOk;
    EXPECT_CALL(linkP2pMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&funcList));
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(linkMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));

    EXPECT_NO_FATAL_FAILURE(GetHmlTwoGuideType(&request, guideChannelList, &guideChannelNum));
    EXPECT_EQ(guideChannelNum, GUIDE_TYPE_NUMBERS_TWO);
    EXPECT_EQ(guideChannelList[0], LANE_SPARKLINK_TRIGGER);
    EXPECT_EQ(guideChannelList[1], LANE_BLE_TRIGGER);
}

/*
* @tc.name: GET_HML_TWO_GUIDE_TYPE_TEST_003
* @tc.desc: GetHmlTwoGuideType test LANE_ACTIVE_AUTH_TRIGGER
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, GET_HML_TWO_GUIDE_TYPE_TEST_003, TestSize.Level1)
{
    LinkRequest request = {};
    WdGuideType guideChannelList[LANE_CHANNEL_BUTT];
    (void)memset_s(guideChannelList, sizeof(guideChannelList), -1, sizeof(guideChannelList));
    uint32_t guideChannelNum = 0;

    NiceMock<LaneLinkP2pDepsInterfaceMock> linkP2pMock;
    LnnEnhanceFuncList funcList = { nullptr };
    funcList.queryControlPlaneNodeValid = QueryControlPlaneNodeValidOk;
    EXPECT_CALL(linkP2pMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&funcList));
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillRepeatedly(Return(true));

    EXPECT_NO_FATAL_FAILURE(GetHmlTwoGuideType(&request, guideChannelList, &guideChannelNum));
    EXPECT_EQ(guideChannelNum, GUIDE_TYPE_NUMBERS_THREE);
    EXPECT_EQ(guideChannelList[0], LANE_SPARKLINK_TRIGGER);
    EXPECT_EQ(guideChannelList[1], LANE_ACTIVE_AUTH_TRIGGER);
    EXPECT_EQ(guideChannelList[2], LANE_BLE_TRIGGER);
}

/*
* @tc.name: GUIDE_CHANNEL_SELECT_TEST_001
* @tc.desc: GuideChannelSelect test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, GUIDE_CHANNEL_SELECT_TEST_001, TestSize.Level1)
{
    P2pLinkReqList *reqInfo = (P2pLinkReqList *)SoftBusCalloc(sizeof(P2pLinkReqList));
    ASSERT_NE(reqInfo, nullptr);
    reqInfo->laneRequestInfo.cb.onLaneLinkFail = nullptr;
    int32_t ret = strcpy_s(reqInfo->laneRequestInfo.networkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(ret, EOK);
    reqInfo->laneRequestInfo.linkType = LANE_LINK_TYPE_BUTT;
    reqInfo->laneRequestInfo.pid = 0;
    reqInfo->laneRequestInfo.isSupportIpv6 = true;
    reqInfo->p2pInfo.networkDelegate = true;
    reqInfo->p2pInfo.p2pOnly = true;
    reqInfo->p2pInfo.bandWidth = 0;
    reqInfo->p2pInfo.triggerLinkTime = 0;
    reqInfo->p2pInfo.availableLinkTime = 0;

    uint32_t laneReqId = 0;
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == nullptr) {
        SoftBusFree(reqInfo);
        ASSERT_NE(msg, nullptr);
    }
    msg->arg1 = laneReqId;
    msg->obj = reqInfo;
    EXPECT_NO_FATAL_FAILURE(GuideChannelSelect(msg));
    if (msg->obj != nullptr) {
        SoftBusFree(msg->obj);
    }
    SoftBusFree(msg);
}

/*
* @tc.name: UPDATE_P2P_LINK_TEST_001
* @tc.desc: UpdateP2pLinkReconnTimesByReqId test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, UPDATE_P2P_LINK_TEST_001, TestSize.Level1)
{
    uint32_t requestId = 0;
    int32_t ret = UpdateP2pLinkReconnTimesByReqId(ASYNC_RESULT_AUTH, requestId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UpdateP2pLinkReconnTimesByReqId(ASYNC_RESULT_P2P, requestId);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
}

/*
* @tc.name: RAW_LINK_INFO_BY_REQ_ID_TEST_001
* @tc.desc: RawLinkInfoByReqId test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, RAW_LINK_INFO_BY_REQ_ID_TEST_001, TestSize.Level1)
{
    LaneLinkInfo linkInfo = {};
    RawLinkInfoList rawLinkInfo = {};
    int32_t ret = DelRawLinkInfoByReqId(P2P_REQ_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
    ret = AddRawLinkInfo(P2P_REQ_ID, LINK_ID_ZERO, &linkInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetRawLinkInfoByReqId(NEW_P2P_REQ_ID, &rawLinkInfo);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
    ret = DelRawLinkInfoByReqId(NEW_P2P_REQ_ID);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
    ret = DelRawLinkInfoByReqId(P2P_REQ_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: CHECK_RAW_LINK_INFO_TEST_001
* @tc.desc: CheckRawLinkInfo test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, CHECK_RAW_LINK_INFO_TEST_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(linkMock, AuthCheckMetaExist).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    uint32_t *p2pRequestId = static_cast<uint32_t *>(SoftBusCalloc(sizeof(uint32_t)));
    ASSERT_NE(p2pRequestId, nullptr);
    *p2pRequestId = P2P_REQ_ID;
    EXPECT_NO_FATAL_FAILURE(CheckRawLinkInfo(nullptr));
    EXPECT_NO_FATAL_FAILURE(CheckRawLinkInfo(static_cast<void *>(p2pRequestId)));
}

/*
* @tc.name: CHECK_AUTH_META_RESULT_TEST_001
* @tc.desc: CheckAuthMetaResult test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, CHECK_AUTH_META_RESULT_TEST_001, TestSize.Level1)
{
    LaneLinkInfo linkInfo = {};
    RawLinkInfoList rawLinkInfo = {};
    int32_t ret = AddRawLinkInfo(P2P_REQ_ID, LINK_ID_ZERO, &linkInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CheckAuthMetaResult(NEW_P2P_REQ_ID, &rawLinkInfo);
    EXPECT_EQ(ret, RAW_LINK_CHECK_INVALID);
    ret = DelRawLinkInfoByReqId(P2P_REQ_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: RECYCLE_P2P_LINK_REQ_BY_LINK_TYPE_TEST_001
* @tc.desc: RecycleP2pLinkedReqByLinkType test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, RECYCLE_P2P_LINK_REQ_BY_LINK_TYPE_TEST_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    char peerNetWorkId[] = "testnetworkid";
    EXPECT_NO_FATAL_FAILURE(RecycleP2pLinkedReqByLinkType(peerNetWorkId, LANE_HML));
    uint32_t p2pRequestId = 0;
    int32_t reason = SOFTBUS_LANE_NOT_FOUND;
    EXPECT_NO_FATAL_FAILURE(HandleRawLinkResultByReqId(p2pRequestId, reason));
    int32_t linkId = 0;
    LaneLinkInfo linkInfo = {
        .linkInfo.rawWifiDirect.pid = 0,
    };
    int32_t ret = AddRawLinkInfo(p2pRequestId, linkId, &linkInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(HandleRawLinkResultByReqId(p2pRequestId, reason));
    EXPECT_NO_FATAL_FAILURE(LnnDestroyWifiDirectInfo());
    EXPECT_EQ(g_rawLinkList, nullptr);
}

/*
* @tc.name: OPEN_ACTION_TO_CONN_TEST_001
* @tc.desc: OpenActionToConn test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, OPEN_ACTION_TO_CONN_TEST_001, TestSize.Level1)
{
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    LinkRequest request = {};
    LaneLinkCb callback = {nullptr};
    int32_t ret = OpenActionToConn(nullptr, LANEREQID, &callback);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = OpenActionToConn(&request, LANEREQID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = OpenActionToConn(&request, LANEREQID, &callback);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
* @tc.name: UPDATE_REASON_TEST_001
* @tc.desc: UpdateReason test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, UPDATE_REASON_TEST_001, TestSize.Level1)
{
    int32_t ret = UpdateReason(AUTH_LINK_TYPE_MAX, LANE_CHANNEL_BUTT, SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UpdateReason(AUTH_LINK_TYPE_MAX, LANE_ACTIVE_AUTH_NEGO, SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT);
    ret = UpdateReason(AUTH_LINK_TYPE_MAX, LANE_ACTIVE_BR_NEGO, SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT);
    ret = UpdateReason(AUTH_LINK_TYPE_MAX, LANE_PROXY_AUTH_NEGO, SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT);
    ret = UpdateReason(AUTH_LINK_TYPE_MAX, LANE_NEW_AUTH_NEGO, SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT);
    ret = UpdateReason(AUTH_LINK_TYPE_MAX, LANE_BLE_TRIGGER, SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_CONN_HV2_BLE_TRIGGER_TIMEOUT);
    ret = UpdateReason(AUTH_LINK_TYPE_MAX, LANE_ACTION_TRIGGER, SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_CONN_HV2_ACTION_TRIGGER_TIMEOUT);
    ret = UpdateReason(AUTH_LINK_TYPE_MAX, LANE_SPARKLINK_TRIGGER, SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_CONN_HV2_SPARKLINK_TRIGGER_TIMEOUT);
    ret = UpdateReason(AUTH_LINK_TYPE_MAX, LANE_ACTIVE_AUTH_TRIGGER, SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT);
    ret = UpdateReason(AUTH_LINK_TYPE_WIFI, LANE_ACTIVE_AUTH_TRIGGER, SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_CONN_HV2_AUTH_WIFI_TRIGGER_TIMEOUT);
    ret = UpdateReason(AUTH_LINK_TYPE_BLE, LANE_ACTIVE_AUTH_TRIGGER, SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_CONN_HV2_AUTH_BLE_TRIGGER_TIMEOUT);
    ret = UpdateReason(AUTH_LINK_TYPE_BR, LANE_ACTIVE_AUTH_TRIGGER, SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT);
    EXPECT_EQ(ret, SOFTBUS_CONN_HV2_AUTH_BR_TRIGGER_TIMEOUT);
}

/*
* @tc.name: UPDATE_GUIDE_CHANNEL_ERR_CODE_TEST_001
* @tc.desc: UpdateFirstGuideChannelErrCode test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, UPDATE_GUIDE_CHANNEL_ERR_CODE_TEST_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(UpdateFirstGuideChannelErrCode(P2P_REQUEST_ID,
        SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT));
    LinkRequest linkRequest = {
        .linkType = LANE_HML,
    };
    LaneLinkCb callback = {nullptr};
    int32_t ret = AddP2pLinkReqItem(ASYNC_RESULT_P2P, P2P_REQUEST_ID, LANEREQID, &linkRequest, &callback);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(UpdateFirstGuideChannelErrCode(P2P_REQUEST_ID,
        SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT));
    WdGuideInfo guideInfo = {
        .laneReqId = LANEREQID,
        .request.linkType = LANE_HML,
        .guideIdx = LANE_CHANNEL_BUTT,
        .guideList[0] = LANE_ACTIVE_AUTH_TRIGGER,
    };
    ret = AddGuideInfoItem(&guideInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(UpdateFirstGuideChannelErrCode(P2P_REQUEST_ID,
        SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT));
    EXPECT_NO_FATAL_FAILURE(DelGuideInfoItem(LANEREQID, LANE_HML));
    guideInfo.guideIdx = 0;
    ret = AddGuideInfoItem(&guideInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(UpdateFirstGuideChannelErrCode(P2P_REQUEST_ID,
        SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT));
    WdGuideInfo guideInfoRet = {0};
    ret = GetGuideInfo(LANEREQID, LANE_HML, &guideInfoRet);
    EXPECT_EQ(ret, SOFTBUS_OK);
    int32_t errCode = guideInfoRet.firstGuideErrCode;
    EXPECT_EQ(SOFTBUS_CONN_HV2_WAIT_CONNECT_RESPONSE_TIMEOUT, errCode);
    EXPECT_NO_FATAL_FAILURE(DelGuideInfoItem(LANEREQID, LANE_HML));
    ret = DelP2pLinkReqByReqId(ASYNC_RESULT_P2P, P2P_REQUEST_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: GET_FIRST_GUIDE_TYPE_AND_ERR_CODE_TEST_001
* @tc.desc: GetFirstGuideTypeAndErrCode test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, GET_FIRST_GUIDE_TYPE_AND_ERR_CODE_TEST_001, TestSize.Level1)
{
    WdGuideType guideType = LANE_CHANNEL_BUTT;
    int32_t guideErrCode = SOFTBUS_INVALID_PARAM;
    int32_t ret = GetFirstGuideTypeAndErrCode(LANEREQID, LANE_HML, &guideType, &guideErrCode);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
    WdGuideInfo guideInfo = {
        .laneReqId = LANEREQID,
        .request.linkType = LANE_HML,
        .guideIdx = 0,
        .guideList[0] = LANE_BLE_TRIGGER,
        .firstGuideErrCode = SOFTBUS_OK,
    };
    ret = AddGuideInfoItem(&guideInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetFirstGuideTypeAndErrCode(LANEREQID, LANE_HML, &guideType, &guideErrCode);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(guideErrCode, SOFTBUS_INVALID_PARAM);
    EXPECT_NO_FATAL_FAILURE(DelGuideInfoItem(LANEREQID, LANE_HML));
    guideInfo.firstGuideErrCode = SOFTBUS_CONN_HV2_BLE_TRIGGER_TIMEOUT;
    ret = AddGuideInfoItem(&guideInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetFirstGuideTypeAndErrCode(LANEREQID, LANE_HML, &guideType, &guideErrCode);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(guideType, LANE_BLE_TRIGGER);
    EXPECT_EQ(guideErrCode, SOFTBUS_CONN_HV2_BLE_TRIGGER_TIMEOUT);
    EXPECT_NO_FATAL_FAILURE(DelGuideInfoItem(LANEREQID, LANE_HML));
}

/*
* @tc.name: ADD_AUTH_SESSION_FLAG_TEST_001
* @tc.desc: AddAuthSessionFlag test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, ADD_AUTH_SESSION_FLAG_TEST_001, TestSize.Level1)
{
    int32_t ret = AddAuthSessionFlag(nullptr, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: GET_PREFER_AUTH_CONN_INFO_TEST_001
* @tc.desc: GetPreferAuthConnInfo test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, GET_PREFER_AUTH_CONN_INFO_TEST_001, TestSize.Level1)
{
    AuthConnInfo connInfo = {};
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = GetPreferAuthConnInfo(NODE_NETWORK_ID, &connInfo, true);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
    EXPECT_CALL(linkMock, AuthGetHmlConnInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetPreferAuthConnInfo(NODE_NETWORK_ID, &connInfo, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: ON_WIFI_DIRECT_DISCONNECT_TEST_001
* @tc.desc: OnWifiDirectDisconnect success and fail test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, ON_WIFI_DIRECT_DISCONNECT_TEST_001, TestSize.Level1)
{
    uint32_t requestId = 1;
    EXPECT_NO_FATAL_FAILURE(OnWifiDirectDisconnectSuccess(requestId));
    EXPECT_NO_FATAL_FAILURE(OnWifiDirectDisconnectFailure(requestId, SOFTBUS_INVALID_PARAM));
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    P2pLinkReqList reqInfo = {};
    int32_t ret = AddNewP2pLinkedInfo(&reqInfo, LINK_ID_ONE, LANE_HML);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(OnWifiDirectDisconnectSuccess(requestId));
    EXPECT_NO_FATAL_FAILURE(DelP2pLinkedByLinkId(LINK_ID_ONE));
}

/*
* @tc.name: DISCONNECT_P2P_WITHOUT_AUTH_CONN_TEST_001
* @tc.desc: DisconnectP2pWithoutAuthConn test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, DISCONNECT_P2P_WITHOUT_AUTH_CONN_TEST_001, TestSize.Level1)
{
    uint32_t pid = 1;
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillOnce(Return(&g_manager));
    int32_t ret = DisconnectP2pWithoutAuthConn(pid, LINK_ID_ONE);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
    P2pLinkReqList reqInfo = {};
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    ret = AddNewP2pLinkedInfo(&reqInfo, LINK_ID_ONE, LANE_HML);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager1));
    ret = DisconnectP2pWithoutAuthConn(pid, LINK_ID_ONE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    EXPECT_NO_FATAL_FAILURE(DelP2pLinkedByLinkId(LINK_ID_ONE));
    ret = DisconnectP2pForLinkNotifyFail(pid, LINK_ID_ONE);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: GET_P2P_LINK_DOWN_PARAM_TEST_001
* @tc.desc: GetP2pLinkDownParam test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, GET_P2P_LINK_DOWN_PARAM_TEST_001, TestSize.Level1)
{
    WifiDirectDisconnectInfo wifiDirectInfo = {0};
    AuthHandle authHandle = {0};
    P2pLinkReqList reqInfo = {};
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = AddNewP2pLinkedInfo(&reqInfo, LINK_ID_ONE, LANE_HML);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddNewP2pLinkedInfo(&reqInfo, LINK_ID_ZERO, LANE_HML);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateP2pLinkedList(LINK_ID_ZERO, AUTH_REQUEST_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetP2pLinkDownParam(AUTH_REQUEST_ID, NEW_P2P_REQ_ID, &wifiDirectInfo, authHandle);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(DelP2pLinkedByAuthReqId(AUTH_REQUEST_ID));
    EXPECT_NO_FATAL_FAILURE(DelP2pLinkedByLinkId(LINK_ID_ONE));
}

/*
* @tc.name: ON_CONN_OPENED_FOR_DISCONNECT_TEST_002
* @tc.desc: OnConnOpenedForDisconnect test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, ON_CONN_OPENED_FOR_DISCONNECT_TEST_002, TestSize.Level1)
{
    uint32_t newAuthRequestId = 0;
    AuthHandle authHandle = {
        .type = AUTH_LINK_TYPE_WIFI,
        .authId = INVAILD_AUTH_ID,
    };
    P2pLinkReqList reqInfo = {};
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillOnce(Return(&g_manager));
    int32_t ret = AddNewP2pLinkedInfo(&reqInfo, LINK_ID_ONE, LANE_HML);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateP2pLinkedList(LINK_ID_ONE, newAuthRequestId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(OnConnOpenedForDisconnect(AUTH_REQUEST_ID, authHandle));
    authHandle.type = AUTH_LINK_TYPE_WIFI - 1;
    EXPECT_NO_FATAL_FAILURE(OnConnOpenedForDisconnect(AUTH_REQUEST_ID, authHandle));
    authHandle.type = AUTH_LINK_TYPE_MAX;
    EXPECT_NO_FATAL_FAILURE(OnConnOpenedForDisconnect(AUTH_REQUEST_ID, authHandle));
    EXPECT_NO_FATAL_FAILURE(DelP2pLinkedByLinkId(LINK_ID_ONE));
}

/*
* @tc.name: GET_FEATURE_CAP_TEST_001
* @tc.desc: GetFeatureCap test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, GET_FEATURE_CAP_TEST_001, TestSize.Level1)
{
    uint64_t local = 0;
    uint64_t remote = 0;
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = GetFeatureCap(NODE_NETWORK_ID, &local, &remote);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
}

/*
* @tc.name: GET_P2P_LINK_REQ_PARAM_BY_CHANNEL_REQ_ID_TEST_001
* @tc.desc: GetP2pLinkReqParamByChannelRequetId test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, GET_P2P_LINK_REQ_PARAM_BY_CHANNEL_REQ_ID_TEST_001, TestSize.Level1)
{
    LinkRequest request = {};
    LaneLinkCb callback = {0};
    uint32_t requestId = 0;
    int32_t ret = AddP2pLinkReqItem(ASYNC_RESULT_CHANNEL, requestId, LANE_REQUEST_ID, &request, &callback);
    EXPECT_EQ(ret, SOFTBUS_OK);
    WifiDirectConnectInfo connectInfo = {};
    int32_t channelRequestId = 1;
    int32_t channelId = 1;
    ret = GetP2pLinkReqParamByChannelRequetId(channelRequestId, channelId, NEW_P2P_REQ_ID, &connectInfo);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
    channelRequestId = 0;
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetP2pLinkReqParamByChannelRequetId(channelRequestId, channelId, NEW_P2P_REQ_ID, &connectInfo);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
    ret = GetP2pLinkReqParamByChannelRequetId(channelRequestId, channelId, NEW_P2P_REQ_ID, &connectInfo);
    EXPECT_EQ(ret, SOFTBUS_LANE_BUILD_LINK_TIMEOUT);
    ret = DelP2pLinkReqByReqId(ASYNC_RESULT_CHANNEL, requestId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: GET_P2P_LINK_REQ_PARAM_BY_AUTH_HANDLE_TEST_001
* @tc.desc: GetP2pLinkReqParamByAuthHandle test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, GET_P2P_LINK_REQ_PARAM_BY_AUTH_HANDLE_TEST_001, TestSize.Level1)
{
    LinkRequest request = {};
    LaneLinkCb callback = {0};
    uint32_t requestId = 1;
    int32_t ret = AddP2pLinkReqItem(ASYNC_RESULT_AUTH, requestId, LANE_REQUEST_ID, &request, &callback);
    EXPECT_EQ(ret, SOFTBUS_OK);
    AuthHandle authHandle = {0};
    WifiDirectConnectInfo wifiDirectInfo = {};
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo)
        .WillOnce(Return(SOFTBUS_INVALID_PARAM))
        .WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetP2pLinkReqParamByAuthHandle(AUTH_REQUEST_ID, NEW_P2P_REQ_ID, &wifiDirectInfo, authHandle);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
    ret = GetP2pLinkReqParamByAuthHandle(AUTH_REQUEST_ID, NEW_P2P_REQ_ID, &wifiDirectInfo, authHandle);
    EXPECT_EQ(ret, SOFTBUS_LANE_BUILD_LINK_TIMEOUT);
    ret = DelP2pLinkReqByReqId(ASYNC_RESULT_AUTH, requestId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: DEL_P2P_LINK_REQ_BY_REQ_ID_TEST_001
* @tc.desc: DelP2pLinkReqByReqId test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, DEL_P2P_LINK_REQ_BY_REQ_ID_TEST_001, TestSize.Level1)
{
    uint32_t requestId = 0;
    WdGuideType guideType = LANE_CHANNEL_BUTT;
    int32_t ret = DelP2pLinkReqByReqId(ASYNC_RESULT_AUTH, requestId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetCurrentGuideType(requestId, LANE_HML, &guideType);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
}

/*
* @tc.name: NOTIFY_LINK_SUCC_TEST_001
* @tc.desc: NotifyLinkSucc test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, NOTIFY_LINK_SUCC_TEST_001, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    uint32_t requestId = 0;
    LaneLinkInfo linkInfo = {
        .type = LANE_P2P,
    };
    EXPECT_NO_FATAL_FAILURE(NotifyLinkSucc(ASYNC_RESULT_CHANNEL, requestId, &linkInfo, LINK_ID_ZERO));
    LinkRequest request = {};
    LaneLinkCb callback = {0};
    int32_t ret = AddP2pLinkReqItem(ASYNC_RESULT_AUTH, requestId, LANE_REQUEST_ID, &request, &callback);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(NotifyLinkSucc(ASYNC_RESULT_AUTH, requestId, &linkInfo, LINK_ID_ZERO));
    ret = AddRawLinkInfo(requestId, LINK_ID_ZERO, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = DelP2pLinkReqByReqId(ASYNC_RESULT_AUTH, requestId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: CREATE_WD_LINK_INFO_TEST_001
* @tc.desc: CreateWDLinkInfo test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, CREATE_WD_LINK_INFO_TEST_001, TestSize.Level1)
{
    const struct WifiDirectLink link = {};
    LaneLinkInfo linkInfo = {};
    int32_t ret = CreateWDLinkInfo(P2P_REQ_ID, &link, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CreateWDLinkInfo(P2P_REQ_ID, nullptr, &linkInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, AuthCheckMetaExist).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    char peerIp[IP_LEN] = "127.1.1.1";
    bool result = IsMetaAuthExist(peerIp);
    EXPECT_FALSE(result);
}

/*
* @tc.name: NOTIFY_RAW_LINK_SUCC_TEST_001
* @tc.desc: NotifyRawLinkSucc test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, NOTIFY_RAW_LINK_SUCC_TEST_001, TestSize.Level1)
{
    const struct WifiDirectLink link = {};
    LaneLinkInfo linkInfo = {};
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, AuthCheckMetaExist)
        .WillOnce(DoAll(SetArgPointee<1>(true), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = NotifyRawLinkSucc(P2P_REQ_ID, &link, &linkInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = NotifyRawLinkSucc(P2P_REQ_ID, &link, nullptr);
    EXPECT_EQ(ret, SOFTBUS_LANE_LIST_ERR);
}

/*
* @tc.name: TRY_DEL_PRELINK_BY_CONN_REQ_ID_TEST_001
* @tc.desc: TryDelPreLinkByConnReqId test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, TRY_DEL_PRELINK_BY_CONN_REQ_ID_TEST_001, TestSize.Level1)
{
    NiceMock<LaneLinkP2pDepsInterfaceMock> linkP2pMock;
    LnnEnhanceFuncList funcList = { nullptr };
    funcList.haveConcurrencyPreLinkReqIdByReuseConnReqId = HaveConcurrencyPreLinkReqIdByReuseConnReqIdFail;
    EXPECT_CALL(linkP2pMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&funcList));
    uint32_t connReqId = 0;
    EXPECT_NO_FATAL_FAILURE(TryDelPreLinkByConnReqId(connReqId));
    funcList.haveConcurrencyPreLinkReqIdByReuseConnReqId = HaveConcurrencyPreLinkReqIdByReuseConnReqIdOk;
    funcList.getConcurrencyLaneReqIdByConnReqId = GetConcurrencyLaneReqIdByConnReqIdFail;
    EXPECT_NO_FATAL_FAILURE(TryDelPreLinkByConnReqId(connReqId));
    funcList.getConcurrencyLaneReqIdByConnReqId = GetConcurrencyLaneReqIdByConnReqIdOk;
    EXPECT_NO_FATAL_FAILURE(TryDelPreLinkByConnReqId(connReqId));
}

/*
* @tc.name: NOTIFY_RAW_LINK_CONNECT_SUCC_TEST_001
* @tc.desc: NotifyRawLinkConnectSuccess test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, NOTIFY_RAW_LINK_CONNECT_SUCC_TEST_001, TestSize.Level1)
{
    const struct WifiDirectLink link = {
        .isReuse = true,
    };
    LaneLinkInfo linkInfo = {};
    NiceMock<LaneLinkP2pDepsInterfaceMock> linkP2pMock;
    NiceMock<LaneDepsInterfaceMock> linkMock;
    LnnEnhanceFuncList funcList = { nullptr };
    funcList.haveConcurrencyPreLinkReqIdByReuseConnReqId = HaveConcurrencyPreLinkReqIdByReuseConnReqIdOk;
    funcList.getConcurrencyLaneReqIdByConnReqId = GetConcurrencyLaneReqIdByConnReqIdFail;
    EXPECT_CALL(linkP2pMock, LnnEnhanceFuncListGet).WillRepeatedly(Return(&funcList));
    EXPECT_NO_FATAL_FAILURE(NotifyRawLinkConnectSuccess(P2P_REQ_ID, &link, &linkInfo));
    funcList.haveConcurrencyPreLinkReqIdByReuseConnReqId = HaveConcurrencyPreLinkReqIdByReuseConnReqIdFail;
    EXPECT_CALL(linkMock, AuthCheckMetaExist).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_NO_FATAL_FAILURE(NotifyRawLinkConnectSuccess(P2P_REQ_ID, &link, nullptr));
    EXPECT_NO_FATAL_FAILURE(OnWifiDirectConnectSuccess(P2P_REQ_ID, nullptr));
}

/*
* @tc.name: HANDLE_WIFI_DIRECT_CONFLICT_TEST_001
* @tc.desc: HandleWifiDirectConflict test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, HANDLE_WIFI_DIRECT_CONFLICT_TEST_001, TestSize.Level1)
{
    int32_t ret = HandleWifiDirectConflict(P2P_REQ_ID, CONFLICT_THREE_VAP);
    EXPECT_EQ(ret, SOFTBUS_LANE_NOT_FOUND);
    LinkRequest request = {
        .isVirtualLink = true,
    };
    LaneLinkCb callback = {0};
    uint32_t requestId = 0;
    ret = AddP2pLinkReqItem(ASYNC_RESULT_P2P, requestId, LANE_REQUEST_ID, &request, &callback);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = HandleWifiDirectConflict(P2P_REQ_ID, CONFLICT_THREE_VAP);
    EXPECT_EQ(ret, SOFTBUS_LANE_CHECK_CONFLICT_FAIL);
    ret = DelP2pLinkReqByReqId(ASYNC_RESULT_P2P, requestId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = PostGuideChannelSelectMessage(LANE_REQUEST_ID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
}