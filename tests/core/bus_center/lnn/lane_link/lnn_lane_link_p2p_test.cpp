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
constexpr int32_t ACTION_ADDR = 1;

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

static struct WifiDirectManager g_manager = {
    .isNegotiateChannelNeeded = nullptr,
    .getRequestId = GetRequestId,
    .connectDevice = ConnectDevice,
    .cancelConnectDevice = nullptr,
    .disconnectDevice = DisconnectDevice,
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

    LnnEnhanceFuncList funcList;
    funcList.updateConcurrencyReuseLaneReqIdByUdid = nullptr;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkP2pDepsInterfaceMock> linkP2pMock;
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
    LnnEnhanceFuncList funcList;
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
    LnnEnhanceFuncList funcList;
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

    EXPECT_NO_FATAL_FAILURE(HandleGuideChannelRetry(LANEREQID, LANE_HML, REASON));
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
* @tc.desc: OnConnOpenFailedForDisconnect test
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
    LnnEnhanceFuncList funcList;
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
}