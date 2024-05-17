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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>
#include <thread>

#include "lnn_feature_capability.h"
#include "lnn_lane_common.h"
#include "lnn_lane_deps_mock.h"
#include "lnn_lane_link_deps_mock.h"
#include "lnn_lane_link_p2p.h"
#include "lnn_select_rule.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char NODE_NETWORK_ID[] = "123456789";
constexpr char BRMAC[] = "testBrMac";
constexpr char ERRORBRMAC[] = "\0testBrMac";
constexpr int32_t SYNCFAIL = 0;
constexpr int32_t SYNCSUCC = 1;
constexpr int32_t ASYNCFAIL = 2;
constexpr int32_t ASYNCSUCC = 3;

int32_t g_laneLinkResult = SOFTBUS_INVALID_PARAM;

class LNNLaneLinkTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneLinkTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneLinkTest start";
    LnnInitLaneLooper();
}

void LNNLaneLinkTest::TearDownTestCase()
{
    LnnDeinitLaneLooper();
    GTEST_LOG_(INFO) << "LNNLaneLinkTest end";
}

void LNNLaneLinkTest::SetUp()
{
}

void LNNLaneLinkTest::TearDown()
{
}

static void OnLaneLinkSuccess(uint32_t reqId, LaneLinkType linkType, const LaneLinkInfo *linkInfo)
{
    (void)reqId;
    (void)linkType;
    (void)linkInfo;
    g_laneLinkResult = SOFTBUS_OK;
    return;
}

static void OnLaneLinkFail(uint32_t reqId, int32_t reason, LaneLinkType linkType)
{
    (void)reqId;
    (void)reason;
    (void)linkType;
    g_laneLinkResult = SOFTBUS_ERR;
    return;
}

static bool IsNegotiateChannelNeeded(const char *remoteNetworkId, enum WifiDirectLinkType linkType)
{
    return false;
}

static uint32_t GetRequestId(void)
{
    return 1;
}

static int32_t ConnectDevice(struct WifiDirectConnectInfo *info, struct WifiDirectConnectCallback *callback)
{
    if (info->pid == SYNCFAIL) {
        return SOFTBUS_ERR;
    }
    if (info->pid == SYNCSUCC) {
        return SOFTBUS_OK;
    }
    if (info->pid == ASYNCFAIL) {
        callback->onConnectFailure(info->requestId, ERROR_WIFI_DIRECT_WAIT_REUSE_RESPONSE_TIMEOUT);
        return SOFTBUS_OK;
    }
    struct WifiDirectLink link = {
        .linkId = 1,
        .linkType = WIFI_DIRECT_LINK_TYPE_P2P,
    };
    callback->onConnectSuccess(info->requestId, &link);
    return SOFTBUS_OK;
}

static int32_t DisconnectDevice(struct WifiDirectDisconnectInfo *info, struct WifiDirectDisconnectCallback *callback)
{
    return SOFTBUS_OK;
}

static bool SupportHmlTwo(void)
{
    return true;
}

static struct WifiDirectManager g_manager = {
    .isNegotiateChannelNeeded= IsNegotiateChannelNeeded,
    .getRequestId = GetRequestId,
    .connectDevice = ConnectDevice,
    .disconnectDevice = DisconnectDevice,
    .supportHmlTwo = SupportHmlTwo,
};

/*
* @tc.name: GET_WLAN_LINKED_FREQUENCY_TEST_001
* @tc.desc: LnnQueryLaneResource test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GET_WLAN_LINKED_FREQUENCY_TEST_001, TestSize.Level1)
{
    int32_t ret = GetWlanLinkedFrequency();
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}

/*
* @tc.name: GET_WLAN_LINKED_FREQUENCY_TEST_002
* @tc.desc: LnnQueryLaneResource test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GET_WLAN_LINKED_FREQUENCY_TEST_002, TestSize.Level1)
{
    using TestLinkType = enum {
        TEST_BR = -1,
    };
    TestLinkType testLink = TEST_BR;
    LaneLinkType linkType = (LaneLinkType)testLink;
    LinkAttribute *ret = GetLinkAttrByLinkType(linkType);
    EXPECT_TRUE(ret == nullptr);
    linkType = LANE_LINK_TYPE_BUTT;
    ret = GetLinkAttrByLinkType(linkType);
    EXPECT_TRUE(ret == nullptr);
    linkType = LANE_P2P;
    ret = GetLinkAttrByLinkType(linkType);
    EXPECT_TRUE(ret != nullptr);
}

/*
* @tc.name: LnnConnectP2p_001
* @tc.desc: test LnnConnectP2p, request == NULL && callback == NULL
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LnnConnectP2p_001, TestSize.Level1)
{
    LinkRequest request;
    LaneLinkCb cb;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    (void)memset_s(&cb, sizeof(LaneLinkCb), 0, sizeof(LaneLinkCb));
    uint32_t laneReqId = 10;

    int32_t ret = LnnConnectP2p(nullptr, laneReqId, &cb);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = LnnConnectP2p(&request, laneReqId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
* @tc.name: LnnConnectP2p_002
* @tc.desc: test LnnConnectP2p, isMetaAuth == true && OpenAuthToConnP2p call GetPreferAuth fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LnnConnectP2p_002, TestSize.Level1)
{
    LinkRequest request;
    LaneLinkCb cb;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    (void)memset_s(&cb, sizeof(LaneLinkCb), 0, sizeof(LaneLinkCb));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_LINK_TYPE_BUTT;
    uint32_t laneReqId = 10;
    int32_t value = 2;

    LaneDepsInterfaceMock linkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_NOT_FIND));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    EXPECT_EQ(SOFTBUS_LANE_GET_LEDGER_INFO_ERR, ret);
    LnnDestroyP2p();
}

/*
* @tc.name: LnnConnectP2p_003
* @tc.desc: test LnnConnectP2p, TryWifiDirectReuse call ConnectWifiDirectWithReuse success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LnnConnectP2p_003, TestSize.Level1)
{
    LinkRequest request;
    LaneLinkCb cb;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    (void)memset_s(&cb, sizeof(LaneLinkCb), 0, sizeof(LaneLinkCb));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, "123");
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_HML;
    request.pid = SYNCSUCC;
    uint32_t laneReqId = 10;
    int32_t value = 3;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: LnnConnectP2p_004
* @tc.desc: test LnnConnectP2p, GetGuideChannelInfo:linkType >= LANE_LINK_TYPE_BUTT
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LnnConnectP2p_004, TestSize.Level1)
{
    LinkRequest request;
    LaneLinkCb cb;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    (void)memset_s(&cb, sizeof(LaneLinkCb), 0, sizeof(LaneLinkCb));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_LINK_TYPE_BUTT;
    uint32_t laneReqId = 10;
    int32_t value = 3;

    LaneDepsInterfaceMock linkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfSync_001
* @tc.desc: test GuideChannelRetryOfSync:
*     LANE_ACTIVE_AUTH_NEGO(fail)->LANE_ACTIVE_BR_NEGO(fail)->LANE_PROXY_AUTH_NEGO(fail)->LANE_NEW_AUTH_NEGO(fail)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetryOfSync_001, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_P2P;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<2>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn).WillOnce(Return(SOFTBUS_ERR)).WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel).WillRepeatedly(Return(SOFTBUS_ERR));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfSync_002
* @tc.desc: test GuideChannelRetryOfSync:LANE_ACTIVE_BR_NEGO(fail)->LANE_PROXY_AUTH_NEGO(fail)->LANE_NEW_AUTH_NEGO(pass)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetryOfSync_002, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_HML;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(DoAll(SetArrayArgument<2>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn).WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel).WillRepeatedly(Return(SOFTBUS_ERR));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfSync_003
* @tc.desc: test GuideChannelRetryOfSync:LANE_ACTIVE_BR_NEGO(fail)->LANE_PROXY_AUTH_NEGO(pass)->LANE_NEW_AUTH_NEGO
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetryOfSync_003, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_HML;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(DoAll(SetArrayArgument<2>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel).WillRepeatedly(Return(SOFTBUS_OK));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfSync_004
* @tc.desc: test GuideChannelRetryOfSync:LANE_NEW_AUTH_NEGO(fail)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetryOfSync_004, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_HML;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 0;
    uint64_t remote = 0;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn).WillRepeatedly(Return(SOFTBUS_ERR));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfSync_005
* @tc.desc: test GuideChannelRetryOfSync:LANE_NEW_AUTH_NEGO(pass)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetryOfSync_005, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_HML;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 0;
    uint64_t remote = 0;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn).WillRepeatedly(Return(SOFTBUS_OK));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfSync_006
* @tc.desc: test GuideChannelRetryOfSync:
*     LANE_ACTIVE_AUTH_TRIGGER(fail)->LANE_BLE_TRIGGER(fail)->LANE_ACTIVE_BR_TRIGGER(fail)->LANE_NEW_AUTH_TRIGGER(fail)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetryOfSync_006, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_HML;
    request.pid = SYNCFAIL;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint64_t remote = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<2>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillOnce(Return(false)).WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfSync_007
* @tc.desc: test GuideChannelRetryOfSync:
*     LANE_ACTIVE_AUTH_TRIGGER(fail)->LANE_BLE_TRIGGER(fail)->LANE_ACTIVE_BR_TRIGGER(pass)->LANE_NEW_AUTH_TRIGGER
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetryOfSync_007, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_HML;
    request.pid = SYNCFAIL;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint64_t remote = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<2>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn).WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfSync_008
* @tc.desc: test GuideChannelRetryOfSync:
*     LANE_BLE_TRIGGER(fail)->LANE_ACTIVE_BR_TRIGGER(fail)->LANE_NEW_AUTH_TRIGGER(pass)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetryOfSync_008, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_HML;
    request.pid = SYNCFAIL;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint64_t remote = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<2>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillRepeatedly(Return(false));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn).WillOnce(Return(SOFTBUS_ERR)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfSync_009
* @tc.desc: test GuideChannelRetryOfSync:LANE_ACTIVE_AUTH_TRIGGER(fail)->LANE_BLE_TRIGGER(pass)->LANE_NEW_AUTH_TRIGGER
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetryOfSync_009, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_HML;
    request.pid = SYNCSUCC;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint64_t remote = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfSync_010
* @tc.desc: test GuideChannelRetryOfSync:LANE_BLE_TRIGGER(pass)->LANE_NEW_AUTH_TRIGGER
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetryOfSync_010, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_HML;
    request.pid = SYNCSUCC;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint64_t remote = 1 << BIT_BLE_TRIGGER_CONNECTION;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(DoAll(SetArrayArgument<2>(ERRORBRMAC, ERRORBRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfAsync_001
* @tc.desc: test GuideChannelRetryOfAsync:
*     LANE_ACTIVE_AUTH_NEGO(fail)->LANE_ACTIVE_BR_NEGO(fail)->LANE_PROXY_AUTH_NEGO(fail)->LANE_NEW_AUTH_NEGO(fail)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetryOfAsync_001, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_P2P;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<2>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillRepeatedly(linkMock.ActionOfConnOpenFailed);
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel(requestId, _, _, NotNull()))
        .WillRepeatedly(laneLinkMock.ActionOfChannelOpenFailed);

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(SOFTBUS_ERR, g_laneLinkResult);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfAsync_002
* @tc.desc: test GuideChannelRetryOfAsync:
*     LANE_ACTIVE_BR_NEGO(fail)->LANE_PROXY_AUTH_NEGO(fail)->LANE_NEW_AUTH_NEGO(pass)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetryOfAsync_002, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_HML;
    request.pid = ASYNCSUCC;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(DoAll(SetArrayArgument<2>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillOnce(linkMock.ActionOfConnOpenFailed)
        .WillOnce(linkMock.ActionOfConnOpened).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel(requestId, _, _, NotNull()))
        .WillRepeatedly(laneLinkMock.ActionOfChannelOpenFailed);
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());
    EXPECT_CALL(linkMock, AuthGetP2pConnInfo).WillRepeatedly(Return(SOFTBUS_OK));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(SOFTBUS_OK, g_laneLinkResult);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfAsync_003
* @tc.desc: test GuideChannelRetryOfAsync:LANE_ACTIVE_BR_NEGO(fail)->LANE_PROXY_AUTH_NEGO(pass)->LANE_NEW_AUTH_NEGO
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetryOfAsync_003, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_HML;
    request.pid = ASYNCSUCC;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(DoAll(SetArrayArgument<2>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillOnce(Return(SOFTBUS_OK)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillRepeatedly(linkMock.ActionOfConnOpenFailed);
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel(requestId, _, _, NotNull()))
        .WillRepeatedly(laneLinkMock.ActionOfChannelOpened);
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineCloseChannelDelay).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGetP2pConnInfo).WillRepeatedly(Return(SOFTBUS_ERR));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(SOFTBUS_OK, g_laneLinkResult);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfAsync_004
* @tc.desc: test GuideChannelRetryOfAsync:LANE_PROXY_AUTH_NEGO(fail)->LANE_NEW_AUTH_NEGO(pass)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetryOfAsync_004, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_HML;
    request.pid = ASYNCSUCC;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillOnce(linkMock.ActionOfConnOpened)
        .WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel(requestId, _, _, NotNull()))
        .WillRepeatedly(laneLinkMock.ActionOfChannelOpenFailed);
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());
    EXPECT_CALL(linkMock, AuthGetP2pConnInfo).WillRepeatedly(Return(SOFTBUS_OK));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(SOFTBUS_OK, g_laneLinkResult);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfAsync_005
* @tc.desc: test GuideChannelRetryOfAsync:
*     LANE_ACTIVE_AUTH_TRIGGER(fail)->LANE_BLE_TRIGGER(fail)->LANE_ACTIVE_BR_TRIGGER(fail)->LANE_NEW_AUTH_TRIGGER(fail)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetryOfAsync_005, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_HML;
    request.pid = ASYNCFAIL;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint64_t remote = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<2>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillRepeatedly(linkMock.ActionOfConnOpenFailed);
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(SOFTBUS_ERR, g_laneLinkResult);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfAsync_006
* @tc.desc: test GuideChannelRetryOfAsync:
*     LANE_BLE_TRIGGER(fail)->LANE_ACTIVE_BR_TRIGGER(fail)->LANE_NEW_AUTH_TRIGGER(opened-fail)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetryOfAsync_006, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_HML;
    request.pid = ASYNCFAIL;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint64_t remote = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<2>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillRepeatedly(Return(false));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillOnce(linkMock.ActionOfConnOpenFailed)
        .WillRepeatedly(linkMock.ActionOfConnOpened);
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(SOFTBUS_ERR, g_laneLinkResult);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfAsync_007
* @tc.desc: test GuideChannelRetryOfAsync:
*     LANE_ACTIVE_AUTH_TRIGGER(fail)->LANE_BLE_TRIGGER(fail)->LANE_NEW_AUTH_TRIGGER(opened-fail)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetryOfAsync_007, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_HML;
    request.pid = ASYNCFAIL;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint64_t remote = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<2>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(false));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillOnce(linkMock.ActionOfConnOpenFailed)
        .WillRepeatedly(linkMock.ActionOfConnOpened);
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(SOFTBUS_ERR, g_laneLinkResult);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfAsync_008
* @tc.desc: test GuideChannelRetryOfAsync:LANE_ACTIVE_AUTH_TRIGGER(fail)->LANE_BLE_TRIGGER(pass)->LANE_NEW_AUTH_TRIGGER
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetryOfAsync_008, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_HML;
    request.pid = ASYNCSUCC;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint64_t remote = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillOnce(linkMock.ActionOfConnOpenFailed)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(linkMock, AuthGetP2pConnInfo).WillRepeatedly(Return(SOFTBUS_OK));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(SOFTBUS_OK, g_laneLinkResult);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetry_001
* @tc.desc: test GuideChannelRetry:fist async
*     LANE_ACTIVE_AUTH_NEGO(fail)->LANE_ACTIVE_BR_NEGO(fail)->LANE_PROXY_AUTH_NEGO(fail)->LANE_NEW_AUTH_NEGO(fail)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetry_001, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_P2P;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<2>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillOnce(linkMock.ActionOfConnOpenFailed)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel(requestId, _, _, NotNull()))
        .WillRepeatedly(laneLinkMock.ActionOfChannelOpenFailed);

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(SOFTBUS_ERR, g_laneLinkResult);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetry_002
* @tc.desc: test GuideChannelRetry:fist sync
*     LANE_ACTIVE_AUTH_NEGO(fail)->LANE_ACTIVE_BR_NEGO(fail)->LANE_PROXY_AUTH_NEGO(fail)->LANE_NEW_AUTH_NEGO(fail)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetry_002, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_P2P;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<2>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillOnce(Return(SOFTBUS_ERR))
        .WillOnce(linkMock.ActionOfConnOpenFailed)
        .WillRepeatedly(linkMock.ActionOfConnOpenFailed);
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel).WillRepeatedly(Return(SOFTBUS_ERR));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(SOFTBUS_ERR, g_laneLinkResult);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetry_003
* @tc.desc: test GuideChannelRetry:fist async
*     LANE_ACTIVE_AUTH_NEGO(fail)->LANE_ACTIVE_BR_NEGO(fail)->LANE_PROXY_AUTH_NEGO(fail)->LANE_NEW_AUTH_NEGO(pass)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetry_003, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_P2P;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<2>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillOnce(linkMock.ActionOfConnOpenFailed)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel(requestId, _, _, NotNull()))
        .WillRepeatedly(laneLinkMock.ActionOfChannelOpenFailed);

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetry_004
* @tc.desc: test GuideChannelRetry:fist sync
*     LANE_ACTIVE_AUTH_NEGO(fail)->LANE_ACTIVE_BR_NEGO(fail)->LANE_PROXY_AUTH_NEGO(fail)->LANE_NEW_AUTH_NEGO(pass)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetry_004, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_P2P;
    request.pid = ASYNCSUCC;

    const LaneLinkCb cb = {
        .OnLaneLinkSuccess = OnLaneLinkSuccess,
        .OnLaneLinkFail = OnLaneLinkFail,
    };

    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    LaneDepsInterfaceMock linkMock;
    LaneLinkDepsInterfaceMock laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(DoAll(SetArgPointee<2>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<2>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info).WillRepeatedly(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info).WillRepeatedly(DoAll(SetArgPointee<2>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillOnce(Return(SOFTBUS_ERR))
        .WillOnce(linkMock.ActionOfConnOpenFailed).WillOnce(linkMock.ActionOfConnOpened)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());
    EXPECT_CALL(linkMock, AuthGetP2pConnInfo).WillRepeatedly(Return(SOFTBUS_OK));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // delay 200ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    EXPECT_EQ(SOFTBUS_OK, g_laneLinkResult);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}
} // namespace OHOS