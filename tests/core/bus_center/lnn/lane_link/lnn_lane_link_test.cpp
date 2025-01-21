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
#include "lnn_lane_interface.h"
#include "lnn_lane_link_deps_mock.h"
#include "lnn_lane_link_p2p.h"
#include "lnn_select_rule.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

constexpr char NODE_NETWORK_ID[] = "123456789";
constexpr char BRMAC[] = "testBrMac";
constexpr int32_t SYNCFAIL = 0;
constexpr int32_t SYNCSUCC = 1;
constexpr int32_t ASYNCFAIL = 2;
constexpr int32_t ASYNCSUCC = 3;
constexpr int32_t USEABLE_LANE_ID = 1234567;
constexpr char USEABLE_IP[] = "192.168.1.1";
constexpr uint64_t DEFAULT_LINK_LATENCY = 30000;
constexpr int32_t REQID = 2;
constexpr int32_t LANEREQID = 12;
constexpr int32_t LANEREQID15 = 15;
constexpr int32_t LANEVALUE = 3;

static SoftBusCond g_cond = {0};
static SoftBusMutex g_lock = {0};
static bool g_isRawHmlResuse = true;
int32_t g_laneLinkResult = SOFTBUS_INVALID_PARAM;
static bool g_isNeedCondWait = true;
int32_t g_connFailReason = ERROR_WIFI_DIRECT_WAIT_REUSE_RESPONSE_TIMEOUT;

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
    (void)SoftBusMutexInit(&g_lock, nullptr);
    (void)SoftBusCondInit(&g_cond);
    LnnInitLnnLooper();
}

void LNNLaneLinkTest::TearDownTestCase()
{
    LnnDeinitLnnLooper();
    (void)SoftBusCondDestroy(&g_cond);
    (void)SoftBusMutexDestroy(&g_lock);
    GTEST_LOG_(INFO) << "LNNLaneLinkTest end";
}

void LNNLaneLinkTest::SetUp()
{
}

void LNNLaneLinkTest::TearDown()
{
}

static void CondSignal(void)
{
    if (SoftBusMutexLock(&g_lock) != SOFTBUS_OK) {
        GTEST_LOG_(ERROR) << "mutex lock fail";
        return;
    }
    if (SoftBusCondSignal(&g_cond) != SOFTBUS_OK) {
        GTEST_LOG_(ERROR) << "cond signal fail";
        (void)SoftBusMutexUnlock(&g_lock);
        return;
    }
    g_isNeedCondWait = false;
    (void)SoftBusMutexUnlock(&g_lock);
}

static void CondWait(void)
{
    if (SoftBusMutexLock(&g_lock) != SOFTBUS_OK) {
        GTEST_LOG_(ERROR) << "mutex lock fail";
        return;
    }
    if (!g_isNeedCondWait) {
        GTEST_LOG_(ERROR) << "has cond signal, no need cond wait";
        (void)SoftBusMutexUnlock(&g_lock);
        return;
    }
    if (SoftBusCondWait(&g_cond, &g_lock, nullptr) != SOFTBUS_OK) {
        GTEST_LOG_(ERROR) << "cond wait fail";
        (void)SoftBusMutexUnlock(&g_lock);
        return;
    }
    (void)SoftBusMutexUnlock(&g_lock);
}

static void SetIsNeedCondWait(bool isNeedWait)
{
    if (SoftBusMutexLock(&g_lock) != SOFTBUS_OK) {
        GTEST_LOG_(ERROR) << "mutex lock fail";
        return;
    }
    g_isNeedCondWait = isNeedWait;
    (void)SoftBusMutexUnlock(&g_lock);
}

static void OnLaneLinkSuccess(uint32_t reqId, LaneLinkType linkType, const LaneLinkInfo *linkInfo)
{
    (void)reqId;
    (void)linkType;
    (void)linkInfo;
    g_laneLinkResult = SOFTBUS_OK;
    CondSignal();
    return;
}

static void OnLaneLinkFail(uint32_t reqId, int32_t reason, LaneLinkType linkType)
{
    (void)reqId;
    (void)reason;
    (void)linkType;
    g_laneLinkResult = SOFTBUS_LANE_BUILD_LINK_FAIL;
    CondSignal();
    return;
}

static LaneLinkCb g_linkCb = {
    .onLaneLinkSuccess = OnLaneLinkSuccess,
    .onLaneLinkFail = OnLaneLinkFail,
};

static int32_t GetLocalAndRemoteMacByLocalIp(
    const char *localIp, char *localMac, size_t localMacSize, char *remoteMac, size_t remoteMacSize)
{
    (void)localIp;
    (void)localMac;
    (void)localMacSize;
    (void)remoteMac;
    (void)remoteMacSize;
    return SOFTBUS_OK;
}

static struct WifiDirectManager manager = {
    .getLocalAndRemoteMacByLocalIp = GetLocalAndRemoteMacByLocalIp,
};

static bool IsNegotiateChannelNeeded(const char *remoteNetworkId, enum WifiDirectLinkType linkType)
{
    return false;
}

static bool IsNegotiateChannelNeededTrue(const char *remoteNetworkId, enum WifiDirectLinkType linkType)
{
    return true;
}

static uint32_t GetRequestId(void)
{
    return 1;
}

static uint32_t GetRequestId2(void)
{
    return REQID;
}

static int32_t ConnectDevice(struct WifiDirectConnectInfo *info, struct WifiDirectConnectCallback *callback)
{
    if (info->pid == SYNCFAIL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (info->pid == SYNCSUCC) {
        return SOFTBUS_OK;
    }
    if (info->pid == ASYNCFAIL) {
        callback->onConnectFailure(info->requestId, g_connFailReason);
        return SOFTBUS_OK;
    }
    struct WifiDirectLink link = {
        .linkId = 1,
        .linkType = WIFI_DIRECT_LINK_TYPE_P2P,
    };
    callback->onConnectSuccess(info->requestId, &link);
    return SOFTBUS_OK;
}

static int32_t ConnectDeviceRawHml(struct WifiDirectConnectInfo *info, struct WifiDirectConnectCallback *callback)
{
    if (info->pid == ASYNCFAIL) {
        callback->onConnectFailure(info->requestId, ERROR_WIFI_DIRECT_WAIT_REUSE_RESPONSE_TIMEOUT);
        return SOFTBUS_OK;
    }
    struct WifiDirectLink link = {
        .linkId = 1,
        .linkType = WIFI_DIRECT_LINK_TYPE_HML,
        .isReuse = g_isRawHmlResuse,
    };
    callback->onConnectSuccess(info->requestId, &link);
    return SOFTBUS_OK;
}

static int32_t ConnectDeviceForCancel(struct WifiDirectConnectInfo *info, struct WifiDirectConnectCallback *callback)
{
    GTEST_LOG_(INFO) << "ConnectDeviceForCancel enter";
    (void)info;
    (void)callback;
    return SOFTBUS_OK;
}

static int32_t DisconnectDevice(struct WifiDirectDisconnectInfo *info, struct WifiDirectDisconnectCallback *callback)
{
    (void)info;
    (void)callback;
    return SOFTBUS_OK;
}

static int32_t DisconnectDevice2(struct WifiDirectDisconnectInfo *info, struct WifiDirectDisconnectCallback *callback)
{
    (void)info;
    (void)callback;
    return SOFTBUS_INVALID_PARAM;
}

static int32_t DisconnectDeviceSuccess(struct WifiDirectDisconnectInfo *info,
    struct WifiDirectDisconnectCallback *callback)
{
    GTEST_LOG_(INFO) << "DisconnectDeviceSuccess enter";
    callback->onDisconnectSuccess(info->requestId);
    return SOFTBUS_OK;
}

static int32_t DisconnectDeviceFail(struct WifiDirectDisconnectInfo *info,
    struct WifiDirectDisconnectCallback *callback)
{
    GTEST_LOG_(INFO) << "DisconnectDeviceFail enter";
    callback->onDisconnectFailure(info->requestId, SOFTBUS_LANE_BUILD_LINK_FAIL);
    return SOFTBUS_OK;
}

static int32_t CancelConnectDevice(const struct WifiDirectConnectInfo *info)
{
    GTEST_LOG_(INFO) << "CancelConnectDevice enter";
    (void)info;
    return SOFTBUS_OK;
}

static int32_t CancelConnectDeviceFail(const struct WifiDirectConnectInfo *info)
{
    GTEST_LOG_(INFO) << "CancelConnectDeviceFail enter";
    (void)info;
    return SOFTBUS_LANE_BUILD_LINK_FAIL;
}

static bool SupportHmlTwo(void)
{
    return true;
}

static struct WifiDirectManager g_manager = {
    .isNegotiateChannelNeeded= IsNegotiateChannelNeeded,
    .getRequestId = GetRequestId,
    .connectDevice = ConnectDevice,
    .cancelConnectDevice = CancelConnectDevice,
    .disconnectDevice = DisconnectDevice,
    .supportHmlTwo = SupportHmlTwo,
};

static struct WifiDirectManager g_manager2 = {
    .isNegotiateChannelNeeded= IsNegotiateChannelNeeded,
    .getRequestId = GetRequestId2,
    .connectDevice = ConnectDevice,
    .cancelConnectDevice = CancelConnectDevice,
    .disconnectDevice = DisconnectDevice,
    .supportHmlTwo = SupportHmlTwo,
};

static struct WifiDirectManager g_manager3 = {
    .isNegotiateChannelNeeded= IsNegotiateChannelNeeded,
    .getRequestId = GetRequestId,
    .connectDevice = ConnectDevice,
    .cancelConnectDevice = CancelConnectDevice,
    .disconnectDevice = DisconnectDevice2,
    .supportHmlTwo = SupportHmlTwo,
};

static bool IsNegotiateChannelNeeded2(const char *remoteNetworkId, enum WifiDirectLinkType linkType)
{
    (void)remoteNetworkId;
    (void)linkType;
    return true;
}

static struct WifiDirectManager g_manager5 = {
    .isNegotiateChannelNeeded= IsNegotiateChannelNeeded2,
};

static struct WifiDirectManager g_manager6 = {
    .isNegotiateChannelNeeded= IsNegotiateChannelNeeded,
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
    EXPECT_EQ(ret, SOFTBUS_LANE_SELECT_FAIL);
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

    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
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

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
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

    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));

    ret = LnnConnectP2p(&request, laneReqId, &cb);
    EXPECT_EQ(SOFTBUS_LANE_GUIDE_BUILD_FAIL, ret);
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
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<LANE_MOCK_PARAM3>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn)
        .WillOnce(Return(SOFTBUS_LANE_BUILD_LINK_FAIL)).WillRepeatedly(Return(SOFTBUS_LANE_BUILD_LINK_FAIL));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel).WillRepeatedly(Return(SOFTBUS_LANE_BUILD_LINK_FAIL));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    SetIsNeedCondWait(true);
    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    EXPECT_EQ(SOFTBUS_LANE_BUILD_LINK_FAIL, g_laneLinkResult);
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
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(DoAll(SetArrayArgument<LANE_MOCK_PARAM3>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn)
        .WillOnce(Return(SOFTBUS_LANE_BUILD_LINK_FAIL)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel).WillRepeatedly(Return(SOFTBUS_LANE_BUILD_LINK_FAIL));

    SetIsNeedCondWait(true);
    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    EXPECT_EQ(SOFTBUS_LANE_BUILD_LINK_FAIL, g_laneLinkResult);
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
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(DoAll(SetArrayArgument<LANE_MOCK_PARAM3>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn).WillRepeatedly(Return(SOFTBUS_LANE_BUILD_LINK_FAIL));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel).WillRepeatedly(Return(SOFTBUS_OK));

    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
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
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 0;
    uint64_t remote = 0;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn).WillRepeatedly(Return(SOFTBUS_LANE_BUILD_LINK_FAIL));

    SetIsNeedCondWait(true);
    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    EXPECT_EQ(SOFTBUS_LANE_BUILD_LINK_FAIL, g_laneLinkResult);
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
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 0;
    uint64_t remote = 0;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn).WillRepeatedly(Return(SOFTBUS_OK));

    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfSync_006
* @tc.desc: test GuideChannelRetryOfSync:
*     LANE_ACTIVE_AUTH_TRIGGER(fail)->LANE_BLE_TRIGGER(fail)->LANE_NEW_AUTH_TRIGGER(fail)
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
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint64_t remote = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillOnce(Return(false)).WillOnce(Return(false))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn).WillRepeatedly(Return(SOFTBUS_LANE_BUILD_LINK_FAIL));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    SetIsNeedCondWait(true);
    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    EXPECT_EQ(SOFTBUS_LANE_BUILD_LINK_FAIL, g_laneLinkResult);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfSync_007
* @tc.desc: test GuideChannelRetryOfSync:
*     LANE_ACTIVE_AUTH_TRIGGER(fail)->LANE_BLE_TRIGGER(fail)->LANE_NEW_AUTH_TRIGGER(pass)
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
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint64_t remote = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn)
        .WillOnce(Return(SOFTBUS_LANE_BUILD_LINK_FAIL)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    SetIsNeedCondWait(true);
    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfSync_008
* @tc.desc: test GuideChannelRetryOfSync:LANE_ACTIVE_AUTH_TRIGGER(fail)->LANE_BLE_TRIGGER(pass)->LANE_NEW_AUTH_TRIGGER
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
    request.pid = SYNCSUCC;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint64_t remote = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn).WillRepeatedly(Return(SOFTBUS_LANE_BUILD_LINK_FAIL));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfSync_009
* @tc.desc: test GuideChannelRetryOfSync:LANE_BLE_TRIGGER(pass)->LANE_NEW_AUTH_TRIGGER
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
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint64_t remote = 1 << BIT_BLE_TRIGGER_CONNECTION;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
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
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<LANE_MOCK_PARAM3>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillRepeatedly(linkMock.ActionOfConnOpenFailed);
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel(requestId, _, _, NotNull()))
        .WillRepeatedly(laneLinkMock.ActionOfChannelOpenFailed);
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    SetIsNeedCondWait(true);
    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    EXPECT_EQ(SOFTBUS_LANE_BUILD_LINK_FAIL, g_laneLinkResult);
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
    LinkRequest request = {};
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_HML;
    request.pid = ASYNCSUCC;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    AuthConnInfo connInfo = {.type = AUTH_LINK_TYPE_P2P};
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<LANE_MOCK_PARAM3>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, AuthGetConnInfoByType)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel(requestId, _, _, NotNull()))
        .WillRepeatedly(laneLinkMock.ActionOfChannelOpenFailed);
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillRepeatedly(linkMock.ActionOfConnOpened);
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());
    EXPECT_CALL(linkMock, AuthGetP2pConnInfo).WillRepeatedly(Return(SOFTBUS_OK));

    SetIsNeedCondWait(true);
    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
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
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(DoAll(SetArrayArgument<LANE_MOCK_PARAM3>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillRepeatedly(linkMock.ActionOfConnOpenFailed);
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel(requestId, _, _, NotNull()))
        .WillRepeatedly(laneLinkMock.ActionOfChannelOpened);
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineCloseChannelDelay).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGetP2pConnInfo).WillRepeatedly(Return(SOFTBUS_LANE_BUILD_LINK_FAIL));

    SetIsNeedCondWait(true);
    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
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
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    AuthConnInfo connInfo = {.type = AUTH_LINK_TYPE_P2P};
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGetConnInfoByType)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillOnce(linkMock.ActionOfConnOpened)
        .WillRepeatedly(Return(SOFTBUS_LANE_BUILD_LINK_FAIL));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel(requestId, _, _, NotNull()))
        .WillRepeatedly(laneLinkMock.ActionOfChannelOpenFailed);
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());
    EXPECT_CALL(linkMock, AuthGetP2pConnInfo).WillRepeatedly(Return(SOFTBUS_OK));

    SetIsNeedCondWait(true);
    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    EXPECT_EQ(SOFTBUS_OK, g_laneLinkResult);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfAsync_005
* @tc.desc: test GuideChannelRetryOfAsync:
*     LANE_ACTIVE_AUTH_TRIGGER(fail)->LANE_BLE_TRIGGER(fail)->LANE_NEW_AUTH_TRIGGER(fail)
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
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint64_t remote = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillRepeatedly(linkMock.ActionOfConnOpenFailed);
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    SetIsNeedCondWait(true);
    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    EXPECT_EQ(SOFTBUS_LANE_BUILD_LINK_FAIL, g_laneLinkResult);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfAsync_006
* @tc.desc: test GuideChannelRetryOfAsync:
*     LANE_ACTIVE_AUTH_TRIGGER(fail)->LANE_BLE_TRIGGER(fail)->LANE_NEW_AUTH_TRIGGER(opened-fail)
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
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    AuthConnInfo connInfo = {.type = AUTH_LINK_TYPE_P2P};
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint64_t remote = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillOnce(linkMock.ActionOfConnOpenFailed)
        .WillRepeatedly(linkMock.ActionOfConnOpened);
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());

    SetIsNeedCondWait(true);
    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    EXPECT_EQ(SOFTBUS_LANE_BUILD_LINK_FAIL, g_laneLinkResult);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfAsync_007
* @tc.desc: test GuideChannelRetryOfAsync:LANE_ACTIVE_AUTH_TRIGGER(fail)->LANE_BLE_TRIGGER(pass)->LANE_NEW_AUTH_TRIGGER
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
    request.pid = ASYNCSUCC;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint64_t remote = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillOnce(linkMock.ActionOfConnOpenFailed)
        .WillRepeatedly(Return(SOFTBUS_OK));
    g_manager.isNegotiateChannelNeeded = IsNegotiateChannelNeededTrue;
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(linkMock, AuthGetP2pConnInfo).WillRepeatedly(Return(SOFTBUS_OK));

    SetIsNeedCondWait(true);
    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    EXPECT_EQ(SOFTBUS_OK, g_laneLinkResult);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
    g_manager.isNegotiateChannelNeeded = IsNegotiateChannelNeeded;
}

/*
* @tc.name: GuideChannelRetryOfAsync_008
* @tc.desc: test GuideChannelRetryOfAsync:LANE_ACTIVE_AUTH_TRIGGER(pass) for detect success
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
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint64_t remote = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint32_t localBle = 1 << BIT_BLE;
    uint32_t requestId = 1;
    AuthConnInfo connInfo = {.type = AUTH_LINK_TYPE_WIFI};

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(localBle), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, LaneDetectReliability).WillRepeatedly(laneLinkMock.ActionOfDetectSuccess);
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillOnce(linkMock.ActionOfConnOpened)
        .WillRepeatedly(Return(SOFTBUS_OK));
    g_manager.isNegotiateChannelNeeded = IsNegotiateChannelNeededTrue;
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(linkMock, AuthGetHmlConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGetP2pConnInfo).WillRepeatedly(Return(SOFTBUS_OK));

    SetIsNeedCondWait(true);
    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    EXPECT_EQ(SOFTBUS_OK, g_laneLinkResult);
    g_manager.isNegotiateChannelNeeded = IsNegotiateChannelNeeded;
    LnnDisconnectP2pWithoutLnn(laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelRetryOfAsync_009
* @tc.desc: test GuideChannelRetryOfAsync:LANE_ACTIVE_AUTH_TRIGGER(fail) for detect fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelRetryOfAsync_009, TestSize.Level1)
{
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    int32_t ret = strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID);
    EXPECT_EQ(EOK, ret);
    request.linkType = LANE_HML;
    request.pid = ASYNCSUCC;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint64_t remote = 1 << BIT_BLE_TRIGGER_CONNECTION;
    uint32_t localBle = 1 << BIT_BLE;
    uint32_t requestId = 1;
    AuthConnInfo connInfo = {.type = AUTH_LINK_TYPE_WIFI};

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetLocalNumU32Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(localBle), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, LaneDetectReliability).WillRepeatedly(laneLinkMock.ActionOfDetectFail);
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillOnce(linkMock.ActionOfConnOpened)
        .WillRepeatedly(Return(SOFTBUS_OK));
    g_manager.isNegotiateChannelNeeded = IsNegotiateChannelNeededTrue;
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(linkMock, AuthGetHmlConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGetP2pConnInfo).WillRepeatedly(Return(SOFTBUS_OK));

    SetIsNeedCondWait(true);
    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    EXPECT_EQ(SOFTBUS_OK, g_laneLinkResult);
    g_manager.isNegotiateChannelNeeded = IsNegotiateChannelNeeded;
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
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<LANE_MOCK_PARAM3>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillOnce(linkMock.ActionOfConnOpenFailed)
        .WillOnce(Return(SOFTBUS_LANE_BUILD_LINK_FAIL))
        .WillRepeatedly(Return(SOFTBUS_LANE_BUILD_LINK_FAIL));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel(requestId, _, _, NotNull()))
        .WillRepeatedly(laneLinkMock.ActionOfChannelOpenFailed);
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    SetIsNeedCondWait(true);
    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    EXPECT_EQ(SOFTBUS_LANE_BUILD_LINK_FAIL, g_laneLinkResult);
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
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<LANE_MOCK_PARAM3>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillOnce(Return(SOFTBUS_LANE_BUILD_LINK_FAIL))
        .WillOnce(linkMock.ActionOfConnOpenFailed)
        .WillRepeatedly(linkMock.ActionOfConnOpenFailed);
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel).WillRepeatedly(Return(SOFTBUS_LANE_BUILD_LINK_FAIL));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    SetIsNeedCondWait(true);
    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    EXPECT_EQ(SOFTBUS_LANE_BUILD_LINK_FAIL, g_laneLinkResult);
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
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<LANE_MOCK_PARAM3>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillOnce(linkMock.ActionOfConnOpenFailed)
        .WillOnce(Return(SOFTBUS_LANE_BUILD_LINK_FAIL))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel(requestId, _, _, NotNull()))
        .WillRepeatedly(laneLinkMock.ActionOfChannelOpenFailed);
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    SetIsNeedCondWait(true);
    ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
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
    LinkRequest request = {};
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_P2P;
    request.pid = ASYNCSUCC;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    AuthConnInfo connInfo = {.type = AUTH_LINK_TYPE_P2P};
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<LANE_MOCK_PARAM3>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, AuthGetConnInfoByType)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel).WillRepeatedly(Return(SOFTBUS_LANE_BUILD_LINK_FAIL));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());
    EXPECT_CALL(linkMock, AuthGetP2pConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillOnce(Return(SOFTBUS_LANE_BUILD_LINK_FAIL))
        .WillOnce(Return(SOFTBUS_LANE_BUILD_LINK_FAIL))
        .WillRepeatedly(linkMock.ActionOfConnOpened);

    SetIsNeedCondWait(true);
    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    EXPECT_EQ(SOFTBUS_OK, g_laneLinkResult);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: GuideChannelDetect_001
* @tc.desc: test GuideChannelDetect:fist sync
*     LANE_ACTIVE_AUTH_NEGO(fail)->LANE_ACTIVE_BR_NEGO(fail)->LANE_PROXY_AUTH_NEGO(fail)->LANE_NEW_AUTH_NEGO(pass)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GuideChannelDetect_001, TestSize.Level1)
{
    LinkRequest request = {};
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_P2P;
    request.pid = ASYNCSUCC;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    AuthConnInfo connInfo = {.type = AUTH_LINK_TYPE_WIFI};
    uint32_t laneReqId = 11;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<LANE_MOCK_PARAM3>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, AuthGetConnInfoByType)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillRepeatedly(linkMock.ActionOfConnOpened);
    EXPECT_CALL(laneLinkMock, TransProxyPipelineGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneLinkMock, TransProxyPipelineOpenChannel).WillRepeatedly(Return(SOFTBUS_LANE_BUILD_LINK_FAIL));
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());
    EXPECT_CALL(linkMock, AuthGetP2pConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, LaneDetectReliability).WillOnce(Return(SOFTBUS_LANE_DETECT_FAIL))
        .WillOnce(Return(SOFTBUS_LANE_DETECT_FAIL))
        .WillRepeatedly(laneLinkMock.ActionOfDetectFail);

    SetIsNeedCondWait(true);
    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    EXPECT_EQ(SOFTBUS_LANE_BUILD_LINK_FAIL, g_laneLinkResult);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: LnnCancelWifiDirect_001
* @tc.desc: test cancel wifiDirect request fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LnnCancelWifiDirect_001, TestSize.Level1)
{
    LinkRequest request = {};
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_P2P;
    request.pid = ASYNCSUCC;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    AuthConnInfo connInfo = {.type = AUTH_LINK_TYPE_P2P};
    uint32_t laneReqId = 12;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<LANE_MOCK_PARAM3>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(false));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR)));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillRepeatedly(linkMock.ActionOfConnOpened);
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());
    EXPECT_CALL(laneLinkMock, TransProxyPipelineCloseChannelDelay).WillRepeatedly(Return(SOFTBUS_OK));
    g_laneLinkResult = SOFTBUS_INVALID_PARAM;
    g_manager.connectDevice = ConnectDeviceForCancel;
    g_manager.cancelConnectDevice = nullptr;
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    LnnCancelWifiDirect(laneReqId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, g_laneLinkResult);
    g_manager.cancelConnectDevice = CancelConnectDeviceFail;
    LnnCancelWifiDirect(laneReqId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, g_laneLinkResult);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
    g_manager.connectDevice = ConnectDevice;
}

/*
* @tc.name: LnnCancelWifiDirect_002
* @tc.desc: test cancel wifiDirect request for success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LnnCancelWifiDirect_002, TestSize.Level1)
{
    LinkRequest request = {};
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_P2P;
    request.pid = ASYNCSUCC;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    AuthConnInfo connInfo = {.type = AUTH_LINK_TYPE_P2P};
    uint32_t laneReqId = 12;
    int32_t value = 3;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<LANE_MOCK_PARAM3>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthDeviceCheckConnInfo).WillOnce(Return(false)).WillRepeatedly(Return(true));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(false));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR)));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillRepeatedly(linkMock.ActionOfConnOpened);
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());
    EXPECT_CALL(laneLinkMock, TransProxyPipelineCloseChannelDelay).WillRepeatedly(Return(SOFTBUS_OK));
    g_laneLinkResult = SOFTBUS_INVALID_PARAM;
    g_manager.connectDevice = ConnectDeviceForCancel;
    g_manager.cancelConnectDevice = CancelConnectDevice;
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    LnnCancelWifiDirect(laneReqId);
    EXPECT_EQ(SOFTBUS_LANE_BUILD_LINK_FAIL, g_laneLinkResult);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
    g_manager.connectDevice = ConnectDevice;
}

static void SetCommonFunction(uint32_t laneReqId, LaneLinkType linkType, struct WifiDirectManager manager)
{
    LinkRequest request = {};
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = linkType;
    request.pid = ASYNCSUCC;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    AuthConnInfo connInfo = {.type = AUTH_LINK_TYPE_P2P};
    int32_t value = LANEVALUE;
    uint64_t local = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint64_t remote = 1 << BIT_SUPPORT_NEGO_P2P_BY_CHANNEL_CAPABILITY;
    uint32_t requestId = 1;

    NiceMock<LaneDepsInterfaceMock> linkMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_OK))
        .WillOnce(DoAll(SetArrayArgument<LANE_MOCK_PARAM3>(BRMAC, BRMAC + BT_MAC_LEN), Return(SOFTBUS_OK)))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, CheckActiveConnection).WillRepeatedly(Return(false));
    EXPECT_CALL(linkMock, LnnGetLocalNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(local), Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR)));
    EXPECT_CALL(linkMock, LnnGetRemoteNumU64Info)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(remote), Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR)));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(linkMock, AuthOpenConn(_, requestId, NotNull(), _)).WillRepeatedly(linkMock.ActionOfConnOpened);
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());
    EXPECT_CALL(laneLinkMock, TransProxyPipelineCloseChannelDelay).WillRepeatedly(Return(SOFTBUS_OK));
    g_laneLinkResult = SOFTBUS_INVALID_PARAM;
    g_manager.connectDevice = ConnectDeviceForCancel;
    g_manager.cancelConnectDevice = CancelConnectDevice;
    EXPECT_CALL(linkMock, GetWifiDirectManager).WillRepeatedly(Return(&manager));

    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: LnnCancelWifiDirect_003
* @tc.desc: test cancel wifiDirect request for success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LnnCancelWifiDirect_003, TestSize.Level1)
{
    uint32_t laneReqId = LANEREQID;
    SetCommonFunction(laneReqId, LANE_HML_RAW, g_manager);
    laneReqId = LANEREQID + 1;
    LnnCancelWifiDirect(laneReqId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, g_laneLinkResult);
    laneReqId = LANEREQID;
    LnnCancelWifiDirect(laneReqId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, g_laneLinkResult);
    int32_t ret = LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    EXPECT_EQ(SOFTBUS_LANE_RESOURCE_NOT_FOUND, ret);
    LnnDestroyP2p();
    g_manager.connectDevice = ConnectDevice;
}

/*
* @tc.name: LnnCancelWifiDirect_004
* @tc.desc: test cancel wifiDirect request for success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LnnCancelWifiDirect_004, TestSize.Level1)
{
    uint32_t laneReqId = LANEREQID;
    SetCommonFunction(laneReqId, LANE_HML_RAW, g_manager3);
    LnnCancelWifiDirect(laneReqId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, g_laneLinkResult);
    int32_t ret = LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    EXPECT_EQ(SOFTBUS_LANE_RESOURCE_NOT_FOUND, ret);
    LnnDestroyP2p();
    g_manager.connectDevice = ConnectDevice;
}

/*
* @tc.name: LnnCancelWifiDirect_005
* @tc.desc: test cancel wifiDirect request for success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LnnCancelWifiDirect_005, TestSize.Level1)
{
    uint32_t laneReqId = LANEREQID;
    SetCommonFunction(laneReqId, LANE_HML_RAW, g_manager2);
    LnnCancelWifiDirect(laneReqId);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, g_laneLinkResult);
    int32_t ret = LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    EXPECT_EQ(SOFTBUS_LANE_RESOURCE_NOT_FOUND, ret);
    LnnDestroyP2p();
    g_manager.connectDevice = ConnectDevice;
}

/*
* @tc.name: LnnCancelWifiDirect_006
* @tc.desc: test cancel wifiDirect request for success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LnnCancelWifiDirect_006, TestSize.Level1)
{
    uint32_t laneReqId = LANEREQID;
    SetCommonFunction(laneReqId, LANE_P2P, g_manager);
    LnnDisconnectP2pWithoutLnn(laneReqId);
    laneReqId = LANEREQID15;
    LnnDisconnectP2pWithoutLnn(laneReqId);
}

/*
* @tc.name: GET_MAC_INFO_BY_LANE_ID_TEST_001
* @tc.desc: GetMacInfoByLaneId test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GET_MAC_INFO_BY_LANE_ID_TEST_001, TestSize.Level1)
{
    uint64_t laneId = INVALID_LANE_ID;
    LnnMacInfo macInfo;
    memset_s(&macInfo, sizeof(LnnMacInfo), 0, sizeof(LnnMacInfo));
    int32_t ret = GetMacInfoByLaneId(laneId, &macInfo);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = GetMacInfoByLaneId(USEABLE_LANE_ID, NULL);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: GET_MAC_INFO_BY_LANE_ID_MOCK_TEST_002
* @tc.desc: GetMacInfoByLaneId test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, GET_MAC_INFO_BY_LANE_ID_MOCK_TEST_002, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> laneMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneDepMock;
    int32_t ret = InitLaneLink();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnMacInfo macInfo;
    LaneResource resource = {
        .laneId = USEABLE_LANE_ID,
        .link.type = LANE_HML,
    };
    EXPECT_EQ(strcpy_s(resource.link.linkInfo.wlan.connInfo.addr, MAX_SOCKET_ADDR_LEN, USEABLE_IP), EOK);
    memset_s(&macInfo, sizeof(LnnMacInfo), 0, sizeof(LnnMacInfo));
    EXPECT_CALL(laneMock, GetWifiDirectManager).WillOnce(Return(NULL)).WillRepeatedly(Return(&manager));
    EXPECT_CALL(laneDepMock, FindLaneResourceByLaneId).WillOnce(Return(SOFTBUS_LANE_RESOURCE_NOT_FOUND))
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(resource), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneDepMock, DelLaneResourceByLaneId).WillRepeatedly(Return(SOFTBUS_OK));
    ret = GetMacInfoByLaneId(USEABLE_LANE_ID, &macInfo);
    EXPECT_EQ(ret, SOFTBUS_LANE_RESOURCE_NOT_FOUND);
    ret = GetMacInfoByLaneId(USEABLE_LANE_ID, &macInfo);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DelLaneResourceByLaneId(USEABLE_LANE_ID, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: CHECK_IS_AUTH_SESSION_SERVER_TEST_002
* @tc.desc: CheckIsAuthSessionServer test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, CHECK_IS_AUTH_SESSION_SERVER_TEST_002, TestSize.Level1)
{
    const char *peerIp = "192.168.33.33";
    bool isServer = true;
    LnnDisconnectP2pWithoutLnn(0);
    EXPECT_EQ(CheckIsAuthSessionServer(nullptr, &isServer), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(CheckIsAuthSessionServer(peerIp, nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(CheckIsAuthSessionServer(peerIp, &isServer), SOFTBUS_NOT_FIND);
    EXPECT_EQ(RemoveAuthSessionServer(nullptr), SOFTBUS_INVALID_PARAM);
    EXPECT_EQ(RemoveAuthSessionServer(peerIp), SOFTBUS_NOT_FIND);
}

/*
* @tc.name: LNN_LANE_LINK_P2P_TEST_001
* @tc.desc: LnnLaneLinkP2P test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_LINK_P2P_TEST_001, TestSize.Level1)
{
    bool isServer;
    int32_t ret = CheckIsAuthSessionServer(nullptr, &isServer);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CheckIsAuthSessionServer("192.168.11.12", nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = CheckIsAuthSessionServer(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: LNN_LANE_LINK_P2P_TEST_002
* @tc.desc: LnnLaneLinkP2P test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_LINK_P2P_TEST_002, TestSize.Level1)
{
    bool isServer;
    uint32_t laneReqId = LANEREQID;
    SetCommonFunction(laneReqId, LANE_P2P, g_manager);
    int32_t ret = CheckIsAuthSessionServer("192.168.11.12", &isServer);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/*
* @tc.name: LNN_LANE_LINK_P2P_TEST_003
* @tc.desc: LnnLaneLinkP2P test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_LINK_P2P_TEST_003, TestSize.Level1)
{
    int32_t ret = RemoveAuthSessionServer(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    uint32_t laneReqId = LANEREQID;
    SetCommonFunction(laneReqId, LANE_P2P, g_manager);
    ret = RemoveAuthSessionServer("192.168.1.1");
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/*
* @tc.name: LNN_LANE_LINK_P2P_TEST_004
* @tc.desc: LnnLaneLinkP2P test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_LINK_P2P_TEST_004, TestSize.Level1)
{
    LanePreferredLinkList recommendList = {};
    LanePreferredLinkList request = {};
    request.linkTypeNum = 1;
    request.linkType[0] = LANE_HML;
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;

    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_LANE_GET_LEDGER_INFO_ERR));
    int32_t ret = SelectAuthLane(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);

    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager6));
    ret = SelectAuthLane(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);

    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(mock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager6));
    ret = SelectAuthLane(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);

    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager5));
    ret = SelectAuthLane(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);

    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(mock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager5));
    ret = SelectAuthLane(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);
}

/*
* @tc.name: LNN_LANE_LINK_P2P_TEST_005
* @tc.desc: LnnLaneLinkP2P test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_LINK_P2P_TEST_005, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LanePreferredLinkList recommendList = {};
    LanePreferredLinkList request = {};
    request.linkTypeNum = 1;
    request.linkType[0] = LANE_P2P;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;

    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager6));
    int32_t ret = SelectAuthLane(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);

    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager5));
    ret = SelectAuthLane(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);

    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(mock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager6));
    ret = SelectAuthLane(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);

    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(mock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager5));
    ret = SelectAuthLane(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);
}

/*
* @tc.name: LNN_LANE_LINK_P2P_TEST_006
* @tc.desc: LnnLaneLinkP2P test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_LINK_P2P_TEST_006, TestSize.Level1)
{
    LanePreferredLinkList recommendList = {};
    LanePreferredLinkList request = {};
    request.linkTypeNum = 1;
    request.linkType[0] = LANE_ETH;

    int32_t ret = SelectAuthLane(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_NO_AVAILABLE_LINK);
}

/*
* @tc.name: LNN_LANE_SELECT_01
* @tc.desc: lnn_lane_select test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_SELECT_01, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LanePreferredLinkList recommendList = {};
    LaneSelectParam request = {};
    request.qosRequire.minBW = MESH_MAGIC_NUMBER;
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
}

/*
* @tc.name: LNN_LANE_SELECT_02
* @tc.desc: lnn_lane_select test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_SELECT_02, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LanePreferredLinkList recommendList = {};
    LaneSelectParam request = {};
    request.qosRequire.minBW = DB_MAGIC_NUMBER;
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(mock, LnnGetOsTypeByNetworkId).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
}

/*
* @tc.name: LNN_LANE_SELECT_03
* @tc.desc: lnn_lane_select test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_SELECT_03, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LanePreferredLinkList recommendList = {};
    LaneSelectParam request = {};
    request.qosRequire.minBW = DB_MAGIC_NUMBER;
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t osType = OH_OS_TYPE;
    EXPECT_CALL(mock, LnnGetOsTypeByNetworkId)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(osType), Return(SOFTBUS_OK)));
    int32_t ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
}

/*
* @tc.name: LNN_LANE_SELECT_04
* @tc.desc: lnn_lane_select test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_SELECT_04, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    LanePreferredLinkList recommendList = {};
    LaneSelectParam request = {};
    request.qosRequire.minBW = DB_MAGIC_NUMBER;
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t osType = OH_OS_TYPE + 1;
    EXPECT_CALL(mock, LnnGetOsTypeByNetworkId)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(osType), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
}

/*
* @tc.name: LNN_LANE_SELECT_05
* @tc.desc: lnn_lane_select test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_SELECT_05, TestSize.Level1)
{
    NiceMock<LaneDepsInterfaceMock> mock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    LanePreferredLinkList recommendList = {};
    LaneSelectParam request = {};
    request.qosRequire.minBW = DB_MAGIC_NUMBER;
    EXPECT_CALL(mock, LnnGetOnlineStateById).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t osType = OH_OS_TYPE + 1;
    EXPECT_CALL(mock, LnnGetOsTypeByNetworkId)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(osType), Return(SOFTBUS_OK)));
    EXPECT_CALL(mock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneLinkMock, FindLaneResourceByLinkType).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = SelectExpectLanesByQos(NODE_NETWORK_ID, &request, &recommendList);
    EXPECT_EQ(ret, SOFTBUS_LANE_GET_LEDGER_INFO_ERR);
}

/*
* @tc.name: LNN_LANE_LINK_RAW_HML_TEST_001
* @tc.desc: test build raw hml link is resuse
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_LINK_RAW_HML_TEST_001, TestSize.Level1)
{
    LinkRequest request = {};
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_HML_RAW;
    request.pid = ASYNCSUCC;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    request.actionAddr = 1;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    bool isMateExist = false;
    g_isRawHmlResuse = true;

    NiceMock<LaneDepsInterfaceMock> laneMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(laneMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    g_manager.connectDevice = ConnectDeviceRawHml;
    EXPECT_CALL(laneMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(laneMock, AuthCheckMetaExist)
        .WillOnce(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(isMateExist), Return(SOFTBUS_OK)))
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(!isMateExist), Return(SOFTBUS_OK)));

    SetIsNeedCondWait(true);
    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: LNN_LANE_LINK_RAW_HML_TEST_002
* @tc.desc: test build raw hml link is not resuse
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_LINK_RAW_HML_TEST_002, TestSize.Level1)
{
    LinkRequest request = {};
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_HML_RAW;
    request.pid = ASYNCSUCC;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    request.actionAddr = 1;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    g_isRawHmlResuse = false;

    NiceMock<LaneDepsInterfaceMock> laneMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(laneMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    g_manager.connectDevice = ConnectDeviceRawHml;
    EXPECT_CALL(laneMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    SetIsNeedCondWait(true);
    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: LNN_LANE_LINK_DISCONN_TEST_001
* @tc.desc: test lane link disconn test succ
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_LINK_DISCONN_TEST_001, TestSize.Level1)
{
    LinkRequest request = {};
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_HML_RAW;
    request.pid = ASYNCSUCC;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    request.actionAddr = 1;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    g_isRawHmlResuse = false;

    NiceMock<LaneDepsInterfaceMock> laneMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(laneMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    g_manager.connectDevice = ConnectDeviceRawHml;
    g_manager.disconnectDevice = DisconnectDeviceSuccess;
    EXPECT_CALL(laneMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    SetIsNeedCondWait(true);
    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: LNN_LANE_LINK_DISCONN_TEST_002
* @tc.desc: test lane link disconn test fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_LINK_DISCONN_TEST_002, TestSize.Level1)
{
    LinkRequest request = {};
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_HML_RAW;
    request.pid = ASYNCSUCC;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    request.actionAddr = 1;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    g_isRawHmlResuse = false;

    NiceMock<LaneDepsInterfaceMock> laneMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(laneMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    g_manager.connectDevice = ConnectDeviceRawHml;
    g_manager.disconnectDevice = DisconnectDeviceFail;
    EXPECT_CALL(laneMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));

    SetIsNeedCondWait(true);
    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: LNN_LANE_LINK_DISCONN_TEST_003
* @tc.desc: test lane link disconn succ with auth opened succ
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_LINK_DISCONN_TEST_003, TestSize.Level1)
{
    LinkRequest request = {};
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_HML;
    request.pid = ASYNCSUCC;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    request.actionAddr = 1;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint32_t requestId = 1;
    g_isRawHmlResuse = false;
    AuthConnInfo connInfo = {.type = AUTH_LINK_TYPE_P2P};

    NiceMock<LaneDepsInterfaceMock> laneMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(laneMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    g_manager.connectDevice = ConnectDeviceRawHml;
    g_manager.disconnectDevice = DisconnectDeviceSuccess;
    g_manager.isNegotiateChannelNeeded = IsNegotiateChannelNeededTrue;
    EXPECT_CALL(laneMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(laneMock, AuthGetHmlConnInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneMock, AuthOpenConn(_, requestId, NotNull(), _)).WillRepeatedly(laneMock.ActionOfConnOpened);
    EXPECT_CALL(laneMock, AuthCloseConn).WillRepeatedly(Return());

    SetIsNeedCondWait(true);
    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: LNN_LANE_LINK_DISCONN_TEST_004
* @tc.desc: test lane link disconn succ with auth opened fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_LINK_DISCONN_TEST_004, TestSize.Level1)
{
    LinkRequest request = {};
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_HML;
    request.pid = ASYNCSUCC;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    request.actionAddr = 1;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint32_t requestId = 1;
    g_isRawHmlResuse = false;
    AuthConnInfo connInfo = {.type = AUTH_LINK_TYPE_P2P};

    NiceMock<LaneDepsInterfaceMock> laneMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(laneMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    g_manager.connectDevice = ConnectDeviceRawHml;
    g_manager.disconnectDevice = DisconnectDeviceSuccess;
    g_manager.isNegotiateChannelNeeded = IsNegotiateChannelNeededTrue;
    EXPECT_CALL(laneMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(laneMock, AuthGetHmlConnInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneMock, AuthOpenConn(_, requestId, NotNull(), _)).WillRepeatedly(laneMock.ActionOfConnOpenFailed);
    EXPECT_CALL(laneMock, AuthCloseConn).WillRepeatedly(Return());

    SetIsNeedCondWait(true);
    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}

/*
* @tc.name: LNN_LANE_LINK_DISCONN_TEST_005
* @tc.desc: test lane link disconn fail with auth opened succ
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkTest, LNN_LANE_LINK_DISCONN_TEST_005, TestSize.Level1)
{
    LinkRequest request = {};
    EXPECT_EQ(strcpy_s(request.peerNetworkId, NETWORK_ID_BUF_LEN, NODE_NETWORK_ID), EOK);
    request.linkType = LANE_HML;
    request.pid = ASYNCSUCC;
    request.triggerLinkTime = SoftBusGetSysTimeMs();
    request.availableLinkTime = DEFAULT_LINK_LATENCY;
    request.actionAddr = 1;
    uint32_t laneReqId = 10;
    int32_t value = 3;
    uint32_t requestId = 1;
    AuthConnInfo connInfo = {.type = AUTH_LINK_TYPE_P2P};

    NiceMock<LaneDepsInterfaceMock> laneMock;
    NiceMock<LaneLinkDepsInterfaceMock> laneLinkMock;
    EXPECT_CALL(laneMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_NOT_FIND)).WillOnce(Return(SOFTBUS_NOT_FIND))
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(laneMock, LnnGetRemoteNumInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM3>(value), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneLinkMock, GetTransReqInfoByLaneReqId).WillRepeatedly(Return(SOFTBUS_OK));
    g_manager.connectDevice = ConnectDeviceRawHml;
    g_manager.disconnectDevice = DisconnectDevice2;
    g_manager.isNegotiateChannelNeeded = IsNegotiateChannelNeededTrue;
    EXPECT_CALL(laneMock, GetWifiDirectManager).WillRepeatedly(Return(&g_manager));
    EXPECT_CALL(laneMock, AuthGetHmlConnInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneMock, AuthOpenConn(_, requestId, NotNull(), _)).WillRepeatedly(laneMock.ActionOfConnOpened);
    EXPECT_CALL(laneMock, AuthCloseConn).WillRepeatedly(Return());

    SetIsNeedCondWait(true);
    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CondWait();
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}
} // namespace OHOS