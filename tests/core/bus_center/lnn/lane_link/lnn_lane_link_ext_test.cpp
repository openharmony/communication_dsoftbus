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
constexpr int32_t SYNCFAIL = 0;
constexpr int32_t SYNCSUCC = 1;
constexpr int32_t ASYNCFAIL = 2;
constexpr int32_t ASYNCSUCC = 3;
constexpr uint64_t DEFAULT_LINK_LATENCY = 30000;

static bool g_isRawHmlResuse = true;
int32_t g_laneLinkResult = SOFTBUS_INVALID_PARAM;
int32_t g_connFailReason = ERROR_WIFI_DIRECT_WAIT_REUSE_RESPONSE_TIMEOUT;

class LNNLaneLinkExtTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneLinkExtTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneLinkExtTest start";
    LnnInitLnnLooper();
}

void LNNLaneLinkExtTest::TearDownTestCase()
{
    LnnDeinitLnnLooper();
    GTEST_LOG_(INFO) << "LNNLaneLinkExtTest end";
}

void LNNLaneLinkExtTest::SetUp()
{
}

void LNNLaneLinkExtTest::TearDown()
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
    g_laneLinkResult = SOFTBUS_LANE_BUILD_LINK_FAIL;
    return;
}

static LaneLinkCb g_linkCb = {
    .onLaneLinkSuccess = OnLaneLinkSuccess,
    .onLaneLinkFail = OnLaneLinkFail,
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
    return SOFTBUS_ERR;
}

static int32_t CancelConnectDevice(const struct WifiDirectConnectInfo *info)
{
    GTEST_LOG_(INFO) << "CancelConnectDevice enter";
    (void)info;
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
    .cancelConnectDevice = CancelConnectDevice,
    .disconnectDevice = DisconnectDevice,
    .supportHmlTwo = SupportHmlTwo,
};


/*
* @tc.name: LNN_LANE_LINK_DISCONN_TEST_001
* @tc.desc: test lane link disconn error with auth opened fail
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkExtTest, LNN_LANE_LINK_DISCONN_TEST_001, TestSize.Level1)
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
    struct WifiDirectManager manager1 = g_manager;
    manager1.connectDevice = ConnectDeviceRawHml;
    manager1.disconnectDevice = DisconnectDevice2;
    manager1.isNegotiateChannelNeeded = IsNegotiateChannelNeededTrue;
    EXPECT_CALL(laneMock, GetWifiDirectManager).WillRepeatedly(Return(&manager1));
    EXPECT_CALL(laneMock, AuthGetHmlConnInfo)
        .WillRepeatedly(DoAll(SetArgPointee<LANE_MOCK_PARAM2>(connInfo), Return(SOFTBUS_OK)));
    EXPECT_CALL(laneMock, AuthGenRequestId).WillRepeatedly(Return(requestId));
    EXPECT_CALL(laneMock, AuthOpenConn(_, requestId, NotNull(), _)).WillRepeatedly(laneMock.ActionOfConnOpenFailed);
    EXPECT_CALL(laneMock, AuthCloseConn).WillRepeatedly(Return());

    int32_t ret = LnnConnectP2p(&request, laneReqId, &g_linkCb);
    std::this_thread::sleep_for(std::chrono::milliseconds(500)); // delay 500ms for looper completion.
    EXPECT_EQ(SOFTBUS_OK, ret);
    LnnDisconnectP2p(NODE_NETWORK_ID, laneReqId);
    LnnDestroyP2p();
}
} // namespace OHOS