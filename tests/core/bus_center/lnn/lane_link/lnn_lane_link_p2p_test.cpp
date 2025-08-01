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

#include "lnn_lane_deps_mock.h"
#include "lnn_lane_interface.h"
#include "lnn_lane_link_deps_mock.h"
#include "lnn_lane_link_p2p.c"
#include "lnn_lane_link_p2p.h"

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
constexpr int32_t AUTH_REQ_ID = 112;

class LNNLaneLinkP2pTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneLinkTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneLinkP2pTest start";
    LnnInitLnnLooper();
    EXPECT_EQ(LnnP2pInit(), SOFTBUS_OK);
}

void LNNLaneLinkTest::TearDownTestCase()
{
    LnnDeinitLnnLooper();
    LnnDestroyP2pLinkInfo();
    GTEST_LOG_(INFO) << "LNNLaneLinkP2pTest end";
}

void LNNLaneLinkTest::SetUp()
{
}

void LNNLaneLinkTest::TearDown()
{
}

/*
* @tc.name: GuideChannelRetryOfSync_004
* @tc.desc: test GuideChannelRetryOfSync:LANE_NEW_AUTH_NEGO(fail)
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkP2pTest, TRY_ADD_PRE_LINK_CONN_TEST_001, TestSize.Level1)
{
    uint32_t authRequestId = AUTH_REQ_ID;
    WifiDirectConnectInfo connectInfo;
    (void)memset_s(&connectInfo, sizeof(WifiDirectConnectInfo), 0, sizeof(WifiDirectConnectInfo));
    LinkRequest request;
    (void)memset_s(&request, sizeof(LinkRequest), 0, sizeof(LinkRequest));
    LaneLinkCb callBack;
    (void)memset_s(&callBack, sizeof(LaneLinkCb), 0, sizeof(LaneLinkCb));
    NiceMock<LaneDepsInterfaceMock> linkMock;
    EXPECT_CALL(linkMock, LnnConvertDlId).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, SoftBusGenerateStrHash).WillRepeatedly(Return(SOFTBUS_OK));
    AddP2pLinkReqItem(ASYNC_RESULT_AUTH, authRequestId, LANEREQID, &request, &callBack);
    EXPECT_NO_FATAL_FAILURE(TryAddPreLinkConn(authRequestId, &connectInfo));
    EXPECT_NO_FATAL_FAILURE(TryAddPreLinkConn(authRequestId, &connectInfo));
    DelP2pLinkReqByReqId(ASYNC_RESULT_AUTH, authRequestId);
    EXPECT_NO_FATAL_FAILURE(TryAddPreLinkConn(authRequestId, &connectInfo));
}