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

#include "lnn_lane_deps_mock.h"
#include "lnn_lane_link.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;

class LNNLaneLinkMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNLaneLinkMockTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneLinkMockTest start";
}

void LNNLaneLinkMockTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "LNNLaneLinkMockTest end";
}

void LNNLaneLinkMockTest::SetUp()
{
}

void LNNLaneLinkMockTest::TearDown()
{
}

/*
* @tc.name: LNN_LANE_LINK_001
* @tc.desc: LnnConnectP2p
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkMockTest, LNN_LANE_LINK_001, TestSize.Level1)
{
    int32_t ret = LnnConnectP2p(nullptr, 0, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    const char *network = "network_123";
    ret = LnnConnectP2p(network, 0, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    LnnLaneP2pInfo p2p;
    ret = LnnConnectP2p(network, 0, &p2p);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_LINK_002
* @tc.desc: LnnDisconnectP2p
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkMockTest, LNN_LANE_LINK_002, TestSize.Level1)
{
    int32_t ret = LnnDisconnectP2p(nullptr, 0, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    const char *network = "network123";
    ret = LnnDisconnectP2p(network, 0, nullptr);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    const char *mac = "AA:11:BB:22:CC:33";
    ret = LnnDisconnectP2p(network, 0, mac);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
* @tc.name: LNN_LANE_LINK_003
* @tc.desc: LnnConnectP2p
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkMockTest, LNN_LANE_LINK_003, TestSize.Level1)
{
    (void)LnnLanePendingInit();
    LaneDepsInterfaceMock linkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, P2pLinkGetRequestId).WillRepeatedly(Return(1));
    EXPECT_CALL(linkMock, AuthSetP2pMac).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());

    auto authOpen = [](const AuthConnCallback *cb) { cb->onConnOpened(1, -1); };
    EXPECT_CALL(linkMock, AuthOpenConn)
        .WillOnce(DoAll(WithArg<2>(authOpen), Return(SOFTBUS_OK)));

    auto p2pOpen = [](const P2pLinkConnectInfo *param) { param->cb.onConnected(1, "192.168.1.3", "192.168.1.4"); };
    EXPECT_CALL(linkMock, P2pLinkConnectDevice)
        .WillOnce(DoAll(WithArg<0>(p2pOpen), Return(SOFTBUS_OK)));
    const char *network = "network_123";
    LnnLaneP2pInfo p2p;
    int32_t ret = LnnConnectP2p(network, 0, &p2p);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(linkMock, AuthOpenConn)
        .WillOnce(DoAll(WithArg<2>(authOpen), Return(SOFTBUS_OK)));

    auto p2pOpenFail = [](const P2pLinkConnectInfo *param) { param->cb.onConnectFailed(1, SOFTBUS_ERR); };
    EXPECT_CALL(linkMock, P2pLinkConnectDevice)
        .WillOnce(DoAll(WithArg<0>(p2pOpenFail), Return(SOFTBUS_OK)));
    ret = LnnConnectP2p(network, 0, &p2p);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    auto authOpenFail = [](const AuthConnCallback *cb) { cb->onConnOpenFailed(1, SOFTBUS_ERR); };
    EXPECT_CALL(linkMock, AuthOpenConn)
        .WillOnce(DoAll(WithArg<2>(authOpenFail), Return(SOFTBUS_OK)));
    ret = LnnConnectP2p(network, 0, &p2p);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    LnnLanePendingDeinit();
}

/*
* @tc.name: LNN_LANE_LINK_004
* @tc.desc: LnnConnectP2p
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkMockTest, LNN_LANE_LINK_004, TestSize.Level1)
{
    (void)LnnLanePendingInit();
    const char *network = "network_123";
    LnnLaneP2pInfo p2p;
    LaneDepsInterfaceMock linkMock;
    EXPECT_CALL(linkMock, P2pLinkGetRequestId).WillRepeatedly(Return(1));
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    int32_t ret = LnnConnectP2p(network, 0, &p2p);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthOpenConn).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = LnnConnectP2p(network, 0, &p2p);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    LnnLanePendingDeinit();
}

/*
* @tc.name: LNN_LANE_LINK_005
* @tc.desc: LnnDisconnectP2p
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LNNLaneLinkMockTest, LNN_LANE_LINK_005, TestSize.Level1)
{
    (void)LnnLanePendingInit();

    const char *network = "network123";
    const char *mac = "AA:11:BB:22:CC:33";
    LaneDepsInterfaceMock linkMock;
    EXPECT_CALL(linkMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, LnnGetRemoteNumInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, AuthGetPreferConnInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, P2pLinkGetRequestId).WillRepeatedly(Return(1));
    EXPECT_CALL(linkMock, AuthOpenConn).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(linkMock, AuthCloseConn).WillRepeatedly(Return());

    EXPECT_CALL(linkMock, P2pLinkDisconnectDevice).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = LnnDisconnectP2p(network, 0, mac);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(linkMock, P2pLinkDisconnectDevice).WillOnce(Return(SOFTBUS_ERR));
    ret = LnnDisconnectP2p(network, 0, mac);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(linkMock, AuthSetP2pMac).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(linkMock, P2pLinkDisconnectDevice).WillOnce(Return(SOFTBUS_OK));
    auto authOpen = [](const AuthConnCallback *cb) { cb->onConnOpened(1, -1); };
    EXPECT_CALL(linkMock, AuthOpenConn)
        .WillOnce(DoAll(WithArg<2>(authOpen), Return(SOFTBUS_OK)));

    ret = LnnDisconnectP2p(network, 0, mac);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(linkMock, P2pLinkDisconnectDevice).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(linkMock, AuthOpenConn)
        .WillOnce(DoAll(WithArg<2>(authOpen), Return(SOFTBUS_OK)));
    ret = LnnDisconnectP2p(network, 0, mac); // add condWait
    EXPECT_EQ(ret, SOFTBUS_OK);

    auto authOpenFail = [](const AuthConnCallback *cb) { cb->onConnOpenFailed(1, SOFTBUS_ERR); };
    EXPECT_CALL(linkMock, AuthOpenConn)
        .WillOnce(DoAll(WithArg<2>(authOpenFail), Return(SOFTBUS_OK)));
    EXPECT_CALL(linkMock, P2pLinkDisconnectDevice).WillOnce(Return(SOFTBUS_OK));
    ret = LnnDisconnectP2p(network, 0, mac); // add condWait
    EXPECT_EQ(ret, SOFTBUS_OK);

    LnnLanePendingDeinit();
}
} // namespace OHOS