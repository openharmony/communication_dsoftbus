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
#include <fstream>
#include <thread>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "p2plink_interface.h"
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "p2plink_loop.h"
#include "p2plink_type.h"
#include "manager_mock.h"

using namespace testing::ext;
using testing::Return;

namespace OHOS {
class P2pInterfaceMockTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        P2pLoopInit();
    }
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

static void OnConnected(int32_t requestId, const char *myIp, const char *peerIp)
{
}

static void OnConnectFailed(int32_t requestId, int32_t reason)
{
}

static P2pLinkCb g_p2pLinkCb = {
    .onConnected = OnConnected,
    .onConnectFailed = OnConnectFailed,
};

static void OnMyRoleChange(P2pLinkRole myRole)
{
}

static void OnDevOffline(const char *peerMac)
{
}

static const P2pLinkPeerDevStateCb g_p2pLinkPeerDevStateCb = {
    .onMyRoleChange = OnMyRoleChange,
    .onDevOffline = OnDevOffline,
};

/*
* @tc.name: P2pLinkConnectDevice001
* @tc.desc: test P2pLinkConnectDevice
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pInterfaceMockTest, P2pLinkConnectDevice001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkConnectDevice001, Start");
    P2pLinkConnectInfo infoTest {
        .requestId = 101,
        .authId = -2859304981150826472,
        .peerMac = "e8:b2:a0:19:a6:b3",
        .expectedRole = ROLE_NONE,
        .pid = 100,
        .cb = g_p2pLinkCb,
    };
    ManagerMock managerMock;
    managerMock.SetupSuccessStub();
    int32_t ret = P2pLinkConnectDevice(&infoTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkConnectDevice001, End");
}

/*
* @tc.name: P2pLinkConnectDevice002
* @tc.desc: P2pLinkConnectInfo is nullptr
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pInterfaceMockTest, P2pLinkConnectDevice002, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkConnectDevice002, Start");
    int32_t ret = P2pLinkConnectDevice(nullptr);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkConnectDevice002, End");
}

/*
* @tc.name: P2pLinkGetRequestId001
* @tc.desc: test P2pLinkGetRequestId
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pInterfaceMockTest, P2pLinkGetRequestId001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkGetRequestId001, Start");
    int32_t ret = P2pLinkGetRequestId();
    EXPECT_EQ(ret, 1);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkGetRequestId001, End");
}

/*
* @tc.name: P2pLinkDisconnectDevice001
* @tc.desc: P2pLinkDisconnectDevice sucesss
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pInterfaceMockTest, P2pLinkDisconnectDevice001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkDisconnectDevice001, Start");
    P2pLinkDisconnectInfo infoTest {
        .authId = -2859304981150826472,
        .peerMac = "e8:b2:a0:19:a6:b3",
        .pid = 100,
    };
    ManagerMock managerMock;
    managerMock.SetupSuccessStub();
    int32_t ret = P2pLinkDisconnectDevice(&infoTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkDisconnectDevice001, End");
}

/*
* @tc.name: P2pLinkDisconnectDevice002
* @tc.desc: P2pLinkDisconnectInfo is nullptr
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pInterfaceMockTest, P2pLinkDisconnectDevice002, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkDisconnectDevice002, Start");
    int32_t ret = P2pLinkDisconnectDevice(nullptr);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkDisconnectDevice002, End");
}

/*
* @tc.name: P2pLinkManagerInit
* @tc.desc: test P2pLinkManagerInit
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pInterfaceMockTest, P2pLinkManagerInit001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkManagerInit001, Start");
    ManagerMock managerMock;
    managerMock.SetupSuccessStub();
    int32_t ret = P2pLinkInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkManagerInit001, End");
}

/*
* @tc.name: P2pLinkRegPeerDevStateChange
* @tc.desc: test P2pLinkRegPeerDevStateChange
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pInterfaceMockTest, P2pLinkRegPeerDevStateChange001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkRegPeerDevStateChange001, Start");
    P2pLinkRegPeerDevStateChange(nullptr);
    ManagerMock managerMock;
    managerMock.SetupSuccessStub();
    P2pLinkRegPeerDevStateChange(&g_p2pLinkPeerDevStateCb);
    EXPECT_EQ(managerMock.p2pLinkPeerDevStateCb, &g_p2pLinkPeerDevStateCb);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkRegPeerDevStateChange001, End");
}

/*
* @tc.name: P2pLinkGetLocalIp
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pInterfaceMockTest, P2pLinkGetLocalIp001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkGetLocalIp001, Start");
    char localIpTest[P2P_MAC_LEN] = {0};
    int32_t localIpLenTest = P2P_MAC_LEN;
    ManagerMock managerMock;
    managerMock.SetupSuccessStub();
    int32_t ret = P2pLinkGetLocalIp(localIpTest, localIpLenTest);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkGetLocalIp001, End");
}

/*
* @tc.name: P2pLinkIsRoleConflict
* @tc.desc: test P2pLinkIsRoleConflict
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pInterfaceMockTest, P2pLinkIsRoleConflict001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkIsRoleConflict001, Start");
    RoleIsConflictInfo roleIsConflictInfoTest;
    ManagerMock managerMock;
    managerMock.SetupSuccessStub();

    ManagerMock::g_connectedNode.peerIp[0] = '\0';
    int32_t ret =P2pLinkIsRoleConflict(&roleIsConflictInfoTest);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ManagerMock::g_connectedNode.peerIp[0] = 't';
    ManagerMock::g_connectedNode.peerIp[1] = '\0';
    roleIsConflictInfoTest.expectedRole = ROLE_GO;
    EXPECT_CALL(managerMock, P2pLinkGetRole).WillRepeatedly(Return(ROLE_GC));
    ret =P2pLinkIsRoleConflict(&roleIsConflictInfoTest);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    roleIsConflictInfoTest.expectedRole = ROLE_AUTO;
    ret =P2pLinkIsRoleConflict(&roleIsConflictInfoTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkIsRoleConflict001, End");
}

/*
* @tc.name: P2pLinkIsRoleConflict
* @tc.desc: RoleIsConflictInfo is nullptr
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pInterfaceMockTest, P2pLinkIsRoleConflict002, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkIsRoleConflict002, Start");
    ManagerMock managerMock;
    managerMock.SetupSuccessStub();
    int32_t ret = P2pLinkIsRoleConflict(nullptr);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkIsRoleConflict002, End");
}

/*
* @tc.name: P2pLinkIsRoleConflict
* @tc.desc: P2pLinkIsEnable is false
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pInterfaceMockTest, P2pLinkIsRoleConflict003, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkIsRoleConflict003, Start");
    RoleIsConflictInfo roleIsConflictInfoTest;
    ManagerMock managerMock;
    managerMock.SetupSuccessStub();
    EXPECT_CALL(managerMock, P2pLinkIsEnable).WillRepeatedly(Return(false));
    int32_t ret =P2pLinkIsRoleConflict(&roleIsConflictInfoTest);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkIsRoleConflict003, End");
}

/*
* @tc.name: P2pLinkIsRoleConflict
* @tc.desc: P2pLinkGetConnedDevByMac return nullptr
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pInterfaceMockTest, P2pLinkIsRoleConflict004, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkIsRoleConflict004, Start");
    RoleIsConflictInfo roleIsConflictInfoTest;
    ManagerMock managerMock;
    managerMock.SetupSuccessStub();
    EXPECT_CALL(managerMock, P2pLinkGetConnedDevByMac).WillRepeatedly(Return(nullptr));
    int32_t ret = P2pLinkIsRoleConflict(&roleIsConflictInfoTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkIsRoleConflict004, End");
}

/*
* @tc.name: P2pLinkGetPeerMacByPeerIp
* @tc.desc: test P2pLinkGetPeerMacByPeerIp
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pInterfaceMockTest, P2pLinkGetPeerMacByPeerIp001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkGetPeerMacByPeerIp001, Start");
    char peerIp[P2P_IP_LEN] = {0};
    char peerMac[P2P_MAC_LEN] = {0};
    int32_t macLen = P2P_MAC_LEN;
    ManagerMock managerMock;
    managerMock.SetupSuccessStub();
    int32_t ret = P2pLinkGetPeerMacByPeerIp(nullptr, peerMac, macLen);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = P2pLinkGetPeerMacByPeerIp(peerIp, nullptr, macLen);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(managerMock, P2pLinkGetRole).WillRepeatedly(Return(ROLE_NONE));
    ret = P2pLinkGetPeerMacByPeerIp(peerIp, peerMac, macLen);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkGetPeerMacByPeerIp001, End");
}

/*
* @tc.name: P2pLinkGetPeerMacByPeerIp
* @tc.desc: test P2pLinkGetPeerMacByPeerIp
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pInterfaceMockTest, P2pLinkGetPeerMacByPeerIp002, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkGetPeerMacByPeerIp002, Start");
    char peerIp[P2P_IP_LEN] = {0};
    char peerMac[P2P_MAC_LEN] = {0};
    int32_t macLen = P2P_MAC_LEN;
    ManagerMock managerMock;
    managerMock.SetupSuccessStub();
    ManagerMock::g_connectedNode.peerMac[0] = '1';
    ManagerMock::g_connectedNode.peerMac[1] = '\0';
    int32_t ret = P2pLinkGetPeerMacByPeerIp(peerIp, peerMac, macLen);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ManagerMock::g_connectedNode.peerMac[0] = '\0';
    ret = P2pLinkGetPeerMacByPeerIp(peerIp, peerMac, macLen);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(managerMock, P2pLinkGetConnedDevByPeerIp).WillRepeatedly(Return(nullptr));
    ret = P2pLinkGetPeerMacByPeerIp(peerIp, peerMac, macLen);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkGetPeerMacByPeerIp002, End");
}

/*
* @tc.name: P2pLinkQueryDevIsOnline
* @tc.desc: test P2pLinkQueryDevIsOnline
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pInterfaceMockTest, P2pLinkQueryDevIsOnline001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkQueryDevIsOnline001, Start");
    char peerMac[P2P_MAC_LEN] = {0};
    ManagerMock managerMock;
    managerMock.SetupSuccessStub();
    int32_t ret = P2pLinkQueryDevIsOnline(peerMac);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = P2pLinkQueryDevIsOnline(nullptr);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(managerMock, P2pLinkGetRole).WillRepeatedly(Return(ROLE_NONE));
    ret = P2pLinkQueryDevIsOnline(peerMac);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(managerMock, P2pLinkGetRole).WillRepeatedly(Return(ROLE_GO));
    EXPECT_CALL(managerMock, P2pLinkGetConnedDevByMac).WillRepeatedly(Return(nullptr));
    EXPECT_EQ(ret, SOFTBUS_ERR);

    std::this_thread::sleep_for(std::chrono::seconds(1));
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pInterfaceMockTest, P2pLinkQueryDevIsOnline001, End");
}
};