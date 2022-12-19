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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either exprets or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstring>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>
#include "p2plink_interface.h"
#include "p2plink_manager.h"
#include "softbus_log.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_adapter_mem.h"
#include "p2plink_common.h"
#include "p2plink_adapter.h"
#include "softbus_server_frame.h"
#include "p2plink_control_message.h"
#include "message_handler.h"
#include "p2plink_device.h"
#include "p2plink_lnn_sync.h"
#include "p2plink_reference.h"
#include "p2plink_message.h"
#include "softbus_access_token_test.h"

static const char *g_testPeerMac = "AA:AA:AA:AA:AA:AA";

using namespace testing::ext;
namespace OHOS {
class P2pManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override {}
    void TearDown() override {}
};

void P2pManagerTest::SetUpTestCase()
{
    SetAceessTokenPermission("P2pManagerTest");
}

void P2pManagerTest::TearDownTestCase()
{
    P2pLinkDevClean();
}

static int32_t TestAddConnedItem(ConnectedNode *connedItem, ConnectedNode *conn, ConnectingNode *conningItem)
{
    if (connedItem == nullptr) {
        CLOGE("Nego ok malloc fail");
        return SOFTBUS_ERR;
    }
    if (strcpy_s(connedItem->peerIp, sizeof(connedItem->peerIp), conn->peerIp) != EOK ||
        strcpy_s(connedItem->peerMac, sizeof(connedItem->peerMac), conn->peerMac) != EOK) {
        SoftBusFree(connedItem);
        CLOGE("strcpy fail");
        return SOFTBUS_ERR;
    }
    connedItem->chanId.inAuthId = conningItem->connInfo.authId;
    connedItem->chanId.authRequestId = conn->chanId.authRequestId;
    return SOFTBUS_OK;
}

char *TestAddJson(const char *mac)
{
    char *buf = nullptr;
    cJSON *root = nullptr;

    root = cJSON_CreateObject();
    if (root == nullptr) {
        return nullptr;
    }

    if (!AddNumberToJsonObject(root, KEY_COMMAND_TYPE, CMD_DISCONNECT_COMMAND) ||
        !AddStringToJsonObject(root, KEY_MAC, mac)) {
        cJSON_Delete(root);
        return nullptr;
    }
    buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return buf;
}

static void TestOnConnected(int32_t requestId, const char *myIp, const char *peerIp)
{
}

static void TestOnConnectFailed(int32_t requestId, int32_t reason)
{
}

static void TestOnMyRoleChange(P2pLinkRole myRole)
{
}

static void TestOnDevOffline(const char *peerMac)
{
}

static void TestP2pStateChanged(bool state)
{
}

static void TestgroupStateChanged(const P2pLinkGroup *group)
{
}

static void TestConnResult(P2pLinkConnState state)
{
}

static void TestWifiCfgChanged(const char *cfgData)
{
}

static void TestEnterDiscState(void)
{
}

static ConnectedNode g_testConnectedNode = {
    .peerMac = "11:11:11:11:11:11",
    .peerIp = "1.1.1.1",
    .localIp = "192.168.1.1",
    .chanId = {
        .inAuthId = 1,
        .p2pAuthId = 2,
        .authRequestId = 3,
        .p2pAuthIdState = P2PLINK_AUTHCHAN_FINISH,
    },
};

static ConnectingNode g_testConnectingNode = {
    .connInfo = {
        .requestId = 11,
        .authId = 12,
        .peerMac = "01:02:03:04:05:06",
        .expectedRole = ROLE_GO,
        .pid = 13,
        .cb = {
            .onConnected = TestOnConnected,
            .onConnectFailed = TestOnConnectFailed,
        },
    },
    .reTryCnt = 0,
    .state = P2PLINK_MANAGER_STATE_NEGO_WAITING,
    .timeOut = 0,
    .myIp = "100.100.1.1",
    .peerIp = "100.100.2.1",
    .peerMac = "01:02:03:04:05:06",
};

static const P2pLinkPeerDevStateCb g_testStateCb = {
    .onMyRoleChange = TestOnMyRoleChange,
    .onDevOffline = TestOnDevOffline,
};

static const BroadcastRecvCb g_testBroadcastRecvCb = {
    .p2pStateChanged = TestP2pStateChanged,
    .groupStateChanged = TestgroupStateChanged,
    .connResult = TestConnResult,
    .wifiCfgChanged = TestWifiCfgChanged,
    .enterDiscState = TestEnterDiscState,
};

/*
* @tc.name: P2pLinkSendHandshakeTest001
* @tc.desc: Test the send handshake information function with error parameter.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkSendHandshakeTest001, TestSize.Level1)
{
    P2pLinkAuthId testChan = {
        .inAuthId = 1,
        .p2pAuthId = 2,
        .authRequestId = 3,
        .p2pAuthIdState = P2PLINK_AUTHCHAN_CREATEING,
    };
    const char *testMyMac = "11:22:33:44:55:66";
    const char *testMyIp = "192.168.0.1";
    int32_t ret = P2pLinkSendHandshake(&testChan, const_cast<char *>(testMyMac), const_cast<char *>(testMyIp));
    EXPECT_EQ(SOFTBUS_ERR, ret);
    
    ret = P2pLinkSendHandshake(&testChan, nullptr, const_cast<char *>(testMyIp));
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = P2pLinkSendHandshake(&testChan, const_cast<char *>(testMyMac), nullptr);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    testChan.p2pAuthIdState = P2PLINK_AUTHCHAN_FINISH;
    ret = P2pLinkSendHandshake(&testChan, const_cast<char *>(testMyMac), nullptr);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
* @tc.name: P2pLinkSendDisConnectTest001
* @tc.desc: use error parameters to verify sends a disconnect request.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkSendDisConnectTest001, TestSize.Level1)
{
    P2pLinkAuthId testChan = {
        .inAuthId = 1,
        .p2pAuthId = 2,
        .authRequestId = 3,
        .p2pAuthIdState = P2PLINK_AUTHCHAN_CREATEING,
    };
    const char *testMyMac = "11:22:33:44:55:66";
    int32_t ret = P2pLinkSendDisConnect(&testChan, testMyMac);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = P2pLinkSendDisConnect(&testChan, nullptr);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
* @tc.name: P2pLinkSendReuseTest001
* @tc.desc: P2pLinkSendReuse use error parameters.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkSendReuseTest001, TestSize.Level1)
{
    P2pLinkAuthId testChan = {
        .inAuthId = 1,
        .p2pAuthId = 2,
        .authRequestId = 3,
        .p2pAuthIdState = P2PLINK_AUTHCHAN_CREATEING,
    };
    const char *testMyMac = "11:22:33:44:55:66";
    int32_t ret = P2pLinkSendReuse(&testChan, const_cast<char *>(testMyMac));
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = P2pLinkSendReuse(&testChan, nullptr);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
* @tc.name: P2pLinkGetConnedDevByMacTest001
* @tc.desc: P2pLinkGetConnedDevByMac user diff parameters.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkGetConnedDevByMacTest001, TestSize.Level1)
{
    int32_t ret = P2pLinkDevInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    ConnectingNode *testItem = (ConnectingNode *)SoftBusCalloc(sizeof(ConnectingNode));
    ASSERT_TRUE(testItem != nullptr);
    ConnectedNode *testConnItem = (ConnectedNode *)SoftBusCalloc(sizeof(ConnectedNode));
    ASSERT_TRUE(testConnItem != nullptr);

    ret = TestAddConnedItem(testConnItem, &g_testConnectedNode, testItem);
    ASSERT_EQ(SOFTBUS_OK, ret);

    ret = P2pLinkConnedIsEmpty();
    EXPECT_EQ(SOFTBUS_OK, ret);

    P2pLinkAddConnedDev(testConnItem);

    ConnectedNode *tmpItem = P2pLinkGetConnedDevByMac(g_testConnectedNode.peerMac);
    EXPECT_NE(nullptr, tmpItem);

    ret = P2pLinkConnedIsEmpty();
    EXPECT_EQ(SOFTBUS_ERR, ret);
    P2pLinkDumpDev();

    tmpItem = P2pLinkGetConnedDevByMac(g_testPeerMac);
    EXPECT_EQ(nullptr, tmpItem);

    SoftBusFree(testItem);
    SoftBusFree(testConnItem);
}

/*
* @tc.name: P2pLinkGetConnedByAuthReqeustIdTest001
* @tc.desc: P2pLinkGetConnedByAuthReqeustId user error parameters.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkGetConnedByAuthReqeustIdTest001, TestSize.Level1)
{
    uint32_t testReqeustId = 1;
    ConnectedNode *testItem = P2pLinkGetConnedByAuthReqeustId(testReqeustId);
    EXPECT_EQ(nullptr, testItem);

    testReqeustId = 3;
    testItem = P2pLinkGetConnedByAuthReqeustId(testReqeustId);
    EXPECT_NE(nullptr, testItem);

    const char *errPeerIp = "11.11.11.11";
    testItem = P2pLinkGetConnedDevByPeerIp(errPeerIp);
    EXPECT_EQ(nullptr, testItem);

    testItem = P2pLinkGetConnedDevByPeerIp(g_testConnectedNode.peerIp);
    EXPECT_NE(nullptr, testItem);

    P2pLinkSetDevStateCallback(&g_testStateCb);
    P2pLinkMyRoleChangeNotify(ROLE_AUTO);
}

/*
* @tc.name: P2pLinkAddConningDevTest001
* @tc.desc: P2pLinkAddConningDev user error parameters.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkAddConningDevTest001, TestSize.Level1)
{
    int32_t ret = P2pLoopInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    LooperInit();

    P2pLinkAddConningDev(&g_testConnectingNode);
}

/*
* @tc.name: P2pLinkGetConningByPeerMacStateTest001
* @tc.desc: P2pLinkGetConningByPeerMacState user error parameters.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkGetConningByPeerMacStateTest001, TestSize.Level1)
{
    InitSoftBusServer();
    int testState = P2PLINK_MANAGER_STATE_NEGO_WAITING;
    ConnectingNode *testConnectingItem = P2pLinkGetConningByPeerMacState(g_testPeerMac, testState);
    EXPECT_EQ(nullptr, testConnectingItem);

    testState = P2PLINK_MANAGER_STATE_HANDSHAKE;
    testConnectingItem = P2pLinkGetConningByPeerMacState(g_testConnectingNode.peerMac, testState);
    EXPECT_EQ(nullptr, testConnectingItem);

    testConnectingItem = P2pLinkGetConningByPeerMacState(g_testPeerMac, g_testConnectingNode.state);
    EXPECT_EQ(nullptr, testConnectingItem);

    int64_t testAuthId = 2;
    P2pLinkDelConnedByAuthId(testAuthId);
    P2pLinkAddConningDev(&g_testConnectingNode);
}

/*
* @tc.name: P2pLinkGetConningDevByReqIdTest001
* @tc.desc: P2pLinkGetConningDevByReqId user error parameters.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkGetConningDevByReqIdTest001, TestSize.Level1)
{
    int32_t testReqId = 21;
    ConnectingNode *testConnectingItem = P2pLinkGetConningDevByReqId(testReqId);
    EXPECT_EQ(nullptr, testConnectingItem);

    testReqId = 11;
    testConnectingItem = P2pLinkGetConningDevByReqId(testReqId);
    EXPECT_NE(nullptr, testConnectingItem);

    P2pLinkDevEnterDiscState();
}

/*
* @tc.name: P2pLinkLnnSyncTest001
* @tc.desc: P2pLinkLnnSync user diff parameters.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkLnnSyncTest001, TestSize.Level1)
{
    P2pLinkRole testRole = ROLE_GC;
    P2pLinkSetRole(testRole);
    EXPECT_EQ(ROLE_GC, P2pLinkGetRole());
    P2pLinkLnnSync();

    testRole = ROLE_GO;
    P2pLinkSetRole(testRole);
    EXPECT_EQ(ROLE_GO, P2pLinkGetRole());
    bool isExpired = true;
    P2pLinkSetMyMacExpired(isExpired);
    char *myMac = P2pLinkGetMyMac();
    EXPECT_NE(nullptr, myMac);
    P2pLinkLnnSync();
}

/*
* @tc.name: P2pLinkCleanTest001
* @tc.desc: some diff param in P2pLinkClean.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkCleanTest001, TestSize.Level1)
{
    int32_t testPort = 10;
    P2pLinkSetGoPort(testPort);
    int32_t ret = P2pLinkGetGoPort();
    EXPECT_EQ(testPort, ret);
    P2pLinkSetGcPort(0);
    ret = P2pLinkGetGcPort();
    EXPECT_EQ(0, ret);
    P2pLinkClean();

    P2pLinkSetGoPort(0);
    ret = P2pLinkGetGoPort();
    EXPECT_EQ(0, ret);
    P2pLinkSetGcPort(testPort);
    ret = P2pLinkGetGcPort();
    EXPECT_EQ(testPort, ret);
    P2pLinkClean();

    P2pLinkSetGoPort(0);
    ret = P2pLinkGetGoPort();
    EXPECT_EQ(0, ret);
    P2pLinkSetGcPort(0);
    ret = P2pLinkGetGcPort();
    EXPECT_EQ(0, ret);
    P2pLinkClean();
}

/*
* @tc.name: P2pLinkInitRefTest001
* @tc.desc: P2pLinkInitRef initialize its own PID and MAC number.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkInitRefTest001, TestSize.Level1)
{
    P2pLinkInitRef();
    int32_t ret = P2pLinkGetMyP2pRef();
    EXPECT_EQ(0, ret);
    P2pLinkDelMyP2pRef();

    P2pLinkAddMyP2pRef();
    ret = P2pLinkGetMyP2pRef();
    EXPECT_EQ(1, ret);
    P2pLinkDelMyP2pRef();

    P2pLinkRefClean();
    ret = P2pLinkGetMyP2pRef();
    EXPECT_EQ(0, ret);
}

/*
* @tc.name: P2pLinkAddPidMacRefTest001
* @tc.desc: some diff param in P2pLinkAddPidMacRef, add own PID and MAC number.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkAddPidMacRefTest001, TestSize.Level1)
{
    int32_t testPid = 11;
    P2pLinkAddPidMacRef(testPid, g_testPeerMac);
    int32_t ret = P2pLinGetMacRefCnt(testPid, g_testPeerMac);
    EXPECT_EQ(1, ret);
    P2pLinkDelPidMacRef(testPid, g_testPeerMac);
    ret = P2pLinGetMacRefCnt(testPid, g_testPeerMac);
    EXPECT_EQ(0, ret);

    int32_t errPid = 5;
    ret = P2pLinGetMacRefCnt(errPid, g_testPeerMac);
    EXPECT_EQ(0, ret);

    const char *errMac = "";
    ret = P2pLinGetMacRefCnt(testPid, errMac);
    EXPECT_EQ(0, ret);

    P2pLinkAddPidMacRef(testPid, g_testPeerMac);
    ret = P2pLinGetMacRefCnt(testPid, g_testPeerMac);
    EXPECT_EQ(1, ret);

    P2pLinkAddPidMacRef(testPid, g_testPeerMac);
    ret = P2pLinGetMacRefCnt(testPid, g_testPeerMac);
    EXPECT_EQ(2, ret);

    P2pLinkDumpRef();
    P2pLinkMyP2pRefClean();
    ret = P2pLinkGetMyP2pRef();
    EXPECT_EQ(0, ret);
}

/*
* @tc.name: P2pLinkSendMessageTest001
* @tc.desc: error diff param in P2pLinkSendMessage.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkSendMessageTest001, TestSize.Level1)
{
    int64_t testAuthId = 1;
    const char *testMac = "01:23:45:67:89:00";
    char *testData = TestAddJson(testMac);
    ASSERT_TRUE(testData != nullptr);
    int32_t ret = P2pLinkSendMessage(testAuthId, testData, strlen(testData) + 1);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
* @tc.name: P2pLinkAdapterInitTest001
* @tc.desc: some diff param in P2pLinkAdapterInit.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkAdapterInitTest001, TestSize.Level1)
{
    int32_t ret = P2pLinkAdapterInit(nullptr);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = P2pLinkAdapterInit(&g_testBroadcastRecvCb);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: P2pLinkGetP2pIpAddressTest001
* @tc.desc: error diff param in P2pLinkGetP2pIpAddress.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkGetP2pIpAddressTest001, TestSize.Level1)
{
    char testP2pIp[P2P_IP_LEN] = {0};
    int32_t ret = P2pLinkGetP2pIpAddress(testP2pIp, sizeof(testP2pIp));
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
* @tc.name: P2pLinkCreateGroupTest001
* @tc.desc: some diff param in P2pLinkCreateGroup.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkCreateGroupTest001, TestSize.Level1)
{
    int32_t testFreq = 2432;
    bool testIsWideBandSupport = true;
    int32_t ret = P2pLinkCreateGroup(testFreq, testIsWideBandSupport);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    testFreq = -1;
    ret = P2pLinkCreateGroup(testFreq, testIsWideBandSupport);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
* @tc.name: P2pLinkGetRecommendChannelTest001
* @tc.desc: right diff param in P2pLinkGetRecommendChannel.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkGetRecommendChannelTest001, TestSize.Level1)
{
    int32_t testFreq = 0;
    int32_t ret = P2pLinkGetRecommendChannel(&testFreq);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    EXPECT_EQ(0, testFreq);
}

/*
* @tc.name: P2pLinkConnectGroupTest001
* @tc.desc: some diff param in P2pLinkConnectGroup.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkConnectGroupTest001, TestSize.Level1)
{
    const char *errGroupConfig = "aaa\nbbb\nccc";
    const char *testGroupConfig = "testWifiName\n11:12:13:14:15:16\ntestWifiPwd\n2412\n1";
    int32_t ret = P2pLinkConnectGroup(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = P2pLinkConnectGroup(errGroupConfig);
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);

    ret = P2pLinkConnectGroup(testGroupConfig);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
* @tc.name: P2pLinkRequestGcIpTest001
* @tc.desc: some diff param in P2pLinkRequestGcIp.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkRequestGcIpTest001, TestSize.Level1)
{
    const char *testMac = "11:22:33:44:55:66";
    char testIp[P2P_IP_LEN] = {0};
    int32_t ret = P2pLinkRequestGcIp(nullptr, testIp, sizeof(testIp));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = P2pLinkRequestGcIp(testMac, nullptr, sizeof(testIp));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = P2pLinkRequestGcIp(testMac, testIp, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = P2pLinkRequestGcIp(testMac, testIp, sizeof(testIp));
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
* @tc.name: P2pLinkConfigGcIpTest001
* @tc.desc: error diff param in P2pLinkConfigGcIp.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkConfigGcIpTest001, TestSize.Level1)
{
    const char *testIp = "192.168.3.3";
    int32_t ret = P2pLinkConfigGcIp(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = P2pLinkConfigGcIp(testIp);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
* @tc.name: P2pLinkGetSelfWifiCfgInfoTest001
* @tc.desc: some diff param in P2pLinkGetSelfWifiCfgInfo.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkGetSelfWifiCfgInfoTest001, TestSize.Level1)
{
    char testWifiCfg[WIFI_CONFIG_DATA_LEN] = {0};
    int32_t ret = P2pLinkGetSelfWifiCfgInfo(nullptr, sizeof(testWifiCfg));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    P2pLinkGetSelfWifiCfgInfo(testWifiCfg, 0);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = memcpy_s(testWifiCfg, sizeof(testWifiCfg), g_testPeerMac, sizeof(g_testPeerMac));
    ASSERT_TRUE(ret == EOK);
    P2pLinkGetSelfWifiCfgInfo(testWifiCfg, sizeof(testWifiCfg));
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: P2pLinkSetPeerWifiCfgInfoTest001
* @tc.desc: some diff param in P2pLinkSetPeerWifiCfgInfo.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkSetPeerWifiCfgInfoTest001, TestSize.Level1)
{
    char testWifiCfg[WIFI_CONFIG_DATA_LEN] = {0};
    const char *errWifiCfg = "\0";
    int32_t ret = P2pLinkSetPeerWifiCfgInfo(nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = P2pLinkSetPeerWifiCfgInfo(errWifiCfg);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = P2pLinkSetPeerWifiCfgInfo(testWifiCfg);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
* @tc.name: P2pLinkSharelinkReuseTest001
* @tc.desc: some diff param in P2pLinkSharelinkReuse.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkSharelinkReuseTest001, TestSize.Level1)
{
    int32_t ret = P2pLinkSharelinkReuse();
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = P2pLinkSharelinkRemoveGroup();
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = P2pLinkReleaseIPAddr();
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
* @tc.name: P2pLinkRequetGroupInfo001
* @tc.desc: error diff param in P2pLinkRequetGroupInfo.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkRequetGroupInfoTest001, TestSize.Level1)
{
    P2pLinkGroup *testGroup = P2pLinkRequetGroupInfo();
    EXPECT_EQ(nullptr, testGroup);
}

/*
* @tc.name: P2pLinkGetChannelListFor5GTest001
* @tc.desc: some diff param in P2pLinkGetChannelListFor5G.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pManagerTest, P2pLinkGetChannelListFor5GTest001, TestSize.Level1)
{
    P2pLink5GList *testList = P2pLinkGetChannelListFor5G();
    EXPECT_NE(nullptr, testList);

    EXPECT_EQ(nullptr, P2pLinkGetGroupConfigInfo());
    P2pLinkStopPeerDiscovery();
    bool ret = P2pLinkIsWideBandwidthSupported();
    EXPECT_EQ(false, ret);

    P2pLinkRemoveGroup();
    P2pLinkRemoveGcGroup();
}
} // namespace OHOS