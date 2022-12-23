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
#include "gtest/gtest.h"
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
#include "p2plink_control_message.c"
#include "p2plink_device.c"
#include "auth_common.h"
#include "p2plink_manager.c"
#include "auth_interface.h"
#include "p2plink_negotiation.h"
#include "p2plink_lnn_sync.c"
#include "p2plink_reference.c"
#include "lnn_local_net_ledger.h"

static const char *g_testPeerMac = "AA:AA:AA:AA:AA:AA";
static const char *g_testMac = "AB:AB:AB:AB:AB:AB";
static const char *g_testIp = "192.168.4.4";
static const int64_t g_testResult = 0;
static const int64_t g_testAuthId = 1000;
static const  int64_t g_testSeq = 2;
static const char *g_testWifiConfig = "testWifiName\n11:12:13:14:15:16\ntestWifiPwd\n2412\n1";

using namespace testing::ext;
namespace OHOS {
class P2pDeviceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

void P2pDeviceTest::SetUpTestCase()
{
    InitSoftBusServer();
    AuthCommonInit();
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

static const P2pLinkPeerDevStateCb g_testCb = {
    .onMyRoleChange = TestOnMyRoleChange,
    .onDevOffline = TestOnDevOffline,
};

static cJSON *TestAddMacIpToJson(const char *mac, const char *ip, const int64_t *result, const char *wifiConfig)
{
    cJSON *json = cJSON_CreateObject();
    if (json == nullptr) {
        return nullptr;
    }

    if (!AddStringToJsonObject(json, KEY_MAC, mac) || !AddStringToJsonObject(json, KEY_IP, ip) ||
        !AddStringToJsonObject(json, KEY_SELF_WIFI_CONFIG, wifiConfig) ||
        !AddNumber64ToJsonObject(json, KEY_RESULT, *result)) {
        cJSON_Delete(json);
        return nullptr;
    }
    return json;
}

static ConnectedNode g_testConnectedNode = {
    .peerMac = "11:11:11:11:11:11",
    .peerIp = "1.1.1.1",
    .localIp = "192.168.1.1",
    .chanId = {
        .inAuthId = 101,
        .p2pAuthId = 102,
        .authRequestId = 103,
        .p2pAuthIdState = P2PLINK_AUTHCHAN_FINISH,
    },
};

static ConnectingNode g_testConnectingNode = {
    .connInfo = {
        .requestId = 111,
        .authId = 112,
        .peerMac = "01:02:03:04:05:06",
        .expectedRole = ROLE_GO,
        .pid = 113,
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

static int32_t TestAddConnedDev(ConnectedNode *connedItem, ConnectedNode *conn, ConnectingNode *conningItem)
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

static AuthConnInfo *TestAddAuthChan(const P2pLinkNegoConnResult *conn)
{
    char *peerMac = nullptr;
    AuthConnInfo *authInfo = NULL;
    int32_t ret;

    authInfo = (AuthConnInfo *)SoftBusCalloc(sizeof(AuthConnInfo) + P2P_MAC_LEN);
    if (authInfo != NULL) {
        authInfo->type = AUTH_LINK_TYPE_P2P;
        authInfo->info.ipInfo.port = conn->goPort;
        ret = strcpy_s(authInfo->info.ipInfo.ip, sizeof(authInfo->info.ipInfo.ip), conn->peerIp);
        if (ret != EOK) {
            SoftBusFree(authInfo);
            return nullptr;
        }
        peerMac = (char *)(authInfo + 1);
        ret = strcpy_s(peerMac, P2P_MAC_LEN, conn->peerMac);
        if (ret != EOK) {
            SoftBusFree(authInfo);
            return nullptr;
        }
    }
    return authInfo;
}

/*
* @tc.name: P2pLinkControlMsgProcTest001
* @tc.desc: some diff param in P2pLinkControlMsgProc.
* @tc.type: FUNC
* @tc.require:
*/

HWTEST_F(P2pDeviceTest, P2pLinkControlMsgProcTest001, TestSize.Level1)
{
    P2pLinkSetDevStateCallback(&g_testCb);
    P2pLinkDevOffLineNotify(g_testPeerMac);
    P2pLinkCmdType testType = CMD_CTRL_CHL_HANDSHAKE;
    P2pLinkSetState(true);
    bool ret = P2pLinkIsEnable();
    EXPECT_EQ(true, ret);
    cJSON *testJson = TestAddMacIpToJson(g_testMac, g_testIp, &g_testResult, g_testWifiConfig);
    ASSERT_TRUE(testJson != nullptr);
    P2pLinkControlMsgProc(g_testAuthId, g_testSeq, testType, testJson);

    ret = P2pLinkIsEnable();
    EXPECT_EQ(true, ret);
    testType = CMD_REUSE_RESPONSE;
    P2pLinkControlMsgProc(g_testAuthId, g_testSeq, testType, testJson);

    ret = P2pLinkIsEnable();
    EXPECT_EQ(true, ret);
    testType = CMD_REUSE;
    P2pLinkControlMsgProc(g_testAuthId, g_testSeq, testType, testJson);

    ret = P2pLinkIsEnable();
    EXPECT_EQ(true, ret);
    testType = CMD_DISCONNECT_COMMAND;
    P2pLinkControlMsgProc(g_testAuthId, g_testSeq, testType, testJson);

    ret = P2pLinkIsEnable();
    EXPECT_EQ(true, ret);
    testType = CMD_GC_WIFI_CONFIG_STATE_CHANGE;
    P2pLinkControlMsgProc(g_testAuthId, g_testSeq, testType, testJson);

    ret = P2pLinkIsEnable();
    EXPECT_EQ(true, ret);
    testType = CMD_STOP;
    P2pLinkControlMsgProc(g_testAuthId, g_testSeq, testType, testJson);
}

/*
* @tc.name: P2pLinkPackReuseResponseTest001
* @tc.desc: some diff param in P2pLinkPackReuseResponse.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pDeviceTest, P2pLinkPackReuseResponseTest001, TestSize.Level1)
{
    char *ret = P2pLinkPackReuseResponse(nullptr, g_testResult);
    EXPECT_EQ(nullptr, ret);

    ret = P2pLinkPackReuseResponse(g_testMac, g_testResult);
    EXPECT_NE(nullptr, ret);
}

/*
* @tc.name: P2pLinkPackDisconnectCmdTest001
* @tc.desc: some diff param in P2pLinkPackDisconnectCmd.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pDeviceTest, P2pLinkPackDisconnectCmdTest001, TestSize.Level1)
{
    char *ret = P2pLinkPackDisconnectCmd(nullptr);
    EXPECT_EQ(nullptr, ret);

    ret = P2pLinkPackDisconnectCmd(g_testMac);
    EXPECT_NE(nullptr, ret);
}

/*
* @tc.name: P2pLinkUnPackDisconnectCmdTest001
* @tc.desc: some diff param in P2pLinkUnPackDisconnectCmd.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pDeviceTest, P2pLinkUnPackDisconnectCmdTest001, TestSize.Level1)
{
    char testMac[P2P_MAC_LEN] = {0};
    cJSON *root = TestAddMacIpToJson(g_testMac, g_testIp, &g_testResult, g_testWifiConfig);
    ASSERT_TRUE(root != nullptr);
    int32_t ret = P2pLinkUnPackDisconnectCmd(root, testMac, sizeof(testMac));
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = P2pLinkUnPackDisconnectCmd(root, nullptr, sizeof(testMac));
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
* @tc.name: P2pLinkPackHandshakeTest001
* @tc.desc: some diff param in P2pLinkPackHandshake.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pDeviceTest, P2pLinkPackHandshakeTest001, TestSize.Level1)
{
    char *ret = P2pLinkPackHandshake(nullptr, g_testIp);
    EXPECT_EQ(nullptr, ret);

    ret = P2pLinkPackHandshake(g_testMac, nullptr);
    EXPECT_EQ(nullptr, ret);

    ret = P2pLinkPackHandshake(g_testMac, g_testIp);
    EXPECT_NE(nullptr, ret);
}

/*
* @tc.name: P2pLinkSendReuseResponseTest001
* @tc.desc: some diff param in P2pLinkSendReuseResponse.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pDeviceTest, P2pLinkSendReuseResponseTest001, TestSize.Level1)
{
    P2pLinkAuthId testChan = {
        .inAuthId = 1,
        .p2pAuthId = 2,
        .authRequestId = 3,
        .p2pAuthIdState = P2PLINK_AUTHCHAN_CREATEING,
    };
    const char *testMyMac = "11:22:33:44:55:66";
    int32_t ret = P2pLinkSendReuseResponse(&testChan, const_cast<char *>(testMyMac), g_testResult);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = P2pLinkSendReuse(&testChan, nullptr);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/*
* @tc.name: P2pLinkHandleHandshakeTest001
* @tc.desc: some diff param in P2pLinkHandleHandshake.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pDeviceTest, P2pLinkHandleHandshakeTest001, TestSize.Level1)
{
    int32_t ret = P2pLinkDevInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    ConnectingNode *testItem = (ConnectingNode *)SoftBusCalloc(sizeof(ConnectingNode));
    ASSERT_TRUE(testItem != nullptr);
    ConnectedNode *testConnItem = (ConnectedNode *)SoftBusCalloc(sizeof(ConnectedNode));
    ASSERT_TRUE(testConnItem != nullptr);

    ret = TestAddConnedDev(testConnItem, &g_testConnectedNode, testItem);
    ASSERT_EQ(SOFTBUS_OK, ret);

    ret = P2pLinkConnedIsEmpty();
    EXPECT_EQ(SOFTBUS_OK, ret);

    P2pLinkAddConnedDev(testConnItem);
    bool res = DevIsNeedAdd(g_testConnectedNode.peerMac);
    EXPECT_EQ(false, res);

    cJSON *testJson = TestAddMacIpToJson(g_testConnectingNode.peerMac, g_testIp, &g_testResult, g_testWifiConfig);
    ASSERT_TRUE(testJson != nullptr);
    P2pLinkHandleHandshake(g_testAuthId, g_testSeq, nullptr);
    P2pLinkHandleHandshake(g_testAuthId, g_testSeq, testJson);

    cJSON *errJson = TestAddMacIpToJson(g_testMac, g_testIp, &g_testResult, g_testWifiConfig);
    ASSERT_TRUE(errJson != nullptr);
    P2pLinkHandleHandshake(g_testAuthId, g_testSeq, errJson);

    int32_t errAuthId = -1;
    P2pLinkUpdateInAuthId(g_testPeerMac, errAuthId);
    P2pLinkUpdateInAuthId(g_testPeerMac, g_testAuthId);
}

/*
* @tc.name: P2pLinkHandleReuseRequestTest001
* @tc.desc: some diff param in P2pLinkHandleReuseRequest.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pDeviceTest, P2pLinkHandleReuseRequestTest001, TestSize.Level1)
{
    cJSON *testJson = TestAddMacIpToJson(g_testConnectingNode.peerMac, g_testIp, &g_testResult, g_testWifiConfig);
    ASSERT_TRUE(testJson != nullptr);
    P2pLinkHandleReuseRequest(g_testAuthId, g_testSeq, nullptr);

    P2pLinkSetRole(ROLE_GC);
    P2pLinkRole myRole = P2pLinkGetRole();
    EXPECT_EQ(ROLE_GC, myRole);
    P2pLinkHandleReuseRequest(g_testAuthId, g_testSeq, testJson);

    cJSON *errJson = TestAddMacIpToJson(g_testPeerMac, g_testIp, &g_testResult, g_testWifiConfig);
    ASSERT_TRUE(errJson != nullptr);
    P2pLinkHandleReuseRequest(g_testAuthId, g_testSeq, errJson);

    P2pLinkDevInit();
    P2pLinkHandleReuseRequest(g_testAuthId, g_testSeq, testJson);

    P2pLinkSetRole(ROLE_GO);
    myRole = P2pLinkGetRole();
    EXPECT_EQ(ROLE_GO, myRole);
    P2pLinkHandleReuseRequest(g_testAuthId, g_testSeq, testJson);

    P2pLinkHandleReuseRequest(g_testAuthId, g_testSeq, testJson);
}

/*
* @tc.name: P2pLinkHandleDisconnectCmdTest001
* @tc.desc: some diff param in P2pLinkHandleDisconnectCmd.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pDeviceTest, P2pLinkHandleDisconnectCmdTest001, TestSize.Level1)
{
    cJSON *testJson = TestAddMacIpToJson(g_testConnectingNode.peerMac, g_testIp, &g_testResult, g_testWifiConfig);
    ASSERT_TRUE(testJson != nullptr);

    P2pLinkSetRole(ROLE_NONE);
    P2pLinkRole myRole = P2pLinkGetRole();
    EXPECT_EQ(ROLE_NONE, myRole);
    P2pLinkHandleDisconnectCmd(g_testAuthId, g_testSeq, testJson);

    P2pLinkInitRef();
    P2pLinkSetRole(ROLE_GO);
    myRole = P2pLinkGetRole();
    EXPECT_EQ(ROLE_GO, myRole);
    P2pLinkHandleDisconnectCmd(g_testAuthId, g_testSeq, testJson);

    P2pLinkAddMyP2pRef();
    P2pLinkHandleDisconnectCmd(g_testAuthId, g_testSeq, nullptr);
    P2pLinkHandleDisconnectCmd(g_testAuthId, g_testSeq, testJson);

    testJson = TestAddMacIpToJson(g_testConnectedNode.peerMac, g_testIp, &g_testResult, g_testWifiConfig);
    ASSERT_TRUE(testJson != nullptr);
    P2pLinkHandleDisconnectCmd(g_testAuthId, g_testSeq, testJson);
}

/*
* @tc.name: P2pLinkHandleWifiCfgTest001
* @tc.desc: some diff param in P2pLinkHandleWifiCfg.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pDeviceTest, P2pLinkHandleWifiCfgTest001, TestSize.Level1)
{
    cJSON *testJson = cJSON_CreateObject();
    ASSERT_TRUE(testJson != nullptr);
    bool ret = AddStringToJsonObject(testJson, KEY_SELF_WIFI_CONFIG, g_testWifiConfig);
    ASSERT_EQ(true, ret);
    P2pLinkHandleWifiCfg(g_testAuthId, g_testSeq, nullptr);
    P2pLinkHandleWifiCfg(g_testAuthId, g_testSeq, testJson);
}

/*
* @tc.name: P2pLinkonAuthChannelCloseTest001
* @tc.desc: some diff param in PP2pLinkonAuthChannelClose.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pDeviceTest, P2pLinkonAuthChannelCloseTest001, TestSize.Level1)
{
    uint32_t testAuthRequestId = 13;
    P2pLinkonAuthChannelClose(testAuthRequestId);
    int32_t ret = P2pLinkDevInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = P2pLinkConnedIsEmpty();
    EXPECT_EQ(SOFTBUS_OK, ret);

    testAuthRequestId = 103;
    P2pLinkonAuthChannelClose(testAuthRequestId);
    ret = P2pLinkConnedIsEmpty();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ConnectingNode *testItem = (ConnectingNode *)SoftBusCalloc(sizeof(ConnectingNode));
    ASSERT_TRUE(testItem != nullptr);
    ConnectedNode *testConnItem = (ConnectedNode *)SoftBusCalloc(sizeof(ConnectedNode));
    ASSERT_TRUE(testConnItem != nullptr);

    ret = TestAddConnedDev(testConnItem, &g_testConnectedNode, testItem);
    ASSERT_EQ(SOFTBUS_OK, ret);
    P2pLinkAddConnedDev(testConnItem);
}

/*
* @tc.name: P2pLinkLnnSyncSetGoMacTest001
* @tc.desc: some diff param in P2pLinkLnnSyncSetGoMac.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pDeviceTest, P2pLinkLnnSyncSetGoMacTest001, TestSize.Level1)
{
    int32_t ret = LnnInitLocalLedger();
    ASSERT_EQ(SOFTBUS_OK, ret);

    P2pLinkConnectInfo testRequestInfo = {
        .requestId = 2,
        .authId = 1,
        .peerMac = "11:12:13:14:15:16",
        .expectedRole = ROLE_GO,
        .pid = 3,
        .cb = {
            .onConnected = TestOnConnected,
            .onConnectFailed = TestOnConnectFailed,
        },
    };

    ret = P2pLinkLnnSyncSetGoMac();
    EXPECT_EQ(SOFTBUS_OK, ret);

    P2pLinkSetRole(ROLE_GC);
    ret = P2pLinkGetRole();
    EXPECT_EQ(ROLE_GC, ret);
    P2pLinkLnnSync();

    ret = P2pLinkInit();
    ASSERT_EQ(SOFTBUS_OK, ret);
    P2pLinkSendStartRequestToNego(&testRequestInfo);
}

/*
* @tc.name: LoopOpenP2pAuthSuccessTest001
* @tc.desc: some diff param in LoopOpenP2pAuthSuccess.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pDeviceTest, LoopOpenP2pAuthSuccessTest001, TestSize.Level1)
{
    P2pLoopMsg testType = P2PLOOP_MSG_TEST;
    P2pAuthSuccessInfo *testArg = (P2pAuthSuccessInfo *)SoftBusCalloc(sizeof(P2pAuthSuccessInfo));
    ASSERT_NE(nullptr, testArg);

    LoopOpenP2pAuthSuccess(testType, nullptr);
    testArg->authId = 1;
    testArg->requestId = 3;

    LoopOpenP2pAuthSuccess(testType, testArg);

    testArg = (P2pAuthSuccessInfo *)SoftBusCalloc(sizeof(P2pAuthSuccessInfo));
    ASSERT_NE(nullptr, testArg);
    testArg->requestId = 103;
    LoopOpenP2pAuthSuccess(testType, testArg);

    testArg = (P2pAuthSuccessInfo *)SoftBusCalloc(sizeof(P2pAuthSuccessInfo));
    ASSERT_NE(nullptr, testArg);
    testArg->authId = 102;
    LoopOpenP2pAuthSuccess(testType, testArg);

    uint32_t errRequestId = 12;
    int32_t testReason = -1;
    OpenP2pAuthSuccess(g_testConnectedNode.chanId.authRequestId, g_testConnectedNode.chanId.p2pAuthId);
    OpenP2pAuthFail(errRequestId, testReason);
}

/*
* @tc.name: LoopOpenP2pAuthChanTest001
* @tc.desc: some diff param in LoopOpenP2pAuthChan.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pDeviceTest, LoopOpenP2pAuthChanTest001, TestSize.Level1)
{
    P2pLinkNegoConnResult testConn = {
        .localIp = "192.168.1.1",
        .localMac = "01:01:01:01:01:01",
        .peerIp = "1.1.1.1",
        .peerMac = "11:11:11:11:11:11",
        .goPort = 1001,
        .authId = 11,
    };
    P2pLoopMsg testType = P2PLOOP_MSG_TEST;
    LoopOpenP2pAuthChan(testType, nullptr);

    int32_t ret = strcpy_s(testConn.peerMac, P2P_MAC_LEN, g_testPeerMac);
    ASSERT_EQ(EOK, ret);
    AuthConnInfo *testAuthInfo = TestAddAuthChan((const P2pLinkNegoConnResult *)&testConn);
    ASSERT_NE(nullptr, testAuthInfo);
    LoopOpenP2pAuthChan(testType, (void *)testAuthInfo);

    ret = strcpy_s(testConn.peerMac, P2P_MAC_LEN, g_testConnectedNode.peerMac);
    ASSERT_EQ(EOK, ret);
    testAuthInfo = TestAddAuthChan((const P2pLinkNegoConnResult *)&testConn);
    ASSERT_NE(nullptr, testAuthInfo);
    LoopOpenP2pAuthChan(testType, (void *)testAuthInfo);

    P2pLinkSetDisconnectState(true);
    testAuthInfo = TestAddAuthChan((const P2pLinkNegoConnResult *)&testConn);
    ASSERT_NE(nullptr, testAuthInfo);
    LoopOpenP2pAuthChan(testType, (void *)testAuthInfo);

    P2pLinkSetDisconnectState(false);
    testAuthInfo = TestAddAuthChan((const P2pLinkNegoConnResult *)&testConn);
    ASSERT_NE(nullptr, testAuthInfo);
    LoopOpenP2pAuthChan(testType, (void *)testAuthInfo);

    int32_t testGcPort = 0;
    P2pLinkSetGcPort(testGcPort);
    testAuthInfo = TestAddAuthChan((const P2pLinkNegoConnResult *)&testConn);
    ASSERT_NE(nullptr, testAuthInfo);
    LoopOpenP2pAuthChan(testType, (void *)testAuthInfo);

    testGcPort = 2;
    P2pLinkSetGcPort(testGcPort);
    testAuthInfo = TestAddAuthChan((const P2pLinkNegoConnResult *)&testConn);
    ASSERT_NE(nullptr, testAuthInfo);
    LoopOpenP2pAuthChan(testType, (void *)testAuthInfo);

    P2pLinkStartOpenP2pAuthChan(&testConn);
    P2pLinkNegoSuccessSetGoInfo(&testConn);
}

/*
* @tc.name: P2pLinkNegoSuccessAddConnedItemTest001
* @tc.desc: some diff param in P2pLinkNegoSuccessAddConnedItem.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pDeviceTest, P2pLinkNegoSuccessAddConnedItemTest001, TestSize.Level1)
{
    P2pLinkNegoConnResult testConn = {
        .localIp = "192.168.2.2",
        .localMac = "02:02:02:02:02:02",
        .peerIp = "2.2.2.2",
        .peerMac = "22:22:22:22:22:22",
        .goPort = 1001,
        .authId = 22,
    };

    int32_t ret = P2pLinkNegoSuccessAddConnedItem((const P2pLinkNegoConnResult *)&testConn,
        (const ConnectingNode *)&g_testConnectingNode);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
*
* @tc.name: P2pLinkNegoConnectedTest001
* @tc.desc: some diff param in P2pLinkNegoConnected.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pDeviceTest, P2pLinkNegoConnectedTest001, TestSize.Level1)
{
    P2pLinkNegoConnResult testConn = {
        .localIp = "192.168.3.3",
        .localMac = "03:03:02:02:02:02",
        .peerIp = "3.3.3.3",
        .peerMac = "33:33:33:33:33:33",
        .goPort = 1003,
        .authId = 33,
    };
    P2pLinkNegoConnected(nullptr);
    P2pLinkSetRole(ROLE_GC);
    EXPECT_EQ(ROLE_GC, P2pLinkGetRole());

    P2pLinkNegoConnected((const P2pLinkNegoConnResult *)&testConn);
    P2pLinkNegoConnected((const P2pLinkNegoConnResult *)&testConn);

    P2pLinkUpdateRole(nullptr);
    EXPECT_EQ(ROLE_NONE, P2pLinkGetRole());

    P2pLinkGroup testGroup;
    testGroup.role = ROLE_GC;
    P2pLinkUpdateRole(&testGroup);
    EXPECT_EQ(ROLE_GC, P2pLinkGetRole());

    int32_t ret = P2pLinkMagicInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
*
* @tc.name: P2pLinkAddPidMacRefTest001
* @tc.desc: some diff param in P2pLinkAddPidMacRef.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pDeviceTest, P2pLinkAddPidMacRefTest001, TestSize.Level1)
{
    int32_t testPid = 1;
    P2pLinkInitRef();
    EXPECT_EQ(nullptr, FindPidItem(testPid));
    P2pLinkAddPidMacRef(testPid, g_testMac);
    EXPECT_NE(nullptr, FindPidItem(testPid));
    P2pLinkAddPidMacRef(testPid, g_testMac);

    P2pLinkAddPidMacRef(testPid, g_testPeerMac);
    EXPECT_NE(nullptr, FindPidItem(testPid));

    testPid = 11;
    P2pLinkDelPidRef(testPid);
    P2pLinkDelPidMacRef(testPid, g_testMac);
    EXPECT_EQ(nullptr, FindPidItem(testPid));

    testPid = 1;
    P2pLinkDelPidRef(testPid);

    EXPECT_EQ(nullptr, FindPidItem(testPid));
    P2pLinkAddPidMacRef(testPid, g_testMac);
    EXPECT_EQ(nullptr, FindPidItem(testPid + 1));
    P2pLinkAddPidMacRef(testPid + 1, g_testPeerMac);

    int32_t errPid = 111;
    const char *errMac = "00:00:00:00:00:00";
    P2pLinkDelPidMacRef(errPid, g_testMac);
    EXPECT_EQ(nullptr, FindPidItem(errPid));

    P2pLinkDelPidMacRef(testPid, errMac);
    EXPECT_NE(nullptr, FindPidItem(testPid));
    P2pLinkDelPidMacRef(testPid, g_testMac);

    P2pLinkDelPidMacRef(testPid + 1, g_testPeerMac);
    EXPECT_EQ(nullptr, FindPidItem(testPid + 1));
}

/*
*
* @tc.name: P2pLinGetMacRefCntTest001
* @tc.desc: some diff param in P2pLinGetMacRefCnt.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pDeviceTest, P2pLinGetMacRefCntTest001, TestSize.Level1)
{
    int32_t testPid = 12;
    int32_t errPid = 22;
    P2pLinkInitRef();
    EXPECT_EQ(nullptr, FindPidItem(testPid));
    P2pLinkAddPidMacRef(testPid, g_testMac);

    DisConnectByPid(errPid);
    EXPECT_EQ(nullptr, FindPidItem(errPid));

    DisConnectByPid(testPid);
}
} // namespace OHOS