/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>
#include "p2plink_manager.h"
#include "softbus_log.h"
#include "p2plink_interface.h"
#include "p2plink_message.c"
#include "p2plink_channel_freq.h"
#include "softbus_errcode.h"
#include "p2plink_json_payload.h"
#include "softbus_json_utils.h"
#include "softbus_adapter_mem.h"
#include "p2plink_common.h"
#include "p2plink_state_machine.h"
#include "p2plink_adapter.h"
#include "softbus_server_frame.h"
#include "p2plink_device.c"
#include "p2plink_state_machine.c"
#include "p2plink_broadcast_receiver.h"
#include "p2plink_control_message.h"
#include "message_handler.h"

#define TEST_FREQUENCY_INVALID (-1)
#define MAX_STRING_NUM 5
#define TEST_FREQUENCY_2G_FIRST 2412
#define TEST_GC_FREQUENCY 2432
#define TEST_DATA_NUM 1
#define TEST_DEL_MS 500
using namespace testing::ext;
namespace OHOS {
class ConnectionP2PFuncTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

void SetUp()
{
    InitSoftBusServer();
}

static void TestP2pLinkNegoSuccess(int32_t requestId, const P2pLinkNegoConnResult *result)
{
    printf("TestP2pLinkNegoSuccess\n");
}

static void TestP2pLinkNegoFail(int32_t requestId, int32_t reason)
{
    printf("TestP2pLinkNegoFail\n");
}

static void TestP2pLinkNegoConnected(const P2pLinkNegoConnResult *result)
{
    printf("TestP2pLinkNegoConnected\n");
}

static P2pLinkNegoCb g_testP2pLinkNegoCb = {
    .onConnected = TestP2pLinkNegoSuccess,
    .onConnectFailed = TestP2pLinkNegoFail,
    .onPeerConnected = TestP2pLinkNegoConnected,
};

/*
* @tc.name: testP2pLinkLoopDisconnectDev001
* @tc.desc: arg is NULL
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkLoopDisconnectDev001, TestSize.Level1)
{
    P2pLinkLoopDisconnectDev(P2PLOOP_P2PAUTHCHAN_OK, nullptr);
    EXPECT_EQ(true, true);
}

/*
* @tc.name: testP2pLinkLoopDisconnectDev002
* @tc.desc: test ConnTypeIsSupport
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkLoopDisconnectDev002, TestSize.Level1)
{
    auto *info = static_cast<P2pLinkDisconnectInfo *>(SoftBusMalloc(sizeof(P2pLinkDisconnectInfo)));
    ASSERT_TRUE(info != nullptr);
    info->pid = 11;
    info->authId = 11;
    (void)strcpy_s(info->peerMac, sizeof(info->peerMac), "abc");

    P2pLinkLoopDisconnectDev(P2PLOOP_P2PAUTHCHAN_OK, info);
    EXPECT_EQ(true, true);
}

/*
* @tc.name: testP2pLinkNeoDataProcess001
* @tc.desc: param is NULL
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkNeoDataProcess001, TestSize.Level1)
{
    P2pLinkNeoDataProcess(P2PLOOP_P2PAUTHCHAN_OK, nullptr);
    EXPECT_EQ(true, true);
}

/*
* @tc.name: testP2pLinkNegoDataRecv001
* @tc.desc: param is NULL
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkNegoDataRecv001, TestSize.Level1)
{
    int64_t authId = 11;
    AuthTransData *data = nullptr;
    P2pLinkNegoDataRecv(authId, data);
    EXPECT_EQ(true, true);
}

/*
* @tc.name: testP2pLinkSendMessage001
* @tc.desc: param is NULL
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkSendMessage001, TestSize.Level1)
{
    char data[] = "data";
    int ret = P2pLinkSendMessage(11, data, strlen(data));
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
* @tc.name: testP2plinkGetGroupGrequency001
* @tc.desc: Use different parameters to convert the channel list to a string.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2plinkChannelListToString001, TestSize.Level1)
{
    P2pLink5GList *testChannelList = (P2pLink5GList *)SoftBusCalloc(sizeof(P2pLink5GList) +
        sizeof(int32_t) * TEST_DATA_NUM);
    ASSERT_TRUE(testChannelList != nullptr);

    testChannelList->num = TEST_DATA_NUM;
    const char *testString = "10";
    testChannelList->chans[0] = atoi(testString);
    char testChannelString[] = "aaabbb";
    int32_t len = sizeof(testChannelList->chans);
    int32_t ret = P2plinkChannelListToString(nullptr, testChannelString, len);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = P2plinkChannelListToString(testChannelList, nullptr, len);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = P2plinkChannelListToString(testChannelList, testChannelString, 0);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    ret = P2plinkChannelListToString(testChannelList, testChannelString, len - 1);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    ret = P2plinkChannelListToString(testChannelList, testChannelString, len);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    testChannelList->num = 0;
    ret = P2plinkChannelListToString(testChannelList, testChannelString, len);
    EXPECT_EQ(ret, SOFTBUS_OK);
    testChannelList->num = TEST_DATA_NUM;
}

/*
* @tc.name: testP2pLinkUpateAndGetStationFreq001
* @tc.desc: some diff param in P2pLinkUpateAndGetStationFreq update and get freq.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkUpateAndGetStationFreq001, TestSize.Level1)
{
    P2pLink5GList *testChannelList = (P2pLink5GList *)SoftBusCalloc(sizeof(P2pLink5GList) +
        sizeof(int32_t) * TEST_DATA_NUM);
    ASSERT_TRUE(testChannelList != nullptr);

    testChannelList->num = TEST_DATA_NUM;
    const char *testString = "22";
    testChannelList->chans[0] = atoi(testString);

    int32_t ret = P2pLinkUpateAndGetStationFreq(nullptr);
    EXPECT_EQ(ret, TEST_FREQUENCY_INVALID);

    testChannelList->num = 0;
    ret = P2pLinkUpateAndGetStationFreq(testChannelList);
    EXPECT_EQ(ret, TEST_FREQUENCY_INVALID);
    testChannelList->num = 1;

    ret = P2pLinkUpateAndGetStationFreq(testChannelList);
    EXPECT_EQ(ret, TEST_FREQUENCY_INVALID);
}

/*
* @tc.name: testP2pLinkParseItemDataByDelimit001
* @tc.desc: some diff param in P2pLinkParseItemDataByDelimit to list.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkParseItemDataByDelimit001, TestSize.Level1)
{
    char *testList[MAX_STRING_NUM] = {nullptr};
    int32_t testOutNum = 0;
    char testString[] = "aaa\nbbb\nccc\nddd\neee";

    P2pLinkParseItemDataByDelimit(testString, "\n", testList, MAX_STRING_NUM, &testOutNum);
    EXPECT_GE(testOutNum, MAX_STRING_NUM);
    int32_t ret = strcmp(testList[0], "aaa");
    EXPECT_EQ(EOK, ret);

    testOutNum = 0;
    P2pLinkParseItemDataByDelimit(nullptr, "\n", testList, MAX_STRING_NUM, &testOutNum);
    EXPECT_EQ(testOutNum, 0);

    P2pLinkParseItemDataByDelimit(testString, nullptr, testList, MAX_STRING_NUM, &testOutNum);
    EXPECT_EQ(testOutNum, 0);

    P2pLinkParseItemDataByDelimit(testString, "\n", nullptr, MAX_STRING_NUM, &testOutNum);
    EXPECT_EQ(testOutNum, 0);

    P2pLinkParseItemDataByDelimit(testString, "\n", testList, 0, &testOutNum);
    EXPECT_EQ(testOutNum, 0);

    P2pLinkParseItemDataByDelimit(testString, "\n", testList, MAX_STRING_NUM, nullptr);
    EXPECT_EQ(testOutNum, 0);
}

/*
* @tc.name: testP2pLinkUnpackRequestMsg001
* @tc.desc: use different parameters to parse the request msg packet.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkUnpackRequestMsg001, TestSize.Level1)
{
    cJSON *testData = cJSON_CreateObject();
    ASSERT_TRUE(testData != nullptr);
    P2pContentType testType = CONTENT_TYPE_GO_INFO;
    P2pRequestMsg testRequest;
    (void)memset_s(&testRequest, sizeof(P2pRequestMsg), 0, sizeof(P2pRequestMsg));
    P2pRequestMsg testRequestMsg = {
        .cmdType = 0,
        .version = 1,
        .role = ROLE_GC,
        .isbridgeSupport = false,
        .contentType = CONTENT_TYPE_GC_INFO,
        .myMac = "11:22:33:44:55:66",
        .wifiCfg = "testWifiCfgInfo",
    };

    int32_t ret = P2pLinkUnpackRequestMsg(nullptr, testType, &testRequest);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = P2pLinkUnpackRequestMsg(testData, testType, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = P2pLinkUnpackRequestMsg(testData, testType, &testRequest);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);

    testType = CONTENT_TYPE_GC_INFO;
    ret = P2pLinkUnpackRequestMsg(testData, testType, &testRequest);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);

    testType = CONTENT_TYPE_RESULT;
    ret = P2pLinkUnpackRequestMsg(testData, testType, &testRequest);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);

    ret = P2pLinkPackRequestMsg(&testRequestMsg, CONTENT_TYPE_RESULT, testData);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = P2pLinkUnpackRequestMsg(testData, testType, &testRequest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    cJSON_Delete(testData);
}

/*
* @tc.name: testP2plinkUnpackRepsonseMsg001
* @tc.desc: use different parameters to parse the repsonse msg packet.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2plinkUnpackRepsonseMsg001, TestSize.Level1)
{
    cJSON *testData = cJSON_CreateObject();
    ASSERT_TRUE(testData != nullptr);
    P2pContentType testType = CONTENT_TYPE_GO_INFO;
    P2pRespMsg testResponse;
    (void)memset_s(&testResponse, sizeof(P2pRespMsg), 0, sizeof(P2pRespMsg));
    P2pRespMsg testResponseMsg = {
        .cmdType = 0,
        .version = 1,
        .result = ROLE_GC,
        .contentType = CONTENT_TYPE_GC_INFO,
        .myMac = "11:22:33:44:55:66",
        .myIp = "192.168.1.1",
        .wifiCfg = "testWifiCfgInfo",
    };

    int32_t ret = P2plinkUnpackRepsonseMsg(nullptr, testType, &testResponse);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = P2plinkUnpackRepsonseMsg(testData, testType, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = P2plinkUnpackRepsonseMsg(testData, testType, &testResponse);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);

    testType = CONTENT_TYPE_GC_INFO;
    ret = P2plinkUnpackRepsonseMsg(testData, testType, &testResponse);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);

    testType = CONTENT_TYPE_RESULT;
    ret = P2plinkUnpackRepsonseMsg(testData, testType, &testResponse);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);

    ret = P2plinkPackRepsonseMsg(&testResponseMsg, CONTENT_TYPE_RESULT, testData);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = P2plinkUnpackRepsonseMsg(testData, testType, &testResponse);
    EXPECT_EQ(ret, SOFTBUS_OK);

    cJSON_Delete(testData);
}

/*
* @tc.name: testP2pLinkNegoInit001
* @tc.desc: some diff param in P2pLinkNegoInit.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkNegoInit001, TestSize.Level1)
{
    int32_t ret = P2pLinkNegoInit(nullptr);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = P2pLinkNegoInit(&g_testP2pLinkNegoCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
* @tc.name: testP2pLinkNegoStart001
* @tc.desc: Start a negotiation with right parameters.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkNegoStarts001, TestSize.Level1)
{
    P2pLinkNegoConnInfo testConnInfo = {
        .authId = 1,
        .requestId = 1,
        .expectRole = ROLE_AUTO,
        .peerMac = "11:22:33:44:55:66",
    };

    int32_t ret = P2pLinkManagerInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    P2pLinkNegoStart(&testConnInfo);
    P2pLinkNegoStop();
}

/*
* @tc.name: testGetP2pLinkNegoStatus001
* @tc.desc: Gets the current negotiation status.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testGetP2pLinkNegoStatus001, TestSize.Level1)
{

    int32_t ret = P2pLinkNegoInit(&g_testP2pLinkNegoCb);
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = GetP2pLinkNegoStatus();
    EXPECT_EQ(ret, P2PLINK_NEG_IDLE);
}

/*
* @tc.name: testP2pLinkNegoMsgProc001
* @tc.desc: Send different types of messages for negotiation.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkNegoMsgProc001, TestSize.Level1)
{
    cJSON *testData = cJSON_CreateObject();
    ASSERT_TRUE(testData != nullptr);
    P2pLinkCmdType testCmdType = CMD_CONNECT_RESPONSE;
    int64_t authId = 1;
    P2pLinkNegoMsgProc(authId, testCmdType, nullptr);

    P2pLinkNegoMsgProc(authId, testCmdType, testData);

    testCmdType = CMD_CONNECT_REQUEST;
    P2pLinkNegoMsgProc(authId, testCmdType, testData);

    cJSON_Delete(testData);
}

/*
* @tc.name: testP2pLinkNegoOnGroupChanged001
* @tc.desc: Different group data is modified to negotiate the group.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkNegoOnGroupChanged001, TestSize.Level1)
{
    P2pLinkGroup group;

    int32_t ret = P2pLinkNegoInit(&g_testP2pLinkNegoCb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    P2pLinkNegoOnGroupChanged(nullptr);
    P2pLinkNegoOnGroupChanged(&group);
}

/*
* @tc.name: testP2pLinkNegoOnConnectState001
* @tc.desc: Change the link to negotiate the recv connection state change.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkNegoOnConnectState001, TestSize.Level1)
{
    P2pLinkConnState testState = P2PLINK_CONNECTING;

    int32_t ret = P2pLinkNegoInit(&g_testP2pLinkNegoCb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    P2pLinkNegoOnConnectState(testState);
}

/*
* @tc.name: testP2pLinkNegoGetFinalRole001
* @tc.desc: Different roles at both ends get the final role.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkNegoGetFinalRole001, TestSize.Level1)
{
    P2pLinkRole testMyRole = ROLE_GO;
    P2pLinkRole testPeerRole = ROLE_GO;
    bool isSupportBridge = false;
    const char *testMyGoMac = "11:22:33:44:55:66";
    const char *testPeerGoMac = "11:22:33:44:55:66";

    int32_t ret = P2pLinkNegoInit(&g_testP2pLinkNegoCb);
    ASSERT_EQ(ret, SOFTBUS_OK);

    P2pLinkSetRole(testMyRole);
    P2pLinkSetGoMac(testMyGoMac);
    ret = P2pLinkNegoGetFinalRole(testPeerRole, testPeerRole, testPeerGoMac, isSupportBridge);
    EXPECT_EQ(ret, ERROR_BOTH_GO);

    testMyRole = ROLE_GC;
    P2pLinkSetRole(testMyRole);
    P2pLinkSetGoMac(testMyGoMac);
    ret = P2pLinkNegoGetFinalRole(testPeerRole, testPeerRole, testPeerGoMac, isSupportBridge);
    EXPECT_EQ(ret, ROLE_GC);


    testMyRole = ROLE_NONE;
    P2pLinkSetRole(testMyRole);
    P2pLinkSetGoMac(testMyGoMac);
    ret = P2pLinkNegoGetFinalRole(testPeerRole, testPeerRole, testPeerGoMac, isSupportBridge);
    EXPECT_EQ(ret, ROLE_GC);
}

/*
* @tc.name: testP2pLinkFsmInit001
* @tc.desc: some diff param in P2pLinkFsmInit.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkFsmInit001, TestSize.Level1)
{
    FsmStateMachine *testFsm = (FsmStateMachine *)SoftBusCalloc(sizeof(FsmStateMachine));
    ASSERT_TRUE(testFsm != nullptr);
    int32_t ret = P2pLinkFsmInit(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = P2pLinkFsmInit(testFsm);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusFree(testFsm);
}

/*
* @tc.name: testP2pLinkFsmDeinit001
* @tc.desc: some diff param in P2pLinkFsmDeinit.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkFsmDeinit001, TestSize.Level1)
{
    FsmStateMachine *testFsm = (FsmStateMachine *)SoftBusCalloc(sizeof(FsmStateMachine));
    ASSERT_TRUE(testFsm != nullptr);
    P2pLinkFsmDeinit(nullptr);

    int32_t ret = P2pLinkFsmInit(testFsm);
    ASSERT_EQ(ret, SOFTBUS_OK);
    P2pLinkFsmDeinit(testFsm);
    P2pLinkFsmDeinit(testFsm);

    SoftBusFree(testFsm);
}

/*
* @tc.name: testP2pLinkFsmAddState001
* @tc.desc: some diff param in P2pLinkFsmAddState.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkFsmAddState001, TestSize.Level1)
{
    FsmStateMachine *testFsm = (FsmStateMachine *)SoftBusCalloc(sizeof(FsmStateMachine));
    ASSERT_TRUE(testFsm != nullptr);
    FsmState *testState = (FsmState *)SoftBusCalloc(sizeof(FsmState));
    ASSERT_TRUE(testState != nullptr);

    int32_t ret = P2pLinkFsmInit(testFsm);
    ASSERT_EQ(ret, SOFTBUS_OK);

    P2pLinkFsmAddState(nullptr, testState);
    bool res = IsExistState(testFsm, testState);
    EXPECT_TRUE(res == false);
    P2pLinkFsmAddState(testFsm, nullptr);
    res = IsExistState(testFsm, testState);
    EXPECT_TRUE(res == false);
    P2pLinkFsmAddState(testFsm, testState);
    P2pLinkFsmAddState(testFsm, testState);
    res = IsExistState(testFsm, testState);
    EXPECT_TRUE(res == true);

    SoftBusFree(testFsm);
    SoftBusFree(testState);
}

/*
* @tc.name: testP2pLinkFsmStart001
* @tc.desc: some diff param in P2pLinkFsmStart.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkFsmStart001, TestSize.Level1)
{
    FsmStateMachine *testFsm = (FsmStateMachine *)SoftBusCalloc(sizeof(FsmStateMachine));
    ASSERT_TRUE(testFsm != nullptr);
    FsmState *testInitialState = (FsmState *)SoftBusCalloc(sizeof(FsmState));
    ASSERT_TRUE(testInitialState != nullptr);

    int32_t ret = P2pLinkFsmInit(testFsm);
    ASSERT_EQ(ret, SOFTBUS_OK);

    P2pLinkFsmStart(testFsm, testInitialState);
    testFsm->currentState =nullptr;
    P2pLinkFsmStart(testFsm, testInitialState);

    P2pLinkFsmAddState(testFsm, testInitialState);
    P2pLinkFsmStart(testFsm, testInitialState);

    P2pLinkFsmStop(testFsm);
    EXPECT_TRUE(testFsm->currentState == NULL);
    P2pLinkFsmStop(testFsm);

    SoftBusFree(testFsm);
    SoftBusFree(testInitialState);
}

/*
* @tc.name: testP2pLinkFsmTransactState001
* @tc.desc: some diff param in P2pLinkFsmTransactState.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkFsmTransactState001, TestSize.Level1)
{
    FsmStateMachine *testFsm = (FsmStateMachine *)SoftBusCalloc(sizeof(FsmStateMachine));
    ASSERT_TRUE(testFsm != nullptr);
    FsmState *testState = (FsmState *)SoftBusCalloc(sizeof(FsmState));
    ASSERT_TRUE(testState != nullptr);

    int32_t ret = P2pLinkNegoInit(&g_testP2pLinkNegoCb);
    ASSERT_EQ(ret, SOFTBUS_OK);
    P2pLinkNegoStop();

    P2pLinkFsmTransactState(nullptr, testState);
    P2pLinkFsmTransactState(testFsm, nullptr);

    testFsm->currentState = nullptr;
    P2pLinkFsmTransactState(testFsm, testState);

    SoftBusFree(testFsm);
    SoftBusFree(testState);
}

/*
* @tc.name: testP2pLinkFsmMsgProc001
* @tc.desc: some diff param in P2pLinkFsmMsgProc.
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(ConnectionP2PFuncTest, testP2pLinkFsmMsgProc001, TestSize.Level1)
{
    FsmStateMachine *testFsm = (FsmStateMachine *)SoftBusCalloc(sizeof(FsmStateMachine));
    ASSERT_TRUE(testFsm != nullptr);

    P2pLoopMsg testMsgType = WAIT_CONN_TIME_OUT;
    int32_t ret = P2pLinkManagerInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    testFsm->currentState = nullptr;
    P2pLinkFsmMsgProc(testFsm, testMsgType, nullptr);

    SoftBusFree(testFsm);
}
} // namespace OHOS