/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "softbus_log.h"
#include "softbus_error_code.h"
#include "p2plink_loop.h"
#include "p2plink_type.h"
#include "exception_branch_checker.h"
#include "p2plink_negotiation.c"
#include "negotiation_mock.h"

using namespace testing::ext;
using testing::Return;

namespace OHOS {
class P2pNegotiationTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

/*
* @tc.name: P2pLinkNeoConnRequestProcTest001
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, P2pLinkNeoConnRequestProcTest001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pLinkNeoConnRequestProcTest001, Start");
    NegotiationMock negotiationMock;
    negotiationMock.SetupSuccessStub();
    int64_t authIdTest = 10;
    const cJSON *dataTest = nullptr;
    EXPECT_CALL(negotiationMock, P2pLinkIsEnable).WillRepeatedly(Return(false));
    ExceptionBranchChecker checkerOne("p2p link is not enable");
    P2pLinkNeoConnRequestProc(authIdTest, dataTest);
    EXPECT_EQ(checkerOne.GetResult(), true);

    ExceptionBranchChecker checkerTwo("get peer mac failed");
    EXPECT_CALL(negotiationMock, P2pLinkIsEnable).WillRepeatedly(Return(true));
    EXPECT_CALL(negotiationMock, GetJsonObjectStringItem).WillRepeatedly(Return(false));
    P2pLinkNeoConnRequestProc(authIdTest, dataTest);
    EXPECT_EQ(checkerTwo.GetResult(), true);

    ExceptionBranchChecker checkerThree("local dev is disconnecting state");
    EXPECT_CALL(negotiationMock, P2pLinkIsEnable).WillRepeatedly(Return(true));
    EXPECT_CALL(negotiationMock, GetJsonObjectStringItem).WillRepeatedly(Return(true));
    EXPECT_CALL(negotiationMock, P2pLinkIsDisconnectState).WillRepeatedly(Return(true));
    P2pLinkNeoConnRequestProc(authIdTest, dataTest);
    EXPECT_EQ(checkerThree.GetResult(), true);

    EXPECT_CALL(negotiationMock, P2pLinkIsDisconnectState).WillRepeatedly(Return(false));
    P2pLinkNeoConnRequestProc(authIdTest, dataTest);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pLinkNeoConnRequestProcTest001, End");
}

bool ActionOfGetJsonObjectNumberItemOne(const cJSON *json, const char * const string, int *target)
{
    *target = CONTENT_TYPE_GC_INFO;
    return true;
}

bool ActionOfGetJsonObjectNumberItemTwo(const cJSON *json, const char * const string, int *target)
{
    *target = CONTENT_TYPE_RESULT;
    return true;
}

/*
* @tc.name: P2pLinkNeoConnResponseProcTest001
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, P2pLinkNeoConnResponseProcTest001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pLinkNeoConnResponseProcTest001, Start");
    NegotiationMock negotiationMock;
    negotiationMock.SetupSuccessStub();
    int64_t authIdTest = 10;
    const cJSON *dataTest = nullptr;

    ExceptionBranchChecker checkerOne("response message failed.");
    EXPECT_CALL(negotiationMock, P2plinkUnpackRepsonseMsg).WillRepeatedly(Return(SOFTBUS_ERR));
    P2pLinkNeoConnResponseProc(authIdTest, dataTest);
    EXPECT_EQ(checkerOne.GetResult(), true);

    EXPECT_CALL(negotiationMock, GetJsonObjectNumberItem).WillRepeatedly(ActionOfGetJsonObjectNumberItemOne);
    P2pLinkNeoConnResponseProc(authIdTest, dataTest);

    EXPECT_CALL(negotiationMock, GetJsonObjectNumberItem).WillRepeatedly(ActionOfGetJsonObjectNumberItemTwo);
    P2pLinkNeoConnResponseProc(authIdTest, dataTest);

    EXPECT_CALL(negotiationMock, P2plinkUnpackRepsonseMsg).WillRepeatedly(Return(SOFTBUS_OK));
    P2pLinkNeoConnResponseProc(authIdTest, dataTest);

    EXPECT_CALL(negotiationMock, GetJsonObjectNumberItem).WillRepeatedly(Return(false));
    ExceptionBranchChecker checkerTwo("get content type from json failed.");
    P2pLinkNeoConnResponseProc(authIdTest, dataTest);
    EXPECT_EQ(checkerTwo.GetResult(), true);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pLinkNeoConnResponseProcTest001, End");
}

/*
* @tc.name: RoleNegoStateProcessTest001
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, RoleNegoStateProcessTest001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "RoleNegoStateProcessTest001, Start");
    NegotiationMock negotiationMock;
    negotiationMock.SetupSuccessStub();
    P2pLoopMsg msgTypeTest = CONN_REQUEST_TIME_OUT;
    ExceptionBranchChecker checkerOne("invoke timeout");
    RoleNegoStateProcess(msgTypeTest, nullptr);
    EXPECT_EQ(checkerOne.GetResult(), true);

    P2pRespMsg p2PRespMsgTest;
    msgTypeTest = CONN_RESPONSE;
    ExceptionBranchChecker checkerTwo("ActionOfP2pLinkFsmMsgProcDelayDel");
    RoleNegoStateProcess(msgTypeTest, &p2PRespMsgTest);
    EXPECT_EQ(checkerTwo.GetResult(), true);

    msgTypeTest = WAIT_ROLE_NEG_TIME_OUT;
    RoleNegoStateProcess(msgTypeTest, &p2PRespMsgTest);

    msgTypeTest = CONN_REQUEST;
    cJSON *cJson = cJSON_CreateObject();
    RoleNegoStateProcess(msgTypeTest, cJson);
    cJSON_Delete(cJson);

    msgTypeTest = CONN_RESPONSE_FAILED;
    ExceptionBranchChecker checkerThree("unsupport message type");
    RoleNegoStateProcess(msgTypeTest, nullptr);
    EXPECT_EQ(checkerThree.GetResult(), true);

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "RoleNegoStateProcessTest001, End");
}

/*
* @tc.name: IsSamePeerDeviceTest001
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, IsSamePeerDeviceTest001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "IsSamePeerDeviceTest001, Start");
    NegotiationMock negotiationMock;
    negotiationMock.SetupSuccessStub();
    cJSON *cJson = cJSON_CreateObject();
    EXPECT_CALL(negotiationMock, GetJsonObjectStringItem).WillRepeatedly(Return(false));
    bool ret = IsSamePeerDevice(cJson);
    EXPECT_EQ(ret, false);

    EXPECT_CALL(negotiationMock, GetJsonObjectStringItem).WillRepeatedly(Return(true));
    ret = IsSamePeerDevice(cJson);
    EXPECT_EQ(ret, true);
    cJSON_Delete(cJson);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "IsSamePeerDeviceTest001, End");
}

/*
* @tc.name: RoleNegoStateOnResponseRecvTest001
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, RoleNegoStateOnResponseRecvTest001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "RoleNegoStateOnResponseRecvTest001, Start");
    NegotiationMock negotiationMock;
    negotiationMock.SetupSuccessStub();
    P2pRespMsg p2PRespMsg;
    p2PRespMsg.contentType = CONTENT_TYPE_GO_INFO;
    RoleNegoStateOnResponseRecv(&p2PRespMsg);

    p2PRespMsg.contentType = CONTENT_TYPE_GC_INFO;
    RoleNegoStateOnResponseRecv(&p2PRespMsg);

    p2PRespMsg.contentType = CONTENT_TYPE_RESULT;
    ExceptionBranchChecker checkerOne("receive peer errcode");
    RoleNegoStateOnResponseRecv(&p2PRespMsg);
    EXPECT_EQ(checkerOne.GetResult(), true);

    EXPECT_CALL(negotiationMock, P2pLinkSetPeerWifiCfgInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    ExceptionBranchChecker checkerTwo("negotiation state failed");
    RoleNegoStateOnResponseRecv(&p2PRespMsg);
    EXPECT_EQ(checkerTwo.GetResult(), true);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "RoleNegoStateOnResponseRecvTest001, End");
}

/*
* @tc.name: ConnectingStateProcessTest001
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, ConnectingStateProcessTest001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ConnectingStateProcessTest001, Start");
    NegotiationMock negotiationMock;
    negotiationMock.SetupSuccessStub();
    P2pLoopMsg msgTypeTest = MAGICLINK_CONN_GROUP_TIME_OUT;
    int32_t state = P2PLINK_CONNECTING;
    ExceptionBranchChecker checkerOne("ActionOfP2pLinkRemoveGroup");
    ConnectingStateProcess(msgTypeTest, &state);
    EXPECT_EQ(checkerOne.GetResult(), true);

    msgTypeTest = MAGICLINK_ON_CONNECTED;
    ExceptionBranchChecker checkerTwo("connect state : connecting.");
    ConnectingStateProcess(msgTypeTest, &state);
    EXPECT_EQ(checkerTwo.GetResult(), true);

    msgTypeTest = MAGICLINK_ON_GROUP_CHANGED;
    ConnectingStateProcess(msgTypeTest, &state);

    msgTypeTest = CONN_REQUEST;
    ConnectingStateProcess(msgTypeTest, &state);

    msgTypeTest = CONN_RESPONSE_FAILED;
    ExceptionBranchChecker checkerThree("unsupport message type");
    ConnectingStateProcess(msgTypeTest, nullptr);
    EXPECT_EQ(checkerThree.GetResult(), true);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ConnectingStateProcessTest001, End");
}

/*
* @tc.name: ConnectingStateOnConnectStateChangedTest001
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, ConnectingStateOnConnectStateChangedTest001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ConnectingStateOnConnectStateChangedTest001, Start");
    NegotiationMock negotiationMock;
    negotiationMock.SetupSuccessStub();
    int32_t state = P2PLINK_CONNECTING;
    ExceptionBranchChecker checkerOne("connect state : connecting.");
    ConnectingStateOnConnectStateChanged(&state);
    EXPECT_EQ(checkerOne.GetResult(), true);

    state = P2PLINK_CONNECTED;
    ExceptionBranchChecker checkerTwo("connect state : connected.");
    ConnectingStateOnConnectStateChanged(&state);
    EXPECT_EQ(checkerTwo.GetResult(), true);

    state = P2PLINK_CONNECT_FAILED;
    ConnectingStateOnConnectStateChanged(&state);

    state = P2PLINK_CONNECTING - 1;
    ExceptionBranchChecker checkerThree("unsupport connect state");
    ConnectingStateOnConnectStateChanged(&state);
    EXPECT_EQ(checkerThree.GetResult(), true);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "ConnectingStateOnConnectStateChangedTest001, End");
}

/*
* @tc.name: GroupCreateStateProcessTest001
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, GroupCreateStateProcessTest001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "GroupCreateStateProcessTest001, Start");
    NegotiationMock negotiationMock;
    negotiationMock.SetupSuccessStub();
    ExceptionBranchChecker checkerOne("invoke timeout");
    P2pLoopMsg p2PLoopMsg = MAGICLINK_CREATE_GROUP_TIME_OUT;
    GroupCreateStateProcess(p2PLoopMsg, nullptr);
    EXPECT_EQ(checkerOne.GetResult(), true);

    ExceptionBranchChecker checkerTwo("ActionOfP2pLinkFsmMsgProcDelayDel");
    p2PLoopMsg = MAGICLINK_ON_GROUP_CHANGED;
    P2pLinkGroup p2PLinkGroup;
    GroupCreateStateProcess(p2PLoopMsg, &p2PLinkGroup);
    EXPECT_EQ(checkerTwo.GetResult(), true);

    int32_t param = 1;
    p2PLoopMsg = CONN_REQUEST_FAILED;
    GroupCreateStateProcess(p2PLoopMsg, &param);

    p2PLoopMsg = CONN_RESPONSE_FAILED;
    GroupCreateStateProcess(p2PLoopMsg, &param);

    p2PLoopMsg = MAGICLINK_ON_CONNECTED;
    GroupCreateStateProcess(p2PLoopMsg, &param);

    p2PLoopMsg = CONN_REQUEST;
    GroupCreateStateProcess(p2PLoopMsg, &param);

    ExceptionBranchChecker checkerThree("unsupport message type");
    p2PLoopMsg = DHCP_TIME_OUT;
    GroupCreateStateProcess(p2PLoopMsg, &param);
    EXPECT_EQ(checkerThree.GetResult(), true);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "GroupCreateStateProcessTest001, End");
}

/*
* @tc.name: WaitConnectStateProcessTest001
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, WaitConnectStateProcessTest001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WaitConnectStateProcessTest001, Start");
    NegotiationMock negotiationMock;
    negotiationMock.SetupSuccessStub();
    ExceptionBranchChecker checkerOne("ActionOfP2pLinkFsmMsgProcDelayDel");
    P2pLoopMsg p2PLoopMsg = CONN_RESPONSE;
    P2pRespMsg p2PRespMsg;
    WaitConnectStateProcess(p2PLoopMsg, &p2PRespMsg);
    EXPECT_EQ(checkerOne.GetResult(), true);

    p2PLoopMsg = CONN_REQUEST_TIME_OUT;
    WaitConnectStateProcess(p2PLoopMsg, &p2PRespMsg);

    P2pLinkGroup p2PLinkGroup;
    p2PLoopMsg = MAGICLINK_ON_GROUP_CHANGED;
    WaitConnectStateProcess(p2PLoopMsg, &p2PLinkGroup);

    p2PLoopMsg = CONN_REQUEST;
    WaitConnectStateProcess(p2PLoopMsg, &p2PRespMsg);

    p2PLoopMsg = WAIT_CONN_TIME_OUT;
    WaitConnectStateProcess(p2PLoopMsg, &p2PRespMsg);

    ExceptionBranchChecker checkerTwo("unsupport message type");
    p2PLoopMsg = P2PLOOP_MSG_PROC;
    WaitConnectStateProcess(p2PLoopMsg, &p2PRespMsg);
    EXPECT_EQ(checkerTwo.GetResult(), true);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "WaitConnectStateProcessTest001, End");
}


/*
* @tc.name: P2pNegotiation001
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, P2pNegotiation001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation001, Start");
    ExceptionBranchChecker checkerOne("idle state enter");
    IdleStateEnter();
    EXPECT_EQ(checkerOne.GetResult(), true);
    ExceptionBranchChecker checkerTwo("idle state exit");
    IdleStateExit();
    EXPECT_EQ(checkerTwo.GetResult(), true);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation001, End");
}

/*
* @tc.name: P2pNegotiation002
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, P2pNegotiation002, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation002, Start");
    ExceptionBranchChecker checkerOne("role negotiation state enter");
    RoleNegoStateEnter();
    EXPECT_EQ(checkerOne.GetResult(), true);
    ExceptionBranchChecker checkerTwo("role negotiation state exit");
    RoleNegoStateExit();
    EXPECT_EQ(checkerTwo.GetResult(), true);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation002, End");
}

/*
* @tc.name: P2pNegotiation003
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, P2pNegotiation003, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation003, Start");
    ExceptionBranchChecker checkerOne("group create state enter");
    GroupCreateStateEnter();
    EXPECT_EQ(checkerOne.GetResult(), true);
    ExceptionBranchChecker checkerTwo("group create state exit");
    GroupCreateStateExit();
    EXPECT_EQ(checkerTwo.GetResult(), true);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation003, End");
}

/*
* @tc.name: P2pNegotiation004
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, P2pNegotiation004, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation004, Start");
    ExceptionBranchChecker checkerOne("wait connect state enter");
    WaitConnectStateEnter();
    EXPECT_EQ(checkerOne.GetResult(), true);
    ExceptionBranchChecker checkerTwo("wait connect state enter");
    WaitConnectStateEnter();
    EXPECT_EQ(checkerTwo.GetResult(), true);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation004, End");
}

/*
* @tc.name: P2pNegotiation005
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, P2pNegotiation005, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation005, Start");
    ExceptionBranchChecker checkerOne("connecting state enter");
    ConnectingStateEnter();
    EXPECT_EQ(checkerOne.GetResult(), true);
    ExceptionBranchChecker checkerTwo("connecting state exit");
    ConnectingStateExit();
    EXPECT_EQ(checkerTwo.GetResult(), true);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation005, End");
}

/*
* @tc.name: P2pNegotiation006
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, P2pNegotiation006, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation006, Start");
    ExceptionBranchChecker checkerOne("dhcp state enter");
    DhcpStateEnter();
    EXPECT_EQ(checkerOne.GetResult(), true);
    ExceptionBranchChecker checkerTwo("dhcp state exit");
    DhcpStateExit();
    EXPECT_EQ(checkerTwo.GetResult(), true);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation006, End");
}

/*
* @tc.name: P2pNegotiation007
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, P2pNegotiation007, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation007, Start");
    NegotiationMock negotiationMock;
    negotiationMock.SetupSuccessStub();
    EXPECT_CALL(negotiationMock, P2pLinkGetDhcpState).WillRepeatedly(Return(true));
    int32_t ret = GetConnectTimeout();
    EXPECT_EQ(P2PLINK_DHCP_CONNECT_TIMEOUT, ret);

    EXPECT_CALL(negotiationMock, P2pLinkGetDhcpState).WillRepeatedly(Return(false));
    ret = GetConnectTimeout();
    EXPECT_EQ(P2PLINK_NEG_TIMEOUT, ret);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation007, End");
}

/*
* @tc.name: P2pNegotiation008
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, P2pNegotiation008, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation008, Start");
    char myGoMac[P2P_MAC_LEN] = {0};
    char peerGoMac[P2P_MAC_LEN] = {1};
    int32_t ret = DecideMyRoleAsGO(ROLE_GO, ROLE_GO, myGoMac, peerGoMac, false);
    EXPECT_EQ(ERROR_BOTH_GO, ret);
    ret = DecideMyRoleAsGO(ROLE_GC, ROLE_GO, myGoMac, peerGoMac, false);
    EXPECT_EQ(ERROR_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE, ret);
    ret = DecideMyRoleAsGO(ROLE_GC, ROLE_GO, nullptr, nullptr, false);
    EXPECT_EQ(ERROR_AVAILABLE_WITH_MISMATCHED_ROLE, ret);
    ret = DecideMyRoleAsGO(ROLE_GC, ROLE_GC, nullptr, nullptr, false);
    EXPECT_EQ(ROLE_GO, ret);
    ret = DecideMyRoleAsGO(ROLE_NONE, ROLE_GO, nullptr, nullptr, false);
    EXPECT_EQ(ERROR_AVAILABLE_WITH_MISMATCHED_ROLE, ret);
    ret = DecideMyRoleAsGO(ROLE_NONE, ROLE_NONE, nullptr, nullptr, false);
    EXPECT_EQ(ROLE_GO, ret);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation008, End");
}

/*
* @tc.name: P2pNegotiation009
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, P2pNegotiation009, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation009, Start");
    char myGoMac[P2P_MAC_LEN] = {0};
    char peerGoMac[P2P_MAC_LEN] = {1};
    int32_t ret = DecideMyRoleAsGC(ROLE_GO, ROLE_GO, myGoMac, myGoMac, false);
    EXPECT_EQ(ROLE_GC, ret);
    ret = DecideMyRoleAsGC(ROLE_GO, ROLE_GO, nullptr, nullptr, false);
    EXPECT_EQ(ERROR_GC_CONNECTED_TO_ANOTHER_DEVICE, ret);
    ret = DecideMyRoleAsGC(ROLE_GC, ROLE_GO, myGoMac, peerGoMac, false);
    EXPECT_EQ(ERROR_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE, ret);
    ret = DecideMyRoleAsGC(ROLE_GC, ROLE_GO, nullptr, nullptr, false);
    EXPECT_EQ(ERROR_AVAILABLE_WITH_MISMATCHED_ROLE, ret);
    ret = DecideMyRoleAsGC(ROLE_GC, ROLE_GC, nullptr, nullptr, true);
    EXPECT_EQ(ROLE_BRIDGE_GC, ret);
    ret = DecideMyRoleAsGC(ROLE_NONE, ROLE_NONE, nullptr, nullptr, true);
    EXPECT_EQ(ROLE_BRIDGE_GC, ret);
    ret = DecideMyRoleAsGC(ROLE_NONE, ROLE_GO, nullptr, nullptr, true);
    EXPECT_EQ(ERROR_AVAILABLE_WITH_MISMATCHED_ROLE, ret);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation009, End");
}

/*
* @tc.name: P2pNegotiation010
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, P2pNegotiation010, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation010, Start");
    int32_t ret = DecideMyRoleAsNone(ROLE_GO, ROLE_GC, nullptr, nullptr, false);
    EXPECT_EQ(ERROR_AVAILABLE_WITH_MISMATCHED_ROLE, ret);
    ret = DecideMyRoleAsNone(ROLE_GO, ROLE_GO, nullptr, nullptr, false);
    EXPECT_EQ(ROLE_GC, ret);
    ret = DecideMyRoleAsNone(ROLE_GC, ROLE_GO, nullptr, nullptr, false);
    EXPECT_EQ(ERROR_AVAILABLE_WITH_MISMATCHED_ROLE, ret);
    ret = DecideMyRoleAsNone(ROLE_GC, ROLE_GC, nullptr, nullptr, true);
    EXPECT_EQ(ROLE_BRIDGE_GC, ret);
    ret = DecideMyRoleAsNone(ROLE_NONE, ROLE_GC, nullptr, nullptr, true);
    EXPECT_EQ(ROLE_GO, ret);
    ret = DecideMyRoleAsNone(ROLE_NONE, ROLE_GO, nullptr, nullptr, true);
    EXPECT_EQ(ROLE_GC, ret);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "P2pNegotiationTest, P2pNegotiation010, End");
}

/*
* @tc.name: DhcpStateProcessTest001
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, DhcpStateProcessTest001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "DhcpStateProcessTest001, Start");
    NegotiationMock negotiationMock;
    negotiationMock.SetupSuccessStub();
    P2pLoopMsg msgType = MAGICLINK_ON_GROUP_CHANGED;
    ExceptionBranchChecker checkerOne("ActionOfP2pLinkFsmMsgProcDelayDel");
    DhcpStateProcess(msgType, nullptr);
    EXPECT_EQ(checkerOne.GetResult(), true);

    msgType = CONN_REQUEST;
    ExceptionBranchChecker checkerTwo("post connect response msg");
    DhcpStateProcess(msgType, nullptr);
    EXPECT_EQ(checkerTwo.GetResult(), true);

    msgType = DHCP_TIME_OUT;
    ExceptionBranchChecker checkerThree("ActionOfP2pLinkRemoveGcGroup");
    DhcpStateProcess(msgType, nullptr);
    EXPECT_EQ(checkerThree.GetResult(), true);

    ExceptionBranchChecker checkerFour("unsupport message type");
    msgType = (P2pLoopMsg)(DHCP_TIME_OUT + 1);
    DhcpStateProcess(msgType, nullptr);
    EXPECT_EQ(checkerFour.GetResult(), true);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "DhcpStateProcessTest001, End");
}

/*
* @tc.name: PackAndSendMsgTest001
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, PackAndSendMsgTest001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "PackAndSendMsgTest001, Start");
    NegotiationMock negotiationMock;
    negotiationMock.SetupSuccessStub();
    int64_t authId = 10;
    bool isRequestMsg = true;
    P2pRequestMsg request;
    int32_t ret = PackAndSendMsg(authId, isRequestMsg, &request);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(negotiationMock, P2pLinkSendMessage).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = PackAndSendMsg(authId, isRequestMsg, &request);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(negotiationMock, P2pLinkPackRequestMsg).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = PackAndSendMsg(authId, isRequestMsg, &request);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    isRequestMsg = false;
    P2pRespMsg response;
    EXPECT_CALL(negotiationMock, P2plinkPackRepsonseMsg).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = PackAndSendMsg(authId, isRequestMsg, &response);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "PackAndSendMsgTest001, End");
}

/*
* @tc.name: FillResponseInfoTest001
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, FillResponseInfoTest001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "FillResponseInfoTest001, Start");
    NegotiationMock negotiationMock;
    negotiationMock.SetupSuccessStub();
    P2pRespMsg response;
    int32_t result = P2PLINK_OK;
    response.contentType = CONTENT_TYPE_RESULT;
    int32_t ret = FillResponseInfo(&response, result);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(negotiationMock, P2pLinkGetSelfWifiCfgInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = FillResponseInfo(&response, result);
    EXPECT_EQ(ret, SOFTBUS_OK);

    response.contentType = CONTENT_TYPE_GO_INFO;
    EXPECT_CALL(negotiationMock, P2pLinkGetGroupConfigInfo).WillRepeatedly(Return(nullptr));
    ret = FillResponseInfo(&response, result);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    response.contentType = CONTENT_TYPE_GC_INFO;
    EXPECT_CALL(negotiationMock, P2plinkChannelListToString).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = FillResponseInfo(&response, result);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "FillResponseInfoTest001, End");
}

/*
* @tc.name: FillRequestInfoTest001
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, FillRequestInfoTest001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "FillRequestInfoTest001, Start");
    NegotiationMock negotiationMock;
    negotiationMock.SetupSuccessStub();
    P2pRequestMsg request;
    int32_t myRole = ROLE_GC;
    int32_t expectedRole = ROLE_GC;
    bool isbridgeSupport = false;
    request.contentType = CONTENT_TYPE_RESULT;
    int32_t ret = FillRequestInfo(&request, myRole, expectedRole, isbridgeSupport);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(negotiationMock, P2pLinkGetSelfWifiCfgInfo).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = FillRequestInfo(&request, myRole, expectedRole, isbridgeSupport);
    EXPECT_EQ(ret, SOFTBUS_OK);
    request.contentType = CONTENT_TYPE_GO_INFO;
    EXPECT_CALL(negotiationMock, P2pLinkGetGroupConfigInfo).WillRepeatedly(Return(nullptr));
    ret = FillRequestInfo(&request, myRole, expectedRole, isbridgeSupport);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "FillRequestInfoTest001, End");
}

/*
* @tc.name: PostConnRequestTest001
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, PostConnRequestTest001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "PostConnRequestTest001, Start");
    NegotiationMock negotiationMock;
    negotiationMock.SetupSuccessStub();
    int64_t authId = 0;
    const char *peerMac = nullptr;
    int32_t expectRole = ROLE_NONE;
    int32_t myRole = ROLE_GC;
    int32_t ret = PostConnRequest(authId, peerMac, expectRole, myRole);
    EXPECT_EQ(ret, SOFTBUS_OK);

    myRole = ROLE_GO;
    ret = PostConnRequest(authId, peerMac, expectRole, myRole);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(negotiationMock, P2pLinkSendMessage).WillRepeatedly(Return(SOFTBUS_ERR));
    ret = PostConnRequest(authId, peerMac, expectRole, myRole);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    EXPECT_CALL(negotiationMock, P2pLinkGetGroupConfigInfo).WillRepeatedly(Return(nullptr));
    ret = PostConnRequest(authId, peerMac, expectRole, myRole);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "PostConnRequestTest001, End");
}

/*
* @tc.name: IdleStateProcessTest001
* @tc.desc: test
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(P2pNegotiationTest, IdleStateProcessTest001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "IdleStateProcessTest001, Start");
    NegotiationMock negotiationMock;
    negotiationMock.SetupSuccessStub();
    P2pLoopMsg msgType = START_NEGOTIATION;
    P2pLinkNegoConnInfo negoConnInfo;
    ExceptionBranchChecker checkerOne("idle state process, msg type = 2");
    IdleStateProcess(msgType, &negoConnInfo);
    EXPECT_EQ(checkerOne.GetResult(), true);

    msgType = CONN_REQUEST;
    ExceptionBranchChecker checkerTwo("idle state process, msg type = 10");
    cJSON *cJson = cJSON_CreateObject();
    IdleStateProcess(msgType, cJson);
    EXPECT_EQ(checkerTwo.GetResult(), true);
    cJSON_Delete(cJson);

    msgType = DHCP_TIME_OUT;
    ExceptionBranchChecker checkerThree("unsupport message type");
    IdleStateProcess(msgType, nullptr);
    EXPECT_EQ(checkerThree.GetResult(), true);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "IdleStateProcessTest001, End");
}
};