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

#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_connection_fsm.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

constexpr char IP[IP_STR_MAX_LEN] = "127.0.0.1";
constexpr uint16_t PORT = 1000;
constexpr char PEERUID[MAX_ACCOUNT_HASH_LEN] = "021315ASD";

namespace OHOS {
using namespace testing::ext;

static LnnConnectionFsm *CreateConnectionFsm();
static LnnConnectionFsm *connFsm = nullptr;
static LnnConnectionFsm *connFsm2 = nullptr;

class LnnConnectionFsmTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LnnConnectionFsmTest::SetUpTestCase()
{
    LooperInit();
    connFsm = CreateConnectionFsm();
    connFsm2 = CreateConnectionFsm();
}

void LnnConnectionFsmTest::TearDownTestCase()
{
    LooperDeinit();
    LnnDestroyConnectionFsm(connFsm);
    LnnDestroyConnectionFsm(connFsm2);
}

void LnnConnectionFsmTest::SetUp()
{
}

void LnnConnectionFsmTest::TearDown()
{
}

LnnConnectionFsm *CreateConnectionFsm()
{
    ConnectionAddr target = {
        .type = CONNECTION_ADDR_WLAN,
        .info.ip.port = PORT
    };
    memcpy_s(target.peerUid, MAX_ACCOUNT_HASH_LEN, PEERUID, strlen(PEERUID));
    memcpy_s(target.info.ip.ip, IP_STR_MAX_LEN, IP, strlen(IP));
    LnnConnectionFsm *connFsm = LnnCreateConnectionFsm(&target);
    EXPECT_TRUE(connFsm != nullptr);
    return connFsm;
}

void FsmStopCallback(struct tagLnnConnectionFsm *connFsm)
{
}

/*
* @tc.name: LNN_CREATE_CONNECTION_FSM_TEST_001
* @tc.desc: para is null
* @tc.type: FUNC
* @tc.require:I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_CREATE_CONNECTION_FSM_TEST_001, TestSize.Level0)
{
    ConnectionAddr *target = nullptr;
    LnnConnectionFsm *fsm = LnnCreateConnectionFsm(target);
    EXPECT_TRUE(fsm == nullptr);
}

/*
* @tc.name: LNN_DESTROY_CONNECTION_FSM_TEST_001
* @tc.desc: test LnnDestroyConnectionFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_DESTROY_CONNECTION_FSM_TEST_001, TestSize.Level0)
{
    LnnConnectionFsm *fsm = nullptr;
    LnnDestroyConnectionFsm(fsm);
    EXPECT_TRUE(fsm == nullptr);
}

/*
* @tc.name: LNN_START_CONNECTION_FSM_TEST_001
* @tc.desc: test LnnStartConnectionFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_START_CONNECTION_FSM_TEST_001, TestSize.Level0)
{
    LnnConnectionFsm *fsm = nullptr;
    int32_t ret = LnnStartConnectionFsm(fsm);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnStartConnectionFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_SEND_JOIN_REQUEST_TO_CONNFSM_TEST_001
* @tc.desc: test LnnSendJoinRequestToConnFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_SEND_JOIN_REQUEST_TO_CONNFSM_TEST_001, TestSize.Level0)
{
    int32_t ret = LnnSendJoinRequestToConnFsm(connFsm2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_SEND_AUTH_RESULT_MSG_TO_CONNFSM_TEST_001
* @tc.desc: test LnnSendAuthResultMsgToConnFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_SEND_AUTH_RESULT_MSG_TO_CONNFSM_TEST_001, TestSize.Level0)
{
    int32_t retCode = 1;
    int32_t ret = LnnSendAuthResultMsgToConnFsm(connFsm2, retCode);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_SEND_NOT_TRUSTED_TO_CONNFSM_TEST_001
* @tc.desc: test LnnSendNotTrustedToConnFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_SEND_NOT_TRUSTED_TO_CONNFSM_TEST_001, TestSize.Level0)
{
    int32_t ret = LnnSendNotTrustedToConnFsm(connFsm2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_SEND_DISCONNECT_MSG_TO_CONNFSM_TEST_001
* @tc.desc: test LnnSendDisconnectMsgToConnFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_SEND_DISCONNECT_MSG_TO_CONNFSM_TEST_001, TestSize.Level0)
{
    int32_t ret = LnnSendDisconnectMsgToConnFsm(connFsm2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_SEND_LEAVE_REQUEST_TO_CONNFSM_TEST_001
* @tc.desc: test LnnSendLeaveRequestToConnFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_SEND_LEAVE_REQUEST_TO_CONNFSM_TEST_001, TestSize.Level0)
{
    int32_t ret = LnnSendLeaveRequestToConnFsm(connFsm2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_SEND_SYNC_OFFLINE_FINISH_TO_CONNFSM_TEST_001
* @tc.desc: test LnnSendSyncOfflineFinishToConnFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_SEND_SYNC_OFFLINE_FINISH_TO_CONNFSM_TEST_001, TestSize.Level0)
{
    int32_t ret = LnnSendSyncOfflineFinishToConnFsm(connFsm2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_SEND_NEW_NETWORK_ONLINE_TO_CONNFSM_TEST_001
* @tc.desc: test LnnSendNewNetworkOnlineToConnFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_SEND_NEW_NETWORK_ONLINE_TO_CONNFSM_TEST_001, TestSize.Level0)
{
    int32_t ret = LnnSendNewNetworkOnlineToConnFsm(connFsm2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
* @tc.name: LNN_STOP_CONNECTION_FSM_TEST_001
* @tc.desc: test LnnStopConnectionFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_STOP_CONNECTION_FSM_TEST_001, TestSize.Level0)
{
    LnnConnectionFsm *fsm = nullptr;
    int32_t ret = LnnStopConnectionFsm(fsm, FsmStopCallback);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
* @tc.name: ON_JOIN_META_NODE_TEST_001
* @tc.desc: test OnJoinMetaNode
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(LnnConnectionFsmTest, ON_JOIN_META_NODE_TEST_001, TestSize.Level1)
{
    MetaJoinRequestNode metaJoinNode;
    CustomData customData = {
        .type = PROXY_TRANSMISION,
        .data = {0},
    };
    int32_t ret;

    (void)memset_s(&metaJoinNode, sizeof(MetaJoinRequestNode), 0, sizeof(MetaJoinRequestNode));
    ret = OnJoinMetaNode(nullptr, &customData);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    ret = OnJoinMetaNode(&metaJoinNode, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
    metaJoinNode.addr.type = CONNECTION_ADDR_SESSION;
    ret = OnJoinMetaNode(&metaJoinNode, &customData);
    EXPECT_TRUE(ret == SOFTBUS_ERR);
}
} // namespace OHOS
