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

namespace OHOS {
using namespace testing::ext;

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
}

void LnnConnectionFsmTest::TearDownTestCase()
{
    LooperDeinit();
}

void LnnConnectionFsmTest::SetUp()
{
}

void LnnConnectionFsmTest::TearDown()
{
}

LnnConnectionFsm *CreateConnectionFsm(){
    ConnectionAddr target;
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
    LnnConnectionFsm *connFsm = LnnCreateConnectionFsm(target);
    EXPECT_TRUE(connFsm == nullptr);
}

/*
* @tc.name: LNN_DESTROY_CONNECTION_FSM_TEST_001
* @tc.desc: test LnnDestroyConnectionFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_DESTROY_CONNECTION_FSM_TEST_001, TestSize.Level0)
{
    LnnConnectionFsm *connFsm = nullptr;
    LnnDestroyConnectionFsm(connFsm);
    EXPECT_TRUE(connFsm == nullptr);
}

/*
* @tc.name: LNN_START_CONNECTION_FSM_TEST_001
* @tc.desc: test LnnStartConnectionFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_START_CONNECTION_FSM_TEST_001, TestSize.Level0)
{
    LnnConnectionFsm *connFsm = nullptr;
    int32_t ret = LnnStartConnectionFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    connFsm = CreateConnectionFsm();
    ret = LnnStartConnectionFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDestroyConnectionFsm(connFsm);
}

/*
* @tc.name: LNN_STOP_CONNECTION_FSM_TEST_001
* @tc.desc: test LnnStopConnectionFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_STOP_CONNECTION_FSM_TEST_001, TestSize.Level0)
{
    LnnConnectionFsm *connFsm = nullptr;
    int32_t ret = LnnStopConnectionFsm(connFsm, FsmStopCallback);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    connFsm = CreateConnectionFsm();
    ret = LnnStopConnectionFsm(connFsm, FsmStopCallback);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDestroyConnectionFsm(connFsm);
}

/*
* @tc.name: LNN_SEND_JOIN_REQUEST_TO_CONNFSM_TEST_001
* @tc.desc: test LnnSendJoinRequestToConnFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_SEND_JOIN_REQUEST_TO_CONNFSM_TEST_001, TestSize.Level0)
{
    LnnConnectionFsm *connFsm = CreateConnectionFsm();
    int32_t ret = LnnSendJoinRequestToConnFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDestroyConnectionFsm(connFsm);
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
    LnnConnectionFsm *connFsm = CreateConnectionFsm();
    int32_t ret = LnnSendAuthResultMsgToConnFsm(connFsm, retCode);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDestroyConnectionFsm(connFsm);
}

/*
* @tc.name: LNN_SEND_NOT_TRUSTED_TO_CONNFSM_TEST_001
* @tc.desc: test LnnSendNotTrustedToConnFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_SEND_NOT_TRUSTED_TO_CONNFSM_TEST_001, TestSize.Level0)
{
    LnnConnectionFsm *connFsm = CreateConnectionFsm();
    int32_t ret = LnnSendNotTrustedToConnFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDestroyConnectionFsm(connFsm);
}

/*
* @tc.name: LNN_SEND_DISCONNECT_MSG_TO_CONNFSM_TEST_001
* @tc.desc: test LnnSendDisconnectMsgToConnFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_SEND_DISCONNECT_MSG_TO_CONNFSM_TEST_001, TestSize.Level0)
{
    LnnConnectionFsm *connFsm = CreateConnectionFsm();
    int32_t ret = LnnSendDisconnectMsgToConnFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDestroyConnectionFsm(connFsm);
}

/*
* @tc.name: LNN_SEND_LEAVE_REQUEST_TO_CONNFSM_TEST_001
* @tc.desc: test LnnSendLeaveRequestToConnFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_SEND_LEAVE_REQUEST_TO_CONNFSM_TEST_001, TestSize.Level0)
{
    LnnConnectionFsm *connFsm = CreateConnectionFsm();
    int32_t ret = LnnSendLeaveRequestToConnFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDestroyConnectionFsm(connFsm);
}

/*
* @tc.name: LNN_SEND_SYNC_OFFLINE_FINISH_TO_CONNFSM_TEST_001
* @tc.desc: test LnnSendSyncOfflineFinishToConnFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_SEND_SYNC_OFFLINE_FINISH_TO_CONNFSM_TEST_001, TestSize.Level0)
{
    LnnConnectionFsm *connFsm = CreateConnectionFsm();
    int32_t ret = LnnSendSyncOfflineFinishToConnFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDestroyConnectionFsm(connFsm);
}

/*
* @tc.name: LNN_SEND_NEW_NETWORK_ONLINE_TO_CONNFSM_TEST_001
* @tc.desc: test LnnSendNewNetworkOnlineToConnFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_SEND_NEW_NETWORK_ONLINE_TO_CONNFSM_TEST_001, TestSize.Level0)
{
    LnnConnectionFsm *connFsm = CreateConnectionFsm();
    int32_t ret = LnnSendNewNetworkOnlineToConnFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnDestroyConnectionFsm(connFsm);
}
} // namespace OHOS
