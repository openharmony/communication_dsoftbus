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

#include "lnn_auth_mock.h"
#include "lnn_connection_fsm.h"
#include "lnn_net_builder.h"
#include "lnn_net_builder_deps_mock.h"
#include "lnn_service_mock.h"
#include "message_handler.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

constexpr char IP[IP_STR_MAX_LEN] = "127.0.0.1";
constexpr uint16_t PORT = 1000;
constexpr char PEERUID[MAX_ACCOUNT_HASH_LEN] = "021315ASD";

namespace OHOS {
using namespace testing;
using namespace testing::ext;

static LnnConnectionFsm *connFsm = nullptr;
static ConnectionAddr target = {
    .type = CONNECTION_ADDR_WLAN,
    .info.ip.port = PORT,
};
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
    memcpy_s(target.peerUid, MAX_ACCOUNT_HASH_LEN, PEERUID, strlen(PEERUID));
    memcpy_s(target.info.ip.ip, IP_STR_MAX_LEN, IP, strlen(IP));
    connFsm2 = LnnCreateConnectionFsm(&target);
    EXPECT_TRUE(connFsm2 != nullptr);
}

void LnnConnectionFsmTest::TearDownTestCase()
{
    LooperDeinit();
    LnnDestroyConnectionFsm(connFsm2);
}

void LnnConnectionFsmTest::SetUp()
{
}

void LnnConnectionFsmTest::TearDown()
{
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
HWTEST_F(LnnConnectionFsmTest, LNN_CREATE_CONNECTION_FSM_TEST_001, TestSize.Level1)
{
    ConnectionAddr *target1 = nullptr;
    LnnConnectionFsm *fsm = LnnCreateConnectionFsm(target1);
    EXPECT_TRUE(fsm == nullptr);
}

/*
* @tc.name: LNN_DESTROY_CONNECTION_FSM_TEST_001
* @tc.desc: test LnnDestroyConnectionFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_DESTROY_CONNECTION_FSM_TEST_001, TestSize.Level1)
{
    LnnConnectionFsm *fsm = nullptr;
    LnnDestroyConnectionFsm(fsm);
}

/*
* @tc.name: LNN_START_CONNECTION_FSM_TEST_001
* @tc.desc: test LnnStartConnectionFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_START_CONNECTION_FSM_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnStartConnectionFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = LnnStartConnectionFsm(connFsm2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusSleepMs(200);
}

/*
* @tc.name: LNN_SEND_JOIN_REQUEST_TO_CONNFSM_TEST_001
* @tc.desc: test LnnSendJoinRequestToConnFsm
* @tc.type: FUNC
* @tc.require: I5PRUD
*/
HWTEST_F(LnnConnectionFsmTest, LNN_SEND_JOIN_REQUEST_TO_CONNFSM_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnStartConnectionFsm(connFsm2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    NiceMock<LnnAuthtInterfaceMock> authMock;
    NiceMock<NetBuilderDepsInterfaceMock> netBuilderMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    ON_CALL(netBuilderMock, AuthGenRequestId).WillByDefault(Return(1));
    EXPECT_CALL(authMock, AuthStartVerify).WillOnce(Return(SOFTBUS_OK)).WillRepeatedly(Return(SOFTBUS_ERR));
    ON_CALL(serviceMock, LnnNotifyJoinResult).WillByDefault(Return());
    ret = LnnSendJoinRequestToConnFsm(connFsm2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusSleepMs(1000);
}
} // namespace OHOS
