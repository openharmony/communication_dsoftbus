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

#include <gtest/gmock.h>
#include <gtest/gtest.h>
#include <securec.h>

#include "auth_mock.h"
#include "bus_center_event_mock.h"
#include "bus_center_manager.h"
#include "lnn_connection_fsm.h"
#include "lnn_net_builder.h"
#include "lnn_node_info.h"
#include "message_handler.h"
#include "softbus_adapter_timer.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;
class ConnFsmMockTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ConnFsmMockTest::SetUpTestCase()
{
    LooperInit();
}

void ConnFsmMockTest::TearDownTestCase()
{
    LooperDeinit();
}

void ConnFsmMockTest::SetUp() { }

void ConnFsmMockTest::TearDown() { }

static void LnnConnectionFsmStopCallback(struct tagLnnConnectionFsm *connFsm)
{
    (void)connFsm;
    return;
}

/*
 * @tc.name: CONN_FSM_MOCK_TEST_001
 * @tc.desc: test LnnCreateConnectionFsm
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnFsmMockTest, CONN_FSM_MOCK_TEST_001, TestSize.Level1)
{
    LnnConnectionFsm *connFsm = nullptr;
    connFsm = LnnCreateConnectionFsm(nullptr, nullptr);
    EXPECT_TRUE(connFsm == nullptr);

    ConnectionAddr addr;
    (void)memset_s(&add, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    connFsm = LnnCreateConnectionFsm(&addr, "pkgName");
    EXPECT_TRUE(connFsm != nullptr);

    LnnDestroyConnectionFsm(connFsm);
}

/*
 * @tc.name: CONN_FSM_MOCK_TEST_002
 * @tc.desc: test LnnStartConnectionFsm
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnFsmMockTest, CONN_FSM_MOCK_TEST_002, TestSize.Level1)
{
    LnnConnectionFsm *connFsm = nullptr;
    ConnectionAddr addr;
    int32_t ret = 0;
    (void)memset_s(&add, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    connFsm = LnnCreateConnectionFsm(&addr, "pkgName");
    EXPECT_TRUE(connFsm != nullptr);

    ret = LnnStartConnectionFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = LnnStopConnectionFsm(connFsm, LnnConnectionFsmStopCallback);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    SoftBusSleepMs(500);
    LnnDestroyConnectionFsm(connFsm);
}

/*
 * @tc.name: CONN_FSM_MOCK_TEST_003
 * @tc.desc: test process joinLnn msg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnFsmMockTest, CONN_FSM_MOCK_TEST_003, TestSize.Level1)
{
    LnnConnectionFsm *connFsm = nullptr;
    ConnectionAddr addr;
    int32_t ret = 0;
    (void)memset_s(&add, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    connFsm = LnnCreateConnectionFsm(&addr, "pkgName");
    EXPECT_TRUE(connFsm != nullptr);

    ret = LnnStartConnectionFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    AuthInterfaceMock authMock;
    BusCenterEventMock busCenterMock;
    ON_CALL(authMock, AuthGenRequestId()).WillByDefault(Return(1));
    EXPECT_CALL(authMock, AuthStartVerify(_, _, _, _, _))
        .WillOnce(Return(SOFTBUS_OK))
        .WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ON_CALL(busCenterMock, LnnNotifyJoinResult(_, _, _)).WillByDefault(Return());
    ret = LnnSendJoinRequestToConnFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_NETWORK_BLE_DISABLE);

    ret = LnnStopConnectionFsm(connFsm, LnnConnectionFsmStopCallback);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    SoftBusSleepMs(500);
    LnnDestroyConnectionFsm(connFsm);
}

/*
 * @tc.name: CONN_FSM_MOCK_TEST_004
 * @tc.desc: test process authDone msg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ConnFsmMockTest, CONN_FSM_MOCK_TEST_004, TestSize.Level1)
{
    ConnectionAddr addr;
    (void)memset_s(&add, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    LnnConnectionFsm *connFsm = LnnCreateConnectionFsm(&addr, "pkgName");
    int32_t ret = LnnStartConnectionFsm(connFsm);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = LnnSendAuthResultMsgToConnFsm(connFsm, SOFTBUS_OK);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = LnnStopConnectionFsm(connFsm, LnnConnectionFsmStopCallback);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    SoftBusSleepMs(500);
    LnnDestroyConnectionFsm(connFsm);
}
} // namespace OHOS
