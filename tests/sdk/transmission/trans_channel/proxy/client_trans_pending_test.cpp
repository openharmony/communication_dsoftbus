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
#include "securec.h"

#include "client_trans_pending.h"
#include "client_trans_proxy_file_manager.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define TEST_SESSION_ID 0
#define TEST_SEQ 1
#define TEST_SESSION_ID_SECOND 2
#define TEST_SEQ_SECOND 2
#define TEST_WAIT_ACK_TIME 10

using namespace std;
using namespace testing::ext;

namespace OHOS {
class ClientTransPendingTest : public testing::Test {
public:
    ClientTransPendingTest() {}
    ~ClientTransPendingTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void ClientTransPendingTest::SetUpTestCase(void)
{
    int32_t ret = InitPendingPacket();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransClientInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}
void ClientTransPendingTest::TearDownTestCase(void) {}

/**
 * @tc.name: TransPendingTest001
 * @tc.desc: client trans pending test,use the wrong or normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransPendingTest, TransPendingTest, TestSize.Level0)
{
    uint32_t id = 1;
    uint64_t seq = 0;

    int32_t ret = CreatePendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = CreatePendingPacket(TEST_SESSION_ID, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = CreatePendingPacket(id, TEST_SEQ);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = CreatePendingPacket(id, seq);
    EXPECT_EQ(SOFTBUS_ALREADY_EXISTED, ret);

    uint32_t waitMillis = TEST_WAIT_ACK_TIME;
    ret = GetPendingPacketData(id, seq, waitMillis, true, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    TransPendData pendDate = {0};
    ret = GetPendingPacketData(TEST_SESSION_ID_SECOND, TEST_SEQ_SECOND, waitMillis, true, &pendDate);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    ret = GetPendingPacketData(TEST_SESSION_ID_SECOND, seq, waitMillis, true, &pendDate);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    ret = GetPendingPacketData(id, TEST_SEQ_SECOND, waitMillis, true, &pendDate);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    ret = SetPendingPacketData(id, seq, &pendDate);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SetPendingPacketData(id, seq, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = SetPendingPacketData(TEST_SESSION_ID_SECOND, TEST_SEQ_SECOND, &pendDate);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    ret = SetPendingPacketData(TEST_SESSION_ID_SECOND, seq, &pendDate);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    ret = SetPendingPacketData(id, TEST_SEQ_SECOND, &pendDate);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);

    ret = GetPendingPacketData(id, seq, waitMillis, false, &pendDate);
    EXPECT_EQ(SOFTBUS_ALREADY_TRIGGERED, ret);

    ret = GetPendingPacketData(id, TEST_SEQ, waitMillis, true, &pendDate);
    EXPECT_EQ(SOFTBUS_TIMOUT, ret);

    DeletePendingPacket(id, seq);

    DeletePendingPacket(TEST_SESSION_ID, seq);

    DeletePendingPacket(id, TEST_SEQ);

    DeletePendingPacket(TEST_SESSION_ID_SECOND, TEST_SEQ_SECOND);
}
} // namespace OHOS nvv