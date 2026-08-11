/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "securec.h"
#include <gtest/gtest.h>

#include "client_trans_pending.h"
#include "client_trans_proxy_file_manager.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define TEST_CHANNEL_ID    1
#define TEST_SEQ           0
#define TEST_WAIT_ACK_TIME 10

using namespace std;
using namespace testing::ext;

namespace OHOS {
class ClientTransPendingTest : public testing::Test {
public:
    ClientTransPendingTest() { }
    ~ClientTransPendingTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) override { }
    void TearDown(void) override { }
};

void ClientTransPendingTest::SetUpTestCase(void)
{
    int32_t ret = InitPendingPacket();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = TransClientInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

void ClientTransPendingTest::TearDownTestCase(void) { }

/*
 * @tc.name: CreatePendingPacketTest001
 * @tc.desc: create a new pending packet returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransPendingTest, CreatePendingPacketTest001, TestSize.Level1)
{
    uint32_t channelId = TEST_CHANNEL_ID;
    uint64_t seq = TEST_SEQ;
    int32_t ret = CreatePendingPacket(channelId, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    DeletePendingPacket(channelId, seq);
}

/*
 * @tc.name: CreatePendingPacketTest002
 * @tc.desc: create a duplicate pending packet returns already existed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransPendingTest, CreatePendingPacketTest002, TestSize.Level1)
{
    uint32_t channelId = TEST_CHANNEL_ID;
    uint64_t seq = TEST_SEQ;
    int32_t ret = CreatePendingPacket(channelId, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = CreatePendingPacket(channelId, seq);
    EXPECT_EQ(SOFTBUS_ALREADY_EXISTED, ret);
    DeletePendingPacket(channelId, seq);
}

/*
 * @tc.name: GetPendingPacketDataTest001
 * @tc.desc: get pending packet data with null data returns invalid param, get non-existent packet returns not find
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransPendingTest, GetPendingPacketDataTest001, TestSize.Level1)
{
    uint32_t channelId = TEST_CHANNEL_ID;
    uint64_t seq = TEST_SEQ;
    int32_t ret = GetPendingPacketData(channelId, seq, TEST_WAIT_ACK_TIME, true, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    TransPendData pendData = { };
    ret = GetPendingPacketData(channelId, seq, TEST_WAIT_ACK_TIME, true, &pendData);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/*
 * @tc.name: GetPendingPacketDataTest002
 * @tc.desc: get already-triggered pending packet with isdelete false returns already triggered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransPendingTest, GetPendingPacketDataTest002, TestSize.Level1)
{
    uint32_t channelId = TEST_CHANNEL_ID;
    uint64_t seq = TEST_SEQ;
    int32_t ret = CreatePendingPacket(channelId, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransPendData pendData = { };
    ret = SetPendingPacketData(channelId, seq, &pendData);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = GetPendingPacketData(channelId, seq, TEST_WAIT_ACK_TIME, false, &pendData);
    EXPECT_EQ(SOFTBUS_ALREADY_TRIGGERED, ret);
}

/*
 * @tc.name: GetPendingPacketDataTest003
 * @tc.desc: get untriggered pending packet with isdelete true times out and deletes node
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransPendingTest, GetPendingPacketDataTest003, TestSize.Level1)
{
    uint32_t channelId = TEST_CHANNEL_ID;
    uint64_t seq = TEST_SEQ;
    int32_t ret = CreatePendingPacket(channelId, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransPendData pendData = { };
    ret = GetPendingPacketData(channelId, seq, TEST_WAIT_ACK_TIME, true, &pendData);
    EXPECT_EQ(SOFTBUS_TIMOUT, ret);
}

/*
 * @tc.name: GetPendingPacketDataTest004
 * @tc.desc: get untriggered pending packet with isdelete false times out and node survives
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransPendingTest, GetPendingPacketDataTest004, TestSize.Level1)
{
    uint32_t channelId = TEST_CHANNEL_ID;
    uint64_t seq = TEST_SEQ;
    int32_t ret = CreatePendingPacket(channelId, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransPendData pendData = { };
    ret = GetPendingPacketData(channelId, seq, TEST_WAIT_ACK_TIME, false, &pendData);
    EXPECT_EQ(SOFTBUS_TIMOUT, ret);
    ret = SetPendingPacketData(channelId, seq, &pendData);
    EXPECT_EQ(SOFTBUS_OK, ret);
    DeletePendingPacket(channelId, seq);
}

/*
 * @tc.name: SetPendingPacketDataTest001
 * @tc.desc: set pending packet data with valid data on existing packet returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransPendingTest, SetPendingPacketDataTest001, TestSize.Level1)
{
    uint32_t channelId = TEST_CHANNEL_ID;
    uint64_t seq = TEST_SEQ;
    int32_t ret = CreatePendingPacket(channelId, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    TransPendData pendData = { };
    ret = SetPendingPacketData(channelId, seq, &pendData);
    EXPECT_EQ(SOFTBUS_OK, ret);
    DeletePendingPacket(channelId, seq);
}

/*
 * @tc.name: SetPendingPacketDataTest002
 * @tc.desc: set pending packet data with null data on existing packet returns ok
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransPendingTest, SetPendingPacketDataTest002, TestSize.Level1)
{
    uint32_t channelId = TEST_CHANNEL_ID;
    uint64_t seq = TEST_SEQ;
    int32_t ret = CreatePendingPacket(channelId, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = SetPendingPacketData(channelId, seq, nullptr);
    EXPECT_EQ(SOFTBUS_OK, ret);
    DeletePendingPacket(channelId, seq);
}

/*
 * @tc.name: SetPendingPacketDataTest003
 * @tc.desc: set pending packet data on non-existent packet returns not find
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransPendingTest, SetPendingPacketDataTest003, TestSize.Level1)
{
    uint32_t channelId = TEST_CHANNEL_ID;
    uint64_t seq = TEST_SEQ;
    TransPendData pendData = { };
    int32_t ret = SetPendingPacketData(channelId, seq, &pendData);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/*
 * @tc.name: DeletePendingPacketTest001
 * @tc.desc: delete existing pending packet makes subsequent get return not find
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransPendingTest, DeletePendingPacketTest001, TestSize.Level1)
{
    uint32_t channelId = TEST_CHANNEL_ID;
    uint64_t seq = TEST_SEQ;
    int32_t ret = CreatePendingPacket(channelId, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    DeletePendingPacket(channelId, seq);
    TransPendData pendData = { };
    ret = GetPendingPacketData(channelId, seq, TEST_WAIT_ACK_TIME, true, &pendData);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/*
 * @tc.name: DeletePendingPacketTest002
 * @tc.desc: delete non-existent pending packet does not corrupt list state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ClientTransPendingTest, DeletePendingPacketTest002, TestSize.Level1)
{
    uint32_t channelId = TEST_CHANNEL_ID;
    uint64_t seq = TEST_SEQ;
    int32_t ret = CreatePendingPacket(channelId, seq);
    EXPECT_EQ(SOFTBUS_OK, ret);
    DeletePendingPacket(channelId, seq + 1);
    ret = CreatePendingPacket(channelId, seq);
    EXPECT_EQ(SOFTBUS_ALREADY_EXISTED, ret);
    DeletePendingPacket(channelId, seq);
}
} // namespace OHOS
