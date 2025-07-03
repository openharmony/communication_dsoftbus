/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "br_proxy_common.h"
#include "br_proxy_server_manager_mock.h"
#include "br_proxy_server_manager.c"
#include "message_handler.h"
#include "nativetoken_kit.h"
#include "softbus_adapter_mem.h"
#include "softbus_common.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
#define CHANNEL_ID 5
#define CHANNEL_ID_ERR 0
#define SESSION_ID 2
#define REQUEST_ID 6
#define PID_TEST 1111
#define UID_TEST 2222
#define TOKENID_TEST 3333

class BrProxyServerManagerTest : public testing::Test {
public:
    BrProxyServerManagerTest()
    {}
    ~BrProxyServerManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void BrProxyServerManagerTest::SetUpTestCase(void)
{
}

void BrProxyServerManagerTest::TearDownTestCase(void)
{
}

/**
 * @tc.name: BrProxyServerManagerTest000
 * @tc.desc: BrProxyServerManagerTest000, use the Normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest000, TestSize.Level1)
{
    int32_t count = 0;
    int32_t ret = BrProxyServerInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = GetServerListCount(&count);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest001
 * @tc.desc: BrProxyServerManagerTest001, use the Normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest001, TestSize.Level1)
{
    BrProxyChannelInfo info = {
        .peerBRMacAddr = "FF:AA:CC:AA:BB:CC",
        .peerBRUuid = "AAAAAAAA-0000-0000-8888-BBBBBBBBBBBB",
    };
    NiceMock<BrProxyServerManagerInterfaceMock> brProxyServerManagerMock;
    EXPECT_CALL(brProxyServerManagerMock, GetCallerPid).WillRepeatedly(Return(PID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerUid).WillRepeatedly(Return(UID_TEST));
    EXPECT_CALL(brProxyServerManagerMock, GetCallerTokenId).WillRepeatedly(Return(TOKENID_TEST));
    int32_t ret = ServerAddChannelToList(info.peerBRMacAddr, info.peerBRUuid, CHANNEL_ID, REQUEST_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: BrProxyServerManagerTest002
 * @tc.desc: BrProxyServerManagerTest002, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BrProxyServerManagerTest, BrProxyServerManagerTest002, TestSize.Level1)
{
    int32_t channelId = 0;
    int32_t ret = GetChannelIdFromServerList(&channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = GetNewChannelId(&channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);
    CloseAllConnect();
    LnnEventBasicInfo info;
    info.event = LNN_EVENT_USER_SWITCHED;
    UserSwitchedHandler(&info);
}
}