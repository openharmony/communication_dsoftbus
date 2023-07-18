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

#include "softbus_def.h"
#include "softbus_errcode.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_server_frame.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_tcp_direct_message.h"

using namespace testing;
using namespace testing::ext;

#define TEST_CHANNELID 5
#define TEST_LEN 50
#define ERR_CHANNELID (-1)
const char *g_sessionName = "ohos.distributedschedule.dms.test";

namespace OHOS {
class TransTcpDirectMessageAppendTest : public testing::Test {
public:
    TransTcpDirectMessageAppendTest()
    {}
    ~TransTcpDirectMessageAppendTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransTcpDirectMessageAppendTest::SetUpTestCase(void)
{
    InitSoftBusServer();
}

void TransTcpDirectMessageAppendTest::TearDownTestCase(void)
{}

/**
 * @tc.name: NotifyChannelOpenFailedTest001
 * @tc.desc: notify channel opend failed test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, NotifyChannelOpenFailedTest001, TestSize.Level1)
{
    int32_t ret;
    ret = CreatSessionConnList();
    EXPECT_EQ(SOFTBUS_OK, ret);
    SessionConn *conn = CreateNewSessinConn(DIRECT_CHANNEL_CLIENT, false);
    ASSERT_TRUE(conn != NULL);
    conn->channelId = TEST_CHANNELID;

    ret = TransTdcAddSessionConn(conn);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = NotifyChannelOpenFailed(TEST_CHANNELID, 0);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    ret = NotifyChannelOpenFailed(ERR_CHANNELID, 0);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: NotifyChannelOpenedTest001
 * @tc.desc: notify channel opend test, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectMessageAppendTest, NotifyChannelOpenedTest001, TestSize.Level1)
{
    int32_t ret;
    SessionConn conn;
    conn.serverSide = true;
    conn.channelId = TEST_CHANNELID;

    ret = CreatSessionConnList();
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = TransTdcAddSessionConn(&conn);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
}
