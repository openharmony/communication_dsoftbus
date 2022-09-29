/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <securec.h>

#include "gtest/gtest.h"
#include "session.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"
#include "auth_interface.h"
#include "trans_tcp_direct_listener.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_message.h"
#include "trans_tcp_direct_wifi.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_tcp_direct_message.h"
#include "softbus_protocol_def.h"

using namespace testing::ext;

namespace OHOS {

class TransTcpDirectTest : public testing::Test {
public:
    TransTcpDirectTest()
    {}
    ~TransTcpDirectTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransTcpDirectTest::SetUpTestCase(void)
{}

void TransTcpDirectTest::TearDownTestCase(void)
{}

/**
 * @tc.name: StartSessionListenerTest001
 * @tc.desc: extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, StartSessionListenerTest001, TestSize.Level1)
{
    int ret = 0;
    LocalListenerInfo info = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "",
            .port = 6000,
            .moduleId = DIRECT_CHANNEL_SERVER_WIFI,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    ret = TransTdcStartSessionListener(UNUSE_BUTT, &info);
    EXPECT_TRUE(ret != 0);

    LocalListenerInfo info2 = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "192.168.8.119",
            .port = -1,
            .moduleId = DIRECT_CHANNEL_SERVER_WIFI,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    ret = TransTdcStartSessionListener(DIRECT_CHANNEL_SERVER_WIFI, &info2);
    EXPECT_TRUE(ret != 0);

    LocalListenerInfo info3 = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "",
            .port = -1,
            .moduleId = DIRECT_CHANNEL_SERVER_WIFI,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    ret = TransTdcStartSessionListener(DIRECT_CHANNEL_SERVER_WIFI, &info3);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: StoptSessionListenerTest001
 * @tc.desc: extern module active publish, stop session whitout start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, StoptSessionListenerTest001, TestSize.Level1)
{
    int ret = 0;
    ret = TransTdcStopSessionListener(DIRECT_CHANNEL_SERVER_WIFI);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: OpenTcpDirectChannelTest001
 * @tc.desc: extern module active publish, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, OpenTcpDirectChannelTest001, TestSize.Level1)
{
    int ret = 0;
    AppInfo appInfo;
    ConnectOption connInfo = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = {0},
            .port = 6000,
            .moduleId = MODULE_MESSAGE_SERVICE,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    if (strcpy_s(connInfo.socketOption.addr, sizeof(connInfo.socketOption.addr), "192.168.8.1") != EOK) {
        return;
    }
    int fd = 1;

    ret = TransOpenDirectChannel(NULL, &connInfo, &fd);
    EXPECT_TRUE(ret != 0);

    ret = TransOpenDirectChannel(&appInfo, NULL, &fd);
    EXPECT_TRUE(ret != 0);

    ret = TransOpenDirectChannel(&appInfo, &connInfo, NULL);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: OpenTcpDirectChannelTest002
 * @tc.desc: extern module active publish, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, OpenTcpDirectChannelTest002, TestSize.Level1)
{
    int ret = 0;
    AppInfo appInfo;
    (void)memset_s(&appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    ConnectOption connInfo = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = {0},
            .port = 6000,
            .moduleId = MODULE_MESSAGE_SERVICE,
            .protocol = LNN_PROTOCOL_IP
        }
    };
    if (strcpy_s(connInfo.socketOption.addr, sizeof(connInfo.socketOption.addr), "192.168.8.1") != EOK) {
        return;
    }
    int32_t channelId = 0;

    ret = OpenTcpDirectChannel(&appInfo, &connInfo, &channelId);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: TransTdcPostBytesTest001
 * @tc.desc: TransTdcPostBytesTest, start with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, TransTdcPostBytesTest001, TestSize.Level1)
{
    int ret = 0;
    const char *bytes = "Get Message";
    TdcPacketHead packetHead = {
        .magicNumber = MAGIC_NUMBER,
        .module = MODULE_SESSION,
        .seq = 0,
        .flags = FLAG_REQUEST,
        .dataLen = strlen(bytes), /* reset after encrypt */
    };
    int32_t channelId = 0;

    ret = TransTdcPostBytes(channelId, NULL, bytes);
    EXPECT_TRUE(ret != 0);

    ret = TransTdcPostBytes(channelId, &packetHead, NULL);
    EXPECT_TRUE(ret != 0);

    packetHead.dataLen = 0;
    ret = TransTdcPostBytes(channelId, &packetHead, bytes);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: GetCipherFlagByAuthIdTest001
 * @tc.desc: GetCipherFlagByAuthId, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, GetCipherFlagByAuthIdTest001, TestSize.Level1)
{
    int64_t authId = 0;
    uint32_t flag = 0;

    int ret = GetCipherFlagByAuthId(authId, &flag, NULL);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: SessionConnListTest001
 * @tc.desc: SessionConnListTest001, start channel with wrong parms.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectTest, SessionConnListTest001, TestSize.Level1)
{
    SessionConn conn;
    ListInit(&conn.node);

    int ret = CreatSessionConnList();
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret = TransTdcAddSessionConn(&conn);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    AppInfo appInfo;
    ret = GetAppInfoById(conn.channelId, &appInfo);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = SetAuthIdByChanId(conn.channelId, 0);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    int authId = GetAuthIdByChanId(conn.channelId);
    EXPECT_TRUE(authId != AUTH_INVALID_ID);

    DestroySoftBusList(GetSessionConnList());
}
} // namespace OHOS