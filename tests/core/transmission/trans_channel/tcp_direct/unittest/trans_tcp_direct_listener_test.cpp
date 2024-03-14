/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "trans_tcp_direct_listener.h"

#include <gtest/gtest.h>
#include "securec.h"

#include "softbus_errcode.h"
#include "softbus_def.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "trans_tcp_direct_listener.c"
#include "softbus_base_listener.h"
#include "trans_tcp_direct_manager.h"
#include "trans_tcp_direct_sessionconn.h"
#include "auth_interface.h"

#define NORMAL_FD 151
#define INVALID_FD (-1)
#define CHANID 123
#define EVENTS 2

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class TransTcpDirectListenerTest : public testing::Test {
public:
    TransTcpDirectListenerTest()
    {}
    ~TransTcpDirectListenerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransTcpDirectListenerTest::SetUpTestCase(void)
{}

void TransTcpDirectListenerTest::TearDownTestCase(void)
{}

/**
 * @tc.name: SwitchAuthLinkTypeToFlagTypeTest001
 * @tc.desc: SwitchAuthLinkTypeToFlagType test.
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(TransTcpDirectListenerTest, SwitchAuthLinkTypeToFlagTypeTest001, TestSize.Level1)
{
    AuthLinkType type = AUTH_LINK_TYPE_BR;
    uint32_t ret = SwitchAuthLinkTypeToFlagType(type);
    EXPECT_EQ(FLAG_BR, ret);
    
    type = AUTH_LINK_TYPE_BLE;
    ret = SwitchAuthLinkTypeToFlagType(type);
    EXPECT_EQ(FLAG_BLE, ret);

    type = AUTH_LINK_TYPE_P2P;
    ret = SwitchAuthLinkTypeToFlagType(type);
    EXPECT_EQ(FLAG_P2P, ret);

    type = AUTH_LINK_TYPE_ENHANCED_P2P;
    ret = SwitchAuthLinkTypeToFlagType(type);
    EXPECT_EQ(FLAG_ENHANCE_P2P, ret);

    type = AUTH_LINK_TYPE_WIFI;
    ret = SwitchAuthLinkTypeToFlagType(type);
    EXPECT_EQ(FLAG_WIFI, ret);
}

/**
 * @tc.name: StartVerifySessionTest001
 * @tc.desc: StartVerifySession test, get cipher flag fail.
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(TransTcpDirectListenerTest, StartVerifySessionTest001, TestSize.Level1)
{
    SessionConn *conn = (SessionConn *)SoftBusMalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);

    int32_t ret = StartVerifySession(conn);
    EXPECT_EQ(SOFTBUS_TRANS_GET_CIPHER_FAILED, ret);
}

/**
 * @tc.name: CreateSessionConnNodeTest001
 * @tc.desc: CreateSessionConnNode test, get local deviceId failed.
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(TransTcpDirectListenerTest, CreateSessionConnNodeTest001, TestSize.Level1)
{
    ConnectOption *clientAddr = (ConnectOption *)SoftBusMalloc(sizeof(ConnectOption));
    ASSERT_TRUE(clientAddr != nullptr);

    ListenerModule module = UNUSE_BUTT;
    int fd = NORMAL_FD;
    int32_t chanId = CHANID;

    int32_t ret = CreateSessionConnNode(module, fd, chanId, clientAddr);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TdcOnConnectEventTest001
 * @tc.desc: TdcOnConnectEvent test, create srv dataBuff fail.
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(TransTcpDirectListenerTest, TdcOnConnectEventTest001, TestSize.Level1)
{
    ConnectOption *clientAddr = (ConnectOption *)SoftBusMalloc(sizeof(ConnectOption));
    ASSERT_TRUE(clientAddr != nullptr);

    ListenerModule module = UNUSE_BUTT;
    int cfd = NORMAL_FD;

    int32_t ret = TdcOnConnectEvent(module, cfd, clientAddr);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TdcOnConnectEventTest002
 * @tc.desc: TdcOnConnectEvent test, use invalid cfd.
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(TransTcpDirectListenerTest, TdcOnConnectEventTest002, TestSize.Level1)
{
    ConnectOption *clientAddr = (ConnectOption *)SoftBusMalloc(sizeof(ConnectOption));
    ASSERT_TRUE(clientAddr != nullptr);

    ListenerModule module = UNUSE_BUTT;
    int cfd = INVALID_FD;

    int32_t ret = TdcOnConnectEvent(module, cfd, clientAddr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TdcOnDataEventTest001
 * @tc.desc: TdcOnDataEvent test, can not get sessionConn by fd.
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(TransTcpDirectListenerTest, TdcOnDataEventTest001, TestSize.Level1)
{
    int fd = NORMAL_FD;
    ListenerModule module = UNUSE_BUTT;
    int events = EVENTS;

    int32_t ret = TdcOnDataEvent(module, events, fd);
    EXPECT_EQ(SOFTBUS_INVALID_FD, ret);
}
}