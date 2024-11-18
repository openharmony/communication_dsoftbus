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

#include "softbus_error_code.h"
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
    int32_t fd = NORMAL_FD;
    int32_t chanId = CHANID;

    int32_t ret = CreateSessionConnNode(module, fd, chanId, clientAddr);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
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
    int32_t cfd = NORMAL_FD;

    int32_t ret = TdcOnConnectEvent(module, cfd, clientAddr);
    EXPECT_NE(SOFTBUS_OK, ret);
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
    int32_t cfd = INVALID_FD;

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
    int32_t fd = NORMAL_FD;
    ListenerModule module = UNUSE_BUTT;
    int32_t events = EVENTS;

    int32_t ret = TdcOnDataEvent(module, events, fd);
    EXPECT_EQ(SOFTBUS_INVALID_FD, ret);
}

/**
 * @tc.name: TransSetTcpDirectConnectType001
 * @tc.desc: TransSetTcpDirectConnectType test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectListenerTest, TransSetTcpDirectConnectType001, TestSize.Level1)
{
    ListenerModule module = DIRECT_CHANNEL_SERVER_HML_START;
    int32_t connectType = 0; // test value
    TransSetTcpDirectConnectType(&connectType, module);
    EXPECT_EQ(connectType, CONNECT_HML);

    module = DIRECT_CHANNEL_SERVER_P2P;
    TransSetTcpDirectConnectType(&connectType, module);
    EXPECT_EQ(connectType, CONNECT_P2P);

    module = DIRECT_CHANNEL_SERVER_WIFI;
    TransSetTcpDirectConnectType(&connectType, module);
    EXPECT_EQ(connectType, CONNECT_TCP);
}

/**
 * @tc.name: ProcessSocketInEvent001
 * @tc.desc: ProcessSocketInEvent test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectListenerTest, ProcessSocketInEvent001, TestSize.Level1)
{
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);
    int32_t fd = 0; // test value
    int32_t ret = ProcessSocketInEvent(conn, fd);
    EXPECT_EQ(ret, SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED);

    conn->serverSide = true;
    ret = ProcessSocketOutEvent(conn, fd);
    EXPECT_EQ(ret, SOFTBUS_TCP_SOCKET_ERR);

    conn->serverSide = false;
    ret = ProcessSocketOutEvent(conn, fd);
    EXPECT_EQ(ret, SOFTBUS_TRANS_ADD_TRIGGER_FAILED);
    SoftBusFree(conn);
}
}