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

#include "trans_tcp_direct_wifi.h"

#include <securec.h>
#include <gtest/gtest.h>

#include "auth_interface.h"
#include "lnn_network_manager.h"
#include "legacy/softbus_adapter_hitrace.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"
#include "trans_log.h"
#include "trans_tcp_direct_message.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_tcp_direct_p2p.h"
#include "wifi_direct_manager.h"
#include "trans_tcp_direct_wifi_test_mock.h"

#define ID_OFFSET (1)
#define HML_IP_PREFIX "172.30."
#define NETWORK_ID_LEN 7
#define NORMAL_CHANNEL 1011
#define NORMAL_FD 155

using namespace testing;
using namespace testing::ext;

namespace OHOS {
extern "C" {
    int32_t GetLocalIpByRemoteIp(const char *remoteIp, char *localIp, int32_t localIpSize);

    static struct WifiDirectManager g_manager = {
        .getLocalIpByRemoteIp = GetLocalIpByRemoteIp,
    };

    struct WifiDirectManager* GetWifiDirectManager(void)
    {
        return &g_manager;
    }
    int32_t GetLocalIpByRemoteIp(const char *remoteIp, char *localIp, int32_t localIpSize)
    {
        return SOFTBUS_OK;
    }

    void TransSrvDelDataBufNode(int32_t channelId)
    {
        return;
    }

    void TransDelSessionConnById(int32_t channelId)
    {
        return;
    }
}

class TransTcpDirectWifiTest : public testing::Test {
public:
    TransTcpDirectWifiTest()
    {}
    ~TransTcpDirectWifiTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransTcpDirectWifiTest::SetUpTestCase(void)
{}

void TransTcpDirectWifiTest::TearDownTestCase(void)
{}

/**
 * @tc.name: OpenTcpDirectChannelTest001
 * @tc.desc: OpenTcpDirectChannel, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectWifiTest, OpenTcpDirectChannelTest001, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    ConnectOption *connInfo = (ConnectOption *)SoftBusMalloc(sizeof(ConnectOption));
    ASSERT_TRUE(connInfo != nullptr);
   
    int32_t ret = OpenTcpDirectChannel(appInfo, connInfo, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftBusFree(appInfo);
    SoftBusFree(connInfo);
}

/**
 * @tc.name: OpenTcpDirectChannelTest002
 * @tc.desc: OpenTcpDirectChannel, return ok.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectWifiTest, OpenTcpDirectChannelTest002, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    ConnectOption *connInfo = (ConnectOption *)SoftBusMalloc(sizeof(ConnectOption));
    ASSERT_TRUE(connInfo != nullptr);
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);

    int32_t channelId = NORMAL_CHANNEL;
    connInfo->type = CONNECT_P2P_REUSE;
    NiceMock<TransTcpDirectWifiInterfaceMock> TcpWifiMock;
    EXPECT_CALL(TcpWifiMock, CreateNewSessinConn).WillOnce(Return(conn));
    EXPECT_CALL(TcpWifiMock, ConnOpenClientSocket).WillOnce(Return(NORMAL_FD));
    EXPECT_CALL(TcpWifiMock, AddTrigger).WillOnce(Return(SOFTBUS_OK));
    int32_t ret = OpenTcpDirectChannel(appInfo, connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_OK, ret);

    SoftBusFree(appInfo);
    SoftBusFree(connInfo);
}

/**
 * @tc.name: OpenTcpDirectChannelTest003
 * @tc.desc: OpenTcpDirectChannel, module is UNUSE_BUTT.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectWifiTest, OpenTcpDirectChannelTest003, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    ConnectOption *connInfo = (ConnectOption *)SoftBusMalloc(sizeof(ConnectOption));
    ASSERT_TRUE(connInfo != nullptr);

    int32_t channelId = NORMAL_CHANNEL;
    connInfo->type = CONNECT_HML;
    NiceMock<TransTcpDirectWifiInterfaceMock> TcpWifiMock;
    EXPECT_CALL(TcpWifiMock, LnnGetProtocolListenerModule).WillOnce(Return(UNUSE_BUTT));
    int32_t ret = OpenTcpDirectChannel(appInfo, connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_TRANS_TCP_UNUSE_LISTENER_MODE, ret);

    SoftBusFree(appInfo);
    SoftBusFree(connInfo);
}

/**
 * @tc.name: OpenTcpDirectChannelTest004
 * @tc.desc: OpenTcpDirectChannel, CreateNewSessinConn func return null.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectWifiTest, OpenTcpDirectChannelTest004, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    ConnectOption *connInfo = (ConnectOption *)SoftBusMalloc(sizeof(ConnectOption));
    ASSERT_TRUE(connInfo != nullptr);

    int32_t channelId = NORMAL_CHANNEL;
    connInfo->type = CONNECT_P2P_REUSE;
    NiceMock<TransTcpDirectWifiInterfaceMock> TcpWifiMock;
    EXPECT_CALL(TcpWifiMock, CreateNewSessinConn).WillOnce(Return(nullptr));
    int32_t ret = OpenTcpDirectChannel(appInfo, connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);

    SoftBusFree(appInfo);
    SoftBusFree(connInfo);
}

/**
 * @tc.name: OpenTcpDirectChannelTest005
 * @tc.desc: Should return SOFTBUS_TRANS_TCP_GET_AUTHID_FAILED  when CreateNewSessinConn return valid paramter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectWifiTest, OpenTcpDirectChannelTest005, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    ConnectOption *connInfo = (ConnectOption *)SoftBusMalloc(sizeof(ConnectOption));
    ASSERT_TRUE(connInfo != nullptr);
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);

    int32_t channelId = NORMAL_CHANNEL;
    connInfo->type = CONNECT_P2P_REUSE;
    NiceMock<TransTcpDirectWifiInterfaceMock> TcpWifiMock;
    ON_CALL(TcpWifiMock, AuthGetLatestIdByUuid(_, _, _, _))
        .WillByDefault(DoAll(SetArgPointee<3>(AuthHandle{.authId = AUTH_INVALID_ID}), Return()));
    EXPECT_CALL(TcpWifiMock, CreateNewSessinConn).WillOnce(Return(conn));
    int32_t ret = OpenTcpDirectChannel(appInfo, connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_TRANS_TCP_GET_AUTHID_FAILED, ret);

    SoftBusFree(appInfo);
    SoftBusFree(connInfo);
}

/**
 * @tc.name: OpenTcpDirectChannelTest006
 * @tc.desc: OpenTcpDirectChannel, ConnOpenClientSocket func return SOFTBUS_NO_INIT.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectWifiTest, OpenTcpDirectChannelTest006, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    ConnectOption *connInfo = (ConnectOption *)SoftBusMalloc(sizeof(ConnectOption));
    ASSERT_TRUE(connInfo != nullptr);
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);
    
    int32_t channelId = NORMAL_CHANNEL;
    connInfo->type = CONNECT_P2P_REUSE;
    NiceMock<TransTcpDirectWifiInterfaceMock> TcpWifiMock;
    EXPECT_CALL(TcpWifiMock, CreateNewSessinConn).WillOnce(Return(conn));
    EXPECT_CALL(TcpWifiMock, ConnOpenClientSocket).WillOnce(Return(SOFTBUS_NO_INIT));
    int32_t ret = OpenTcpDirectChannel(appInfo, connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    SoftBusFree(appInfo);
    SoftBusFree(connInfo);
}

/**
 * @tc.name: OpenTcpDirectChannelTest007
 * @tc.desc: OpenTcpDirectChannel, AddTrigger func return SOFTBUS_NO_INIT.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectWifiTest, OpenTcpDirectChannelTest007, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    ConnectOption *connInfo = (ConnectOption *)SoftBusMalloc(sizeof(ConnectOption));
    ASSERT_TRUE(connInfo != nullptr);
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);
    
    int32_t channelId = NORMAL_CHANNEL;
    connInfo->type = CONNECT_P2P_REUSE;
    NiceMock<TransTcpDirectWifiInterfaceMock> TcpWifiMock;
    EXPECT_CALL(TcpWifiMock, CreateNewSessinConn).WillOnce(Return(conn));
    EXPECT_CALL(TcpWifiMock, ConnOpenClientSocket).WillRepeatedly(Return(NORMAL_FD));
    EXPECT_CALL(TcpWifiMock, AddTrigger).WillRepeatedly(Return(SOFTBUS_NO_INIT));
    int32_t ret = OpenTcpDirectChannel(appInfo, connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_TRANS_ADD_TRIGGER_FAILED, ret);

    SoftBusFree(appInfo);
    SoftBusFree(connInfo);
    SoftBusFree(conn);
}

/**
 * @tc.name: OpenTcpDirectChannelTest008
 * @tc.desc: OpenTcpDirectChannel, TransSrvAddDataBufNode func return SOFTBUS_NO_INIT.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectWifiTest, OpenTcpDirectChannelTest008, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    ConnectOption *connInfo = (ConnectOption *)SoftBusMalloc(sizeof(ConnectOption));
    ASSERT_TRUE(connInfo != nullptr);
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);
    
    int32_t channelId = NORMAL_CHANNEL;
    connInfo->type = CONNECT_P2P_REUSE;
    NiceMock<TransTcpDirectWifiInterfaceMock> TcpWifiMock;
    EXPECT_CALL(TcpWifiMock, CreateNewSessinConn).WillOnce(Return(conn));
    EXPECT_CALL(TcpWifiMock, ConnOpenClientSocket).WillRepeatedly(Return(NORMAL_FD));
    EXPECT_CALL(TcpWifiMock, TransSrvAddDataBufNode).WillRepeatedly(Return(SOFTBUS_NO_INIT));
    int32_t ret = OpenTcpDirectChannel(appInfo, connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_MALLOC_ERR, ret);

    SoftBusFree(appInfo);
    SoftBusFree(connInfo);
}

/**
 * @tc.name: OpenTcpDirectChannelTest009
 * @tc.desc: OpenTcpDirectChannel, TransTdcAddSessionConn func return SOFTBUS_NO_INIT.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransTcpDirectWifiTest, OpenTcpDirectChannelTest009, TestSize.Level1)
{
    AppInfo *appInfo = (AppInfo *)SoftBusMalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    ConnectOption *connInfo = (ConnectOption *)SoftBusMalloc(sizeof(ConnectOption));
    ASSERT_TRUE(connInfo != nullptr);
    SessionConn *conn = (SessionConn *)SoftBusCalloc(sizeof(SessionConn));
    ASSERT_TRUE(conn != nullptr);
    
    int32_t channelId = NORMAL_CHANNEL;
    connInfo->type = CONNECT_P2P_REUSE;
    NiceMock<TransTcpDirectWifiInterfaceMock> TcpWifiMock;
    EXPECT_CALL(TcpWifiMock, CreateNewSessinConn).WillOnce(Return(conn));
    EXPECT_CALL(TcpWifiMock, ConnOpenClientSocket).WillRepeatedly(Return(NORMAL_FD));
    EXPECT_CALL(TcpWifiMock, TransTdcAddSessionConn).WillRepeatedly(Return(SOFTBUS_NO_INIT));
    int32_t ret = OpenTcpDirectChannel(appInfo, connInfo, &channelId);
    EXPECT_EQ(SOFTBUS_TRANS_ADD_SESSION_CONN_FAILED, ret);

    SoftBusFree(appInfo);
    SoftBusFree(connInfo);
}
}