/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>

#include "auth_log.h"
#include "auth_tcp_connection.c"
#include "auth_tcp_connection.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"

namespace OHOS {
using namespace testing::ext;
constexpr uint32_t TEST_DATA_LEN = 30;

class AuthTcpConnectionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthTcpConnectionTest::SetUpTestCase() { }

void AuthTcpConnectionTest::TearDownTestCase() { }

void AuthTcpConnectionTest::SetUp()
{
    AUTH_LOGI(AUTH_TEST, "AuthTcpConnectionTest start.");
}

void AuthTcpConnectionTest::TearDown() { }

/*
 * @tc.name: UNPACK_SOCKET_PKT_TEST_001
 * @tc.desc: unpack socket pkt test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, UNPACK_SOCKET_PKT_TEST_001, TestSize.Level1)
{
    const uint8_t data[AUTH_PKT_HEAD_LEN] = { 0 };
    uint32_t len = 1;
    SocketPktHead head;
    (void)memset_s(&head, sizeof(head), 0, sizeof(head));
    int32_t ret = UnpackSocketPkt(data, len, &head);
    EXPECT_TRUE(ret == SOFTBUS_NO_ENOUGH_DATA);
    len = AUTH_PKT_HEAD_LEN;
    ret = UnpackSocketPkt(data, len, &head);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: MODULE_TO_DATA_TYPE_TEST_001
 * @tc.desc: module to data type test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, MODULE_TO_DATA_TYPE_TEST_001, TestSize.Level1)
{
    int32_t module = MODULE_TRUST_ENGINE;
    uint32_t ret = ModuleToDataType(module);
    EXPECT_TRUE(ret == DATA_TYPE_DEVICE_ID);
    module = MODULE_AUTH_SDK;
    ret = ModuleToDataType(module);
    EXPECT_TRUE(ret == DATA_TYPE_AUTH);
    module = MODULE_AUTH_CONNECTION;
    ret = ModuleToDataType(module);
    EXPECT_TRUE(ret == DATA_TYPE_DEVICE_INFO);
    module = MODULE_MESSAGE_SERVICE;
    ret = ModuleToDataType(module);
    EXPECT_TRUE(ret == DATA_TYPE_CONNECTION);
}

/*
 * @tc.name: RECV_PACKET_HEAD_TEST_001
 * @tc.desc: recv packet head test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, RECV_PACKET_HEAD_TEST_001, TestSize.Level1)
{
    int32_t fd = 0;
    SocketPktHead pktHead;
    (void)memset_s(&pktHead, sizeof(SocketPktHead), 0, sizeof(SocketPktHead));
    int32_t ret = RecvPacketHead(AUTH, fd, &pktHead);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: RECV_PACKET_DATA_TEST_001
 * @tc.desc: recv packet head test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, RECV_PACKET_DATA_TEST_001, TestSize.Level1)
{
    int32_t fd = 0;
    SocketPktHead pktHead;
    uint8_t data[TEST_DATA_LEN] = { 0 };
    (void)memset_s(&pktHead, sizeof(SocketPktHead), 0, sizeof(SocketPktHead));
    pktHead.module = MODULE_AUTH_CHANNEL;
    NotifyDataReceived(AUTH, fd, &pktHead, data);
    pktHead.module = MODULE_AUTH_MSG;
    NotifyDataReceived(AUTH, fd, &pktHead, data);
    pktHead.module = MODULE_CONNECTION;
    NotifyDataReceived(AUTH, fd, &pktHead, data);

    uint32_t len = TEST_DATA_LEN;
    uint8_t *packetData = RecvPacketData(fd, len);
    EXPECT_TRUE(packetData == nullptr);
}

/*
 * @tc.name: PROCESS_SOCKET_OUT_EVENT_TEST_001
 * @tc.desc: process socket out event test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, PROCESS_SOCKET_OUT_EVENT_TEST_001, TestSize.Level1)
{
    int32_t fd = 0;
    bool isClient = true;
    NotifyConnected(AUTH, fd, isClient);
    NotifyDisconnected(fd);
    StopSocketListening(AUTH);

    int32_t ret = ProcessSocketOutEvent(AUTH, fd);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: PROCESS_SOCKET_IN_EVENT_TEST_001
 * @tc.desc: process socket in event test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, PROCESS_SOCKET_IN_EVENT_TEST_001, TestSize.Level1)
{
    int32_t fd = 0;
    int32_t channelId = 0;
    SocketPktHead head;
    const uint8_t data[TEST_DATA_LEN] = { 0 };
    (void)memset_s(&head, sizeof(SocketPktHead), 0, sizeof(SocketPktHead));
    NotifyChannelDataReceived(channelId, &head, data);
    NotifyChannelDisconnected(channelId);

    int32_t ret = ProcessSocketInEvent(AUTH, fd);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_CONNECT_EVENT_TEST_001
 * @tc.desc: on connect event test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, ON_CONNECT_EVENT_TEST_001, TestSize.Level1)
{
    ListenerModule module = AUTH_P2P;
    int32_t cfd = -1;
    ConnectOption clientAddr;
    (void)memset_s(&clientAddr, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    int32_t ret = OnConnectEvent(module, cfd, &clientAddr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    cfd = 0;
    ret = OnConnectEvent(module, cfd, &clientAddr);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ON_DATA_EVENT_TEST_001
 * @tc.desc: on data event test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, ON_DATA_EVENT_TEST_001, TestSize.Level1)
{
    ListenerModule module = AUTH_P2P;
    int32_t events = SOFTBUS_SOCKET_OUT;
    int32_t fd = 0;
    int32_t ret = OnDataEvent(module, events, fd);
    EXPECT_NE(ret, SOFTBUS_OK);
    events = SOFTBUS_SOCKET_IN;
    ret = OnDataEvent(module, events, fd);
    EXPECT_NE(ret, SOFTBUS_OK);
    events = SOFTBUS_SOCKET_EXCEPTION;
    ret = OnDataEvent(module, events, fd);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: START_SOCKET_LISTENING_TEST_001
 * @tc.desc: start socket listening test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, START_SOCKET_LISTENING_TEST_001, TestSize.Level1)
{
    LocalListenerInfo info = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "192.168.12.1",
            .port = 22,
            .moduleId = AUTH,
            .protocol = LNN_PROTOCOL_IP,
        },
    };
    int32_t ret = StartSocketListening(AUTH, &info);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SOCKET_GET_CONN_INFO_TEST_001
 * @tc.desc: socket get conn info test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, SOCKET_GET_CONN_INFO_TEST_001, TestSize.Level1)
{
    int32_t fd = 0;
    AuthConnInfo connInfo;
    bool isServer;
    (void)memset_s(&connInfo, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    int32_t ret = SocketGetConnInfo(fd, nullptr, &isServer);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = SocketGetConnInfo(fd, &connInfo, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = SocketGetConnInfo(fd, &connInfo, &isServer);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/*
 * @tc.name: SOCKET_CONNECT_INNER_TEST_001
 * @tc.desc: SocketConnectInner test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, SOCKET_CONNECT_INNER_TEST_001, TestSize.Level1)
{
    const char *localIp = "192.168.11.22";
    const char *peerIp = "192.168.11.33";
    int32_t ret = SocketConnectInner(nullptr, peerIp, 37025, AUTH, true);
    EXPECT_TRUE(ret == AUTH_INVALID_FD);
    ret = SocketConnectInner(localIp, nullptr, 37025, AUTH, true);
    EXPECT_TRUE(ret == AUTH_INVALID_FD);
    ret = SocketConnectInner(localIp, peerIp, 37025, AUTH, true);
    EXPECT_TRUE(ret == SOFTBUS_CONN_SOCKET_GET_INTERFACE_ERR);
}

/*
 * @tc.name: NIP_SOCKET_CONNECT_DEVICE_TEST_001
 * @tc.desc: NipSocketConnectDevice test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, NIP_SOCKET_CONNECT_DEVICE_TEST_001, TestSize.Level1)
{
    const char *addr = "192.168.11.44";
    int32_t ret = NipSocketConnectDevice(AUTH, addr, 37025, true);
    EXPECT_TRUE(ret == AUTH_INVALID_FD);
    ret = NipSocketConnectDevice(AUTH, nullptr, 37025, true);
    EXPECT_TRUE(ret == AUTH_INVALID_FD);
}

/*
 * @tc.name: AUTH_OPEN_CHANNEL_WITH_ALL_IP_TEST_001
 * @tc.desc: AuthOpenChannelWithAllIp test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthTcpConnectionTest, AUTH_OPEN_CHANNEL_WITH_ALL_IP_TEST_001, TestSize.Level1)
{
    const char *localIp = "192.168.11.22";
    const char *remoteIp = "192.168.11.33";
    int32_t ret = AuthOpenChannelWithAllIp(localIp, remoteIp, 37025);
    EXPECT_TRUE(ret == INVALID_CHANNEL_ID);
    ret = AuthOpenChannelWithAllIp(nullptr, remoteIp, 37025);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthOpenChannelWithAllIp(localIp, nullptr, 37025);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = AuthOpenChannelWithAllIp(localIp, remoteIp, 0);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS
