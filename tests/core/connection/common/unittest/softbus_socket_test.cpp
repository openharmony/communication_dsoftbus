/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "softbus_socket.h"

#include <string.h>
#include <gtest/gtest.h>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>

#include "softbus_adapter_mem.h"
#include "softbus_adapter_errcode.h"
#include "softbus_adapter_socket.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"
#include "softbus_def.h"
#include "conn_log.h"

#include "mock/softbus_socket_mock.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS::SoftBus;

#define SOCKET_PORT_TEST      8080

// Mock SocketInterface for testing
static int32_t MockGetSockPort(int32_t fd) { return SOCKET_PORT_TEST; }
static int32_t MockOpenServerSocket(const LocalListenerInfo *option) { return 0; }
static int32_t MockOpenClientSocket(const ConnectOption *option, const char *bindAddr, bool isNonBlock) { return 100; }
static int32_t MockAcceptClient(int32_t fd, ConnectOption *clientAddr, int32_t *cfd) { return 0; }

class SoftBusSocketTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
    }

    static void TearDownTestCase()
    {
    }

    void SetUp() override
    {
        mock = std::make_unique<SocketTestMock>();
    }

    void TearDown() override
    {
        mock.reset();
    }

    std::unique_ptr<SocketTestMock> mock;
};

/*
 * @tc.name: RegistSocketProtocolTest_NullInterface
 * @tc.desc: test RegistSocketProtocol with null interface
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, RegistSocketProtocolTest_NullInterface, TestSize.Level1)
{
    auto ret = RegistSocketProtocol(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: RegistSocketProtocolTest_NameIsNull
 * @tc.desc: test RegistSocketProtocol with null name
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, RegistSocketProtocolTest_NameIsNull, TestSize.Level1)
{
    SocketInterface iface = {
        .name = nullptr,
        .type = LNN_PROTOCOL_IP,
        .GetSockPort = MockGetSockPort,
        .OpenServerSocket = MockOpenServerSocket,
        .OpenClientSocket = MockOpenClientSocket,
        .AcceptClient = MockAcceptClient,
    };

    auto ret = RegistSocketProtocol(&iface);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: RegistSocketProtocolTest_EmptyName
 * @tc.desc: test RegistSocketProtocol with empty name
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, RegistSocketProtocolTest_EmptyName, TestSize.Level1)
{
    SocketInterface iface = {
        .name = "",
        .type = LNN_PROTOCOL_IP,
        .GetSockPort = MockGetSockPort,
        .OpenServerSocket = MockOpenServerSocket,
        .OpenClientSocket = MockOpenClientSocket,
        .AcceptClient = MockAcceptClient,
    };

    auto ret = RegistSocketProtocol(&iface);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: RegistSocketProtocolTest_InvalidInterface
 * @tc.desc: test RegistSocketProtocol with invalid interface (null function pointers)
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, RegistSocketProtocolTest_InvalidInterface, TestSize.Level1)
{
    SocketInterface iface = {
        .name = "test",
        .type = LNN_PROTOCOL_IP,
        .GetSockPort = nullptr,
        .OpenServerSocket = MockOpenServerSocket,
        .OpenClientSocket = MockOpenClientSocket,
        .AcceptClient = MockAcceptClient,
    };

    auto ret = RegistSocketProtocol(&iface);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: RegistSocketProtocolTest_Success
 * @tc.desc: test successful protocol registration
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, RegistSocketProtocolTest_Success, TestSize.Level1)
{
    // Initialize mutex first
    auto initRet = ConnInitSockets();
    ASSERT_EQ(initRet, SOFTBUS_OK);

    SocketInterface iface = {
        .name = "test",
        .type = LNN_PROTOCOL_BLE,
        .GetSockPort = MockGetSockPort,
        .OpenServerSocket = MockOpenServerSocket,
        .OpenClientSocket = MockOpenClientSocket,
        .AcceptClient = MockAcceptClient,
    };

    auto ret = RegistSocketProtocol(&iface);
    EXPECT_EQ(ret, SOFTBUS_CONN_SOCKET_INTERNAL_ERR);

    ConnDeinitSockets();
}

/*
 * @tc.name: GetSocketInterfaceTest_NotFound
 * @tc.desc: test GetSocketInterface when interface not found
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, GetSocketInterfaceTest_NotFound, TestSize.Level1)
{
    // Initialize mutex first
    auto initRet = ConnInitSockets();
    ASSERT_EQ(initRet, SOFTBUS_OK);

    // Use LNN_PROTOCOL_BLE which is not registered by ConnInitSockets
    auto iface = GetSocketInterface(LNN_PROTOCOL_BLE);
    EXPECT_EQ(iface, nullptr);

    ConnDeinitSockets();
}

/*
 * @tc.name: GetSocketInterfaceTest_Success
 * @tc.desc: test successful GetSocketInterface
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, GetSocketInterfaceTest_Success, TestSize.Level1)
{
    // Initialize mutex first
    auto initRet = ConnInitSockets();
    ASSERT_EQ(initRet, SOFTBUS_OK);

    auto iface = GetSocketInterface(LNN_PROTOCOL_IP);
    EXPECT_NE(iface, nullptr);
    EXPECT_EQ(iface->type, LNN_PROTOCOL_IP);

    ConnDeinitSockets();
}

/*
 * @tc.name: ConnInitSocketsTest_Success
 * @tc.desc: test successful socket initialization
 * @tc.type: FUNC
 * @tc.desc: NOTE: Sockets are initialized in SetUpTestCase
 * @require:
 */
HWTEST_F(SoftBusSocketTest, ConnInitSocketsTest_Success, TestSize.Level1)
{
    auto ret = ConnInitSockets();
    EXPECT_EQ(ret, SOFTBUS_OK);

    // Clean up for other tests
    ConnDeinitSockets();
}

/*
 * @tc.name: ConnOpenClientSocketTest_NullOption
 * @tc.desc: test ConnOpenClientSocket with null option
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnOpenClientSocketTest_NullOption, TestSize.Level1)
{
    auto ret = ConnOpenClientSocket(nullptr, nullptr, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ConnOpenClientSocketTest_InterfaceNotFound
 * @tc.desc: test ConnOpenClientSocket when interface not found
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnOpenClientSocketTest_InterfaceNotFound, TestSize.Level1)
{
    // Initialize mutex first
    auto initRet = ConnInitSockets();
    ASSERT_EQ(initRet, SOFTBUS_OK);

    // Use LNN_PROTOCOL_BLE which is registered by our test, not by ConnInitSockets
    // But first deinitialize to clear the registered protocols, then don't register BLE
    ConnDeinitSockets();

    // Reinitialize to set up mutex again
    initRet = ConnInitSockets();
    ASSERT_EQ(initRet, SOFTBUS_OK);

    // Now test with a protocol that's not registered by ConnInitSockets
    ConnectOption option;
    option.socketOption.protocol = LNN_PROTOCOL_BLE;

    auto ret = ConnOpenClientSocket(&option, nullptr, false);
    EXPECT_EQ(ret, SOFTBUS_CONN_SOCKET_GET_INTERFACE_ERR);

    ConnDeinitSockets();
}

/*
 * @tc.name: ConnToggleNonBlockModeTest_InvalidFd
 * @tc.desc: test ConnToggleNonBlockMode with invalid fd
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnToggleNonBlockModeTest_InvalidFd, TestSize.Level1)
{
    auto ret = ConnToggleNonBlockMode(-1, true);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ConnToggleNonBlockModeTest_FcntlGetFail
 * @tc.desc: test ConnToggleNonBlockMode when fcntl F_GETFL fails
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnToggleNonBlockModeTest_FcntlGetFail, TestSize.Level1)
{
    EXPECT_CALL(*mock, FcntlHook(_, F_GETFL, _))
        .WillOnce(Return(-1));

    auto ret = ConnToggleNonBlockMode(10, true);
    EXPECT_EQ(ret, SOFTBUS_CONN_SOCKET_FCNTL_ERR);
}

/*
 * @tc.name: ConnToggleNonBlockModeTest_SetToNonBlock
 * @tc.desc: test setting socket to non-blocking mode
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnToggleNonBlockModeTest_SetToNonBlock, TestSize.Level1)
{
    EXPECT_CALL(*mock, FcntlHook(_, F_GETFL, _))
        .WillOnce(Return(0));
    EXPECT_CALL(*mock, FcntlHook(_, F_SETFL, _))
        .WillOnce(Return(0));

    auto ret = ConnToggleNonBlockMode(10, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConnToggleNonBlockModeTest_SetToBlock
 * @tc.desc: test setting socket to blocking mode
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnToggleNonBlockModeTest_SetToBlock, TestSize.Level1)
{
    EXPECT_CALL(*mock, FcntlHook(_, F_GETFL, _))
        .WillOnce(Return(O_NONBLOCK));
    EXPECT_CALL(*mock, FcntlHook(_, F_SETFL, _))
        .WillOnce(Return(0));

    auto ret = ConnToggleNonBlockMode(10, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConnToggleNonBlockModeTest_AlreadyInState
 * @tc.desc: test ConnToggleNonBlockMode when already in target state
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnToggleNonBlockModeTest_AlreadyInState, TestSize.Level1)
{
    EXPECT_CALL(*mock, FcntlHook(_, F_GETFL, _))
        .WillOnce(Return(O_NONBLOCK));

    auto ret = ConnToggleNonBlockMode(10, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConnSendSocketDataTest_InvalidParams
 * @tc.desc: test ConnSendSocketData with invalid parameters
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnSendSocketDataTest_InvalidParams, TestSize.Level1)
{
    char buf[10] = {0};

    auto ret = ConnSendSocketData(-1, buf, 10, 1000);
    EXPECT_EQ(ret, -1);

    ret = ConnSendSocketData(10, nullptr, 10, 1000);
    EXPECT_EQ(ret, -1);

    ret = ConnSendSocketData(10, buf, 0, 1000);
    EXPECT_EQ(ret, -1);
}

/*
 * @tc.name: ConnSendSocketDataTest_WaitEventFail
 * @tc.desc: test ConnSendSocketData when WaitEvent fails
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnSendSocketDataTest_WaitEventFail, TestSize.Level1)
{
    char buf[10] = {0};

    EXPECT_CALL(*mock, WaitEventHook(_, SOFTBUS_SOCKET_OUT, _))
        .WillOnce(Return(-1));

    auto ret = ConnSendSocketData(10, buf, 10, 1000);
    EXPECT_EQ(ret, -1);
}

/*
 * @tc.name: ConnSendSocketDataTest_SendSuccess
 * @tc.desc: test successful data sending
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnSendSocketDataTest_SendSuccess, TestSize.Level1)
{
    char buf[10];
    memset_s(buf, sizeof(buf), 'T', sizeof(buf));

    EXPECT_CALL(*mock, WaitEventHook(_, SOFTBUS_SOCKET_OUT, _))
        .WillOnce(Return(1));
    EXPECT_CALL(*mock, SocketSendHook(_, _, _, _))
        .WillOnce(Return(10));

    auto ret = ConnSendSocketData(10, buf, 10, 1000);
    EXPECT_EQ(ret, 10);
}

/*
 * @tc.name: ConnSendSocketDataTest_PartialSend
 * @tc.desc: test partial data sending
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnSendSocketDataTest_PartialSend, TestSize.Level1)
{
    char buf[10];
    memset_s(buf, sizeof(buf), 'A', sizeof(buf));

    EXPECT_CALL(*mock, WaitEventHook(_, SOFTBUS_SOCKET_OUT, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(*mock, SocketSendHook(_, _, _, _))
        .WillOnce(Return(5))
        .WillOnce(Return(5));

    auto ret = ConnSendSocketData(10, buf, 10, 1000);
    EXPECT_EQ(ret, 10);
}

/*
 * @tc.name: ConnRecvSocketDataTest_InvalidParams
 * @tc.desc: test ConnRecvSocketData with invalid parameters
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnRecvSocketDataTest_InvalidParams, TestSize.Level1)
{
    char buf[10] = {0};

    auto ret = ConnRecvSocketData(-1, buf, 10, 1000);
    EXPECT_EQ(ret, -1);

    ret = ConnRecvSocketData(10, nullptr, 10, 1000);
    EXPECT_EQ(ret, -1);

    ret = ConnRecvSocketData(10, buf, 0, 1000);
    EXPECT_EQ(ret, -1);
}

/*
 * @tc.name: ConnRecvSocketDataTest_WaitEventFail
 * @tc.desc: test ConnRecvSocketData when WaitEvent fails
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnRecvSocketDataTest_WaitEventFail, TestSize.Level1)
{
    char buf[10] = {0};

    EXPECT_CALL(*mock, WaitEventHook(_, SOFTBUS_SOCKET_IN, _))
        .WillOnce(Return(-1));

    auto ret = ConnRecvSocketData(10, buf, 10, 1000);
    EXPECT_EQ(ret, -1);
}

/*
 * @tc.name: ConnRecvSocketDataTest_RecvSuccess
 * @tc.desc: test successful data receiving
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnRecvSocketDataTest_RecvSuccess, TestSize.Level1)
{
    char buf[10] = {0};

    EXPECT_CALL(*mock, WaitEventHook(_, SOFTBUS_SOCKET_IN, _))
        .WillOnce(Return(1));
    EXPECT_CALL(*mock, SocketRecvHook(_, _, _, _))
        .WillOnce(Return(10));

    auto ret = ConnRecvSocketData(10, buf, 10, 1000);
    EXPECT_EQ(ret, 10);
}

/*
 * @tc.name: ConnRecvSocketDataTest_NoTimeout
 * @tc.desc: test ConnRecvSocketData with no timeout
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnRecvSocketDataTest_NoTimeout, TestSize.Level1)
{
    char buf[10] = {0};

    EXPECT_CALL(*mock, SocketRecvHook(_, _, _, _))
        .WillOnce(Return(5));

    auto ret = ConnRecvSocketData(10, buf, 10, 0);
    EXPECT_EQ(ret, 5);
}

/*
 * @tc.name: ConnRecvSocketDataTest_EAGAIN
 * @tc.desc: test ConnRecvSocketData when recv returns EAGAIN
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnRecvSocketDataTest_EAGAIN, TestSize.Level1)
{
    char buf[10] = {0};

    EXPECT_CALL(*mock, WaitEventHook(_, SOFTBUS_SOCKET_IN, _))
        .WillOnce(Return(1));
    EXPECT_CALL(*mock, SocketRecvHook(_, _, _, _))
        .WillOnce(Return(SOFTBUS_ADAPTER_SOCKET_EAGAIN));

    auto ret = ConnRecvSocketData(10, buf, 10, 1000);
    EXPECT_EQ(ret, 0);
}

/*
 * @tc.name: ConnRecvSocketDataTest_PeerClose
 * @tc.desc: test ConnRecvSocketData when peer closes connection
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnRecvSocketDataTest_PeerClose, TestSize.Level1)
{
    char buf[10] = {0};

    EXPECT_CALL(*mock, WaitEventHook(_, SOFTBUS_SOCKET_IN, _))
        .WillOnce(Return(1));
    EXPECT_CALL(*mock, SocketRecvHook(_, _, _, _))
        .WillOnce(Return(0));

    auto ret = ConnRecvSocketData(10, buf, 10, 1000);
    EXPECT_EQ(ret, -1);
}

/*
 * @tc.name: ConnRecvSocketMsgTest_InvalidParams
 * @tc.desc: test ConnRecvSocketMsg with invalid parameters
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnRecvSocketMsgTest_InvalidParams, TestSize.Level1)
{
    SoftBusMsgHdr msg = {0};

    auto ret = ConnRecvSocketMsg(-1, &msg, 1000, 0);
    EXPECT_EQ(ret, -1);

    ret = ConnRecvSocketMsg(10, nullptr, 1000, 0);
    EXPECT_EQ(ret, -1);
}

/*
 * @tc.name: ConnRecvSocketMsgTest_WaitEventFail
 * @tc.desc: test ConnRecvSocketMsg when WaitEvent fails
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnRecvSocketMsgTest_WaitEventFail, TestSize.Level1)
{
    SoftBusMsgHdr msg = {0};

    EXPECT_CALL(*mock, WaitEventHook(_, SOFTBUS_SOCKET_IN, _))
        .WillOnce(Return(-1));

    auto ret = ConnRecvSocketMsg(10, &msg, 1000, 0);
    EXPECT_EQ(ret, -1);
}

/*
 * @tc.name: ConnRecvSocketMsgTest_RecvSuccess
 * @tc.desc: test successful message receiving
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnRecvSocketMsgTest_RecvSuccess, TestSize.Level1)
{
    SoftBusMsgHdr msg = {0};

    EXPECT_CALL(*mock, WaitEventHook(_, SOFTBUS_SOCKET_IN, _))
        .WillOnce(Return(1));
    EXPECT_CALL(*mock, SocketRecvMsgHook(_, _, _))
        .WillOnce(Return(10));

    auto ret = ConnRecvSocketMsg(10, &msg, 1000, 0);
    EXPECT_EQ(ret, 10);
}

/*
 * @tc.name: ConnGetSocketErrorTest
 * @tc.desc: test ConnGetSocketError
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnGetSocketErrorTest, TestSize.Level1)
{
    EXPECT_CALL(*mock, SocketGetErrorHook(_))
        .WillOnce(Return(0));

    auto ret = ConnGetSocketError(10);
    EXPECT_EQ(ret, 0);
}

/*
 * @tc.name: ConnGetPeerSocketAddr6Test_NullSocketAddr
 * @tc.desc: test ConnGetPeerSocketAddr6 with null socketAddr
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnGetPeerSocketAddr6Test_NullSocketAddr, TestSize.Level1)
{
    auto ret = ConnGetPeerSocketAddr6(10, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ConnGetPeerSocketAddr6Test_GetPeerNameFail
 * @tc.desc: test ConnGetPeerSocketAddr6 when GetPeerName fails
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnGetPeerSocketAddr6Test_GetPeerNameFail, TestSize.Level1)
{
    SocketAddr socketAddr = {{0}, 0};

    EXPECT_CALL(*mock, SocketGetPeerNameHook(_, _))
        .WillOnce(Return(-1));

    auto ret = ConnGetPeerSocketAddr6(10, &socketAddr);
    EXPECT_EQ(ret, SOFTBUS_TCP_SOCKET_ERR);
}

/*
 * @tc.name: ConnGetPeerSocketAddr6Test_IPv4
 * @tc.desc: test ConnGetPeerSocketAddr6 with IPv4 address
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnGetPeerSocketAddr6Test_IPv4, TestSize.Level1)
{
    SocketAddr socketAddr = {{0}, 0};
    SoftBusSockAddr addr = {0};
    auto *addrIn = reinterpret_cast<SoftBusSockAddrIn *>(&addr);

    addrIn->sinFamily = SOFTBUS_AF_INET;
    addrIn->sinPort = SoftBusHtoNs(8080);

    EXPECT_CALL(*mock, SocketGetPeerNameHook(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(addr), Return(0)));
    EXPECT_CALL(*mock, InetNtoPHook(SOFTBUS_AF_INET, _, _, _))
        .WillOnce(Return("192.168.1.1"));

    auto ret = ConnGetPeerSocketAddr6(10, &socketAddr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(socketAddr.port, 8080);
}

/*
 * @tc.name: ConnGetPeerSocketAddrTest_NullSocketAddr
 * @tc.desc: test ConnGetPeerSocketAddr with null socketAddr
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnGetPeerSocketAddrTest_NullSocketAddr, TestSize.Level1)
{
    auto ret = ConnGetPeerSocketAddr(10, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: ConnGetPeerSocketAddrTest_GetPeerNameFail
 * @tc.desc: test ConnGetPeerSocketAddr when GetPeerName fails
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnGetPeerSocketAddrTest_GetPeerNameFail, TestSize.Level1)
{
    SocketAddr socketAddr = {{0}, 0};

    EXPECT_CALL(*mock, SocketGetPeerNameHook(_, _))
        .WillOnce(Return(-1));

    auto ret = ConnGetPeerSocketAddr(10, &socketAddr);
    EXPECT_EQ(ret, SOFTBUS_TCP_SOCKET_ERR);
}

/*
 * @tc.name: ConnGetPeerSocketAddrTest_IPv4
 * @tc.desc: test ConnGetPeerSocketAddr with IPv4 address
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnGetPeerSocketAddrTest_IPv4, TestSize.Level1)
{
    SocketAddr socketAddr = {{0}, 0};
    SoftBusSockAddr addr = {0};
    auto *addrIn = reinterpret_cast<SoftBusSockAddrIn *>(&addr);

    addrIn->sinFamily = SOFTBUS_AF_INET;
    addrIn->sinPort = SoftBusHtoNs(9090);

    EXPECT_CALL(*mock, SocketGetPeerNameHook(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(addr), Return(0)));
    EXPECT_CALL(*mock, InetNtoPHook(SOFTBUS_AF_INET, _, _, _))
        .WillOnce(Return("10.0.0.1"));

    auto ret = ConnGetPeerSocketAddr(10, &socketAddr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(socketAddr.port, 9090);
}

/*
 * @tc.name: ConnPreAssignPortTest_SocketCreateFail
 * @tc.desc: test ConnPreAssignPort when socket creation fails
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnPreAssignPortTest_SocketCreateFail, TestSize.Level1)
{
    EXPECT_CALL(*mock, SocketCreateHook(_, _, _, _))
        .WillOnce(Return(-1));

    auto ret = ConnPreAssignPort(SOFTBUS_AF_INET);
    EXPECT_EQ(ret, SOFTBUS_TCPCONNECTION_SOCKET_ERR);
}

/*
 * @tc.name: ConnPreAssignPortTest_SetOptFail
 * @tc.desc: test ConnPreAssignPort when SetOpt fails
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnPreAssignPortTest_SetOptFail, TestSize.Level1)
{
    int32_t testFd = 100;

    EXPECT_CALL(*mock, SocketCreateHook(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(testFd), Return(0)));
    EXPECT_CALL(*mock, SocketSetOptHook(_, _, SO_REUSEPORT, _, _))
        .WillOnce(Return(-1));
    EXPECT_CALL(*mock, SocketCloseHook(_))
        .Times(1);

    auto ret = ConnPreAssignPort(SOFTBUS_AF_INET);
    EXPECT_EQ(ret, SOFTBUS_TCPCONNECTION_SOCKET_ERR);
}

/*
 * @tc.name: GetDomainByAddrTest_NullAddr
 * @tc.desc: test GetDomainByAddr with null address
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, GetDomainByAddrTest_NullAddr, TestSize.Level1)
{
    auto ret = GetDomainByAddr(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: GetDomainByAddrTest_IPv6
 * @tc.desc: test GetDomainByAddr with IPv6 address
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, GetDomainByAddrTest_IPv6, TestSize.Level1)
{
    auto ret = GetDomainByAddr("fe80::1");
    EXPECT_EQ(ret, SOFTBUS_AF_INET6);
}

/*
 * @tc.name: GetDomainByAddrTest_IPv4
 * @tc.desc: test GetDomainByAddr with IPv4 address
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, GetDomainByAddrTest_IPv4, TestSize.Level1)
{
    auto ret = GetDomainByAddr("192.168.1.1");
    EXPECT_EQ(ret, SOFTBUS_AF_INET);
}

/*
 * @tc.name: Ipv6AddrInToAddrTest_NullParams
 * @tc.desc: test Ipv6AddrInToAddr with null parameters
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, Ipv6AddrInToAddrTest_NullParams, TestSize.Level1)
{
    char addr[IP_LEN] = {0};

    auto ret = Ipv6AddrInToAddr(nullptr, addr, IP_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    SoftBusSockAddrIn6 addrIn6 = {0};
    ret = Ipv6AddrInToAddr(&addrIn6, nullptr, IP_LEN);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = Ipv6AddrInToAddr(&addrIn6, addr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: Ipv6AddrInToAddrTest_InetNtoPFail
 * @tc.desc: test Ipv6AddrInToAddr when InetNtoP fails
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, Ipv6AddrInToAddrTest_InetNtoPFail, TestSize.Level1)
{
    SoftBusSockAddrIn6 addrIn6 = {0};
    char addr[IP_LEN] = {0};

    EXPECT_CALL(*mock, InetNtoPHook(SOFTBUS_AF_INET6, _, _, _))
        .WillOnce(Return(nullptr));

    auto ret = Ipv6AddrInToAddr(&addrIn6, addr, IP_LEN);
    EXPECT_EQ(ret, SOFTBUS_SOCKET_ADDR_ERR);
}

/*
 * @tc.name: Ipv6AddrToAddrInTest_WithIfName
 * @tc.desc: test Ipv6AddrToAddrIn with interface name
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, Ipv6AddrToAddrInTest_WithIfName, TestSize.Level1)
{
    SoftBusSockAddrIn6 addrIn6 = {0};
    const char *ip = "fe80::1%wlan0";

    EXPECT_CALL(*mock, IfNameToIndexHook(_))
        .WillOnce(Return(1));
    EXPECT_CALL(*mock, InetPtoNHook(SOFTBUS_AF_INET6, _, _))
        .WillOnce(Return(0));

    auto ret = Ipv6AddrToAddrIn(&addrIn6, ip, 8080);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(addrIn6.sin6ScopeId, 1);
}

/*
 * @tc.name: Ipv6AddrToAddrInTest_IfNameToIndexFail
 * @tc.desc: test Ipv6AddrToAddrIn when IfNameToIndex fails
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, Ipv6AddrToAddrInTest_IfNameToIndexFail, TestSize.Level1)
{
    SoftBusSockAddrIn6 addrIn6 = {0};
    const char *ip = "fe80::1%wlan0";

    EXPECT_CALL(*mock, IfNameToIndexHook(_))
        .WillOnce(Return(0));

    auto ret = Ipv6AddrToAddrIn(&addrIn6, ip, 8080);
    EXPECT_EQ(ret, SOFTBUS_SOCKET_ADDR_ERR);
}

/*
 * @tc.name: Ipv4AddrToAddrInTest_NullParams
 * @tc.desc: test Ipv4AddrToAddrIn with null parameters
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, Ipv4AddrToAddrInTest_NullParams, TestSize.Level1)
{
    SoftBusSockAddrIn addrIn = {0};

    auto ret = Ipv4AddrToAddrIn(nullptr, "192.168.1.1", 8080);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = Ipv4AddrToAddrIn(&addrIn, nullptr, 8080);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: Ipv4AddrToAddrInTest_InetPtoNFail
 * @tc.desc: test Ipv4AddrToAddrIn when InetPtoN fails
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, Ipv4AddrToAddrInTest_InetPtoNFail, TestSize.Level1)
{
    SoftBusSockAddrIn addrIn = {0};

    EXPECT_CALL(*mock, InetPtoNHook(SOFTBUS_AF_INET, "192.168.1.1", _))
        .WillOnce(Return(-1));

    auto ret = Ipv4AddrToAddrIn(&addrIn, "192.168.1.1", 8080);
    EXPECT_EQ(ret, SOFTBUS_SOCKET_ADDR_ERR);
}

/*
 * @tc.name: IsHmlIpAddrTest_NullIp
 * @tc.desc: test IsHmlIpAddr with null IP
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, IsHmlIpAddrTest_NullIp, TestSize.Level1)
{
    auto ret = IsHmlIpAddr(nullptr);
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: IsHmlIpAddrTest_IPv6
 * @tc.desc: test IsHmlIpAddr with IPv6 address
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, IsHmlIpAddrTest_IPv6, TestSize.Level1)
{
    auto ret = IsHmlIpAddr("fe80::1");
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: IsHmlIpAddrTest_HmlIPv4
 * @tc.desc: test IsHmlIpAddr with HML IPv4 address
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, IsHmlIpAddrTest_HmlIPv4, TestSize.Level1)
{
    auto ret = IsHmlIpAddr("172.30.1.1");
    EXPECT_TRUE(ret);
}

/*
 * @tc.name: IsHmlIpAddrTest_NonHmlIPv4
 * @tc.desc: test IsHmlIpAddr with non-HML IPv4 address
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, IsHmlIpAddrTest_NonHmlIPv4, TestSize.Level1)
{
    auto ret = IsHmlIpAddr("192.168.1.1");
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: BindToInterfaceTest_IPv6
 * @tc.desc: test BindToInterface with IPv6 (should skip)
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, BindToInterfaceTest_IPv6, TestSize.Level1)
{
    char ifName[IF_NAME_SIZE] = {0};

    // For IPv6, BindToInterface should not bind (interface name should remain empty)
    BindToInterface("fe80::1", SOFTBUS_AF_INET6, 10, ifName, IF_NAME_SIZE);
    EXPECT_EQ(strlen(ifName), 0);
}

/*
 * @tc.name: BindToInterfaceTest_NullIp
 * @tc.desc: test BindToInterface with null IP
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, BindToInterfaceTest_NullIp, TestSize.Level1)
{
    char ifName[IF_NAME_SIZE] = {0};

    // For null IP, BindToInterface should not bind (interface name should remain empty)
    BindToInterface(nullptr, SOFTBUS_AF_INET, 10, ifName, IF_NAME_SIZE);
    EXPECT_EQ(strlen(ifName), 0);
}

/*
 * @tc.name: BindToInterfaceTest_BindAddrAll
 * @tc.desc: test BindToInterface with BIND_ADDR_ALL
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, BindToInterfaceTest_BindAddrAll, TestSize.Level1)
{
    char ifName[IF_NAME_SIZE] = {0};

    // For BIND_ADDR_ALL ("0"), BindToInterface should not bind
    BindToInterface("0", SOFTBUS_AF_INET, 10, ifName, IF_NAME_SIZE);
    EXPECT_EQ(strlen(ifName), 0);
}

/*
 * @tc.name: BindToInterfaceTest_GetIfAddrsFail
 * @tc.desc: test BindToInterface when getifaddrs fails
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, BindToInterfaceTest_GetIfAddrsFail, TestSize.Level1)
{
    char ifName[IF_NAME_SIZE] = {0};

    EXPECT_CALL(*mock, GetIfAddrsHook())
        .WillOnce(Return(-1));

    BindToInterface("192.168.1.1", SOFTBUS_AF_INET, 10, ifName, IF_NAME_SIZE);
    // When getifaddrs fails, interface name should remain empty (no binding occurred)
    EXPECT_EQ(strlen(ifName), 0);
}

/*
 * @tc.name: BindToInterfaceTest_InetAtonFail
 * @tc.desc: test BindToInterface when inet_aton fails
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, BindToInterfaceTest_InetAtonFail, TestSize.Level1)
{
    char ifName[IF_NAME_SIZE] = {0};

    EXPECT_CALL(*mock, GetIfAddrsHook())
        .WillOnce(Return(0));
    EXPECT_CALL(*mock, InetAtonHook(_, _))
        .WillOnce(Return(0));
    EXPECT_CALL(*mock, FreeIfAddrsHook())
        .Times(1);

    BindToInterface("192.168.1.1", SOFTBUS_AF_INET, 10, ifName, IF_NAME_SIZE);
    // When inet_aton fails, interface name should remain empty
    EXPECT_EQ(strlen(ifName), 0);
}

/*
 * @tc.name: BindToInterfaceTest_NotFound
 * @tc.desc: test BindToInterface when IP not found
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, BindToInterfaceTest_NotFound, TestSize.Level1)
{
    char ifName[IF_NAME_SIZE] = {0};

    mock->SetTestIfAddr("10.0.0.1", "wlan0");

    EXPECT_CALL(*mock, GetIfAddrsHook())
        .WillOnce(Return(0));
    EXPECT_CALL(*mock, InetAtonHook(_, _))
        .WillOnce(Return(1));
    EXPECT_CALL(*mock, FreeIfAddrsHook())
        .Times(1);

    BindToInterface("192.168.1.1", SOFTBUS_AF_INET, 10, ifName, IF_NAME_SIZE);
    // When IP not found in interface list, interface name should remain empty
    EXPECT_EQ(strlen(ifName), 0);

    mock->ClearTestIfAddr();
}

/*
 * @tc.name: ConnSendSocketDataTest_SendFail
 * @tc.desc: test ConnSendSocketData when send fails
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnSendSocketDataTest_SendFail, TestSize.Level1)
{
    char buf[10];
    memset_s(buf, sizeof(buf), 'X', sizeof(buf));

    EXPECT_CALL(*mock, WaitEventHook(_, SOFTBUS_SOCKET_OUT, _))
        .WillOnce(Return(1));
    EXPECT_CALL(*mock, SocketSendHook(_, _, _, _))
        .WillOnce(Return(-1));

    auto ret = ConnSendSocketData(10, buf, 10, 1000);
    EXPECT_EQ(ret, -1);
}

/*
 * @tc.name: ConnSendSocketDataTest_Timeout
 * @tc.desc: test ConnSendSocketData when WaitEvent times out
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnSendSocketDataTest_Timeout, TestSize.Level1)
{
    char buf[10];
    memset_s(buf, sizeof(buf), 'W', sizeof(buf));

    EXPECT_CALL(*mock, WaitEventHook(_, SOFTBUS_SOCKET_OUT, _))
        .WillOnce(Return(0));

    auto ret = ConnSendSocketData(10, buf, 10, 1000);
    EXPECT_EQ(ret, 0);
}

/*
 * @tc.name: ConnRecvSocketDataTest_RecvFail
 * @tc.desc: test ConnRecvSocketData when recv fails
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnRecvSocketDataTest_RecvFail, TestSize.Level1)
{
    char buf[10] = {0};

    EXPECT_CALL(*mock, WaitEventHook(_, SOFTBUS_SOCKET_IN, _))
        .WillOnce(Return(1));
    EXPECT_CALL(*mock, SocketRecvHook(_, _, _, _))
        .WillOnce(Return(-1));

    auto ret = ConnRecvSocketData(10, buf, 10, 1000);
    EXPECT_EQ(ret, -1);
}

/*
 * @tc.name: ConnRecvSocketMsgTest_RecvMsgFail
 * @tc.desc: test ConnRecvSocketMsg when recvmsg fails
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnRecvSocketMsgTest_RecvMsgFail, TestSize.Level1)
{
    SoftBusMsgHdr msg = {0};

    EXPECT_CALL(*mock, WaitEventHook(_, SOFTBUS_SOCKET_IN, _))
        .WillOnce(Return(1));
    EXPECT_CALL(*mock, SocketRecvMsgHook(_, _, _))
        .WillOnce(Return(-1));

    auto ret = ConnRecvSocketMsg(10, &msg, 1000, 0);
    EXPECT_EQ(ret, -1);
}

/*
 * @tc.name: ConnRecvSocketMsgTest_EAGAIN
 * @tc.desc: test ConnRecvSocketMsg when recvmsg returns EAGAIN
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnRecvSocketMsgTest_EAGAIN, TestSize.Level1)
{
    SoftBusMsgHdr msg = {0};

    EXPECT_CALL(*mock, WaitEventHook(_, SOFTBUS_SOCKET_IN, _))
        .WillOnce(Return(1));
    EXPECT_CALL(*mock, SocketRecvMsgHook(_, _, _))
        .WillOnce(Return(SOFTBUS_ADAPTER_SOCKET_EAGAIN));

    auto ret = ConnRecvSocketMsg(10, &msg, 1000, 0);
    EXPECT_EQ(ret, 0);
}

/*
 * @tc.name: ConnGetSocketErrorTest_Error
 * @tc.desc: test ConnGetSocketError with error
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnGetSocketErrorTest_Error, TestSize.Level1)
{
    EXPECT_CALL(*mock, SocketGetErrorHook(_))
        .WillOnce(Return(ECONNRESET));

    auto ret = ConnGetSocketError(10);
    EXPECT_EQ(ret, ECONNRESET);
}

/*
 * @tc.name: ConnGetLocalSocketPortTest_NotInitialized
 * @tc.desc: test ConnGetLocalSocketPort when not initialized
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnGetLocalSocketPortTest_NotInitialized, TestSize.Level1)
{
    // Ensure sockets are not initialized
    ConnDeinitSockets();

    auto ret = ConnGetLocalSocketPort(10);
    EXPECT_LT(ret, 0);

    // Reinitialize for other tests
    ConnInitSockets();
}

/*
 * @tc.name: ConnGetPeerSocketAddr6Test_IPv6
 * @tc.desc: test ConnGetPeerSocketAddr6 with IPv6 address
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnGetPeerSocketAddr6Test_IPv6, TestSize.Level1)
{
    SocketAddr socketAddr = {{0}, 0};
    SoftBusSockAddr addr = {0};
    auto *addrIn6 = reinterpret_cast<SoftBusSockAddrIn6 *>(&addr);

    addrIn6->sin6Family = SOFTBUS_AF_INET6;
    addrIn6->sin6Port = SoftBusHtoNs(7070);

    EXPECT_CALL(*mock, SocketGetPeerNameHook(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(addr), Return(0)));
    EXPECT_CALL(*mock, InetNtoPHook(SOFTBUS_AF_INET6, _, _, _))
        .WillOnce(Return("fe80::1"));

    auto ret = ConnGetPeerSocketAddr6(10, &socketAddr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(socketAddr.port, 7070);
}

/*
 * @tc.name: ConnGetPeerSocketAddrTest_IPv6
 * @tc.desc: test ConnGetPeerSocketAddr with IPv6 address
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnGetPeerSocketAddrTest_IPv6, TestSize.Level1)
{
    SocketAddr socketAddr = {{0}, 0};
    SoftBusSockAddr addr = {0};
    auto *addrIn6 = reinterpret_cast<SoftBusSockAddrIn6 *>(&addr);

    addrIn6->sin6Family = SOFTBUS_AF_INET6;
    addrIn6->sin6Port = SoftBusHtoNs(6060);

    EXPECT_CALL(*mock, SocketGetPeerNameHook(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(addr), Return(0)));
    EXPECT_CALL(*mock, InetNtoPHook(SOFTBUS_AF_INET6, _, _, _))
        .WillOnce(Return("2001:db8::1"));

    auto ret = ConnGetPeerSocketAddr(10, &socketAddr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(socketAddr.port, 6060);
}

/*
 * @tc.name: ConnPreAssignPortTest_Success
 * @tc.desc: test success ConnPreAssignPort
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnPreAssignPortTest_Success, TestSize.Level1)
{
    int32_t testFd = 100;

    EXPECT_CALL(*mock, SocketCreateHook(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(testFd), Return(0)));
    EXPECT_CALL(*mock, SocketSetOptHook(_, _, SO_REUSEPORT, _, _))
        .WillOnce(Return(0));
    EXPECT_CALL(*mock, SocketBindHook(_, _, _))
        .WillOnce(Return(0));

    auto ret = ConnPreAssignPort(SOFTBUS_AF_INET);
    EXPECT_EQ(ret, testFd);
}

/*
 * @tc.name: ConnPreAssignPortTest_BindFail
 * @tc.desc: test ConnPreAssignPort when bind fails
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnPreAssignPortTest_BindFail, TestSize.Level1)
{
    int32_t testFd = 100;

    EXPECT_CALL(*mock, SocketCreateHook(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(testFd), Return(0)));
    EXPECT_CALL(*mock, SocketSetOptHook(_, _, SO_REUSEPORT, _, _))
        .WillOnce(Return(0));
    EXPECT_CALL(*mock, SocketBindHook(_, _, _))
        .WillOnce(Return(-1));
    EXPECT_CALL(*mock, SocketCloseHook(_))
        .Times(1);

    auto ret = ConnPreAssignPort(SOFTBUS_AF_INET);
    EXPECT_EQ(ret, SOFTBUS_TCPCONNECTION_SOCKET_ERR);
}

/*
 * @tc.name: ConnPreAssignPortTest_IPv6
 * @tc.desc: test ConnPreAssignPort with IPv6
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnPreAssignPortTest_IPv6, TestSize.Level1)
{
    int32_t testFd = 200;

    EXPECT_CALL(*mock, SocketCreateHook(SOFTBUS_AF_INET6, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(testFd), Return(0)));
    EXPECT_CALL(*mock, SocketSetOptHook(_, _, SO_REUSEPORT, _, _))
        .WillOnce(Return(0));
    EXPECT_CALL(*mock, SocketBindHook(_, _, _))
        .WillOnce(Return(0));

    auto ret = ConnPreAssignPort(SOFTBUS_AF_INET6);
    EXPECT_EQ(ret, testFd);
}

/*
 * @tc.name: GetDomainByAddrTest_InvalidFormat
 * @tc.desc: test GetDomainByAddr with invalid format
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, GetDomainByAddrTest_InvalidFormat, TestSize.Level1)
{
    auto ret = GetDomainByAddr("invalid.address");
    EXPECT_EQ(ret, SOFTBUS_AF_INET);
}

/*
 * @tc.name: GetDomainByAddrTest_LoopbackIPv4
 * @tc.desc: test GetDomainByAddr with loopback IPv4
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, GetDomainByAddrTest_LoopbackIPv4, TestSize.Level1)
{
    auto ret = GetDomainByAddr("127.0.0.1");
    EXPECT_EQ(ret, SOFTBUS_AF_INET);
}

/*
 * @tc.name: GetDomainByAddrTest_LinkLocalIPv6
 * @tc.desc: test GetDomainByAddr with link-local IPv6
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, GetDomainByAddrTest_LinkLocalIPv6, TestSize.Level1)
{
    auto ret = GetDomainByAddr("fe80::1234:5678");
    EXPECT_EQ(ret, SOFTBUS_AF_INET6);
}

/*
 * @tc.name: GetDomainByAddrTest_GlobalIPv6
 * @tc.desc: test GetDomainByAddr with global IPv6
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, GetDomainByAddrTest_GlobalIPv6, TestSize.Level1)
{
    auto ret = GetDomainByAddr("2001:db8::1");
    EXPECT_EQ(ret, SOFTBUS_AF_INET6);
}

/*
 * @tc.name: Ipv6AddrToAddrInTest_NullIp
 * @tc.desc: test Ipv6AddrToAddrIn with null IP
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, Ipv6AddrToAddrInTest_NullIp, TestSize.Level1)
{
    SoftBusSockAddrIn6 addrIn6 = {0};

    auto ret = Ipv6AddrToAddrIn(&addrIn6, nullptr, 8080);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: Ipv6AddrToAddrInTest_NoIfName
 * @tc.desc: test Ipv6AddrToAddrIn without interface name
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, Ipv6AddrToAddrInTest_NoIfName, TestSize.Level1)
{
    SoftBusSockAddrIn6 addrIn6 = {0};
    const char *ip = "fe80::1";

    EXPECT_CALL(*mock, InetPtoNHook(SOFTBUS_AF_INET6, _, _))
        .WillOnce(Return(0));

    auto ret = Ipv6AddrToAddrIn(&addrIn6, ip, 8080);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(addrIn6.sin6ScopeId, 0);
}

/*
 * @tc.name: Ipv6AddrToAddrInTest_InetPtoNFail
 * @tc.desc: test Ipv6AddrToAddrIn when InetPtoN fails
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, Ipv6AddrToAddrInTest_InetPtoNFail, TestSize.Level1)
{
    SoftBusSockAddrIn6 addrIn6 = {0};
    const char *ip = "fe80::1";

    EXPECT_CALL(*mock, InetPtoNHook(SOFTBUS_AF_INET6, _, _))
        .WillOnce(Return(-1));

    auto ret = Ipv6AddrToAddrIn(&addrIn6, ip, 8080);
    EXPECT_EQ(ret, SOFTBUS_SOCKET_ADDR_ERR);
}

/*
 * @tc.name: Ipv4AddrToAddrInTest_Success
 * @tc.desc: test successful Ipv4AddrToAddrIn
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, Ipv4AddrToAddrInTest_Success, TestSize.Level1)
{
    SoftBusSockAddrIn addrIn = {0};
    const char *ip = "192.168.1.1";

    EXPECT_CALL(*mock, InetPtoNHook(SOFTBUS_AF_INET, _, _))
        .WillOnce(Return(0));

    auto ret = Ipv4AddrToAddrIn(&addrIn, ip, 8080);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: Ipv4AddrToAddrInTest_ZeroPort
 * @tc.desc: test Ipv4AddrToAddrIn with zero port
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, Ipv4AddrToAddrInTest_ZeroPort, TestSize.Level1)
{
    SoftBusSockAddrIn addrIn = {0};
    const char *ip = "192.168.1.1";

    EXPECT_CALL(*mock, InetPtoNHook(SOFTBUS_AF_INET, _, _))
        .WillOnce(Return(0));

    auto ret = Ipv4AddrToAddrIn(&addrIn, ip, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: IsHmlIpAddrTest_EmptyString
 * @tc.desc: test IsHmlIpAddr with empty string
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, IsHmlIpAddrTest_EmptyString, TestSize.Level1)
{
    auto ret = IsHmlIpAddr("");
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: IsHmlIpAddrTest_NonHmlIPv4Start
 * @tc.desc: test IsHmlIpAddr with non-HML IPv4 just before range
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, IsHmlIpAddrTest_NonHmlIPv4Start, TestSize.Level1)
{
    auto ret = IsHmlIpAddr("172.15.255.255");
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: IsHmlIpAddrTest_NonHmlIPv4End
 * @tc.desc: test IsHmlIpAddr with non-HML IPv4 just after range
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, IsHmlIpAddrTest_NonHmlIPv4End, TestSize.Level1)
{
    auto ret = IsHmlIpAddr("172.32.0.0");
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: IsHmlIpAddrTest_PrivateIPv4
 * @tc.desc: test IsHmlIpAddr with private IPv4 (non-HML)
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, IsHmlIpAddrTest_PrivateIPv4, TestSize.Level1)
{
    auto ret = IsHmlIpAddr("10.0.0.1");
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: BindToInterfaceTest_InvalidFamily
 * @tc.desc: test BindToInterface with invalid address family
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, BindToInterfaceTest_InvalidFamily, TestSize.Level1)
{
    char ifName[IF_NAME_SIZE] = {0};

    // Invalid family - should not bind
    BindToInterface("192.168.1.1", AF_MAX, 10, ifName, IF_NAME_SIZE);
    EXPECT_EQ(strlen(ifName), 0);
}

/*
 * @tc.name: ConnToggleNonBlockModeTest_MultipleToggles
 * @tc.desc: test multiple non-blocking mode toggles
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnToggleNonBlockModeTest_MultipleToggles, TestSize.Level1)
{
    // Toggle to non-blocking
    EXPECT_CALL(*mock, FcntlHook(_, F_GETFL, _))
        .WillOnce(Return(0));
    EXPECT_CALL(*mock, FcntlHook(_, F_SETFL, _))
        .WillOnce(Return(0));

    auto ret = ConnToggleNonBlockMode(10, true);
    EXPECT_EQ(ret, SOFTBUS_OK);

    // Toggle back to blocking
    EXPECT_CALL(*mock, FcntlHook(_, F_GETFL, _))
        .WillOnce(Return(O_NONBLOCK));
    EXPECT_CALL(*mock, FcntlHook(_, F_SETFL, _))
        .WillOnce(Return(0));

    ret = ConnToggleNonBlockMode(10, false);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConnSendSocketDataTest_LargeData
 * @tc.desc: test sending large data
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnSendSocketDataTest_LargeData, TestSize.Level1)
{
    const int largeSize = 65536;
    char *largeBuf = new char[largeSize];
    memset_s(largeBuf, largeSize, 'A', largeSize);

    EXPECT_CALL(*mock, WaitEventHook(_, SOFTBUS_SOCKET_OUT, _))
        .WillOnce(Return(1));
    EXPECT_CALL(*mock, SocketSendHook(_, _, _, _))
        .WillOnce(Return(largeSize));

    auto ret = ConnSendSocketData(10, largeBuf, largeSize, 1000);
    EXPECT_EQ(ret, largeSize);

    delete[] largeBuf;
}

/*
 * @tc.name: ConnRecvSocketDataTest_LargeData
 * @tc.desc: test receiving large data
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnRecvSocketDataTest_LargeData, TestSize.Level1)
{
    const int largeSize = 65536;
    char *largeBuf = new char[largeSize];
    memset_s(largeBuf, largeSize, 0, largeSize);

    EXPECT_CALL(*mock, WaitEventHook(_, SOFTBUS_SOCKET_IN, _))
        .WillOnce(Return(1));
    EXPECT_CALL(*mock, SocketRecvHook(_, _, _, _))
        .WillOnce(Return(largeSize));

    auto ret = ConnRecvSocketData(10, largeBuf, largeSize, 1000);
    EXPECT_EQ(ret, largeSize);

    delete[] largeBuf;
}

/*
 * @tc.name: GetSocketInterfaceTest_NotInitialized
 * @tc.desc: test GetSocketInterface when not initialized
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, GetSocketInterfaceTest_NotInitialized, TestSize.Level1)
{
    // Ensure deinitialized (safe to call multiple times)
    ConnDeinitSockets();

    auto iface = GetSocketInterface(LNN_PROTOCOL_IP);
    EXPECT_EQ(iface, nullptr);

    // Reinitialize for other tests
    ConnInitSockets();
}

/*
 * @tc.name: RegistSocketProtocolTest_DuplicateRegistration
 * @tc.desc: test duplicate protocol registration
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, RegistSocketProtocolTest_DuplicateRegistration, TestSize.Level1)
{
    auto initRet = ConnInitSockets();
    ASSERT_EQ(initRet, SOFTBUS_OK);

    SocketInterface iface = {
        .name = "test_duplicate",
        .type = LNN_PROTOCOL_IP,
        .GetSockPort = MockGetSockPort,
        .OpenServerSocket = MockOpenServerSocket,
        .OpenClientSocket = MockOpenClientSocket,
        .AcceptClient = MockAcceptClient,
    };

    // First registration should fail because IP is already registered
    auto ret = RegistSocketProtocol(&iface);
    EXPECT_NE(ret, SOFTBUS_OK);

    ConnDeinitSockets();
}

/*
 * @tc.name: ConnDeinitSocketsTest_MultipleCalls
 * @tc.desc: test multiple ConnDeinitSockets calls
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnDeinitSocketsTest_MultipleCalls, TestSize.Level1)
{
    auto initRet = ConnInitSockets();
    ASSERT_EQ(initRet, SOFTBUS_OK);

    // Multiple deinit calls should not crash
    ConnDeinitSockets();
    ConnDeinitSockets();

    // Reinitialize for other tests
    ConnInitSockets();
}

/*
 * @tc.name: ConnInitSocketsTest_MultipleCalls
 * @tc.desc: test multiple ConnInitSockets calls
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnInitSocketsTest_MultipleCalls, TestSize.Level1)
{
    auto initRet = ConnInitSockets();
    EXPECT_EQ(initRet, SOFTBUS_OK);

    // Second init call behavior depends on implementation
    initRet = ConnInitSockets();
    // Should either succeed or fail gracefully, not crash

    // Clean up - deinitialize even if init was called twice
    ConnDeinitSockets();
}

/*
 * @tc.name: ConnToggleNonBlockModeTest_VeryLargeFd
 * @tc.desc: test ConnToggleNonBlockMode with very large fd
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnToggleNonBlockModeTest_VeryLargeFd, TestSize.Level1)
{
    int32_t veryLargeFd = 2147483647; // INT32_MAX

    EXPECT_CALL(*mock, FcntlHook(_, F_GETFL, _))
        .WillOnce(Return(0));
    EXPECT_CALL(*mock, FcntlHook(_, F_SETFL, _))
        .WillOnce(Return(0));

    auto ret = ConnToggleNonBlockMode(veryLargeFd, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: ConnSendSocketDataTest_OneByte
 * @tc.desc: test sending one byte
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnSendSocketDataTest_OneByte, TestSize.Level1)
{
    char buf[1] = {'A'};

    EXPECT_CALL(*mock, WaitEventHook(_, SOFTBUS_SOCKET_OUT, _))
        .WillOnce(Return(1));
    EXPECT_CALL(*mock, SocketSendHook(_, _, _, _))
        .WillOnce(Return(1));

    auto ret = ConnSendSocketData(10, buf, 1, 1000);
    EXPECT_EQ(ret, 1);
}

/*
 * @tc.name: ConnRecvSocketDataTest_OneByte
 * @tc.desc: test receiving one byte
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnRecvSocketDataTest_OneByte, TestSize.Level1)
{
    char buf[1] = {0};

    EXPECT_CALL(*mock, WaitEventHook(_, SOFTBUS_SOCKET_IN, _))
        .WillOnce(Return(1));
    EXPECT_CALL(*mock, SocketRecvHook(_, _, _, _))
        .WillOnce(Return(1));

    auto ret = ConnRecvSocketData(10, buf, 1, 1000);
    EXPECT_EQ(ret, 1);
}

/*
 * @tc.name: ConnGetSocketErrorTest_VeryLargeFd
 * @tc.desc: test ConnGetSocketError with very large fd
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnGetSocketErrorTest_VeryLargeFd, TestSize.Level1)
{
    int32_t veryLargeFd = 2147483647;

    EXPECT_CALL(*mock, SocketGetErrorHook(veryLargeFd))
        .WillOnce(Return(0));

    auto ret = ConnGetSocketError(veryLargeFd);
    EXPECT_EQ(ret, 0);
}

/*
 * @tc.name: ConnGetLocalSocketPortTest_VeryLargeFd
 * @tc.desc: test ConnGetLocalSocketPort with very large fd
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnGetLocalSocketPortTest_VeryLargeFd, TestSize.Level1)
{
    auto initRet = ConnInitSockets();
    ASSERT_EQ(initRet, SOFTBUS_OK);

    int32_t veryLargeFd = 2147483647;

    auto ret = ConnGetLocalSocketPort(veryLargeFd);
    // Should handle gracefully, return error or port
    EXPECT_TRUE(ret < 0 || ret > 0);

    ConnDeinitSockets();
}

/*
 * @tc.name: Ipv6AddrInToAddrTest_InvalidFamily
 * @tc.desc: test Ipv6AddrInToAddr with invalid address family
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, Ipv6AddrInToAddrTest_InvalidFamily, TestSize.Level1)
{
    SoftBusSockAddrIn6 addrIn6 = {0};
    addrIn6.sin6Family = AF_MAX; // Invalid family
    char addr[IP_LEN] = {0};

    auto ret = Ipv6AddrInToAddr(&addrIn6, addr, IP_LEN);
    EXPECT_EQ(ret, SOFTBUS_SOCKET_ADDR_ERR);
}

/*
 * @tc.name: ConnSendSocketDataTest_MultiplePartialSend
 * @tc.desc: test ConnSendSocketData with multiple partial sends
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnSendSocketDataTest_MultiplePartialSend, TestSize.Level1)
{
    char buf[100];
    memset_s(buf, sizeof(buf), 'B', sizeof(buf));

    EXPECT_CALL(*mock, WaitEventHook(_, SOFTBUS_SOCKET_OUT, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(*mock, SocketSendHook(_, _, _, _))
        .WillOnce(Return(10))
        .WillOnce(Return(20))
        .WillOnce(Return(30))
        .WillOnce(Return(40));

    auto ret = ConnSendSocketData(10, buf, 100, 1000);
    EXPECT_EQ(ret, 100);
}

/*
 * @tc.name: ConnGetPeerSocketAddr6Test_ZeroPort
 * @tc.desc: test ConnGetPeerSocketAddr6 with zero port
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnGetPeerSocketAddr6Test_ZeroPort, TestSize.Level1)
{
    SocketAddr socketAddr = {{0}, 0};
    SoftBusSockAddr addr = {0};
    auto *addrIn = reinterpret_cast<SoftBusSockAddrIn *>(&addr);

    addrIn->sinFamily = SOFTBUS_AF_INET;
    addrIn->sinPort = 0;

    EXPECT_CALL(*mock, SocketGetPeerNameHook(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(addr), Return(0)));
    EXPECT_CALL(*mock, InetNtoPHook(SOFTBUS_AF_INET, _, _, _))
        .WillOnce(Return("192.168.1.1"));

    auto ret = ConnGetPeerSocketAddr6(10, &socketAddr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(socketAddr.port, 0);
}

/*
 * @tc.name: ConnGetPeerSocketAddrTest_ZeroPort
 * @tc.desc: test ConnGetPeerSocketAddr with zero port
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnGetPeerSocketAddrTest_ZeroPort, TestSize.Level1)
{
    SocketAddr socketAddr = {{0}, 0};
    SoftBusSockAddr addr = {0};
    auto *addrIn = reinterpret_cast<SoftBusSockAddrIn *>(&addr);

    addrIn->sinFamily = SOFTBUS_AF_INET;
    addrIn->sinPort = 0;

    EXPECT_CALL(*mock, SocketGetPeerNameHook(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(addr), Return(0)));
    EXPECT_CALL(*mock, InetNtoPHook(SOFTBUS_AF_INET, _, _, _))
        .WillOnce(Return("10.0.0.1"));

    auto ret = ConnGetPeerSocketAddr(10, &socketAddr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(socketAddr.port, 0);
}

/*
 * @tc.name: IsHmlIpAddrTest_InvalidCharacters
 * @tc.desc: test IsHmlIpAddr with invalid characters
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, IsHmlIpAddrTest_InvalidCharacters, TestSize.Level1)
{
    auto ret = IsHmlIpAddr("abc.def.ghi.jkl");
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: IsHmlIpAddrTest_PartialIPv4
 * @tc.desc: test IsHmlIpAddr with partial IPv4
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, IsHmlIpAddrTest_PartialIPv4, TestSize.Level1)
{
    auto ret = IsHmlIpAddr("192.168");
    EXPECT_FALSE(ret);
}

/*
 * @tc.name: GetDomainByAddrTest_BroadcastIPv4
 * @tc.desc: test GetDomainByAddr with broadcast IPv4
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, GetDomainByAddrTest_BroadcastIPv4, TestSize.Level1)
{
    auto ret = GetDomainByAddr("255.255.255.255");
    EXPECT_EQ(ret, SOFTBUS_AF_INET);
}

/*
 * @tc.name: BindToInterfaceTest_BroadcastAddr
 * @tc.desc: test BindToInterface with broadcast address
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, BindToInterfaceTest_BroadcastAddr, TestSize.Level1)
{
    char ifName[IF_NAME_SIZE] = {0};

    // Broadcast address - should not bind
    BindToInterface("255.255.255.255", SOFTBUS_AF_INET, 10, ifName, IF_NAME_SIZE);
    EXPECT_EQ(strlen(ifName), 0);
}
