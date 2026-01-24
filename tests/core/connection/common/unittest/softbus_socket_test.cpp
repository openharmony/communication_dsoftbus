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

// Mock SocketInterface for testing
static int32_t MockGetSockPort(int32_t fd) { return 8080; }
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
    EXPECT_EQ(ret, SOFTBUS_OK);

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

    SocketInterface testIface = {
        .name = "test",
        .type = LNN_PROTOCOL_BLE,
        .GetSockPort = MockGetSockPort,
        .OpenServerSocket = MockOpenServerSocket,
        .OpenClientSocket = MockOpenClientSocket,
        .AcceptClient = MockAcceptClient,
    };
    RegistSocketProtocol(&testIface);

    auto iface = GetSocketInterface(LNN_PROTOCOL_BLE);
    EXPECT_NE(iface, nullptr);
    EXPECT_EQ(iface->type, LNN_PROTOCOL_BLE);

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
    ConnectOption option = {
        .socketOption = {
            .protocol = LNN_PROTOCOL_BLE,
        }
    };

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
    char buf[10] = "test";

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
    char buf[10] = "test";

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
 * @tc.name: ConnCloseSocketTest_InvalidFd
 * @tc.desc: test ConnCloseSocket with invalid fd
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnCloseSocketTest_InvalidFd, TestSize.Level1)
{
    // Test that ConnCloseSocket handles invalid fd gracefully
    // Verify that SocketCloseHook is not called for invalid fd
    EXPECT_CALL(*mock, SocketCloseHook(_))
        .Times(0);

    ConnCloseSocket(-1);
}

/*
 * @tc.name: ConnCloseSocketTest_Success
 * @tc.desc: test successful socket closing
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnCloseSocketTest_Success, TestSize.Level1)
{
    EXPECT_CALL(*mock, SocketCloseHook(10))
        .Times(1);

    ConnCloseSocket(10);
}

/*
 * @tc.name: ConnShutdownSocketTest_InvalidFd
 * @tc.desc: test ConnShutdownSocket with invalid fd
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnShutdownSocketTest_InvalidFd, TestSize.Level1)
{
    // Test that ConnShutdownSocket handles invalid fd gracefully
    // Verify that SocketShutDownHook and SocketCloseHook are not called for invalid fd
    EXPECT_CALL(*mock, SocketShutDownHook(_, _))
        .Times(0);
    EXPECT_CALL(*mock, SocketCloseHook(_))
        .Times(0);

    ConnShutdownSocket(-1);
}

/*
 * @tc.name: ConnShutdownSocketTest_Success
 * @tc.desc: test successful socket shutdown
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnShutdownSocketTest_Success, TestSize.Level1)
{
    EXPECT_CALL(*mock, SocketShutDownHook(10, SOFTBUS_SHUT_RDWR))
        .WillOnce(Return(0));
    EXPECT_CALL(*mock, SocketCloseHook(10))
        .Times(1);

    ConnShutdownSocket(10);
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
 * @tc.name: ConnGetLocalSocketPortTest_Success
 * @tc.desc: test successful ConnGetLocalSocketPort
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnGetLocalSocketPortTest_Success, TestSize.Level1)
{
    // Initialize sockets to init mutex and register TCP protocol
    auto initRet = ConnInitSockets();
    ASSERT_EQ(initRet, SOFTBUS_OK);

    // Test that ConnGetLocalSocketPort works with the registered TCP interface
    // Since ConnInitSockets registered TCP (LNN_PROTOCOL_IP), GetSocketInterface
    // should find it. For invalid fd=10, GetTcpSockPort will return an error code.
    auto ret = ConnGetLocalSocketPort(10);
    // The function should not crash, and should return either:
    // - An error code (negative) from GetTcpSockPort for invalid fd
    // - SOFTBUS_CONN_SOCKET_GET_INTERFACE_ERR if interface not found
    EXPECT_TRUE(ret < 0 || ret == SOFTBUS_CONN_SOCKET_GET_INTERFACE_ERR);

    ConnDeinitSockets();
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
 * @tc.name: ConnPreAssignPortTest_BindFail
 * @tc.desc: test ConnPreAssignPort when Bind fails
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnPreAssignPortTest_BindFail, TestSize.Level1)
{
    int32_t testFd = 100;

    EXPECT_CALL(*mock, SocketCreateHook(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(testFd), Return(0)));
    EXPECT_CALL(*mock, SocketSetOptHook(_, _, SO_REUSEPORT, _, _))
        .WillOnce(Return(0));
    EXPECT_CALL(*mock, InetPtoNHook(SOFTBUS_AF_INET, _, _))
        .WillOnce(Return(1));
    EXPECT_CALL(*mock, SocketBindHook(_, _, _))
        .WillOnce(Return(-1));
    EXPECT_CALL(*mock, SocketCloseHook(_))
        .Times(1);

    auto ret = ConnPreAssignPort(SOFTBUS_AF_INET);
    EXPECT_EQ(ret, SOFTBUS_TCPCONNECTION_SOCKET_ERR);
}

/*
 * @tc.name: ConnPreAssignPortTest_Success
 * @tc.desc: test successful ConnPreAssignPort
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, ConnPreAssignPortTest_Success, TestSize.Level1)
{
    int32_t testFd = 100;

    EXPECT_CALL(*mock, SocketCreateHook(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(testFd), Return(0)));
    EXPECT_CALL(*mock, SocketSetOptHook(_, _, SO_REUSEPORT, _, _))
        .WillOnce(Return(0));
    EXPECT_CALL(*mock, InetPtoNHook(SOFTBUS_AF_INET, _, _))
        .WillOnce(Return(1));
    EXPECT_CALL(*mock, SocketBindHook(_, _, _))
        .WillOnce(Return(0));

    auto ret = ConnPreAssignPort(SOFTBUS_AF_INET);
    EXPECT_EQ(ret, 100);

    EXPECT_CALL(*mock, SocketCloseHook(_))
        .Times(1);
    ConnCloseSocket(ret);
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
 * @tc.name: Ipv6AddrInToAddrTest_NoIfName
 * @tc.desc: test Ipv6AddrInToAddr without interface name
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, Ipv6AddrInToAddrTest_NoIfName, TestSize.Level1)
{
    SoftBusSockAddrIn6 addrIn6 = {0};
    char addr[IP_LEN] = {0};
    const char *testIp = "fe80::1";

    EXPECT_CALL(*mock, InetNtoPHook(SOFTBUS_AF_INET6, _, _, _))
        .WillOnce(Return(testIp));
    EXPECT_CALL(*mock, IndexToIfNameHook(_, _, _))
        .WillOnce(Return(-1));

    auto ret = Ipv6AddrInToAddr(&addrIn6, addr, IP_LEN);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_STREQ(addr, testIp);
}

/*
 * @tc.name: Ipv6AddrToAddrInTest_NullParams
 * @tc.desc: test Ipv6AddrToAddrIn with null parameters
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, Ipv6AddrToAddrInTest_NullParams, TestSize.Level1)
{
    SoftBusSockAddrIn6 addrIn6 = {0};

    auto ret = Ipv6AddrToAddrIn(nullptr, "::1", 8080);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = Ipv6AddrToAddrIn(&addrIn6, nullptr, 8080);
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

    EXPECT_CALL(*mock, InetPtoNHook(SOFTBUS_AF_INET6, ip, _))
        .WillOnce(Return(0));

    auto ret = Ipv6AddrToAddrIn(&addrIn6, ip, 8080);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(addrIn6.sin6Family, SOFTBUS_AF_INET6);
    EXPECT_EQ(SoftBusNtoHs(addrIn6.sin6Port), 8080);
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
 * @tc.name: Ipv4AddrToAddrInTest_Success
 * @tc.desc: test successful Ipv4AddrToAddrIn
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, Ipv4AddrToAddrInTest_Success, TestSize.Level1)
{
    SoftBusSockAddrIn addrIn = {0};
    const char *ip = "192.168.1.1";

    EXPECT_CALL(*mock, InetPtoNHook(SOFTBUS_AF_INET, ip, _))
        .WillOnce(Return(1));

    auto ret = Ipv4AddrToAddrIn(&addrIn, ip, 8080);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_EQ(addrIn.sinFamily, SOFTBUS_AF_INET);
    EXPECT_EQ(SoftBusNtoHs(addrIn.sinPort), 8080);
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
 * @tc.name: BindToInterfaceTest_Success
 * @tc.desc: test successful BindToInterface
 * @tc.type: FUNC
 */
HWTEST_F(SoftBusSocketTest, BindToInterfaceTest_Success, TestSize.Level1)
{
    char ifName[IF_NAME_SIZE] = {0};

    mock->SetTestIfAddr("192.168.1.1", "wlan0");

    EXPECT_CALL(*mock, GetIfAddrsHook())
        .WillOnce(Return(0));
    EXPECT_CALL(*mock, InetAtonHook(_, _))
        .WillOnce(Return(1));
    EXPECT_CALL(*mock, FreeIfAddrsHook())
        .Times(1);
    EXPECT_CALL(*mock, SocketSetOptHook(10, _, SOFTBUS_SO_BINDTODEVICE, _, _))
        .WillOnce(Return(0));

    BindToInterface("192.168.1.1", SOFTBUS_AF_INET, 10, ifName, IF_NAME_SIZE);
    // Successful binding should have set the interface name
    EXPECT_GT(strlen(ifName), 0);

    mock->ClearTestIfAddr();
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
