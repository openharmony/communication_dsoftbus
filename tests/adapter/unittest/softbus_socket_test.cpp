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

#include <fcntl.h>
#include <securec.h>
#include <unistd.h>

#include "softbus_adapter_errcode.h"
#include "softbus_adapter_socket.h"
#include "softbus_error_code.h"
#include "gtest/gtest.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
const int32_t PROTOCOL_MAXLEN = 100;
const int32_t TEST_BUF_SIZE = 10;
const int32_t TEST_PORT = 8888;
const int32_t TEST_IPV6_PORT = 8089;
const int32_t LOCAL_HOST_VALUE = 16777343;
const int32_t CMD_EXIT = 0x11001100;
const int32_t CMD_RECV = 0x22002200;
const int32_t CMD_REPLY = 0x33003300;
const int32_t SET_SIZE = 100;
const int32_t WLAN_INDEX = 4;

SoftBusSockAddrIn g_serAddr = { .sinFamily = SOFTBUS_AF_INET,
    .sinPort = SoftBusHtoNs(TEST_PORT),
    .sinAddr = { .sAddr = SoftBusInetAddr("127.0.0.1") } };

struct SocketProtocol {
    unsigned int cmd;
    char data[PROTOCOL_MAXLEN];
};

class AdapterDsoftbusSocketTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AdapterDsoftbusSocketTest::SetUpTestCase(void) { }

void AdapterDsoftbusSocketTest::TearDownTestCase(void) { }

void AdapterDsoftbusSocketTest::SetUp() { }

void AdapterDsoftbusSocketTest::TearDown() { }

static void SocketServiceStart(int32_t localFlag)
{
    int32_t socketFd = -1;
    int32_t optVal = 1;
    int32_t backLog = 2;
    SoftBusSockAddrIn cliAddr = { 0 };
    int32_t acceptFd = -1;
    struct SocketProtocol buf = { 0 };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketSetOpt(socketFd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEADDR, &optVal, sizeof(optVal));
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketBind(socketFd, (SoftBusSockAddr *)&g_serAddr, sizeof(SoftBusSockAddrIn));
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketListen(socketFd, backLog);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketAccept(socketFd, (SoftBusSockAddr *)&cliAddr, &acceptFd);
    EXPECT_EQ(0, ret);

    if (localFlag) {
        char serviceIP[20];
        SoftBusSockAddrIn serviceAddr;
        SoftBusSocketGetLocalName(acceptFd, (SoftBusSockAddr *)&serviceAddr);
        SoftBusInetNtoP(SOFTBUS_AF_INET, &serviceAddr.sinAddr, serviceIP, sizeof(serviceIP));
        uint16_t port = SoftBusNtoHs(serviceAddr.sinPort);
        EXPECT_EQ(port, TEST_PORT);
    }

    while (1) {
        (void)memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
        ret = SoftBusSocketRecv(acceptFd, (void *)&buf, sizeof(struct SocketProtocol), 0);
        EXPECT_TRUE(ret != -1);
        if (buf.cmd == CMD_EXIT) {
            break;
        } else if (buf.cmd == CMD_RECV) {
            (void)memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
            buf.cmd = CMD_REPLY;
            (void)strcpy_s(buf.data, sizeof(buf.data), "Beautiful World!");
            ret = SoftBusSocketSend(acceptFd, (void *)&buf, sizeof(struct SocketProtocol), 0);
            EXPECT_TRUE(ret != -1);
        } else {
            printf("unknown cmd\n");
        }
    }

    ret = SoftBusSocketClose(acceptFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
    printf("socket service will exit\n");
    _exit(0);
}

static void SocketIpv6ServiceStart(int localFlag)
{
    int32_t socketFd = -1;
    int32_t optVal = 1;
    int32_t backLog = 2;
    SoftBusSockAddrIn cliAddr = { 0 };
    int32_t acceptFd = -1;
    struct SocketProtocol buf = { 0 };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET6, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketSetOpt(socketFd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEADDR, &optVal, sizeof(optVal));
    EXPECT_EQ(0, ret);
    SoftBusSockAddrIn6 addrIn6 = { 0 };
    addrIn6.sin6Family = SOFTBUS_AF_INET6;
    addrIn6.sin6Port = SoftBusHtoNs(TEST_IPV6_PORT);
    const char *srcAddr = "::1";
    SoftBusInetPtoN(SOFTBUS_AF_INET6, srcAddr, &addrIn6.sin6Addr);
    addrIn6.sin6ScopeId = SoftBusIfNameToIndex("lo");
    ret = SoftBusSocketBind(socketFd, (SoftBusSockAddr *)&addrIn6, sizeof(SoftBusSockAddrIn6));
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketListen(socketFd, backLog);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketAccept(socketFd, (SoftBusSockAddr *)&cliAddr, &acceptFd);
    EXPECT_EQ(0, ret);

    if (localFlag) {
        char serviceIP[46];
        SoftBusSockAddrIn6 serviceAddr6 = { 0 };
        SoftBusSocketGetLocalName(acceptFd, (SoftBusSockAddr *)&serviceAddr6);
        SoftBusInetNtoP(SOFTBUS_AF_INET6, &serviceAddr6.sin6Addr, serviceIP, sizeof(serviceIP));
        uint16_t port = SoftBusNtoHs(serviceAddr6.sin6Port);
        EXPECT_EQ(port, TEST_IPV6_PORT);
    }

    while (1) {
        (void)memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
        ret = SoftBusSocketRecv(acceptFd, (void *)&buf, sizeof(struct SocketProtocol), 0);
        EXPECT_TRUE(ret != -1);
        if (buf.cmd == CMD_EXIT) {
            break;
        } else if (buf.cmd == CMD_RECV) {
            (void)memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
            buf.cmd = CMD_REPLY;
            (void)strcpy_s(buf.data, sizeof(buf.data), "Beautiful World!");
            ret = SoftBusSocketSend(acceptFd, (void *)&buf, sizeof(struct SocketProtocol), 0);
            EXPECT_TRUE(ret != -1);
        } else {
            printf("unknown cmd\n");
        }
    }

    ret = SoftBusSocketClose(acceptFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
    printf("socket ipv6 service will exit\n");
    _exit(0);
}

static void ClientConnect(int32_t *socketFd)
{
    EXPECT_TRUE(socketFd != nullptr);
    SoftBusSockAddrIn serAddr = { .sinFamily = SOFTBUS_AF_INET,
        .sinPort = SoftBusHtoNs(8888),
        .sinAddr = { .sAddr = SoftBusInetAddr("127.0.0.1") } };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketConnect(*socketFd, (SoftBusSockAddr *)&serAddr, sizeof(SoftBusSockAddrIn));
    EXPECT_EQ(0, ret);
}

static void ClientIpv6Connect(int32_t *socketFd)
{
    EXPECT_TRUE(socketFd != nullptr);
    SoftBusSockAddrIn6 addrIn6 = { 0 };
    addrIn6.sin6Family = SOFTBUS_AF_INET6;
    addrIn6.sin6Port = SoftBusHtoNs(TEST_IPV6_PORT);
    const char *srcAddr = "::1";
    SoftBusInetPtoN(SOFTBUS_AF_INET6, srcAddr, &addrIn6.sin6Addr);
    addrIn6.sin6ScopeId = SoftBusIfNameToIndex("lo");
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET6, SOFTBUS_SOCK_STREAM, 0, socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketConnect(*socketFd, (SoftBusSockAddr *)&addrIn6, sizeof(SoftBusSockAddrIn6));
    EXPECT_EQ(0, ret);
}

static void ClientExit(int32_t socketFd)
{
    struct SocketProtocol buf = {
        .cmd = CMD_EXIT,
    };
    int32_t ret = SoftBusSocketSend(socketFd, (void *)&buf, sizeof(struct SocketProtocol), 0);
    EXPECT_TRUE(ret != -1);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
    sleep(1);
}

/*
 * @tc.name: SoftBusSocketCreate001
 * @tc.desc: Create Socket Success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketCreate001, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketCreate(
        SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM | SOFTBUS_SOCK_NONBLOCK | SOFTBUS_SOCK_CLOEXEC, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketCreate002
 * @tc.desc: Error Domain
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketCreate002, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t ret = SoftBusSocketCreate(-1, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);
}

/*
 * @tc.name: SoftBusSocketCreate003
 * @tc.desc: Error type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketCreate003, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, 0, 0, &socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);
    ret = SoftBusSocketCreate(SOFTBUS_AF_INET, 0xFFFFFFFF, 0, &socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);
}

/*
 * @tc.name: SoftBusSocketCreate004
 * @tc.desc: Error protocol
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketCreate004, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, 0, -1, &socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);
}

/*
 * @tc.name: SoftBusSocketCreate005
 * @tc.desc: Error socketFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketCreate005, TestSize.Level0)
{
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, NULL);
    EXPECT_EQ(SOFTBUS_ADAPTER_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusSocketSetOptTest001
 * @tc.desc: opt set success
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSetOptTest001, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t optVal = 1;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);

    SoftBusSocketSetOpt(socketFd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEADDR, &optVal, sizeof(optVal));
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
}

/*
 * @tc.name: SoftBusSocketSetOptTest002
 * @tc.desc: select SOFTBUS_IPPROTO_IP Protocol
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSetOptTest002, TestSize.Level0)
{
    int32_t socketFd;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
    int32_t optVal = 1;
    int32_t optValLen = sizeof(int);
    ret = SoftBusSocketSetOpt(socketFd, SOFTBUS_IPPROTO_IP, SOFTBUS_IP_TOS, &optVal, optValLen);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
}

/*
 * @tc.name: SoftBusSocketSetOptTest003
 * @tc.desc: select SOFTBUS_SO_KEEPALIVE Protocol
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSetOptTest003, TestSize.Level0)
{
    int32_t socketFd;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);

    int32_t optVal = 1;
    int32_t optValLen = sizeof(int);
    ret = SoftBusSocketSetOpt(socketFd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_KEEPALIVE, &optVal, optValLen);
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
}

/*
 * @tc.name: SoftBusSocketSetOptTest004
 * @tc.desc: socketFd illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSetOptTest004, TestSize.Level0)
{
    int32_t optVal = 1;
    int32_t optValLen = sizeof(int);
    int32_t ret = SoftBusSocketSetOpt(-1, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEADDR, &optVal, optValLen);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);
}

/*
 * @tc.name: SoftBusSocketSetOptTest005
 * @tc.desc: Protocol is illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSetOptTest005, TestSize.Level0)
{
    int32_t socketFd;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
    int32_t optVal = 10;
    int32_t optValLen = sizeof(int);
    ret = SoftBusSocketSetOpt(socketFd, SOFTBUS_IPPROTO_IP, -1, &optVal, optValLen);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
}

/*
 * @tc.name: SoftBusSocketSetOptTest006
 * @tc.desc: optVal is illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSetOptTest006, TestSize.Level0)
{
    int32_t socketFd;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
    int32_t optValLen = sizeof(int);
    ret = SoftBusSocketSetOpt(socketFd, SOFTBUS_IPPROTO_IP, SOFTBUS_IP_TOS, NULL, optValLen);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
}

#if HAVE_PRO
/*
 * @tc.name: SoftBusSocketSetOptTest007
 * @tc.desc: optValLen is illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSetOptTest007, TestSize.Level0)
{
    int32_t socketFd;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
    int32_t optVal = 1;
    ret = SoftBusSocketSetOpt(socketFd, SOFTBUS_IPPROTO_IP, SOFTBUS_IP_TOS, &optVal, -1);
    EXPECT_EQ(-1, ret);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
}
#endif

/*
 * @tc.name: SoftBusSocketGetOptTest001
 * @tc.desc: positive
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketGetOptTest001, TestSize.Level0)
{
    int32_t socketFd;
    int32_t on = 1;
    int32_t onLen = sizeof(on);
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
    ret = SoftBusSocketGetOpt(socketFd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEADDR, &on, &onLen);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
}

/*
 * @tc.name: SoftBusSocketGetOptTest002
 * @tc.desc: socketFd illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketGetOptTest002, TestSize.Level0)
{
    int32_t on = 1;
    int32_t onLen = sizeof(on);
    int32_t rc = SoftBusSocketGetOpt(-1, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEADDR, &on, &onLen);
    EXPECT_TRUE(rc == -1);
}

/*
 * @tc.name: SoftBusSocketGetLocalNameTest001
 * @tc.desc: test in service get port
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketGetLocalNameTest001, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(1);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;

    ClientConnect(&socketFd);

    ClientExit(socketFd);
    return;
}

/*
 * @tc.name: SoftBusSocketGetLocalNameTest002
 * @tc.desc: socketFd illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketGetLocalNameTest002, TestSize.Level0)
{
    int32_t socketFd = -1;
    SoftBusSockAddrIn clientAddr;
    int32_t ret = SoftBusSocketGetLocalName(socketFd, (SoftBusSockAddr *)&clientAddr);
    EXPECT_EQ(-1, ret);
}

/*
 * @tc.name: SoftBusSocketGetLocalNameTest003
 * @tc.desc: addr is null
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketGetLocalNameTest003, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t ret;
    int32_t socketFd = -1;

    ClientConnect(&socketFd);

    ret = SoftBusSocketGetLocalName(socketFd, NULL);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);

    ClientExit(socketFd);
}

/*
 * @tc.name: SoftBusSocketGetLocalNameTest004
 * @tc.desc: addrLen is null
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketGetLocalNameTest004, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t ret;
    int32_t socketFd = -1;

    ClientConnect(&socketFd);

    SoftBusSockAddrIn clientAddr;
    ret = SoftBusSocketGetLocalName(socketFd, (SoftBusSockAddr *)&clientAddr);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);

    ClientExit(socketFd);
}

/*
 * @tc.name: SoftBusSocketGetLocalNameTest005
 * @tc.desc: socketFd is service fd
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketGetLocalNameTest005, TestSize.Level0)
{
    int32_t socketFd;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
    SoftBusSockAddrIn clientAddr;
    ret = SoftBusSocketGetLocalName(socketFd, (SoftBusSockAddr *)&clientAddr);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
}

/*
 * @tc.name: SoftBusSocketGetLocalNameTest006
 * @tc.desc: socketFd illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketGetLocalNameTest006, TestSize.Level0)
{
    int32_t socketFd = -1;
    SoftBusSockAddrIn6 clientAddr6 = { 0 };
    int32_t ret = SoftBusSocketGetLocalName(socketFd, (SoftBusSockAddr *)&clientAddr6);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);
}

/*
 * @tc.name: SoftBusSocketGetLocalNameTest007
 * @tc.desc: addrLen is null
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketGetLocalNameTest007, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketIpv6ServiceStart(0);
        return;
    }
    sleep(1);
    int32_t ret;
    int32_t socketFd = -1;

    ClientIpv6Connect(&socketFd);

    SoftBusSockAddrIn6 clientAddr6 = { 0 };
    ret = SoftBusSocketGetLocalName(socketFd, (SoftBusSockAddr *)&clientAddr6);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);

    ClientExit(socketFd);
}

/*
 * @tc.name: SoftBusSocketGetPeerNameTest001
 * @tc.desc: get service port success
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketGetPeerNameTest001, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t ret;
    int32_t socketFd = -1;

    ClientConnect(&socketFd);

    char serviceIP[20];
    SoftBusSockAddrIn serviceAddr;

    ret = SoftBusSocketGetPeerName(socketFd, (SoftBusSockAddr *)&serviceAddr);
    EXPECT_EQ(0, ret);
    SoftBusInetNtoP(SOFTBUS_AF_INET, &serviceAddr.sinAddr, serviceIP, sizeof(serviceIP));
    uint16_t port = SoftBusNtoHs(serviceAddr.sinPort);
    EXPECT_EQ(TEST_PORT, port);

    ClientExit(socketFd);
}

/*
 * @tc.name: SoftBusSocketGetPeerNameTest002
 * @tc.desc: socketFd illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketGetPeerNameTest002, TestSize.Level0)
{
    SoftBusSockAddr addr;
    int32_t rc = SoftBusSocketGetPeerName(-1, &addr);
    EXPECT_TRUE(rc == -1);
}

/*
 * @tc.name: SoftBusSocketGetPeerNameTest003
 * @tc.desc: get service port success
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketGetPeerNameTest003, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t ret;
    int32_t socketFd = -1;

    ClientConnect(&socketFd);

    ret = SoftBusSocketGetPeerName(socketFd, NULL);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);

    ClientExit(socketFd);
}

/*
 * @tc.name: SoftBusSocketGetPeerNameTest004
 * @tc.desc: get service port success
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketGetPeerNameTest004, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t ret;
    int32_t socketFd = -1;

    ClientConnect(&socketFd);

    SoftBusSockAddrIn serviceAddr;

    ret = SoftBusSocketGetPeerName(socketFd, (SoftBusSockAddr *)&serviceAddr);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);

    ClientExit(socketFd);
}

/*
 * @tc.name: SoftBusSocketGetPeerNameTest005
 * @tc.desc: socketFd is illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketGetPeerNameTest005, TestSize.Level0)
{
    int32_t socketFd;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
    SoftBusSockAddrIn serviceAddr;
    ret = SoftBusSocketGetPeerName(socketFd, (SoftBusSockAddr *)&serviceAddr);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
}

/*
 * @tc.name: SoftBusSocketGetPeerNameTest006
 * @tc.desc: get service port success
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketGetPeerNameTest006, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketIpv6ServiceStart(0);
        return;
    }
    sleep(1);
    int32_t ret;
    int32_t socketFd = -1;

    ClientIpv6Connect(&socketFd);

    char serviceIP[46];
    SoftBusSockAddrIn6 serviceAddr6 { 0 };

    ret = SoftBusSocketGetPeerName(socketFd, (SoftBusSockAddr *)&serviceAddr6);
    EXPECT_EQ(0, ret);
    SoftBusInetNtoP(SOFTBUS_AF_INET6, &serviceAddr6.sin6Addr, serviceIP, sizeof(serviceIP));
    uint16_t port = SoftBusNtoHs(serviceAddr6.sin6Port);
    EXPECT_EQ(TEST_IPV6_PORT, port);

    ClientExit(socketFd);
}

/*
 * @tc.name: SoftBusSocketBind001
 * @tc.desc: Bind Socket Success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketBind001, TestSize.Level0)
{
    int32_t socketFd = -1;
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketBind(socketFd, &addr, sizeof(SoftBusSockAddrIn));
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketBind002
 * @tc.desc: addrLen is illegal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketBind002, TestSize.Level0)
{
    int32_t socketFd = -1;
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketBind(socketFd, &addr, sizeof(SoftBusSockAddrIn) - 1);
    EXPECT_NE(0, ret);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketBind003
 * @tc.desc: socketFd is illegal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketBind003, TestSize.Level0)
{
    int32_t socketFd = -1;
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    int32_t ret = SoftBusSocketBind(socketFd, &addr, sizeof(SoftBusSockAddrIn));
    EXPECT_NE(0, ret);
}

/*
 * @tc.name: SoftBusSocketBind004
 * @tc.desc: addr is illegal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketBind004, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketBind(socketFd, NULL, sizeof(SoftBusSockAddrIn));
    EXPECT_EQ(-1, ret);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketBind005
 * @tc.desc: Bind Socket Success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketBind005, TestSize.Level0)
{
    int32_t socketFd = -1;
    SoftBusSockAddrIn6 addrIn6 = { 0 };
    addrIn6.sin6Family = SOFTBUS_AF_INET6;
    addrIn6.sin6Port = SoftBusHtoNs(TEST_IPV6_PORT);
    const char *srcAddr = "::1";
    SoftBusInetPtoN(SOFTBUS_AF_INET6, srcAddr, &addrIn6.sin6Addr);
    addrIn6.sin6ScopeId = SoftBusIfNameToIndex("lo");
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET6, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketBind(socketFd, (SoftBusSockAddr *)&addrIn6, sizeof(SoftBusSockAddrIn6));
    EXPECT_NE(SOFTBUS_ADAPTER_OK, ret);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketListen001
 * @tc.desc: Listen Socket Success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketListen001, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t backLog = 2;
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketBind(socketFd, &addr, sizeof(SoftBusSockAddrIn));
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketListen(socketFd, backLog);
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketListen002
 * @tc.desc: backlog is illegal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketListen002, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t backLog = -1;
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketBind(socketFd, &addr, sizeof(SoftBusSockAddrIn));
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketListen(socketFd, backLog);
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketListen003
 * @tc.desc: socketFd is illegal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketListen003, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t backLog = 2;

    int32_t ret = SoftBusSocketListen(socketFd, backLog);
    EXPECT_EQ(-1, ret);
}

/*
 * @tc.name: SoftBusSocketListen004
 * @tc.desc: Listen Socket Success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketListen004, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t backLog = 2;
    SoftBusSockAddrIn6 addrIn6 = { 0 };
    addrIn6.sin6Family = SOFTBUS_AF_INET6;
    addrIn6.sin6Port = SoftBusHtoNs(TEST_IPV6_PORT);
    const char *srcAddr = "::1";
    SoftBusInetPtoN(SOFTBUS_AF_INET6, srcAddr, &addrIn6.sin6Addr);
    addrIn6.sin6ScopeId = SoftBusIfNameToIndex("lo");
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET6, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketBind(socketFd, (SoftBusSockAddr *)&addrIn6, sizeof(SoftBusSockAddrIn6));
    EXPECT_NE(SOFTBUS_ADAPTER_OK, ret);

    ret = SoftBusSocketListen(socketFd, backLog);
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketAccept001
 * @tc.desc: Accept Socket Success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketAccept001, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;

    ClientConnect(&socketFd);
    EXPECT_TRUE(socketFd != -1);

    ClientExit(socketFd);
}

/*
 * @tc.name: SoftBusSocketAccept002
 * @tc.desc: socketFd is illegal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketAccept002, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t acceptFd = -1;
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    int32_t ret = SoftBusSocketAccept(socketFd, &addr, &acceptFd);
    EXPECT_NE(0, ret);
}

/*
 * @tc.name: SoftBusSocketAccept003
 * @tc.desc: acceptFd is illegal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketAccept003, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t optVal = 1;
    int32_t backLog = 2;
    SoftBusSockAddrIn serAddr = { .sinFamily = SOFTBUS_AF_INET,
        .sinPort = SoftBusHtoNs(TEST_PORT),
        .sinAddr = { .sAddr = SoftBusInetAddr("127.0.0.1") } };
    SoftBusSockAddrIn cliAddr = { 0 };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);

    SoftBusSocketSetOpt(socketFd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEADDR, &optVal, sizeof(optVal));
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketBind(socketFd, (SoftBusSockAddr *)&serAddr, sizeof(SoftBusSockAddrIn));
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketListen(socketFd, backLog);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketAccept(socketFd, (SoftBusSockAddr *)&cliAddr, NULL);
    EXPECT_EQ(SOFTBUS_ADAPTER_INVALID_PARAM, ret);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketConnect001
 * @tc.desc: connect success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketConnect001, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(1);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;

    ClientConnect(&socketFd);
    EXPECT_TRUE(socketFd != -1);

    ClientExit(socketFd);
}

/*
 * @tc.name: SoftBusSocketConnect002
 * @tc.desc: socketFd is illegal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketConnect002, TestSize.Level0)
{
    int32_t socketFd = -1;
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    int32_t ret = SoftBusSocketConnect(socketFd, &addr, sizeof(SoftBusSockAddrIn));
    EXPECT_NE(0, ret);
}

/*
 * @tc.name: SoftBusSocketConnect003
 * @tc.desc: addr is illegal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketConnect003, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketConnect(socketFd, NULL, -1);
    EXPECT_TRUE(ret < 0);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketConnect004
 * @tc.desc: addrLen is illegal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketConnect004, TestSize.Level0)
{
    int32_t socketFd = -1;
    SoftBusSockAddrIn serAddr = { .sinFamily = SOFTBUS_AF_INET,
        .sinPort = SoftBusHtoNs(8888),
        .sinAddr = { .sAddr = SoftBusInetAddr("127.0.0.1") } };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketConnect(socketFd, (SoftBusSockAddr *)&serAddr, sizeof(SoftBusSockAddrIn));
    EXPECT_NE(0, ret);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketConnect005
 * @tc.desc: addrLen is illegal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketConnect005, TestSize.Level0)
{
    int32_t socketFd = -1;
    SoftBusSockAddrIn6 addrIn6 = { 0 };
    addrIn6.sin6Family = SOFTBUS_AF_INET6;
    addrIn6.sin6Port = SoftBusHtoNs(TEST_PORT);
    const char *srcAddr = "::1";
    SoftBusInetPtoN(SOFTBUS_AF_INET6, srcAddr, &addrIn6.sin6Addr);
    addrIn6.sin6ScopeId = SoftBusIfNameToIndex("lo");
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET6, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketConnect(socketFd, (SoftBusSockAddr *)&addrIn6, sizeof(SoftBusSockAddrIn6));
    EXPECT_NE(0, ret);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketFdZeroTest001
 * @tc.desc: set fdsBits zero success
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketFdZeroTest001, TestSize.Level0)
{
    SoftBusFdSet set = { 0 };
    set.fdsBits[0] = 1;
    SoftBusSocketFdZero(&set);
    EXPECT_TRUE(set.fdsBits[0] == 0);
}

/*
 * @tc.name: SoftBusSocketFdSetTest001
 * @tc.desc: socketFd set success
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketFdSetTest001, TestSize.Level0)
{
    int32_t socketFd;
    SoftBusFdSet set = { 0 };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    SoftBusSocketFdSet(socketFd, &set);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketFdSetTest003
 * @tc.desc: set is NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketFdSetTest003, TestSize.Level0)
{
    int32_t socketFd;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    SoftBusSocketFdSet(socketFd, NULL);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketFdClrTest001
 * @tc.desc: fd clr success
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketFdClrTest001, TestSize.Level0)
{
    SoftBusFdSet set;
    SoftBusSocketFdZero(&set);
    SoftBusSocketFdSet(1, &set);
    SoftBusSocketFdClr(1, &set);
    EXPECT_TRUE(set.fdsBits[0] == 0);
}

/*
 * @tc.name: SoftBusSocketFdIssetTest001
 * @tc.desc: FdIsset success
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketFdIssetTest001, TestSize.Level0)
{
    SoftBusFdSet set;
    SoftBusSocketFdSet(1, &set);
    int32_t ret = SoftBusSocketFdIsset(1, &set);
    EXPECT_TRUE(ret == 1);
}

/*
 * @tc.name: SoftBusSocketFdIssetTest002
 * @tc.desc: fd not in set
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketFdIssetTest002, TestSize.Level0)
{
    SoftBusFdSet set = { 0 };
    SoftBusSocketFdClr(1, &set);
    int32_t ret = SoftBusSocketFdIsset(1, &set);
    EXPECT_TRUE(ret == 0);
}

/*
 * @tc.name: SoftBusSocketFdIssetTest003
 * @tc.desc: set is null
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketFdIssetTest003, TestSize.Level0)
{
    int32_t ret = SoftBusSocketFdIsset(1, NULL);
    EXPECT_TRUE(ret == 0);
}

/*
 * @tc.name: SoftBusSocketSelectTest001
 * @tc.desc: select read fds
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSelectTest001, TestSize.Level0)
{
    int32_t socketFd;
    SoftBusFdSet readFds;
    SoftBusSockTimeOut tv = { .sec = 5, .usec = 1 };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);

    SoftBusSocketFdZero(&readFds);
    SoftBusSocketFdSet(socketFd, &readFds);
    ret = SoftBusSocketSelect(SET_SIZE, &readFds, NULL, NULL, &tv);
    EXPECT_TRUE(ret >= 0);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketSelectTest002
 * @tc.desc: select write fds
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSelectTest002, TestSize.Level0)
{
    int32_t socketFd;
    SoftBusFdSet writeFds;
    SoftBusFdSet fdSelect;
    SoftBusSockTimeOut tv = { .sec = 5, .usec = 1 };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);

    SoftBusSocketFdZero(&writeFds);
    SoftBusSocketFdSet(socketFd, &writeFds);
    fdSelect = writeFds;
    ret = SoftBusSocketSelect(SET_SIZE, NULL, &fdSelect, NULL, &tv);
    EXPECT_TRUE(ret >= 0);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketSelectTest003
 * @tc.desc: select expcept fds
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSelectTest003, TestSize.Level0)
{
    int32_t socketFd;
    SoftBusFdSet exceptFds;
    SoftBusFdSet fdSelect;
    SoftBusSockTimeOut tv = { .sec = 5, .usec = 1 };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);

    SoftBusSocketFdZero(&exceptFds);
    SoftBusSocketFdSet(socketFd, &exceptFds);
    fdSelect = exceptFds;
    ret = SoftBusSocketSelect(SET_SIZE, NULL, NULL, &fdSelect, &tv);
    EXPECT_TRUE(ret >= 0);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketSelectTest004
 * @tc.desc: select all fds
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSelectTest004, TestSize.Level0)
{
    SoftBusFdSet readFds, writeFds, exceptFds;
    SoftBusSockTimeOut tv = { .sec = 5, .usec = 1 };
    SoftBusSocketFdZero(&readFds);
    SoftBusSocketFdZero(&writeFds);
    SoftBusSocketFdZero(&exceptFds);
    int32_t ret = SoftBusSocketSelect(SET_SIZE, &readFds, &writeFds, &exceptFds, &tv);
    EXPECT_TRUE(ret >= 0);
}

/*
 * @tc.name: SoftBusSocketSelectTest005
 * @tc.desc: nfds is illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSelectTest005, TestSize.Level0)
{
    SoftBusSockTimeOut tv = { .sec = 5, .usec = 1 };
    int32_t ret = SoftBusSocketSelect(SET_SIZE, NULL, NULL, NULL, &tv);
    EXPECT_TRUE(ret >= 0);
}

/*
 * @tc.name: SoftBusSocketSelectTest006
 * @tc.desc: The value of timeOut is 0
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSelectTest006, TestSize.Level0)
{
    SoftBusSockTimeOut tv = { .sec = 0, .usec = 0 };
    SoftBusFdSet readFds, writeFds, exceptFds;
    int32_t ret = SoftBusSocketSelect(SET_SIZE, &readFds, &writeFds, &exceptFds, &tv);
    EXPECT_TRUE(ret >= 0);
}

/*
 * @tc.name: SoftBusSocketIoctlTest001
 * @tc.desc:fd is illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketIoctlTest001, TestSize.Level0)
{
    int32_t nread = 0;
    long cmd = 1;
    int32_t socketFd = -1;
    int32_t ret = SoftBusSocketIoctl(socketFd, cmd, &nread);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);
}

/*
 * @tc.name: SoftBusSocketIoctlTest002
 * @tc.desc: cmd is illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketIoctlTest002, TestSize.Level0)
{
    int32_t nread;
    long cmd = -1;
    int32_t socketFd;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketIoctl(socketFd, cmd, &nread);
    EXPECT_EQ(-1, ret);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketFcntlTest001
 * @tc.desc: Fcntl is success
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketFcntlTest001, TestSize.Level0)
{
    int32_t socketFd;
    long cmd = 1;
    long flag = 0;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketFcntl(socketFd, cmd, flag);
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketFcntlTest002
 * @tc.desc: socketFd is illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketFcntlTest002, TestSize.Level0)
{
    int32_t socketFd = -1;
    long cmd = F_DUPFD;
    long flag = 0;
    int32_t ret = SoftBusSocketFcntl(socketFd, cmd, flag);
    EXPECT_EQ(-1, ret);
}

#if HAVE_PRO
/*
 * @tc.name: SoftBusSocketSendTest001
 * @tc.desc: socketFd is invalid
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSendTest001, TestSize.Level0)
{
    int32_t socketFd = -1;
    char buf[TEST_BUF_SIZE] = { 0 };

    int32_t ret = SoftBusSocketSend(socketFd, buf, TEST_BUF_SIZE, 0);
    EXPECT_EQ(-1, ret);
}
#endif

/*
 * @tc.name: SoftBusSocketSendTest002
 * @tc.desc: buf is invalid
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSendTest002, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;
    SoftBusSockAddrIn serAddr = { .sinFamily = SOFTBUS_AF_INET,
        .sinPort = SoftBusHtoNs(8888),
        .sinAddr = { .sAddr = SoftBusInetAddr("127.0.0.1") } };
    struct SocketProtocol buf = { 0 };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketConnect(socketFd, (SoftBusSockAddr *)&serAddr, sizeof(SoftBusSockAddrIn));
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketSend(socketFd, NULL, 0, 0);
    EXPECT_TRUE(ret <= 0);
    (void)memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
    buf.cmd = CMD_EXIT;
    ret = SoftBusSocketSend(socketFd, (void *)&buf, sizeof(struct SocketProtocol), 0);
    EXPECT_TRUE(ret != -1);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketSendTest003
 * @tc.desc: bufLen is invalid
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSendTest003, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;
    SoftBusSockAddrIn serAddr = { .sinFamily = SOFTBUS_AF_INET,
        .sinPort = SoftBusHtoNs(8888),
        .sinAddr = { .sAddr = SoftBusInetAddr("127.0.0.1") } };
    struct SocketProtocol buf = { 0 };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketConnect(socketFd, (SoftBusSockAddr *)&serAddr, sizeof(SoftBusSockAddrIn));
    EXPECT_EQ(0, ret);
    buf.cmd = CMD_RECV;
    (void)strncpy_s(buf.data, sizeof(buf.data), "Happy New Year!", sizeof(buf.data));
    ret = SoftBusSocketSend(socketFd, (void *)&buf, 0, 0);
    EXPECT_TRUE(ret <= 0);
    (void)memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
    buf.cmd = CMD_EXIT;
    ret = SoftBusSocketSend(socketFd, (void *)&buf, sizeof(struct SocketProtocol), 0);
    EXPECT_TRUE(ret != -1);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketSendTest004
 * @tc.desc: positive
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSendTest004, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;
    struct SocketProtocol buf = { 0 };
    ClientConnect(&socketFd);

    buf.cmd = CMD_RECV;
    (void)strncpy_s(buf.data, sizeof(buf.data), "Happy New Year!", sizeof(buf.data));
    int32_t ret = SoftBusSocketSend(socketFd, (void *)&buf, sizeof(struct SocketProtocol), 1);
    EXPECT_TRUE(ret >= 0);

    ClientExit(socketFd);
}

/*
 * @tc.name: SoftBusSocketSendToTest001
 * @tc.desc: socketFd is illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSendToTest001, TestSize.Level0)
{
    int32_t socketFd = -1;
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    struct SocketProtocol buf = { 0 };
    int32_t ret = SoftBusSocketSendTo(socketFd, (void *)&buf, sizeof(buf), 0, &addr, sizeof(SoftBusSockAddrIn));
    EXPECT_EQ(-1, ret);
}

/*
 * @tc.name: SoftBusSocketSendToTest002
 * @tc.desc: send to success
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSendToTest002, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;
    struct SocketProtocol buf = { 0 };
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    ClientConnect(&socketFd);

    buf.cmd = CMD_RECV;
    (void)strncpy_s(buf.data, sizeof(buf.data), "Happy New Year!", sizeof(buf.data));
    int32_t ret = SoftBusSocketSendTo(socketFd, (void *)&buf, sizeof(buf), 0, &addr, sizeof(SoftBusSockAddrIn));
    EXPECT_TRUE(ret >= 0);

    ClientExit(socketFd);
}

/*
 * @tc.name: SoftBusSocketSendToTest003
 * @tc.desc: buf is null
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSendToTest003, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;
    struct SocketProtocol buf = { 0 };
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    ClientConnect(&socketFd);

    int32_t ret = SoftBusSocketSendTo(socketFd, NULL, sizeof(buf), 0, &addr, sizeof(SoftBusSockAddrIn));
    EXPECT_TRUE(ret == -1);

    ClientExit(socketFd);
}

/*
 * @tc.name: SoftBusSocketSendToTest004
 * @tc.desc: addr is NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSendToTest004, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;
    struct SocketProtocol buf = { 0 };
    ClientConnect(&socketFd);

    int32_t ret = SoftBusSocketSendTo(socketFd, (void *)&buf, sizeof(buf), 0, NULL, sizeof(SoftBusSockAddrIn));
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);

    ClientExit(socketFd);
}

/*
 * @tc.name: SoftBusSocketSendToTest005
 * @tc.desc: addrLen is illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSendToTest005, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;
    struct SocketProtocol buf = { 0 };
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    ClientConnect(&socketFd);

    int32_t ret = SoftBusSocketSendTo(socketFd, (void *)&buf, sizeof(buf), 0, &addr, 0);

    EXPECT_TRUE(ret < 0);

    ClientExit(socketFd);
}

/*
 * @tc.name: SoftBusSocketSendToTest006
 * @tc.desc: bufLen is illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSendToTest006, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;
    struct SocketProtocol buf = { 0 };
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    ClientConnect(&socketFd);

    int32_t ret = SoftBusSocketSendTo(socketFd, (void *)&buf, 0, 0, &addr, sizeof(SoftBusSockAddrIn));
    EXPECT_TRUE(ret == 0);

    ClientExit(socketFd);
}

/*
 * @tc.name: SoftBusSocketSendTest007
 * @tc.desc: buf is invalid
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketSendTest007, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketIpv6ServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;
    SoftBusSockAddrIn6 addrIn6 = { 0 };
    addrIn6.sin6Family = SOFTBUS_AF_INET6;
    addrIn6.sin6Port = SoftBusHtoNs(TEST_IPV6_PORT);
    const char *srcAddr = "::1";
    SoftBusInetPtoN(SOFTBUS_AF_INET6, srcAddr, &addrIn6.sin6Addr);
    addrIn6.sin6ScopeId = SoftBusIfNameToIndex("lo");
    struct SocketProtocol buf = { 0 };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET6, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketConnect(socketFd, (SoftBusSockAddr *)&addrIn6, sizeof(SoftBusSockAddrIn6));
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketSend(socketFd, NULL, 0, 0);
    EXPECT_TRUE(ret <= 0);
    (void)memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
    buf.cmd = CMD_EXIT;
    ret = SoftBusSocketSend(socketFd, (void *)&buf, sizeof(struct SocketProtocol), 0);
    EXPECT_TRUE(ret != -1);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketRecvTest001
 * @tc.desc: socketFd is NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketRecvTest001, TestSize.Level0)
{
    int32_t socketFd = -1;
    struct SocketProtocol buf = { 0 };
    int32_t ret = SoftBusSocketRecv(socketFd, (void *)&buf, sizeof(struct SocketProtocol), 0);
    EXPECT_NE(0, ret);
}

/*
 * @tc.name: SoftBusSocketRecvTest002
 * @tc.desc: recv success
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketRecvTest002, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;
    struct SocketProtocol buf = { 0 };
    ClientConnect(&socketFd);

    buf.cmd = CMD_RECV;
    (void)strncpy_s(buf.data, sizeof(buf.data), "Hello World!", sizeof(buf.data));
    int32_t ret = SoftBusSocketSend(socketFd, (void *)&buf, sizeof(struct SocketProtocol), 0);
    EXPECT_TRUE(ret != -1);

    (void)memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
    ret = SoftBusSocketRecv(socketFd, (void *)&buf, sizeof(struct SocketProtocol), 0);
    EXPECT_TRUE(ret != -1);

    ClientExit(socketFd);
}

/*
 * @tc.name:  SoftBusSocketRecvFromTest001
 * @tc.desc: positive
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketRecvFromTest001, TestSize.Level0)
{
    int32_t socketFd = -1;
    SoftBusSockAddr fromAddr = { 0 };
    int32_t fromAddrLen;
    int32_t ret = SoftBusSocketRecvFrom(socketFd, NULL, 0, 0, &fromAddr, &fromAddrLen);
    EXPECT_EQ(-1, ret);
}

/*
 * @tc.name: SoftBusSocketShutDownTest001
 * @tc.desc: socketFd is service fd
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketShutDownTest001, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t optVal = 1;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);

    SoftBusSocketSetOpt(socketFd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEADDR, &optVal, sizeof(optVal));
    EXPECT_EQ(0, ret);

    SoftBusSocketShutDown(socketFd, SOFTBUS_SHUT_RDWR);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusSocketShutDownTest002
 * @tc.desc: socketFd is illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketShutDownTest002, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t ret = SoftBusSocketShutDown(socketFd, SOFTBUS_SHUT_RDWR);
    EXPECT_TRUE(ret != 0);
}

/*
 * @tc.name: SoftBusSocketShutDownTest003
 * @tc.desc: how is illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketShutDownTest003, TestSize.Level0)
{
    int32_t socketFd;

    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_TRUE(ret == 0);
    ret = SoftBusSocketShutDown(socketFd, -1);
    EXPECT_TRUE(ret != 0);
    SoftBusSocketClose(socketFd);
}

/*
 * @tc.name: SoftBusSocketCloseTest001
 * @tc.desc: normal close
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketCloseTest001, TestSize.Level0)
{
    int32_t socketFd;

    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_TRUE(ret == 0);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_TRUE(ret == 0);
}

/*
 * @tc.name: SoftBusSocketCloseTest002
 * @tc.desc: fd is illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketCloseTest002, TestSize.Level0)
{
    int32_t socketFd = -1;

    int32_t ret = SoftBusSocketClose(socketFd);
    EXPECT_TRUE(ret == -1);
}

/*
 * @tc.name: SoftBusInetPtoNTest001
 * @tc.desc: string is valid format
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusInetPtoNTest001, TestSize.Level0)
{
    const char *src = "192.168.0.1";
    char dst[TEST_BUF_SIZE] = { 0 };
    int32_t ret = SoftBusInetPtoN(SOFTBUS_AF_INET, src, dst);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(0x100A8C0, *(unsigned int *)dst);
}

/*
 * @tc.name: SoftBusInetPtoNTest002
 * @tc.desc: string is invalid format
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusInetPtoNTest002, TestSize.Level0)
{
    const char *src = "abcde";
    char dst[TEST_BUF_SIZE] = { 0 };
    int32_t ret = SoftBusInetPtoN(SOFTBUS_AF_INET, src, dst);
    EXPECT_EQ(SOFTBUS_ADAPTER_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusInetPtoNTest003
 * @tc.desc: string is invalid format
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusInetPtoNTest003, TestSize.Level0)
{
    const char *src = "1234";
    char dst[TEST_BUF_SIZE] = { 0 };
    int32_t ret = SoftBusInetPtoN(SOFTBUS_AF_INET, src, dst);
    EXPECT_EQ(SOFTBUS_ADAPTER_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusInetPtoNTest004
 * @tc.desc: string is invalid format
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusInetPtoNTest004, TestSize.Level0)
{
    const char *src = "0x1234";
    char dst[TEST_BUF_SIZE] = { 0 };
    int32_t ret = SoftBusInetPtoN(SOFTBUS_AF_INET, src, dst);
    EXPECT_EQ(SOFTBUS_ADAPTER_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusInetPtoNTest005
 * @tc.desc: string is invalid format
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusInetPtoNTest005, TestSize.Level0)
{
    const char *src = "__*0x1234";
    char dst[TEST_BUF_SIZE] = { 0 };
    int32_t ret = SoftBusInetPtoN(SOFTBUS_AF_INET, src, dst);
    EXPECT_EQ(SOFTBUS_ADAPTER_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusInetPtoNTest006
 * @tc.desc: af is illegal
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusInetPtoNTest006, TestSize.Level0)
{
    const char *src = "192.168.0.1";
    char dst[TEST_BUF_SIZE] = { 0 };
    int32_t ret = SoftBusInetPtoN(-1, src, dst);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);
}

/*
 * @tc.name: SoftBusInetPtoNTest007
 * @tc.desc: loop back
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusInetPtoNTest007, TestSize.Level0)
{
    const char *src = "::1";
    char dst[46] = { 0 };
    int32_t ret = SoftBusInetPtoN(SOFTBUS_AF_INET6, src, dst);
    EXPECT_EQ(0, ret);
}

/*
 * @tc.name: SoftBusHtoNlTest001
 * @tc.desc: positive
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusHtoNlTest001, TestSize.Level0)
{
    uint32_t hostlong = 0x12345678;
    uint32_t ret = SoftBusHtoNl(hostlong);
    EXPECT_EQ(0x78563412, ret);
}

/*
 * @tc.name: SoftBusHtoNlTest002
 * @tc.desc: positive
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusHtoNlTest002, TestSize.Level0)
{
    uint32_t hostlong = 0x0;
    uint32_t ret = SoftBusHtoNl(hostlong);
    EXPECT_EQ(0x0, ret);
}

/*
 * @tc.name: SoftBusHtoNsTest001
 * @tc.desc: positive
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusHtoNsTest001, TestSize.Level0)
{
    uint16_t hostshort = 0x1234;
    uint16_t ret = SoftBusHtoNs(hostshort);
    EXPECT_EQ(0x3412, ret);
}

/*
 * @tc.name: SoftBusHtoNsTest002
 * @tc.desc: positive
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusHtoNsTest002, TestSize.Level0)
{
    uint16_t hostshort = 0x0;
    uint16_t ret = SoftBusHtoNs(hostshort);
    EXPECT_EQ(0x0, ret);
}

/*
 * @tc.name: SoftBusNtoHlTest001
 * @tc.desc: positive
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusNtoHlTest001, TestSize.Level0)
{
    int32_t netlong = 0x12345678;
    int32_t ret = SoftBusNtoHl(netlong);
    EXPECT_EQ(0x78563412, ret);
}

/*
 * @tc.name: SoftBusNtoHlTest002
 * @tc.desc: positive
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusNtoHlTest002, TestSize.Level0)
{
    uint32_t netlong = 0x12;
    uint32_t ret = SoftBusNtoHl(netlong);
    EXPECT_EQ(0x12000000, ret);
}

/*
 * @tc.name: SoftBusNtoHsTest001
 * @tc.desc: positive
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusNtoHsTest001, TestSize.Level0)
{
    uint16_t netshort = 0x1234;
    uint16_t ret = SoftBusNtoHs(netshort);
    EXPECT_EQ(0x3412, ret);
}

/*
 * @tc.name: SoftBusNtoHsTest002
 * @tc.desc: positive
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusNtoHsTest002, TestSize.Level0)
{
    uint16_t netshort = 0x12;
    uint16_t ret = SoftBusNtoHs(netshort);
    EXPECT_EQ(0x1200, ret);
}

/*
 * @tc.name: SoftBusInetAddrTest001
 * @tc.desc: positive
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusInetAddrTest001, TestSize.Level0)
{
    const char *cp = "127.0.0.1";
    int32_t ret = SoftBusInetAddr(cp);
    EXPECT_EQ(LOCAL_HOST_VALUE, ret);
}

/*
 * @tc.name: SoftBusInetAddrTest002
 * @tc.desc: invalid cp
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusInetAddrTest002, TestSize.Level0)
{
    const char *cp = "abcde";
    int32_t ret = SoftBusInetAddr(cp);
    EXPECT_EQ(-1, ret);
}

/*
 * @tc.name: SoftBusInetAddrTest003
 * @tc.desc: invalid cp
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusInetAddrTest003, TestSize.Level0)
{
    const char *cp = "0x1234";
    int32_t ret = SoftBusInetAddr(cp);
    EXPECT_EQ(0x34120000, ret);
}

/*
 * @tc.name: SoftBusInetAddrTest004
 * @tc.desc: invalid cp
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusInetAddrTest004, TestSize.Level0)
{
    const char *cp = "1234";
    int32_t ret = SoftBusInetAddr(cp);
    EXPECT_EQ(0xD2040000, ret);
}

/*
 * @tc.name: SoftBusInetAddrTest005
 * @tc.desc: invalid cp
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusInetAddrTest005, TestSize.Level0)
{
    const char *cp = "adc1234";
    int32_t ret = SoftBusInetAddr(cp);
    EXPECT_EQ(-1, ret);
}

/*
 * @tc.name: SoftBusIfNameToIndexTest001
 * @tc.desc: chba0
 * @tc.type: FUNC
 * @tc.require: 4
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusIfNameToIndexTest001, TestSize.Level0)
{
    const char *ifname = "wlan0";
    int32_t ret = SoftBusIfNameToIndex(ifname);
    EXPECT_TRUE(ret >= 0);
}

/*
 * @tc.name: SoftBusIndexToIfNameTest001
 * @tc.desc: invalidIndex
 * @tc.type: FUNC
 * @tc.require: SOFTBUS_ADAPTER_ERR
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusIndexToIfNameTest001, TestSize.Level0)
{
    char ifname[IF_NAME_SIZE] = { 0 };
    int32_t invalidIndex = -1;
    int32_t ret = SoftBusIndexToIfName(invalidIndex, ifname, IF_NAME_SIZE);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);
}

/*
 * @tc.name: SoftBusIndexToIfNameTest001
 * @tc.desc: invalidIndex
 * @tc.type: FUNC
 * @tc.require: SOFTBUS_INVALID_PARAM
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusIndexToIfNameTest002, TestSize.Level0)
{
    char ifname[IF_NAME_SIZE] = { 0 };
    int32_t invalidIndex = 1000;
    int32_t ret = SoftBusIndexToIfName(invalidIndex, ifname, IF_NAME_SIZE);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: SoftBusIndexToIfNameTest001
 * @tc.desc: WLAN_INDEX
 * @tc.type: FUNC
 * @tc.require: SOFTBUS_ADAPTER_OK
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusIndexToIfNameTest003, TestSize.Level0)
{
    char ifname[IF_NAME_SIZE] = { 0 };
    int32_t ret = SoftBusIndexToIfName(WLAN_INDEX, ifname, IF_NAME_SIZE);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
}

/*
 * @tc.name: SoftBusSocketFullFunc001
 * @tc.desc: Cover Serial Multiple Interfaces
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AdapterDsoftbusSocketTest, SoftBusSocketFullFunc001, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t ret;
    int32_t socketFd = -1;
    struct SocketProtocol buf = { 0 };

    ClientConnect(&socketFd);
    EXPECT_TRUE(socketFd != -1);

    buf.cmd = CMD_RECV;
    (void)strncpy_s(buf.data, sizeof(buf.data), "Happy New Year!", sizeof(buf.data));
    ret = SoftBusSocketSend(socketFd, (void *)&buf, sizeof(struct SocketProtocol), 0);
    sleep(1);
    EXPECT_TRUE(ret >= 0);
    printf("data is %s\n", buf.data);

    (void)memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
    ret = SoftBusSocketRecv(socketFd, (void *)&buf, sizeof(struct SocketProtocol), 0);
    EXPECT_TRUE(ret >= 0);
    printf("data is %s\n", buf.data);

    ClientExit(socketFd);
}
} // namespace OHOS
