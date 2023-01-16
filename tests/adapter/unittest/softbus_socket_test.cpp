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

#include <unistd.h>
#include <securec.h>
#include <fcntl.h>
#include "gtest/gtest.h"
#include "softbus_adapter_socket.h"
#include "softbus_adapter_errcode.h"
#include "softbus_errcode.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
const int PROTOCOL_MAXLEN = 100;
const int TEST_BUF_SIZE = 10;
const int TEST_PORT = 8888;
const int LOCAL_HOST_VALUE = 16777343;
const int CMD_EXIT = 0x11001100;
const int CMD_RECV = 0x22002200;
const int CMD_REPLY = 0x33003300;
const int SET_SIZE = 100;

SoftBusSockAddrIn g_serAddr = {
    .sinFamily = SOFTBUS_AF_INET,
    .sinPort = SoftBusHtoNs(TEST_PORT),
    .sinAddr = {
        .sAddr = SoftBusInetAddr("127.0.0.1")
    }
};

struct SocketProtocol {
    unsigned int cmd;
    char data[PROTOCOL_MAXLEN];
};

class DsoftbusSocketTest : public testing::Test {
protected:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DsoftbusSocketTest::SetUpTestCase(void)
{
}

void DsoftbusSocketTest::TearDownTestCase(void)
{
}

void DsoftbusSocketTest::SetUp()
{
}

void DsoftbusSocketTest::TearDown()
{
}

static void SocketServiceStart(int localFlag)
{
    int32_t socketFd = -1;
    int32_t optVal = 1;
    int32_t backLog = 2;
    SoftBusSockAddrIn cliAddr = {0};
    int addrLen = sizeof(SoftBusSockAddrIn);
    int acceptFd = -1;
    struct SocketProtocol buf = {0};
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketSetOpt(socketFd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEADDR, &optVal, sizeof(optVal));
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketBind(socketFd, (SoftBusSockAddr *)&g_serAddr, sizeof(SoftBusSockAddrIn));
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketListen(socketFd, backLog);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketAccept(socketFd, (SoftBusSockAddr *)&cliAddr, &addrLen, &acceptFd);
    EXPECT_EQ(0, ret);

    if (localFlag) {
        char serviceIP[20];
        SoftBusSockAddrIn serviceAddr;
        int32_t serviceAddrLen = sizeof(SoftBusSockAddrIn);
        SoftBusSocketGetLocalName(acceptFd, (SoftBusSockAddr *)&serviceAddr, &serviceAddrLen);
        SoftBusInetNtoP(SOFTBUS_AF_INET, &serviceAddr.sinAddr, serviceIP, sizeof(serviceIP));
        uint16_t port = SoftBusNtoHs(serviceAddr.sinPort);
        EXPECT_EQ(port, TEST_PORT);
    }

    while (1) {
        memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
        ret = SoftBusSocketRecv(acceptFd, (void *)&buf, sizeof(struct SocketProtocol), 0);
        EXPECT_TRUE(ret != -1);
        if (buf.cmd == CMD_EXIT) {
            break;
        } else if (buf.cmd == CMD_RECV) {
            memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
            buf.cmd = CMD_REPLY;
            (void)strncpy_s(buf.data, sizeof(buf.data), "Beautiful World!", sizeof(buf.data));
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

static void ClientConnect(int32_t *socketFd)
{
    EXPECT_TRUE(socketFd != NULL);
    SoftBusSockAddrIn serAddr = {
        .sinFamily = SOFTBUS_AF_INET,
        .sinPort = SoftBusHtoNs(8888),
        .sinAddr = {
            .sAddr = SoftBusInetAddr("127.0.0.1")
        }
    };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketConnect(*socketFd, (SoftBusSockAddr *)&serAddr, sizeof(SoftBusSockAddrIn));
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketCreate001, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM | SOFTBUS_SOCK_NONBLOCK |
        SOFTBUS_SOCK_CLOEXEC, 0, &socketFd);
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketCreate002, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketCreate003, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketCreate004, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketCreate005, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSetOptTest001, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSetOptTest002, TestSize.Level0)
{
    int socketFd;
    int ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
    int optVal = 1;
    int optValLen = sizeof(int);
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSetOptTest003, TestSize.Level0)
{
    int socketFd;
    int ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);

    int optVal = 1;
    int optValLen = sizeof(int);
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSetOptTest004, TestSize.Level0)
{
    int optVal = 1;
    int optValLen = sizeof(int);
    int ret = SoftBusSocketSetOpt(-1, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEADDR, &optVal, optValLen);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);
}

/*
* @tc.name: SoftBusSocketSetOptTest005
* @tc.desc: Protocol is illegal
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSetOptTest005, TestSize.Level0)
{
    int socketFd;
    int ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
    int optVal = 10;
    int optValLen = sizeof(int);
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSetOptTest006, TestSize.Level0)
{
    int socketFd;
    int ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
    int optValLen = sizeof(int);
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSetOptTest007, TestSize.Level0)
{
    int socketFd;
    int ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
    int optVal = 1;
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketGetOptTest001, TestSize.Level0)
{
    int socketFd;
    int on = 1;
    int onLen = sizeof(on);
    int ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketGetOptTest002, TestSize.Level0)
{
    int on = 1;
    int onLen = sizeof(on);
    int rc = SoftBusSocketGetOpt(-1, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEADDR, &on, &onLen);
    EXPECT_TRUE(rc == -1);
}

/*
* @tc.name: SoftBusSocketGetLocalNameTest001
* @tc.desc: test in service get port
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketGetLocalNameTest001, TestSize.Level0)
{
    sleep(1);
    int pid = -1;
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketGetLocalNameTest002, TestSize.Level0)
{
    int32_t socketFd = -1;
    SoftBusSockAddrIn clientAddr;
    int32_t clientAddrLen = sizeof(SoftBusSockAddrIn);
    int32_t ret = SoftBusSocketGetLocalName(socketFd, (SoftBusSockAddr *)&clientAddr, &clientAddrLen);
    EXPECT_EQ(-1, ret);
}

/*
* @tc.name: SoftBusSocketGetLocalNameTest003
* @tc.desc: addr is null
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketGetLocalNameTest003, TestSize.Level0)
{
    sleep(1);
    int pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t ret;
    int32_t socketFd = -1;

    ClientConnect(&socketFd);

    int32_t clientAddrLen = sizeof(SoftBusSockAddrIn);
    ret = SoftBusSocketGetLocalName(socketFd, NULL, &clientAddrLen);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);

    ClientExit(socketFd);
}

/*
* @tc.name: SoftBusSocketGetLocalNameTest004
* @tc.desc: addrLen is null
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketGetLocalNameTest004, TestSize.Level0)
{
    sleep(1);
    int pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t ret;
    int32_t socketFd = -1;

    ClientConnect(&socketFd);

    SoftBusSockAddrIn clientAddr;
    ret = SoftBusSocketGetLocalName(socketFd, (SoftBusSockAddr *)&clientAddr, NULL);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);

    ClientExit(socketFd);
}

/*
* @tc.name: SoftBusSocketGetLocalNameTest005
* @tc.desc: socketFd is service fd
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketGetLocalNameTest005, TestSize.Level0)
{
    int socketFd;
    int ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
    SoftBusSockAddrIn clientAddr;
    int32_t clientAddrLen = sizeof(SoftBusSockAddrIn);
    ret = SoftBusSocketGetLocalName(socketFd, (SoftBusSockAddr *)&clientAddr, &clientAddrLen);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
}

/*
* @tc.name: SoftBusSocketGetPeerNameTest001
* @tc.desc: get service port success
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketGetPeerNameTest001, TestSize.Level0)
{
    sleep(1);
    int pid = -1;
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
    int32_t serviceAddrLen = sizeof(SoftBusSockAddrIn);

    ret = SoftBusSocketGetPeerName(socketFd, (SoftBusSockAddr *)&serviceAddr, &serviceAddrLen);
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketGetPeerNameTest002, TestSize.Level0)
{
    SoftBusSockAddr addr;
    int addrLen = sizeof(addr);
    int rc = SoftBusSocketGetPeerName(-1, &addr, &addrLen);
    EXPECT_TRUE(rc == -1);
}

/*
* @tc.name: SoftBusSocketGetPeerNameTest003
* @tc.desc: get service port success
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketGetPeerNameTest003, TestSize.Level0)
{
    sleep(1);
    int pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t ret;
    int32_t socketFd = -1;

    ClientConnect(&socketFd);

    int32_t serviceAddrLen = sizeof(SoftBusSockAddrIn);

    ret = SoftBusSocketGetPeerName(socketFd, NULL, &serviceAddrLen);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);

    ClientExit(socketFd);
}

/*
* @tc.name: SoftBusSocketGetPeerNameTest004
* @tc.desc: get service port success
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketGetPeerNameTest004, TestSize.Level0)
{
    sleep(1);
    int pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t ret;
    int32_t socketFd = -1;

    ClientConnect(&socketFd);

    SoftBusSockAddrIn serviceAddr;

    ret = SoftBusSocketGetPeerName(socketFd, (SoftBusSockAddr *)&serviceAddr, NULL);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);

    ClientExit(socketFd);
}

/*
* @tc.name: SoftBusSocketGetPeerNameTest005
* @tc.desc: socketFd is illegal
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketGetPeerNameTest005, TestSize.Level0)
{
    int socketFd;
    int ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
    SoftBusSockAddrIn serviceAddr;
    int32_t serviceAddrLen = sizeof(SoftBusSockAddrIn);
    ret = SoftBusSocketGetPeerName(socketFd, (SoftBusSockAddr *)&serviceAddr, &serviceAddrLen);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);

    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(SOFTBUS_ADAPTER_OK, ret);
}

/*
* @tc.name: SoftBusSocketBind001
* @tc.desc: Bind Socket Success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketBind001, TestSize.Level0)
{
    int32_t socketFd = -1;
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketBind(socketFd, &addr, sizeof(SoftBusSockAddr));
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketBind002, TestSize.Level0)
{
    int32_t socketFd = -1;
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketBind(socketFd, &addr, sizeof(SoftBusSockAddr) - 1);
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketBind003, TestSize.Level0)
{
    int32_t socketFd = -1;
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    int32_t ret = SoftBusSocketBind(socketFd, &addr, sizeof(SoftBusSockAddr));
    EXPECT_NE(0, ret);
}

/*
* @tc.name: SoftBusSocketBind004
* @tc.desc: addr is illegal
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketBind004, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketBind(socketFd, NULL, sizeof(SoftBusSockAddr));
    EXPECT_EQ(-1, ret);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
* @tc.name: SoftBusSocketListen001
* @tc.desc: Listen Socket Success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketListen001, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t backLog = 2;
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketBind(socketFd, &addr, sizeof(SoftBusSockAddr));
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketListen002, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t backLog = -1;
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketBind(socketFd, &addr, sizeof(SoftBusSockAddr));
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketListen003, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t backLog = 2;

    int32_t ret = SoftBusSocketListen(socketFd, backLog);
    EXPECT_EQ(-1, ret);
}

/*
* @tc.name: SoftBusSocketAccept001
* @tc.desc: Accept Socket Success
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketAccept001, TestSize.Level0)
{
    sleep(1);
    int pid = -1;
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketAccept002, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t acceptFd = -1;
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    int32_t addrLen = sizeof(SoftBusSockAddr);
    int32_t ret = SoftBusSocketAccept(socketFd, &addr, &addrLen, &acceptFd);
    EXPECT_NE(0, ret);
}

/*
* @tc.name: SoftBusSocketAccept003
* @tc.desc: acceptFd is illegal
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketAccept003, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t optVal = 1;
    int32_t backLog = 2;
    SoftBusSockAddrIn serAddr = {
        .sinFamily = SOFTBUS_AF_INET,
        .sinPort = SoftBusHtoNs(TEST_PORT),
        .sinAddr = {
            .sAddr = SoftBusInetAddr("127.0.0.1")
        }
    };
    SoftBusSockAddrIn cliAddr = {0};
    int addrLen = sizeof(SoftBusSockAddrIn);
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);

    SoftBusSocketSetOpt(socketFd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEADDR, &optVal, sizeof(optVal));
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketBind(socketFd, (SoftBusSockAddr *)&serAddr, sizeof(SoftBusSockAddrIn));
    EXPECT_EQ(0, ret);

    ret = SoftBusSocketListen(socketFd, backLog);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketAccept(socketFd, (SoftBusSockAddr *)&cliAddr, &addrLen, NULL);
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketConnect001, TestSize.Level0)
{
    sleep(1);
    int pid = -1;
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketConnect002, TestSize.Level0)
{
    int32_t socketFd = -1;
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    int32_t ret = SoftBusSocketConnect(socketFd, &addr, sizeof(SoftBusSockAddr));
    EXPECT_NE(0, ret);
}

/*
* @tc.name: SoftBusSocketConnect003
* @tc.desc: addr is illegal
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketConnect003, TestSize.Level0)
{
    int32_t socketFd = -1;
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketConnect(socketFd, NULL, sizeof(SoftBusSockAddrIn));
    EXPECT_EQ(-1, ret);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
* @tc.name: SoftBusSocketConnect004
* @tc.desc: addrLen is illegal
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketConnect004, TestSize.Level0)
{
    int32_t socketFd = -1;
    SoftBusSockAddrIn serAddr = {
        .sinFamily = SOFTBUS_AF_INET,
        .sinPort = SoftBusHtoNs(8888),
        .sinAddr = {
            .sAddr = SoftBusInetAddr("127.0.0.1")
        }
    };
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketConnect(socketFd, (SoftBusSockAddr *)&serAddr, -1);
    EXPECT_NE(0, ret);
    ret = SoftBusSocketClose(socketFd);
    EXPECT_EQ(0, ret);
}

/*
* @tc.name: SoftBusSocketFdZeroTest001
* @tc.desc: set is NULL
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketFdZeroTest001, TestSize.Level0)
{
    SoftBusSocketFdZero(NULL);
}

/*
* @tc.name: SoftBusSocketFdZeroTest002
* @tc.desc: set fdsBits zero success
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketFdZeroTest002, TestSize.Level0)
{
    SoftBusFdSet set = {0};
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketFdSetTest001, TestSize.Level0)
{
    int32_t socketFd;
    SoftBusFdSet set = {0};
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketFdSetTest003, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketFdClrTest001, TestSize.Level0)
{
    SoftBusFdSet set;
    SoftBusSocketFdZero(&set);
    SoftBusSocketFdSet(1, &set);
    SoftBusSocketFdClr(1, &set);
    EXPECT_TRUE(set.fdsBits[0] == 0);
}

/*
* @tc.name: SoftBusSocketFdClrTest002
* @tc.desc: set is null
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketFdClrTest002, TestSize.Level0)
{
    SoftBusSocketFdClr(1, NULL);
}

/*
* @tc.name: SoftBusSocketFdClrTest003
* @tc.desc: clear fd is not set
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketFdClrTest003, TestSize.Level0)
{
    SoftBusFdSet set;
    SoftBusSocketFdZero(&set);
    SoftBusSocketFdClr(1, NULL);
}

/*
* @tc.name: SoftBusSocketFdIssetTest001
* @tc.desc: FdIsset success
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketFdIssetTest001, TestSize.Level0)
{
    SoftBusFdSet set;
    SoftBusSocketFdSet(1, &set);
    int ret = SoftBusSocketFdIsset(1, &set);
    EXPECT_TRUE(ret == 1);
}

/*
* @tc.name: SoftBusSocketFdIssetTest002
* @tc.desc: fd not in set
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketFdIssetTest002, TestSize.Level0)
{
    SoftBusFdSet set = {0};
    SoftBusSocketFdClr(1, &set);
    int ret = SoftBusSocketFdIsset(1, &set);
    EXPECT_TRUE(ret == 0);
}

/*
* @tc.name: SoftBusSocketFdIssetTest003
* @tc.desc: set is null
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketFdIssetTest003, TestSize.Level0)
{
    int ret = SoftBusSocketFdIsset(1, NULL);
    EXPECT_TRUE(ret == 0);
}

/*
* @tc.name: SoftBusSocketSelectTest001
* @tc.desc: select read fds
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSelectTest001, TestSize.Level0)
{
    int32_t socketFd;
    SoftBusFdSet readFds;
    SoftBusSockTimeOut tv = {
        .sec = 5,
        .usec = 1
    };
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSelectTest002, TestSize.Level0)
{
    int32_t socketFd;
    SoftBusFdSet writeFds;
    SoftBusFdSet fdSelect;
    SoftBusSockTimeOut tv = {
        .sec = 5,
        .usec = 1
    };
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSelectTest003, TestSize.Level0)
{
    int32_t socketFd;
    SoftBusFdSet exceptFds;
    SoftBusFdSet fdSelect;
    SoftBusSockTimeOut tv = {
        .sec = 5,
        .usec = 1
    };
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSelectTest004, TestSize.Level0)
{
    SoftBusFdSet readFds, writeFds, exceptFds;
    SoftBusSockTimeOut tv = {
        .sec = 5,
        .usec = 1
    };
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSelectTest005, TestSize.Level0)
{
    SoftBusSockTimeOut tv = {
        .sec = 5,
        .usec = 1
    };
    int32_t ret = SoftBusSocketSelect(SET_SIZE, NULL, NULL, NULL, &tv);
    EXPECT_TRUE(ret >= 0);
}

/*
* @tc.name: SoftBusSocketSelectTest006
* @tc.desc: timeOut is not set
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSelectTest006, TestSize.Level0)
{
    SoftBusFdSet readFds, writeFds, exceptFds;
    int32_t ret = SoftBusSocketSelect(SET_SIZE, &readFds, &writeFds, &exceptFds, NULL);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);
}

/*
* @tc.name: SoftBusSocketIoctlTest001
* @tc.desc:fd is illegal
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketIoctlTest001, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketIoctlTest002, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketFcntlTest001, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketFcntlTest002, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSendTest001, TestSize.Level0)
{
    int32_t socketFd = -1;
    char buf[TEST_BUF_SIZE] = {0};

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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSendTest002, TestSize.Level0)
{
    sleep(1);
    int pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;
    SoftBusSockAddrIn serAddr = {
        .sinFamily = SOFTBUS_AF_INET,
        .sinPort = SoftBusHtoNs(8888),
        .sinAddr = {
            .sAddr = SoftBusInetAddr("127.0.0.1")
        }
    };
    struct SocketProtocol buf = {0};
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketConnect(socketFd, (SoftBusSockAddr *)&serAddr, sizeof(SoftBusSockAddrIn));
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketSend(socketFd, NULL, 0, 0);
    EXPECT_TRUE(ret <= 0);
    memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSendTest003, TestSize.Level0)
{
    sleep(1);
    int pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;
    SoftBusSockAddrIn serAddr = {
        .sinFamily = SOFTBUS_AF_INET,
        .sinPort = SoftBusHtoNs(8888),
        .sinAddr = {
            .sAddr = SoftBusInetAddr("127.0.0.1")
        }
    };
    struct SocketProtocol buf = {0};
    int32_t ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    EXPECT_EQ(0, ret);
    ret = SoftBusSocketConnect(socketFd, (SoftBusSockAddr *)&serAddr, sizeof(SoftBusSockAddrIn));
    EXPECT_EQ(0, ret);
    buf.cmd = CMD_RECV;
    (void)strncpy_s(buf.data, sizeof(buf.data), "Happy New Year!", sizeof(buf.data));
    ret = SoftBusSocketSend(socketFd, (void *)&buf, 0, 0);
    EXPECT_TRUE(ret <= 0);
    memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSendTest004, TestSize.Level0)
{
    sleep(1);
    int pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;
    struct SocketProtocol buf = {0};
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSendToTest001, TestSize.Level0)
{
    int32_t socketFd = -1;
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    struct SocketProtocol buf = {0};
    int32_t ret = SoftBusSocketSendTo(socketFd, (void *)&buf, sizeof(buf), 0, &addr, sizeof(SoftBusSockAddr));
    EXPECT_EQ(-1, ret);
}

/*
* @tc.name: SoftBusSocketSendToTest002
* @tc.desc: send to success
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSendToTest002, TestSize.Level0)
{
    sleep(1);
    int pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;
    struct SocketProtocol buf = {0};
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    ClientConnect(&socketFd);

    buf.cmd = CMD_RECV;
    (void)strncpy_s(buf.data, sizeof(buf.data), "Happy New Year!", sizeof(buf.data));
    int32_t ret = SoftBusSocketSendTo(socketFd, (void *)&buf, sizeof(buf), 0, &addr, sizeof(SoftBusSockAddr));
    EXPECT_TRUE(ret >= 0);

    ClientExit(socketFd);
}

/*
* @tc.name: SoftBusSocketSendToTest003
* @tc.desc: buf is null
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSendToTest003, TestSize.Level0)
{
    sleep(1);
    int pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;
    struct SocketProtocol buf = {0};
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    ClientConnect(&socketFd);

    int32_t ret = SoftBusSocketSendTo(socketFd, NULL, sizeof(buf), 0, &addr, sizeof(SoftBusSockAddr));
    EXPECT_TRUE(ret == -1);

    ClientExit(socketFd);
}

/*
* @tc.name: SoftBusSocketSendToTest004
* @tc.desc: addr is NULL
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSendToTest004, TestSize.Level0)
{
    sleep(1);
    int pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;
    struct SocketProtocol buf = {0};
    ClientConnect(&socketFd);

    int32_t ret = SoftBusSocketSendTo(socketFd, (void *)&buf, sizeof(buf), 0, NULL, sizeof(SoftBusSockAddr));
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);

    ClientExit(socketFd);
}

/*
* @tc.name: SoftBusSocketSendToTest005
* @tc.desc: addrLen is illegal
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSendToTest005, TestSize.Level0)
{
    sleep(1);
    int pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;
    struct SocketProtocol buf = {0};
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketSendToTest006, TestSize.Level0)
{
    sleep(1);
    int pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;
    struct SocketProtocol buf = {0};
    SoftBusSockAddr addr = {
        .saFamily = SOFTBUS_AF_INET,
    };
    ClientConnect(&socketFd);

    int32_t ret = SoftBusSocketSendTo(socketFd, (void *)&buf, 0, 0, &addr, sizeof(SoftBusSockAddr));
    EXPECT_TRUE(ret == 0);

    ClientExit(socketFd);
}

/*
* @tc.name: SoftBusSocketRecvTest001
* @tc.desc: socketFd is NULL
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketRecvTest001, TestSize.Level0)
{
    int32_t socketFd = -1;
    struct SocketProtocol buf = {0};
    int32_t ret = SoftBusSocketRecv(socketFd, (void *)&buf, sizeof(struct SocketProtocol), 0);
    EXPECT_NE(0, ret);
}

/*
* @tc.name: SoftBusSocketRecvTest002
* @tc.desc: recv success
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketRecvTest002, TestSize.Level0)
{
    sleep(1);
    int32_t pid = -1;
    if ((pid = fork()) == 0) {
        SocketServiceStart(0);
        return;
    }
    sleep(1);
    int32_t socketFd = -1;
    struct SocketProtocol buf = {0};
    ClientConnect(&socketFd);

    buf.cmd = CMD_RECV;
    (void)strncpy_s(buf.data, sizeof(buf.data), "Hello World!", sizeof(buf.data));
    int32_t ret = SoftBusSocketSend(socketFd, (void *)&buf, sizeof(struct SocketProtocol), 0);
    EXPECT_TRUE(ret != -1);

    memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketRecvFromTest001, TestSize.Level0)
{
    int32_t socketFd = -1;
    SoftBusSockAddr fromAddr = {0};
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketShutDownTest001, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketShutDownTest002, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketShutDownTest003, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketCloseTest001, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusSocketCloseTest002, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusInetPtoNTest001, TestSize.Level0)
{
    const char *src = "192.168.0.1";
    char dst[TEST_BUF_SIZE] = {0};
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
HWTEST_F(DsoftbusSocketTest, SoftBusInetPtoNTest002, TestSize.Level0)
{
    const char *src = "abcde";
    char dst[TEST_BUF_SIZE] = {0};
    int32_t ret = SoftBusInetPtoN(SOFTBUS_AF_INET, src, dst);
    EXPECT_EQ(SOFTBUS_ADAPTER_INVALID_PARAM, ret);
}

/*
* @tc.name: SoftBusInetPtoNTest003
* @tc.desc: string is invalid format
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusInetPtoNTest003, TestSize.Level0)
{
    const char *src = "1234";
    char dst[TEST_BUF_SIZE] = {0};
    int32_t ret = SoftBusInetPtoN(SOFTBUS_AF_INET, src, dst);
    EXPECT_EQ(SOFTBUS_ADAPTER_INVALID_PARAM, ret);
}

/*
* @tc.name: SoftBusInetPtoNTest004
* @tc.desc: string is invalid format
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusInetPtoNTest004, TestSize.Level0)
{
    const char *src = "0x1234";
    char dst[TEST_BUF_SIZE] = {0};
    int32_t ret = SoftBusInetPtoN(SOFTBUS_AF_INET, src, dst);
    EXPECT_EQ(SOFTBUS_ADAPTER_INVALID_PARAM, ret);
}

/*
* @tc.name: SoftBusInetPtoNTest005
* @tc.desc: string is invalid format
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusInetPtoNTest005, TestSize.Level0)
{
    const char *src = "__*0x1234";
    char dst[TEST_BUF_SIZE] = {0};
    int32_t ret = SoftBusInetPtoN(SOFTBUS_AF_INET, src, dst);
    EXPECT_EQ(SOFTBUS_ADAPTER_INVALID_PARAM, ret);
}

/*
* @tc.name: SoftBusInetPtoNTest006
* @tc.desc: af is illegal
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusInetPtoNTest006, TestSize.Level0)
{
    const char *src = "192.168.0.1";
    char dst[TEST_BUF_SIZE] = {0};
    int32_t ret = SoftBusInetPtoN(-1, src, dst);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);
}

/*
* @tc.name: SoftBusHtoNlTest001
* @tc.desc: positive
* @tc.type: FUNC
* @tc.require: 1
*/
HWTEST_F(DsoftbusSocketTest, SoftBusHtoNlTest001, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusHtoNlTest002, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusHtoNsTest001, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusHtoNsTest002, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusNtoHlTest001, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusNtoHlTest002, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusNtoHsTest001, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusNtoHsTest002, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusInetAddrTest001, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusInetAddrTest002, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusInetAddrTest003, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusInetAddrTest004, TestSize.Level0)
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
HWTEST_F(DsoftbusSocketTest, SoftBusInetAddrTest005, TestSize.Level0)
{
    const char *cp = "adc1234";
    int32_t ret = SoftBusInetAddr(cp);
    EXPECT_EQ(-1, ret);
}

/*
* @tc.name: SoftBusSocketFullFunc001
* @tc.desc: Cover Serial Multiple Interfaces
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DsoftbusSocketTest, SoftBusSocketFullFunc001, TestSize.Level0)
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
    struct SocketProtocol buf = {0};

    ClientConnect(&socketFd);
    EXPECT_TRUE(socketFd != -1);

    buf.cmd = CMD_RECV;
    (void)strncpy_s(buf.data, sizeof(buf.data), "Happy New Year!", sizeof(buf.data));
    ret = SoftBusSocketSend(socketFd, (void *)&buf, sizeof(struct SocketProtocol), 0);
    sleep(1);
    EXPECT_TRUE(ret >= 0);
    printf("data is %s\n", buf.data);

    memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
    ret = SoftBusSocketRecv(socketFd, (void *)&buf, sizeof(struct SocketProtocol), 0);
    EXPECT_TRUE(ret >= 0);
    printf("data is %s\n", buf.data);

    ClientExit(socketFd);
}
}
