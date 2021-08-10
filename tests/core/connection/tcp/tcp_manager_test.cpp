/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <pthread.h>
#include <securec.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_base_listener.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_tcp_connect_manager.h"
#include "softbus_tcp_socket.h"
#include "softbus_thread_pool.h"
#include "softbus_utils.h"

static const int MAXLNE = 50;

using namespace testing::ext;

namespace OHOS {
const char *Ip = "127.0.0.1";
const char *g_data = "1234567890";

static uint32_t g_connectionId = 0;
static ConnectFuncInterface *g_interface = nullptr;
static ConnectResult g_result;
static ConnectCallback g_cb;
static int g_receivedDatalength = 0;

void TcpOnConnected(uint32_t connectionId, const ConnectionInfo *info)
{
    printf("TcpOnConnected %08x\n", connectionId);
}

void TcpOnDisConnect(uint32_t connectionId, const ConnectionInfo *info)
{
    printf("TcpOnDisConnect %08x\n", connectionId);
}

void TcpDataReceived(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int length)
{
    g_receivedDatalength = length;
    printf("nDataReceived with length:%d\n", length);
}

void TcpOnConnectionSuccessed(uint32_t requestId, uint32_t connectionId, const ConnectionInfo *info)
{
    g_connectionId = connectionId;
    printf("OnConnectionEnabled with requestId:%u connectionId:%08x\n", requestId, connectionId);
}

void TcpOnConnectionFailed(uint32_t requestId, int32_t reason)
{
    printf("OnConnectionFailed with requestId:%u reason:%d\n", requestId, reason);
}

class SoftbusTcpManagerTest : public testing::Test {
public:
    SoftbusTcpManagerTest()
    {}
    ~SoftbusTcpManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void SoftbusTcpManagerTest::SetUpTestCase(void)
{}

void SoftbusTcpManagerTest::TearDownTestCase(void)
{}

void SoftbusTcpManagerTest::SetUp(void)
{
    g_cb.OnConnected = TcpOnConnected;
    g_cb.OnDataReceived = TcpDataReceived;
    g_cb.OnDisconnected = TcpOnDisConnect;
    g_interface = ConnInitTcp(&g_cb);
    g_result.OnConnectSuccessed = TcpOnConnectionSuccessed;
    g_result.OnConnectFailed = TcpOnConnectionFailed;
    g_connectionId = 0;
    g_receivedDatalength = 0;
}

void SoftbusTcpManagerTest::TearDown(void)
{
    free(g_interface);
    g_interface = nullptr;
}

void CreateServer(void *arg)
{
    int listenfd, connfd, n;
    struct sockaddr_in servaddr;
    char buff[MAXLNE];
    int port = 6667;
    int defaultListen = 5;

    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("create socket error: %s(errno: %d)\n", strerror(errno), errno);
        return;
    }

    (void)memset_s(&servaddr, sizeof(servaddr), 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    inet_pton(AF_INET, Ip, &servaddr.sin_addr);
    servaddr.sin_port = htons(port);

    if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
        close(listenfd);
        printf("bind socket error: %s(errno: %d)\n", strerror(errno), errno);
        return;
    }
    if (listen(listenfd, defaultListen) == -1) {
        close(listenfd);
        printf("listen socket error: %s(errno: %d)\n", strerror(errno), errno);
        return;
    }

    while (true) {
        if ((connfd = accept(listenfd, (struct sockaddr *)nullptr, nullptr)) == -1) {
            printf("accept socket error: %s(errno: %d)\n", strerror(errno), errno);
            continue;
        }
        break;
    }

    while (true) {
        n = recv(connfd, buff, MAXLNE, 0);
        if (n <= 0) {
            break;
        }
        printf("recv msg with length:%d from client\n", n);
        n = send(connfd, buff, n, 0);
        printf("send msg with length:%d to client\n", n);
    }
    close(connfd);
    close(listenfd);
}

/*
* @tc.name: testBaseListener001
* @tc.desc: test TcpGetConnNum
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusTcpManagerTest, testTcpManager001, TestSize.Level1)
{
    EXPECT_EQ(0, TcpGetConnNum());
};

/*
* @tc.name: testBaseListener002
* @tc.desc: test TcpConnectDevice with invalid param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusTcpManagerTest, testTcpManager002, TestSize.Level1)
{
    int port= 6666;
    uint32_t requestId = 1;
    ConnectOption option;
    option.type = CONNECT_BR;
    option.info.ipOption.port = port;
    (void)strcpy_s(option.info.ipOption.ip, IP_LEN, Ip);
    int ret;
    ret = TcpConnectDevice(nullptr, requestId, &g_result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TcpConnectDevice(&option, requestId, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = TcpConnectDevice(&option, requestId, &g_result);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
};

/*
* @tc.name: testBaseListener003
* @tc.desc: test TcpDisconnectDevice with wrong id
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusTcpManagerTest, testTcpManager003, TestSize.Level1)
{
    EXPECT_EQ(SOFTBUS_ERR, TcpDisconnectDevice(g_connectionId));
};

/*
* @tc.name: testBaseListener004
* @tc.desc: test TcpGetConnectionInfo with invalid param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusTcpManagerTest, testTcpManager004, TestSize.Level1)
{
    ConnectionInfo info = {};
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, TcpGetConnectionInfo(g_connectionId, nullptr));
    EXPECT_EQ(SOFTBUS_ERR, TcpGetConnectionInfo(g_connectionId, &info));
    EXPECT_EQ(false, info.isAvailable);
};

/*
* @tc.name: testBaseListener005
* @tc.desc: test start and stop listener multi times
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusTcpManagerTest, testTcpManager005, TestSize.Level1)
{
    int port = 6666;
    LocalListenerInfo info = {};
    info.type = CONNECT_BR;
    info.info.ipListenerInfo.port = port;
    (void)strcpy_s(info.info.ipListenerInfo.ip, IP_LEN, Ip);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, TcpStartListening(nullptr));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, TcpStartListening(&info));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, TcpStopListening(nullptr));

    info.type = CONNECT_TCP;
    EXPECT_EQ(SOFTBUS_ERR, TcpStopListening(&info));
    EXPECT_EQ(port, TcpStartListening(&info));
    EXPECT_EQ(SOFTBUS_ERR, TcpStartListening(&info));
    EXPECT_EQ(SOFTBUS_OK, TcpStopListening(&info));
    EXPECT_TRUE(SOFTBUS_OK != TcpStopListening(&info));
};

/*
* @tc.name: testTcpManager006
* @tc.desc: test TcpDisconnectDevice
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusTcpManagerTest, testTcpManager006, TestSize.Level1)
{
    int port = 6666;
    LocalListenerInfo info = {};
    info.type = CONNECT_TCP;
    info.info.ipListenerInfo.port = port;
    (void)strcpy_s(info.info.ipListenerInfo.ip, IP_LEN, Ip);

    uint32_t requestId = 1;
    ConnectOption option;
    option.type = CONNECT_TCP;
    option.info.ipOption.port = port;
    (void)strcpy_s(option.info.ipOption.ip, IP_LEN, Ip);

    EXPECT_EQ(port, TcpStartListening(&info));
    EXPECT_EQ(SOFTBUS_OK, TcpConnectDevice(&option, requestId, &g_result));
    sleep(1);
    EXPECT_EQ(2, TcpGetConnNum());
    EXPECT_EQ(SOFTBUS_OK, TcpDisconnectDevice(g_connectionId));
    sleep(1);
    EXPECT_EQ(0, TcpGetConnNum());
    EXPECT_EQ(SOFTBUS_OK, TcpStopListening(&info));
}

/*
* @tc.name: testTcpManager007
* @tc.desc: test post out of max length
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusTcpManagerTest, testTcpManager007, TestSize.Level1)
{
    pthread_t pid;

    int clientPort = 6666;
    int serverPort = 6667;
    LocalListenerInfo info = {};
    info.type = CONNECT_TCP;
    info.info.ipListenerInfo.port = clientPort;
    (void)strcpy_s(info.info.ipListenerInfo.ip, IP_LEN, Ip);

    uint32_t requestId = 1;
    ConnectOption option = {};
    option.type = CONNECT_TCP;
    option.info.ipOption.port = serverPort;
    (void)strcpy_s(option.info.ipOption.ip, IP_LEN, Ip);

    ConnPktHead head = {0};
    head.len = strlen(g_data);
    char data[sizeof(head) + head.len];
    (void)memcpy_s(&data, sizeof(head), (void*)&head, sizeof(head));
    (void)memcpy_s(&data[sizeof(head)], head.len, g_data, head.len);

    pthread_create(&pid, nullptr, (void *(*)(void *))CreateServer, nullptr);
    sleep(1);
    EXPECT_EQ(clientPort, TcpStartListening(&info));
    EXPECT_EQ(SOFTBUS_OK, TcpConnectDevice(&option, requestId, &g_result));
    EXPECT_EQ(1, TcpGetConnNum());
    for (int i = 0; i < 3; i++) {
        EXPECT_EQ(SOFTBUS_OK, TcpPostBytes(g_connectionId, data, sizeof(ConnPktHead) + head.len, 0, 0));
        sleep(1);
        EXPECT_EQ(int(sizeof(ConnPktHead) + head.len), g_receivedDatalength);
        g_receivedDatalength = 0;
    }
    EXPECT_EQ(SOFTBUS_OK, TcpDisconnectDevice(g_connectionId));
    EXPECT_EQ(0, TcpGetConnNum());
    EXPECT_EQ(SOFTBUS_OK, TcpStopListening(&info));
    EXPECT_EQ(0, TcpGetConnNum());
    pthread_join(pid, nullptr);
}

/*
* @tc.name: testTcpManager008
* @tc.desc: test connect out of max connect num
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusTcpManagerTest, testTcpManager008, TestSize.Level1)
{
    int port = 6666;
    LocalListenerInfo info = {};
    info.type = CONNECT_TCP;
    info.info.ipListenerInfo.port = port;
    (void)strcpy_s(info.info.ipListenerInfo.ip, IP_LEN, Ip);

    uint32_t requestId = 1;
    ConnectOption option;
    option.type = CONNECT_TCP;
    option.info.ipOption.port = port;
    (void)strcpy_s(option.info.ipOption.ip, IP_LEN, Ip);

    int32_t maxConnNum;
    int32_t i = 0;
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_TCP_MAX_CONN_NUM,
        (unsigned char*)&maxConnNum, sizeof(maxConnNum)) != SOFTBUS_OK) {
        LOG_ERR("get maxConnNum fail");
    }
    printf("maxConnNum: %d\n", maxConnNum);
    EXPECT_EQ(port, TcpStartListening(&info));
    while (TcpGetConnNum() < maxConnNum) {
        EXPECT_EQ(SOFTBUS_OK, TcpConnectDevice(&option, requestId, &g_result));
        sleep(1);
        i += 2;
        EXPECT_EQ(i, TcpGetConnNum());
    }
    EXPECT_TRUE(SOFTBUS_OK != TcpConnectDevice(&option, requestId, &g_result));
    TcpDisconnectDeviceNow(&option);
    sleep(1);
    EXPECT_EQ(0, TcpGetConnNum());
    EXPECT_EQ(SOFTBUS_OK, TcpStopListening(&info));
}

/*
* @tc.name: testBaseListener009
* @tc.desc: test connect and post to self
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusTcpManagerTest, testTcpManager009, TestSize.Level1)
{
    int port = 6666;
    LocalListenerInfo info = {};
    info.type = CONNECT_TCP;
    info.info.ipListenerInfo.port = port;
    (void)strcpy_s(info.info.ipListenerInfo.ip, IP_LEN, Ip);

    uint32_t requestId = 1;
    ConnectOption option;
    option.type = CONNECT_TCP;
    option.info.ipOption.port = port;
    (void)strcpy_s(option.info.ipOption.ip, IP_LEN, Ip);

    int maxDataLen;
    if (SoftbusGetConfig(SOFTBUS_INT_CONN_TCP_MAX_LENGTH,
        (unsigned char*)&maxDataLen, sizeof(maxDataLen)) != SOFTBUS_OK) {
        LOG_ERR("get maxDataLen fail");
    }
    printf("maxDataLen: %d\n", maxDataLen);
    ConnPktHead head = {0};
    head.len = maxDataLen + 1;
    char data[sizeof(head) + maxDataLen];
    (void)memcpy_s(&data, sizeof(head), (void*)&head, sizeof(head));
    (void)memset_s(&data[sizeof(head)], head.len, 0x1, head.len);

    EXPECT_EQ(port, TcpStartListening(&info));
    EXPECT_EQ(SOFTBUS_OK, TcpConnectDevice(&option, requestId, &g_result));
    sleep(1);
    EXPECT_EQ(2, TcpGetConnNum());
    EXPECT_EQ(SOFTBUS_OK, TcpPostBytes(g_connectionId, data, sizeof(ConnPktHead) + head.len, 0, 0));
    sleep(1);
    EXPECT_EQ(0, TcpGetConnNum());
    EXPECT_EQ(SOFTBUS_OK, TcpStopListening(&info));
    EXPECT_EQ(0, TcpGetConnNum());
}
}