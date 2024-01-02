/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <pthread.h>
#include <securec.h>

#include "common_list.h"
#include "softbus_base_listener.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_tcp_socket.h"
#include "softbus_utils.h"
#include "softbus_conn_manager.h"

using namespace testing::ext;

static const int INVALID_FD = -1;
static const int TEST_FD = 1;
static pthread_mutex_t g_isInitedLock;
static int g_count = 0;
static int g_port = 6666;

namespace OHOS {
class SoftbusConnCommonTest : public testing::Test {
public:
    SoftbusConnCommonTest()
    {}
    ~SoftbusConnCommonTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

int ThreadPoolTask(void* arg)
{
    pthread_mutex_lock(&g_isInitedLock);
    g_count++;
    pthread_mutex_unlock(&g_isInitedLock);
    return SOFTBUS_OK;
}

void SoftbusConnCommonTest::SetUpTestCase(void)
{
    pthread_mutex_init(&g_isInitedLock, nullptr);
    GTEST_LOG_(INFO) << "SoftbusConnCommonTestSetUp";
    ConnServerInit();
}

void SoftbusConnCommonTest::TearDownTestCase(void)
{
    g_count = 0;
    g_port++;
    GTEST_LOG_(INFO) << "+-------------------------------------------+";
}

void SoftbusConnCommonTest::SetUp(void)
{
    g_count = 0;
}

void SoftbusConnCommonTest::TearDown(void)
{
    g_count = 0;
}

int32_t ConnectEvent(ListenerModule module, int32_t cfd, const ConnectOption *clientAddr)
{
    return 0;
}

int32_t DataEvent(ListenerModule module, int32_t events, int32_t fd)
{
    return 0;
}

SocketAddr g_socketAddr = {
    .addr = "127.0.0.1",
    .port = g_port,
};

/*
* @tc.name: testBaseListener002
* @tc.desc: test GetSoftbusBaseListener and set
* @tc.type: FUNC
* @tc.require: I5HSOL
*/
HWTEST_F(SoftbusConnCommonTest, testBaseListener002, TestSize.Level1)
{
    int i;
    int port = 6666;
    SoftbusBaseListener *setListener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(setListener != nullptr);
    setListener->onConnectEvent = ConnectEvent;
    setListener->onDataEvent = DataEvent;
    for (i = PROXY; i < LISTENER_MODULE_DYNAMIC_START; i++) {
        LocalListenerInfo info = {
            .type = CONNECT_TCP,
            .socketOption = {
                .addr = "127.0.0.1",
                .port = port,
                .moduleId = static_cast<ListenerModule>(i),
                .protocol = LNN_PROTOCOL_IP
            }
        };
        EXPECT_EQ(port, StartBaseListener(&info, setListener));
        ASSERT_EQ(SOFTBUS_OK, StopBaseListener(static_cast<ListenerModule>(i)));
        ++port;
    }
    free(setListener);
};

/*
* @tc.name: testBaseListener006
* @tc.desc: test Invalid trigger param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusConnCommonTest, testBaseListener006, TestSize.Level1)
{
    int module;
    int triggerType;
    int fd = 1;
    for (triggerType = READ_TRIGGER; triggerType <= RW_TRIGGER; triggerType++) {
        EXPECT_EQ(SOFTBUS_INVALID_PARAM, AddTrigger(UNUSE_BUTT, fd, static_cast<TriggerType>(triggerType)));
        EXPECT_EQ(SOFTBUS_INVALID_PARAM, DelTrigger(UNUSE_BUTT, fd, static_cast<TriggerType>(triggerType)));
    }
    for (module = PROXY; module < LISTENER_MODULE_DYNAMIC_START; module++) {
        for (triggerType = READ_TRIGGER; triggerType <= RW_TRIGGER; triggerType++) {
            EXPECT_EQ(SOFTBUS_INVALID_PARAM, AddTrigger(static_cast<ListenerModule>(module), INVALID_FD,
                static_cast<TriggerType>(triggerType)));
            EXPECT_EQ(SOFTBUS_INVALID_PARAM, DelTrigger(static_cast<ListenerModule>(module), INVALID_FD,
                static_cast<TriggerType>(triggerType)));
        }
    }
};

/*
* @tc.name: testBaseListener007
* @tc.desc: test Not set baselistener
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusConnCommonTest, testBaseListener007, TestSize.Level1)
{
    int module;
    int triggerType;
    int fd = 1;
    for (module = PROXY; module < LISTENER_MODULE_DYNAMIC_START; module++) {
        for (triggerType = READ_TRIGGER; triggerType <= RW_TRIGGER; triggerType++) {
            EXPECT_EQ(SOFTBUS_ERR, AddTrigger(static_cast<ListenerModule>(module),
                fd, static_cast<TriggerType>(triggerType)));
            EXPECT_EQ(SOFTBUS_OK, DelTrigger(static_cast<ListenerModule>(module),
                fd, static_cast<TriggerType>(triggerType)));
        }
    }
};

/*
* @tc.name: testBaseListener008
* @tc.desc: test add del trigger
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusConnCommonTest, testBaseListener008, TestSize.Level1)
{
    int module;
    int triggerType;
    int fd = 1;
    int port = 6666;

    for (module = PROXY; module < LISTENER_MODULE_DYNAMIC_START; module++) {
        SoftbusBaseListener* listener = (SoftbusBaseListener*)malloc(sizeof(SoftbusBaseListener));
        ASSERT_TRUE(listener != nullptr);
        listener->onConnectEvent = ConnectEvent;
        listener->onDataEvent = DataEvent;

        LocalListenerInfo info = {
            .type = CONNECT_TCP,
            .socketOption = {.addr = "127.0.0.1",
                             .port = port,
                             .moduleId = static_cast<ListenerModule>(module),
                             .protocol = LNN_PROTOCOL_IP}
        };
        EXPECT_EQ(port, StartBaseListener(&info, listener));
        for (triggerType = READ_TRIGGER; triggerType <= RW_TRIGGER; triggerType++) {
            EXPECT_EQ(SOFTBUS_OK, AddTrigger(static_cast<ListenerModule>(module),
                fd, static_cast<TriggerType>(triggerType)));
            EXPECT_EQ(SOFTBUS_OK, AddTrigger(static_cast<ListenerModule>(module),
                fd, static_cast<TriggerType>(triggerType)));
            EXPECT_EQ(SOFTBUS_OK, DelTrigger(static_cast<ListenerModule>(module),
                fd, static_cast<TriggerType>(triggerType)));
            EXPECT_EQ(SOFTBUS_OK, DelTrigger(static_cast<ListenerModule>(module),
                fd, static_cast<TriggerType>(triggerType)));
        }
        EXPECT_EQ(SOFTBUS_OK, StopBaseListener(static_cast<ListenerModule>(module)));
        free(listener);
    }
};

/*
 * @tc.name: testBaseListener016
 * @tc.desc: Test StartBaseClient invalid input param ListenerModule module.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StartBaseClient operates normally.
 */
HWTEST_F(SoftbusConnCommonTest, testBaseListener016, TestSize.Level1)
{
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, StartBaseClient(static_cast<ListenerModule>(PROXY - 1), NULL));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM,
        StartBaseClient(static_cast<ListenerModule>(DIRECT_CHANNEL_SERVER_WIFI + 1), NULL));
};

/*
 * @tc.name: testBaseListener017
 * @tc.desc: Test StartBaseClient, BaseListener not set, start failed.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StartBaseClient operates normally.
 */
HWTEST_F(SoftbusConnCommonTest, testBaseListener017, TestSize.Level1)
{
    SoftbusBaseListener* listener = (SoftbusBaseListener*)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener != nullptr);
    listener->onConnectEvent = ConnectEvent;
    listener->onDataEvent = DataEvent;
    int i;
    for (i = PROXY; i < LISTENER_MODULE_DYNAMIC_START; i++) {
        EXPECT_EQ(SOFTBUS_OK, StartBaseClient(static_cast<ListenerModule>(i), listener));
    }
    free(listener);
};

/*
 * @tc.name: testBaseListener021
 * @tc.desc: Test StartBaseListener invalid input param const char *ip.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StartBaseListener operates normally.
 */
HWTEST_F(SoftbusConnCommonTest, testBaseListener021, TestSize.Level1)
{
    SoftbusBaseListener* listener = (SoftbusBaseListener*)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener != nullptr);
    listener->onConnectEvent = ConnectEvent;
    listener->onDataEvent = DataEvent;
    LocalListenerInfo info = {
        .type = CONNECT_TCP,
        .socketOption = {.addr = "",
                         .port = 666,
                         .moduleId = PROXY,
                         .protocol = LNN_PROTOCOL_IP}
    };
    int i;
    for (i = PROXY; i < LISTENER_MODULE_DYNAMIC_START; i++) {
        info.socketOption.moduleId = static_cast<ListenerModule>(i);
        EXPECT_EQ(SOFTBUS_ERR, StartBaseListener(&info, listener));
    }
    free(listener);
};

/*
 * @tc.name: testBaseListener022
 * @tc.desc: Test StartBaseListener invalid input param int32_t port < 0.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StartBaseListener operates normally.
 */
HWTEST_F(SoftbusConnCommonTest, testBaseListener022, TestSize.Level1)
{
    SoftbusBaseListener* listener = (SoftbusBaseListener*)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener != nullptr);
    listener->onConnectEvent = ConnectEvent;
    listener->onDataEvent = DataEvent;
    LocalListenerInfo info = {
        .type = CONNECT_TCP,
        .socketOption = {.addr = "127.0.0.1",
                         .port = -1,
                         .moduleId = PROXY,
                         .protocol = LNN_PROTOCOL_IP}
    };
    int i;
    for (i = PROXY; i <= LISTENER_MODULE_DYNAMIC_START; i++) {
        info.socketOption.moduleId = static_cast<ListenerModule>(i);
        EXPECT_EQ(SOFTBUS_INVALID_PARAM, StartBaseListener(&info, listener));
    }
    free(listener);
};

/*
 * @tc.name: testBaseListener026
 * @tc.desc: Test StopBaseListener invalid input param ListenerModule module.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StopBaseListener operates normally.
 */
HWTEST_F(SoftbusConnCommonTest, testBaseListener026, TestSize.Level1)
{
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, StopBaseListener(static_cast<ListenerModule>(PROXY - 1)));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, StopBaseListener(static_cast<ListenerModule>(UNUSE_BUTT)));
};

/*
 * @tc.name: testBaseListener027
 * @tc.desc: Test StopBaseListener failed g_listenerList[module].info = NULL.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StopBaseListener operates normally.
 */
HWTEST_F(SoftbusConnCommonTest, testBaseListener027, TestSize.Level1)
{
    int i;
    for (i = PROXY; i < LISTENER_MODULE_DYNAMIC_START; i++) {
        EXPECT_EQ(SOFTBUS_OK, StopBaseListener(static_cast<ListenerModule>(i)));
    }
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, StopBaseListener(UNUSE_BUTT));
};

/*
* @tc.name: testTcpSocket001
* @tc.desc: test OpenTcpServerSocket
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusConnCommonTest, testTcpSocket001, TestSize.Level1)
{
    const SocketInterface *tcp = GetTcpProtocol();
    ASSERT_NE(tcp, nullptr);

    LocalListenerInfo info = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "127.0.0.1",
            .port = g_port,
            .moduleId = DIRECT_CHANNEL_SERVER_WIFI,
            .protocol = LNN_PROTOCOL_IP
        }
    };

    int fd = tcp->OpenServerSocket(&info);
    int ret = (fd <= 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    ASSERT_TRUE(ret == SOFTBUS_OK);
    int port = tcp->GetSockPort(fd);
    EXPECT_EQ(port, g_port);
    ConnCloseSocket(fd);

    fd = tcp->OpenServerSocket(nullptr);
    ret = (fd <= 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ConnCloseSocket(fd);

    info.socketOption.port = -1;
    fd = tcp->OpenServerSocket(&info);
    ret = (fd <= 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ConnCloseSocket(fd);
};

/*
* @tc.name: testTcpSocket002
* @tc.desc: test OpenTcpClientSocket
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusConnCommonTest, testTcpSocket002, TestSize.Level1)
{
    const SocketInterface *tcp = GetTcpProtocol();
    ASSERT_NE(tcp, nullptr);

    ConnectOption option = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "127.0.0.1",
            .port = g_port,
            .moduleId = DIRECT_CHANNEL_SERVER_WIFI,
            .protocol = LNN_PROTOCOL_IP
        }
    };

    int fd = tcp->OpenClientSocket(nullptr, "127.0.0.1", false);
    int ret = (fd < 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ConnCloseSocket(fd);
    fd = tcp->OpenClientSocket(nullptr, nullptr, false);
    ret = (fd < 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ConnCloseSocket(fd);

    option.socketOption.port = -1;
    fd = tcp->OpenClientSocket(&option, "127.0.0.1", false);
    ret = (fd < 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ConnCloseSocket(fd);
};

/*
* @tc.name: testBaseListener003
* @tc.desc: test GetTcpSockPort invalid fd
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusConnCommonTest, testTcpSocket003, TestSize.Level1)
{
    const SocketInterface *tcp = GetTcpProtocol();
    ASSERT_NE(tcp, nullptr);
    int invalidFd = 1;
    int port = tcp->GetSockPort(invalidFd);
    int ret = (port <= 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_ERR);
};

/*
* @tc.name: testTcpSocket004
* @tc.desc: test ConnSendSocketData invalid fd
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusConnCommonTest, testTcpSocket004, TestSize.Level1)
{
    const SocketInterface *tcp = GetTcpProtocol();
    ASSERT_NE(tcp, nullptr);

    int clientFd = tcp->OpenClientSocket(nullptr, "127.5.0.1", false);
    int ret = (clientFd < 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ssize_t bytes = ConnSendSocketData(clientFd, "Hello world", 11, 0);
    EXPECT_EQ(bytes, -1);
    ConnShutdownSocket(clientFd);
};

/*
* @tc.name: testSocket001
* @tc.desc: test ConnGetLocalSocketPort port
* @tc.type: FUNC
* @tc.require: I5PC1B
*/
HWTEST_F(SoftbusConnCommonTest, testSocket001, TestSize.Level1)
{
    int ret;
    ret = ConnGetLocalSocketPort(INVALID_FD);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);

    ret = ConnGetLocalSocketPort(TEST_FD);
    EXPECT_TRUE(ret < 0);
};

/*
* @tc.name: testSocket002
* @tc.desc: test ConnGetPeerSocketAddr param is invalid
* @tc.type: FUNC
* @tc.require: I5PC1B
*/
HWTEST_F(SoftbusConnCommonTest, testSocket002, TestSize.Level1)
{
    int ret;
    ret = ConnGetPeerSocketAddr(INVALID_FD, &g_socketAddr);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    ret = ConnGetPeerSocketAddr(TEST_FD, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = ConnGetPeerSocketAddr(TEST_FD, &g_socketAddr);
    EXPECT_EQ(SOFTBUS_ERR, ret);
};

/*
 * @tc.name: testConnSetTcpUserTimeOut001
 * @tc.desc: Test ConnSetTcpUserTimeOut param is invalid
 * @tc.in: test module, test number,test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The ThreadPoolDestroy operates normally.
 */
HWTEST_F(SoftbusConnCommonTest, testConnSetTcpUserTimeOut001, TestSize.Level1)
{
    int32_t fd = -1;
    uint32_t millSec= 1;
    int ret = ConnSetTcpUserTimeOut(fd, millSec);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: testConnSetTcpUserTimeOut002
 * @tc.desc: Test ConnSetTcpUserTimeOut param is invalid
 * @tc.in: test module, test number,test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The ThreadPoolDestroy operates normally.
 */
HWTEST_F(SoftbusConnCommonTest, testConnSetTcpUserTimeOut002, TestSize.Level1)
{
    int32_t fd = 1;
    uint32_t millSec= 321;
    int ret = ConnSetTcpUserTimeOut(fd, millSec);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
* @tc.name: testSocket003
* @tc.desc: test ConnGetPeerSocketAddr param is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusConnCommonTest, testSocket003, TestSize.Level1)
{
    int ret;
    SocketAddr socketAddr;
    ret = ConnGetPeerSocketAddr(INVALID_FD, &socketAddr);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
* @tc.name: testSocket004
* @tc.desc: test ConnGetLocalSocketPort port
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusConnCommonTest, testSocket004, TestSize.Level1)
{
    int ret;
    ret = ConnGetLocalSocketPort(INVALID_FD);
    EXPECT_NE(SOFTBUS_OK, ret);
}
}
