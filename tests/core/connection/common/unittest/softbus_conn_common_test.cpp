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
#include <sys/epoll.h>

#include <pthread.h>
#include <securec.h>

#include "common_list.h"
#include "softbus_adapter_mock.h"
#include "softbus_base_listener.h"
#include "softbus_conn_common.h"
#include "softbus_conn_manager.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"
#include "softbus_tcp_socket.h"
#include "softbus_watch_event_interface.h"

using namespace testing::ext;
using namespace testing;

static const int32_t INVALID_FD = -1;
static const int32_t TEST_FD = 1;
static pthread_mutex_t g_isInitedLock;
static int32_t g_count = 0;
static int32_t g_port = 6666;

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

int32_t ThreadPoolTask(void* arg)
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
    int32_t i;
    int32_t port = 6666;
    SoftbusBaseListener *setListener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(setListener != nullptr);
    setListener->onConnectEvent = ConnectEvent;
    setListener->onDataEvent = DataEvent;

    SoftbusAdapterMock mock;
    EXPECT_CALL(mock, SoftBusSocketSetOpt).WillRepeatedly(Return(SOFTBUS_ADAPTER_OK));
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
    int32_t module;
    int32_t triggerType;
    int32_t fd = 1;
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
    int32_t module;
    int32_t triggerType;
    int32_t fd = 1;
    for (module = PROXY; module < LISTENER_MODULE_DYNAMIC_START; module++) {
        for (triggerType = READ_TRIGGER; triggerType <= RW_TRIGGER; triggerType++) {
            EXPECT_EQ(SOFTBUS_CONN_FAIL, AddTrigger(static_cast<ListenerModule>(module),
                fd, static_cast<TriggerType>(triggerType)));
            EXPECT_EQ(SOFTBUS_NOT_FIND, DelTrigger(static_cast<ListenerModule>(module),
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
    int32_t module;
    int32_t triggerType;
    int32_t fd = 1;
    int32_t port = 6666;
    SoftbusBaseListener* listener = (SoftbusBaseListener*)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener != nullptr);
    listener->onConnectEvent = ConnectEvent;
    listener->onDataEvent = DataEvent;
    
    SoftbusAdapterMock mock;
    EXPECT_CALL(mock, SoftBusSocketSetOpt).WillRepeatedly(Return(SOFTBUS_ADAPTER_OK));
    for (module = PROXY; module < LISTENER_MODULE_DYNAMIC_START; module++) {
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
            EXPECT_EQ(SOFTBUS_NOT_FIND, DelTrigger(static_cast<ListenerModule>(module),
                fd, static_cast<TriggerType>(triggerType)));
        }
        EXPECT_EQ(SOFTBUS_OK, StopBaseListener(static_cast<ListenerModule>(module)));
        ++port;
    }
    free(listener);
};

/*
* @tc.name: testBaseListener009
* @tc.desc: test add del trigger
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusConnCommonTest, testBaseListener009, TestSize.Level1)
{
    int32_t module;
    int32_t triggerType;
    int32_t port = 6666;
    SoftbusBaseListener* listener = (SoftbusBaseListener*)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener != nullptr);
    listener->onConnectEvent = ConnectEvent;
    listener->onDataEvent = DataEvent;
    
    SoftbusAdapterMock mock;
    EXPECT_CALL(mock, SoftBusSocketSetOpt).WillRepeatedly(Return(SOFTBUS_ADAPTER_OK));
 
    int32_t fdArray[1024] = {0};
    for (int32_t index = 0; index < 1024; index++) {
        fdArray[index] = epoll_create(0);
    }
    for (module = PROXY; module < LISTENER_MODULE_DYNAMIC_START; module++) {
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
                fdArray[1023], static_cast<TriggerType>(triggerType)));
            EXPECT_EQ(SOFTBUS_OK, AddTrigger(static_cast<ListenerModule>(module),
                fdArray[1023], static_cast<TriggerType>(triggerType)));
            EXPECT_EQ(SOFTBUS_OK, DelTrigger(static_cast<ListenerModule>(module),
                fdArray[1023], static_cast<TriggerType>(triggerType)));
            EXPECT_EQ(SOFTBUS_NOT_FIND, DelTrigger(static_cast<ListenerModule>(module),
                fdArray[1023], static_cast<TriggerType>(triggerType)));
        }
        EXPECT_EQ(SOFTBUS_OK, StopBaseListener(static_cast<ListenerModule>(module)));
        ++port;
    }
    
    for (int32_t index = 0; index < 1024; index++) {
        SoftBusSocketClose(fdArray[index]);
    }
    free(listener);
};

/*
* @tc.name: testBaseListener010
* @tc.desc: test GetSoftbusBaseListener and set
* @tc.type: FUNC
* @tc.require: I5HSOL
*/
HWTEST_F(SoftbusConnCommonTest, testBaseListener010, TestSize.Level1)
{
    int32_t i;
    int32_t port = 6666;
    SoftbusBaseListener *setListener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(setListener != nullptr);
    setListener->onConnectEvent = ConnectEvent;
    setListener->onDataEvent = DataEvent;
    
    SoftbusAdapterMock mock;
    EXPECT_CALL(mock, SoftBusSocketSetOpt).WillRepeatedly(Return(SOFTBUS_ADAPTER_OK));
    for (i = PROXY; i < LISTENER_MODULE_DYNAMIC_START; i++) {
        LocalListenerInfo info = {
            .type = CONNECT_TCP,
            .socketOption = {
                .addr = "::1%lo",
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
 * @tc.name: testBaseListener021
 * @tc.desc: Test StartBaseListener invalid input param const char *ip.
 */
HWTEST_F(SoftbusConnCommonTest, testBaseListener021, TestSize.Level1)
{
    SoftbusBaseListener* listener = (SoftbusBaseListener*)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener != nullptr);
    listener->onConnectEvent = ConnectEvent;
    listener->onDataEvent = DataEvent;
 
    int32_t i;
    int32_t port = 6666;
    for (i = PROXY; i < LISTENER_MODULE_DYNAMIC_START; i++) {
        LocalListenerInfo info = {
            .type = CONNECT_TCP,
            .socketOption = {
                .addr = "::1%lo",
                .port = port,
                .moduleId = static_cast<ListenerModule>(i),
                .protocol = LNN_PROTOCOL_IP
            }
        };
        EXPECT_EQ(SOFTBUS_OK, StartBaseClient(static_cast<ListenerModule>(i), listener));
        EXPECT_EQ(SOFTBUS_CONN_LISTENER_NOT_IDLE, StartBaseListener(&info, listener));
        ASSERT_EQ(SOFTBUS_OK, StopBaseListener(static_cast<ListenerModule>(i)));
        port++;
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
    int32_t i;
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
    int32_t i;
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

    SoftbusAdapterMock mock;
    EXPECT_CALL(mock, SoftBusSocketSetOpt).WillRepeatedly(Return(SOFTBUS_ADAPTER_OK));
    int32_t fd = tcp->OpenServerSocket(&info);
    int32_t ret = (fd <= 0) ? SOFTBUS_INVALID_PARAM : SOFTBUS_OK;
    ASSERT_TRUE(ret == SOFTBUS_OK);
    int32_t port = tcp->GetSockPort(fd);
    EXPECT_EQ(port, g_port);
    ConnCloseSocket(fd);

    fd = tcp->OpenServerSocket(nullptr);
    ret = (fd <= 0) ? SOFTBUS_INVALID_PARAM : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ConnCloseSocket(fd);

    info.socketOption.port = -1;
    fd = tcp->OpenServerSocket(&info);
    ret = (fd <= 0) ? SOFTBUS_INVALID_PARAM : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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

    SoftbusAdapterMock mock;
    EXPECT_CALL(mock, SoftBusSocketSetOpt).WillRepeatedly(Return(SOFTBUS_ADAPTER_OK));
    int32_t fd = tcp->OpenClientSocket(nullptr, "127.0.0.1", false);
    int32_t ret = (fd < 0) ? SOFTBUS_INVALID_PARAM : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ConnCloseSocket(fd);
    fd = tcp->OpenClientSocket(nullptr, nullptr, false);
    ret = (fd < 0) ? SOFTBUS_INVALID_PARAM : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ConnCloseSocket(fd);

    option.socketOption.port = -1;
    fd = tcp->OpenClientSocket(&option, "127.0.0.1", false);
    ret = (fd < 0) ? SOFTBUS_INVALID_PARAM : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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
    int32_t invalidFd = 1;
    int32_t port = tcp->GetSockPort(invalidFd);
    int32_t ret = (port <= 0) ? SOFTBUS_INVALID_PARAM : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
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

    SoftbusAdapterMock mock;
    EXPECT_CALL(mock, SoftBusSocketSetOpt).WillRepeatedly(Return(SOFTBUS_ADAPTER_OK));
    int32_t clientFd = tcp->OpenClientSocket(nullptr, "127.5.0.1", false);
    int32_t ret = (clientFd < 0) ? SOFTBUS_INVALID_PARAM : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ssize_t bytes = ConnSendSocketData(clientFd, "Hello world", 11, 0);
    EXPECT_EQ(bytes, -1);
    ConnShutdownSocket(clientFd);
};

/*
* @tc.name: testTcpSocket005
* @tc.desc: test OpenTcpServerSocket
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusConnCommonTest, testTcpSocket006, TestSize.Level1)
{
    const SocketInterface *tcp = GetTcpProtocol();
    ASSERT_NE(tcp, nullptr);

    LocalListenerInfo info = {
        .type = CONNECT_TCP,
        .socketOption = {
            .addr = "::1%lo",
            .port = g_port,
            .moduleId = DIRECT_CHANNEL_SERVER_WIFI,
            .protocol = LNN_PROTOCOL_IP
        }
    };

    SoftbusAdapterMock mock;
    EXPECT_CALL(mock, SoftBusSocketSetOpt).WillRepeatedly(Return(SOFTBUS_ADAPTER_OK));
    int32_t fd = tcp->OpenServerSocket(&info);
    int32_t ret = (fd <= 0) ? SOFTBUS_INVALID_PARAM : SOFTBUS_OK;
    ASSERT_TRUE(ret == SOFTBUS_OK);
    int32_t port = tcp->GetSockPort(fd);
    EXPECT_EQ(port, g_port);
    ConnCloseSocket(fd);

    fd = tcp->OpenServerSocket(nullptr);
    ret = (fd <= 0) ? SOFTBUS_INVALID_PARAM : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ConnCloseSocket(fd);

    info.socketOption.port = -1;
    fd = tcp->OpenServerSocket(&info);
    ret = (fd <= 0) ? SOFTBUS_INVALID_PARAM : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ConnCloseSocket(fd);
};

/*
* @tc.name: testSocket001
* @tc.desc: test ConnGetLocalSocketPort port
* @tc.type: FUNC
* @tc.require: I5PC1B
*/
HWTEST_F(SoftbusConnCommonTest, testSocket001, TestSize.Level1)
{
    int32_t ret;
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
    int32_t ret;

    ret = ConnGetPeerSocketAddr(TEST_FD, NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    SoftbusAdapterMock mock;
    EXPECT_CALL(mock, SoftBusSocketGetPeerName).WillRepeatedly(Return(SOFTBUS_ADAPTER_ERR));
    ret = ConnGetPeerSocketAddr(INVALID_FD, &g_socketAddr);
    EXPECT_EQ(SOFTBUS_TCP_SOCKET_ERR, ret);

    ret = ConnGetPeerSocketAddr(TEST_FD, &g_socketAddr);
    EXPECT_EQ(SOFTBUS_TCP_SOCKET_ERR, ret);
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
    uint32_t millSec = 1;

    SoftbusAdapterMock mock;
    EXPECT_CALL(mock, SoftBusSocketSetOpt).WillRepeatedly(Return(SOFTBUS_ADAPTER_OK));
    int32_t ret = ConnSetTcpUserTimeOut(fd, millSec);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);
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
    uint32_t millSec = 321;

    SoftbusAdapterMock mock;
    EXPECT_CALL(mock, SoftBusSocketSetOpt).WillRepeatedly(Return(SOFTBUS_ADAPTER_ERR));
    int32_t ret = ConnSetTcpUserTimeOut(fd, millSec);
    EXPECT_EQ(SOFTBUS_ADAPTER_ERR, ret);
}

/*
* @tc.name: testSocket003
* @tc.desc: test ConnGetPeerSocketAddr param is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusConnCommonTest, testSocket003, TestSize.Level1)
{
    int32_t ret;
    SocketAddr socketAddr;
    SoftbusAdapterMock mock;
    EXPECT_CALL(mock, SoftBusSocketGetPeerName).WillOnce(Return(SOFTBUS_ADAPTER_ERR));
    ret = ConnGetPeerSocketAddr(INVALID_FD, &socketAddr);
    EXPECT_EQ(SOFTBUS_TCP_SOCKET_ERR, ret);
}

/*
* @tc.name: testSocket004
* @tc.desc: test ConnGetLocalSocketPort port
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusConnCommonTest, testSocket004, TestSize.Level1)
{
    int32_t ret;
    ret = ConnGetLocalSocketPort(INVALID_FD);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
* @tc.name: testConnPreAssignPort001
* @tc.desc: test ConnPreAssignPort SoftBusSocketCreate is failed
* @tc.type: FUNC
* @tc.require: I5PC1B
*/
HWTEST_F(SoftbusConnCommonTest, testConnPreAssignPort001, TestSize.Level1)
{
    int32_t ret;
    ret = ConnPreAssignPort(-1);
    EXPECT_EQ(SOFTBUS_TCPCONNECTION_SOCKET_ERR, ret);

    SoftbusAdapterMock mock;

    EXPECT_CALL(mock, SoftBusSocketSetOpt).WillOnce(Return(SOFTBUS_ADAPTER_OK));
    ret = ConnPreAssignPort(SOFTBUS_AF_INET);

    EXPECT_CALL(mock, SoftBusSocketSetOpt).WillOnce(Return(SOFTBUS_ADAPTER_OK));
    ret = ConnPreAssignPort(SOFTBUS_AF_INET6);

    EXPECT_CALL(mock, SoftBusSocketSetOpt).WillOnce(Return(SOFTBUS_ADAPTER_ERR));
    ret = ConnPreAssignPort(SOFTBUS_AF_INET);
    EXPECT_EQ(SOFTBUS_TCPCONNECTION_SOCKET_ERR, ret);
};

/*
* @tc.name: ConnGetPeerSocketAddr001
* @tc.desc: test ConnGetPeerSocketAddr is SUCC
* @tc.type: FUNC
* @tc.require: I5PC1B
*/
HWTEST_F(SoftbusConnCommonTest, ConnGetPeerSocketAddr001, TestSize.Level1)
{
    int32_t ret;
    SoftbusAdapterMock mock;
    EXPECT_CALL(mock, SoftBusSocketGetPeerName).WillOnce(Return(SOFTBUS_ADAPTER_OK))
        .WillRepeatedly(SoftbusAdapterMock::ActionOfSoftBusSocketGetPeerName);
    ret = ConnGetPeerSocketAddr(TEST_FD, &g_socketAddr);
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = ConnGetPeerSocketAddr(TEST_FD, &g_socketAddr);
    EXPECT_EQ(SOFTBUS_OK, ret);
};

/*
* @tc.name: WaitQueueLength001
* @tc.desc: test WaitQueueLength001 is failed
* @tc.type: FUNC
* @tc.require: I5PC1B
*/
HWTEST_F(SoftbusConnCommonTest, WaitQueueLength001, TestSize.Level1)
{
    int32_t ret;
    uint32_t unitNum = 1;
    LockFreeQueue *lockFreeQueue = CreateQueue(unitNum);
    SoftbusAdapterMock mock;
    SoftBusCond *cond = { 0 };
    SoftBusMutex *mutex = { 0 };

    EXPECT_CALL(mock, SoftBusGetTime).WillOnce(Return(SOFTBUS_OK)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    EXPECT_CALL(mock, SoftBusCondWait).WillOnce(Return(SOFTBUS_OK)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    ret = WaitQueueLength(lockFreeQueue, 0, 0, cond, mutex);
    EXPECT_EQ(SOFTBUS_CONN_COND_WAIT_FAIL, ret);
};

/*
* @tc.name: SoftbusListenerNodeOp001
* @tc.desc: test SoftbusListenerNodeOp001 DestroyBaseListener
* @tc.type: FUNC
* @tc.require: I5PC1B
*/
HWTEST_F(SoftbusConnCommonTest, SoftbusListenerNodeOp001, TestSize.Level1)
{
    int32_t ret;
    ListenerModule module = LISTENER_MODULE_DYNAMIC_START;
    CreateListenerModule();
    ret = IsListenerNodeExist(module);
    EXPECT_EQ(true, ret);

    DeinitBaseListener();
    ret = IsListenerNodeExist(module);
    EXPECT_EQ(false, ret);
};

static int32_t OnGetAllFdEvent(ListNode *list)
{
    return SOFTBUS_OK;
}

/*
* @tc.name: AddEvent001
* @tc.desc: test AddEvent001 param is error
* @tc.type: FUNC
* @tc.require: I5PC1B
*/
HWTEST_F(SoftbusConnCommonTest, AddEvent001, TestSize.Level1)
{
    int32_t fd = -1;
    int32_t ret = AddEvent(NULL, fd, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
 
    EventWatcher watcher = {0};
    watcher.watcherId = -1;
 
    ret = AddEvent(&watcher, fd, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
};

/*
* @tc.name: AddEvent002
* @tc.desc: test AddEvent002 param is error
* @tc.type: FUNC
* @tc.require: I5PC1B
*/
HWTEST_F(SoftbusConnCommonTest, AddEvent002, TestSize.Level1)
{
    int32_t fd = 1;
    EventWatcher *watcher = RegisterEventWatcher(OnGetAllFdEvent);
 
    int32_t ret = AddEvent(watcher, fd, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
 
    ret = AddEvent(watcher, -1, READ_TRIGGER);
    EXPECT_TRUE(ret < 0);

    CloseEventWatcher(watcher);
};
 
/*
* @tc.name: ModifyEvent001
* @tc.desc: test ModifyEvent001  param is error
* @tc.type: FUNC
* @tc.require: I5PC1B
*/
HWTEST_F(SoftbusConnCommonTest, ModifyEvent001, TestSize.Level1)
{
    int32_t fd = -1;
 
    int32_t ret = ModifyEvent(NULL, fd, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
 
    EventWatcher watcher = {0};
    watcher.watcherId = -1;
    ret = ModifyEvent(&watcher, fd, EXCEPT_TRIGGER);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
};

/*
* @tc.name: ModifyEvent002
* @tc.desc: test ModifyEvent002 param is error
* @tc.type: FUNC
* @tc.require: I5PC1B
*/
HWTEST_F(SoftbusConnCommonTest, ModifyEvent002, TestSize.Level1)
{
    int32_t fd = 1;
    EventWatcher *watcher = RegisterEventWatcher(OnGetAllFdEvent);
 
    AddEvent(watcher, fd, READ_TRIGGER);
    int32_t ret = ModifyEvent(watcher, fd, WRITE_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
 
    ret = ModifyEvent(watcher, -1, READ_TRIGGER);
    EXPECT_TRUE(ret < 0);

    CloseEventWatcher(watcher);
};
 
/*
* @tc.name: RemoveEvent001
* @tc.desc: test RemoveEvent001  param is error
* @tc.type: FUNC
* @tc.require: I5PC1B
*/
HWTEST_F(SoftbusConnCommonTest, RemoveEvent001, TestSize.Level1)
{
    int32_t fd = -1;
 
    int32_t ret = RemoveEvent(NULL, fd);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
 
    EventWatcher watcher = {0};
    watcher.watcherId = -1;
    ret = RemoveEvent(&watcher, fd);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
};

/*
* @tc.name: RemoveEvent002
* @tc.desc: test RemoveEvent002 param is error
* @tc.type: FUNC
* @tc.require: I5PC1B
*/
HWTEST_F(SoftbusConnCommonTest, RemoveEvent002, TestSize.Level1)
{
    int32_t fd = 1;
    EventWatcher *watcher = RegisterEventWatcher(OnGetAllFdEvent);
 
    AddEvent(watcher, fd, READ_TRIGGER);
    int32_t ret = RemoveEvent(watcher, fd);
    EXPECT_EQ(SOFTBUS_OK, ret);
 
    ret = RemoveEvent(watcher, -1);
    EXPECT_TRUE(ret < 0);

    CloseEventWatcher(watcher);
};
 
/*
* @tc.name: WatchEvent001
* @tc.desc: test WatchEvent001 param is error
* @tc.type: FUNC
* @tc.require: I5PC1B
*/
HWTEST_F(SoftbusConnCommonTest, WatchEvent001, TestSize.Level1)
{
    ListNode fdEventNode;
    ListInit(&fdEventNode);
 
    int32_t ret = WatchEvent(NULL, -1, &fdEventNode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
 
    EventWatcher watcher = {0};
    watcher.watcherId = -1;
    ret = WatchEvent(&watcher, -1, &fdEventNode);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    watcher.watcherId = 1;
    ret = WatchEvent(&watcher, -1, &fdEventNode);
    EXPECT_TRUE(ret < 0);
};
}
