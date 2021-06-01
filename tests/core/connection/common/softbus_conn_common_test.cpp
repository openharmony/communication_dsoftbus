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

#include <gtest/gtest.h>
#include <pthread.h>

#include "common_list.h"
#include "softbus_base_listener.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_tcp_socket.h"
#include "softbus_thread_pool.h"
#include "softbus_utils.h"

using namespace testing::ext;

static const int INVALID_FD = -1;
static pthread_mutex_t g_isInitedLock;
static int g_count = 0;
static int g_port = 6666;

namespace OHOS {
class SoftbusCommonTest : public testing::Test {
public:
    SoftbusCommonTest()
    {}
    ~SoftbusCommonTest()
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

void SoftbusCommonTest::SetUpTestCase(void)
{
    pthread_mutex_init(&g_isInitedLock, nullptr);
    GTEST_LOG_(INFO) << "SoftbusCommonTestSetUp";
}

void SoftbusCommonTest::TearDownTestCase(void)
{
    g_count = 0;
    g_port++;
    GTEST_LOG_(INFO) << "+-------------------------------------------+";
}

void SoftbusCommonTest::SetUp(void)
{
    g_count = 0;
}

void SoftbusCommonTest::TearDown(void)
{
    g_count = 0;
}

int32_t ConnectEvent(int32_t events, int32_t cfd, const char *ip)
{
    return 0;
}

int32_t DataEvent(int32_t events, int32_t fd)
{
    return 0;
}

/*
* @tc.name: testBaseListener001
* @tc.desc: test GetSoftbusBaseListener invalid input param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusCommonTest, testBaseListener001, TestSize.Level1)
{
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, GetSoftbusBaseListener(PROXY, nullptr));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, GetSoftbusBaseListener(AUTH, nullptr));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, GetSoftbusBaseListener(DIRECT_CHANNEL_SERVER, nullptr));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, GetSoftbusBaseListener(UNUSE_BUTT, nullptr));
};

/*
* @tc.name: testBaseListener002
* @tc.desc: test GetSoftbusBaseListener and set
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusCommonTest, testBaseListener002, TestSize.Level1)
{
    int i;
    for (i = PROXY; i <= UNUSE_BUTT; i++) {
        EXPECT_EQ(SOFTBUS_INVALID_PARAM, SetSoftbusBaseListener(static_cast<ListenerModule>(i), nullptr));
    }
    SoftbusBaseListener *setListener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(setListener != nullptr);
    setListener->onConnectEvent = ConnectEvent;
    setListener->onDataEvent = DataEvent;
    for (i = PROXY; i < UNUSE_BUTT; i++) {
        SoftbusBaseListener *getListener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
        if (getListener == nullptr) {
            free(setListener);
            return;
        }
        EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(i), setListener));
        EXPECT_EQ(SOFTBUS_OK, GetSoftbusBaseListener(static_cast<ListenerModule>(i), getListener));
        EXPECT_EQ(setListener->onConnectEvent, getListener->onConnectEvent);
        EXPECT_EQ(setListener->onDataEvent, getListener->onDataEvent);
        DestroyBaseListener(static_cast<ListenerModule>(i));
        if (getListener != nullptr) {
            free(getListener);
        }
    }
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, SetSoftbusBaseListener(UNUSE_BUTT, setListener));
    free(setListener);
};

/*
* @tc.name: testBaseListener003
* @tc.desc: test start stop listener
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusCommonTest, testBaseListener003, TestSize.Level1)
{
    ListenerModule module = PROXY;
    int port = 6666;
    EXPECT_EQ(SOFTBUS_ERR, StopBaseListener(module));
    SoftbusBaseListener* listener = (SoftbusBaseListener*)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener != nullptr);
    listener->onConnectEvent = ConnectEvent;
    listener->onDataEvent = DataEvent;
    EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(module, listener));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, StartBaseListener(module, nullptr, port, SERVER_MODE));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, StartBaseListener(module, "127.0.0.1", -1, SERVER_MODE));
    EXPECT_EQ(port, StartBaseListener(module, "127.0.0.1", port, SERVER_MODE));
    EXPECT_EQ(SOFTBUS_ERR, StartBaseListener(module, "127.0.0.1", port, SERVER_MODE));
    EXPECT_EQ(SOFTBUS_OK, StopBaseListener(module));
    EXPECT_EQ(SOFTBUS_OK, StopBaseListener(module));
    DestroyBaseListener(module);
    free(listener);
};

/*
* @tc.name: testBaseListener004
* @tc.desc: test start client
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusCommonTest, testBaseListener004, TestSize.Level1)
{
    ListenerModule module = DIRECT_CHANNEL_SERVER;
    EXPECT_EQ(SOFTBUS_ERR, StopBaseListener(module));
    SoftbusBaseListener* listener = (SoftbusBaseListener*)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener != nullptr);
    listener->onConnectEvent = ConnectEvent;
    listener->onDataEvent = DataEvent;
    EXPECT_EQ(SOFTBUS_ERR, StartBaseClient(module));
    EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(module, listener));
    EXPECT_EQ(SOFTBUS_OK, StartBaseClient(module));
    EXPECT_EQ(SOFTBUS_ERR, StartBaseClient(module));
    EXPECT_EQ(SOFTBUS_OK, StopBaseListener(module));
    DestroyBaseListener(module);
    free(listener);
};

/*
* @tc.name: testBaseListener005
* @tc.desc: test set start stop listener
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusCommonTest, testBaseListener005, TestSize.Level1)
{
    int ret;
    int module;
    int port = 6666;
    for (module = PROXY; module < UNUSE_BUTT; module++) {
        SoftbusBaseListener* listener = (SoftbusBaseListener*)malloc(sizeof(SoftbusBaseListener));
        if (listener == nullptr) {
            for (int i = 0; i < module; i++) {
                ret = StopBaseListener(static_cast<ListenerModule>(i));
                EXPECT_EQ(SOFTBUS_OK, ret);
                DestroyBaseListener(static_cast<ListenerModule>(i));
            }
            continue;
        }
        listener->onConnectEvent = ConnectEvent;
        listener->onDataEvent = DataEvent;
        ret = SetSoftbusBaseListener(static_cast<ListenerModule>(module), listener);
        EXPECT_EQ(SOFTBUS_OK, ret);
        ret = StartBaseListener(static_cast<ListenerModule>(module), "127.0.0.1",
            port + static_cast<ListenerModule>(module), SERVER_MODE);
        EXPECT_EQ(port + module, ret);
        free(listener);
    }
    for (module = PROXY; module < UNUSE_BUTT; module++) {
        ret = StopBaseListener(static_cast<ListenerModule>(module));
        EXPECT_EQ(SOFTBUS_OK, ret);
        DestroyBaseListener(static_cast<ListenerModule>(module));
    }
};

/*
* @tc.name: testBaseListener006
* @tc.desc: test Invalid trigger param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusCommonTest, testBaseListener006, TestSize.Level1)
{
    int module;
    int triggerType;
    int fd = 1;
    for (triggerType = READ_TRIGGER; triggerType <= RW_TRIGGER; triggerType++) {
        EXPECT_EQ(SOFTBUS_INVALID_PARAM, AddTrigger(UNUSE_BUTT, fd, static_cast<TriggerType>(triggerType)));
        EXPECT_EQ(SOFTBUS_INVALID_PARAM, DelTrigger(UNUSE_BUTT, fd, static_cast<TriggerType>(triggerType)));
    }
    for (module = PROXY; module < UNUSE_BUTT; module++) {
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
HWTEST_F(SoftbusCommonTest, testBaseListener007, TestSize.Level1)
{
    int module;
    int triggerType;
    int fd = 1;
    for (module = PROXY; module < UNUSE_BUTT; module++) {
        for (triggerType = READ_TRIGGER; triggerType <= RW_TRIGGER; triggerType++) {
            EXPECT_EQ(SOFTBUS_ERR, AddTrigger(static_cast<ListenerModule>(module),
                fd, static_cast<TriggerType>(triggerType)));
            EXPECT_EQ(SOFTBUS_ERR, DelTrigger(static_cast<ListenerModule>(module),
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
HWTEST_F(SoftbusCommonTest, testBaseListener008, TestSize.Level1)
{
    int module;
    int triggerType;
    int fd = 1;
    int port = 6666;

    for (module = PROXY; module < UNUSE_BUTT; module++) {
        SoftbusBaseListener* listener = (SoftbusBaseListener*)malloc(sizeof(SoftbusBaseListener));
        ASSERT_TRUE(listener != nullptr);
        listener->onConnectEvent = ConnectEvent;
        listener->onDataEvent = DataEvent;
        EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(module), listener));
        EXPECT_EQ(port, StartBaseListener(static_cast<ListenerModule>(module), "127.0.0.1", port, SERVER_MODE));
        for (triggerType = READ_TRIGGER; triggerType <= RW_TRIGGER; triggerType++) {
            EXPECT_EQ(SOFTBUS_OK, AddTrigger(static_cast<ListenerModule>(module),
                fd, static_cast<TriggerType>(triggerType)));
            EXPECT_EQ(SOFTBUS_ERR, AddTrigger(static_cast<ListenerModule>(module),
                fd, static_cast<TriggerType>(triggerType)));
            EXPECT_EQ(SOFTBUS_OK, DelTrigger(static_cast<ListenerModule>(module),
                fd, static_cast<TriggerType>(triggerType)));
            EXPECT_EQ(SOFTBUS_OK, DelTrigger(static_cast<ListenerModule>(module),
                fd, static_cast<TriggerType>(triggerType)));
        }
        EXPECT_EQ(SOFTBUS_OK, StopBaseListener(static_cast<ListenerModule>(module)));
        DestroyBaseListener(static_cast<ListenerModule>(module));
        free(listener);
    }
};

/*
* @tc.name: testTcpSocket001
* @tc.desc: test OpenTcpServerSocket
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusCommonTest, testTcpSocket001, TestSize.Level1)
{
    int fd = OpenTcpServerSocket("127.0.0.1", g_port);
    int ret = (fd <= 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_OK);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    int port = GetTcpSockPort(fd);
    EXPECT_EQ(port, g_port);
    CloseTcpFd(fd);

    fd = OpenTcpServerSocket(nullptr, g_port);
    ret = (fd <= 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_ERR);
    CloseTcpFd(fd);
    fd = OpenTcpServerSocket("127.0.0.1", -1);
    ret = (fd <= 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_ERR);
    CloseTcpFd(fd);
};

/*
* @tc.name: testTcpSocket002
* @tc.desc: test OpenTcpClientSocket
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusCommonTest, testTcpSocket002, TestSize.Level1)
{
    int fd = OpenTcpClientSocket("127.0.0.1", "194.0.0.1", g_port);
    int ret = (fd <= 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_ERR);
    int port = GetTcpSockPort(fd);
    EXPECT_EQ(port, -1);
    CloseTcpFd(fd);

    fd = OpenTcpClientSocket(nullptr, "127.0.0.1", g_port);
    ret = (fd <= 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_ERR);
    CloseTcpFd(fd);
    fd = OpenTcpClientSocket("127.0.0.1", nullptr, g_port);
    ret = (fd <= 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_ERR);
    CloseTcpFd(fd);
    fd = OpenTcpClientSocket("127.0.0.1", "127.0.0.1", -1);
    ret = (fd <= 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_ERR);
    CloseTcpFd(fd);
};

/*
* @tc.name: testBaseListener003
* @tc.desc: test GetTcpSockPort invalid fd
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusCommonTest, testTcpSocket003, TestSize.Level1)
{
    int invalidFd = 1;
    int port = GetTcpSockPort(invalidFd);
    int ret = (port <= 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_ERR);
};

/*
* @tc.name: testTcpSocket004
* @tc.desc: test SendTcpData invalid fd
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusCommonTest, testTcpSocket004, TestSize.Level1)
{
    int clientFd = OpenTcpClientSocket("127.0.0.1", "127.5.0.1", g_port);
    int ret = (clientFd <= 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_ERR);
    ssize_t bytes = SendTcpData(clientFd, "Hello world", 11, 0);
    EXPECT_EQ(bytes, -1);
    TcpShutDown(clientFd);
};

/*
* @tc.name: testThreadPool001
* @tc.desc: test ThreadPoolInit invalid input param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusCommonTest, testThreadPool001, TestSize.Level1)
{
    int threadNum = 2;
    int queueMaxNum = 4;
    int invalidNum = 0;

    ThreadPool *pool = ThreadPoolInit(invalidNum, queueMaxNum);
    EXPECT_EQ(nullptr, pool);
    pool = ThreadPoolInit(threadNum, invalidNum);
    EXPECT_EQ(nullptr, pool);
    pool = ThreadPoolInit(threadNum, queueMaxNum);
    EXPECT_EQ(true, pool != nullptr);

    EXPECT_EQ(SOFTBUS_OK, ThreadPoolDestroy(pool));
}

/*
* @tc.name: testThreadPool002
* @tc.desc: test ThreadPoolAddJob and remove with invalid param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusCommonTest, testThreadPool002, TestSize.Level1)
{
    int threadNum = 2;
    int queueMaxNum = 4;

    ThreadPool *pool = ThreadPoolInit(threadNum, queueMaxNum);
    EXPECT_EQ(true, pool != nullptr);

    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ThreadPoolAddJob(nullptr, ThreadPoolTask, nullptr, ONCE, (uintptr_t)0));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ThreadPoolAddJob(nullptr, ThreadPoolTask, nullptr, PERSISTENT, (uintptr_t)0));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ThreadPoolAddJob(pool, nullptr, nullptr, ONCE, (uintptr_t)0));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ThreadPoolAddJob(pool, nullptr, nullptr, PERSISTENT, (uintptr_t)0));

    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ThreadPoolRemoveJob(nullptr, (uintptr_t)0));
    EXPECT_EQ(SOFTBUS_OK, ThreadPoolDestroy(pool));
}

/*
* @tc.name: testThreadPool003
* @tc.desc: test null ThreadPoolDestroy
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusCommonTest, testThreadPool003, TestSize.Level1)
{
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ThreadPoolDestroy(nullptr));
}

/*
* @tc.name: testThreadPool004
* @tc.desc: test ThreadPoolAddJob out of max num
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusCommonTest, testThreadPool004, TestSize.Level1)
{
    int threadNum = 2;
    int queueMaxNum = 4;

    ThreadPool *pool = ThreadPoolInit(threadNum, queueMaxNum);
    int ret = (pool != nullptr) ? SOFTBUS_OK : SOFTBUS_ERR;
    EXPECT_EQ(ret, SOFTBUS_OK);

    for (int i = 0; i < queueMaxNum; i++) {
        ret = ThreadPoolAddJob(pool, ThreadPoolTask, nullptr, PERSISTENT, (uintptr_t)i);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    ret = ThreadPoolAddJob(pool, ThreadPoolTask, nullptr, PERSISTENT, (uintptr_t)queueMaxNum);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    sleep(3);
    ret = (g_count != queueMaxNum) ? SOFTBUS_OK : SOFTBUS_ERR;
    EXPECT_EQ(ret, SOFTBUS_OK);
    for (int i = 0; i < queueMaxNum; i++) {
        ret = ThreadPoolRemoveJob(pool, (uintptr_t)i);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    ret = ThreadPoolRemoveJob(pool, (uintptr_t)queueMaxNum);
    EXPECT_EQ(ret, SOFTBUS_OK);
    if (pool != nullptr) {
        ret = ThreadPoolDestroy(pool);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
};

/*
* @tc.name: testThreadPool005
* @tc.desc: test ThreadPoolAddJob and remove
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftbusCommonTest, testThreadPool005, TestSize.Level1)
{
    int threadNum = 2;
    int queueMaxNum = 4;

    ThreadPool *pool = ThreadPoolInit(threadNum, queueMaxNum);
    int ret = (pool != nullptr) ? SOFTBUS_OK : SOFTBUS_ERR;
    EXPECT_EQ(ret, SOFTBUS_OK);

    for (int i = 0; i < queueMaxNum; i++) {
        ret = ThreadPoolAddJob(pool, ThreadPoolTask, nullptr, ONCE, (uintptr_t)i);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    sleep(3);
    EXPECT_EQ(queueMaxNum, g_count);
    for (int i = 0; i < queueMaxNum; i++) {
        ret = ThreadPoolRemoveJob(pool, (uintptr_t)i);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    if (pool != nullptr) {
        ret = ThreadPoolDestroy(pool);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
};
}
