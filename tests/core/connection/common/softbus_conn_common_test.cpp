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
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, GetSoftbusBaseListener(DIRECT_CHANNEL_SERVER_WIFI, nullptr));
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
    int port = 6666;
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
        ++port;
        EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(i), setListener));
        EXPECT_EQ(port, StartBaseListener(static_cast<ListenerModule>(i), "127.0.0.1", port, SERVER_MODE));
        EXPECT_EQ(SOFTBUS_OK, GetSoftbusBaseListener(static_cast<ListenerModule>(i), getListener));
        EXPECT_EQ(setListener->onConnectEvent, getListener->onConnectEvent);
        EXPECT_EQ(setListener->onDataEvent, getListener->onDataEvent);
        ASSERT_EQ(SOFTBUS_OK, StopBaseListener(static_cast<ListenerModule>(i)));
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
    ListenerModule module = DIRECT_CHANNEL_SERVER_WIFI;
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
            EXPECT_EQ(SOFTBUS_OK, AddTrigger(static_cast<ListenerModule>(module),
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
 * @tc.name: testBaseListener009
 * @tc.desc: Test GetSoftbusBaseListener invalid input param SoftbusBaseListener *listener.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The GetSoftbusBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener009, TestSize.Level1)
{
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, GetSoftbusBaseListener(AUTH_P2P, nullptr));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, GetSoftbusBaseListener(DIRECT_CHANNEL_SERVER_P2P, nullptr));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, GetSoftbusBaseListener(DIRECT_CHANNEL_CLIENT, nullptr));
};

/*
 * @tc.name: testBaseListener010
 * @tc.desc: Test GetSoftbusBaseListener invalid input param ListenerModule module.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The GetSoftbusBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener010, TestSize.Level1)
{
    SoftbusBaseListener *getListener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    if (getListener == nullptr) {
        return;
    }
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, GetSoftbusBaseListener(static_cast<ListenerModule>(UNUSE_BUTT), getListener));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, GetSoftbusBaseListener(static_cast<ListenerModule>(PROXY - 1), getListener));
    if (getListener != nullptr) {
        free(getListener);
    }
};

/*
 * @tc.name: testBaseListener011
 * @tc.desc: Test SetSoftbusBaseListener invalid input param const SoftbusBaseListener *listener.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The GetSoftbusBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener011, TestSize.Level1)
{
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, SetSoftbusBaseListener(AUTH_P2P, nullptr));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, SetSoftbusBaseListener(DIRECT_CHANNEL_SERVER_P2P, nullptr));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, SetSoftbusBaseListener(DIRECT_CHANNEL_CLIENT, nullptr));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, SetSoftbusBaseListener(PROXY, nullptr));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, SetSoftbusBaseListener(AUTH, nullptr));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, SetSoftbusBaseListener(DIRECT_CHANNEL_SERVER_WIFI, nullptr));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, SetSoftbusBaseListener(UNUSE_BUTT, nullptr));
};

/*
 * @tc.name: testBaseListener012
 * @tc.desc: Test SetSoftbusBaseListener invalid input param ListenerModule module.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The SetSoftbusBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener012, TestSize.Level1)
{
    SoftbusBaseListener *setListener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    if (setListener == nullptr) {
        return;
    }
    setListener->onConnectEvent = ConnectEvent;
    setListener->onDataEvent = DataEvent;
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, SetSoftbusBaseListener(static_cast<ListenerModule>(UNUSE_BUTT), setListener));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, SetSoftbusBaseListener(static_cast<ListenerModule>(PROXY - 1), setListener));
    if (setListener != nullptr) {
        free(setListener);
    }
};

/*
 * @tc.name: testBaseListener013
 * @tc.desc: Test setSoftbusBaseListene SOFTBUS_OK.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The SetSoftbusBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener013, TestSize.Level1)
{
    int i;
    SoftbusBaseListener *setListener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(setListener != nullptr);
    setListener->onConnectEvent = ConnectEvent;
    setListener->onDataEvent = DataEvent;
    for (i = PROXY; i < UNUSE_BUTT; i++) {
        EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(i), setListener));
        DestroyBaseListener(static_cast<ListenerModule>(i));
    }
    free(setListener);
};

/*
 * @tc.name: testBaseListener014
 * @tc.desc: Test GetSoftbusBaseListener SOFTBUS_ERR.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The GetSoftbusBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener014, TestSize.Level1)
{
    int i;
    SoftbusBaseListener *getListener = nullptr;
    for (i = PROXY; i < UNUSE_BUTT; i++) {
        getListener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
        if (getListener == nullptr) {
            return;
        }
        EXPECT_EQ(SOFTBUS_ERR, GetSoftbusBaseListener(static_cast<ListenerModule>(i), getListener));
    }
};

/*
 * @tc.name: testBaseListener015
 * @tc.desc: Test SetSoftbusBaseListener SOFTBUS_OK.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The SetSoftbusBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener015, TestSize.Level1)
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
HWTEST_F(SoftbusCommonTest, testBaseListener016, TestSize.Level1)
{
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, StartBaseClient(static_cast<ListenerModule>(PROXY - 1)));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, StartBaseClient(static_cast<ListenerModule>(DIRECT_CHANNEL_SERVER_WIFI + 1)));
};

/*
 * @tc.name: testBaseListener017
 * @tc.desc: Test StartBaseClient, BaseListener not set, start failed.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StartBaseClient operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener017, TestSize.Level1)
{
    int i;
    for (i = PROXY; i < UNUSE_BUTT; i++) {
        EXPECT_EQ(SOFTBUS_ERR, StartBaseClient(static_cast<ListenerModule>(i)));
    }
};

/*
 * @tc.name: testBaseListener018
 * @tc.desc: Test StartBaseClient, BaseListener set, start OK.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The SetSoftbusBaseListener and StartBaseClient operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener018, TestSize.Level1)
{
    int i;
    SoftbusBaseListener *setListener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(setListener != nullptr);
    setListener->onConnectEvent = ConnectEvent;
    setListener->onDataEvent = DataEvent;
    for (i = PROXY; i < UNUSE_BUTT; i++) {
        EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(i), setListener));
        EXPECT_EQ(SOFTBUS_OK, StartBaseClient(static_cast<ListenerModule>(i)));
        EXPECT_EQ(SOFTBUS_ERR, StartBaseClient(static_cast<ListenerModule>(i)));
        DestroyBaseListener(static_cast<ListenerModule>(i));
    }
    free(setListener);
};

/*
 * @tc.name: testBaseListener019
 * @tc.desc: Test StartBaseClient, BaseListener set, start OK.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartBaseClient and SetSoftbusBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener019, TestSize.Level1)
{
    int i;
    SoftbusBaseListener *setListener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(setListener != nullptr);
    setListener->onConnectEvent = ConnectEvent;
    setListener->onDataEvent = DataEvent;
    for (i = PROXY; i < UNUSE_BUTT; i++) {
        EXPECT_EQ(SOFTBUS_ERR, StartBaseClient(static_cast<ListenerModule>(i)));
        EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(i), setListener));
        EXPECT_EQ(SOFTBUS_OK, StartBaseClient(static_cast<ListenerModule>(i)));
        EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(i), setListener));
        EXPECT_EQ(SOFTBUS_ERR, StartBaseClient(static_cast<ListenerModule>(i)));
        DestroyBaseListener(static_cast<ListenerModule>(i));
    }
    free(setListener);
};

/*
 * @tc.name: testBaseListener020
 * @tc.desc: Test StartBaseListener invalid input param ListenerModule module.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StartBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener020, TestSize.Level1)
{
    EXPECT_EQ(SOFTBUS_INVALID_PARAM,
        StartBaseListener(static_cast<ListenerModule>(PROXY - 1), "127.0.0.1", 666, SERVER_MODE));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM,
        StartBaseListener(static_cast<ListenerModule>(UNUSE_BUTT), "127.0.0.1", 666, SERVER_MODE));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM,
        StartBaseListener(static_cast<ListenerModule>(PROXY - 1), "127.0.0.1", 666, CLIENT_MODE));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM,
        StartBaseListener(static_cast<ListenerModule>(UNUSE_BUTT), "127.0.0.1", 666, CLIENT_MODE));
    EXPECT_EQ(
        SOFTBUS_INVALID_PARAM, StartBaseListener(static_cast<ListenerModule>(PROXY - 1), "127.0.0.1", 666, UNSET_MODE));
    EXPECT_EQ(SOFTBUS_INVALID_PARAM,
        StartBaseListener(static_cast<ListenerModule>(UNUSE_BUTT), "127.0.0.1", 666, UNSET_MODE));
};

/*
 * @tc.name: testBaseListener021
 * @tc.desc: Test StartBaseListener invalid input param const char *ip.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StartBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener021, TestSize.Level1)
{
    int i;
    for (i = PROXY; i <= UNUSE_BUTT; i++) {
        EXPECT_EQ(SOFTBUS_INVALID_PARAM, StartBaseListener(static_cast<ListenerModule>(i), nullptr, 666, SERVER_MODE));
        EXPECT_EQ(SOFTBUS_INVALID_PARAM, StartBaseListener(static_cast<ListenerModule>(i), nullptr, 666, CLIENT_MODE));
        EXPECT_EQ(SOFTBUS_INVALID_PARAM, StartBaseListener(static_cast<ListenerModule>(i), nullptr, 666, UNSET_MODE));
    }
};

/*
 * @tc.name: testBaseListener022
 * @tc.desc: Test StartBaseListener invalid input param int32_t port < 0.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StartBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener022, TestSize.Level1)
{
    int i;
    for (i = PROXY; i <= UNUSE_BUTT; i++) {
        EXPECT_EQ(
            SOFTBUS_INVALID_PARAM, StartBaseListener(static_cast<ListenerModule>(i), "127.0.0.1", -1, SERVER_MODE));
        EXPECT_EQ(
            SOFTBUS_INVALID_PARAM, StartBaseListener(static_cast<ListenerModule>(i), "127.0.0.1", -1, CLIENT_MODE));
        EXPECT_EQ(
            SOFTBUS_INVALID_PARAM, StartBaseListener(static_cast<ListenerModule>(i), "127.0.0.1", -1, UNSET_MODE));
    }
};

/*
 * @tc.name: testBaseListener023
 * @tc.desc: Test StartBaseListener, BaseListener not set, start failed.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StartBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener023, TestSize.Level1)
{
    int i;
    for (i = PROXY; i < UNUSE_BUTT; i++) {
        EXPECT_EQ(SOFTBUS_ERR, StartBaseListener(static_cast<ListenerModule>(i), "127.0.0.1", 666, SERVER_MODE));
        EXPECT_EQ(SOFTBUS_ERR, StartBaseListener(static_cast<ListenerModule>(i), "127.0.0.1", 666, CLIENT_MODE));
        EXPECT_EQ(SOFTBUS_ERR, StartBaseListener(static_cast<ListenerModule>(i), "127.0.0.1", 666, UNSET_MODE));
    }
};

/*
 * @tc.name: testBaseListener024
 * @tc.desc: Test StartBaseListener, BaseListener set, start OK.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The SetSoftbusBaseListener and StartBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener024, TestSize.Level1)
{
    int i;
    int port = 6666;
    SoftbusBaseListener *setListener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(setListener != nullptr);
    setListener->onConnectEvent = ConnectEvent;
    setListener->onDataEvent = DataEvent;
    for (i = PROXY; i < UNUSE_BUTT; i++) {
        EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(i), setListener));
        ++port;
        EXPECT_EQ(port, StartBaseListener(static_cast<ListenerModule>(i), "127.0.0.1", port, SERVER_MODE));
        DestroyBaseListener(static_cast<ListenerModule>(i));
    }
    free(setListener);
};

/*
 * @tc.name: testBaseListener025
 * @tc.desc: Test StartBaseListener, BaseListener set, start OK.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The SetSoftbusBaseListener and StartBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener025, TestSize.Level1)
{
    int i;
    int port = 6666;
    SoftbusBaseListener *setListener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(setListener != nullptr);
    setListener->onConnectEvent = ConnectEvent;
    setListener->onDataEvent = DataEvent;
    for (i = PROXY; i < UNUSE_BUTT; i++) {
        ++port;
        SoftbusBaseListener *getListener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
        if (getListener == nullptr) {
            free(setListener);
            return;
        }
        EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(i), setListener));
        EXPECT_EQ(port, StartBaseListener(static_cast<ListenerModule>(i), "127.0.0.1", port, SERVER_MODE));
        EXPECT_EQ(SOFTBUS_ERR, StartBaseListener(static_cast<ListenerModule>(i), "127.0.0.1", port, SERVER_MODE));
        DestroyBaseListener(static_cast<ListenerModule>(i));
        EXPECT_EQ(SOFTBUS_ERR, GetSoftbusBaseListener(static_cast<ListenerModule>(i), getListener));
    }
    free(setListener);
};

/*
 * @tc.name: testBaseListener026
 * @tc.desc: Test StopBaseListener invalid input param ListenerModule module.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StopBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener026, TestSize.Level1)
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
HWTEST_F(SoftbusCommonTest, testBaseListener027, TestSize.Level1)
{
    int i;
    for (i = PROXY; i < UNUSE_BUTT; i++) {
        EXPECT_EQ(SOFTBUS_ERR, StopBaseListener(static_cast<ListenerModule>(i)));
    }
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, StopBaseListener(UNUSE_BUTT));
};

/*
 * @tc.name: testBaseListener028
 * @tc.desc: Test SetSoftbusBaseListener and get StartBaseListener and stop.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The SetSoftbusBaseListener and StopBaseListener and StartBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener028, TestSize.Level1)
{
    int i;
    int port = 6666;
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
        ++port;
        EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(i), setListener));
        EXPECT_EQ(SOFTBUS_OK, GetSoftbusBaseListener(static_cast<ListenerModule>(i), getListener));
        EXPECT_EQ(setListener->onConnectEvent, getListener->onConnectEvent);
        EXPECT_EQ(setListener->onDataEvent, getListener->onDataEvent);
        if (getListener != nullptr) {
            free(getListener);
        }
        EXPECT_EQ(port, StartBaseListener(static_cast<ListenerModule>(i), "127.0.0.1", port, SERVER_MODE));
        EXPECT_EQ(SOFTBUS_OK, StopBaseListener(static_cast<ListenerModule>(i)));
        DestroyBaseListener(static_cast<ListenerModule>(i));
    }
    free(setListener);
};

/*
 * @tc.name: testBaseListener029
 * @tc.desc: Test SetSoftbusBaseListener and get StartBaseListener and stop and startBaseClient.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The SetSoftbusBaseListener and StartBaseClient and StartBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener029, TestSize.Level1)
{
    int i;
    int port = 6666;
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
        ++port;
        EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(i), setListener));
        EXPECT_EQ(SOFTBUS_OK, GetSoftbusBaseListener(static_cast<ListenerModule>(i), getListener));
        EXPECT_EQ(setListener->onConnectEvent, getListener->onConnectEvent);
        EXPECT_EQ(setListener->onDataEvent, getListener->onDataEvent);
        if (getListener != nullptr) {
            free(getListener);
        }
        EXPECT_EQ(SOFTBUS_OK, StartBaseClient(static_cast<ListenerModule>(i)));
        EXPECT_EQ(SOFTBUS_ERR, StartBaseListener(static_cast<ListenerModule>(i), "127.0.0.1", port, SERVER_MODE));
        EXPECT_EQ(SOFTBUS_OK, StopBaseListener(static_cast<ListenerModule>(i)));
        EXPECT_EQ(SOFTBUS_OK, StopBaseListener(static_cast<ListenerModule>(i)));
        DestroyBaseListener(static_cast<ListenerModule>(i));
        EXPECT_EQ(SOFTBUS_ERR, StopBaseListener(static_cast<ListenerModule>(i)));
    }
    free(setListener);
};

/*
 * @tc.name: testBaseListener030
 * @tc.desc: Test AddTrigger DelTrigger invalid triggerType param.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The AddTrigger and DelTrigger operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener030, TestSize.Level1)
{
    int module;
    int fd = 1;
    int port = 6666;

    for (module = PROXY; module < UNUSE_BUTT; module++) {
        SoftbusBaseListener *listener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
        ASSERT_TRUE(listener != nullptr);
        listener->onConnectEvent = ConnectEvent;
        listener->onDataEvent = DataEvent;
        EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(module), listener));
        EXPECT_EQ(port, StartBaseListener(static_cast<ListenerModule>(module), "127.0.0.1", port, SERVER_MODE));

        EXPECT_EQ(SOFTBUS_INVALID_PARAM,
            AddTrigger(static_cast<ListenerModule>(module), fd, static_cast<TriggerType>(READ_TRIGGER - 1)));
        EXPECT_EQ(SOFTBUS_INVALID_PARAM,
            AddTrigger(static_cast<ListenerModule>(module), fd, static_cast<TriggerType>(RW_TRIGGER + 1)));
        EXPECT_EQ(SOFTBUS_INVALID_PARAM,
            DelTrigger(static_cast<ListenerModule>(module), fd, static_cast<TriggerType>(READ_TRIGGER - 1)));
        EXPECT_EQ(SOFTBUS_INVALID_PARAM,
            DelTrigger(static_cast<ListenerModule>(module), fd, static_cast<TriggerType>(RW_TRIGGER + 1)));

        EXPECT_EQ(SOFTBUS_OK, StopBaseListener(static_cast<ListenerModule>(module)));
        DestroyBaseListener(static_cast<ListenerModule>(module));
        free(listener);
    }
};

/*
 * @tc.name: testBaseListener031
 * @tc.desc: Test DestroyBaseListener valid input param.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DestroyBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener031, TestSize.Level1)
{
    int module = PROXY;
    int port = 6666;
    SoftbusBaseListener *listener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener != nullptr);
    listener->onConnectEvent = ConnectEvent;
    listener->onDataEvent = DataEvent;
    EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(module), listener));
    EXPECT_EQ(port, StartBaseListener(static_cast<ListenerModule>(module), "127.0.0.1", port, SERVER_MODE));

    EXPECT_EQ(SOFTBUS_OK, StopBaseListener(static_cast<ListenerModule>(module)));
    DestroyBaseListener(static_cast<ListenerModule>(module));
    EXPECT_EQ(SOFTBUS_ERR, StartBaseListener(static_cast<ListenerModule>(module), "127.0.0.1", port, SERVER_MODE));
    free(listener);
};

/*
 * @tc.name: testBaseListener032
 * @tc.desc: Test DestroyBaseListener empty corresponding module listener.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DestroyBaseListener and StartBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener032, TestSize.Level1)
{
    int port = 6666;

    SoftbusBaseListener *listener1 = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener1 != nullptr);
    listener1->onConnectEvent = ConnectEvent;
    listener1->onDataEvent = DataEvent;
    EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(PROXY, listener1));
    EXPECT_EQ(PROXY + port, StartBaseListener(PROXY, "127.0.0.1", PROXY + port, SERVER_MODE));

    SoftbusBaseListener *listener2 = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener2 != nullptr);
    listener2->onConnectEvent = ConnectEvent;
    listener2->onDataEvent = DataEvent;
    EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(AUTH, listener2));
    EXPECT_EQ(AUTH + port, StartBaseListener(AUTH, "127.0.0.1", AUTH + port, SERVER_MODE));

    EXPECT_EQ(SOFTBUS_OK, StopBaseListener(PROXY));
    EXPECT_EQ(SOFTBUS_OK, StopBaseListener(AUTH));
    DestroyBaseListener(PROXY);
    EXPECT_EQ(SOFTBUS_ERR, StartBaseListener(PROXY, "127.0.0.1", PROXY + port, SERVER_MODE));
    EXPECT_EQ(AUTH + port, StartBaseListener(AUTH, "127.0.0.1", AUTH + port, SERVER_MODE));

    EXPECT_EQ(SOFTBUS_OK, StopBaseListener(AUTH));
    DestroyBaseListener(AUTH);
    EXPECT_EQ(SOFTBUS_ERR, StartBaseListener(AUTH, "127.0.0.1", AUTH + port, SERVER_MODE));
    free(listener1);
    free(listener2);
};

/*
 * @tc.name: testBaseListener033
 * @tc.desc: Test DestroyBaseListener without StopBaseListener.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StartBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener033, TestSize.Level1)
{
    int module = PROXY;
    int port = 6666;

    SoftbusBaseListener *listener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener != nullptr);
    listener->onConnectEvent = ConnectEvent;
    listener->onDataEvent = DataEvent;
    EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(module), listener));
    EXPECT_EQ(port, StartBaseListener(static_cast<ListenerModule>(module), "127.0.0.1", port, SERVER_MODE));

    DestroyBaseListener(static_cast<ListenerModule>(module));
    EXPECT_EQ(SOFTBUS_ERR, StartBaseListener(static_cast<ListenerModule>(module), "127.0.0.1", port, SERVER_MODE));
    free(listener);
};

/*
 * @tc.name: testBaseListener034
 * @tc.desc: Test AddTrigger with empty info.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The AddTrigger operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener034, TestSize.Level1)
{
    int module = PROXY;
    int triggerType = READ_TRIGGER;
    int fd = 1;
    int port = 6666;

    SoftbusBaseListener *listener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener != nullptr);
    listener->onConnectEvent = ConnectEvent;
    listener->onDataEvent = DataEvent;
    EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(module), listener));
    EXPECT_EQ(port, StartBaseListener(static_cast<ListenerModule>(module), "127.0.0.1", port, SERVER_MODE));

    DestroyBaseListener(static_cast<ListenerModule>(module));
    EXPECT_EQ(SOFTBUS_ERR, AddTrigger(static_cast<ListenerModule>(module), fd, static_cast<TriggerType>(triggerType)));
    free(listener);
};

/*
 * @tc.name: testBaseListener035
 * @tc.desc: Test DelTrigger with empty info.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The DelTrigger operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener035, TestSize.Level1)
{
    int module = PROXY;
    int triggerType = READ_TRIGGER;
    int fd = 1;
    int port = 6666;

    SoftbusBaseListener *listener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener != nullptr);
    listener->onConnectEvent = ConnectEvent;
    listener->onDataEvent = DataEvent;
    EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(module), listener));
    EXPECT_EQ(port, StartBaseListener(static_cast<ListenerModule>(module), "127.0.0.1", port, SERVER_MODE));

    DestroyBaseListener(static_cast<ListenerModule>(module));
    EXPECT_EQ(SOFTBUS_ERR, DelTrigger(static_cast<ListenerModule>(module), fd, static_cast<TriggerType>(triggerType)));
    free(listener);
};

/*
 * @tc.name: testBaseListener036
 * @tc.desc: Test StartBaseListener after ResetBaseListener.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StartBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener036, TestSize.Level1)
{
    int module = PROXY;
    int port = 6666;

    SoftbusBaseListener *listener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener != nullptr);
    listener->onConnectEvent = ConnectEvent;
    listener->onDataEvent = DataEvent;
    EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(module), listener));
    EXPECT_EQ(port, StartBaseListener(static_cast<ListenerModule>(module), "127.0.0.1", port, SERVER_MODE));

    ResetBaseListener(static_cast<ListenerModule>(module));
    EXPECT_EQ(port, StartBaseListener(static_cast<ListenerModule>(module), "127.0.0.1", port, SERVER_MODE));

    EXPECT_EQ(SOFTBUS_OK, StopBaseListener(static_cast<ListenerModule>(module)));
    DestroyBaseListener(static_cast<ListenerModule>(module));
    free(listener);
};

/*
 * @tc.name: testBaseListener037
 * @tc.desc: Test StopBaseListener after ResetBaseListener.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StopBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener037, TestSize.Level1)
{
    int module = PROXY;
    int port = 6666;

    SoftbusBaseListener *listener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener != nullptr);
    listener->onConnectEvent = ConnectEvent;
    listener->onDataEvent = DataEvent;
    EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(module), listener));
    EXPECT_EQ(port, StartBaseListener(static_cast<ListenerModule>(module), "127.0.0.1", port, SERVER_MODE));

    ResetBaseListener(static_cast<ListenerModule>(module));
    EXPECT_EQ(SOFTBUS_OK, StopBaseListener(static_cast<ListenerModule>(module)));

    DestroyBaseListener(static_cast<ListenerModule>(module));
    free(listener);
};

/*
 * @tc.name: testBaseListener038
 * @tc.desc: Test AddTrigger DelTrigger after ResetBaseListener.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The AddTrigger and DelTrigger operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener038, TestSize.Level1)
{
    int module = PROXY;
    int triggerType = READ_TRIGGER;
    int fd = 1;
    int port = 6666;

    SoftbusBaseListener *listener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener != nullptr);
    listener->onConnectEvent = ConnectEvent;
    listener->onDataEvent = DataEvent;
    EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(module), listener));
    EXPECT_EQ(port, StartBaseListener(static_cast<ListenerModule>(module), "127.0.0.1", port, SERVER_MODE));

    ResetBaseListener(static_cast<ListenerModule>(module));
    EXPECT_EQ(SOFTBUS_OK, AddTrigger(static_cast<ListenerModule>(module), fd, static_cast<TriggerType>(triggerType)));
    EXPECT_EQ(SOFTBUS_OK, DelTrigger(static_cast<ListenerModule>(module), fd, static_cast<TriggerType>(triggerType)));

    EXPECT_EQ(SOFTBUS_OK, StopBaseListener(static_cast<ListenerModule>(module)));
    DestroyBaseListener(static_cast<ListenerModule>(module));
    free(listener);
};

/*
 * @tc.name: testBaseListener039
 * @tc.desc: Test StartBaseListener after ResetBaseListenerSet.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StartBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener039, TestSize.Level1)
{
    int module = PROXY;
    int port = 6666;

    SoftbusBaseListener *listener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener != nullptr);
    listener->onConnectEvent = ConnectEvent;
    listener->onDataEvent = DataEvent;
    EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(module), listener));
    EXPECT_EQ(port, StartBaseListener(static_cast<ListenerModule>(module), "127.0.0.1", port, SERVER_MODE));

    ResetBaseListenerSet(static_cast<ListenerModule>(module));
    EXPECT_EQ(SOFTBUS_ERR, StartBaseListener(static_cast<ListenerModule>(module), "127.0.0.1", port, SERVER_MODE));

    EXPECT_EQ(SOFTBUS_OK, StopBaseListener(static_cast<ListenerModule>(module)));
    DestroyBaseListener(static_cast<ListenerModule>(module));
    free(listener);
};

/*
 * @tc.name: testBaseListener040
 * @tc.desc: Test StopBaseListener after ResetBaseListenerSet.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StopBaseListener operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener040, TestSize.Level1)
{
    int module = PROXY;
    int port = 6666;

    SoftbusBaseListener *listener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener != nullptr);
    listener->onConnectEvent = ConnectEvent;
    listener->onDataEvent = DataEvent;
    EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(module), listener));
    EXPECT_EQ(port, StartBaseListener(static_cast<ListenerModule>(module), "127.0.0.1", port, SERVER_MODE));

    ResetBaseListenerSet(static_cast<ListenerModule>(module));
    EXPECT_EQ(SOFTBUS_OK, StopBaseListener(static_cast<ListenerModule>(module)));

    DestroyBaseListener(static_cast<ListenerModule>(module));
    free(listener);
};

/*
 * @tc.name: testBaseListener041
 * @tc.desc: Test AddTrigger DelTrigger after ResetBaseListenerSet.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The AddTrigger and DelTrigger operates normally.
 */
HWTEST_F(SoftbusCommonTest, testBaseListener041, TestSize.Level1)
{
    int module = PROXY;
    int triggerType = READ_TRIGGER;
    int fd = 1;
    int port = 6666;

    SoftbusBaseListener *listener = (SoftbusBaseListener *)malloc(sizeof(SoftbusBaseListener));
    ASSERT_TRUE(listener != nullptr);
    listener->onConnectEvent = ConnectEvent;
    listener->onDataEvent = DataEvent;
    EXPECT_EQ(SOFTBUS_OK, SetSoftbusBaseListener(static_cast<ListenerModule>(module), listener));
    EXPECT_EQ(port, StartBaseListener(static_cast<ListenerModule>(module), "127.0.0.1", port, SERVER_MODE));

    ResetBaseListenerSet(static_cast<ListenerModule>(module));
    EXPECT_EQ(SOFTBUS_OK, AddTrigger(static_cast<ListenerModule>(module), fd, static_cast<TriggerType>(triggerType)));
    EXPECT_EQ(SOFTBUS_OK, DelTrigger(static_cast<ListenerModule>(module), fd, static_cast<TriggerType>(triggerType)));

    EXPECT_EQ(SOFTBUS_OK, StopBaseListener(static_cast<ListenerModule>(module)));
    DestroyBaseListener(static_cast<ListenerModule>(module));
    free(listener);
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
    int fd = OpenTcpClientSocket("127.0.0.1", "194.0.0.1", g_port, false);
    int ret = (fd <= 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_ERR);
    int port = GetTcpSockPort(fd);
    EXPECT_EQ(port, -1);
    CloseTcpFd(fd);

    fd = OpenTcpClientSocket(nullptr, "127.0.0.1", g_port, false);
    ret = (fd <= 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_ERR);
    CloseTcpFd(fd);
    fd = OpenTcpClientSocket("127.0.0.1", nullptr, g_port, false);
    ret = (fd <= 0) ? SOFTBUS_ERR : SOFTBUS_OK;
    EXPECT_EQ(ret, SOFTBUS_ERR);
    CloseTcpFd(fd);
    fd = OpenTcpClientSocket("127.0.0.1", "127.0.0.1", -1, false);
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
    int clientFd = OpenTcpClientSocket("127.0.0.1", "127.5.0.1", g_port, false);
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

/*
 * @tc.name: testThreadPool006
 * @tc.desc: test ThreadPoolAddJob after pool == nullptr
 * @tec.in: test module,test number,test levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: ThreadPoolAddJob and ThreadPoolDestroy and ThreadPoolInit operates normally.
 */
HWTEST_F(SoftbusCommonTest, testThreadPool006, TestSize.Level1)
{
    int threadNum = 1;
    int queueMaxNum = 2;
    g_count = 0;

    ThreadPool *pool = ThreadPoolInit(threadNum, queueMaxNum);
    int ret = (pool != nullptr) ? SOFTBUS_OK : SOFTBUS_ERR;
    EXPECT_EQ(ret, SOFTBUS_OK);

    if (pool != nullptr) {
        ret = ThreadPoolDestroy(pool);
        pool = nullptr;
        EXPECT_EQ(ret, SOFTBUS_OK);
    }

    int handId = 0;
    ret = ThreadPoolAddJob(pool, ThreadPoolTask, nullptr, ONCE, (uintptr_t)handId);
    EXPECT_TRUE(ret != SOFTBUS_OK);
};

/*
 * @tc.name: testThreadPool007
 * @tc.desc: Test call ThreadPoolAddJob twice to create a thread twice.
 * @tc.in: test module, test number, test levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: ThreadPoolInit and ThreadPoolAddJob and ThreadPoolDestroy operates normally.
 */
HWTEST_F(SoftbusCommonTest, testThreadPool007, TestSize.Level1)
{
    int threadNum = 2;
    int queueMaxNum = 4;
    g_count = 0;

    ThreadPool *pool = ThreadPoolInit(threadNum, queueMaxNum);
    int ret = (pool != nullptr) ? SOFTBUS_OK : SOFTBUS_ERR;
    EXPECT_EQ(ret, SOFTBUS_OK);

    int handId = 0;
    ret = ThreadPoolAddJob(pool, ThreadPoolTask, nullptr, PERSISTENT, (uintptr_t)handId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = ThreadPoolAddJob(pool, ThreadPoolTask, nullptr, PERSISTENT, (uintptr_t)handId);
    EXPECT_EQ(ret, SOFTBUS_ALREADY_EXISTED);

    if (pool != nullptr) {
        ret = ThreadPoolDestroy(pool);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
};

/*
 * @tc.name: testThreadPool008
 * @tc.desc: Test ThreadPoolAddJob when queueCurNum add some jobs.
 * @tc.in: test module, test number, test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The testGThreadPool operates normally.
 */
HWTEST_F(SoftbusCommonTest, testThreadPool008, TestSize.Level1)
{
    int threadNum = 2;
    int queueMaxNum = 4;
    g_count = 0;

    ThreadPool *pool = ThreadPoolInit(threadNum, queueMaxNum);
    int ret = (pool != nullptr) ? SOFTBUS_OK : SOFTBUS_ERR;
    EXPECT_EQ(ret, SOFTBUS_OK);

    for (int i = 0; i < queueMaxNum; i++) {
        ret = ThreadPoolAddJob(pool, ThreadPoolTask, nullptr, PERSISTENT, (uintptr_t)i);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }

    usleep(500);
    EXPECT_EQ(pool->queueCurNum, queueMaxNum);

    if (pool != nullptr) {
        ret = ThreadPoolDestroy(pool);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
};

/*
 * @tc.name: testThreadPool009
 * @tc.desc: Test ThreadPoolAddJob when ThreadPoolInit failed.
 * @tc.in: test module, test number, test levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The testGThreadPool operates normally.
 */
HWTEST_F(SoftbusCommonTest, testThreadPool009, TestSize.Level1)
{
    int threadNum = -1;
    int queueMaxNum = -1;
    g_count = 0;

    ThreadPool *pool = ThreadPoolInit(threadNum, queueMaxNum);
    int ret = (pool != nullptr) ? SOFTBUS_OK : SOFTBUS_ERR;
    EXPECT_EQ(ret, SOFTBUS_ERR);

    int handId = 0;
    ret = ThreadPoolAddJob(pool, ThreadPoolTask, nullptr, PERSISTENT, (uintptr_t)handId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    if (pool != nullptr) {
        ret = ThreadPoolDestroy(pool);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
};

/*
 * @tc.name: testThreadPool010
 * @tc.desc: Test ThreadPoolAddJob when add the same handle but different jobMode.
 * @tc.in: test module, test number, test levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The testGThreadPool operates normally.
 */
HWTEST_F(SoftbusCommonTest, testThreadPool010, TestSize.Level1)
{
    int threadNum = 2;
    int queueMaxNum = 4;
    g_count = 0;

    ThreadPool *pool = ThreadPoolInit(threadNum, queueMaxNum);
    int ret = (pool != nullptr) ? SOFTBUS_OK : SOFTBUS_ERR;
    EXPECT_EQ(ret, SOFTBUS_OK);

    if (nullptr != pool) {
        int handId = 0;
        ret = ThreadPoolAddJob(pool, ThreadPoolTask, nullptr, ONCE, (uintptr_t)handId);
        EXPECT_EQ(ret, SOFTBUS_OK);

        ret = ThreadPoolAddJob(pool, ThreadPoolTask, nullptr, PERSISTENT, (uintptr_t)handId);
        EXPECT_EQ(ret, SOFTBUS_ALREADY_EXISTED);

        ret = ThreadPoolDestroy(pool);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
};

/*
 * @tc.name: testThreadPool011
 * @tc.desc: Test ThreadPoolAddJob add the same handle when jobMode is ONCE.
 * @tc.in: test module, test number, test levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The ThreadPoolAddJob operates normally.
 */
HWTEST_F(SoftbusCommonTest, testThreadPool011, TestSize.Level1)
{
    int threadNum = 2;
    int queueMaxNum = 4;
    g_count = 0;

    ThreadPool *pool = ThreadPoolInit(threadNum, queueMaxNum);
    int ret = (pool != nullptr) ? SOFTBUS_OK : SOFTBUS_ERR;
    EXPECT_EQ(ret, SOFTBUS_OK);

    if (nullptr != pool) {
        for (int i = 0; i < queueMaxNum; i++) {
            ret = ThreadPoolAddJob(pool, ThreadPoolTask, nullptr, ONCE, (uintptr_t)i);
            EXPECT_EQ(ret, SOFTBUS_OK);
        }

        int handId = 0;
        ret = ThreadPoolAddJob(pool, ThreadPoolTask, nullptr, ONCE, (uintptr_t)handId);
        EXPECT_EQ(ret, SOFTBUS_ERR);

        ret = ThreadPoolDestroy(pool);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
};

/*
 * @tc.name: testThreadPool012
 * @tc.desc: Test ThreadPoolRemoveJob when handId out of max.
 * @tc.in: test module, test number, test levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The ThreadPoolRemoveJob operates normally.
 */
HWTEST_F(SoftbusCommonTest, testThreadPool012, TestSize.Level1)
{
    int threadNum = 2;
    int queueMaxNum = 4;
    g_count = 0;

    ThreadPool *pool = ThreadPoolInit(threadNum, queueMaxNum);
    int ret = (pool != nullptr) ? SOFTBUS_OK : SOFTBUS_ERR;
    EXPECT_EQ(ret, SOFTBUS_OK);

    if (nullptr != pool) {
        for (int i = 0; i < queueMaxNum; i++) {
            ret = ThreadPoolAddJob(pool, ThreadPoolTask, nullptr, ONCE, (uintptr_t)i);
            EXPECT_EQ(ret, SOFTBUS_OK);
        }

        ret = ThreadPoolRemoveJob(pool, (uintptr_t)queueMaxNum);
        EXPECT_EQ(ret, SOFTBUS_OK);

        ret = ThreadPoolDestroy(pool);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
};

/*
 * @tc.name: testThreadPool013
 * @tc.desc: Test ThreadPoolRemoveJob when no add job.
 * @tc.in: test module, test number, test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The ThreadPoolRemoveJob operates normally.
 */
HWTEST_F(SoftbusCommonTest, testThreadPool013, TestSize.Level1)
{
    int threadNum = 2;
    int queueMaxNum = 4;

    ThreadPool *pool = ThreadPoolInit(threadNum, queueMaxNum);
    int ret = (pool != nullptr) ? SOFTBUS_OK : SOFTBUS_ERR;
    EXPECT_EQ(ret, SOFTBUS_OK);

    int handId = 0;
    ret = ThreadPoolRemoveJob(pool, (uintptr_t)handId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    if (pool != nullptr) {
        ret = ThreadPoolDestroy(pool);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
};

/*
 * @tc.name: testThreadPool014
 * @tc.desc: Test ThreadPoolRemoveJob remove the same handle when the added job mode is ONCE.
 * @tc.in: test module, test number, test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The ThreadPoolRemoveJob operates normally.
 */
HWTEST_F(SoftbusCommonTest, testThreadPool014, TestSize.Level1)
{
    int threadNum = 2;
    int queueMaxNum = 4;
    g_count = 0;

    ThreadPool *pool = ThreadPoolInit(threadNum, queueMaxNum);
    int ret = (pool != nullptr) ? SOFTBUS_OK : SOFTBUS_ERR;
    EXPECT_EQ(ret, SOFTBUS_OK);

    for (int i = 0; i < queueMaxNum; i++) {
        ret = ThreadPoolAddJob(pool, ThreadPoolTask, nullptr, ONCE, (uintptr_t)i);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
    usleep(1000);

    int handId = 0;
    ret = ThreadPoolRemoveJob(pool, (uintptr_t)handId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = ThreadPoolRemoveJob(pool, (uintptr_t)handId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    if (pool != nullptr) {
        ret = ThreadPoolDestroy(pool);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
};

/*
 * @tc.name: testThreadPool015
 * @tc.desc: Test ThreadPoolRemoveJob when ThreadPoolInit failed.
 * @tc.in: test module, test number, test levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The ThreadPoolRemoveJob operates normally.
 */
HWTEST_F(SoftbusCommonTest, testThreadPool015, TestSize.Level1)
{
    int threadNum = -1;
    int queueMaxNum = -1;
    g_count = 0;

    ThreadPool *pool = ThreadPoolInit(threadNum, queueMaxNum);
    int ret = (pool != nullptr) ? SOFTBUS_OK : SOFTBUS_ERR;
    EXPECT_EQ(ret, SOFTBUS_ERR);

    int handId = 0;
    ret = ThreadPoolAddJob(pool, ThreadPoolTask, nullptr, ONCE, (uintptr_t)handId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = ThreadPoolRemoveJob(pool, (uintptr_t)handId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    if (pool != nullptr) {
        ret = ThreadPoolDestroy(pool);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
};

/*
 * @tc.name: testThreadPool016
 * @tc.desc: Test ThreadPoolRemoveJob remove the same hand when the added job mode is PERSISTENT.
 * @tc.in: test module, test number, test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The ThreadPoolRemoveJob operates normally.
 */
HWTEST_F(SoftbusCommonTest, testThreadPool016, TestSize.Level1)
{
    int threadNum = 2;
    int queueMaxNum = 4;
    g_count = 0;

    ThreadPool *pool = ThreadPoolInit(threadNum, queueMaxNum);
    int ret = (pool != nullptr) ? SOFTBUS_OK : SOFTBUS_ERR;
    EXPECT_EQ(ret, SOFTBUS_OK);

    if (nullptr != pool) {
        for (int i = 0; i < queueMaxNum; i++) {
            ret = ThreadPoolAddJob(pool, ThreadPoolTask, nullptr, PERSISTENT, (uintptr_t)i);
            EXPECT_EQ(ret, SOFTBUS_OK);
        }

        int handId = 0;
        ret = ThreadPoolRemoveJob(pool, (uintptr_t)handId);
        EXPECT_EQ(ret, SOFTBUS_OK);

        ret = ThreadPoolRemoveJob(pool, (uintptr_t)handId);
        EXPECT_EQ(ret, SOFTBUS_OK);

        ret = ThreadPoolDestroy(pool);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
};

/*
 * @tc.name: testThreadPool017
 * @tc.desc: Test ThreadPoolDestroy under normal process.
 * @tc.in: test module, test number, test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The testGThreadPool operates normally.
 */
HWTEST_F(SoftbusCommonTest, testThreadPool017, TestSize.Level1)
{
    int threadNum = 2;
    int queueMaxNum = 4;

    ThreadPool *pool = ThreadPoolInit(threadNum, queueMaxNum);
    int ret = (pool != nullptr) ? SOFTBUS_OK : SOFTBUS_ERR;
    EXPECT_EQ(ret, SOFTBUS_OK);

    if (pool != nullptr) {
        ret = ThreadPoolDestroy(pool);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
};

/*
 * @tc.name: testThreadPool018
 * @tc.desc: Test ThreadPoolDestroy when ThreadPoolInit failed
 * @tc.in: test module,test  number,test levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The ThreadPoolDestroy operates normally.
 */
HWTEST_F(SoftbusCommonTest, testThreadPool018, TestSize.Level1)
{
    int threadNum = -1;
    int queueMaxNum = -1;

    ThreadPool *pool = ThreadPoolInit(threadNum, queueMaxNum);
    int ret = (pool != nullptr) ? SOFTBUS_OK : SOFTBUS_ERR;
    EXPECT_EQ(ret, SOFTBUS_ERR);

    ret = ThreadPoolDestroy(pool);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
};

/*
 * @tc.name: testThreadPool019
 * @tc.desc: Test ThreadPoolDestroy when not ThreadPoolAddJob.
 * @tc.in: test module, test number,test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The ThreadPoolDestroy operates normally.
 */
HWTEST_F(SoftbusCommonTest, testThreadPool019, TestSize.Level1)
{
    int threadNum = 2;
    int queueMaxNum = 4;

    ThreadPool *pool = ThreadPoolInit(threadNum, queueMaxNum);
    int ret = (pool != nullptr) ? SOFTBUS_OK : SOFTBUS_ERR;
    EXPECT_EQ(ret, SOFTBUS_OK);

    if (nullptr != pool) {
        ret = ThreadPoolDestroy(pool);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
};

/*
 * @tc.name: testThreadPool020
 * @tc.desc: Test ThreadPoolDestroy when not ThreadPoolRemoveJob.
 * @tc.in: test module, test number, test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The ThreadPoolDestroy operates normally.
 */
HWTEST_F(SoftbusCommonTest, testThreadPool020, TestSize.Level1)
{
    int threadNum = 2;
    int queueMaxNum = 4;
    g_count = 0;

    ThreadPool *pool = ThreadPoolInit(threadNum, queueMaxNum);
    int ret = (pool != nullptr) ? SOFTBUS_OK : SOFTBUS_ERR;
    EXPECT_EQ(ret, SOFTBUS_OK);

    if (nullptr != pool) {
        for (int i = 0; i < queueMaxNum; i++) {
            ret = ThreadPoolAddJob(pool, ThreadPoolTask, nullptr, PERSISTENT, (uintptr_t)i);
            EXPECT_EQ(ret, SOFTBUS_OK);
        }
        ret = ThreadPoolDestroy(pool);
        EXPECT_EQ(ret, SOFTBUS_OK);
    }
};
} // namespace OHOS
