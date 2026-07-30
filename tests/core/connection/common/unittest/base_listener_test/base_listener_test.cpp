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

#include "base_listener_mock.h"
#include "softbus_base_listener.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"
#include "conn_log.h"

#include <cstdio>
#include <cstring>
#include <gtest/gtest.h>
#include <securec.h>

#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"

using namespace testing::ext;
using namespace testing;
using namespace std;

namespace OHOS {
static EventWatcher g_mockEventWatcher = {0};
static int32_t g_connectEventCallCount = 0;
static int32_t g_dataEventCallCount = 0;

static int32_t MockOnConnectEvent(ListenerModule module, int32_t clientFd, const ConnectOption *clientAddr)
{
    g_connectEventCallCount++;
    return SOFTBUS_OK;
}

static int32_t MockOnDataEvent(ListenerModule module, int32_t events, int32_t fd)
{
    g_dataEventCallCount++;
    return SOFTBUS_OK;
}

class BaseListenerUnitTest : public testing::Test {
public:
    BaseListenerUnitTest() {}
    ~BaseListenerUnitTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void BaseListenerUnitTest::SetUpTestCase(void) {}

void BaseListenerUnitTest::TearDownTestCase(void) {}

void BaseListenerUnitTest::SetUp(void)
{
    g_connectEventCallCount = 0;
    g_dataEventCallCount = 0;
}

void BaseListenerUnitTest::TearDown(void) {}

static void SetupInitMocks(NiceMock<BaseListenerTestMock> &mock)
{
    EXPECT_CALL(mock, SoftBusMutexInit(_, _))
        .WillRepeatedly(Invoke([](SoftBusMutex *mutex, const SoftBusMutexAttr *attr) -> int32_t {
            return SOFTBUS_OK;
        }));
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexDestroy(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, SoftBusCalloc(_))
        .WillRepeatedly(Invoke([](uint32_t size) -> void * {
            return calloc(1, size);
        }));
    EXPECT_CALL(mock, SoftBusFree(_)).WillRepeatedly(Invoke([](void *ptr) { free(ptr); }));
    EXPECT_CALL(mock, RegisterEventWatcher(_)).WillRepeatedly(Return(&g_mockEventWatcher));
    EXPECT_CALL(mock, CloseEventWatcher(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, AddEvent(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, RemoveEvent(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ModifyEvent(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnStartActionAsync(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
}

/*
 * @tc.name: InitBaseListenerTest001
 * @tc.desc: test InitBaseListener success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, InitBaseListenerTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    int32_t ret = InitBaseListener();
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: InitBaseListenerTest002
 * @tc.desc: test InitBaseListener with watch thread state lock init fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, InitBaseListenerTest002, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    EXPECT_CALL(mock, SoftBusMutexInit(_, _))
        .WillOnce(Return(SOFTBUS_ERR));
    int32_t ret = InitBaseListener();
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
}

/*
 * @tc.name: InitBaseListenerTest003
 * @tc.desc: test InitBaseListener with listener list lock init fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, InitBaseListenerTest003, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    EXPECT_CALL(mock, SoftBusMutexInit(_, _))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, SoftBusMutexDestroy(_)).WillRepeatedly(Return());
    int32_t ret = InitBaseListener();
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
}

/*
 * @tc.name: InitBaseListenerTest004
 * @tc.desc: test InitBaseListener with remove abnormal fd lock init fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, InitBaseListenerTest004, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    EXPECT_CALL(mock, SoftBusMutexInit(_, _))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, SoftBusMutexDestroy(_)).WillRepeatedly(Return());
    int32_t ret = InitBaseListener();
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
}

/*
 * @tc.name: InitBaseListenerTest005
 * @tc.desc: test InitBaseListener with listener list lock fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, InitBaseListenerTest005, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    EXPECT_CALL(mock, SoftBusMutexInit(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexDestroy(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, SoftBusMutexLock(_))
        .WillOnce(Return(SOFTBUS_ERR));
    int32_t ret = InitBaseListener();
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
}

/*
 * @tc.name: InitBaseListenerTest006
 * @tc.desc: test InitBaseListener with RegisterEventWatcher fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, InitBaseListenerTest006, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    EXPECT_CALL(mock, SoftBusMutexInit(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexDestroy(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, RegisterEventWatcher(_)).WillOnce(Return(nullptr));
    int32_t ret = InitBaseListener();
    EXPECT_EQ(SOFTBUS_MEM_ERR, ret);
}

/*
 * @tc.name: DeinitBaseListenerTest001
 * @tc.desc: test DeinitBaseListener success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DeinitBaseListenerTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    int32_t ret = InitBaseListener();
    EXPECT_EQ(SOFTBUS_OK, ret);
    DeinitBaseListener();
}

/*
 * @tc.name: DeinitBaseListenerTest002
 * @tc.desc: test DeinitBaseListener with active modules
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DeinitBaseListenerTest002, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    DeinitBaseListener();
}

/*
 * @tc.name: DeinitBaseListenerTest003
 * @tc.desc: test multiple DeinitBaseListener calls
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DeinitBaseListenerTest003, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    DeinitBaseListener();
    DeinitBaseListener();
}

/*
 * @tc.name: CreateListenerModuleTest001
 * @tc.desc: test CreateListenerModule success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, CreateListenerModuleTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    uint32_t module = CreateListenerModule();
    EXPECT_GE(module, LISTENER_MODULE_DYNAMIC_START);
    EXPECT_LE(module, LISTENER_MODULE_DYNAMIC_END);
}

/*
 * @tc.name: CreateListenerModuleTest002
 * @tc.desc: test CreateListenerModule with lock fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, CreateListenerModuleTest002, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_ERR));
    uint32_t module = CreateListenerModule();
    EXPECT_EQ(module, UNUSE_BUTT);
}

/*
 * @tc.name: CreateListenerModuleTest003
 * @tc.desc: test CreateListenerModule with calloc fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, CreateListenerModuleTest003, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusCalloc(_)).WillOnce(Return(nullptr));
    uint32_t module = CreateListenerModule();
    EXPECT_EQ(module, UNUSE_BUTT);
}

/*
 * @tc.name: CreateListenerModuleTest004
 * @tc.desc: test CreateListenerModule with mutex init fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, CreateListenerModuleTest004, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexInit(_, _)).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    EXPECT_EQ(module, UNUSE_BUTT);
}

/*
 * @tc.name: CreateListenerModuleTest005
 * @tc.desc: test CreateListenerModule with all dynamic modules occupied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, CreateListenerModuleTest005, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    std::vector<uint32_t> modules;
    for (int i = 0; i <= LISTENER_MODULE_DYNAMIC_END - LISTENER_MODULE_DYNAMIC_START; i++) {
        uint32_t module = CreateListenerModule();
        modules.push_back(module);
    }
    uint32_t extraModule = CreateListenerModule();
    EXPECT_EQ(extraModule, UNUSE_BUTT);
}

/*
 * @tc.name: CreateListenerModuleTest006
 * @tc.desc: test CreateListenerModule after DestroyBaseListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, CreateListenerModuleTest006, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module1 = CreateListenerModule();
    EXPECT_GE(module1, LISTENER_MODULE_DYNAMIC_START);
    DestroyBaseListener(module1);
    uint32_t module2 = CreateListenerModule();
    EXPECT_GE(module2, LISTENER_MODULE_DYNAMIC_START);
    EXPECT_LE(module2, LISTENER_MODULE_DYNAMIC_END);
}

/*
 * @tc.name: DestroyBaseListenerTest001
 * @tc.desc: test DestroyBaseListener with invalid module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DestroyBaseListenerTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    DestroyBaseListener(LISTENER_MODULE_DYNAMIC_START - 1);
    DestroyBaseListener(LISTENER_MODULE_DYNAMIC_END + 1);
}

/*
 * @tc.name: DestroyBaseListenerTest002
 * @tc.desc: test DestroyBaseListener with non-exist module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DestroyBaseListenerTest002, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    DestroyBaseListener(LISTENER_MODULE_DYNAMIC_START);
}

/*
 * @tc.name: DestroyBaseListenerTest003
 * @tc.desc: test DestroyBaseListener with running module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DestroyBaseListenerTest003, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnCloseSocket(_)).WillRepeatedly(Return());
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    DestroyBaseListener(module);
}

/*
 * @tc.name: StartBaseClientTest001
 * @tc.desc: test StartBaseClient with invalid module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseClientTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(-1, &listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = StartBaseClient(UNUSE_BUTT, &listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: StartBaseClientTest002
 * @tc.desc: test StartBaseClient with null listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseClientTest002, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    int32_t ret = StartBaseClient(0, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: StartBaseClientTest003
 * @tc.desc: test StartBaseClient with null onConnectEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseClientTest003, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    SoftbusBaseListener listener = {0};
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(0, &listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: StartBaseClientTest004
 * @tc.desc: test StartBaseClient with null onDataEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseClientTest004, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    int32_t ret = StartBaseClient(0, &listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: StartBaseClientTest005
 * @tc.desc: test StartBaseClient with get listener node fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseClientTest005, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_ERR));
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(0, &listener);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StartBaseClientTest006
 * @tc.desc: test StartBaseClient with listener node lock fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseClientTest006, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_ERR));
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(0, &listener);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
}

/*
 * @tc.name: StartBaseClientTest007
 * @tc.desc: test StartBaseClient with start watch thread fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseClientTest007, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, ConnStartActionAsync(_, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StartBaseClientTest008
 * @tc.desc: test StartBaseClient success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseClientTest008, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StartBaseClientTest009
 * @tc.desc: test StartBaseClient with listener not idle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseClientTest009, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_CONN_LISTENER_NOT_IDLE, ret);
}

/*
 * @tc.name: StartBaseClientTest010
 * @tc.desc: test StartBaseClient after StopBaseListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseClientTest010, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnCloseSocket(_)).WillRepeatedly(Return());
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StopBaseListener(module);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StartBaseListenerTest001
 * @tc.desc: test StartBaseListener with null info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(nullptr, &listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: StartBaseListenerTest002
 * @tc.desc: test StartBaseListener with invalid connect type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest002, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    LocalListenerInfo info = {0};
    info.type = CONNECT_BLE;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: StartBaseListenerTest003
 * @tc.desc: test StartBaseListener with invalid port
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest003, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = -1;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: StartBaseListenerTest004
 * @tc.desc: test StartBaseListener with invalid module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest004, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = -1;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: StartBaseListenerTest005
 * @tc.desc: test StartBaseListener with null listener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest005, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    int32_t ret = StartBaseListener(&info, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: StartBaseListenerTest006
 * @tc.desc: test StartBaseListener with null onConnectEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest006, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: StartBaseListenerTest007
 * @tc.desc: test StartBaseListener with null onDataEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest007, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: StartBaseListenerTest008
 * @tc.desc: test StartBaseListener with lock fail on removeAbnormalFdLock
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest008, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_ERR));
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StartBaseListenerTest009
 * @tc.desc: test StartBaseListener with get listener node fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest009, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    EXPECT_CALL(mock, SoftBusCalloc(_)).WillRepeatedly(Return(nullptr));
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StartBaseListenerTest010
 * @tc.desc: test StartBaseListener with CONNECT_P2P type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest010, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    LocalListenerInfo info = {0};
    info.type = CONNECT_P2P;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    EXPECT_CALL(mock, SoftBusCalloc(_)).WillRepeatedly(Return(nullptr));
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: StartBaseListenerTest011
 * @tc.desc: test StartBaseListener with CONNECT_HML type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest011, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    LocalListenerInfo info = {0};
    info.type = CONNECT_HML;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    EXPECT_CALL(mock, SoftBusCalloc(_)).WillRepeatedly(Return(nullptr));
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_NE(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: StartBaseListenerTest012
 * @tc.desc: test StartBaseListener with module id out of range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest012, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = UNUSE_BUTT;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: StartBaseListenerTest013
 * @tc.desc: test StartBaseListener with socket interface not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest013, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, GetSocketInterface(_)).WillRepeatedly(Return(nullptr));
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StartBaseListenerTest014
 * @tc.desc: test StartBaseListener with open server socket fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest014, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    static SocketInterface mockSocketIf = {0};
    mockSocketIf.OpenServerSocket = [](const LocalListenerInfo *info) -> int32_t { return -1; };
    EXPECT_CALL(mock, GetSocketInterface(_)).WillRepeatedly(Return(&mockSocketIf));
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StartBaseListenerTest015
 * @tc.desc: test StartBaseListener with socket listen fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest015, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    static SocketInterface mockSocketIf = {0};
    mockSocketIf.OpenServerSocket = [](const LocalListenerInfo *info) -> int32_t { return 10; };
    mockSocketIf.GetSockPort = [](int32_t fd) -> int32_t { return 8888; };
    EXPECT_CALL(mock, GetSocketInterface(_)).WillRepeatedly(Return(&mockSocketIf));
    EXPECT_CALL(mock, SoftBusSocketListen(_, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, ConnShutdownSocket(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StartBaseListenerTest016
 * @tc.desc: test StartBaseListener with get sock port fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest016, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    static SocketInterface mockSocketIf = {0};
    mockSocketIf.OpenServerSocket = [](const LocalListenerInfo *info) -> int32_t { return 10; };
    mockSocketIf.GetSockPort = [](int32_t fd) -> int32_t { return -1; };
    EXPECT_CALL(mock, GetSocketInterface(_)).WillRepeatedly(Return(&mockSocketIf));
    EXPECT_CALL(mock, SoftBusSocketListen(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnShutdownSocket(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StartBaseListenerTest017
 * @tc.desc: test StartBaseListener with start watch thread fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest017, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    static SocketInterface mockSocketIf = {0};
    mockSocketIf.OpenServerSocket = [](const LocalListenerInfo *info) -> int32_t { return 10; };
    mockSocketIf.GetSockPort = [](int32_t fd) -> int32_t { return 8888; };
    EXPECT_CALL(mock, GetSocketInterface(_)).WillRepeatedly(Return(&mockSocketIf));
    EXPECT_CALL(mock, SoftBusSocketListen(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnShutdownSocket(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, ConnStartActionAsync(_, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StartBaseListenerTest018
 * @tc.desc: test StartBaseListener with AddEvent fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest018, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    static SocketInterface mockSocketIf = {0};
    mockSocketIf.OpenServerSocket = [](const LocalListenerInfo *info) -> int32_t { return 10; };
    mockSocketIf.GetSockPort = [](int32_t fd) -> int32_t { return 8888; };
    EXPECT_CALL(mock, GetSocketInterface(_)).WillRepeatedly(Return(&mockSocketIf));
    EXPECT_CALL(mock, SoftBusSocketListen(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnShutdownSocket(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, AddEvent(_, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StartBaseListenerTest019
 * @tc.desc: test StartBaseListener success with CONNECT_TCP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest019, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    static SocketInterface mockSocketIf = {0};
    mockSocketIf.OpenServerSocket = [](const LocalListenerInfo *info) -> int32_t { return 10; };
    mockSocketIf.GetSockPort = [](int32_t fd) -> int32_t { return 8888; };
    EXPECT_CALL(mock, GetSocketInterface(_)).WillRepeatedly(Return(&mockSocketIf));
    EXPECT_CALL(mock, SoftBusSocketListen(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnShutdownSocket(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_GT(ret, 0);
}

/*
 * @tc.name: StartBaseListenerTest020
 * @tc.desc: test StartBaseListener with listener not idle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest020, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    static SocketInterface mockSocketIf = {0};
    mockSocketIf.OpenServerSocket = [](const LocalListenerInfo *info) -> int32_t { return 10; };
    mockSocketIf.GetSockPort = [](int32_t fd) -> int32_t { return 8888; };
    EXPECT_CALL(mock, GetSocketInterface(_)).WillRepeatedly(Return(&mockSocketIf));
    EXPECT_CALL(mock, SoftBusSocketListen(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnShutdownSocket(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_GT(ret, 0);
    ret = StartBaseListener(&info, &listener);
    EXPECT_EQ(SOFTBUS_CONN_LISTENER_NOT_IDLE, ret);
}

/*
 * @tc.name: StartBaseListenerTest021
 * @tc.desc: test StartBaseListener with CONNECT_P2P success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest021, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    static SocketInterface mockSocketIf = {0};
    mockSocketIf.OpenServerSocket = [](const LocalListenerInfo *info) -> int32_t { return 20; };
    mockSocketIf.GetSockPort = [](int32_t fd) -> int32_t { return 9999; };
    EXPECT_CALL(mock, GetSocketInterface(_)).WillRepeatedly(Return(&mockSocketIf));
    EXPECT_CALL(mock, SoftBusSocketListen(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnShutdownSocket(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    LocalListenerInfo info = {0};
    info.type = CONNECT_P2P;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_GT(ret, 0);
}

/*
 * @tc.name: StartBaseListenerTest022
 * @tc.desc: test StartBaseListener with CONNECT_HML success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest022, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    static SocketInterface mockSocketIf = {0};
    mockSocketIf.OpenServerSocket = [](const LocalListenerInfo *info) -> int32_t { return 30; };
    mockSocketIf.GetSockPort = [](int32_t fd) -> int32_t { return 7777; };
    EXPECT_CALL(mock, GetSocketInterface(_)).WillRepeatedly(Return(&mockSocketIf));
    EXPECT_CALL(mock, SoftBusSocketListen(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnShutdownSocket(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    LocalListenerInfo info = {0};
    info.type = CONNECT_HML;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_GT(ret, 0);
}

/*
 * @tc.name: StartBaseListenerTest023
 * @tc.desc: test StartBaseListener with RemoveEvent fail during cleanup
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerTest023, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    static SocketInterface mockSocketIf = {0};
    mockSocketIf.OpenServerSocket = [](const LocalListenerInfo *info) -> int32_t { return 10; };
    mockSocketIf.GetSockPort = [](int32_t fd) -> int32_t { return 8888; };
    EXPECT_CALL(mock, GetSocketInterface(_)).WillRepeatedly(Return(&mockSocketIf));
    EXPECT_CALL(mock, SoftBusSocketListen(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnShutdownSocket(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, ConnCloseSocket(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, RemoveEvent(_, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_GT(ret, 0);
    ret = StopBaseListener(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StopBaseListenerTest001
 * @tc.desc: test StopBaseListener with invalid module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StopBaseListenerTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    int32_t ret = StopBaseListener(-1);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = StopBaseListener(UNUSE_BUTT);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: StopBaseListenerTest002
 * @tc.desc: test StopBaseListener with non-exist module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StopBaseListenerTest002, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = StopBaseListener(0);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/*
 * @tc.name: StopBaseListenerTest003
 * @tc.desc: test StopBaseListener success after StartBaseClient
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StopBaseListenerTest003, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StopBaseListener(module);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StopBaseListenerTest004
 * @tc.desc: test StopBaseListener with lock fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StopBaseListenerTest004, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    ret = StopBaseListener(module);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StopBaseListenerTest005
 * @tc.desc: test StopBaseListener after StartBaseListener success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StopBaseListenerTest005, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    static SocketInterface mockSocketIf = {0};
    mockSocketIf.OpenServerSocket = [](const LocalListenerInfo *info) -> int32_t { return 10; };
    mockSocketIf.GetSockPort = [](int32_t fd) -> int32_t { return 8888; };
    EXPECT_CALL(mock, GetSocketInterface(_)).WillRepeatedly(Return(&mockSocketIf));
    EXPECT_CALL(mock, SoftBusSocketListen(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnShutdownSocket(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, ConnCloseSocket(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, RemoveEvent(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_GT(ret, 0);
    ret = StopBaseListener(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StopBaseListenerTest006
 * @tc.desc: test StopBaseListener when not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StopBaseListenerTest006, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnCloseSocket(_)).WillRepeatedly(Return());
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StopBaseListener(module);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StopBaseListener(module);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: IsListenerNodeExistTest001
 * @tc.desc: test IsListenerNodeExist with non-exist module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, IsListenerNodeExistTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    bool exist = IsListenerNodeExist(0);
    EXPECT_FALSE(exist);
}

/*
 * @tc.name: IsListenerNodeExistTest002
 * @tc.desc: test IsListenerNodeExist with created module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, IsListenerNodeExistTest002, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    uint32_t module = CreateListenerModule();
    EXPECT_GE(module, LISTENER_MODULE_DYNAMIC_START);
    EXPECT_LE(module, LISTENER_MODULE_DYNAMIC_END);
    bool exist = IsListenerNodeExist(module);
    EXPECT_TRUE(exist);
}

/*
 * @tc.name: IsListenerNodeExistTest003
 * @tc.desc: test IsListenerNodeExist with destroyed module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, IsListenerNodeExistTest003, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    EXPECT_TRUE(IsListenerNodeExist(module));
    DestroyBaseListener(module);
    EXPECT_FALSE(IsListenerNodeExist(module));
}

/*
 * @tc.name: AddTriggerTest001
 * @tc.desc: test AddTrigger with invalid module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    int32_t ret = AddTrigger(-1, 1, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = AddTrigger(UNUSE_BUTT, 1, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: AddTriggerTest002
 * @tc.desc: test AddTrigger with invalid fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest002, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    int32_t ret = AddTrigger(0, 0, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = AddTrigger(0, -1, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: AddTriggerTest003
 * @tc.desc: test AddTrigger with invalid trigger type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest003, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    int32_t ret = AddTrigger(0, 1, (TriggerType)100);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: AddTriggerTest004
 * @tc.desc: test AddTrigger with non-exist module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest004, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = AddTrigger(0, 1, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/*
 * @tc.name: AddTriggerTest005
 * @tc.desc: test AddTrigger with lock fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest005, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = AddTrigger(0, 1, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
}

/*
 * @tc.name: AddTriggerTest006
 * @tc.desc: test AddTrigger with valid trigger types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest006, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_TRUE(AddTrigger(0, 1, READ_TRIGGER) != SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(AddTrigger(0, 1, WRITE_TRIGGER) != SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(AddTrigger(0, 1, EXCEPT_TRIGGER) != SOFTBUS_INVALID_PARAM);
    EXPECT_TRUE(AddTrigger(0, 1, RW_TRIGGER) != SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: AddTriggerTest007
 * @tc.desc: test AddTrigger with calloc fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest007, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusCalloc(_)).WillRepeatedly(Return(nullptr));
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    int32_t ret = AddTrigger(module, 1, READ_TRIGGER);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: AddTriggerTest008
 * @tc.desc: test AddTrigger with AddEvent fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest008, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, AddEvent(_, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    int32_t ret = AddTrigger(module, 1, READ_TRIGGER);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: AddTriggerTest009
 * @tc.desc: test AddTrigger with module not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest009, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    int32_t ret = AddTrigger(module, 1, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_CONN_FAIL, ret);
}

/*
 * @tc.name: AddTriggerTest010
 * @tc.desc: test AddTrigger with ModifyEvent fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest010, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, ModifyEvent(_, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    int32_t ret = AddTrigger(module, 1, READ_TRIGGER);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: AddTriggerTest011
 * @tc.desc: test AddTrigger with RW_TRIGGER on non-running module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest011, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    int32_t ret = AddTrigger(module, 1, RW_TRIGGER);
    EXPECT_EQ(SOFTBUS_CONN_FAIL, ret);
}

/*
 * @tc.name: AddTriggerTest012
 * @tc.desc: test AddTrigger with EXCEPT_TRIGGER on non-running module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest012, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    int32_t ret = AddTrigger(module, 1, EXCEPT_TRIGGER);
    EXPECT_EQ(SOFTBUS_CONN_FAIL, ret);
}

/*
 * @tc.name: AddTriggerTest013
 * @tc.desc: test AddTrigger with running module success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest013, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: AddTriggerTest014
 * @tc.desc: test AddTrigger with WRITE_TRIGGER on running module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest014, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, WRITE_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: AddTriggerTest015
 * @tc.desc: test AddTrigger with duplicate trigger on existing fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest015, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: AddTriggerTest016
 * @tc.desc: test AddTrigger with different trigger on existing fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest016, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ModifyEvent(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, WRITE_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: AddTriggerTest017
 * @tc.desc: test AddTrigger with EXCEPT_TRIGGER on running module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest017, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, EXCEPT_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: AddTriggerTest018
 * @tc.desc: test AddTrigger with RW_TRIGGER on running module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest018, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, RW_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: AddTriggerTest019
 * @tc.desc: test AddTrigger with ModifyEvent fail on existing fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest019, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ModifyEvent(_, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, WRITE_TRIGGER);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: AddTriggerTest020
 * @tc.desc: test AddTrigger with multiple fds on running module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerTest020, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 20, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 30, WRITE_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: DelTriggerTest001
 * @tc.desc: test DelTrigger with invalid module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DelTriggerTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    int32_t ret = DelTrigger(-1, 1, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = DelTrigger(UNUSE_BUTT, 1, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: DelTriggerTest002
 * @tc.desc: test DelTrigger with invalid fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DelTriggerTest002, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    int32_t ret = DelTrigger(0, 0, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    ret = DelTrigger(0, -1, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: DelTriggerTest003
 * @tc.desc: test DelTrigger with invalid trigger type
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DelTriggerTest003, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    int32_t ret = DelTrigger(0, 1, (TriggerType)100);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/*
 * @tc.name: DelTriggerTest004
 * @tc.desc: test DelTrigger with non-exist module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DelTriggerTest004, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = DelTrigger(0, 1, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/*
 * @tc.name: DelTriggerTest005
 * @tc.desc: test DelTrigger with lock fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DelTriggerTest005, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = DelTrigger(0, 1, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
}

/*
 * @tc.name: DelTriggerTest006
 * @tc.desc: test DelTrigger with non-exist fd on module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DelTriggerTest006, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    int32_t ret = DelTrigger(module, 1, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/*
 * @tc.name: DelTriggerTest007
 * @tc.desc: test DelTrigger with EXCEPT_TRIGGER on non-running module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DelTriggerTest007, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    int32_t ret = DelTrigger(module, 1, EXCEPT_TRIGGER);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/*
 * @tc.name: DelTriggerTest008
 * @tc.desc: test DelTrigger with WRITE_TRIGGER on non-running module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DelTriggerTest008, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    int32_t ret = DelTrigger(module, 1, WRITE_TRIGGER);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/*
 * @tc.name: DelTriggerTest009
 * @tc.desc: test DelTrigger with running module and existing fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DelTriggerTest009, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, RemoveEvent(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DelTrigger(module, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: DelTriggerTest010
 * @tc.desc: test DelTrigger with partial trigger removal
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DelTriggerTest010, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ModifyEvent(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, RemoveEvent(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, WRITE_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DelTrigger(module, 10, WRITE_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: DelTriggerTest011
 * @tc.desc: test DelTrigger with non-existing fd on running module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DelTriggerTest011, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DelTrigger(module, 99, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/*
 * @tc.name: DelTriggerTest012
 * @tc.desc: test DelTrigger with mismatch trigger on existing fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DelTriggerTest012, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, RemoveEvent(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DelTrigger(module, 10, WRITE_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: DelTriggerTest013
 * @tc.desc: test DelTrigger with RW_TRIGGER on running module
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DelTriggerTest013, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, RemoveEvent(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, RW_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DelTrigger(module, 10, RW_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: DelTriggerTest014
 * @tc.desc: test DelTrigger with multiple fds then remove one
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DelTriggerTest014, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, RemoveEvent(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 20, WRITE_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DelTrigger(module, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: CreateDestroyListenerModuleTest001
 * @tc.desc: test create and destroy listener module flow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, CreateDestroyListenerModuleTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    EXPECT_GE(module, LISTENER_MODULE_DYNAMIC_START);
    EXPECT_LE(module, LISTENER_MODULE_DYNAMIC_END);
    DestroyBaseListener(module);
}

/*
 * @tc.name: CreateDestroyListenerModuleTest002
 * @tc.desc: test create multiple modules and destroy them
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, CreateDestroyListenerModuleTest002, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module1 = CreateListenerModule();
    uint32_t module2 = CreateListenerModule();
    EXPECT_NE(module1, module2);
    EXPECT_TRUE(IsListenerNodeExist(module1));
    EXPECT_TRUE(IsListenerNodeExist(module2));
    DestroyBaseListener(module1);
    EXPECT_FALSE(IsListenerNodeExist(module1));
    EXPECT_TRUE(IsListenerNodeExist(module2));
    DestroyBaseListener(module2);
    EXPECT_FALSE(IsListenerNodeExist(module2));
}

/*
 * @tc.name: StartBaseClientAndStopTest001
 * @tc.desc: test StartBaseClient and StopBaseListener full cycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseClientAndStopTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnCloseSocket(_)).WillRepeatedly(Return());
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StopBaseListener(module);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StartBaseListenerAndStopTest001
 * @tc.desc: test StartBaseListener and StopBaseListener full cycle
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerAndStopTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    static SocketInterface mockSocketIf = {0};
    mockSocketIf.OpenServerSocket = [](const LocalListenerInfo *info) -> int32_t { return 10; };
    mockSocketIf.GetSockPort = [](int32_t fd) -> int32_t { return 8888; };
    EXPECT_CALL(mock, GetSocketInterface(_)).WillRepeatedly(Return(&mockSocketIf));
    EXPECT_CALL(mock, SoftBusSocketListen(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnShutdownSocket(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, ConnCloseSocket(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, RemoveEvent(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_GT(ret, 0);
    ret = AddTrigger(0, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StopBaseListener(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: AddDelTriggerTest001
 * @tc.desc: test AddTrigger and DelTrigger with all trigger types
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddDelTriggerTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, RemoveEvent(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DelTrigger(module, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, WRITE_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DelTrigger(module, 10, WRITE_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, EXCEPT_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DelTrigger(module, 10, EXCEPT_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: AddDelTriggerTest002
 * @tc.desc: test AddTrigger and DelTrigger with RW_TRIGGER
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddDelTriggerTest002, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, RemoveEvent(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, RW_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DelTrigger(module, 10, RW_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StartBaseListenerWithP2pIpv6Test001
 * @tc.desc: test StartBaseListener with P2P enhanced module and IPv6
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerWithP2pIpv6Test001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    static SocketInterface mockSocketIf = {0};
    mockSocketIf.OpenServerSocket = [](const LocalListenerInfo *info) -> int32_t { return 10; };
    mockSocketIf.GetSockPort = [](int32_t fd) -> int32_t { return 8888; };
    EXPECT_CALL(mock, GetSocketInterface(_)).WillRepeatedly(Return(&mockSocketIf));
    EXPECT_CALL(mock, SoftBusSocketListen(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusSocketSetOpt(_, _, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, GetDomainByAddr(_)).WillRepeatedly(Return(2));
    EXPECT_CALL(mock, ConnShutdownSocket(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    LocalListenerInfo info = {0};
    info.type = CONNECT_P2P;
    info.socketOption.port = 0;
    info.socketOption.moduleId = AUTH_ENHANCED_P2P_START;
    info.socketOption.protocol = LNN_PROTOCOL_IP;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_GT(ret, 0);
}

/*
 * @tc.name: StartBaseListenerWithHmlIpv6Test001
 * @tc.desc: test StartBaseListener with HML type and IPv6
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerWithHmlIpv6Test001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    static SocketInterface mockSocketIf = {0};
    mockSocketIf.OpenServerSocket = [](const LocalListenerInfo *info) -> int32_t { return 10; };
    mockSocketIf.GetSockPort = [](int32_t fd) -> int32_t { return 8888; };
    EXPECT_CALL(mock, GetSocketInterface(_)).WillRepeatedly(Return(&mockSocketIf));
    EXPECT_CALL(mock, SoftBusSocketListen(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusSocketSetOpt(_, _, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, GetDomainByAddr(_)).WillRepeatedly(Return(2));
    EXPECT_CALL(mock, ConnShutdownSocket(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    LocalListenerInfo info = {0};
    info.type = CONNECT_HML;
    info.socketOption.port = 0;
    info.socketOption.moduleId = AUTH_ENHANCED_P2P_START;
    info.socketOption.protocol = LNN_PROTOCOL_IP;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_GT(ret, 0);
}

/*
 * @tc.name: StopBaseListenerWithTriggersTest001
 * @tc.desc: test StopBaseListener with pending triggers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StopBaseListenerWithTriggersTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, RemoveEvent(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnCloseSocket(_)).WillRepeatedly(Return());
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 20, WRITE_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 30, EXCEPT_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StopBaseListener(module);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: TriggerAddDelCycleTest001
 * @tc.desc: test add and delete trigger cycle on same fd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, TriggerAddDelCycleTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, RemoveEvent(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    for (int i = 0; i < 3; i++) {
        ret = AddTrigger(module, 10, READ_TRIGGER);
        EXPECT_EQ(SOFTBUS_OK, ret);
        ret = DelTrigger(module, 10, READ_TRIGGER);
        EXPECT_EQ(SOFTBUS_OK, ret);
    }
}

/*
 * @tc.name: MultipleModuleTest001
 * @tc.desc: test multiple modules with StartBaseClient and triggers
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, MultipleModuleTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, RemoveEvent(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnCloseSocket(_)).WillRepeatedly(Return());
    uint32_t module1 = CreateListenerModule();
    uint32_t module2 = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module1, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StartBaseClient(module2, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module1, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module2, 20, WRITE_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StopBaseListener(module1);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StopBaseListener(module2);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StartBaseListenerWithMemErrTest001
 * @tc.desc: test StartBaseListener with memcpy_s fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerWithMemErrTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusCalloc(_)).WillRepeatedly(Return(nullptr));
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: AddTriggerWithNodeLockFailTest001
 * @tc.desc: test AddTrigger with node lock fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerWithNodeLockFailTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = AddTrigger(0, 1, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
}

/*
 * @tc.name: DelTriggerWithNodeLockFailTest001
 * @tc.desc: test DelTrigger with node lock fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DelTriggerWithNodeLockFailTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = DelTrigger(0, 1, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_LOCK_ERR, ret);
}

/*
 * @tc.name: StopBaseListenerWithServerModeTest001
 * @tc.desc: test StopBaseListener with server mode and listenFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StopBaseListenerWithServerModeTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    static SocketInterface mockSocketIf = {0};
    mockSocketIf.OpenServerSocket = [](const LocalListenerInfo *info) -> int32_t { return 10; };
    mockSocketIf.GetSockPort = [](int32_t fd) -> int32_t { return 8888; };
    EXPECT_CALL(mock, GetSocketInterface(_)).WillRepeatedly(Return(&mockSocketIf));
    EXPECT_CALL(mock, SoftBusSocketListen(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnShutdownSocket(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, ConnCloseSocket(_)).WillRepeatedly(Return());
    EXPECT_CALL(mock, RemoveEvent(_, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_GT(ret, 0);
    ret = AddTrigger(0, 100, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StopBaseListener(0);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/*
 * @tc.name: AddTriggerAfterStopTest001
 * @tc.desc: test AddTrigger after StopBaseListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, AddTriggerAfterStopTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnCloseSocket(_)).WillRepeatedly(Return());
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StopBaseListener(module);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddTrigger(module, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_CONN_FAIL, ret);
}

/*
 * @tc.name: DelTriggerAfterStopTest001
 * @tc.desc: test DelTrigger after StopBaseListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, DelTriggerAfterStopTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConnCloseSocket(_)).WillRepeatedly(Return());
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = StopBaseListener(module);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = DelTrigger(module, 10, READ_TRIGGER);
    EXPECT_EQ(SOFTBUS_NOT_FIND, ret);
}

/*
 * @tc.name: StartBaseListenerWithLockFailTest001
 * @tc.desc: test StartBaseListener with node lock fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StartBaseListenerWithLockFailTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_OK))
        .WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    LocalListenerInfo info = {0};
    info.type = CONNECT_TCP;
    info.socketOption.port = 0;
    info.socketOption.moduleId = 0;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseListener(&info, &listener);
    EXPECT_NE(SOFTBUS_OK, ret);
}

/*
 * @tc.name: StopBaseListenerWithRemoveAbnormalFdLockFailTest001
 * @tc.desc: test StopBaseListener with removeAbnormalFdLock fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BaseListenerUnitTest, StopBaseListenerWithRemoveAbnormalFdLockFailTest001, TestSize.Level1)
{
    NiceMock<BaseListenerTestMock> mock;
    SetupInitMocks(mock);
    InitBaseListener();
    EXPECT_CALL(mock, SoftBusMutexLock(_)).WillRepeatedly(Return(SOFTBUS_ERR));
    EXPECT_CALL(mock, SoftBusMutexUnlock(_)).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t module = CreateListenerModule();
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = MockOnConnectEvent;
    listener.onDataEvent = MockOnDataEvent;
    int32_t ret = StartBaseClient(module, &listener);
    ret = StopBaseListener(module);
    EXPECT_NE(SOFTBUS_OK, ret);
}
} // namespace OHOS
