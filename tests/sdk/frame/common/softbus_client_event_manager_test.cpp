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
#include <securec.h>
#include <gtest/gtest.h>

#include "softbus_adapter_mem.h"
#include "softbus_client_event_manager.c"
#include "softbus_client_frame_manager.h"
#include "softbus_error_code.h"

#define protected public
#define private public
#include "softbus_client_frame_manager.c"
#undef private
#undef protected

using namespace std;
using namespace testing::ext;

namespace OHOS {
#define FRAME_HEADER_LEN 4

class SoftbusClientEventManagerTest : public testing::Test {
public:
    SoftbusClientEventManagerTest()
    {}
    ~SoftbusClientEventManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    static int32_t OnEventCallback(void *arg, unsigned int argLen, void *userData)
    {
        return 0;
    }
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void SoftbusClientEventManagerTest::SetUpTestCase(void)
{}

void SoftbusClientEventManagerTest::TearDownTestCase(void)
{}

/**
 * @tc.name: EventClientInit001
 * @tc.desc: EventClientInit, use the wrong parameter.
 * @tc.desc: EventClientDeinit, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusClientEventManagerTest, EventClientInit001, TestSize.Level1)
{
    EventClientDeinit();
    int32_t ret = EventClientInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    EventClientDeinit();
}

/**
 * @tc.name: EventClientInit002
 * @tc.desc: EventClientInit, use the wrong parameter.
 * @tc.desc: EventClientDeinit, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusClientEventManagerTest, EventClientInit002, TestSize.Level1)
{
    int32_t ret = EventClientInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = EventClientInit(); // test is inited
    EXPECT_EQ(SOFTBUS_OK, ret);

    EventClientDeinit();
}

/**
 * @tc.name: EventClientInit003
 * @tc.desc: EventClientInit, use the wrong parameter.
 * @tc.desc: EventClientDeinit, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusClientEventManagerTest, EventClientInit003, TestSize.Level1)
{
    ASSERT_TRUE(nullptr == g_observerList);
    g_observerList = CreateSoftBusList();
    int32_t ret = EventClientInit();
    EXPECT_EQ(SOFTBUS_OK, ret);
    EventClientDeinit();
}

/**
 * @tc.name: RegisterEventCallback001
 * @tc.desc: RegisterEventCallback, use the wrong parameter.
 * @tc.desc: CLIENT_NotifyObserver, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusClientEventManagerTest, RegisterEventCallback001, TestSize.Level1)
{
    EventCallback *cb =
        (EventCallback *)SoftBusCalloc(sizeof(EventCallback));
    ASSERT_TRUE(cb != nullptr);

    std::unique_ptr<char[]> data = nullptr;
    ssize_t len = 2;
    data = std::make_unique<char[]>(len + FRAME_HEADER_LEN);

    int32_t res = -1;
    int32_t ret = RegisterEventCallback((enum SoftBusEvent)res, *cb, data.get() + FRAME_HEADER_LEN);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    res = 4;
    ret = RegisterEventCallback((enum SoftBusEvent)res, *cb, data.get() + FRAME_HEADER_LEN);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
    res = 1;
    ret = RegisterEventCallback(EVENT_SERVER_DEATH, NULL, data.get() + FRAME_HEADER_LEN);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);


    ret = RegisterEventCallback((enum SoftBusEvent)res, *cb, data.get() + FRAME_HEADER_LEN);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    unsigned int argLen = 2;
    CLIENT_NotifyObserver((enum SoftBusEvent)res, data.get() + FRAME_HEADER_LEN, argLen);

    CLIENT_NotifyObserver(EVENT_SERVER_DEATH, data.get() + FRAME_HEADER_LEN, argLen);

    enum SoftBusEvent event = SoftBusEvent::EVENT_SERVER_DEATH;
    CLIENT_NotifyObserver(event, data.get() + FRAME_HEADER_LEN, argLen);

    ret = EventClientInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    CLIENT_NotifyObserver(event, data.get() + FRAME_HEADER_LEN, argLen);

    event = SoftBusEvent::EVENT_BUTT;
    CLIENT_NotifyObserver(event, data.get() + FRAME_HEADER_LEN, argLen);

    if (cb != nullptr) {
        SoftBusFree(cb);
    }
}

/**
 * @tc.name: RegisterEventCallback002
 * @tc.desc: RegisterEventCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusClientEventManagerTest, RegisterEventCallback002, TestSize.Level1)
{
    EventCallback cb = SoftbusClientEventManagerTest::OnEventCallback;

    enum SoftBusEvent event = EVENT_SERVER_RECOVERY;
    const ssize_t len = 2;
    std::unique_ptr<char[]> data = std::make_unique<char[]>(len + FRAME_HEADER_LEN);
    ASSERT_TRUE(data != nullptr);

    EventClientDeinit();
    int32_t ret = RegisterEventCallback(event, cb, data.get() + FRAME_HEADER_LEN);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    ret = EventClientInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = RegisterEventCallback(event, cb, data.get());
    EXPECT_EQ(SOFTBUS_OK, ret);

    unsigned int argLen = 2;
    CLIENT_NotifyObserver(event, data.get() + FRAME_HEADER_LEN, argLen);
}

/**
 * @tc.name: RegisterEventCallback003
 * @tc.desc: RegisterEventCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusClientEventManagerTest, RegisterEventCallback003, TestSize.Level1)
{
    EventCallback cb = SoftbusClientEventManagerTest::OnEventCallback;

    enum SoftBusEvent event = EVENT_SERVER_RECOVERY;
    const ssize_t len = 2;
    std::unique_ptr<char[]> data = std::make_unique<char[]>(len + FRAME_HEADER_LEN);
    ASSERT_TRUE(data != nullptr);

    EventClientDeinit();
    int32_t ret = RegisterEventCallback(event, cb, data.get() + FRAME_HEADER_LEN);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    ret = EventClientInit();
    EXPECT_EQ(SOFTBUS_OK, ret);

    ret = RegisterEventCallback(event, cb, data.get());
    EXPECT_EQ(SOFTBUS_OK, ret);

    g_observerList->cnt = MAX_OBSERVER_CNT;
    ret = RegisterEventCallback(event, cb, data.get());
    EXPECT_EQ(SOFTBUS_TRANS_OBSERVER_EXCEED_LIMIT, ret);
}

/**
 * @tc.name: DelClientPkgName001
 * @tc.desc: DelClientPkgName, use the wrong parameter.
 * @tc.desc: EventClientDeinit, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusClientEventManagerTest, DelClientPkgName001, TestSize.Level1)
{
    const char *pkgName = "000";
    int32_t ret = InitSoftBus(NULL);
    EXPECT_EQ(SOFTBUS_INVALID_PKGNAME, ret);

    ret = InitSoftBus(pkgName);
    EXPECT_EQ(SOFTBUS_NO_INIT, ret);

    char *clientName[SOFTBUS_PKGNAME_MAX_NUM] = {0};
    uint32_t clientNameNum = GetSoftBusClientNameList(NULL, SOFTBUS_PKGNAME_MAX_NUM);
    EXPECT_EQ(0, clientNameNum);
    clientNameNum = GetSoftBusClientNameList(clientName, 0);
    EXPECT_EQ(0, clientNameNum);

    clientNameNum = GetSoftBusClientNameList(clientName, SOFTBUS_PKGNAME_MAX_NUM);
    EXPECT_EQ(0, clientNameNum);
}

/**
 * @tc.name: CheckPackageName001
 * @tc.desc: CheckPackageName, use the wrong parameter.
 * @tc.desc: EventClientDeinit, use the wrong parameter.
 * @tc.desc: AddClientPkgName, number of pkgName exceeds maximum.
 * @tc.desc: DelClientPkgName
 * @tc.desc: FreeClientPkgName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusClientEventManagerTest, CheckPackageName001, TestSize.Level1)
{
    const char *pkgName = "000";

    const char *tmpPkgName = "000111";
    int32_t ret = CheckPackageName(tmpPkgName);
    EXPECT_EQ(SOFTBUS_INVALID_PKGNAME, ret);

    FreeClientPkgName();
    ret = AddClientPkgName(pkgName);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = AddClientPkgName(pkgName);
    EXPECT_EQ(SOFTBUS_INVALID_PKGNAME, ret);

    DelClientPkgName(pkgName);
    FreeClientPkgName();
}

/**
 * @tc.name: ConnClientDeinitTest001
 * @tc.desc: ClientModuleDeinit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusClientEventManagerTest, ConnClientDeinitTest001, TestSize.Level1)
{
    ConnClientDeinit();
    ClientModuleDeinit();
    EXPECT_TRUE(1);
}
} // OHOS
