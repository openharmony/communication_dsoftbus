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

#include "softbus_client_event_manager.h"
#include "softbus_client_frame_manager.h"
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"

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
    int ret = EventClientInit();
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

    int res = -1;
    int ret = RegisterEventCallback((enum SoftBusEvent)res, *cb, data.get() + FRAME_HEADER_LEN);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    res = 4;
    ret = RegisterEventCallback((enum SoftBusEvent)res, *cb, data.get() + FRAME_HEADER_LEN);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    res = 1;
    ret = RegisterEventCallback(EVENT_SERVER_DEATH, NULL, data.get() + FRAME_HEADER_LEN);
    EXPECT_EQ(SOFTBUS_ERR, ret);


    ret = RegisterEventCallback((enum SoftBusEvent)res, *cb, data.get() + FRAME_HEADER_LEN);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    unsigned int argLen = 2;
    CLIENT_NotifyObserver((enum SoftBusEvent)res, data.get() + FRAME_HEADER_LEN, argLen);

    res = 4;
    CLIENT_NotifyObserver(EVENT_SERVER_DEATH, data.get() + FRAME_HEADER_LEN, argLen);

    if (cb != nullptr) {
        SoftBusFree(cb);
    }
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
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    ret = InitSoftBus(pkgName);
    EXPECT_EQ(SOFTBUS_OK, ret);

    char *clientName[SOFTBUS_PKGNAME_MAX_NUM] = {0};
    uint32_t clientNameNum = GetSoftBusClientNameList(NULL, SOFTBUS_PKGNAME_MAX_NUM);
    EXPECT_EQ(0, clientNameNum);
    clientNameNum = GetSoftBusClientNameList(clientName, 0);
    EXPECT_EQ(0, clientNameNum);

    clientNameNum = GetSoftBusClientNameList(clientName, SOFTBUS_PKGNAME_MAX_NUM);
    EXPECT_NE(0, clientNameNum);
}

/**
 * @tc.name: CheckPackageName001
 * @tc.desc: CheckPackageName, use the wrong parameter.
 * @tc.desc: EventClientDeinit, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusClientEventManagerTest, CheckPackageName001, TestSize.Level1)
{
    const char *pkgName = "000";
    int ret = CheckPackageName(pkgName);
    EXPECT_EQ(SOFTBUS_OK, ret);

    const char *tmpPkgName = "000111";
    ret = CheckPackageName(tmpPkgName);
    EXPECT_EQ(SOFTBUS_INVALID_PKGNAME, ret);

    ret = CheckPackageName(pkgName);
    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // OHOS
