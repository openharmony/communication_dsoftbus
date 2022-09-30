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

#include <cstdio>
#include <ctime>
#include <gtest/gtest.h>
#include <sys/time.h>
#include <unistd.h>

#include "softbus_access_token_test.h"
#include "discovery_service.h"

using namespace testing::ext;

#define TEST_ERRO_MOUDULE       ((MODULE_LNN) + 3)

namespace OHOS {
static int g_subscribeId = 0;
static int g_publishId = 0;
static const char *g_pkgName = "Softbus_Kits";

class DiscSdkOnlyL2Test : public testing::Test {
public:
    DiscSdkOnlyL2Test()
    {}
    ~DiscSdkOnlyL2Test()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void DiscSdkOnlyL2Test::SetUpTestCase(void)
{
    SetAceessTokenPermission("discSdkOnlyL2Test");
}

void DiscSdkOnlyL2Test::TearDownTestCase(void)
{}

static int GetSubscribeId(void)
{
    g_subscribeId++;
    return g_subscribeId;
}

static int GetPublishId(void)
{
    g_publishId++;
    return g_publishId;
}

static SubscribeInfo g_sInfo = {
    .subscribeId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata3",
    .dataLen = sizeof("capdata3")
};

static PublishInfo g_pInfo = {
    .publishId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata4",
    .dataLen = sizeof("capdata4")
};

static void TestDeviceFound(const DeviceInfo *device)
{
    printf("[client]TestDeviceFound\n");
}

static void TestDiscoverFailed(int subscribeId, DiscoveryFailReason failReason)
{
    printf("[client]TestDiscoverFailed\n");
}

static void TestDiscoverySuccess(int subscribeId)
{
    printf("[client]TestDiscoverySuccess\n");
}

static void TestPublishSuccess(int publishId)
{
    printf("[client]TestPublishSuccess\n");
}

static void TestPublishFail(int publishId, PublishFailReason reason)
{
    printf("[client]TestPublishFail\n");
}

static IDiscoveryCallback g_subscribeCb = {
    .OnDeviceFound = TestDeviceFound,
    .OnDiscoverFailed = TestDiscoverFailed,
    .OnDiscoverySuccess = TestDiscoverySuccess
};

static IPublishCallback g_publishCb = {
    .OnPublishSuccess = TestPublishSuccess,
    .OnPublishFail = TestPublishFail
};

/**
 * @tc.name: UnPublishServiceTest004
 * @tc.desc: not start publish.
 * @tc.in: Test Moudle, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The UnPublishService operates normally.
 */
HWTEST_F(DiscSdkOnlyL2Test, UnPublishServiceTest001, TestSize.Level2)
{
    int ret;
    int tmpId = GetPublishId();

    ret = UnPublishService(g_pkgName, tmpId);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: UnPublishServiceTest005
 * @tc.desc: Verify UnPublishService again.
 * @tc.in: Test Moudle, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The UnPublishService operates normally.
 */
HWTEST_F(DiscSdkOnlyL2Test, UnPublishServiceTest002, TestSize.Level2)
{
    int ret;
    int tmpId = GetPublishId();

    g_pInfo.publishId = tmpId;
    PublishService(g_pkgName, &g_pInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, tmpId);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, tmpId);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: StopDiscoveryTest004
 * @tc.desc: not start discover.
 * @tc.in: Test Moudle, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StopDiscovery operates normally.
 */
HWTEST_F(DiscSdkOnlyL2Test, StopDiscoveryTest001, TestSize.Level2)
{
    int ret;
    int tmpId = GetSubscribeId();

    ret = StopDiscovery(g_pkgName, tmpId);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: StopDiscoveryTest005
 * @tc.desc: Verify StopDiscovery again.
 * @tc.in: Test Moudle, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StopDiscovery operates normally.
 */
HWTEST_F(DiscSdkOnlyL2Test, StopDiscoveryTest002, TestSize.Level2)
{
    int ret;
    int tmpId = GetSubscribeId();

    g_sInfo.subscribeId = tmpId;
    StartDiscovery(g_pkgName, &g_sInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, tmpId);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, tmpId);
    EXPECT_TRUE(ret != 0);
}
} // namespace OHOS
