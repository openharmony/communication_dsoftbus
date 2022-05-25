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

#include "discovery_service.h"

using namespace testing::ext;

#define TEST_ERRO_MOUDULE       ((MODULE_LNN) + 3)

namespace OHOS {
static int g_subscribeId = 0;
static int g_publishId = 0;
static const char *g_pkgName = "Softbus_Kits";
static const char *g_pkgName_1 = "Softbus_Kits_1";
static const char *g_erroPkgName = "Softbus_Erro_Kits";
static const char* g_erroPkgName1 = "ErroErroErroErroErroErroErroErroErroErroErroErroErroErroErroErroEErroE";

const int32_t ERRO_CAPDATA_LEN = 514;

class DiscSdkTestBle : public testing::Test {
public:
    DiscSdkTestBle()
    {}
    ~DiscSdkTestBle()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void DiscSdkTestBle::SetUpTestCase(void)
{}

void DiscSdkTestBle::TearDownTestCase(void)
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

static PublishInfo g_pInfo1 = {
    .publishId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = NULL,
    .dataLen = 0
};

static SubscribeInfo g_sInfo1 = {
    .subscribeId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "hicall",
    .capabilityData = NULL,
    .dataLen = 0
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
 * @tc.name: PublishServiceTest001
 * @tc.desc: Test active publish, verify correct parameter with passive mode and "BLE" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishService and UnPublishService operates normally.
 */
HWTEST_F(DiscSdkTestBle, PublishServiceTest001, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = BLE,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: PublishServiceTest002
 * @tc.desc: Test active publish, verify correct parameter with active mode and "BLE" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishService and UnPublishService operates normally.
 */
HWTEST_F(DiscSdkTestBle, PublishServiceTest002, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StartDiscoveryTest001
 * @tc.desc: Test active discover, verify correct parameter with active mode and "BLE" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery and StopDiscovery operates normally.
 */
HWTEST_F(DiscSdkTestBle, StartDiscoveryTest001, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StartDiscoveryTest002
 * @tc.desc: Test active discover, verify correct parameter with active mode and "BLE" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery and StopDiscovery operates normally.
 */
HWTEST_F(DiscSdkTestBle, StartDiscoveryTest002, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StartDiscoveryTest003
 * @tc.desc: Test passive discover verify correct parameter with passive mode and "BLE" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery and StopDiscovery operates normally.
 */
HWTEST_F(DiscSdkTestBle, StartDiscoveryTest003, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = BLE,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}
} // namespace OHOS
