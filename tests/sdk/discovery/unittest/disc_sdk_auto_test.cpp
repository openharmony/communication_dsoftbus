/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "disc_sdk_test_bt_status.h"
#include "softbus_access_token_test.h"
#include "softbus_errcode.h"

using namespace testing::ext;

namespace OHOS {
static int32_t g_subscribeId = 0;
static int32_t g_publishId = 0;
static const char *g_pkgName = "Softbus_Kits";
static const char *g_pkgName1 = "Softbus_Kits_1";
static const char *g_erroPkgName = "";

class DiscSdkAutoTest : public testing::Test {
public:
    DiscSdkAutoTest()
    {}
    ~DiscSdkAutoTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void DiscSdkAutoTest::SetUpTestCase(void)
{
    SetAceessTokenPermission("DiscTest");
}

void DiscSdkAutoTest::TearDownTestCase(void)
{}

static int32_t GetSubscribeId(void)
{
    g_subscribeId++;
    return g_subscribeId;
}

static int32_t GetPublishId(void)
{
    g_publishId++;
    return g_publishId;
}

static SubscribeInfo g_sInfo = {
    .subscribeId = 1,
    .mode = DISCOVER_MODE_PASSIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata3",
    .dataLen = strlen("capdata3")
};

static PublishInfo g_pInfo = {
    .publishId = 1,
    .mode = DISCOVER_MODE_PASSIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata4",
    .dataLen = strlen("capdata4")
};

static PublishInfo g_pInfo1 = {
    .publishId = 1,
    .mode = DISCOVER_MODE_PASSIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = nullptr,
    .dataLen = 0
};

static SubscribeInfo g_sInfo1 = {
    .subscribeId = 1,
    .mode = DISCOVER_MODE_PASSIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "dvKit",
    .capabilityData = nullptr,
    .dataLen = 0
};

static void TestDeviceFound(const DeviceInfo *device)
{
    printf("[client]TestDeviceFound\n");
}

static void TestDiscoverFailed(int32_t subscribeId, DiscoveryFailReason failReason)
{
    printf("[client]TestDiscoverFailed\n");
}

static void TestDiscoverySuccess(int32_t subscribeId)
{
    printf("[client]TestDiscoverySuccess\n");
}

static void TestPublishSuccess(int32_t publishId)
{
    printf("[client]TestPublishSuccess\n");
}

static void TestPublishFail(int32_t publishId, PublishFailReason reason)
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
 * @tc.desc: Test active publish, verify correct parameter with passive mode and "AUTO" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishService and UnPublishService operates normally.
 */
HWTEST_F(DiscSdkAutoTest, PublishServiceTest001, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    testInfo.freq = MID;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    testInfo.freq = HIGH;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    testInfo.freq = SUPER_HIGH;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: PublishServiceTest002
 * @tc.desc: Test active publish, verify correct parameter with active mode and "AUTO" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishService and UnPublishService operates normally.
 */
HWTEST_F(DiscSdkAutoTest, PublishServiceTest002, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };
    bool isBtOn = SoftbusTestGetBtStatus();
    printf("bt status %s\n", isBtOn ? "on" : "off");

    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    testInfo.freq = MID;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    testInfo.freq = HIGH;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    testInfo.freq = SUPER_HIGH;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
}

/**
 * @tc.name: PublishServiceTest003
 * @tc.desc: Extern module publishuse the same parameter again, perform two subscriptions.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The PublishService operates normally.
 */
HWTEST_F(DiscSdkAutoTest, PublishServiceTest003, TestSize.Level1)
{
    int32_t ret;

    g_pInfo.publishId = GetPublishId();
    ret = PublishService(g_pkgName, &g_pInfo, &g_publishCb);
    ret = PublishService(g_pkgName, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: PublishServiceTest004
 * @tc.desc: Test active publish, use the wrong Medium and Freq Under the AUTO.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The PublishService and UnPublishService operates normally.
 */
HWTEST_F(DiscSdkAutoTest, PublishServiceTest004, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    testInfo.freq = LOW;
}

/**
 * @tc.name: PublishServiceTest005
 * @tc.desc: Test active publish, verify correct parameter with passive mode and "AUTO" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishService and UnPublishService operates normally.
 */
HWTEST_F(DiscSdkAutoTest, PublishServiceTest005, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    testInfo.freq = MID;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    testInfo.freq = HIGH;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    testInfo.freq = SUPER_HIGH;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: PublishServiceTest006
 * @tc.desc: Test active publish, verify correct parameter with active mode and "AUTO" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishService and UnPublishService operates normally.
 */
HWTEST_F(DiscSdkAutoTest, PublishServiceTest006, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };
    bool isBtOn = SoftbusTestGetBtStatus();
    printf("bt status %s\n", isBtOn ? "on" : "off");

    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    testInfo.freq = MID;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    testInfo.freq = HIGH;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    testInfo.freq = SUPER_HIGH;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
}

/**
 * @tc.name: PublishServiceTest007
 * @tc.desc: Verify wrong parameter.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The PublishService and UnPublishService operates normally.
 */
HWTEST_F(DiscSdkAutoTest, PublishServiceTest007, TestSize.Level1)
{
    int32_t ret;
    g_pInfo.publishId = GetPublishId();
    ret = PublishService(g_erroPkgName, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: PublishServiceTest008
 * @tc.desc: Test passive publish, use the wrong Medium and Freq Under the AUTO.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The PublishService and UnPublishService operates normally.
 */
HWTEST_F(DiscSdkAutoTest, PublishServiceTest008, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    testInfo.freq = LOW;
}

/**
 * @tc.name: PublishServiceTest009
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishService and UnPublishService operates normally.
 */
HWTEST_F(DiscSdkAutoTest, PublishServiceTest009, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: PublishServiceTest010
 * @tc.desc: Test active publish, verify correct parameter with active mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishService and UnPublishService operates normally.
 */
HWTEST_F(DiscSdkAutoTest, PublishServiceTest010, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };
    bool isBtOn = SoftbusTestGetBtStatus();
    printf("bt status %s\n", isBtOn ? "on" : "off");

    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = UnPublishService(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: StartDiscoveryTest001
 * @tc.desc: Test active discover, verify correct parameter with active mode and "AUTO" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery and StopDiscovery operates normally.
 */
HWTEST_F(DiscSdkAutoTest, StartDiscoveryTest001, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3")
    };
    bool isBtOn = SoftbusTestGetBtStatus();
    printf("bt status %s\n", isBtOn ? "on" : "off");

    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    testInfo.freq = MID;
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    testInfo.freq = HIGH;
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    testInfo.freq = SUPER_HIGH;
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
}

/**
 * @tc.name: StartDiscoveryTest002
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery and StopDiscovery operates normally.
 */
HWTEST_F(DiscSdkAutoTest, StartDiscoveryTest002, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3")
    };

    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: StartDiscoveryTest003
 * @tc.desc: Test passive discover verify correct parameter with passive mode and "AUTO" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery and StopDiscovery operates normally.
 */
HWTEST_F(DiscSdkAutoTest, StartDiscoveryTest003, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3")
    };

    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    testInfo.freq = MID;
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    testInfo.freq = HIGH;
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    testInfo.freq = SUPER_HIGH;
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: StartDiscoveryTest004
 * @tc.desc:Test extern module active discoveruse wrong Medium and Freq Under the AUTO.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery operates normally.
 */
HWTEST_F(DiscSdkAutoTest, StartDiscoveryTest004, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3")
    };

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    testInfo.freq = LOW;
}

/**
 * @tc.name: StartDiscoveryTest005
 * @tc.desc: Test active publish, verify correct parameter with active mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery and StopDiscovery operates normally.
 */
HWTEST_F(DiscSdkAutoTest, StartDiscoveryTest005, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3")
    };
    bool isBtOn = SoftbusTestGetBtStatus();
    printf("bt status %s\n", isBtOn ? "on" : "off");

    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: UnPublishService
 * @tc.desc: Extern module stop publishuse the wrong parameter.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The UnPublishService operates normally.
 */
HWTEST_F(DiscSdkAutoTest, UnPublishServiceTest001, TestSize.Level1)
{
    int32_t ret;
    int32_t tmpId = GetPublishId();

    g_pInfo.publishId = tmpId;
    PublishService(g_pkgName, &g_pInfo, &g_publishCb);

    ret = UnPublishService(nullptr, tmpId);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = UnPublishService(g_erroPkgName, tmpId);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = UnPublishService(g_pkgName1, tmpId);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: UnPublishServiceTest002
 * @tc.desc: Extern module stop publishuse the normal parameter.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The UnPublishService operates normally.
 */
HWTEST_F(DiscSdkAutoTest, UnPublishServiceTest002, TestSize.Level1)
{
    int32_t ret;
    int32_t tmpId1 = GetPublishId();
    int32_t tmpId2 = GetPublishId();
    g_pInfo.publishId = tmpId1;
    PublishService(g_pkgName, &g_pInfo, &g_publishCb);
    g_pInfo1.publishId = tmpId2;
    PublishService(g_pkgName, &g_pInfo1, &g_publishCb);

    ret = UnPublishService(g_pkgName, tmpId1);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = UnPublishService(g_pkgName, tmpId2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: UnPublishServiceTest003
 * @tc.desc: Extern module stop publishrelease the same parameter again, perform two subscriptions.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The UnPublishService operates normally.
 */
HWTEST_F(DiscSdkAutoTest, UnPublishServiceTest003, TestSize.Level1)
{
    int32_t ret;
    int32_t tmpId = GetPublishId();

    g_pInfo.publishId = tmpId;
    PublishService(g_pkgName, &g_pInfo, &g_publishCb);

    ret = UnPublishService(g_pkgName, tmpId);
    ret = UnPublishService(g_pkgName, tmpId);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: UnPublishServiceTest004
 * @tc.desc: Extern module stop publish, use the normal parameter and different frequencies under active AUTO.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The UnPublishService operates normally.
 */
HWTEST_F(DiscSdkAutoTest, UnPublishServiceTest004, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };
    bool isBtOn = SoftbusTestGetBtStatus();
    printf("bt status %s\n", isBtOn ? "on" : "off");

    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    testInfo.freq = MID;
    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    testInfo.freq = HIGH;
    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    testInfo.freq = SUPER_HIGH;
    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
}

/**
 * @tc.name: UnPublishServiceTest005
 * @tc.desc: Extern module stop publish, use the normal parameter and different frequencies under passive AUTO.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The UnPublishService operates normally.
 */
HWTEST_F(DiscSdkAutoTest, UnPublishServiceTest005, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    testInfo.freq = MID;
    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    testInfo.freq = HIGH;
    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    testInfo.freq = SUPER_HIGH;
    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: UnPublishServiceTest006
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The UnPublishService operates normally.
 */
HWTEST_F(DiscSdkAutoTest, UnPublishServiceTest006, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: UnPublishServiceTest007
 * @tc.desc: Test active publish, verify correct parameter with active mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The UnPublishService operates normally.
 */
HWTEST_F(DiscSdkAutoTest, UnPublishServiceTest007, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };
    bool isBtOn = SoftbusTestGetBtStatus();
    printf("bt status %s\n", isBtOn ? "on" : "off");

    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = UnPublishService(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: StopDiscoveryTest001
 * @tc.desc: Extern module stop discoveruse the wrong parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The StopDiscovery operates normally
 */
HWTEST_F(DiscSdkAutoTest, StopDiscoveryTest001, TestSize.Level1)
{
    int32_t ret;
    int32_t tmpId = GetSubscribeId();

    g_sInfo.subscribeId = tmpId;
    StartDiscovery(g_pkgName, &g_sInfo, &g_subscribeCb);

    ret = StopDiscovery(nullptr, tmpId);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = StopDiscovery(g_erroPkgName, tmpId);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = StopDiscovery(g_pkgName1, tmpId);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: StopDiscoveryTest002
 * @tc.desc: Extern module stop discoveruse the normal parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StopDiscovery operates normally
 */
HWTEST_F(DiscSdkAutoTest, StopDiscoveryTest002, TestSize.Level1)
{
    int32_t ret;
    int32_t tmpId1 = GetSubscribeId();
    int32_t tmpId2 = GetSubscribeId();

    g_sInfo.subscribeId = tmpId1;
    StartDiscovery(g_pkgName, &g_sInfo, &g_subscribeCb);
    g_sInfo1.subscribeId = tmpId2;
    StartDiscovery(g_pkgName, &g_sInfo1, &g_subscribeCb);

    ret = StopDiscovery(g_pkgName, tmpId1);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = StopDiscovery(g_pkgName, tmpId2);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: StopDiscoveryTest003
 * @tc.desc: Extern module stop discoverrelease the same parameter again, perform two subscriptions.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StopDiscovery operates normally
 */
HWTEST_F(DiscSdkAutoTest, StopDiscoveryTest003, TestSize.Level1)
{
    int32_t ret;
    int32_t tmpId = GetSubscribeId();

    g_sInfo.subscribeId = tmpId;
    StartDiscovery(g_pkgName, &g_sInfo, &g_subscribeCb);

    ret = StopDiscovery(g_pkgName, tmpId);
    ret = StopDiscovery(g_pkgName, tmpId);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: StopDiscoveryTest004
 * @tc.desc:Test extern module stop active discover, use Diff Freq Under the AUTO.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The StopDiscovery operates normally
 */
HWTEST_F(DiscSdkAutoTest, StopDiscoveryTest004, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3")
    };
    bool isBtOn = SoftbusTestGetBtStatus();
    printf("bt status %s\n", isBtOn ? "on" : "off");

    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    testInfo.freq = MID;
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    testInfo.freq = HIGH;
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    testInfo.freq = SUPER_HIGH;
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
}

/**
 * @tc.name: StopDiscoveryTest005
 * @tc.desc:Test extern module stop passive discover, use Diff Freq Under the AUTO.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StopDiscovery operates normally
 */
HWTEST_F(DiscSdkAutoTest, StopDiscoveryTest005, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3")
    };
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    testInfo.freq = MID;
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    testInfo.freq = HIGH;
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    testInfo.freq = SUPER_HIGH;
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/**
 * @tc.name: StopDiscoveryTest006
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:The StopDiscovery operates normally
 */
HWTEST_F(DiscSdkAutoTest, StopDiscoveryTest006, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3")
    };

    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name:StopDiscoveryTest007
 * @tc.desc: Test active publish, verify correct parameter with active mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:The StopDiscovery operates normally
 */
HWTEST_F(DiscSdkAutoTest, StopDiscoveryTest007, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3")
    };
    bool isBtOn = SoftbusTestGetBtStatus();
    printf("bt status %s\n", isBtOn ? "on" : "off");

    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
}
} // namespace OHOS
