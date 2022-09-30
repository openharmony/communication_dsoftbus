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
static const char *g_pkgName_1 = "Softbus_Kits_1";
static const char *g_erroPkgName = "Softbus_Erro_Kits";
static const char* g_erroPkgName1 = "ErroErroErroErroErroErroErroErroErroErroErroErroErroErroErroErroEErroE";

const int32_t ERRO_CAPDATA_LEN = 514;

class Disc_Test : public testing::Test {
public:
    Disc_Test()
    {}
    ~Disc_Test()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void Disc_Test::SetUpTestCase(void)
{
    SetAceessTokenPermission("discTest");
}

void Disc_Test::TearDownTestCase(void)
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
 * @tc.desc: Test for wrong parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, PublishServiceTest001, TestSize.Level0)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    ret = PublishService(NULL, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);

    ret = PublishService(g_pkgName, NULL, &g_publishCb);
    EXPECT_TRUE(ret != 0);

    ret = PublishService(g_pkgName, &testInfo, NULL);
    EXPECT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.mode = DISCOVER_MODE_ACTIVE;

    testInfo.freq = (ExchangeFreq)(SUPER_HIGH + 1);
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capabilityData = NULL;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.dataLen = sizeof("capdata1");
}

/**
 * @tc.name: PublishServiceTest002
 * @tc.desc: Test GetPublishId and PublishService to see if they are running properly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, PublishServiceTest002, TestSize.Level0)
{
    int ret;

    g_pInfo.publishId = GetPublishId();
    ret = PublishService(g_pkgName, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, g_pInfo.publishId);

    g_pInfo1.publishId = GetPublishId();
    ret = PublishService(g_pkgName, &g_pInfo1, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, g_pInfo1.publishId);

    g_pInfo1.publishId = GetPublishId();
    ret = PublishService(g_pkgName_1, &g_pInfo1, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, g_pInfo1.publishId);
}

/**
 * @tc.name: PublishServiceTest003
 * @tc.desc: Verify same parameter again
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, PublishServiceTest003, TestSize.Level0)
{
    int ret;

    g_pInfo.publishId = GetPublishId();
    ret = PublishService(g_pkgName, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, g_pInfo.publishId);
}

/**
 * @tc.name: PublishServiceTest004
 * @tc.desc: Test active publish, verify correct parameter with active mode and "COAP" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishService and UnPublishService operates normally.
 */
HWTEST_F(Disc_Test, PublishServiceTest004, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
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
 * @tc.name: PublishServiceTest005
 * @tc.desc: Test passive publish, verify correct parameter with passive mode and "AUTO" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishService and UnPublishService operates normally.
 */
HWTEST_F(Disc_Test, PublishServiceTest005, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
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
 * @tc.name: PublishServiceTest006
 * @tc.desc: Test passive publish, verify correct parameter with passive mode and "COAP" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishService and UnPublishService operates normally.
 */
HWTEST_F(Disc_Test, PublishServiceTest006, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
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
 * @tc.name: PublishServiceTest007
 * @tc.desc: Verify wrong parameter.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require:The PublishService operates normally.
 */
HWTEST_F(Disc_Test, PublishServiceTest007, TestSize.Level1)
{
    int ret;
    g_pInfo.publishId = GetPublishId();
    ret = PublishService(g_erroPkgName1, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: PublishServiceTest008
 * @tc.desc: Test active publish, verify wrong parameter with active mode and "COAP" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require:The PublishService operates normally.
 */
HWTEST_F(Disc_Test, PublishServiceTest008, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char*)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;
}
/**
 * @tc.name: PublishServiceTest009
 * @tc.desc: Test active publish, verify wrong parameter with active mode and "BLE" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require:The PublishService operates normally.
 */
HWTEST_F(Disc_Test, PublishServiceTest009, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char*)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = BLE;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;
}

/**
 * @tc.name: PublishServiceTest010
 * @tc.desc: Test active publish, verify wrong parameter with active mode and "AUTO" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require:The PublishService operates normally.
 */
HWTEST_F(Disc_Test, PublishServiceTest010, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char*)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = AUTO;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;
}

/**
 * @tc.name: PublishServiceTest011
 * @tc.desc: Test passive publish, verify wrong parameter with active mode and "COAP" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require:The PublishService operates normally.
 */
HWTEST_F(Disc_Test, PublishServiceTest011, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char*)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;
}

/**
 * @tc.name: PublishServiceTest012
 * @tc.desc: Test passive publish, verify wrong parameter with active mode and "AUTO" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require:The PublishService operates normally.
 */
HWTEST_F(Disc_Test, PublishServiceTest012, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char*)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = AUTO;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;
}

/**
 * @tc.name: PublishServiceTest013
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"COAP" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishService and UnPublishService operates normally.
 */
HWTEST_F(Disc_Test, PublishServiceTest013, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "hicall";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "profile";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "homevisionPic";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "castPlus";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "aaCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "ddmpCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: PublishServiceTest014
 * @tc.desc: Test active publish, verify correct parameter with active mode,"COAP" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishService and UnPublishService operates normally.
 */
HWTEST_F(Disc_Test, PublishServiceTest014, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "hicall";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "profile";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "homevisionPic";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "castPlus";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "aaCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "ddmpCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: PublishServiceTest015
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishService and UnPublishService operates normally.
 */
HWTEST_F(Disc_Test, PublishServiceTest015, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "hicall";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "profile";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "homevisionPic";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "castPlus";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "aaCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "ddmpCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: PublishServiceTest016
 * @tc.desc: Test active publish, verify correct parameter with active mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishService and UnPublishService operates normally.
 */
HWTEST_F(Disc_Test, PublishServiceTest016, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "hicall";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "profile";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "homevisionPic";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "castPlus";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "aaCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "ddmpCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: StartDiscoveryTest001
 * @tc.desc: Verify statrtdiscovery wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, StartDiscoveryTest001, TestSize.Level0)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    ret = StartDiscovery(NULL, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret != 0);

    ret = StartDiscovery(g_pkgName, NULL, &g_subscribeCb);
    EXPECT_TRUE(ret != 0);

    ret = StartDiscovery(g_pkgName, &testInfo, NULL);
    EXPECT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret != 0);
    testInfo.mode = DISCOVER_MODE_ACTIVE;

    testInfo.freq = (ExchangeFreq)(SUPER_HIGH + 1);
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capabilityData = NULL;
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret != 0);
    testInfo.dataLen = sizeof("capdata1");
}

/**
 * @tc.name: StartDiscoveryTest002
 * @tc.desc: Verify the StartDiscovery error parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, StartDiscoveryTest002, TestSize.Level0)
{
    int ret;
    g_sInfo.subscribeId = GetSubscribeId();
    ret = StartDiscovery(g_pkgName, &g_sInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, g_sInfo.subscribeId);

    g_sInfo1.subscribeId = GetSubscribeId();
    ret = StartDiscovery(g_pkgName, &g_sInfo1, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, g_sInfo1.subscribeId);

    g_sInfo1.subscribeId = GetSubscribeId();
    ret = StartDiscovery(g_pkgName_1, &g_sInfo1, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, g_sInfo1.subscribeId);
}

/**
 * @tc.name: StartDiscoveryTest003
 * @tc.desc: Verify startdiscovery same parameter again
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, StartDiscoveryTest003, TestSize.Level0)
{
    int ret;

    g_sInfo.subscribeId = GetSubscribeId();
    ret = StartDiscovery(g_pkgName, &g_sInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, g_sInfo.subscribeId);
}

/**
 * @tc.name: StartDiscoveryTest004
 * @tc.desc: Test active discover, verify correct parameter with active mode and "AUTO" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery and StopDiscovery operates normally.
 */
HWTEST_F(Disc_Test, StartDiscoveryTest004, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
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
 * @tc.name: StartDiscoveryTest005
 * @tc.desc: Test passive discover verify correct parameter with passive mode and "COAP" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery and StopDiscovery operates normally.
 */
HWTEST_F(Disc_Test, StartDiscoveryTest005, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
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
 * @tc.name: StartDiscoveryTest006
 * @tc.desc: Test passive discover, verify correct parameter with passive mode and "AUTO" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery and StopDiscovery operates normally.
 */
HWTEST_F(Disc_Test, StartDiscoveryTest006, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
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
 * @tc.name: StartDiscoveryTest007
 * @tc.desc: Test passive discover verify correct parameter with passive mode and "COAP" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery and StopDiscovery operates normally.
 */
HWTEST_F(Disc_Test, StartDiscoveryTest007, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
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
 * @tc.name: StartDiscoveryTest008
 * @tc.desc: Test passive discover verify correct parameter with active mode and "COAP" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery and StopDiscovery operates normally.
 */
HWTEST_F(Disc_Test, StartDiscoveryTest008, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
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
 * @tc.name: StartDiscoveryTest009
 * @tc.desc: Test passive discover, verify correct parameter with passive mode and "AUTO" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery and StopDiscovery operates normally.
 */
HWTEST_F(Disc_Test, StartDiscoveryTest009, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
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
 * @tc.name: StartDiscoveryTest010
 * @tc.desc:  Test extern module passive discoveruse wrong Medium and Freq Under the COAP.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery and StopDiscovery operates normally.
 */
HWTEST_F(Disc_Test, StartDiscoveryTest010, TestSize.Level0)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;
}

/**
 * @tc.name: StartDiscoveryTest011
 * @tc.desc:  Test extern module passive discoveruse wrong Medium and Freq Under the AUTO.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery and StopDiscovery operates normally.
 */
HWTEST_F(Disc_Test, StartDiscoveryTest011, TestSize.Level0)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;
}

/**
 * @tc.name: StartDiscoveryTest012
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"COAP" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery and StopDiscovery operates normally.
 */
HWTEST_F(Disc_Test, StartDiscoveryTest012, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
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

    testInfo.capability = "hicall";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "profile";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "homevisionPic";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "castPlus";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "aaCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "ddmpCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: StartDiscoveryTest013
 * @tc.desc: Test active publish, verify correct parameter with active mode,"COAP" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery and StopDiscovery operates normally.
 */
HWTEST_F(Disc_Test, StartDiscoveryTest013, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
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

    testInfo.capability = "hicall";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "profile";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "homevisionPic";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "castPlus";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "aaCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "ddmpCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: StartDiscoveryTest014
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery and StopDiscovery operates normally.
 */
HWTEST_F(Disc_Test, StartDiscoveryTest014, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
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

    testInfo.capability = "hicall";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "profile";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "homevisionPic";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "castPlus";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "aaCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "ddmpCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: StartDiscoveryTest015
 * @tc.desc: Test active publish, verify correct parameter with active mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StartDiscovery and StopDiscovery operates normally.
 */
HWTEST_F(Disc_Test, StartDiscoveryTest015, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
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

    testInfo.capability = "hicall";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "profile";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "homevisionPic";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "castPlus";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "aaCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "ddmpCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: UnPublishServiceTest001
 * @tc.desc: Verify unpublishservice wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, UnPublishServiceTest001, TestSize.Level0)
{
    int ret;
    int tmpId = GetPublishId();

    g_pInfo.publishId = tmpId;
    PublishService(g_pkgName, &g_pInfo, &g_publishCb);
    ret = UnPublishService(NULL, tmpId);
    EXPECT_TRUE(ret != 0);
    ret = UnPublishService(g_erroPkgName, tmpId);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: UnPublishServiceTest002
 * @tc.desc: Verify publishservice and unpublishservice normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, UnPublishServiceTest002, TestSize.Level0)
{
    int ret;
    int tmpId1 = GetPublishId();
    int tmpId2 = GetPublishId();

    g_pInfo.publishId = tmpId1;
    PublishService(g_pkgName, &g_pInfo, &g_publishCb);
    g_pInfo1.publishId = tmpId2;
    PublishService(g_pkgName, &g_pInfo1, &g_publishCb);
    ret = UnPublishService(g_pkgName, tmpId1);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, tmpId2);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: UnPublishServiceTest003
 * @tc.desc: Verify publishservice and unpublishservice same parameter again.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, UnPublishServiceTest003, TestSize.Level0)
{
    int ret;
    int tmpId = GetPublishId();

    g_pInfo.publishId = tmpId;
    PublishService(g_pkgName, &g_pInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, tmpId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: UnPublishServiceTest004
 * @tc.desc: Extern module stop publish, use the normal parameter and different frequencies under active COAP.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The UnPublishService operates normally.
 */
HWTEST_F(Disc_Test, UnPublishServiceTest004, TestSize.Level0)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: UnPublishServiceTest005
 * @tc.desc: Extern module stop publish, use the normal parameter and different frequencies under passive COAP.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The UnPublishService operates normally.
 */
HWTEST_F(Disc_Test, UnPublishServiceTest005, TestSize.Level0)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: UnPublishServiceTest006
 * @tc.desc: Extern module stop publish, use the normal parameter and different frequencies under active AUTO.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The UnPublishService operates normally.
 */
HWTEST_F(Disc_Test, UnPublishServiceTest006, TestSize.Level0)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: UnPublishServiceTest007
 * @tc.desc: Extern module stop publish, use the normal parameter and different frequencies under passive AUTO.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The UnPublishService operates normally.
 */
HWTEST_F(Disc_Test, UnPublishServiceTest007, TestSize.Level0)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    PublishService(g_pkgName, &testInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: UnPublishServiceTest008
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"COAP" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The UnPublishService operates normally.
 */
HWTEST_F(Disc_Test, UnPublishServiceTest008, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "hicall";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "profile";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "homevisionPic";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "castPlus";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "aaCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "ddmpCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: UnPublishServiceTest009
 * @tc.desc: Test active publish, verify correct parameter with active mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The UnPublishService operates normally.
 */
HWTEST_F(Disc_Test, UnPublishServiceTest009, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "hicall";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "profile";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "homevisionPic";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "castPlus";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "aaCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "ddmpCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: UnPublishServiceTest010
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The UnPublishService operates normally.
 */
HWTEST_F(Disc_Test, UnPublishServiceTest010, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "hicall";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "profile";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "homevisionPic";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "castPlus";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "aaCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "ddmpCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: UnPublishServiceTest011
 * @tc.desc: Test active publish, verify correct parameter with active mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The UnPublishService operates normally.
 */
HWTEST_F(Disc_Test, UnPublishServiceTest011, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "hicall";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "profile";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "homevisionPic";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "castPlus";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "aaCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "ddmpCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: StopDiscoveryTest001
 * @tc.desc: Verify stopdiscovery wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, StopDiscoveryTest001, TestSize.Level0)
{
    int ret;
    int tmpId = GetSubscribeId();

    g_sInfo.subscribeId = tmpId;
    StartDiscovery(g_pkgName, &g_sInfo, &g_subscribeCb);
    ret = StopDiscovery(NULL, tmpId);
    EXPECT_TRUE(ret != 0);
    ret = StopDiscovery(g_erroPkgName, tmpId);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: StopDiscoveryTest002
 * @tc.desc: test under normal conditions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, StopDiscoveryTest002, TestSize.Level0)
{
    int ret;
    int tmpId1 = GetSubscribeId();
    int tmpId2 = GetSubscribeId();

    g_sInfo.subscribeId = tmpId1;
    StartDiscovery(g_pkgName, &g_sInfo, &g_subscribeCb);
    g_sInfo1.subscribeId = tmpId2;
    StartDiscovery(g_pkgName, &g_sInfo1, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, tmpId1);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, tmpId2);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StopDiscoveryTest003
 * @tc.desc: Verify StartDiscovery and StopDiscovery same parameter again.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, StopDiscoveryTest003, TestSize.Level0)
{
    int ret;
    int tmpId = GetSubscribeId();

    g_sInfo.subscribeId = tmpId;
    StartDiscovery(g_pkgName, &g_sInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, tmpId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StopDiscoveryTest004
 * @tc.desc:Test extern module stop active discover, use Diff Freq Under the COAP.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The StopDiscovery operates normally
 */
HWTEST_F(Disc_Test, StopDiscoveryTest004, TestSize.Level0)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StopDiscoveryTest005
 * @tc.desc:Test extern module stop passive discover, use Diff Freq Under the COAP.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The StopDiscovery operates normally
 */
HWTEST_F(Disc_Test, StopDiscoveryTest005, TestSize.Level0)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StopDiscoveryTest006
 * @tc.desc:Test extern module stop active discover, use Diff Freq Under the AUTO.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The StopDiscovery operates normally
 */
HWTEST_F(Disc_Test, StopDiscoveryTest006, TestSize.Level0)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StopDiscoveryTest007
 * @tc.desc:Test extern module stop passive discover, use Diff Freq Under the AUTO.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The StopDiscovery operates normally
 */
HWTEST_F(Disc_Test, StopDiscoveryTest007, TestSize.Level0)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StopDiscoveryTest008
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"COAP" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:The StopDiscovery operates normally
 */
HWTEST_F(Disc_Test, StopDiscoveryTest008, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
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

    testInfo.capability = "hicall";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "profile";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "homevisionPic";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "castPlus";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "aaCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "ddmpCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name:StopDiscoveryTest009
 * @tc.desc: Test active publish, verify correct parameter with active mode,"COAP" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:The StopDiscovery operates normally
 */
HWTEST_F(Disc_Test, StopDiscoveryTest009, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
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

    testInfo.capability = "hicall";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "profile";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "homevisionPic";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "castPlus";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "aaCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "ddmpCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: StopDiscoveryTest011
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:The StopDiscovery operates normally
 */
HWTEST_F(Disc_Test, StopDiscoveryTest011, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
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

    testInfo.capability = "hicall";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "profile";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "homevisionPic";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "castPlus";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "aaCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "ddmpCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name:StopDiscoveryTest012
 * @tc.desc: Test active publish, verify correct parameter with active mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:The StopDiscovery operates normally
 */
HWTEST_F(Disc_Test, StopDiscoveryTest012, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
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

    testInfo.capability = "hicall";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "profile";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "homevisionPic";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "castPlus";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "aaCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "ddmpCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, testInfo.subscribeId);
}
} // namespace OHOS
