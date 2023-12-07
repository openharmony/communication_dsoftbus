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

#include <cstdio>
#include <ctime>
#include <gtest/gtest.h>
#include <sys/time.h>
#include <unistd.h>

#include "softbus_access_token_test.h"
#include "softbus_bus_center.h"
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

class DiscSdkTest : public testing::Test {
public:
    DiscSdkTest()
    {}
    ~DiscSdkTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void DiscSdkTest::SetUpTestCase(void)
{
    SetAceessTokenPermission("discTest");
}

void DiscSdkTest::TearDownTestCase(void)
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
    .dataLen = strlen("capdata3")
};

static PublishInfo g_pInfo = {
    .publishId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata4",
    .dataLen = strlen("capdata4")
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

static void TestOnDiscoverResult(int32_t refreshId, RefreshResult reason)
{
    (void)refreshId;
    (void)reason;
    printf("[client]TestDiscoverResult\n");
}

static void TestOnPublishResult(int publishId, PublishResult reason)
{
    (void)publishId;
    (void)reason;
    printf("[client]TestPublishResult\n");
}

static const IRefreshCallback g_refreshCb = {
    .OnDeviceFound = TestDeviceFound,
    .OnDiscoverResult = TestOnDiscoverResult
};

static const IPublishCb g_publishCb = {
    .OnPublishResult = TestOnPublishResult,
};

/**
 * @tc.name: PublishLNNTest001
 * @tc.desc: Test for wrong parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, PublishLNNTest001, TestSize.Level0)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    ret = PublishLNN(NULL, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);

    ret = PublishLNN(g_pkgName, NULL, &g_publishCb);
    EXPECT_TRUE(ret != 0);

    ret = PublishLNN(g_pkgName, &testInfo, NULL);
    EXPECT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.mode = DISCOVER_MODE_ACTIVE;

    testInfo.freq = (ExchangeFreq)(SUPER_HIGH + 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capabilityData = NULL;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.dataLen = strlen("capdata1");
}

/**
 * @tc.name: PublishLNNTest002
 * @tc.desc: Test GetPublishId and PublishLNN to see if they are running properly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, PublishLNNTest002, TestSize.Level0)
{
    int ret;

    g_pInfo.publishId = GetPublishId();
    ret = PublishLNN(g_pkgName, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, g_pInfo.publishId);

    g_pInfo1.publishId = GetPublishId();
    ret = PublishLNN(g_pkgName, &g_pInfo1, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, g_pInfo1.publishId);

    g_pInfo1.publishId = GetPublishId();
    ret = PublishLNN(g_pkgName_1, &g_pInfo1, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName_1, g_pInfo1.publishId);
}

/**
 * @tc.name: PublishLNNTest003
 * @tc.desc: Verify same parameter again
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, PublishLNNTest003, TestSize.Level0)
{
    int ret;

    g_pInfo.publishId = GetPublishId();
    ret = PublishLNN(g_pkgName, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, g_pInfo.publishId);
}

/**
 * @tc.name: PublishLNNTest004
 * @tc.desc: Test active publish, verify correct parameter with active mode and "COAP" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, PublishLNNTest004, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: PublishLNNTest005
 * @tc.desc: Test passive publish, verify correct parameter with passive mode and "AUTO" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, PublishLNNTest005, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: PublishLNNTest006
 * @tc.desc: Test passive publish, verify correct parameter with passive mode and "COAP" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, PublishLNNTest006, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: PublishLNNTest007
 * @tc.desc: Verify wrong parameter.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require:The PublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, PublishLNNTest007, TestSize.Level1)
{
    int ret;
    g_pInfo.publishId = GetPublishId();
    ret = PublishLNN(g_erroPkgName1, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: PublishLNNTest008
 * @tc.desc: Test active publish, verify wrong parameter with active mode and "COAP" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require:The PublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, PublishLNNTest008, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char*)"capdata2",
        .dataLen = strlen("capdata2")
    };

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;
}
/**
 * @tc.name: PublishLNNTest009
 * @tc.desc: Test active publish, verify wrong parameter with active mode and "BLE" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require:The PublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, PublishLNNTest009, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char*)"capdata2",
        .dataLen = strlen("capdata2")
    };

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = BLE;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;
}

/**
 * @tc.name: PublishLNNTest010
 * @tc.desc: Test active publish, verify wrong parameter with active mode and "AUTO" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require:The PublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, PublishLNNTest010, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char*)"capdata2",
        .dataLen = strlen("capdata2")
    };

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = AUTO;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;
}

/**
 * @tc.name: PublishLNNTest011
 * @tc.desc: Test passive publish, verify wrong parameter with active mode and "COAP" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require:The PublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, PublishLNNTest011, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char*)"capdata2",
        .dataLen = strlen("capdata2")
    };

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;
}

/**
 * @tc.name: PublishLNNTest012
 * @tc.desc: Test passive publish, verify wrong parameter with active mode and "AUTO" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require:The PublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, PublishLNNTest012, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char*)"capdata2",
        .dataLen = strlen("capdata2")
    };

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = AUTO;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;
}

/**
 * @tc.name: PublishLNNTest013
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"COAP" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, PublishLNNTest013, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "hicall";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "profile";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "homevisionPic";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "castPlus";
    testInfo.capabilityData = (unsigned char *)"{\"castPlus\":\"capdata2\"}";
    testInfo.dataLen = strlen("{\"castPlus\":\"capdata2\"}");
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    testInfo.capabilityData = (unsigned char *)"capdata2";
    testInfo.dataLen = strlen("capdata2");
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "aaCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "ddmpCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: PublishLNNTest014
 * @tc.desc: Test active publish, verify correct parameter with active mode,"COAP" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, PublishLNNTest014, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "hicall";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "profile";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "homevisionPic";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "castPlus";
    testInfo.capabilityData = (unsigned char *)"{\"castPlus\":\"capdata2\"}";
    testInfo.dataLen = strlen("{\"castPlus\":\"capdata2\"}");
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    testInfo.capabilityData = (unsigned char *)"capdata2";
    testInfo.dataLen = strlen("capdata2");
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "aaCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "ddmpCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: PublishLNNTest015
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, PublishLNNTest015, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "hicall";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "profile";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "homevisionPic";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "castPlus";
    testInfo.capabilityData = (unsigned char *)"{\"castPlus\":\"capdata2\"}";
    testInfo.dataLen = strlen("{\"castPlus\":\"capdata2\"}");
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    testInfo.capabilityData = (unsigned char *)"capdata2";
    testInfo.dataLen = strlen("capdata2");
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "aaCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "ddmpCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: PublishLNNTest016
 * @tc.desc: Test active publish, verify correct parameter with active mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, PublishLNNTest016, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "hicall";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "profile";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "homevisionPic";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "castPlus";
    testInfo.capabilityData = (unsigned char *)"{\"castPlus\":\"capdata2\"}";
    testInfo.dataLen = strlen("{\"castPlus\":\"capdata2\"}");
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    testInfo.capabilityData = (unsigned char *)"capdata2";
    testInfo.dataLen = strlen("capdata2");
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "aaCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "ddmpCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: RefreshLNNTest001
 * @tc.desc: Verify statrtdiscovery wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest001, TestSize.Level0)
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
        .dataLen = strlen("capdata3")
    };

    ret = RefreshLNN(NULL, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(g_pkgName, NULL, &g_refreshCb);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(g_pkgName, &testInfo, NULL);
    EXPECT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);
    testInfo.mode = DISCOVER_MODE_ACTIVE;

    testInfo.freq = (ExchangeFreq)(SUPER_HIGH + 1);
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capabilityData = NULL;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);
    testInfo.dataLen = strlen("capdata1");
}

/**
 * @tc.name: RefreshLNNTest002
 * @tc.desc: Verify the RefreshLNN error parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest002, TestSize.Level0)
{
    int ret;
    g_sInfo.subscribeId = GetSubscribeId();
    ret = RefreshLNN(g_pkgName, &g_sInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, g_sInfo.subscribeId);

    g_sInfo1.subscribeId = GetSubscribeId();
    ret = RefreshLNN(g_pkgName, &g_sInfo1, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, g_sInfo1.subscribeId);

    g_sInfo1.subscribeId = GetSubscribeId();
    ret = RefreshLNN(g_pkgName_1, &g_sInfo1, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, g_sInfo1.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest003
 * @tc.desc: Verify RefreshLNN same parameter again
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest003, TestSize.Level0)
{
    int ret;

    g_sInfo.subscribeId = GetSubscribeId();
    ret = RefreshLNN(g_pkgName, &g_sInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, g_sInfo.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest004
 * @tc.desc: Test active discover, verify correct parameter with active mode and "AUTO" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest004, TestSize.Level1)
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
        .dataLen = strlen("capdata3")
    };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: RefreshLNNTest005
 * @tc.desc: Test passive discover verify correct parameter with passive mode and "COAP" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest005, TestSize.Level1)
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
        .dataLen = strlen("capdata3")
    };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: RefreshLNNTest006
 * @tc.desc: Test passive discover, verify correct parameter with passive mode and "AUTO" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest006, TestSize.Level1)
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
        .dataLen = strlen("capdata3")
    };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: RefreshLNNTest007
 * @tc.desc: Test passive discover verify correct parameter with passive mode and "COAP" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest007, TestSize.Level1)
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
        .dataLen = strlen("capdata3")
    };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: RefreshLNNTest008
 * @tc.desc: Test passive discover verify correct parameter with active mode and "COAP" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest008, TestSize.Level1)
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
        .dataLen = strlen("capdata3")
    };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: RefreshLNNTest009
 * @tc.desc: Test passive discover, verify correct parameter with passive mode and "AUTO" medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest009, TestSize.Level1)
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
        .dataLen = strlen("capdata3")
    };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: RefreshLNNTest010
 * @tc.desc:  Test extern module passive discoveruse wrong Medium and Freq Under the COAP.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest010, TestSize.Level0)
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
        .dataLen = strlen("capdata3")
    };

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;
}

/**
 * @tc.name: RefreshLNNTest011
 * @tc.desc:  Test extern module passive discoveruse wrong Medium and Freq Under the AUTO.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest011, TestSize.Level0)
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
        .dataLen = strlen("capdata3")
    };

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;
}

/**
 * @tc.name: RefreshLNNTest012
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"COAP" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest012, TestSize.Level1)
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
        .dataLen = strlen("capdata3")
    };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "hicall";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "profile";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "homevisionPic";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "castPlus";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "aaCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "ddmpCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest013
 * @tc.desc: Test active publish, verify correct parameter with active mode,"COAP" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest013, TestSize.Level1)
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
        .dataLen = strlen("capdata3")
    };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "hicall";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "profile";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "homevisionPic";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "castPlus";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "aaCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "ddmpCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest014
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest014, TestSize.Level1)
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
        .dataLen = strlen("capdata3")
    };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "hicall";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "profile";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "homevisionPic";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "castPlus";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "aaCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "ddmpCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest015
 * @tc.desc: Test active publish, verify correct parameter with active mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest015, TestSize.Level1)
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
        .dataLen = strlen("capdata3")
    };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "hicall";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "profile";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "homevisionPic";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "castPlus";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "aaCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "ddmpCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: StopPublishLNNTest001
 * @tc.desc: Verify StopPublishLNN wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, StopPublishLNNTest001, TestSize.Level0)
{
    int ret;
    int tmpId = GetPublishId();

    g_pInfo.publishId = tmpId;
    PublishLNN(g_pkgName, &g_pInfo, &g_publishCb);
    ret = StopPublishLNN(NULL, tmpId);
    EXPECT_TRUE(ret != 0);
    ret = StopPublishLNN(g_erroPkgName, tmpId);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: StopPublishLNNTest002
 * @tc.desc: Verify PublishLNN and StopPublishLNN normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, StopPublishLNNTest002, TestSize.Level0)
{
    int ret;
    int tmpId1 = GetPublishId();
    int tmpId2 = GetPublishId();

    g_pInfo.publishId = tmpId1;
    PublishLNN(g_pkgName, &g_pInfo, &g_publishCb);
    g_pInfo1.publishId = tmpId2;
    PublishLNN(g_pkgName, &g_pInfo1, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, tmpId1);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, tmpId2);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StopPublishLNNTest003
 * @tc.desc: Verify PublishLNN and StopPublishLNN same parameter again.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, StopPublishLNNTest003, TestSize.Level0)
{
    int ret;
    int tmpId = GetPublishId();

    g_pInfo.publishId = tmpId;
    PublishLNN(g_pkgName, &g_pInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, tmpId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StopPublishLNNTest004
 * @tc.desc: Extern module stop publish, use the normal parameter and different frequencies under active COAP.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, StopPublishLNNTest004, TestSize.Level0)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StopPublishLNNTest005
 * @tc.desc: Extern module stop publish, use the normal parameter and different frequencies under passive COAP.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, StopPublishLNNTest005, TestSize.Level0)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StopPublishLNNTest006
 * @tc.desc: Extern module stop publish, use the normal parameter and different frequencies under active AUTO.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, StopPublishLNNTest006, TestSize.Level0)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StopPublishLNNTest007
 * @tc.desc: Extern module stop publish, use the normal parameter and different frequencies under passive AUTO.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, StopPublishLNNTest007, TestSize.Level0)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StopPublishLNNTest008
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"COAP" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, StopPublishLNNTest008, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "hicall";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "profile";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "homevisionPic";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "castPlus";
    testInfo.capabilityData = (unsigned char *)"{\"castPlus\":\"capdata2\"}";
    testInfo.dataLen = strlen("{\"castPlus\":\"capdata2\"}");
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    testInfo.capabilityData = (unsigned char *)"capdata2";
    testInfo.dataLen = strlen("capdata2");
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "aaCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "ddmpCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: StopPublishLNNTest009
 * @tc.desc: Test active publish, verify correct parameter with active mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, StopPublishLNNTest009, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "hicall";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "profile";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "homevisionPic";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "castPlus";
    testInfo.capabilityData = (unsigned char *)"{\"castPlus\":\"capdata2\"}";
    testInfo.dataLen = strlen("{\"castPlus\":\"capdata2\"}");
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    testInfo.capabilityData = (unsigned char *)"capdata2";
    testInfo.dataLen = strlen("capdata2");
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "aaCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "ddmpCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: StopPublishLNNTest010
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, StopPublishLNNTest010, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "hicall";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "profile";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "homevisionPic";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "castPlus";
    testInfo.capabilityData = (unsigned char *)"{\"castPlus\":\"capdata2\"}";
    testInfo.dataLen = strlen("{\"castPlus\":\"capdata2\"}");
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    testInfo.capabilityData = (unsigned char *)"capdata2";
    testInfo.dataLen = strlen("capdata2");
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "aaCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "ddmpCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: StopPublishLNNTest011
 * @tc.desc: Test active publish, verify correct parameter with active mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, StopPublishLNNTest011, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = strlen("capdata2")
    };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "hicall";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "profile";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "homevisionPic";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "castPlus";
    testInfo.capabilityData = (unsigned char *)"{\"castPlus\":\"capdata2\"}";
    testInfo.dataLen = strlen("{\"castPlus\":\"capdata2\"}");
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    testInfo.capabilityData = (unsigned char *)"capdata2";
    testInfo.dataLen = strlen("capdata2");
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "aaCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "ddmpCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capability = "osdCapability";
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: StopRefreshLNNTest001
 * @tc.desc: Verify StopRefreshLNN wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, StopRefreshLNNTest001, TestSize.Level0)
{
    int ret;
    int tmpId = GetSubscribeId();

    g_sInfo.subscribeId = tmpId;
    RefreshLNN(g_pkgName, &g_sInfo, &g_refreshCb);
    ret = StopRefreshLNN(NULL, tmpId);
    EXPECT_TRUE(ret != 0);
    ret = StopRefreshLNN(g_erroPkgName, tmpId);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: StopRefreshLNNTest002
 * @tc.desc: test under normal conditions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, StopRefreshLNNTest002, TestSize.Level0)
{
    int ret;
    int tmpId1 = GetSubscribeId();
    int tmpId2 = GetSubscribeId();

    g_sInfo.subscribeId = tmpId1;
    RefreshLNN(g_pkgName, &g_sInfo, &g_refreshCb);
    g_sInfo1.subscribeId = tmpId2;
    RefreshLNN(g_pkgName, &g_sInfo1, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, tmpId1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, tmpId2);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StopRefreshLNNTest003
 * @tc.desc: Verify RefreshLNN and StopRefreshLNN same parameter again.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, StopRefreshLNNTest003, TestSize.Level0)
{
    int ret;
    int tmpId = GetSubscribeId();

    g_sInfo.subscribeId = tmpId;
    RefreshLNN(g_pkgName, &g_sInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, tmpId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StopRefreshLNNTest004
 * @tc.desc:Test extern module stop active discover, use Diff Freq Under the COAP.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The StopRefreshLNN operates normally
 */
HWTEST_F(DiscSdkTest, StopRefreshLNNTest004, TestSize.Level0)
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
        .dataLen = strlen("capdata3")
    };
    RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StopRefreshLNNTest005
 * @tc.desc:Test extern module stop passive discover, use Diff Freq Under the COAP.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The StopRefreshLNN operates normally
 */
HWTEST_F(DiscSdkTest, StopRefreshLNNTest005, TestSize.Level0)
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
        .dataLen = strlen("capdata3")
    };
    RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StopRefreshLNNTest006
 * @tc.desc:Test extern module stop active discover, use Diff Freq Under the AUTO.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The StopRefreshLNN operates normally
 */
HWTEST_F(DiscSdkTest, StopRefreshLNNTest006, TestSize.Level0)
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
        .dataLen = strlen("capdata3")
    };
    RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StopRefreshLNNTest007
 * @tc.desc:Test extern module stop passive discover, use Diff Freq Under the AUTO.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The StopRefreshLNN operates normally
 */
HWTEST_F(DiscSdkTest, StopRefreshLNNTest007, TestSize.Level0)
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
        .dataLen = strlen("capdata3")
    };
    RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: StopRefreshLNNTest008
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"COAP" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:The StopRefreshLNN operates normally
 */
HWTEST_F(DiscSdkTest, StopRefreshLNNTest008, TestSize.Level1)
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
        .dataLen = strlen("capdata3")
    };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "hicall";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "profile";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "homevisionPic";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "castPlus";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "aaCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "ddmpCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name:StopRefreshLNNTest009
 * @tc.desc: Test active publish, verify correct parameter with active mode,"COAP" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:The StopRefreshLNN operates normally
 */
HWTEST_F(DiscSdkTest, StopRefreshLNNTest009, TestSize.Level1)
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
        .dataLen = strlen("capdata3")
    };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "hicall";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "profile";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "homevisionPic";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "castPlus";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "aaCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "ddmpCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: StopRefreshLNNTest011
 * @tc.desc: Test active publish, verify correct parameter with passive mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:The StopRefreshLNN operates normally
 */
HWTEST_F(DiscSdkTest, StopRefreshLNNTest011, TestSize.Level1)
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
        .dataLen = strlen("capdata3")
    };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "hicall";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "profile";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "homevisionPic";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "castPlus";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "aaCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "ddmpCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name:StopRefreshLNNTest012
 * @tc.desc: Test active publish, verify correct parameter with active mode,"AUTO" medium and diff capability.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:The StopRefreshLNN operates normally
 */
HWTEST_F(DiscSdkTest, StopRefreshLNNTest012, TestSize.Level1)
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
        .dataLen = strlen("capdata3")
    };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "hicall";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "profile";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "homevisionPic";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "castPlus";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "aaCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "ddmpCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.capability = "osdCapability";
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
}

} // namespace OHOS
