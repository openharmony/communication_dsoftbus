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
#include <securec.h>
#include <sys/time.h>
#include <unistd.h>

#include "softbus_access_token_test.h"
#include "softbus_adapter_mem.h"
#include "softbus_bus_center.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

using namespace testing::ext;

namespace OHOS {
static int32_t g_publishId = 0;
static const char *g_pkgName = "com.softbus.test";
static const char *g_pkgName1 = "com.softbus.test1";
static const char *g_erroPkgName1 = "ErroErroErroErroErroErroErroErroErroErroErroErroErro_Lager_Than_PKG_NAME_SIZE_MAX";

class BusCenterSdkPublish : public testing::Test {
public:
    BusCenterSdkPublish() { }
    ~BusCenterSdkPublish() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() { }
    void TearDown() { }
};

void BusCenterSdkPublish::SetUpTestCase(void)
{
    SetAccessTokenPermission("busCenterTest");
}

void BusCenterSdkPublish::TearDownTestCase(void) { }

static int32_t GetPublishId(void)
{
    g_publishId++;
    return g_publishId;
}

static PublishInfo g_newpInfo = { .publishId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata2",
    .dataLen = sizeof("capdata2"),
    .ranging = false };

static PublishInfo g_newpInfo1 = { .publishId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata4",
    .dataLen = sizeof("capdata4"),
    .ranging = false };

static void TestOnPublishResult(int32_t publishId, PublishResult reason)
{
    (void)publishId;
    (void)reason;
}

static const IPublishCb g_publishCb = {
    .OnPublishResult = TestOnPublishResult,
};

/**
 * @tc.name: PublishLNNTest001
 * @tc.desc: Use new Publish interface, test active publish mode, use wrong parameters in COAP medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN operates normally.
 */
HWTEST_F(BusCenterSdkPublish, PublishLNNTest001, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = { .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1"),
        .ranging = false };

    ret = PublishLNN(NULL, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = PublishLNN(g_pkgName, NULL, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = PublishLNN(g_pkgName, &testInfo, NULL);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    testInfo.capabilityData = NULL;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.capability = NULL;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    testInfo.capability = "dvKit";

    testInfo.dataLen = MAX_CAPABILITYDATA_LEN + 1;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: PublishLNNTest002
 * @tc.desc: Test active publish use new Publish interface, use parameters outside the given range in COAP.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN operates normally.
 */
HWTEST_F(BusCenterSdkPublish, PublishLNNTest002, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = { .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1"),
        .ranging = false };

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    testInfo.medium = COAP;

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_PASSIVE - 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    testInfo.mode = DISCOVER_MODE_ACTIVE;

    testInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: PublishLNNTest003
 * @tc.desc: Test passive publish use new Publish interface, use wrong capa.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN operates normally.
 */
HWTEST_F(BusCenterSdkPublish, PublishLNNTest003, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = { .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1"),
        .ranging = false };

    ret = PublishLNN(g_erroPkgName1, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_INIT);
    ret = StopPublishLNN(g_erroPkgName1, testInfo.publishId);

    uint8_t *g_erroPkgName2 = (uint8_t *)SoftBusCalloc(PKG_NAME_SIZE_MAX);
    ASSERT_NE(g_erroPkgName2, nullptr);
    (void)memset_s(g_erroPkgName2, PKG_NAME_SIZE_MAX, 1, PKG_NAME_SIZE_MAX);
    ret = PublishLNN((const char *)g_erroPkgName2, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_INIT);
    SoftBusFree(g_erroPkgName2);

    g_erroPkgName2 = (uint8_t *)SoftBusCalloc(PKG_NAME_SIZE_MAX + 1);
    ASSERT_NE(g_erroPkgName2, nullptr);
    (void)memset_s(g_erroPkgName2, PKG_NAME_SIZE_MAX + 1, 1, PKG_NAME_SIZE_MAX + 1);
    ret = PublishLNN((const char *)g_erroPkgName2, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_INIT);
    SoftBusFree(g_erroPkgName2);

    g_erroPkgName2 = (uint8_t *)SoftBusCalloc(PKG_NAME_SIZE_MAX + 1);
    ASSERT_NE(g_erroPkgName2, nullptr);
    (void)memset_s(g_erroPkgName2, PKG_NAME_SIZE_MAX, 1, PKG_NAME_SIZE_MAX);
    ret = PublishLNN((const char *)g_erroPkgName2, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_INIT);
    SoftBusFree(g_erroPkgName2);

    testInfo.medium = BLE;
    ret = PublishLNN(g_erroPkgName1, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_INIT);

    testInfo.medium = COAP;
    ret = PublishLNN(g_erroPkgName1, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_INIT);
}

/**
 * @tc.name: PublishLNNTest004
 * @tc.desc: Test passive publish use new Publish interface, use different capabilityData.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN operates normally.
 */
HWTEST_F(BusCenterSdkPublish, PublishLNNTest004, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = { .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = BLE,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1"),
        .ranging = false };

    testInfo.publishId = GetPublishId();
    testInfo.capabilityData = NULL;
    testInfo.dataLen = sizeof("capdata1");
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    testInfo.publishId = GetPublishId();
    testInfo.capabilityData = (unsigned char *)"";
    testInfo.dataLen = sizeof("capdata1");
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.publishId = GetPublishId();
    testInfo.capabilityData = NULL;
    testInfo.dataLen = 0;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.publishId = GetPublishId();
    testInfo.capabilityData = (unsigned char *)"";
    testInfo.dataLen = 0;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.publishId = GetPublishId();
    testInfo.capabilityData = (unsigned char *)"capdata1";
    testInfo.dataLen = 0;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.capabilityData = (unsigned char *)SoftBusCalloc(MAX_CAPABILITYDATA_LEN);
    ASSERT_NE(testInfo.capabilityData, nullptr);
    (void)memset_s(testInfo.capabilityData, MAX_CAPABILITYDATA_LEN, 1, MAX_CAPABILITYDATA_LEN);
    testInfo.dataLen = MAX_CAPABILITYDATA_LEN;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusFree(testInfo.capabilityData);
}

/**
 * @tc.name: PublishLNNTest005
 * @tc.desc: Use new Publish interface, test Invoke PublishID multiple times, use different PublishID.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN operates normally.
 */
HWTEST_F(BusCenterSdkPublish, PublishLNNTest005, TestSize.Level1)
{
    int32_t ret;

    g_newpInfo.publishId = GetPublishId();
    ret = PublishLNN(g_pkgName, &g_newpInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, g_newpInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_newpInfo1.publishId = GetPublishId();
    ret = PublishLNN(g_pkgName, &g_newpInfo1, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, g_newpInfo1.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_newpInfo1.publishId = GetPublishId();
    ret = PublishLNN(g_pkgName1, &g_newpInfo1, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName1, g_newpInfo1.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: PublishLNNTest006
 * @tc.desc: Test active publish use new Publish interface, use different freq under the COAP.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and UnPublishService operates normally.
 */
HWTEST_F(BusCenterSdkPublish, PublishLNNTest006, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = { .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1"),
        .ranging = false };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.freq = MID;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.freq = HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.freq = SUPER_HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.freq = EXTREME_HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: PublishLNNTest007
 * @tc.desc: Test passive publish use new Publish interface, use different freq under the COAP.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and UnPublishService operates normally.
 */
HWTEST_F(BusCenterSdkPublish, PublishLNNTest007, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = { .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1"),
        .ranging = false };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.freq = MID;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.freq = HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.freq = SUPER_HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.freq = EXTREME_HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: PublishLNNTest008
 * @tc.desc: Test active publish use new Publish interface, use different freq under the AUTO.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and StopPublishLNN operates normally.
 */
HWTEST_F(BusCenterSdkPublish, PublishLNNTest008, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = { .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2"),
        .ranging = false };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.freq = MID;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.freq = HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.freq = SUPER_HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.freq = EXTREME_HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: PublishLNNTest009
 * @tc.desc: Test passive publish use new Publish interface, use different freq under the AUTO.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and StopPublishLNN operates normally.
 */
HWTEST_F(BusCenterSdkPublish, PublishLNNTest009, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = { .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "ddmpCapability",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3"),
        .ranging = false };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.freq = MID;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.freq = HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.freq = SUPER_HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.freq = EXTREME_HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: PublishLNNTest010
 * @tc.desc: Test new Publish interface, enable the ranging function in COAP.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN operates normally.
 */
HWTEST_F(BusCenterSdkPublish, PublishLNNTest010, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = { .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1"),
        .ranging = true };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.publishId = GetPublishId();
    testInfo.mode = DISCOVER_MODE_ACTIVE;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: PublishLNNTest011
 * @tc.desc: Test new Publish interface, disabling the ranging function in COAP.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN operates normally.
 */
HWTEST_F(BusCenterSdkPublish, PublishLNNTest011, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = { .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1"),
        .ranging = false };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.publishId = GetPublishId();
    testInfo.mode = DISCOVER_MODE_ACTIVE;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: PublishLNNTest012
 * @tc.desc: Test new Publish interface, enable the ranging function in AUTO.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN operates normally.
 */
HWTEST_F(BusCenterSdkPublish, PublishLNNTest012, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = { .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1"),
        .ranging = true };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.publishId = GetPublishId();
    testInfo.mode = DISCOVER_MODE_ACTIVE;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: PublishLNNTest013
 * @tc.desc: Test new Publish interface, disabling the ranging function in AUTO.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN operates normally.
 */
HWTEST_F(BusCenterSdkPublish, PublishLNNTest013, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = { .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1"),
        .ranging = false };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testInfo.publishId = GetPublishId();
    testInfo.mode = DISCOVER_MODE_ACTIVE;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: PublishLNNTest014
 * @tc.desc: Test active publish use new Publish interface, use different freq under the BLE.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and StopPublishLNN operates normally.
 */
HWTEST_F(BusCenterSdkPublish, PublishLNNTest014, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = { .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1"),
        .ranging = false };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.freq = MID;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.freq = HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.freq = SUPER_HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.freq = EXTREME_HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: PublishLNNTest015
 * @tc.desc: Test passive publish use new Publish interface, use different freq under the BLE.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and StopPublishLNN operates normally.
 */
HWTEST_F(BusCenterSdkPublish, PublishLNNTest015, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = { .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = BLE,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1"),
        .ranging = false };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.freq = MID;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.freq = HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.freq = SUPER_HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.freq = EXTREME_HIGH;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: PublishLNNTest016
 * @tc.desc: Test new Publish interface , enable the ranging function in BLE.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN operates normally.
 */
HWTEST_F(BusCenterSdkPublish, PublishLNNTest016, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = { .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = BLE,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1"),
        .ranging = true };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.publishId = GetPublishId();
    testInfo.mode = DISCOVER_MODE_ACTIVE;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: PublishLNNTest017
 * @tc.desc: Test new Publish interface, disabling the ranging function in BLE.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN operates normally.
 */
HWTEST_F(BusCenterSdkPublish, PublishLNNTest017, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = { .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = BLE,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1"),
        .ranging = false };

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    testInfo.publishId = GetPublishId();
    testInfo.mode = DISCOVER_MODE_ACTIVE;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
}

/**
 * @tc.name: StopPublishLNN001
 * @tc.desc: Verify use wrong parameters .
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and StopPublishLNN operates normally.
 */
HWTEST_F(BusCenterSdkPublish, StopPublishLNN001, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = { .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1"),
        .ranging = false };

    PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    ret = StopPublishLNN(NULL, testInfo.publishId);
    EXPECT_TRUE(ret != 0);
    ret = StopPublishLNN(g_erroPkgName1, testInfo.publishId);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: StopPublishLNN002
 * @tc.desc: Verify stoppublish different publishID, invoke multiple times to stop publish.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and StopPublishLNN operates normally.
 */
HWTEST_F(BusCenterSdkPublish, StopPublishLNN002, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = { .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1"),
        .ranging = false };

    int32_t testID = testInfo.publishId;
    PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    testInfo.publishId = GetPublishId();
    PublishLNN(g_pkgName, &testInfo, &g_publishCb);

    ret = StopPublishLNN(g_pkgName, testID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: StopPublishLNN003
 * @tc.desc: Verify same publishID stoppublish twice.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and StopPublishLNN operates normally.
 */
HWTEST_F(BusCenterSdkPublish, StopPublishLNN003, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = { .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1"),
        .ranging = false };

    PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    EXPECT_TRUE(ret != 0);
}
} // namespace OHOS