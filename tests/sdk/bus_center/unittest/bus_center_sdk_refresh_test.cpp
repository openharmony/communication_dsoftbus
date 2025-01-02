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
#include "softbus_bus_center.h"

using namespace testing::ext;

namespace OHOS {
static int32_t g_subscribeId = 0;
static const char *g_pkgName = "com.softbus.test";
static const char *g_pkgName1 = "com.softbus.test1";
static const char *g_erroPkgName = "ErroErroErroErroErroErroErroErroErroErroErroErroErroErroErroErroEErroE";

const int32_t ERRO_CAPDATA_LEN = 514;

class BusCenterSdkRefresh : public testing::Test {
public:
    BusCenterSdkRefresh() { }
    ~BusCenterSdkRefresh() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() { }
    void TearDown() { }
};

void BusCenterSdkRefresh::SetUpTestCase(void)
{
    SetAccessTokenPermission("busCenterTest");
}

void BusCenterSdkRefresh::TearDownTestCase(void) { }

static int32_t GetSubscribeId(void)
{
    g_subscribeId++;
    return g_subscribeId;
}

static SubscribeInfo g_sInfo2 = { .subscribeId = GetSubscribeId(),
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata3",
    .dataLen = strlen("capdata3") };

static SubscribeInfo g_sInfo3 = { .subscribeId = GetSubscribeId(),
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "hicall",
    .capabilityData = NULL,
    .dataLen = 0 };

static void OnDiscoverResult(int32_t refreshId, RefreshResult Reason)
{
    printf("[client]TestDiscoverResult\n");
}

static void TestDeviceFound(const DeviceInfo *device)
{
    printf("[client]TestDeviceFound\n");
}

static void TestRangeDeviceFound(const DeviceInfo *device)
{
    printf("TestRangeDeviceFound rang:%d\n", device->range);
}

static IRefreshCallback g_refreshCb1 = { .OnDeviceFound = TestDeviceFound, .OnDiscoverResult = OnDiscoverResult };

static IRefreshCallback g_refreshCb2 = { .OnDeviceFound = TestRangeDeviceFound, .OnDiscoverResult = OnDiscoverResult };

/**
 * @tc.name: RefreshLNNTest001
 * @tc.desc: Test active discovery mode, use wrong parameters in COAP medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest001, TestSize.Level1)
{
    int32_t ret;
    g_sInfo2.subscribeId = GetSubscribeId();
    ret = RefreshLNN(g_pkgName, &g_sInfo2, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, g_sInfo2.subscribeId);

    g_sInfo3.subscribeId = GetSubscribeId();
    ret = RefreshLNN(g_pkgName, &g_sInfo3, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, g_sInfo3.subscribeId);

    g_sInfo3.subscribeId = GetSubscribeId();
    ret = RefreshLNN(g_pkgName1, &g_sInfo3, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName1, g_sInfo3.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest002
 * @tc.desc: Test active discovery mode, use diff freq in COAP medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest002, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = { .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3") };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = EXTREME_HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: RefreshLNNTest003
 * @tc.desc: Test passive discovery mode, use diff freq in COAP medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest003, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = { .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3") };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = EXTREME_HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: RefreshLNNTest004
 * @tc.desc: Test active discovery mode, use correct parameters in AUTO medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest004, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = { .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3") };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest005
 * @tc.desc: Test passive discovery mode, use correct parameters in AUTO medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest005, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = { .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3") };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest006
 * @tc.desc: Test active discovery mode, use wrong parameters in AUTO medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest006, TestSize.Level1)
{
    int32_t ret;

    g_sInfo2.subscribeId = GetSubscribeId();
    ret = RefreshLNN(g_pkgName, &g_sInfo2, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, g_sInfo2.subscribeId);

    g_sInfo3.subscribeId = GetSubscribeId();
    ret = RefreshLNN(g_pkgName, &g_sInfo3, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, g_sInfo3.subscribeId);

    g_sInfo3.subscribeId = GetSubscribeId();
    ret = RefreshLNN(g_pkgName1, &g_sInfo3, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName1, g_sInfo3.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest007
 * @tc.desc: Test active discovery mode, use diff freq in AUTO medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest007, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = { .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3") };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = EXTREME_HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: RefreshLNNTest008
 * @tc.desc: Test passive discovery mode, use diff freq in AUTO medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest008, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = { .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3") };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = MID;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    testInfo.freq = EXTREME_HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: RefreshLNNTest009
 * @tc.desc: Test active discovery mode, use wrong Subscribeinfo in AUTO medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest009, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = { .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3") };

    ret = RefreshLNN(NULL, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(g_pkgName, NULL, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(g_pkgName, &testInfo, NULL);
    EXPECT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(AUTO + 3);
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = AUTO;

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.mode = DISCOVER_MODE_ACTIVE;

    testInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capabilityData = NULL;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: RefreshLNNTest010
 * @tc.desc: Verify startdiscovery again, Use the same and correct parameters in COAP medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefershLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest010, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = { .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3") };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: RefreshLNNTest011
 * @tc.desc: Verify startdiscovery again, Use the same and correct parameters in AUTO medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest011, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = { .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3") };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.name: RefreshLNNTest012
 * @tc.desc: Test ble range in BLE, need enable the ranging on peer device.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest012, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = { .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3") };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb2);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest013
 * @tc.desc: Test ble range in COAP medium, need enable the ranging on peer device.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest013, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = { .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3") };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb2);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest014
 * @tc.desc: Test ble range in AUTO medium, need enable the ranging on peer device.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest014, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = { .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3") };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb2);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest015
 * @tc.desc: Test active discovery mode, use correct parameters in BLE medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest015, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = { .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3") };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest016
 * @tc.desc: Test passive discovery mode, use correct parameters in BLE medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest016, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = { .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = BLE,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3") };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest017
 * @tc.desc: Test active discovery mode, use wrong parameters in BLE medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest017, TestSize.Level1)
{
    int32_t ret;

    g_sInfo2.subscribeId = GetSubscribeId();
    ret = RefreshLNN(g_pkgName, &g_sInfo2, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, g_sInfo2.subscribeId);

    g_sInfo3.subscribeId = GetSubscribeId();
    ret = RefreshLNN(g_pkgName, &g_sInfo3, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, g_sInfo3.subscribeId);

    g_sInfo3.subscribeId = GetSubscribeId();
    ret = RefreshLNN(g_pkgName1, &g_sInfo3, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName1, g_sInfo3.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest018
 * @tc.desc: Test active discovery mode, use diff freq in BLE medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest018, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = { .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3") };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.freq = MID;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.freq = HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.freq = SUPER_HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.freq = EXTREME_HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest019
 * @tc.desc: Test passive discovery mode, use diff freq in BLE medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest019, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = { .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = BLE,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3") };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.freq = MID;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.freq = HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.freq = SUPER_HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    testInfo.freq = EXTREME_HIGH;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest020
 * @tc.desc: Verify startdiscovery again, Use the same and correct parameters in BLE medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefershLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest020, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = { .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3") };

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret == 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
}
} // namespace OHOS