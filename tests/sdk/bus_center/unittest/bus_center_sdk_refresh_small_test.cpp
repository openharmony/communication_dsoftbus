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

#include "softbus_access_token_test.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"
#include "softbus_server_frame.h"
#include "softbus_server_proxy.h"

using namespace testing::ext;

namespace OHOS {
static int32_t g_subscribeId = 0;
static const char PKG_NAME1[] = "com.softbus.test";
constexpr char TEST_PKG_NAME[] = "com.softbus.test";
constexpr char ERRO_PKG_NAME[] = "ErroErroErroErroErroErroErroErroErroErroErroErroErroErroErroErroEErroE";

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
    InitSoftBusServer();
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
 * @tc.desc: Test active discovery mode, use wrong Subscribeinfo in COAP medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest001, TestSize.Level1)
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

    ret = RefreshLNN(NULL, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(TEST_PKG_NAME, NULL, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(TEST_PKG_NAME, &testInfo, NULL);
    EXPECT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = RefreshLNN(TEST_PKG_NAME, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = RefreshLNN(TEST_PKG_NAME, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.mode = DISCOVER_MODE_ACTIVE;

    testInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = RefreshLNN(TEST_PKG_NAME, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capabilityData = NULL;
    ret = RefreshLNN(TEST_PKG_NAME, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = RefreshLNN(TEST_PKG_NAME, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: RefreshLNNTest002
 * @tc.desc: Test passive discovery mode, use wrong Subscribeinfo in COAP medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest002, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = { .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3") };

    ret = RefreshLNN(NULL, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(TEST_PKG_NAME, NULL, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(TEST_PKG_NAME, &testInfo, NULL);
    EXPECT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = RefreshLNN(TEST_PKG_NAME, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = RefreshLNN(TEST_PKG_NAME, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.mode = DISCOVER_MODE_ACTIVE;

    testInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = RefreshLNN(TEST_PKG_NAME, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capabilityData = NULL;
    ret = RefreshLNN(TEST_PKG_NAME, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = RefreshLNN(TEST_PKG_NAME, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: RefreshLNNTest003
 * @tc.desc: Test active discovery mode, use wrong Subscribeinfo in COAP medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest003, TestSize.Level1)
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

    ret = RefreshLNN(NULL, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(PKG_NAME1, NULL, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(PKG_NAME1, &testInfo, NULL);
    EXPECT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.mode = DISCOVER_MODE_ACTIVE;

    testInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capabilityData = NULL;
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: RefreshLNNTest004
 * @tc.desc: Test passive discovery mode, use wrong Subscribeinfo in COAP medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest004, TestSize.Level1)
{
    int32_t ret;
    SubscribeInfo testInfo = { .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = strlen("capdata3") };

    ret = RefreshLNN(NULL, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(PKG_NAME1, NULL, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(PKG_NAME1, &testInfo, NULL);
    EXPECT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.mode = DISCOVER_MODE_ACTIVE;

    testInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capabilityData = NULL;
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: RefreshLNNTest005
 * @tc.desc: Test active discovery mode, use wrong Subscribeinfo in AUTO medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest005, TestSize.Level1)
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

    ret = RefreshLNN(PKG_NAME1, NULL, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(PKG_NAME1, &testInfo, NULL);
    EXPECT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(AUTO + 3);
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = AUTO;

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.mode = DISCOVER_MODE_ACTIVE;

    testInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capabilityData = NULL;
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: RefreshLNNTest006
 * @tc.desc: Test passive discovery mode, use wrong Subscribeinfo in AUTO medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest006, TestSize.Level1)
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

    ret = RefreshLNN(NULL, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(PKG_NAME1, NULL, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(PKG_NAME1, &testInfo, NULL);
    EXPECT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(AUTO + 3);
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = AUTO;

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.mode = DISCOVER_MODE_ACTIVE;

    testInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capabilityData = NULL;
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: RefreshLNNTest007
 * @tc.desc: Test active discovery mode, use wrong Subscribeinfo in BLE medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest007, TestSize.Level1)
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

    ret = RefreshLNN(NULL, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(PKG_NAME1, NULL, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(PKG_NAME1, &testInfo, NULL);
    EXPECT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(BLE + 2);
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = BLE;

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.mode = DISCOVER_MODE_ACTIVE;

    testInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capabilityData = NULL;
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: RefreshLNNTest008
 * @tc.desc: Test passive discovery mode, use wrong Subscribeinfo in BLE medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, RefreshLNNTest008, TestSize.Level1)
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

    ret = RefreshLNN(NULL, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(PKG_NAME1, NULL, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);

    ret = RefreshLNN(PKG_NAME1, &testInfo, NULL);
    EXPECT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(BLE + 2);
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.medium = BLE;

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.mode = DISCOVER_MODE_ACTIVE;

    testInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capabilityData = NULL;
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = RefreshLNN(PKG_NAME1, &testInfo, &g_refreshCb1);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: StopRefreshLNNTest001
 * @tc.desc: Verify stop discovery wrong parameter in BLE medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StopRefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, StopRefreshLNNTest001, TestSize.Level1)
{
    int32_t ret;
    int32_t tmpId = GetSubscribeId();
    g_sInfo2.subscribeId = tmpId;

    RefreshLNN(TEST_PKG_NAME, &g_sInfo2, &g_refreshCb1);
    ret = StopRefreshLNN(NULL, tmpId);
    EXPECT_TRUE(ret != 0);
    ret = StopRefreshLNN(ERRO_PKG_NAME, tmpId);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: StopRefreshLNNTest002
 * @tc.desc: Verify stop discovery wrong parameter in COAP medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StopRefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, StopRefreshLNNTest002, TestSize.Level1)
{
    int32_t ret;
    int32_t tmpId = GetSubscribeId();
    g_sInfo2.subscribeId = tmpId;

    RefreshLNN(PKG_NAME1, &g_sInfo2, &g_refreshCb1);
    ret = StopRefreshLNN(NULL, tmpId);
    EXPECT_TRUE(ret != 0);
    ret = StopRefreshLNN(ERRO_PKG_NAME, tmpId);
    EXPECT_TRUE(ret != 0);
}

/**
 * @tc.name: StopRefreshLNNTest003
 * @tc.desc: Verify stop discovery wrong parameter in AUTO medium.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The StopRefreshLNN operates normally.
 */
HWTEST_F(BusCenterSdkRefresh, StopRefreshLNNTest003, TestSize.Level1)
{
    int32_t ret;
    int32_t tmpId = GetSubscribeId();
    g_sInfo2.subscribeId = tmpId;

    RefreshLNN(PKG_NAME1, &g_sInfo2, &g_refreshCb1);
    ret = StopRefreshLNN(NULL, tmpId);
    EXPECT_TRUE(ret != 0);
    ret = StopRefreshLNN(ERRO_PKG_NAME, tmpId);
    EXPECT_TRUE(ret != 0);
}
} // namespace OHOS