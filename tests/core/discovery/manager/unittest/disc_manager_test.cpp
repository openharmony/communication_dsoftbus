/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/time.h>
#include <unistd.h>

#include "disc_coap.h"
#include "disc_log.h"
#include "disc_manager.h"
#include "nstackx.h"
#include "softbus_error_code.h"

#define TEST_ERRO_MOUDULE1 ((MODULE_LNN)-1)
#define TEST_ERRO_MOUDULE2 ((MODULE_LNN)-2)
#define TEST_ERRO_MOUDULE  ((MODULE_LNN) + 3)
#define ERRO_CAPDATA_LEN   (MAX_CAPABILITYDATA_LEN + 1)
#define TEST_ASSERT_TRUE(ret)              \
    if (ret) {                             \
        DISC_LOGI(DISC_TEST, "[succ]\n");  \
        g_succTestCount++;                 \
    } else {                               \
        DISC_LOGI(DISC_TEST, "[error]\n"); \
        g_failTestCount++;                 \
    }

using namespace testing::ext;

namespace OHOS {
static int32_t g_succTestCount = 0;
static int32_t g_failTestCount = 0;
static int32_t g_devieceFoundCount = 0;
static const char *g_corrPkgName = "CorrCorrCorrCorrCorrCorrCorrCorrCorrCorrCorrCorrCorrCorrCorrCorr";
static const char *g_erroPkgName = "ErroErroErroErroErroErroErroErroErroErroErroErroErroErroErroErroE";
static DiscoveryFuncInterface *g_coapDiscFunc = NULL;
static PublishOption g_publishOption = { .freq = 0, .capabilityBitmap = { 1 }, .capabilityData = NULL, .dataLen = 0 };
static SubscribeOption g_subscribeOption = { .freq = 1,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capabilityBitmap = { 2 },
    .capabilityData = NULL,
    .dataLen = 0 };

const int32_t TEST_PUBLISHINNER_ID = 1;
const int32_t TEST_PUBLISH_ID = 2;
const int32_t TEST_SUBSCRIBEINNER_ID = 3;
const int32_t TEST_SUBSCRIBE_ID = 4;
const int32_t TEST_PUBLISHINNER_ID1 = 5;
const int32_t TEST_PUBLISH_ID1 = 6;
const int32_t TEST_SUBSCRIBEINNER_ID1 = 7;
const int32_t TEST_SUBSCRIBE_ID1 = 8;
const int32_t TEST_BITMAP_CAP = 127;
const uint32_t PUB_CAP_BITMAP_2 = 6;
const uint32_t PUBLISH_MODE_2 = 5;
const uint32_t FILTER_CAP_BITMAP_2 = 4;
const uint32_t DISC_MODE_2 = 8;

class DiscManagerTest : public testing::Test {
public:
    DiscManagerTest() { }
    ~DiscManagerTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void DiscManagerTest::SetUpTestCase(void) { }

void DiscManagerTest::TearDownTestCase(void) { }

static int32_t TestDeviceFound(
    const char *packageName, const DeviceInfo *device, const InnerDeviceInfoAddtions *additions)
{
    (void)additions;
    g_devieceFoundCount++;
    DISC_LOGI(DISC_TEST, "[device found]success!\n");
    return 0;
}

static void TestInnerDeviceFound(const DeviceInfo *device, const InnerDeviceInfoAddtions *additions)
{
    (void)device;
    (void)additions;
    g_devieceFoundCount++;
    DISC_LOGI(DISC_TEST, "[inner device found]success!\n");
}

static DiscInnerCallback g_innerCallback = { .OnDeviceFound = TestInnerDeviceFound };

static int32_t DiscCoapStartDiscovery(uint32_t filterCapBitmap, uint32_t discMode)
{
    if (g_coapDiscFunc == NULL) {
        printf("g_coapDiscFunc is NULL.\n");
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }

    g_subscribeOption.capabilityBitmap[0] = filterCapBitmap;
    switch (discMode) {
        case 0:
            if (g_coapDiscFunc->Subscribe(&g_subscribeOption) != 0) {
                printf("passivce start discvoery failed.\n");
                return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
            }
            break;
        case 1:
            if (g_coapDiscFunc->StartAdvertise(&g_subscribeOption) != 0) {
                printf("active start discvoery failed.\n");
                return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
            }
            break;
        default:
            printf("unsupport mode.\n");
            return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    return SOFTBUS_OK;
}

static int32_t DiscCoapStopDiscovery(uint32_t filterCapBitmap, uint32_t discMode)
{
    if (g_coapDiscFunc == NULL) {
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }

    g_subscribeOption.capabilityBitmap[0] = filterCapBitmap;
    switch (discMode) {
        case 0:
            if (g_coapDiscFunc->Unsubscribe(&g_subscribeOption) != 0) {
                return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
            }
            break;
        case 1:
            if (g_coapDiscFunc->StopAdvertise(&g_subscribeOption) != 0) {
                return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
            }
            break;
        default:
            return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    return SOFTBUS_OK;
}

static int32_t DiscCoapUnpulbishService(uint32_t pubCapBitmap, uint32_t publishMode)
{
    if (g_coapDiscFunc == NULL) {
        printf("g_coapDiscFunc is NULL.\n");
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }

    g_publishOption.capabilityBitmap[0] = pubCapBitmap;
    switch (publishMode) {
        case 0:
            if (g_coapDiscFunc->StopScan(&g_publishOption) != 0) {
                printf("passive unpublish failed.\n");
                return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
            }
            break;
        case 1:
            if (g_coapDiscFunc->Unpublish(&g_publishOption) != 0) {
                printf("active unpublish failed.\n");
                return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
            }
            break;
        default:
            printf("unsupport mode.\n");
            return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    return SOFTBUS_OK;
}

static DiscInnerCallback g_discInnerCb = { .OnDeviceFound = NULL };

static IServerDiscInnerCallback g_subscribeCb = { .OnServerDeviceFound = TestDeviceFound };

static PublishInfo g_pInnerInfo = { .publishId = TEST_PUBLISHINNER_ID,
    .mode = DISCOVER_MODE_PASSIVE,
    .medium = COAP,
    .freq = LOW,
    .capability = "hicall",
    .capabilityData = (unsigned char *)"capdata1",
    .dataLen = sizeof("capdata1") };

static PublishInfo g_pInfo = { .publishId = TEST_PUBLISH_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata2",
    .dataLen = sizeof("capdata2") };

static SubscribeInfo g_sInnerInfo = { .subscribeId = TEST_SUBSCRIBEINNER_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata3",
    .dataLen = sizeof("capdata3") };

static SubscribeInfo g_sInfo = { .subscribeId = TEST_SUBSCRIBE_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "hicall",
    .capabilityData = (unsigned char *)"capdata4",
    .dataLen = sizeof("capdata4") };

static PublishInfo g_pInnerInfo1 = { .publishId = TEST_PUBLISHINNER_ID1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = LOW,
    .capability = "hicall",
    .capabilityData = NULL,
    .dataLen = 0 };

static PublishInfo g_pInfo1 = { .publishId = TEST_PUBLISH_ID1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = NULL,
    .dataLen = 0 };

static SubscribeInfo g_sInnerInfo1 = { .subscribeId = TEST_SUBSCRIBEINNER_ID1,
    .mode = DISCOVER_MODE_PASSIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "dvKit",
    .capabilityData = NULL,
    .dataLen = 0 };

static SubscribeInfo g_sInfo1 = { .subscribeId = TEST_SUBSCRIBE_ID1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "hicall",
    .capabilityData = NULL,
    .dataLen = 0 };

/**
 * @tc.name: DiscPublishTest001
 * @tc.desc: Test inner module active publish, but softbus discover manager is not init.
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest001, TestSize.Level1)
{
    int32_t ret = DiscPublish(MODULE_CONN, &g_pInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscPublishTest002
 * @tc.desc: Test inner module active publish, use wrong Medium and Freq Under the COAP of MODULE_LNN.
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest002, TestSize.Level1)
{
    PublishInfo testInfo = { .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1") };

    DiscMgrInit();

    int32_t ret = DiscPublish((DiscModule)TEST_ERRO_MOUDULE, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capability = "hicall";
    testInfo.capabilityData = NULL;
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.dataLen = sizeof("capdata1");

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscPublishTest003
 * @tc.desc: Inner LNN module active publish, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest003, TestSize.Level1)
{
    DiscMgrInit();

    int32_t ret = DiscPublish(MODULE_LNN, &g_pInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscPublish(MODULE_LNN, &g_pInnerInfo1);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscPublishTest004
 * @tc.desc: Inner module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest004, TestSize.Level1)
{
    DiscMgrInit();

    int32_t ret = DiscPublish(MODULE_LNN, &g_pInnerInfo1);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscPublish(MODULE_LNN, &g_pInnerInfo1);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscPublishTest005
 * @tc.desc: Test inner module active publish, but softbus discover manager is not init.
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest005, TestSize.Level1)
{
    PublishInfo testInfo = { .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1") };

    int32_t ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

PublishInfo discPublishTestAbstractInfo001 = { .publishId = TEST_PUBLISHINNER_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = AUTO,
    .freq = LOW,
    .capability = "hicall",
    .capabilityData = (unsigned char *)"capdata1",
    .dataLen = sizeof("capdata1") };

void DiscPublishTestAbstract001(DiscModule module, PublishInfo *info)
{
    DiscMgrInit();

    int32_t ret = DiscPublish(module, info);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(module, info->publishId);

    info->freq = MID;
    ret = DiscPublish(module, info);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(module, info->publishId);

    info->freq = HIGH;
    ret = DiscPublish(module, info);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(module, info->publishId);

    info->freq = SUPER_HIGH;
    ret = DiscPublish(module, info);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(module, info->publishId);

    info->freq = EXTREME_HIGH;
    ret = DiscPublish(module, info);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(module, info->publishId);

    info->freq = LOW;
    DiscMgrDeinit();
}

/**
 * @tc.name: DiscPublishTest006
 * @tc.desc: Test inner module active publish, use Diff Freq Under the AUTO of MODULE_LNN.
 *           Test inner module active publish, use Diff Freq Under the AUTO of MODULE_CONN.
 *           Test inner module active publish, use Diff Freq Under the BLE of MODULE_LNN.
 *           Test inner module active publish, use Diff Freq Under the BLE of MODULE_CONN.
 *           Test inner module active publish, use Diff Freq Under the COAP of MODULE_LNN.
 *           Test inner module active publish, use Diff Freq Under the COAP of MODULE_LNN.
 *           Test inner module active publish, use Diff Freq Under the COAP of MODULE_CONN.
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest006, TestSize.Level1)
{
    DiscPublishTestAbstract001(MODULE_LNN, &discPublishTestAbstractInfo001);
    DiscPublishTestAbstract001(MODULE_CONN, &discPublishTestAbstractInfo001);

    discPublishTestAbstractInfo001.medium = BLE;
    DiscPublishTestAbstract001(MODULE_LNN, &discPublishTestAbstractInfo001);
    DiscPublishTestAbstract001(MODULE_CONN, &discPublishTestAbstractInfo001);

    discPublishTestAbstractInfo001.medium = COAP;
    DiscPublishTestAbstract001(MODULE_LNN, &discPublishTestAbstractInfo001);
    DiscPublishTestAbstract001(MODULE_CONN, &discPublishTestAbstractInfo001);
}

PublishInfo discPublishTestAbstractInfo002 = { .publishId = TEST_PUBLISHINNER_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = LOW,
    .capability = "hicall",
    .capabilityData = (unsigned char *)"capdata1",
    .dataLen = sizeof("capdata1") };

void DiscPublishTestAbstract002(DiscModule module, PublishInfo *info)
{
    DiscMgrInit();

    int32_t ret = DiscPublish((DiscModule)TEST_ERRO_MOUDULE2, info);
    TEST_ASSERT_TRUE(ret != 0);

    info->medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscPublish(module, info);
    TEST_ASSERT_TRUE(ret != 0);
    info->medium = COAP;

    info->freq = (ExchangeFreq)(LOW - 1);
    ret = DiscPublish(module, info);
    TEST_ASSERT_TRUE(ret != 0);
    info->freq = LOW;

    ret = DiscPublish(module, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscPublishTest007
 * @tc.desc: Test inner module active publish, use wrong Medium and Freq Under the COAP of MODULE_LNN.
 *           Test inner module active publish, use wrong Medium and Freq Under the BLE of MODULE_LNN.
 *           Test inner module active publish, use wrong Medium and Freq Under the AUTO of MODULE_LNN.
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest007, TestSize.Level1)
{
    DiscPublishTestAbstract002(MODULE_LNN, &discPublishTestAbstractInfo002);

    discPublishTestAbstractInfo002.medium = BLE;
    DiscPublishTestAbstract002(MODULE_LNN, &discPublishTestAbstractInfo002);

    discPublishTestAbstractInfo002.medium = AUTO;
    DiscPublishTestAbstract002(MODULE_LNN, &discPublishTestAbstractInfo002);
}

/**
 * @tc.name: DiscStartScanTest001
 * @tc.desc: Inner CONN module passive publish, the module is not initialized.
 * @tc.type: FUNC
 * @tc.require: The DiscStartScan operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartScanTest001, TestSize.Level1)
{
    int32_t ret = DiscStartScan(MODULE_CONN, &g_pInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscStartScanTest002
 * @tc.desc: Inner LNN module passive publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscStartScan operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartScanTest002, TestSize.Level1)
{
    PublishInfo testInfo = { .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1") };

    DiscMgrInit();

    int32_t ret = DiscStartScan((DiscModule)TEST_ERRO_MOUDULE, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = DiscStartScan(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = DiscStartScan(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capability = "hicall";
    testInfo.capabilityData = NULL;
    ret = DiscStartScan(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = DiscStartScan(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.dataLen = sizeof("capdata1");

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartScanTest003
 * @tc.desc: Inner LNN module passive publish, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscStartScan operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartScanTest003, TestSize.Level1)
{
    DiscMgrInit();

    int32_t ret = DiscStartScan(MODULE_LNN, &g_pInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartScanTest004
 * @tc.desc: Inner LNN module passive publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscStartScan operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartScanTest004, TestSize.Level1)
{
    DiscMgrInit();

    int32_t ret = DiscStartScan(MODULE_LNN, &g_pInnerInfo1);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartScanTest005
 * @tc.desc: Test passive discover, but softbus discover manager is not initialized.
 * @tc.type: FUNC
 * @tc.require:The DiscStartScan operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartScanTest005, TestSize.Level1)
{
    PublishInfo testInfo = { .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1") };

    int32_t ret = DiscStartScan(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

PublishInfo discStartScanTestAbstractInfo001 = { .publishId = TEST_PUBLISHINNER_ID,
    .mode = DISCOVER_MODE_PASSIVE,
    .medium = COAP,
    .freq = LOW,
    .capability = "hicall",
    .capabilityData = (unsigned char *)"capdata1",
    .dataLen = sizeof("capdata1") };

void DiscStartScanTestAbstract001(DiscModule module, PublishInfo *info, DiscModule erroModule)
{
    DiscMgrInit();

    int32_t ret = DiscStartScan(erroModule, info);
    TEST_ASSERT_TRUE(ret != 0);

    info->medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscStartScan(module, info);
    TEST_ASSERT_TRUE(ret != 0);
    info->medium = COAP;

    info->freq = (ExchangeFreq)(LOW - 1);
    ret = DiscStartScan(module, info);
    TEST_ASSERT_TRUE(ret != 0);
    info->freq = LOW;

    ret = DiscStartScan(module, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartScanTest006
 * @tc.desc: Test passive discover,use wrong Medium and Freq Under the COAP of MODULE_LNN.
 *           Test passive discover,use wrong Medium and Freq Under the AUTO of MODULE_LNN.
 *           Test passive discover,use wrong Medium and Freq Under the BLE of MODULE_LNN.
 * @tc.type: FUNC
 * @tc.require:The DiscStartScan operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartScanTest006, TestSize.Level1)
{
    DiscStartScanTestAbstract001(MODULE_LNN, &discStartScanTestAbstractInfo001, (DiscModule)TEST_ERRO_MOUDULE2);

    discStartScanTestAbstractInfo001.medium = AUTO;
    DiscStartScanTestAbstract001(MODULE_LNN, &discStartScanTestAbstractInfo001, (DiscModule)TEST_ERRO_MOUDULE1);

    discStartScanTestAbstractInfo001.medium = BLE;
    DiscStartScanTestAbstract001(MODULE_LNN, &discStartScanTestAbstractInfo001, (DiscModule)TEST_ERRO_MOUDULE2);
}

/**
 * @tc.name: DiscStartAdvertiseTest001
 * @tc.desc: Inner CONN module active discover, the module is not initialized.
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest001, TestSize.Level1)
{
    int32_t ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscStartAdvertiseTest002
 * @tc.desc: Inner LNN module active discover, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest002, TestSize.Level1)
{
    SubscribeInfo testInfo = { .subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3") };

    DiscMgrInit();

    int32_t ret = DiscStartAdvertise((DiscModule)TEST_ERRO_MOUDULE, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capability = "hicall";
    testInfo.capabilityData = NULL;
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.dataLen = sizeof("capdata1");

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartAdvertiseTest003
 * @tc.desc: Inner CONN module active discover, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest003, TestSize.Level1)
{
    DiscMgrInit();

    int32_t ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartAdvertiseTest004
 * @tc.desc: Inner CONN module active discover, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest004, TestSize.Level1)
{
    DiscMgrInit();

    int32_t ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo1);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

SubscribeInfo discStartAdvertiseTestAbstractInfo001 = { .subscribeId = TEST_SUBSCRIBEINNER_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata3",
    .dataLen = sizeof("capdata3") };

void DiscStartAdvertiseTestAbstract001(DiscModule module, SubscribeInfo *info)
{
    DiscMgrInit();

    int32_t ret = DiscStartAdvertise((DiscModule)TEST_ERRO_MOUDULE1, info);
    TEST_ASSERT_TRUE(ret != 0);

    info->medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscStartAdvertise(module, info);
    TEST_ASSERT_TRUE(ret != 0);
    info->medium = COAP;

    info->freq = (ExchangeFreq)(LOW - 1);
    ret = DiscStartAdvertise(module, info);
    TEST_ASSERT_TRUE(ret != 0);
    info->freq = LOW;

    ret = DiscStartAdvertise(module, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    info->freq = MID;
    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartAdvertiseTest005
 * @tc.desc: Test inner start discover, use wrong Medium and Freq Under the COAP of MODULE_LNN.
 *           Test inner start discover, use wrong Medium and Freq Under the BLE of MODULE_LNN.
 *           Test inner start discover, use wrong Medium and Freq Under the AUTO of MODULE_LNN.
 *           Test inner module active discover, but softbus discover manager is not init.
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest005, TestSize.Level1)
{
    DiscStartAdvertiseTestAbstract001(MODULE_LNN, &discStartAdvertiseTestAbstractInfo001);

    discStartAdvertiseTestAbstractInfo001.medium = BLE;
    DiscStartAdvertiseTestAbstract001(MODULE_LNN, &discStartAdvertiseTestAbstractInfo001);

    discStartAdvertiseTestAbstractInfo001.medium = AUTO;
    DiscStartAdvertiseTestAbstract001(MODULE_LNN, &discStartAdvertiseTestAbstractInfo001);

    discStartAdvertiseTestAbstractInfo001.medium = COAP;
    int32_t ret = DiscStartAdvertise(MODULE_CONN, &discStartAdvertiseTestAbstractInfo001);
    TEST_ASSERT_TRUE(ret == 0);
}

SubscribeInfo discStartAdvertiseTestAbstractInfo002 = { .subscribeId = TEST_SUBSCRIBEINNER_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = AUTO,
    .freq = LOW,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata3",
    .dataLen = sizeof("capdata3") };

void DiscStartAdvertiseTestAbstract002(DiscModule module, SubscribeInfo *info)
{
    DiscMgrInit();

    int32_t ret = DiscStartAdvertise(MODULE_LNN, info);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_LNN, info->subscribeId);

    info->freq = MID;
    ret = DiscStartAdvertise(MODULE_LNN, info);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_LNN, info->subscribeId);

    info->freq = HIGH;
    ret = DiscStartAdvertise(MODULE_LNN, info);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_LNN, info->subscribeId);

    info->freq = SUPER_HIGH;
    ret = DiscStartAdvertise(MODULE_LNN, info);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_LNN, info->subscribeId);

    info->freq = EXTREME_HIGH;
    ret = DiscStartAdvertise(MODULE_LNN, info);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_LNN, info->subscribeId);

    info->freq = LOW;
    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartAdvertiseTest006
 * @tc.desc: Test inner module active discover, use Diff Freq Under the AUTO of MODULE_LNN.
 *           Test inner module active discover, use Diff Freq Under the AUTO of MODULE_CONN.
 *           Test inner module active discover, use Diff Freq Under the BLE of MODULE_LNN.
 *           Test inner module active discover, use Diff Freq Under the BLE of MODULE_CONN.
 *           Test inner module active discover, use Diff Freq Under the COAP of MODULE_LNN.
 *           Test inner module active discover, use use Diff Freq Under the COAP of MODULE_CONN.
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest006, TestSize.Level1)
{
    DiscStartAdvertiseTestAbstract002(MODULE_LNN, &discStartAdvertiseTestAbstractInfo002);
    DiscStartAdvertiseTestAbstract002(MODULE_CONN, &discStartAdvertiseTestAbstractInfo002);

    discStartAdvertiseTestAbstractInfo002.medium = BLE;
    DiscStartAdvertiseTestAbstract002(MODULE_LNN, &discStartAdvertiseTestAbstractInfo002);
    DiscStartAdvertiseTestAbstract002(MODULE_CONN, &discStartAdvertiseTestAbstractInfo002);

    discStartAdvertiseTestAbstractInfo002.medium = COAP;
    DiscStartAdvertiseTestAbstract002(MODULE_LNN, &discStartAdvertiseTestAbstractInfo002);
    DiscStartAdvertiseTestAbstract002(MODULE_CONN, &discStartAdvertiseTestAbstractInfo002);
}

/**
 * @tc.name: DiscSubscribeTest001
 * @tc.desc: Inner CONN module passive discover, the module is not initialized.
 * @tc.type: FUNC
 * @tc.require: The DiscSubscribe operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSubscribeTest001, TestSize.Level1)
{
    int32_t ret = DiscSubscribe(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscSubscribeTest002
 * @tc.desc: Inner LNN module passive discover, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscSubscribe operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSubscribeTest002, TestSize.Level1)
{
    SubscribeInfo testInfo = { .subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3") };

    DiscMgrInit();

    int32_t ret = DiscSubscribe((DiscModule)TEST_ERRO_MOUDULE, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = DiscSubscribe(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = DiscSubscribe(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capability = "hicall";
    testInfo.capabilityData = NULL;
    ret = DiscSubscribe(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = DiscSubscribe(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.dataLen = sizeof("capdata1");

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSubscribeTest003
 * @tc.desc: Inner CONN module passive discover, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscSubscribe operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSubscribeTest003, TestSize.Level1)
{
    DiscMgrInit();

    int32_t ret = DiscSubscribe(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSubscribeTest004
 * @tc.desc: Inner CONN module passive discover, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscSubscribe operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSubscribeTest004, TestSize.Level1)
{
    DiscMgrInit();

    int32_t ret = DiscSubscribe(MODULE_CONN, &g_sInnerInfo1);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSubscribeTest005
 * @tc.desc: Inner CONN module passive discover, use the same parameter again, Perform two subscriptions.
 * @tc.type: FUNC
 * @tc.require:The DiscSubscribe operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSubscribeTest005, TestSize.Level1)
{
    DiscMgrInit();

    int32_t ret = DiscSubscribe(MODULE_CONN, &g_sInnerInfo1);
    ret = DiscSubscribe(MODULE_CONN, &g_sInnerInfo1);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

SubscribeInfo discSubscribeTestAbstractInfo001 = { .subscribeId = TEST_SUBSCRIBEINNER_ID,
    .mode = DISCOVER_MODE_PASSIVE,
    .medium = BLE,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata3",
    .dataLen = sizeof("capdata3") };

void DiscSubscribeTestAbstract001(DiscModule module, SubscribeInfo *info)
{
    DiscMgrInit();

    int32_t ret = DiscSubscribe((DiscModule)TEST_ERRO_MOUDULE1, info);
    TEST_ASSERT_TRUE(ret != 0);

    info->medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscSubscribe(module, info);
    TEST_ASSERT_TRUE(ret != 0);
    info->medium = COAP;

    info->freq = (ExchangeFreq)(LOW - 1);
    ret = DiscSubscribe(module, info);
    TEST_ASSERT_TRUE(ret != 0);
    info->freq = LOW;

    ret = DiscSubscribe(module, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    info->medium = BLE,
    info->freq = MID,
    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSubscribeTest006
 * @tc.desc: Inner LNN module passive discover, use wrong parameter.
 *           Inner LNN module passive discover, use the wrong parameter.
 *           Softbus discovery manager is not init.
 * @tc.type: FUNC
 * @tc.require: The DiscSubscribe operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSubscribeTest006, TestSize.Level1)
{
    DiscSubscribeTestAbstract001(MODULE_LNN, &discSubscribeTestAbstractInfo001);

    discSubscribeTestAbstractInfo001.medium = AUTO;
    DiscSubscribeTestAbstract001(MODULE_LNN, &discSubscribeTestAbstractInfo001);

    discSubscribeTestAbstractInfo001.medium = COAP;
    int32_t ret = DiscSubscribe(MODULE_CONN, &discSubscribeTestAbstractInfo001);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscUnpublishTest001
 * @tc.desc: Inner CONN module stop publish, the module is not initialized.
 * @tc.type: FUNC
 * @tc.require: The DiscUnpublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscUnpublishTest001, TestSize.Level1)
{
    int32_t ret = DiscUnpublish(MODULE_CONN, TEST_PUBLISHINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscUnpublishTest002
 * @tc.desc: Inner LNN module stop publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscUnpublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscUnpublishTest002, TestSize.Level1)
{
    DiscMgrInit();
    DiscPublish(MODULE_LNN, &g_pInnerInfo1);

    int32_t ret = DiscUnpublish((DiscModule)TEST_ERRO_MOUDULE, TEST_PUBLISHINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscUnpublishTest003
 * @tc.desc: Inner LNN module stop publish, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscUnpublish operates normally
 */
HWTEST_F(DiscManagerTest, DiscUnpublishTest003, TestSize.Level1)
{
    DiscMgrInit();
    DiscPublish(MODULE_LNN, &g_pInnerInfo1);

    int32_t ret = DiscUnpublish(MODULE_LNN, TEST_PUBLISHINNER_ID1);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscUnpublishTest004
 * @tc.desc: Inner LNN module stop publish, release the same parameter again, perform two subscriptions.
 * @tc.type: FUNC
 * @tc.require: The DiscUnpublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscUnpublishTest004, TestSize.Level1)
{
    DiscMgrInit();
    DiscPublish(MODULE_LNN, &g_pInnerInfo1);

    int32_t ret = DiscUnpublish(MODULE_LNN, TEST_PUBLISHINNER_ID1);

    ret = DiscUnpublish(MODULE_LNN, TEST_PUBLISHINNER_ID1);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscUnpublishTest005
 * @tc.desc: Inner LNN module stop publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscUppublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscUnpublishTest005, TestSize.Level1)
{
    DiscMgrInit();
    DiscPublish(MODULE_LNN, &g_pInnerInfo1);

    int32_t ret = DiscUnpublish((DiscModule)TEST_ERRO_MOUDULE1, TEST_PUBLISHINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscUnpublishTest006
 * @tc.desc: Inner CONN module stop publish, the module initialized, Directly to unpubish.
 * @tc.type: FUNC
 * @tc.require: The DiscUnpublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscUnpublishTest006, TestSize.Level1)
{
    DiscMgrInit();
    int32_t ret = DiscUnpublish(MODULE_CONN, TEST_PUBLISHINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);
    DiscMgrDeinit();
}

PublishInfo discUnpublishTestAbstractInfo001 = { .publishId = TEST_PUBLISHINNER_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = AUTO,
    .freq = LOW,
    .capability = "hicall",
    .capabilityData = (unsigned char *)"capdata1",
    .dataLen = sizeof("capdata1") };

void DiscUnpublishTestAbstract001(DiscModule module, PublishInfo *info)
{
    DiscMgrInit();

    DiscPublish(module, info);
    int32_t ret = DiscUnpublish(module, info->publishId);
    TEST_ASSERT_TRUE(ret == 0);

    info->freq = MID;
    DiscPublish(module, info);
    ret = DiscUnpublish(module, info->publishId);
    TEST_ASSERT_TRUE(ret == 0);

    info->freq = HIGH;
    DiscPublish(module, info);
    ret = DiscUnpublish(module, info->publishId);
    TEST_ASSERT_TRUE(ret == 0);

    info->freq = SUPER_HIGH;
    DiscPublish(module, info);
    ret = DiscUnpublish(module, info->publishId);
    TEST_ASSERT_TRUE(ret == 0);

    info->freq = EXTREME_HIGH;
    DiscPublish(module, info);
    ret = DiscUnpublish(module, info->publishId);
    TEST_ASSERT_TRUE(ret == 0);

    info->freq = LOW;
    DiscMgrDeinit();
}

/**
 * @tc.name: DiscUnpublishTest007
 * @tc.desc: Inner LNN module active publish, use the normal parameter and different frequencies under AUTO.
 *           Inner CONN module active publish, use the normal parameter and different frequencies under AUTO.
 *           Inner LNN module active publish, use the normal parameter and different frequencies under BLE.
 *           Inner CONN module active publish, use the normal parameter and different frequencies under BLE.
 *           inner LNN module active publish, use the normal parameter and different frequencies under COAP.
 *           inner CONN module active publish, use the normal parameter and different frequencies under COAP.
 * @tc.type: FUNC
 * @tc.require: The DiscUnpublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscUnpublishTest007, TestSize.Level1)
{
    DiscUnpublishTestAbstract001(MODULE_LNN, &discUnpublishTestAbstractInfo001);
    DiscUnpublishTestAbstract001(MODULE_CONN, &discUnpublishTestAbstractInfo001);

    discUnpublishTestAbstractInfo001.medium = BLE;
    DiscUnpublishTestAbstract001(MODULE_LNN, &discUnpublishTestAbstractInfo001);
    DiscUnpublishTestAbstract001(MODULE_CONN, &discUnpublishTestAbstractInfo001);

    discUnpublishTestAbstractInfo001.medium = COAP;
    DiscUnpublishTestAbstract001(MODULE_LNN, &discUnpublishTestAbstractInfo001);
    DiscUnpublishTestAbstract001(MODULE_LNN, &discUnpublishTestAbstractInfo001);
}

/**
 * @tc.name: DiscStopAdvertiseTest001
 * @tc.desc: Inner CONN module stop discover, the module is not initialized.
 * @tc.type: FUNC
 * @tc.require: The DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStopAdvertiseTest001, TestSize.Level1)
{
    int32_t ret = DiscStopAdvertise(MODULE_CONN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscStopAdvertiseTest002
 * @tc.desc: Inner module stop discover, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStopAdvertiseTest002, TestSize.Level1)
{
    DiscMgrInit();
    DiscStartAdvertise(MODULE_LNN, &g_sInnerInfo);

    int32_t ret = DiscStopAdvertise((DiscModule)TEST_ERRO_MOUDULE, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStopAdvertiseTest003
 * @tc.desc: Inner LNN module stop discover, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStopAdvertiseTest003, TestSize.Level1)
{
    DiscMgrInit();
    DiscStartAdvertise(MODULE_LNN, &g_sInnerInfo);

    int32_t ret = DiscStopAdvertise(MODULE_LNN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStopAdvertiseTest004
 * @tc.desc: Inner LNN module stop discover, use the same parameter again, perform two subscriptions.
 * @tc.type: FUNC
 * @tc.require: The DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStopAdvertiseTest004, TestSize.Level1)
{
    DiscMgrInit();
    DiscStartAdvertise(MODULE_LNN, &g_sInnerInfo);

    int32_t ret = DiscStopAdvertise(MODULE_LNN, TEST_SUBSCRIBEINNER_ID);
    ret = DiscStopAdvertise(MODULE_LNN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStopAdvertiseTest005
 * @tc.desc: Test inner module stop discover, use the wrong parameter.


 * @tc.type: FUNC
 * @tc.require:The DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStopAdvertiseTest005, TestSize.Level1)
{
    DiscMgrInit();
    DiscStartAdvertise(MODULE_LNN, &g_sInnerInfo);

    int32_t ret = DiscStopAdvertise((DiscModule)TEST_ERRO_MOUDULE1, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStopAdvertiseTest006
 * @tc.desc: Test inner module stop discover, bur module is not start discover.
 * @tc.type: FUNC
 * @tc.require:The DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStopAdvertiseTest006, TestSize.Level1)
{
    DiscMgrInit();
    int32_t ret = DiscStopAdvertise(MODULE_CONN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);
    DiscMgrDeinit();
}

SubscribeInfo discStopAdvertiseTestAbstractInfo001 = { .subscribeId = TEST_SUBSCRIBEINNER_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = AUTO,
    .freq = LOW,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata3",
    .dataLen = sizeof("capdata3") };

void DiscStopAdvertiseTestAbstract001(DiscModule module, SubscribeInfo *info)
{
    DiscMgrInit();

    DiscStartAdvertise(module, info);
    int32_t ret = DiscStopAdvertise(module, info->subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    info->freq = MID;
    DiscStartAdvertise(module, info);
    ret = DiscStopAdvertise(module, info->subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    info->freq = HIGH;
    DiscStartAdvertise(module, info);
    ret = DiscStopAdvertise(module, info->subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    info->freq = SUPER_HIGH;
    DiscStartAdvertise(module, info);
    ret = DiscStopAdvertise(module, info->subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    info->freq = EXTREME_HIGH;
    DiscStartAdvertise(module, info);
    ret = DiscStopAdvertise(module, info->subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    info->freq = LOW;
    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStopAdvertiseTest007
 * @tc.desc: Test inner module active discover, use Diff Freq Under the AUTO of MODULE_LNN.
 *           Test inner module active discover, use Diff Freq Under the AUTO of MODULE_CONN.
 *           Test inner module active discover, use Diff Freq Under the BLE of MODULE_LNN.
 *           Test inner module active discover, use Diff Freq Under the BLE of MODULE_CONN.
 *           Test inner module active discover, use Diff Freq Under the COAP of MODULE_LNN.
 *           Test inner module active discover, use Diff Freq Under the COAP of MODULE_CONN.
 * @tc.type: FUNC
 * @tc.require:The DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStopAdvertiseTest007, TestSize.Level1)
{
    DiscStopAdvertiseTestAbstract001(MODULE_LNN, &discStopAdvertiseTestAbstractInfo001);
    DiscStopAdvertiseTestAbstract001(MODULE_CONN, &discStopAdvertiseTestAbstractInfo001);

    discStopAdvertiseTestAbstractInfo001.medium = BLE;
    DiscStopAdvertiseTestAbstract001(MODULE_LNN, &discStopAdvertiseTestAbstractInfo001);
    DiscStopAdvertiseTestAbstract001(MODULE_CONN, &discStopAdvertiseTestAbstractInfo001);

    discStopAdvertiseTestAbstractInfo001.medium = COAP;
    DiscStopAdvertiseTestAbstract001(MODULE_LNN, &discStopAdvertiseTestAbstractInfo001);
    DiscStopAdvertiseTestAbstract001(MODULE_CONN, &discStopAdvertiseTestAbstractInfo001);
}

/**
 * @tc.name: PublishServiceTest001
 * @tc.desc: Extern module publish, the module is not initialized.
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, PublishServiceTest001, TestSize.Level1)
{
    int32_t ret = DiscPublishService("pkgname1", &g_pInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: PublishServiceTest002
 * @tc.desc: Extern module active publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, PublishServiceTest002, TestSize.Level1)
{
    PublishInfo testInfo = { .publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2") };

    DiscMgrInit();

    int32_t ret = DiscPublishService(NULL, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscPublishService(g_erroPkgName, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscPublishService("pkgname1", NULL);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.mode = DISCOVER_MODE_ACTIVE;

    testInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capability = "dvKit";
    testInfo.capabilityData = NULL;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.dataLen = sizeof("capdata1");

    DiscMgrDeinit();
}

/**
 * @tc.name: PublishServiceTest003
 * @tc.desc: Extern module publish, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally
 */
HWTEST_F(DiscManagerTest, PublishServiceTest003, TestSize.Level1)
{
    DiscMgrInit();

    int32_t ret = DiscPublishService("pkgname1", &g_pInfo);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscPublishService("pkgname1", &g_pInfo1);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscPublishService(g_corrPkgName, &g_pInfo);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: PublishServiceTest004
 * @tc.desc: Extern module publish, use the same parameter again, perform two subscriptions.
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, PublishServiceTest004, TestSize.Level1)
{
    DiscMgrInit();

    int32_t ret = DiscPublishService("pkgname1", &g_pInfo);
    ret = DiscPublishService("pkgname1", &g_pInfo);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: PublishServiceTest005
 * @tc.desc: Test extern module active publish, use the wrong Medium and Freq Under the COAP.
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, PublishServiceTest005, TestSize.Level1)
{
    PublishInfo testInfo = { .publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2") };

    DiscMgrInit();

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    int32_t ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    DiscMgrDeinit();
}

/**
 * @tc.name: PublishServiceTest006
 * @tc.desc: Test extern module active publish, use wrong Medium and Freq Under the BLE.
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, PublishServiceTest006, TestSize.Level1)
{
    PublishInfo testInfo = { .publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2") };

    DiscMgrInit();

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    int32_t ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    DiscMgrDeinit();
}

/**
 * @tc.name: PublishServiceTest007
 * @tc.desc: Test extern module active publish, use wrong Medium and Freq Under the AUTO.
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, PublishServiceTest007, TestSize.Level1)
{
    PublishInfo testInfo = { .publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2") };

    DiscMgrInit();

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    int32_t ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    DiscMgrDeinit();
}

PublishInfo publishServiceTestAbstractInfo = { .publishId = TEST_PUBLISH_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = AUTO,
    .freq = LOW,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata2",
    .dataLen = sizeof("capdata2") };

void PublishServiceTestAbstract001(PublishInfo *info)
{
    DiscMgrInit();

    int32_t ret = DiscPublishService("pkgname1", info);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", info->publishId);

    info->freq = MID;
    ret = DiscPublishService("pkgname1", info);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", info->publishId);

    info->freq = HIGH;
    ret = DiscPublishService("pkgname1", info);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", info->publishId);

    info->freq = SUPER_HIGH;
    ret = DiscPublishService("pkgname1", info);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", info->publishId);

    info->freq = EXTREME_HIGH;
    ret = DiscPublishService("pkgname1", info);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", info->publishId);

    info->freq = LOW;
    DiscMgrDeinit();
}

/**
 * @tc.name: PublishServiceTest008
 * @tc.desc: Test extern module active publish, use Diff Freq Under the AUTO.
 *           Test extern module passive publish, use Diff Freq Under the AUTO.
 *           Test extern module active publish, use Diff Freq Under the BLE.
 *           Test extern module passive publish, use Diff Freq Under the BLE.
 *           Test extern module active publish, use Diff Freq Under the COAP.
 *           Test extern module passive publish, use Diff Freq Under the COAP.
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, PublishServiceTest008, TestSize.Level1)
{
    PublishServiceTestAbstract001(&publishServiceTestAbstractInfo);

    publishServiceTestAbstractInfo.mode = DISCOVER_MODE_PASSIVE;
    PublishServiceTestAbstract001(&publishServiceTestAbstractInfo);

    publishServiceTestAbstractInfo.mode = DISCOVER_MODE_ACTIVE;
    publishServiceTestAbstractInfo.medium = BLE;
    PublishServiceTestAbstract001(&publishServiceTestAbstractInfo);

    publishServiceTestAbstractInfo.mode = DISCOVER_MODE_PASSIVE;
    PublishServiceTestAbstract001(&publishServiceTestAbstractInfo);

    publishServiceTestAbstractInfo.mode = DISCOVER_MODE_ACTIVE;
    publishServiceTestAbstractInfo.medium = COAP;
    PublishServiceTestAbstract001(&publishServiceTestAbstractInfo);

    publishServiceTestAbstractInfo.mode = DISCOVER_MODE_ACTIVE;
    PublishServiceTestAbstract001(&publishServiceTestAbstractInfo);
}

/**
 * @tc.name: StartDiscoveryTest001
 * @tc.desc: Extern module discover, the module is not initialized.
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StartDiscoveryTest001, TestSize.Level1)
{
    int32_t ret = DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: StartDiscoveryTest002
 * @tc.desc: Extern module active discover, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally
 */
HWTEST_F(DiscManagerTest, StartDiscoveryTest002, TestSize.Level1)
{
    SubscribeInfo testInfo = { .subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3") };

    DiscMgrInit();

    int32_t ret = DiscStartDiscovery(NULL, &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscStartDiscovery(g_erroPkgName, &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscStartDiscovery("pkgname1", NULL, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscStartDiscovery("pkgname1", &testInfo, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.mode = DISCOVER_MODE_ACTIVE;

    testInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capability = "dvKit";
    testInfo.capabilityData = NULL;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.dataLen = sizeof("capdata1");

    DiscMgrDeinit();
}

/**
 * @tc.name: StartDiscoveryTest003
 * @tc.desc: Extern module discover, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StartDiscoveryTest003, TestSize.Level1)
{
    DiscMgrInit();

    int32_t ret = DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscStartDiscovery("pkgname1", &g_sInfo1, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscStartDiscovery(g_corrPkgName, &g_sInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: StartDiscoveryTest004
 * @tc.desc: Extern module discover, use the same parameter again, perform two subscriptions.
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StartDiscoveryTest004, TestSize.Level1)
{
    DiscMgrInit();

    int32_t ret = DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);
    ret = DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

SubscribeInfo startDiscoveryTestAbstractInfo002 = { .subscribeId = TEST_SUBSCRIBEINNER_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata3",
    .dataLen = sizeof("capdata3") };

void StartDiscoveryTestAbstract002(SubscribeInfo *info)
{
    DiscMgrInit();

    info->medium = (ExchangeMedium)(AUTO - 1);
    int32_t ret = DiscStartDiscovery("pkgname1", info, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);
    info->medium = COAP;

    info->freq = (ExchangeFreq)(LOW - 1);
    ret = DiscStartDiscovery("pkgname1", info, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);
    info->freq = LOW;

    info->medium = COAP;
    info->freq = MID;
    DiscMgrDeinit();
}

/**
 * @tc.name: StartDiscoveryTest005
 * @tc.desc: Test extern module active discover, use wrong Medium and Freq Under the COAP.
 *           Test extern module active discover, use wrong Medium and Freq Under the BLE.
 *           Test extern module active discover, use wrong Medium and Freq Under the AUTO.
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StartDiscoveryTest005, TestSize.Level1)
{
    StartDiscoveryTestAbstract002(&startDiscoveryTestAbstractInfo002);

    startDiscoveryTestAbstractInfo002.medium = BLE;
    StartDiscoveryTestAbstract002(&startDiscoveryTestAbstractInfo002);

    startDiscoveryTestAbstractInfo002.medium = AUTO;
    StartDiscoveryTestAbstract002(&startDiscoveryTestAbstractInfo002);
}

SubscribeInfo startDiscoveryTestAbstractInfo001 = { .subscribeId = TEST_SUBSCRIBE_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = AUTO,
    .freq = LOW,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata3",
    .dataLen = sizeof("capdata3") };

void StartDiscoveryTestAbstract001(SubscribeInfo *info)
{
    DiscMgrInit();

    int32_t ret = DiscStartDiscovery("pkgname1", info, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", info->subscribeId);

    info->freq = MID;
    ret = DiscStartDiscovery("pkgname1", info, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", info->subscribeId);

    info->freq = HIGH;
    ret = DiscStartDiscovery("pkgname1", info, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", info->subscribeId);

    info->freq = SUPER_HIGH;
    ret = DiscStartDiscovery("pkgname1", info, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", info->subscribeId);

    info->freq = EXTREME_HIGH;
    ret = DiscStartDiscovery("pkgname1", info, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", info->subscribeId);

    DiscMgrDeinit();
}

/**
 * @tc.name: StartDiscoveryTest006
 * @tc.desc: Test extern module active discover, use Diff Freq Under the AUTO.
 *           Test extern module passive discover, use Diff Freq Under the AUTO.
 *           Test extern module active discover, use Diff Freq Under the BLE.
 *           Test extern module discover, use the normal parameter and different frequencies under passive COAP.
 *           Test extern module discover, use the normal parameter and different frequencies under passive BLE.
 *           Test extern module discover, use the normal parameter and different frequencies under active COAP.
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StartDiscoveryTest006, TestSize.Level1)
{
    StartDiscoveryTestAbstract001(&startDiscoveryTestAbstractInfo001);

    startDiscoveryTestAbstractInfo001.mode = DISCOVER_MODE_PASSIVE;
    StartDiscoveryTestAbstract001(&startDiscoveryTestAbstractInfo001);

    startDiscoveryTestAbstractInfo001.mode = DISCOVER_MODE_ACTIVE;
    startDiscoveryTestAbstractInfo001.medium = BLE;
    StartDiscoveryTestAbstract001(&startDiscoveryTestAbstractInfo001);

    startDiscoveryTestAbstractInfo001.mode = DISCOVER_MODE_PASSIVE;
    startDiscoveryTestAbstractInfo001.medium = COAP;
    StartDiscoveryTestAbstract001(&startDiscoveryTestAbstractInfo001);

    startDiscoveryTestAbstractInfo001.medium = BLE;
    StartDiscoveryTestAbstract001(&startDiscoveryTestAbstractInfo001);

    startDiscoveryTestAbstractInfo001.mode = DISCOVER_MODE_ACTIVE;
    startDiscoveryTestAbstractInfo001.medium = COAP;
    StartDiscoveryTestAbstract001(&startDiscoveryTestAbstractInfo001);
}

/**
 * @tc.name: UnPublishServiceTest001
 * @tc.desc: Extern module stop publish, the module is not initialized.
 * @tc.type: FUNC
 * @tc.require: The DiscUnPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, UnPublishServiceTest001, TestSize.Level1)
{
    int32_t ret = DiscUnPublishService("pkgname1", TEST_PUBLISH_ID);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UnPublishServiceTest002
 * @tc.desc: Extern module stop publish, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscUnPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, UnPublishServiceTest002, TestSize.Level1)
{
    DiscMgrInit();
    DiscPublishService("pkgname1", &g_pInfo);

    int32_t ret = DiscUnPublishService(NULL, TEST_PUBLISH_ID);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscUnPublishService(g_erroPkgName, TEST_PUBLISH_ID);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscUnPublishService("pkgname2", TEST_PUBLISH_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: UnPublishServiceTest003
 * @tc.desc: Extern module stop publish, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscUnPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, UnPublishServiceTest003, TestSize.Level1)
{
    DiscMgrInit();
    DiscPublishService("pkgname1", &g_pInfo);
    DiscPublishService("pkgname1", &g_pInfo1);
    DiscPublishService(g_corrPkgName, &g_pInfo);

    int32_t ret = DiscUnPublishService("pkgname1", TEST_PUBLISH_ID);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscUnPublishService("pkgname1", TEST_PUBLISH_ID1);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscUnPublishService(g_corrPkgName, TEST_PUBLISH_ID);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: UnPublishServiceTest004
 * @tc.desc: Extern module stop publish, release the same parameter again, perform two subscriptions.
 * @tc.type: FUNC
 * @tc.require: The DiscUnPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, UnPublishServiceTest004, TestSize.Level1)
{
    DiscMgrInit();
    DiscPublishService("pkgname1", &g_pInfo);

    int32_t ret = DiscUnPublishService("pkgname1", TEST_PUBLISH_ID);
    ret = DiscUnPublishService("pkgname1", TEST_PUBLISH_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

void UnPublishServiceTestAbstract001(PublishInfo *info)
{
    DiscMgrInit();

    DiscPublishService("pkgname1", info);
    int32_t ret = DiscUnPublishService("pkgname1", info->publishId);
    TEST_ASSERT_TRUE(ret == 0);

    info->freq = MID;
    DiscPublishService("pkgname1", info);
    ret = DiscUnPublishService("pkgname1", info->publishId);
    TEST_ASSERT_TRUE(ret == 0);

    info->freq = HIGH;
    DiscPublishService("pkgname1", info);
    ret = DiscUnPublishService("pkgname1", info->publishId);
    TEST_ASSERT_TRUE(ret == 0);

    info->freq = SUPER_HIGH;
    DiscPublishService("pkgname1", info);
    ret = DiscUnPublishService("pkgname1", info->publishId);
    TEST_ASSERT_TRUE(ret == 0);

    info->freq = EXTREME_HIGH;
    DiscPublishService("pkgname1", info);
    ret = DiscUnPublishService("pkgname1", info->publishId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: UnPublishServiceTest005
 * @tc.desc: Extern module stop publish, use the normal parameter and different frequencies under active COAP.
 *           Extern module stop publish, use the normal parameter and different frequencies under passive COAP.
 *           Extern module stop publish, use the normal parameter and different frequencies under active BLE.
 *           Extern module stop publish, use the normal parameter and different frequencies under passive BLE.
 *           Extern module stop publish, use the normal parameter and different frequencies under active AUTO.
 *           Extern module stop publish, use the normal parameter and different frequencies under passive AUTO.
 * @tc.type: FUNC
 * @tc.require: The DiscUnPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, UnPublishServiceTest005, TestSize.Level1)
{
    publishServiceTestAbstractInfo.medium = AUTO;
    UnPublishServiceTestAbstract001(&publishServiceTestAbstractInfo);

    publishServiceTestAbstractInfo.mode = DISCOVER_MODE_PASSIVE;
    UnPublishServiceTestAbstract001(&publishServiceTestAbstractInfo);

    publishServiceTestAbstractInfo.mode = DISCOVER_MODE_ACTIVE;
    publishServiceTestAbstractInfo.medium = BLE;
    UnPublishServiceTestAbstract001(&publishServiceTestAbstractInfo);

    publishServiceTestAbstractInfo.mode = DISCOVER_MODE_PASSIVE;
    UnPublishServiceTestAbstract001(&publishServiceTestAbstractInfo);

    publishServiceTestAbstractInfo.mode = DISCOVER_MODE_ACTIVE;
    publishServiceTestAbstractInfo.medium = AUTO;
    UnPublishServiceTestAbstract001(&publishServiceTestAbstractInfo);

    publishServiceTestAbstractInfo.mode = DISCOVER_MODE_PASSIVE;
    UnPublishServiceTestAbstract001(&publishServiceTestAbstractInfo);
}

/**
 * @tc.name: StopDiscoveryTest001
 * @tc.desc: Extern module stop discover, the module is not initialized.
 * @tc.type: FUNC
 * @tc.require: The DiscStopDiscovery operates normally
 */
HWTEST_F(DiscManagerTest, StopDiscoveryTest001, TestSize.Level1)
{
    int32_t ret = DiscStopDiscovery("pkgname1", TEST_SUBSCRIBE_ID);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: StopDiscoveryTest002
 * @tc.desc: Extern module stop discover, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscStopDiscovery operates normally
 */
HWTEST_F(DiscManagerTest, StopDiscoveryTest002, TestSize.Level1)
{
    DiscMgrInit();
    DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);

    int32_t ret = DiscStopDiscovery(NULL, TEST_SUBSCRIBE_ID);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscStopDiscovery(g_erroPkgName, TEST_SUBSCRIBE_ID);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscStopDiscovery("pkgname2", TEST_SUBSCRIBE_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: StopDiscoveryTest003
 * @tc.desc: Extern module stop discover, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscStopDiscovery operates normally
 */
HWTEST_F(DiscManagerTest, StopDiscoveryTest003, TestSize.Level1)
{
    DiscMgrInit();
    DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);
    DiscStartDiscovery("pkgname1", &g_sInfo1, &g_subscribeCb);
    DiscStartDiscovery(g_corrPkgName, &g_sInfo, &g_subscribeCb);

    int32_t ret = DiscStopDiscovery("pkgname1", TEST_SUBSCRIBE_ID);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscStopDiscovery("pkgname1", TEST_SUBSCRIBE_ID1);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscStopDiscovery(g_corrPkgName, TEST_SUBSCRIBE_ID);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: StopDiscoveryTest004
 * @tc.desc: Extern module stop discover, release the same parameter again, perform two subscriptions.
 * @tc.type: FUNC
 * @tc.require: The DiscStopDiscovery operates normally
 */
HWTEST_F(DiscManagerTest, StopDiscoveryTest004, TestSize.Level1)
{
    DiscMgrInit();
    DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);

    int32_t ret = DiscStopDiscovery("pkgname1", TEST_SUBSCRIBE_ID);
    ret = DiscStopDiscovery("pkgname1", TEST_SUBSCRIBE_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

SubscribeInfo stopDiscoveryTestAbstractInfo001 = { .subscribeId = TEST_SUBSCRIBE_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = LOW,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata3",
    .dataLen = sizeof("capdata3") };

void StopDiscoveryTestAbstract001(SubscribeInfo *info)
{
    DiscMgrInit();

    DiscStartDiscovery("pkgname1", info, &g_subscribeCb);
    int32_t ret = DiscStopDiscovery("pkgname1", info->subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    info->freq = MID;
    DiscStartDiscovery("pkgname1", info, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", info->subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    info->freq = HIGH;
    DiscStartDiscovery("pkgname1", info, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", info->subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    info->freq = SUPER_HIGH;
    DiscStartDiscovery("pkgname1", info, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", info->subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    info->freq = EXTREME_HIGH;
    DiscStartDiscovery("pkgname1", info, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", info->subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: StopDiscoveryTest005
 * @tc.desc: Test extern module stop active discover, use Diff Freq Under the COAP.
 *           Test extern module stop passive discover, use Diff Freq Under the COAP.
 *           Test extern module stop active discover, use Diff Freq Under the BLE.
 *           Test extern module stop passive discover, use Diff Freq Under the BLE.
 *           Test extern module stop active discover, use Diff Freq Under the AUTO.
 *           Test extern module stop passive discover, use Diff Freq Under the AUTO.
 * @tc.type: FUNC
 * @tc.require: The DiscStopDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StopDiscoveryTest005, TestSize.Level1)
{
    StopDiscoveryTestAbstract001(&stopDiscoveryTestAbstractInfo001);

    stopDiscoveryTestAbstractInfo001.mode = DISCOVER_MODE_PASSIVE;
    StopDiscoveryTestAbstract001(&stopDiscoveryTestAbstractInfo001);

    stopDiscoveryTestAbstractInfo001.mode = DISCOVER_MODE_ACTIVE;
    stopDiscoveryTestAbstractInfo001.medium = BLE;
    StopDiscoveryTestAbstract001(&stopDiscoveryTestAbstractInfo001);

    stopDiscoveryTestAbstractInfo001.mode = DISCOVER_MODE_PASSIVE;
    StopDiscoveryTestAbstract001(&stopDiscoveryTestAbstractInfo001);

    stopDiscoveryTestAbstractInfo001.mode = DISCOVER_MODE_ACTIVE;
    stopDiscoveryTestAbstractInfo001.medium = AUTO;
    StopDiscoveryTestAbstract001(&stopDiscoveryTestAbstractInfo001);

    stopDiscoveryTestAbstractInfo001.mode = DISCOVER_MODE_PASSIVE;
    StopDiscoveryTestAbstract001(&stopDiscoveryTestAbstractInfo001);
}

/**
 * @tc.name: DiscSetDiscoverCallbackTest001
 * @tc.desc: Callback set process.
 * @tc.type: FUNC
 * @tc.require: DiscSetDiscoverCallback and DiscStartAdvertise and DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSetDiscoverCallbackTest001, TestSize.Level1)
{
    DiscMgrInit();

    int32_t ret = DiscSetDiscoverCallback(MODULE_CONN, &g_innerCallback);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscStopAdvertise(MODULE_CONN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSetDiscoverCallbackTest002
 * @tc.desc: Callback set process.
 * @tc.type: FUNC
 * @tc.require: DiscStartAdvertise and DiscSetDiscoverCallback and DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSetDiscoverCallbackTest002, TestSize.Level1)
{
    DiscMgrInit();

    int32_t ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscSetDiscoverCallback(MODULE_CONN, &g_innerCallback);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscStopAdvertise(MODULE_CONN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSetDiscoverCallbackTest003
 * @tc.desc: Extern onDeviceFound test.
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSetDiscoverCallbackTest003, TestSize.Level1)
{
    DeviceInfo devInfo;
    DiscMgrInit();
    int32_t ret = DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);

    devInfo.capabilityBitmap[0] = TEST_BITMAP_CAP;
    TestInnerDeviceFound(&devInfo, NULL);
    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSetDiscoverCallbackTest004
 * @tc.desc: Inner onDeviceFound test.
 * @tc.type: FUNC
 * @tc.require: DiscStartAdvertise and DiscSetDiscoverCallback and DiscStopAdvertise operates normally
 */
HWTEST_F(DiscManagerTest, DiscSetDiscoverCallbackTest004, TestSize.Level1)
{
    DeviceInfo devInfo;
    DiscMgrInit();

    int32_t ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscSetDiscoverCallback(MODULE_CONN, &g_innerCallback);
    TEST_ASSERT_TRUE(ret == 0);

    devInfo.capabilityBitmap[0] = TEST_BITMAP_CAP;
    TestInnerDeviceFound(&devInfo, NULL);

    ret = DiscStopAdvertise(MODULE_CONN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSetDiscoverCallbackTest005
 * @tc.desc: Inner onDeviceFound test with no callback.
 * @tc.type: FUNC
 * @tc.require: DiscStartAdvertise and DiscStopAdvertise operates normally
 */
HWTEST_F(DiscManagerTest, DiscSetDiscoverCallbackTest005, TestSize.Level1)
{
    DeviceInfo devInfo;
    DiscMgrInit();

    int32_t ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    devInfo.capabilityBitmap[0] = TEST_BITMAP_CAP;
    TestInnerDeviceFound(&devInfo, NULL);

    ret = DiscStopAdvertise(MODULE_CONN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSetDiscoverCallbackTest006
 * @tc.desc: Callback use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require: DiscStartAdvertise and DiscSetDiscoverCallback and DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSetDiscoverCallbackTest006, TestSize.Level1)
{
    DiscMgrInit();

    int32_t ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscSetDiscoverCallback(MODULE_CONN, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscStopAdvertise(MODULE_CONN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscCoapStopDiscoveryTest001
 * @tc.desc: Active stop discovery, use the normal parameter.
 * @tc.type: FUNC
 * @tc.require: The DiscCoapStopDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, DiscCoapStopDiscoveryTest001, TestSize.Level1)
{
    g_coapDiscFunc = DiscCoapInit(&g_discInnerCb);
    DiscCoapStartDiscovery(1, 1);

    int32_t ret = DiscCoapStopDiscovery(1, 1);
    TEST_ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: DiscCoapStopDiscoveryTest002
 * @tc.desc: Passive stop discovery, the module is not initialized.
 * @tc.type: FUNC
 * @tc.require: The DiscCoapStopDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, DiscCoapStopDiscoveryTest002, TestSize.Level1)
{
    DiscCoapStartDiscovery(1, 1);
    int32_t ret = DiscCoapStopDiscovery(1, 1);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscCoapStopDiscoveryTest003
 * @tc.desc: Active stop discovery, the module is not initialized.
 * @tc.type: FUNC
 * @tc.require: The DiscCoapStopDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, DiscCoapStopDiscoveryTest003, TestSize.Level1)
{
    int32_t ret = DiscCoapStopDiscovery(1, 1);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscCoapPulbishServiceTest001
 * @tc.desc: Inner module publishing, use wrong parameters.
 * @tc.type: FUNC
 * @tc.require: The DiscCoapUnpulbishService operates normally.
 */
HWTEST_F(DiscManagerTest, DiscCoapPulbishServiceTest001, TestSize.Level1)
{
    g_coapDiscFunc = DiscCoapInit(&g_discInnerCb);

    int32_t ret = DiscCoapUnpulbishService(PUB_CAP_BITMAP_2, PUBLISH_MODE_2);
    TEST_ASSERT_TRUE(ret != 0);
    DiscCoapDeinit();
}

/**
 * @tc.name: DiscCoapPulbishServiceTest002
 * @tc.desc: Inner module publishing, use normal parameters.
 * @tc.type: FUNC
 * @tc.require: The DiscCoapUnpulbishService operates normally.
 */
HWTEST_F(DiscManagerTest, DiscCoapPulbishServiceTest002, TestSize.Level1)
{
    g_coapDiscFunc = DiscCoapInit(&g_discInnerCb);

    int32_t ret = DiscCoapUnpulbishService(1, 0);
    TEST_ASSERT_TRUE(ret == 0);
    DiscCoapDeinit();
}

/**
 * @tc.name: DiscCoapStartDiscoveryTest001
 * @tc.desc: Inner module Discovery, use wrong parameters.
 * @tc.type: FUNC
 * @tc.require: The DiscCoapStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, DiscCoapStartDiscoveryTest001, TestSize.Level1)
{
    g_coapDiscFunc = DiscCoapInit(&g_discInnerCb);

    int32_t ret = DiscCoapStartDiscovery(FILTER_CAP_BITMAP_2, DISC_MODE_2);
    TEST_ASSERT_TRUE(ret != 0);
    DiscCoapDeinit();
}

/**
 * @tc.name: DiscCoapStartDiscoveryTest002
 * @tc.desc: Test coap discovery, use normal parameters.
 * @tc.type: FUNC
 * @tc.require: The DiscCoapStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, DiscCoapStartDiscoveryTest002, TestSize.Level1)
{
    g_coapDiscFunc = DiscCoapInit(&g_discInnerCb);

    int32_t ret = DiscCoapStartDiscovery(1, 1);
    TEST_ASSERT_TRUE(ret == 0);
    DiscCoapDeinit();
}

/**
 * @tc.name: DiscCoapUnpulbishServiceTest001
 * @tc.desc: Inner modules stop publishing, using wrong parameters.
 * @tc.type: FUNC
 * @tc.require: The DiscCoapUnpulbishService operates normally.
 */
HWTEST_F(DiscManagerTest, DiscCoapUnpulbishServiceTest001, TestSize.Level1)
{
    g_coapDiscFunc = DiscCoapInit(&g_discInnerCb);

    int32_t ret = DiscCoapUnpulbishService(PUB_CAP_BITMAP_2, PUBLISH_MODE_2);
    TEST_ASSERT_TRUE(ret != 0);
    DiscCoapDeinit();
}

/**
 * @tc.name: DiscCoapUnpulbishServiceTest002
 * @tc.desc: Test stop publishing, using the normal parameters.
 * @tc.type: FUNC
 * @tc.require: The DiscCoapUnpulbishService operates normally.
 */
HWTEST_F(DiscManagerTest, DiscCoapUnpulbishServiceTest002, TestSize.Level1)
{
    g_coapDiscFunc = DiscCoapInit(&g_discInnerCb);

    int32_t ret = DiscCoapUnpulbishService(1, 0);
    TEST_ASSERT_TRUE(ret == 0);
    DiscCoapDeinit();
}
} // namespace OHOS
