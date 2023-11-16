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
#include <securec.h>
#include <cstdint>

#include "disc_log.h"
#include "disc_manager.h"
#include "nstackx.h"
#include "disc_coap.h"
#include "softbus_errcode.h"

#define TEST_ERRO_MOUDULE1      ((MODULE_LNN) - 1)
#define TEST_ERRO_MOUDULE2      ((MODULE_LNN) - 2)
#define TEST_ERRO_MOUDULE       ((MODULE_LNN) + 3)
#define ERRO_CAPDATA_LEN        (MAX_CAPABILITYDATA_LEN + 1)
#define TEST_ASSERT_TRUE(ret)  \
    if (ret) {                 \
        DISC_LOGI(DISC_TEST, "[succ]\n");    \
        g_succTestCount++;       \
    } else {                   \
        DISC_LOGI(DISC_TEST, "[error]\n");    \
        g_failTestCount++;       \
    }


using namespace testing::ext;

namespace OHOS {
static int32_t g_succTestCount = 0;
static int32_t g_failTestCount = 0;
static int32_t g_devieceFoundCount = 0;
static const char *g_corrPkgName = "CorrCorrCorrCorrCorrCorrCorrCorrCorrCorrCorrCorrCorrCorrCorrCorr";
static const char *g_erroPkgName = "ErroErroErroErroErroErroErroErroErroErroErroErroErroErroErroErroE";
static DiscoveryFuncInterface *g_coapDiscFunc = NULL;
static PublishOption g_publishOption = {.freq = 0, .capabilityBitmap = {1}, .capabilityData = NULL, .dataLen = 0};
static SubscribeOption g_subscribeOption = {.freq = 1,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capabilityBitmap = {2},
    .capabilityData = NULL,
    .dataLen = 0
};

const int32_t TEST_PUBLISHINNER_ID = 1;
const int32_t TEST_PUBLISH_ID = 2;
const int32_t TEST_SUBSCRIBEINNER_ID = 3;
const int32_t TEST_SUBSCRIBE_ID = 4;
const int32_t TEST_PUBLISHINNER_ID1 = 5;
const int32_t TEST_PUBLISH_ID1 = 6;
const int32_t TEST_SUBSCRIBEINNER_ID1 = 7;
const int32_t TEST_SUBSCRIBE_ID1 = 8;
const int32_t TEST_BITMAP_CAP = 127;

class DiscManagerTest : public testing::Test {
public:
    DiscManagerTest()
    {}
    ~DiscManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void DiscManagerTest::SetUpTestCase(void)
{}

void DiscManagerTest::TearDownTestCase(void)
{}

static int32_t TestDeviceFound(const char *packageName, const DeviceInfo *device,
    const InnerDeviceInfoAddtions *addtions)
{
    (void)addtions;
    g_devieceFoundCount++;
    DISC_LOGI(DISC_TEST, "[device found]success!\n");
    return 0;
}

static void TestInnerDeviceFound(const DeviceInfo *device, const InnerDeviceInfoAddtions *addtions)
{
    (void)device;
    (void)addtions;
    g_devieceFoundCount++;
    DISC_LOGI(DISC_TEST, "[inner device found]success!\n");
}

static DiscInnerCallback g_innerCallback = {
    .OnDeviceFound = TestInnerDeviceFound
};

static int32_t DiscCoapStartDiscovery(uint32_t filterCapBitmap, uint32_t discMode)
{
    if (g_coapDiscFunc == NULL) {
        printf("g_coapDiscFunc is NULL.\n");
        return SOFTBUS_ERR;
    }

    g_subscribeOption.capabilityBitmap[0] = filterCapBitmap;
    switch (discMode) {
        case 0:
            if (g_coapDiscFunc->Subscribe(&g_subscribeOption) != 0) {
                printf("passivce start discvoery failed.\n");
                return SOFTBUS_ERR;
            }
            break;
        case 1:
            if (g_coapDiscFunc->StartAdvertise(&g_subscribeOption) != 0) {
                printf("active start discvoery failed.\n");
                return SOFTBUS_ERR;
            }
            break;
        default:
            printf("unsupport mode.\n");
            return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DiscCoapStopDiscovery(uint32_t filterCapBitmap, uint32_t discMode)
{
    if (g_coapDiscFunc == NULL) {
        return SOFTBUS_ERR;
    }

    g_subscribeOption.capabilityBitmap[0] = filterCapBitmap;
    switch (discMode) {
        case 0:
            if (g_coapDiscFunc->Unsubscribe(&g_subscribeOption) != 0) {
                return SOFTBUS_ERR;
            }
            break;
        case 1:
            if (g_coapDiscFunc->StopAdvertise(&g_subscribeOption) != 0) {
                return SOFTBUS_ERR;
            }
            break;
        default:
            return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DiscCoapUnpulbishService(uint32_t pubCapBitmap, uint32_t publishMode)
{
    if (g_coapDiscFunc == NULL) {
        printf("g_coapDiscFunc is NULL.\n");
        return SOFTBUS_ERR;
    }

    g_publishOption.capabilityBitmap[0] = pubCapBitmap;
    switch (publishMode) {
        case 0:
            if (g_coapDiscFunc->StopScan(&g_publishOption) != 0) {
                printf("passive unpublish failed.\n");
                return SOFTBUS_ERR;
            }
            break;
        case 1:
            if (g_coapDiscFunc->Unpublish(&g_publishOption) != 0) {
                printf("active unpublish failed.\n");
                return SOFTBUS_ERR;
            }
            break;
        default:
            printf("unsupport mode.\n");
            return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static DiscInnerCallback g_discInnerCb = {
    .OnDeviceFound = NULL
};

static IServerDiscInnerCallback g_subscribeCb = {
    .OnServerDeviceFound = TestDeviceFound
};

static PublishInfo g_pInnerInfo = {
    .publishId = TEST_PUBLISHINNER_ID,
    .mode = DISCOVER_MODE_PASSIVE,
    .medium = COAP,
    .freq = LOW,
    .capability = "hicall",
    .capabilityData = (unsigned char *)"capdata1",
    .dataLen = sizeof("capdata1")
};

static PublishInfo g_pInfo = {
    .publishId = TEST_PUBLISH_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata2",
    .dataLen = sizeof("capdata2")
};

static SubscribeInfo g_sInnerInfo = {
    .subscribeId = TEST_SUBSCRIBEINNER_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata3",
    .dataLen = sizeof("capdata3")
};

static SubscribeInfo g_sInfo = {
    .subscribeId = TEST_SUBSCRIBE_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "hicall",
    .capabilityData = (unsigned char *)"capdata4",
    .dataLen = sizeof("capdata4")
};

static PublishInfo g_pInnerInfo1 = {
    .publishId = TEST_PUBLISHINNER_ID1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = LOW,
    .capability = "hicall",
    .capabilityData = NULL,
    .dataLen = 0
};

static PublishInfo g_pInfo1 = {
    .publishId = TEST_PUBLISH_ID1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = NULL,
    .dataLen = 0
};

static SubscribeInfo g_sInnerInfo1 = {
    .subscribeId = TEST_SUBSCRIBEINNER_ID1,
    .mode = DISCOVER_MODE_PASSIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "dvKit",
    .capabilityData = NULL,
    .dataLen = 0
};

static SubscribeInfo g_sInfo1 = {
    .subscribeId = TEST_SUBSCRIBE_ID1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "hicall",
    .capabilityData = NULL,
    .dataLen = 0
};

/**
 * @tc.name: DiscPublishTest001
 * @tc.desc: Test inner module active publish，but softbus discover manager is not init.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest001, TestSize.Level1)
{
    int ret;
    ret = DiscPublish(MODULE_CONN, &g_pInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscPublishTest002
 * @tc.desc: Test inner module active publish, use wrong Medium and Freq Under the COAP of MODULE_LNN.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest002, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    ret = DiscPublish((DiscModule)TEST_ERRO_MOUDULE, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(SUPER_HIGH + 1);
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
 * @tc.desc: Inner LNN module active publish，use the normal parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest003, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscPublish(MODULE_LNN, &g_pInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscPublish(MODULE_LNN, &g_pInnerInfo1);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscPublishTest004
 * @tc.desc: Inner module active publish，use the wrong parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscPublish(MODULE_LNN, &g_pInnerInfo1);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscPublish(MODULE_LNN, &g_pInnerInfo1);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscPublishTest005
 * @tc.desc: Test inner module active publish，but softbus discover manager is not init.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest005, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char*)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscPublishTest006
 * @tc.desc: Test inner module active publish, use Diff Freq Under the AUTO of MODULE_LNN.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest006, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_LNN, testInfo.publishId);

    testInfo.freq = MID;
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_LNN, testInfo.publishId);

    testInfo.freq = HIGH;
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_LNN, testInfo.publishId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_LNN, testInfo.publishId);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscPublishTest007
 * @tc.desc: Test inner module active publish, use Diff Freq Under the AUTO of MODULE_CONN.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest007, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    ret = DiscPublish(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_CONN, testInfo.publishId);

    testInfo.freq = MID;
    ret = DiscPublish(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_CONN, testInfo.publishId);

    testInfo.freq = HIGH;
    ret = DiscPublish(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_CONN, testInfo.publishId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscPublish(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_CONN, testInfo.publishId);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscPublishTest008
 * @tc.desc: Test inner module active publish, use Diff Freq Under the BLE of MODULE_LNN.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest008, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_LNN, testInfo.publishId);

    testInfo.freq = MID;
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_LNN, testInfo.publishId);

    testInfo.freq = HIGH;
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_LNN, testInfo.publishId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_LNN, testInfo.publishId);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscPublishTest009
 * @tc.desc: Test inner module active publish, use Diff Freq Under the BLE of MODULE_CONN.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest009, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    ret = DiscPublish(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_CONN, testInfo.publishId);

    testInfo.freq = MID;
    ret = DiscPublish(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_CONN, testInfo.publishId);

    testInfo.freq = HIGH;
    ret = DiscPublish(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_CONN, testInfo.publishId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscPublish(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_CONN, testInfo.publishId);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscPublishTest010
 * @tc.desc: Test inner module active publish, use Diff Freq Under the COAP of MODULE_LNN.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest010, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_LNN, testInfo.publishId);

    testInfo.freq = MID;
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_LNN, testInfo.publishId);

    testInfo.freq = HIGH;
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_LNN, testInfo.publishId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_LNN, testInfo.publishId);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscPublishTest011
 * @tc.desc: Test inner module active publish, use Diff Freq Under the COAP of MODULE_CONN.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest011, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    ret = DiscPublish(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_CONN, testInfo.publishId);

    testInfo.freq = MID;
    ret = DiscPublish(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_CONN, testInfo.publishId);

    testInfo.freq = HIGH;
    ret = DiscPublish(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_CONN, testInfo.publishId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscPublish(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_CONN, testInfo.publishId);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscPublishTest012
 * @tc.desc: Test inner module active publish, use wrong Medium and Freq Under the COAP of MODULE_LNN.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest012, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char*)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    ret = DiscPublish((DiscModule)TEST_ERRO_MOUDULE2, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    ret = DiscPublish(MODULE_LNN, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscPublishTest013
 * @tc.desc: Test inner module active publish, use wrong Medium and Freq Under the BLE of MODULE_LNN.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest013, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char*)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    ret = DiscPublish((DiscModule)TEST_ERRO_MOUDULE2, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    ret = DiscPublish(MODULE_LNN, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscPublishTest014
 * @tc.desc: Test inner module active publish, use wrong Medium and Freq Under the AUTO of MODULE_LNN.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest014, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char*)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    ret = DiscPublish((DiscModule)TEST_ERRO_MOUDULE2, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    ret = DiscPublish(MODULE_LNN, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscPublishTest015
 * @tc.desc: Inner CONN module active publish，use the normal parameter and different frequencies under COAP.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscPublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscPublishTest015, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {.publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1")};

    DiscMgrInit();

    ret = DiscPublish(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_CONN, testInfo.publishId);

    testInfo.freq = MID;
    ret = DiscPublish(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_CONN, testInfo.publishId);

    testInfo.freq = HIGH;
    ret = DiscPublish(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_CONN, testInfo.publishId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscPublish(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnpublish(MODULE_CONN, testInfo.publishId);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartScanTest001
 * @tc.desc: Inner CONN module passive publish，the module is not initialized.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscStartScan operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartScanTest001, TestSize.Level1)
{
    int ret;
    ret = DiscStartScan(MODULE_CONN, &g_pInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscStartScanTest002
 * @tc.desc: Inner LNN module passive publish，use the wrong parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscStartScan operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartScanTest002, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {.publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1")};

    DiscMgrInit();

    ret = DiscStartScan((DiscModule)TEST_ERRO_MOUDULE, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = DiscStartScan(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(SUPER_HIGH + 1);
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
 * @tc.desc: Inner LNN module passive publish，use the normal parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStartScan operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartScanTest003, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscStartScan(MODULE_LNN, &g_pInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartScanTest004
 * @tc.desc: Inner LNN module passive publish，use the wrong parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscStartScan operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartScanTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscStartScan(MODULE_LNN, &g_pInnerInfo1);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartScanTest005
 * @tc.desc: Test passive discover, but softbus discover manager is not initialized.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require:The DiscStartScan operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartScanTest005, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    ret = DiscStartScan(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscStartScanTest006
 * @tc.desc: Test passive discover,use wrong Medium and Freq Under the COAP of MODULE_LNN.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require:The DiscStartScan operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartScanTest006, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char*)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    ret = DiscStartScan((DiscModule)TEST_ERRO_MOUDULE2, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscStartScan(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = DiscStartScan(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    ret = DiscStartScan(MODULE_LNN, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartScanTest007
 * @tc.desc: Test passive discover,use wrong Medium and Freq Under the AUTO of MODULE_LNN.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require:The DiscStartScan operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartScanTest007, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    ret = DiscStartScan((DiscModule)TEST_ERRO_MOUDULE1, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscStartScan(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = DiscStartScan(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    ret = DiscStartScan(MODULE_LNN, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartScanTest008
 * @tc.desc: Test passive discover,use wrong Medium and Freq Under the BLE of MODULE_LNN.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:The DiscStartScan operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartScanTest008, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = BLE,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char*)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    ret = DiscStartScan((DiscModule)TEST_ERRO_MOUDULE2, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscStartScan(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = DiscStartScan(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    ret = DiscStartScan(MODULE_LNN, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartAdvertiseTest001
 * @tc.desc: Inner CONN module active discover，the module is not initialized.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest001, TestSize.Level1)
{
    int ret;
    ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscStartAdvertiseTest002
 * @tc.desc: Inner LNN module active discover，use the wrong parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest002, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {.subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")};

    DiscMgrInit();

    ret = DiscStartAdvertise((DiscModule)TEST_ERRO_MOUDULE, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(SUPER_HIGH + 1);
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
 * @tc.desc: Inner CONN module active discover，use the normal parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest003, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartAdvertiseTest004
 * @tc.desc: Inner CONN module active discover，use the wrong parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo1);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartAdvertiseTest005
 * @tc.desc: Test inner start discover, use wrong Medium and Freq Under the COAP of MODULE_LNN.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest005, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {.subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")};

    DiscMgrInit();

    ret = DiscStartAdvertise((DiscModule)TEST_ERRO_MOUDULE1, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    ret = DiscStartAdvertise(MODULE_LNN, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartAdvertiseTest006
 * @tc.desc: Test inner start discover, use wrong Medium and Freq Under the BLE of MODULE_LNN.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest006, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {.subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")};

    DiscMgrInit();

    ret = DiscStartAdvertise((DiscModule)TEST_ERRO_MOUDULE1, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    ret = DiscStartAdvertise(MODULE_LNN, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartAdvertiseTest007
 * @tc.desc: Test inner start discover, use wrong Medium and Freq Under the AUTO of MODULE_LNN.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest007, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {.subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")};

    DiscMgrInit();

    ret = DiscStartAdvertise((DiscModule)TEST_ERRO_MOUDULE1, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    ret = DiscStartAdvertise(MODULE_LNN, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartAdvertiseTest008
 * @tc.desc: Test inner module active discover，but softbus discover manager is not init.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest008, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {.subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")};

    ret = DiscStartAdvertise(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: DiscStartAdvertiseTest009
 * @tc.desc: Test inner module active discover，use Diff Freq Under the AUTO of MODULE_LNN.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest009, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {.subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")};

    DiscMgrInit();

    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);

    testInfo.freq = MID;
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);

    testInfo.freq = HIGH;
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartAdvertiseTest010
 * @tc.desc: Test inner module active discover，use Diff Freq Under the AUTO of MODULE_CONN.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest010, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {.subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")};

    DiscMgrInit();

    ret = DiscStartAdvertise(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);

    testInfo.freq = MID;
    ret = DiscStartAdvertise(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);

    testInfo.freq = HIGH;
    ret = DiscStartAdvertise(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscStartAdvertise(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartAdvertiseTest011
 * @tc.desc: Test inner module active discover，use Diff Freq Under the BLE of MODULE_LNN.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest011, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {.subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")};

    DiscMgrInit();

    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);

    testInfo.freq = MID;
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);

    testInfo.freq = HIGH;
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartAdvertiseTest012
 * @tc.desc: Test inner module active discover，use Diff Freq Under the BLE of MODULE_CONN.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest012, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {.subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")};

    DiscMgrInit();

    ret = DiscStartAdvertise(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);

    testInfo.freq = MID;
    ret = DiscStartAdvertise(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);

    testInfo.freq = HIGH;
    ret = DiscStartAdvertise(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscStartAdvertise(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartAdvertiseTest013
 * @tc.desc: Test inner module active discover，use Diff Freq Under the COAP of MODULE_LNN.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest013, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {.subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")};

    DiscMgrInit();

    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);

    testInfo.freq = MID;
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);

    testInfo.freq = HIGH;
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartAdvertiseTest014
 * @tc.desc: Test inner module active discover，use use Diff Freq Under the COAP of MODULE_CONN.
 * @tc.in: Test Module, Test Number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest014, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {.subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")};

    DiscMgrInit();

    ret = DiscStartAdvertise(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);

    testInfo.freq = MID;
    ret = DiscStartAdvertise(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);

    testInfo.freq = HIGH;
    ret = DiscStartAdvertise(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscStartAdvertise(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartAdvertiseTest015
 * @tc.desc: Inner CONN module active discover，use the normal parameter and different frequencies under COAP.
 * @tc.in: test module, test number, test levels.
 * @tc.out: Zero.
 * @tc.type: FUNC
 * @tc.require: The DiscStartAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStartAdvertiseTest015, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {.subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")};

    DiscMgrInit();

    ret = DiscStartAdvertise(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);

    testInfo.freq = MID;
    ret = DiscStartAdvertise(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);

    testInfo.freq = HIGH;
    ret = DiscStartAdvertise(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscStartAdvertise(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSubscribeTest001
 * @tc.desc: Inner CONN module passive discover，the module is not initialized.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscSubscribe operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSubscribeTest001, TestSize.Level1)
{
    int ret;
    ret = DiscSubscribe(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscSubscribeTest002
 * @tc.desc: Inner LNN module passive discover，use the wrong parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscSubscribe operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSubscribeTest002, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {.subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")};

    DiscMgrInit();

    ret = DiscSubscribe((DiscModule)TEST_ERRO_MOUDULE, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = DiscSubscribe(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(SUPER_HIGH + 1);
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
 * @tc.desc: Inner CONN module passive discover，use the wrong parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscSubscribe operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSubscribeTest003, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscSubscribe(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSubscribeTest004
 * @tc.desc: Inner CONN module passive discover，use the normal parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscSubscribe operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSubscribeTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscSubscribe(MODULE_CONN, &g_sInnerInfo1);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSubscribeTest005
 * @tc.desc: Inner CONN module passive discover，use the same parameter again, Perform two subscriptions.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require:The DiscSubscribe operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSubscribeTest005, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscSubscribe(MODULE_CONN, &g_sInnerInfo1);
    ret = DiscSubscribe(MODULE_CONN, &g_sInnerInfo1);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSubscribeTest006
 * @tc.desc: Inner LNN module passive discover, use wrong parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscSubscribe operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSubscribeTest006, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = BLE,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char*)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    ret = DiscSubscribe((DiscModule)TEST_ERRO_MOUDULE1, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscSubscribe(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = DiscSubscribe(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    ret = DiscSubscribe(MODULE_LNN, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSubscribeTest007
 * @tc.desc: Inner LNN module passive discover，use the wrong parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscSubscribe operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSubscribeTest007, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char*)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    ret = DiscSubscribe((DiscModule)TEST_ERRO_MOUDULE1, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscSubscribe(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = DiscSubscribe(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    ret = DiscSubscribe(MODULE_LNN, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSubscribeTest008
 * @tc.desc: Softbus discovery manager is not init.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscSubscribe operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSubscribeTest008, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char*)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    ret = DiscSubscribe(MODULE_CONN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscUnpublishTest001
 * @tc.desc: Inner CONN module stop publish，the module is not initialized.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscUnpublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscUnpublishTest001, TestSize.Level1)
{
    int ret;
    ret = DiscUnpublish(MODULE_CONN, TEST_PUBLISHINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscUnpublishTest002
 * @tc.desc: Inner LNN module stop publish，use the wrong parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscUnpublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscUnpublishTest002, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscPublish(MODULE_LNN, &g_pInnerInfo1);

    ret = DiscUnpublish((DiscModule)TEST_ERRO_MOUDULE, TEST_PUBLISHINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscUnpublishTest003
 * @tc.desc: Inner LNN module stop publish，use the normal parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscUnpublish operates normally
 */
HWTEST_F(DiscManagerTest, DiscUnpublishTest003, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscPublish(MODULE_LNN, &g_pInnerInfo1);

    ret = DiscUnpublish(MODULE_LNN, TEST_PUBLISHINNER_ID1);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscUnpublishTest004
 * @tc.desc: Inner LNN module stop publish，release the same parameter again, perform two subscriptions.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscUnpublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscUnpublishTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscPublish(MODULE_LNN, &g_pInnerInfo1);

    ret = DiscUnpublish(MODULE_LNN, TEST_PUBLISHINNER_ID1);

    ret = DiscUnpublish(MODULE_LNN, TEST_PUBLISHINNER_ID1);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscUnpublishTest005
 * @tc.desc: Inner LNN module stop publish，use the wrong parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscUppublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscUnpublishTest005, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscPublish(MODULE_LNN, &g_pInnerInfo1);

    ret = DiscUnpublish((DiscModule)TEST_ERRO_MOUDULE1, TEST_PUBLISHINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscUnpublishTest006
 * @tc.desc: Inner CONN module stop publish，the module initialized, Directly to unpubish.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscUnpublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscUnpublishTest006, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    ret = DiscUnpublish(MODULE_CONN, TEST_PUBLISHINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);
    DiscMgrDeinit();
}

/**
 * @tc.name: DiscUnpublishTest007
 * @tc.desc: Inner LNN module active publish, use the normal parameter and different frequencies under AUTO.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscUnpublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscUnpublishTest007, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    DiscPublish(MODULE_LNN, &testInfo);
    ret = DiscUnpublish(MODULE_LNN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscPublish(MODULE_LNN, &testInfo);
    ret = DiscUnpublish(MODULE_LNN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscPublish(MODULE_LNN, &testInfo);
    ret = DiscUnpublish(MODULE_LNN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscPublish(MODULE_LNN, &testInfo);
    ret = DiscUnpublish(MODULE_LNN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscUnpublishTest008
 * @tc.desc: Inner CONN module active publish，use the normal parameter and different frequencies under AUTO.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscUnpublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscUnpublishTest008, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    DiscPublish(MODULE_CONN, &testInfo);
    ret = DiscUnpublish(MODULE_CONN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscPublish(MODULE_CONN, &testInfo);
    ret = DiscUnpublish(MODULE_CONN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscPublish(MODULE_CONN, &testInfo);
    ret = DiscUnpublish(MODULE_CONN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscPublish(MODULE_CONN, &testInfo);
    ret = DiscUnpublish(MODULE_CONN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscUnpublishTest009
 * @tc.desc: Inner LNN module active publish，use the normal parameter and different frequencies under BLE.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscUnpublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscUnpublishTest009, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    DiscPublish(MODULE_LNN, &testInfo);
    ret = DiscUnpublish(MODULE_LNN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscPublish(MODULE_LNN, &testInfo);
    ret = DiscUnpublish(MODULE_LNN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscPublish(MODULE_LNN, &testInfo);
    ret = DiscUnpublish(MODULE_LNN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscPublish(MODULE_LNN, &testInfo);
    ret = DiscUnpublish(MODULE_LNN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscUnpublishTest010
 * @tc.desc: inner CONN module active publish，use the normal parameter and different frequencies under BLE.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscUnpublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscUnpublishTest010, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    DiscPublish(MODULE_CONN, &testInfo);
    ret = DiscUnpublish(MODULE_CONN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscPublish(MODULE_CONN, &testInfo);
    ret = DiscUnpublish(MODULE_CONN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscPublish(MODULE_CONN, &testInfo);
    ret = DiscUnpublish(MODULE_CONN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscPublish(MODULE_CONN, &testInfo);
    ret = DiscUnpublish(MODULE_CONN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscUnpublishTest011
 * @tc.desc: inner LNN module active publish，use the normal parameter and different frequencies under COAP.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscUnpublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscUnpublishTest011, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    DiscPublish(MODULE_LNN, &testInfo);
    ret = DiscUnpublish(MODULE_LNN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscPublish(MODULE_LNN, &testInfo);
    ret = DiscUnpublish(MODULE_LNN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscPublish(MODULE_LNN, &testInfo);
    ret = DiscUnpublish(MODULE_LNN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscPublish(MODULE_LNN, &testInfo);
    ret = DiscUnpublish(MODULE_LNN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscUnpublishTest012
 * @tc.desc: inner CONN module active publish，use the normal parameter and different frequencies under COAP.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscUnpublish operates normally.
 */
HWTEST_F(DiscManagerTest, DiscUnpublishTest012, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    DiscPublish(MODULE_CONN, &testInfo);
    ret = DiscUnpublish(MODULE_CONN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscPublish(MODULE_CONN, &testInfo);
    ret = DiscUnpublish(MODULE_CONN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscPublish(MODULE_CONN, &testInfo);
    ret = DiscUnpublish(MODULE_CONN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscPublish(MODULE_CONN, &testInfo);
    ret = DiscUnpublish(MODULE_CONN, testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStopAdvertiseTest001
 * @tc.desc: Inner CONN module stop discover，the module is not initialized.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStopAdvertiseTest001, TestSize.Level1)
{
    int ret;
    ret = DiscStopAdvertise(MODULE_CONN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscStopAdvertiseTest002
 * @tc.desc: Inner module stop discover，use the wrong parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStopAdvertiseTest002, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscStartAdvertise(MODULE_LNN, &g_sInnerInfo);

    ret = DiscStopAdvertise((DiscModule)TEST_ERRO_MOUDULE, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStopAdvertiseTest003
 * @tc.desc: Inner LNN module stop discover，use the normal parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStopAdvertiseTest003, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscStartAdvertise(MODULE_LNN, &g_sInnerInfo);

    ret = DiscStopAdvertise(MODULE_LNN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStopAdvertiseTest004
 * @tc.desc: Inner LNN module stop discover，use the same parameter again, perform two subscriptions.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStopAdvertiseTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscStartAdvertise(MODULE_LNN, &g_sInnerInfo);

    ret = DiscStopAdvertise(MODULE_LNN, TEST_SUBSCRIBEINNER_ID);
    ret = DiscStopAdvertise(MODULE_LNN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStopAdvertiseTest005
 * @tc.desc: Test inner module stop discover，use the wrong parameter.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require:The DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStopAdvertiseTest005, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscStartAdvertise(MODULE_LNN, &g_sInnerInfo);

    ret = DiscStopAdvertise((DiscModule)TEST_ERRO_MOUDULE1, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStopAdvertiseTest006
 * @tc.desc: Test inner module stop discover，bur module is not start discover.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require:The DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStopAdvertiseTest006, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    ret = DiscStopAdvertise(MODULE_CONN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);
    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStopAdvertiseTest007
 * @tc.desc: Test inner module active discover，use Diff Freq Under the AUTO of MODULE_LNN.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:The DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStopAdvertiseTest007, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    DiscStartAdvertise(MODULE_LNN, &testInfo);
    ret = DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscStartAdvertise(MODULE_LNN, &testInfo);
    ret = DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscStartAdvertise(MODULE_LNN, &testInfo);
    ret = DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscStartAdvertise(MODULE_LNN, &testInfo);
    ret = DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStopAdvertiseTest008
 * @tc.desc: Test inner module active discover，use Diff Freq Under the AUTO of MODULE_CONN.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:The DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStopAdvertiseTest008, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    DiscStartAdvertise(MODULE_CONN, &testInfo);
    ret = DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscStartAdvertise(MODULE_CONN, &testInfo);
    ret = DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscStartAdvertise(MODULE_CONN, &testInfo);
    ret = DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscStartAdvertise(MODULE_CONN, &testInfo);
    ret = DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStopAdvertiseTest009
 * @tc.desc: Test inner module active discover，use Diff Freq Under the BLE of MODULE_LNN.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:The DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStopAdvertiseTest009, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    DiscStartAdvertise(MODULE_LNN, &testInfo);
    ret = DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscStartAdvertise(MODULE_LNN, &testInfo);
    ret = DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscStartAdvertise(MODULE_LNN, &testInfo);
    ret = DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscStartAdvertise(MODULE_LNN, &testInfo);
    ret = DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStopAdvertiseTest010
 * @tc.desc: Test inner module active discover，use Diff Freq Under the BLE of MODULE_CONN.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:The DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStopAdvertiseTest010, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    DiscStartAdvertise(MODULE_CONN, &testInfo);
    ret = DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscStartAdvertise(MODULE_CONN, &testInfo);
    ret = DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscStartAdvertise(MODULE_CONN, &testInfo);
    ret = DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscStartAdvertise(MODULE_CONN, &testInfo);
    ret = DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStopAdvertiseTest011
 * @tc.desc: Test inner module active discover，use Diff Freq Under the COAP of MODULE_LNN.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:The DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStopAdvertiseTest011, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    DiscStartAdvertise(MODULE_LNN, &testInfo);
    ret = DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscStartAdvertise(MODULE_LNN, &testInfo);
    ret = DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscStartAdvertise(MODULE_LNN, &testInfo);
    ret = DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscStartAdvertise(MODULE_LNN, &testInfo);
    ret = DiscStopAdvertise(MODULE_LNN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStopAdvertiseTest012
 * @tc.desc: Test inner module active discover，use Diff Freq Under the COAP of MODULE_CONN.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:The DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscStopAdvertiseTest012, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    DiscStartAdvertise(MODULE_CONN, &testInfo);
    ret = DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscStartAdvertise(MODULE_CONN, &testInfo);
    ret = DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscStartAdvertise(MODULE_CONN, &testInfo);
    ret = DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscStartAdvertise(MODULE_CONN, &testInfo);
    ret = DiscStopAdvertise(MODULE_CONN, testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: PublishServiceTest001
 * @tc.desc: Extern module publish，the module is not initialized.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, PublishServiceTest001, TestSize.Level1)
{
    int ret;
    ret = DiscPublishService("pkgname1", &g_pInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: PublishServiceTest002
 * @tc.desc: Extern module active publish，use the wrong parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, PublishServiceTest002, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {.publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")};

    DiscMgrInit();

    ret = DiscPublishService(NULL, &testInfo);
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

    testInfo.freq = (ExchangeFreq)(SUPER_HIGH + 1);
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
 * @tc.desc: Extern module publish，use the normal parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally
 */
HWTEST_F(DiscManagerTest, PublishServiceTest003, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscPublishService("pkgname1", &g_pInfo);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscPublishService("pkgname1", &g_pInfo1);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscPublishService(g_corrPkgName, &g_pInfo);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: PublishServiceTest004
 * @tc.desc: Extern module publish，use the same parameter again, perform two subscriptions.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, PublishServiceTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscPublishService("pkgname1", &g_pInfo);
    ret = DiscPublishService("pkgname1", &g_pInfo);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: PublishServiceTest005
 * @tc.desc: Test extern module active publish，use the wrong Medium and Freq Under the COAP.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, PublishServiceTest005, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    DiscMgrInit();

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscPublishService("pkgname1", &testInfo);
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
 * @tc.desc: Test extern module active publish，use wrong Medium and Freq Under the BLE.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, PublishServiceTest006, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    DiscMgrInit();

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscPublishService("pkgname1", &testInfo);
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
 * @tc.desc: Test extern module active publish，use wrong Medium and Freq Under the AUTO.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, PublishServiceTest007, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    DiscMgrInit();

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    DiscMgrDeinit();
}

/**
 * @tc.name: PublishServiceTest008
 * @tc.desc: Test extern module active publish，use Diff Freq Under the AUTO.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, PublishServiceTest008, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    DiscMgrInit();

    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    testInfo.freq = MID;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    testInfo.freq = HIGH;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    DiscMgrDeinit();
}

/**
 * @tc.name: PublishServiceTest009
 * @tc.desc: Test extern module passive publish，use Diff Freq Under the AUTO.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, PublishServiceTest009, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    DiscMgrInit();

    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    testInfo.freq = MID;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    testInfo.freq = HIGH;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    DiscMgrDeinit();
}

/**
 * @tc.name: PublishServiceTest010
 * @tc.desc: Test extern module active publish，use Diff Freq Under the BLE.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, PublishServiceTest010, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    DiscMgrInit();

    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    testInfo.freq = MID;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    testInfo.freq = HIGH;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    DiscMgrDeinit();
}

/**
 * @tc.name: PublishServiceTest011
 * @tc.desc: Test extern module passive publish，use Diff Freq Under the BLE.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, PublishServiceTest011, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = BLE,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    DiscMgrInit();

    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    testInfo.freq = MID;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    testInfo.freq = HIGH;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    DiscMgrDeinit();
}

/**
 * @tc.name: PublishServiceTest012
 * @tc.desc: Test extern module active publish，use Diff Freq Under the COAP.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, PublishServiceTest012, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    DiscMgrInit();

    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    testInfo.freq = MID;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    testInfo.freq = HIGH;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    DiscMgrDeinit();
}

/**
 * @tc.name: PublishServiceTest013
 * @tc.desc: Test extern module passive publish，use Diff Freq Under the COAP.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, PublishServiceTest013, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {
        .publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    DiscMgrInit();

    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    testInfo.freq = MID;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    testInfo.freq = HIGH;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscPublishService("pkgname1", &testInfo);
    TEST_ASSERT_TRUE(ret == 0);
    DiscUnPublishService("pkgname1", testInfo.publishId);

    DiscMgrDeinit();
}

/**
 * @tc.name: StartDiscoveryTest001
 * @tc.desc: Extern module discover，the module is not initialized.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StartDiscoveryTest001, TestSize.Level1)
{
    int ret;
    ret = DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: StartDiscoveryTest002
 * @tc.desc: Extern module active discover，use the wrong parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally
 */
HWTEST_F(DiscManagerTest, StartDiscoveryTest002, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {.subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")};

    DiscMgrInit();

    ret = DiscStartDiscovery(NULL, &testInfo, &g_subscribeCb);
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

    testInfo.freq = (ExchangeFreq)(SUPER_HIGH + 1);
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
 * @tc.desc: Extern module discover，use the normal parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StartDiscoveryTest003, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscStartDiscovery("pkgname1", &g_sInfo1, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscStartDiscovery(g_corrPkgName, &g_sInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: StartDiscoveryTest004
 * @tc.desc: Extern module discover，use the same parameter again, perform two subscriptions.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StartDiscoveryTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);
    ret = DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: StartDiscoveryTest005
 * @tc.desc: Test extern module active discover，use wrong Medium and Freq Under the COAP.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StartDiscoveryTest005, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char*)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    DiscMgrDeinit();
}

/**
 * @tc.name: StartDiscoveryTest006
 * @tc.desc: Test extern module active discover，use wrong Medium and Freq Under the BLE.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StartDiscoveryTest006, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char*)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    DiscMgrDeinit();
}

/**
 * @tc.name: StartDiscoveryTest007
 * @tc.desc: Test extern module active discover，use wrong Medium and Freq Under the AUTO.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StartDiscoveryTest007, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBEINNER_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char*)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    DiscMgrDeinit();
}

/**
 * @tc.name: StartDiscoveryTest008
 * @tc.desc: Test extern module active discover，use Diff Freq Under the AUTO.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StartDiscoveryTest008, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBE_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    testInfo.freq = MID;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    testInfo.freq = HIGH;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    DiscMgrDeinit();
}

/**
 * @tc.name: StartDiscoveryTest009
 * @tc.desc: Test extern module passive discover，use Diff Freq Under the AUTO.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StartDiscoveryTest009, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBE_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    testInfo.freq = MID;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    testInfo.freq = HIGH;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    DiscMgrDeinit();
}

/**
 * @tc.name: StartDiscoveryTest010
 * @tc.desc: Test extern module active discover，use Diff Freq Under the BLE.
 * @tc.in: Test module, Test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StartDiscoveryTest010, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBE_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    testInfo.freq = MID;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    testInfo.freq = HIGH;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    DiscMgrDeinit();
}

/**
 * @tc.name: StartDiscoveryTest011
 * @tc.desc: extern module discover, use the normal parameter and different frequencies under passive COAP.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StartDiscoveryTest011, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {.subscribeId = TEST_SUBSCRIBE_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")};

    DiscMgrInit();

    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    testInfo.freq = MID;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    testInfo.freq = HIGH;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    DiscMgrDeinit();
}


/**
 * @tc.name: StartDiscoveryTest012
 * @tc.desc: Extern module discover, use the normal parameter and different frequencies under passive BLE.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StartDiscoveryTest012, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {.subscribeId = TEST_SUBSCRIBE_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = BLE,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")};

    DiscMgrInit();

    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    testInfo.freq = MID;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    testInfo.freq = HIGH;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    DiscMgrDeinit();
}

/**
 * @tc.name: StartDiscoveryTest013
 * @tc.desc: Extern module discover, use the normal parameter and different frequencies under active COAP.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StartDiscoveryTest013, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {.subscribeId = TEST_SUBSCRIBE_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")};

    DiscMgrInit();

    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    testInfo.freq = MID;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    testInfo.freq = HIGH;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    testInfo.freq = SUPER_HIGH;
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);
    DiscStopDiscovery("pkgname1", testInfo.subscribeId);

    DiscMgrDeinit();
}

/**
 * @tc.name: UnPublishServiceTest001
 * @tc.desc: Extern module stop publish，the module is not initialized.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscUnPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, UnPublishServiceTest001, TestSize.Level1)
{
    int ret;
    ret = DiscUnPublishService("pkgname1", TEST_PUBLISH_ID);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UnPublishServiceTest002
 * @tc.desc: Extern module stop publish，use the wrong parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscUnPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, UnPublishServiceTest002, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscPublishService("pkgname1", &g_pInfo);

    ret = DiscUnPublishService(NULL, TEST_PUBLISH_ID);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscUnPublishService(g_erroPkgName, TEST_PUBLISH_ID);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscUnPublishService("pkgname2", TEST_PUBLISH_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: UnPublishServiceTest003
 * @tc.desc: Extern module stop publish，use the normal parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscUnPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, UnPublishServiceTest003, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscPublishService("pkgname1", &g_pInfo);
    DiscPublishService("pkgname1", &g_pInfo1);
    DiscPublishService(g_corrPkgName, &g_pInfo);

    ret = DiscUnPublishService("pkgname1", TEST_PUBLISH_ID);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscUnPublishService("pkgname1", TEST_PUBLISH_ID1);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscUnPublishService(g_corrPkgName, TEST_PUBLISH_ID);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: UnPublishServiceTest004
 * @tc.desc: Extern module stop publish，release the same parameter again, perform two subscriptions.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscUnPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, UnPublishServiceTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscPublishService("pkgname1", &g_pInfo);

    ret = DiscUnPublishService("pkgname1", TEST_PUBLISH_ID);
    ret = DiscUnPublishService("pkgname1", TEST_PUBLISH_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: UnPublishServiceTest005
 * @tc.desc: Extern module stop publish, use the normal parameter and different frequencies under active COAP.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscUnPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, UnPublishServiceTest005, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {.publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")};

    DiscMgrInit();

    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: UnPublishServiceTest006
 * @tc.desc: Extern module stop publish, use the normal parameter and different frequencies under passive COAP.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscUnPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, UnPublishServiceTest006, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {.publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")};

    DiscMgrInit();

    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: UnPublishServiceTest007
 * @tc.desc: Extern module stop publish, use the normal parameter and different frequencies under active BLE.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscUnPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, UnPublishServiceTest007, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {.publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")};

    DiscMgrInit();

    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: UnPublishServiceTest008
 * @tc.desc: Extern module stop publish, use the normal parameter and different frequencies under passive BLE.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscUnPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, UnPublishServiceTest008, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {.publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = BLE,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")};

    DiscMgrInit();

    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: UnPublishServiceTest009
 * @tc.desc: Extern module stop publish, use the normal parameter and different frequencies under active AUTO.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscUnPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, UnPublishServiceTest009, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {.publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")};

    DiscMgrInit();

    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: UnPublishServiceTest010
 * @tc.desc: Extern module stop publish, use the normal parameter and different frequencies under passive AUTO.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscUnPublishService operates normally.
 */
HWTEST_F(DiscManagerTest, UnPublishServiceTest010, TestSize.Level1)
{
    int ret;
    PublishInfo testInfo = {.publishId = TEST_PUBLISH_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")};

    DiscMgrInit();

    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscPublishService("pkgname1", &testInfo);
    ret = DiscUnPublishService("pkgname1", testInfo.publishId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: StopDiscoveryTest001
 * @tc.desc: Extern module stop discover，the module is not initialized.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscStopDiscovery operates normally
 */
HWTEST_F(DiscManagerTest, StopDiscoveryTest001, TestSize.Level1)
{
    int ret;
    ret = DiscStopDiscovery("pkgname1", TEST_SUBSCRIBE_ID);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: StopDiscoveryTest002
 * @tc.desc: Extern module stop discover，use the wrong parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscStopDiscovery operates normally
 */
HWTEST_F(DiscManagerTest, StopDiscoveryTest002, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);

    ret = DiscStopDiscovery(NULL, TEST_SUBSCRIBE_ID);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscStopDiscovery(g_erroPkgName, TEST_SUBSCRIBE_ID);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscStopDiscovery("pkgname2", TEST_SUBSCRIBE_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: StopDiscoveryTest003
 * @tc.desc: Extern module stop discover，use the normal parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStopDiscovery operates normally
 */
HWTEST_F(DiscManagerTest, StopDiscoveryTest003, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);
    DiscStartDiscovery("pkgname1", &g_sInfo1, &g_subscribeCb);
    DiscStartDiscovery(g_corrPkgName, &g_sInfo, &g_subscribeCb);

    ret = DiscStopDiscovery("pkgname1", TEST_SUBSCRIBE_ID);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscStopDiscovery("pkgname1", TEST_SUBSCRIBE_ID1);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscStopDiscovery(g_corrPkgName, TEST_SUBSCRIBE_ID);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: StopDiscoveryTest004
 * @tc.desc: Extern module stop discover，release the same parameter again, perform two subscriptions.
 * @tc.in: Test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscStopDiscovery operates normally
 */
HWTEST_F(DiscManagerTest, StopDiscoveryTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);

    ret = DiscStopDiscovery("pkgname1", TEST_SUBSCRIBE_ID);
    ret = DiscStopDiscovery("pkgname1", TEST_SUBSCRIBE_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: StopDiscoveryTest005
 * @tc.desc: Test extern module stop active discover, use Diff Freq Under the COAP.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStopDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StopDiscoveryTest005, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBE_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: StopDiscoveryTest006
 * @tc.desc: Test extern module stop passive discover, use Diff Freq Under the COAP.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStopDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StopDiscoveryTest006, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBE_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: StopDiscoveryTest007
 * @tc.desc: Test extern module stop active discover, use Diff Freq Under the BLE.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStopDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StopDiscoveryTest007, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBE_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = BLE,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: StopDiscoveryTest008
 * @tc.desc: Test extern module stop passive discover, use Diff Freq Under the BLE.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStopDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StopDiscoveryTest008, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBE_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = BLE,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: StopDiscoveryTest009
 * @tc.desc: Test extern module stop active discover，use Diff Freq Under the AUTO.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStopDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StopDiscoveryTest009, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBE_ID,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: StopDiscoveryTest010
 * @tc.desc: Test extern module stop passive discover, use Diff Freq Under the AUTO.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscStopDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, StopDiscoveryTest010, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBE_ID,
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = AUTO,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    DiscMgrInit();

    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = MID;
    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = HIGH;
    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    testInfo.freq = SUPER_HIGH;
    DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    ret = DiscStopDiscovery("pkgname1", testInfo.subscribeId);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSetDiscoverCallbackTest001
 * @tc.desc: Callback set process.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: DiscSetDiscoverCallback and DiscStartAdvertise and DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSetDiscoverCallbackTest001, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscSetDiscoverCallback(MODULE_CONN, &g_innerCallback);
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
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: DiscStartAdvertise and DiscSetDiscoverCallback and DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSetDiscoverCallbackTest002, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo);
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
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: NA
 * @tc.type: FUNC
 * @tc.require: The DiscStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSetDiscoverCallbackTest003, TestSize.Level1)
{
    int ret;
    DeviceInfo devInfo;
    DiscMgrInit();
    ret = DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);

    devInfo.capabilityBitmap[0] = TEST_BITMAP_CAP;
    TestInnerDeviceFound(&devInfo, NULL);
    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSetDiscoverCallbackTest004
 * @tc.desc: Inner onDeviceFound test.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: DiscStartAdvertise and DiscSetDiscoverCallback and DiscStopAdvertise operates normally
 */
HWTEST_F(DiscManagerTest, DiscSetDiscoverCallbackTest004, TestSize.Level1)
{
    int ret;
    DeviceInfo devInfo;
    DiscMgrInit();

    ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo);
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
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: DiscStartAdvertise and DiscStopAdvertise operates normally
 */
HWTEST_F(DiscManagerTest, DiscSetDiscoverCallbackTest005, TestSize.Level1)
{
    int ret;
    DeviceInfo devInfo;
    DiscMgrInit();

    ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo);
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
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: DiscStartAdvertise and DiscSetDiscoverCallback and DiscStopAdvertise operates normally.
 */
HWTEST_F(DiscManagerTest, DiscSetDiscoverCallbackTest006, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscSetDiscoverCallback(MODULE_CONN, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscStopAdvertise(MODULE_CONN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: NSTACKX_SendMsgDirectTest001
 * @tc.desc: Test NSTACKX_SendMsgDirect input valid param.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The NSTACKX_SendMsgDirect operates normally.
 */
HWTEST_F(DiscManagerTest, NSTACKX_SendMsgDirectTest001, TestSize.Level1)
{
    const char *muduleName = (const char *)malloc(sizeof(char));
    ASSERT_TRUE(muduleName != nullptr);
    const char *uuid = (const char *)malloc(sizeof(char));
    ASSERT_TRUE(uuid != nullptr);
    const uint8_t *data = (const uint8_t *)malloc(sizeof(uint8_t));
    ASSERT_TRUE(data != nullptr);
    uint32_t len = 1;
    const char *ipaddr = (const char *)malloc(sizeof(char));
    ASSERT_TRUE(ipaddr != nullptr);
    uint8_t type = 2;
    NSTACKX_Parameter g_parameter;
    int32_t ret;

    NSTACKX_Init(&g_parameter);
    ret = NSTACKX_SendMsgDirect(muduleName, uuid, data, len, ipaddr, type);
    NSTACKX_Deinit();
    TEST_ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: NSTACKX_SendMsgDirectTest002
 * @tc.desc: Test NSTACKX_SendMsgDirect input invalid param.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The NSTACKX_SendMsgDirect operates normally.
 */
HWTEST_F(DiscManagerTest, NSTACKX_SendMsgDirectTest002, TestSize.Level1)
{
    const char *muduleName = (const char *)malloc(sizeof(char));
    ASSERT_TRUE(muduleName != nullptr);
    const char *uuid = (const char *)malloc(sizeof(char));
    ASSERT_TRUE(uuid != nullptr);
    const uint8_t *data = (const uint8_t *)malloc(sizeof(uint8_t));
    ASSERT_TRUE(data != nullptr);
    uint32_t len = 1;
    const char *ipaddr = nullptr;
    uint8_t type = 2;
    NSTACKX_Parameter g_parameter;
    int32_t ret;

    NSTACKX_Init(&g_parameter);
    ret = NSTACKX_SendMsgDirect(muduleName, uuid, data, len, ipaddr, type);
    TEST_ASSERT_TRUE(ret == -1);
}

/**
 * @tc.name: NSTACKX_SendMsgDirectTest003
 * @tc.desc: Test NSTACKX_SendMsgDirect not init.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The NSTACKX_SendMsgDirect operates normally.
 */
HWTEST_F(DiscManagerTest, NSTACKX_SendMsgDirectTest003, TestSize.Level1)
{
    const char *muduleName = (const char *)malloc(sizeof(char));
    ASSERT_TRUE(muduleName != nullptr);
    const char *uuid = (const char *)malloc(sizeof(char));
    ASSERT_TRUE(uuid != nullptr);
    const uint8_t *data = (const uint8_t *)malloc(sizeof(uint8_t));
    ASSERT_TRUE(data != nullptr);
    uint32_t len = 1;
    const char *ipaddr = (const char *)malloc(sizeof(char));
    ASSERT_TRUE(ipaddr != nullptr);
    uint8_t type = 2;
    int32_t ret;

    ret = NSTACKX_SendMsgDirect(muduleName, uuid, data, len, ipaddr, type);
    TEST_ASSERT_TRUE(ret == -1);
}

/**
 * @tc.name: NSTACKX_SendMsgTest001
 * @tc.desc: Test NSTACKX_SendMsg input valid param.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The NSTACKX_SendMsg operates normally.
 */
HWTEST_F(DiscManagerTest, NSTACKX_SendMsgTest001, TestSize.Level1)
{
    const char *muduleName = (const char *)malloc(sizeof(char));
    ASSERT_TRUE(muduleName != nullptr);
    const char *uuid = (const char *)malloc(sizeof(char));
    ASSERT_TRUE(muduleName != nullptr);
    const uint8_t *data = (const uint8_t *)malloc(sizeof(uint8_t));
    ASSERT_TRUE(data != nullptr);
    uint32_t len = 1;
    NSTACKX_Parameter g_parameter;
    int32_t ret;

    NSTACKX_Init(&g_parameter);
    ret = NSTACKX_SendMsg(muduleName, uuid, data, len);
    NSTACKX_Deinit();
    TEST_ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: NSTACKX_SendMsgTest002
 * @tc.desc: Test NSTACKX_SendMsg input invalid param.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The NSTACKX_SendMsg operates normally.
 */
HWTEST_F(DiscManagerTest, NSTACKX_SendMsgTest002, TestSize.Level1)
{
    NSTACKX_Parameter g_parameter;
    int32_t ret;

    NSTACKX_Init(&g_parameter);
    ret = NSTACKX_SendMsg(nullptr, nullptr, nullptr, 0);
    NSTACKX_Deinit();
    TEST_ASSERT_TRUE(ret == -2);
}

/**
 * @tc.name: NSTACKX_SendMsgTest003
 * @tc.desc: Test NSTACKX_SendMsg not init.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The NSTACKX_SendMsg operates normally.
 */
HWTEST_F(DiscManagerTest, NSTACKX_SendMsgTest003, TestSize.Level1)
{
    const char *muduleName = (const char *)malloc(sizeof(char));
    ASSERT_TRUE(muduleName != nullptr);
    const char *uuid = (const char *)malloc(sizeof(char));
    ASSERT_TRUE(uuid != nullptr);
    const uint8_t *data = (const uint8_t *)malloc(sizeof(uint8_t));
    ASSERT_TRUE(data != nullptr);
    uint32_t len = 1;
    int32_t ret;

    ret = NSTACKX_SendMsg(muduleName, uuid, data, len);
    TEST_ASSERT_TRUE(ret == -1);
}

/**
 * @tc.name: DiscCoapStopDiscoveryTest001
 * @tc.desc: Active stop discovery，use the normal parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscCoapStopDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, DiscCoapStopDiscoveryTest001, TestSize.Level1)
{
    int ret;
    const uint32_t cap_bitmap_1 = 1;
    const uint32_t disc_mode_active = 1;
    g_coapDiscFunc = DiscCoapInit(&g_discInnerCb);
    DiscCoapStartDiscovery(cap_bitmap_1, disc_mode_active);

    ret = DiscCoapStopDiscovery(cap_bitmap_1, disc_mode_active);
    TEST_ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: DiscCoapStopDiscoveryTest002
 * @tc.desc: Passive stop discovery，the module is not initialized.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscCoapStopDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, DiscCoapStopDiscoveryTest002, TestSize.Level1)
{
    int ret;
    const uint32_t cap_bitmap_1 = 1;
    const uint32_t disc_mode_passive = 1;

    DiscCoapStartDiscovery(cap_bitmap_1, disc_mode_passive);
    ret = DiscCoapStopDiscovery(cap_bitmap_1, disc_mode_passive);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscCoapStopDiscoveryTest003
 * @tc.desc: Active stop discovery，the module is not initialized.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscCoapStopDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, DiscCoapStopDiscoveryTest003, TestSize.Level1)
{
    int ret;
    const uint32_t cap_bitmap_1 = 1;
    const uint32_t disc_mode_active = 1;

    ret = DiscCoapStopDiscovery(cap_bitmap_1, disc_mode_active);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: RegisterDeviceInfoTest001
 * @tc.desc: Registering device Information，use the normal parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The NSTACKX_RegisterDevice operates normally.
 */
HWTEST_F(DiscManagerTest, RegisterDeviceInfoTest001, TestSize.Level1)
{
    int ret;
    const char *device_name = "TEST";
    const char *device_id = "abcdefgfhijklmnopqrstuvwxyz";
    const char *device_bt_mac = "11:22:33:44:55:66";
    const char *device_wifi_mac = "11:22:33:44:77:88";
    const char *device_ip = "192.168.0.1";
    const char *net_work_name = "wlan0";
    const uint32_t device_type = 0;
    const char *version = "3.1.0";
    NSTACKX_LocalDeviceInfo *localDevInfo = (NSTACKX_LocalDeviceInfo *)malloc(sizeof(NSTACKX_LocalDeviceInfo));
    ASSERT_TRUE(localDevInfo != nullptr);
    (void)memset_s(localDevInfo, 0, sizeof(NSTACKX_LocalDeviceInfo), 0);
    strcpy_s(localDevInfo->name, sizeof(localDevInfo->name), device_name);
    strcpy_s(localDevInfo->deviceId, sizeof(localDevInfo->deviceId), device_id);
    strcpy_s(localDevInfo->btMacAddr, sizeof(localDevInfo->btMacAddr), device_bt_mac);
    strcpy_s(localDevInfo->wifiMacAddr, sizeof(localDevInfo->wifiMacAddr), device_wifi_mac);
    strcpy_s(localDevInfo->networkIpAddr, sizeof(localDevInfo->networkIpAddr), device_ip);
    strcpy_s(localDevInfo->networkName, sizeof(localDevInfo->networkName), net_work_name);
    strcpy_s(localDevInfo->version, sizeof(localDevInfo->version), version);
    localDevInfo->deviceType = device_type;

    ret = NSTACKX_RegisterDevice(localDevInfo);
    free(localDevInfo);
    TEST_ASSERT_TRUE(ret == 0);
}

/**
 * @tc.name: RegisterDeviceInfoTest002
 * @tc.desc: Registering device Information，the parameter is not assigned.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The NSTACKX_RegisterDevice operates normally.
 */
HWTEST_F(DiscManagerTest, RegisterDeviceInfoTest002, TestSize.Level1)
{
    int ret;
    NSTACKX_LocalDeviceInfo *localDevInfo = (NSTACKX_LocalDeviceInfo *)malloc(sizeof(NSTACKX_LocalDeviceInfo));
    ASSERT_TRUE(localDevInfo != nullptr);
    (void)memset_s(localDevInfo, 0, sizeof(NSTACKX_LocalDeviceInfo), 0);
    ret = NSTACKX_RegisterDevice(localDevInfo);
    free(localDevInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: RegisterDeviceInfoTest003
 * @tc.desc: Registering device Information，use the wrong parameter.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The NSTACKX_RegisterDevice operates normally.
 */
HWTEST_F(DiscManagerTest, RegisterDeviceInfoTest003, TestSize.Level1)
{
    int ret;
    const char *device_name = "TEST";
    const char *device_id = "abcdefgfhijklmnopqrstuvwxyz";
    const char *device_bt_mac = "11:22:33:44:55:66";
    const char *device_wifi_mac = "11:22:33:44:77:88";
    const char *err_device_ip = "192.168";
    const char *net_work_name = "wlan0";
    const uint32_t device_type = 0;
    const char *version = "3.1.0";
    NSTACKX_LocalDeviceInfo *localDevInfo = (NSTACKX_LocalDeviceInfo *)malloc(sizeof(NSTACKX_LocalDeviceInfo));
    ASSERT_TRUE(localDevInfo != nullptr);
    (void)memset_s(localDevInfo, 0, sizeof(NSTACKX_LocalDeviceInfo), 0);
    strcpy_s(localDevInfo->name, sizeof(localDevInfo->name), device_name);
    strcpy_s(localDevInfo->deviceId, sizeof(localDevInfo->deviceId), device_id);
    strcpy_s(localDevInfo->btMacAddr, sizeof(localDevInfo->btMacAddr), device_bt_mac);
    strcpy_s(localDevInfo->wifiMacAddr, sizeof(localDevInfo->wifiMacAddr), device_wifi_mac);
    strcpy_s(localDevInfo->networkIpAddr, sizeof(localDevInfo->networkIpAddr), err_device_ip);
    strcpy_s(localDevInfo->networkName, sizeof(localDevInfo->networkName), net_work_name);
    strcpy_s(localDevInfo->version, sizeof(localDevInfo->version), version);
    localDevInfo->deviceType = device_type;

    ret = NSTACKX_RegisterDevice(localDevInfo);
    free(localDevInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscCoapPulbishServiceTest001
 * @tc.desc: Inner module publishing, use wrong parameters.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscCoapUnpulbishService operates normally.
 */
HWTEST_F(DiscManagerTest, DiscCoapPulbishServiceTest001, TestSize.Level1)
{
    int ret;
    const uint32_t pub_cap_bitmap_2 = 6;
    const uint32_t publish_mode_2 = 5;
    g_coapDiscFunc = DiscCoapInit(&g_discInnerCb);

    ret = DiscCoapUnpulbishService(pub_cap_bitmap_2, publish_mode_2);
    TEST_ASSERT_TRUE(ret != 0);
    DiscCoapDeinit();
}

/**
 * @tc.name: DiscCoapPulbishServiceTest002
 * @tc.desc: Inner module publishing, use normal parameters.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscCoapUnpulbishService operates normally.
 */
HWTEST_F(DiscManagerTest, DiscCoapPulbishServiceTest002, TestSize.Level1)
{
    int ret;
    const uint32_t pub_cap_bitmap_1 = 1;
    const uint32_t pub_lish_mode_1 = 0;
    g_coapDiscFunc = DiscCoapInit(&g_discInnerCb);

    ret = DiscCoapUnpulbishService(pub_cap_bitmap_1, pub_lish_mode_1);
    TEST_ASSERT_TRUE(ret == 0);
    DiscCoapDeinit();
}

/**
 * @tc.name: DiscCoapStartDiscoveryTest001
 * @tc.desc: Inner module Discovery, use wrong parameters.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscCoapStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, DiscCoapStartDiscoveryTest001, TestSize.Level1)
{
    int ret;
    const uint32_t filter_cap_bitmap_2 = 4;
    const uint32_t disc_mode_2 = 8;
    g_coapDiscFunc = DiscCoapInit(&g_discInnerCb);

    ret = DiscCoapStartDiscovery(filter_cap_bitmap_2, disc_mode_2);
    TEST_ASSERT_TRUE(ret != 0);
    DiscCoapDeinit();
}

/**
 * @tc.name: DiscCoapStartDiscoveryTest002
 * @tc.desc: Test coap discovery, use normal parameters.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscCoapStartDiscovery operates normally.
 */
HWTEST_F(DiscManagerTest, DiscCoapStartDiscoveryTest002, TestSize.Level1)
{
    int ret;
    const uint32_t filter_cap_bitmap_1 = 1;
    const uint32_t disc_mode_1 = 1;
    g_coapDiscFunc = DiscCoapInit(&g_discInnerCb);

    ret = DiscCoapStartDiscovery(filter_cap_bitmap_1, disc_mode_1);
    TEST_ASSERT_TRUE(ret == 0);
    DiscCoapDeinit();
}

/**
 * @tc.name: DiscCoapUnpulbishServiceTest001
 * @tc.desc: Inner modules stop publishing, using wrong parameters.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The DiscCoapUnpulbishService operates normally.
 */
HWTEST_F(DiscManagerTest, DiscCoapUnpulbishServiceTest001, TestSize.Level1)
{
    int ret;
    const uint32_t pub_cap_bitmap_2 = 6;
    const uint32_t publish_mode_2 = 5;
    g_coapDiscFunc = DiscCoapInit(&g_discInnerCb);

    ret = DiscCoapUnpulbishService(pub_cap_bitmap_2, publish_mode_2);
    TEST_ASSERT_TRUE(ret != 0);
    DiscCoapDeinit();
}

/**
 * @tc.name: DiscCoapUnpulbishServiceTest002
 * @tc.desc: Test stop publishing, using the normal parameters.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The DiscCoapUnpulbishService operates normally.
 */
HWTEST_F(DiscManagerTest, DiscCoapUnpulbishServiceTest002, TestSize.Level1)
{
    int ret;
    const uint32_t pub_cap_bitmap_1 = 1;
    const uint32_t pub_lish_mode_1 = 0;
    g_coapDiscFunc = DiscCoapInit(&g_discInnerCb);

    ret = DiscCoapUnpulbishService(pub_cap_bitmap_1, pub_lish_mode_1);
    TEST_ASSERT_TRUE(ret == 0);
    DiscCoapDeinit();
}

/**
 * @tc.name: NSTACKX_Test001
 * @tc.desc: Test NSTACKX_GetDeviceList with invalid param.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The NSTACKX_GetDeviceList operates normally.
 */
HWTEST_F(DiscManagerTest, NSTACKX_Test001, TestSize.Level1)
{
    NSTACKX_DeviceInfo deviceList;
    uint32_t deviceCountPtr = 0;
    int32_t ret;
    NSTACKX_Parameter g_parameter;

    (void)memset_s(&deviceList, 0, sizeof(NSTACKX_LocalDeviceInfo), 0);
    NSTACKX_Init(&g_parameter);
    ret = NSTACKX_GetDeviceList(&deviceList, &deviceCountPtr);
    TEST_ASSERT_TRUE(ret == -2);

    deviceCountPtr = NSTACKX_MAX_DEVICE_NUM;
    (void)memset_s(&deviceList, 0, sizeof(NSTACKX_LocalDeviceInfo), 0);
    ret = NSTACKX_GetDeviceList(&deviceList, &deviceCountPtr);
    TEST_ASSERT_TRUE(ret == -2);
    NSTACKX_Deinit();
}

/**
 * @tc.name: NSTACKX_Test002
 * @tc.desc: Test NSTACKX_GetDeviceList with return value In NSTACKX different states.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The NSTACKX_GetDeviceList operates normally.
 */
HWTEST_F(DiscManagerTest, NSTACKX_Test002, TestSize.Level1)
{
    NSTACKX_DeviceInfo deviceList;
    uint32_t deviceCountPtr = NSTACKX_MAX_DEVICE_NUM;
    int32_t ret;
    NSTACKX_Parameter g_parameter;

    (void)memset_s(&deviceList, 0, sizeof(NSTACKX_LocalDeviceInfo), 0);
    ret = NSTACKX_GetDeviceList(&deviceList, &deviceCountPtr);
    TEST_ASSERT_TRUE(ret == -1);

    NSTACKX_Init(&g_parameter);
    ret = NSTACKX_GetDeviceList(&deviceList, &deviceCountPtr);
    TEST_ASSERT_TRUE(ret == 0);

    NSTACKX_Deinit();
    ret = NSTACKX_GetDeviceList(&deviceList, &deviceCountPtr);
    TEST_ASSERT_TRUE(ret == -1);
}

/*
 * @tc.name: testNSTACKX_RegisterDeviceAn001
 * @tc.desc: Test testNSTACKX_RegisterDeviceAn with invalid param.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The NSTACKX_RegisterDeviceAn operates normally.
 */
HWTEST_F(DiscManagerTest, testNSTACKX_RegisterDeviceAn001, TestSize.Level1)
{
    int32_t ret;
    NSTACKX_Parameter g_parameter;

    NSTACKX_Init(&g_parameter);
    ret = NSTACKX_RegisterDeviceAn(nullptr, 0);
    TEST_ASSERT_TRUE(ret == -2);
    NSTACKX_Deinit();
};

/*
 * @tc.name: testNSTACKX_RegisterDeviceAn002
 * @tc.desc: Test testNSTACKX_RegisterDeviceAn not initialized.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The NSTACKX_RegisterDeviceAn operates normally.
 */
HWTEST_F(DiscManagerTest, testNSTACKX_RegisterDeviceAn002, TestSize.Level1)
{
    int32_t ret;

    ret = NSTACKX_RegisterDeviceAn(nullptr, 0);
    TEST_ASSERT_TRUE(ret == -1);
};

/*
 * @tc.name: testNSTACKX_RegisterDeviceAn003
 * @tc.desc: Test testNSTACKX_RegisterDeviceAn yes or no.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require: The NSTACKX_RegisterDeviceAn operates normally.
 */
HWTEST_F(DiscManagerTest, testNSTACKX_RegisterDeviceAn003, TestSize.Level1)
{
    int32_t ret;
    NSTACKX_Parameter g_parameter;
    NSTACKX_LocalDeviceInfo testInfo = {"testdata"};

    NSTACKX_Init(&g_parameter);
    ret = NSTACKX_RegisterDeviceAn(&testInfo, 0);
    TEST_ASSERT_TRUE(ret == 0);
    NSTACKX_Deinit();
};

/*
 * @tc.name: testNSTACKX_RegisterCapability004
 * @tc.desc: Test NSTACKX_RegisterCapability with invalid param.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The NSTACKX_RegisterDeviceAn operates normally.
 */
HWTEST_F(DiscManagerTest, NSTACKX_RegisterCapability004, TestSize.Level1)
{
    int32_t ret;
    uint32_t mapNum = 3;
    NSTACKX_Parameter g_parameter;

    NSTACKX_Init(&g_parameter);
    ret = NSTACKX_RegisterCapability(mapNum, 0);
    TEST_ASSERT_TRUE(ret == -2);
    ret = NSTACKX_RegisterCapability(0, 0);
    TEST_ASSERT_TRUE(ret == -2);
    NSTACKX_Deinit();
};

/*
 * @tc.name: testNSTACKX_RegisterCapability005
 * @tc.desc: Test NSTACKX_RegisterCapability Uninitialized.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The NSTACKX_RegisterDeviceAn operates normally.
 */
HWTEST_F(DiscManagerTest, NSTACKX_RegisterCapability005, TestSize.Level1)
{
    int32_t ret;

    ret = NSTACKX_RegisterCapability(0, 0);
    TEST_ASSERT_TRUE(ret == -1);
};

/*
 * @tc.name: testBaseListener006
 * @tc.desc: Test NSTACKX_RegisterCapability yes or no.
 * @tc.in: test module, test number, Test Levels.
 * @tc.out: Nonzero
 * @tc.type: FUNC
 * @tc.require: The NSTACKX_RegisterDeviceAn operates normally.
 */
HWTEST_F(DiscManagerTest, NSTACKX_RegisterCapability006, TestSize.Level1)
{
    int32_t ret;
    uint32_t mapNum = 3;
    NSTACKX_Parameter g_parameter;

    NSTACKX_Init(&g_parameter);
    ret = NSTACKX_RegisterCapability(mapNum, 0);
    TEST_ASSERT_TRUE(ret != 0);
    NSTACKX_Deinit();
};
}