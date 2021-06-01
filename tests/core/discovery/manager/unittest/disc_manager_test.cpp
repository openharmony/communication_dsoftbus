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

#include "disc_manager.h"
#include "softbus_log.h"

#define TEST_ERRO_MOUDULE       ((MODULE_LNN) + 3)
#define ERRO_CAPDATA_LEN        (MAX_CAPABILITYDATA_LEN + 1)
#define TEST_ASSERT_TRUE(ret)  \
    if (ret) {                 \
        LOG_INFO("[succ]\n");    \
        g_succTestCount++;       \
    } else {                   \
        LOG_INFO("[error]\n");    \
        g_failTestCount++;       \
    }


using namespace testing::ext;

namespace OHOS {
static int32_t g_succTestCount = 0;
static int32_t g_failTestCount = 0;
static int32_t g_devieceFoundCount = 0;
static const char *g_corrPkgName = "CorrCorrCorrCorrCorrCorrCorrCorrCorrCorrCorrCorrCorrCorrCorrCorr";
static const char *g_erroPkgName = "ErroErroErroErroErroErroErroErroErroErroErroErroErroErroErroErroE";

const int32_t TEST_PUBLISHINNER_ID = 1;
const int32_t TEST_PUBLISH_ID = 2;
const int32_t TEST_SUBSCRIBEINNER_ID = 3;
const int32_t TEST_SUBSCRIBE_ID = 4;
const int32_t TEST_PUBLISHINNER_ID1 = 5;
const int32_t TEST_PUBLISH_ID1 = 6;
const int32_t TEST_SUBSCRIBEINNER_ID1 = 7;
const int32_t TEST_SUBSCRIBE_ID1 = 8;
const int32_t TEST_BITMAP_CAP = 127;

class Disc_ManagerTest : public testing::Test {
public:
    Disc_ManagerTest()
    {}
    ~Disc_ManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void Disc_ManagerTest::SetUpTestCase(void)
{}

void Disc_ManagerTest::TearDownTestCase(void)
{}

static void TestDeviceFound(const char *packageName, const DeviceInfo *device)
{
    g_devieceFoundCount++;
    LOG_INFO("[device found]success!\n");
}

static void TestInnerDeviceFound(const DeviceInfo *device)
{
    g_devieceFoundCount++;
    LOG_INFO("[inner device found]success!\n");
}

static void TestDiscoverFailed(const char *packageName, int subscribeId, DiscoveryFailReason failReason)
{
    LOG_INFO("[TestCallback]TestDiscoverFailed!\n");
}

static void TestDiscoverySuccess(const char *packageName, int subscribeId)
{
    LOG_INFO("[TestCallback]TestDiscoverySuccess!\n");
}

static void TestPublishSuccess(const char *packageName, int publishId)
{
    LOG_INFO("[TestCallback]TestPublishSuccess!\n");
}

static void TestPublishFail(const char *packageName, int publishId, PublishFailReason reason)
{
    LOG_INFO("[TestCallback]TestPublishFail!\n");
}

static DiscInnerCallback g_innerCallback = {
    .OnDeviceFound = TestInnerDeviceFound
};

static IServerDiscoveryCallback g_subscribeCb = {
    .OnServerDeviceFound = TestDeviceFound,
    .OnServerDiscoverFailed = TestDiscoverFailed,
    .OnServerDiscoverySuccess = TestDiscoverySuccess
};

static IServerPublishCallback g_publishCb = {
    .OnServerPublishSuccess = TestPublishSuccess,
    .OnServerPublishFail = TestPublishFail
};

static PublishInnerInfo g_pInnerInfo = {
    .publishId = TEST_PUBLISHINNER_ID,
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

static SubscribeInnerInfo g_sInnerInfo = {
    .subscribeId = TEST_SUBSCRIBEINNER_ID,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata3",
    .dataLen = sizeof("capdata3"),
    .isSameAccount = true,
    .isWakeRemote = false
};

static SubscribeInfo g_sInfo = {
    .subscribeId = TEST_SUBSCRIBE_ID,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "hicall",
    .capabilityData = (unsigned char *)"capdata4",
    .dataLen = sizeof("capdata4"),
    .isSameAccount = true,
    .isWakeRemote = false
};

static PublishInnerInfo g_pInnerInfo1 = {
    .publishId = TEST_PUBLISHINNER_ID1,
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

static SubscribeInnerInfo g_sInnerInfo1 = {
    .subscribeId = TEST_SUBSCRIBEINNER_ID1,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = NULL,
    .dataLen = 0,
    .isSameAccount = true,
    .isWakeRemote = false
};

static SubscribeInfo g_sInfo1 = {
    .subscribeId = TEST_SUBSCRIBE_ID1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "hicall",
    .capabilityData = NULL,
    .dataLen = 0,
    .isSameAccount = true,
    .isWakeRemote = false
};

/**
 * @tc.name: DiscPublishTest001
 * @tc.desc: inner module active publish，The module is not initialized.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscPublishTest001, TestSize.Level1)
{
    int ret;
    ret = DiscPublish(MODULE_CONN, &g_pInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscPublishTest002
 * @tc.desc: inner module active publish，use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscPublishTest002, TestSize.Level1)
{
    int ret;
    PublishInnerInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .medium = COAP,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    ret = DiscPublish((DiscModule)TEST_ERRO_MOUDULE, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchanageMedium)(COAP + 1);
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(SUPER_HIGH + 1);
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capability = "test";
    ret = DiscPublish(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
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
 * @tc.desc: inner module active publish，use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscPublishTest003, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscPublish(MODULE_LNN, &g_pInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscPublish(MODULE_LNN, &g_pInnerInfo1);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscPublishTest004
 * @tc.desc: inner module active publish，use the same parameter again.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscPublishTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscPublish(MODULE_LNN, &g_pInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscPublish(MODULE_LNN, &g_pInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartScanTest001
 * @tc.desc: inner module passive publish，The module is not initialized.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscStartScanTest001, TestSize.Level1)
{
    int ret;
    ret = DiscStartScan(MODULE_CONN, &g_pInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscStartScanTest002
 * @tc.desc: inner module passive publish，use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscStartScanTest002, TestSize.Level1)
{
    int ret;
    PublishInnerInfo testInfo = {
        .publishId = TEST_PUBLISHINNER_ID,
        .medium = COAP,
        .freq = LOW,
        .capability = "hicall",
        .capabilityData = (unsigned char *)"capdata1",
        .dataLen = sizeof("capdata1")
    };

    DiscMgrInit();

    ret = DiscStartScan((DiscModule)TEST_ERRO_MOUDULE, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchanageMedium)(COAP + 1);
    ret = DiscStartScan(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(SUPER_HIGH + 1);
    ret = DiscStartScan(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capability = "test";
    ret = DiscStartScan(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
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
 * @tc.desc: inner module passive publish，use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscStartScanTest003, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscStartScan(MODULE_LNN, &g_pInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscStartScan(MODULE_LNN, &g_pInnerInfo1);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartScanTest004
 * @tc.desc: inner module passive publish，use the same parameter again.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscStartScanTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscStartScan(MODULE_LNN, &g_pInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscStartScan(MODULE_LNN, &g_pInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartAdvertiseTest001
 * @tc.desc: inner module active discover，The module is not initialized.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscStartAdvertiseTest001, TestSize.Level1)
{
    int ret;
    ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscStartAdvertiseTest002
 * @tc.desc: inner module active discover，use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscStartAdvertiseTest002, TestSize.Level1)
{
    int ret;
    SubscribeInnerInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBEINNER_ID,
        .medium = COAP,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3"),
        .isSameAccount = true,
        .isWakeRemote = false
    };

    DiscMgrInit();

    ret = DiscStartAdvertise((DiscModule)TEST_ERRO_MOUDULE, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchanageMedium)(COAP + 1);
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(SUPER_HIGH + 1);
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capability = "test";
    ret = DiscStartAdvertise(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
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
 * @tc.desc: inner module active discover，use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscStartAdvertiseTest003, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo1);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStartAdvertiseTest004
 * @tc.desc: inner module active discover，use the same parameter again.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscStartAdvertiseTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSubscribeTest001
 * @tc.desc: inner module passive discover，The module is not initialized.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscSubscribeTest001, TestSize.Level1)
{
    int ret;
    ret = DiscSubscribe(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscSubscribeTest002
 * @tc.desc: inner module passive discover，use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscSubscribeTest002, TestSize.Level1)
{
    int ret;
    SubscribeInnerInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBEINNER_ID,
        .medium = COAP,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3"),
        .isSameAccount = true,
        .isWakeRemote = false
    };

    DiscMgrInit();

    ret = DiscSubscribe((DiscModule)TEST_ERRO_MOUDULE, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchanageMedium)(COAP + 1);
    ret = DiscSubscribe(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(SUPER_HIGH + 1);
    ret = DiscSubscribe(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capability = "test";
    ret = DiscSubscribe(MODULE_LNN, &testInfo);
    TEST_ASSERT_TRUE(ret != 0);
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
 * @tc.desc: inner module passive discover，use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscSubscribeTest003, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscSubscribe(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscSubscribe(MODULE_CONN, &g_sInnerInfo1);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSubscribeTest004
 * @tc.desc: inner module passive discover，use the same parameter again.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscSubscribeTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscSubscribe(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscSubscribe(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscUnpublishTest001
 * @tc.desc: inner module stop publish，The module is not initialized.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscUnpublishTest001, TestSize.Level1)
{
    int ret;
    ret = DiscUnpublish(MODULE_CONN, TEST_PUBLISHINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscUnpublishTest002
 * @tc.desc: inner module stop publish，use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscUnpublishTest002, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscPublish(MODULE_LNN, &g_pInnerInfo);

    ret = DiscUnpublish((DiscModule)TEST_ERRO_MOUDULE, TEST_PUBLISHINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscUnpublishTest003
 * @tc.desc: inner module stop publish，use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscUnpublishTest003, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscPublish(MODULE_LNN, &g_pInnerInfo);
    DiscPublish(MODULE_LNN, &g_pInnerInfo1);

    ret = DiscUnpublish(MODULE_LNN, TEST_PUBLISHINNER_ID);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscUnpublish(MODULE_LNN, TEST_PUBLISHINNER_ID1);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscUnpublishTest004
 * @tc.desc: inner module stop publish，release the same parameter again.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscUnpublishTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscPublish(MODULE_LNN, &g_pInnerInfo);

    ret = DiscUnpublish(MODULE_LNN, TEST_PUBLISHINNER_ID);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscUnpublish(MODULE_LNN, TEST_PUBLISHINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStopAdvertiseTest001
 * @tc.desc: inner module stop discover，The module is not initialized.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscStopAdvertiseTest001, TestSize.Level1)
{
    int ret;
    ret = DiscStopAdvertise(MODULE_CONN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: DiscStopAdvertiseTest002
 * @tc.desc: inner module stop discover，use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscStopAdvertiseTest002, TestSize.Level1)
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
 * @tc.desc: inner module stop discover，use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscStopAdvertiseTest003, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscStartAdvertise(MODULE_LNN, &g_sInnerInfo);
    DiscStartAdvertise(MODULE_LNN, &g_sInnerInfo1);

    ret = DiscStopAdvertise(MODULE_LNN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscStopAdvertise(MODULE_LNN, TEST_SUBSCRIBEINNER_ID1);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscStopAdvertiseTest004
 * @tc.desc: inner module stop discover，release the same parameter again.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscStopAdvertiseTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscStartAdvertise(MODULE_LNN, &g_sInnerInfo);

    ret = DiscStopAdvertise(MODULE_LNN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscStopAdvertise(MODULE_LNN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: PublishServiceTest001
 * @tc.desc: extern module publish，The module is not initialized.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, PublishServiceTest001, TestSize.Level1)
{
    int ret;
    ret = DiscPublishService("pkgname1", &g_pInfo, &g_publishCb);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: PublishServiceTest002
 * @tc.desc: extern module publish，use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, PublishServiceTest002, TestSize.Level1)
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

    ret = DiscPublishService(NULL, &testInfo, &g_publishCb);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscPublishService(g_erroPkgName, &testInfo, &g_publishCb);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscPublishService("pkgname1", NULL, &g_publishCb);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscPublishService("pkgname1", &testInfo, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchanageMedium)(COAP + 1);
    ret = DiscPublishService("pkgname1", &testInfo, &g_publishCb);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.medium = COAP;

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    ret = DiscPublishService("pkgname1", &testInfo, &g_publishCb);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.mode = DISCOVER_MODE_ACTIVE;

    testInfo.freq = (ExchangeFreq)(SUPER_HIGH + 1);
    ret = DiscPublishService("pkgname1", &testInfo, &g_publishCb);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.freq = LOW;

    testInfo.capability = "test";
    ret = DiscPublishService("pkgname1", &testInfo, &g_publishCb);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.capability = "dvKit";

    testInfo.capabilityData = NULL;
    ret = DiscPublishService("pkgname1", &testInfo, &g_publishCb);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = DiscPublishService("pkgname1", &testInfo, &g_publishCb);
    TEST_ASSERT_TRUE(ret != 0);
    testInfo.dataLen = sizeof("capdata1");

    DiscMgrDeinit();
}

/**
 * @tc.name: PublishServiceTest003
 * @tc.desc: extern module publish，use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, PublishServiceTest003, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscPublishService("pkgname1", &g_pInfo, &g_publishCb);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscPublishService("pkgname1", &g_pInfo1, &g_publishCb);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscPublishService(g_corrPkgName, &g_pInfo, &g_publishCb);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: PublishServiceTest004
 * @tc.desc: extern module publish，use the same parameter again.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, PublishServiceTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscPublishService("pkgname1", &g_pInfo, &g_publishCb);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscPublishService("pkgname1", &g_pInfo, &g_publishCb);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: StartDiscoveryTest001
 * @tc.desc: extern module discover，The module is not initialized.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, StartDiscoveryTest001, TestSize.Level1)
{
    int ret;
    ret = DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: StartDiscoveryTest002
 * @tc.desc: extern module discover，use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, StartDiscoveryTest002, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = TEST_SUBSCRIBEINNER_ID,
        .medium = COAP,
        .mode = DISCOVER_MODE_ACTIVE,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3"),
        .isSameAccount = true,
        .isWakeRemote = false
    };

    DiscMgrInit();

    ret = DiscStartDiscovery(NULL, &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscStartDiscovery(g_erroPkgName, &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscStartDiscovery("pkgname1", NULL, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);

    ret = DiscStartDiscovery("pkgname1", &testInfo, NULL);
    TEST_ASSERT_TRUE(ret != 0);

    testInfo.medium = (ExchanageMedium)(COAP + 1);
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

    testInfo.capability = "test";
    ret = DiscStartDiscovery("pkgname1", &testInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);
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
 * @tc.desc: extern module discover，use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, StartDiscoveryTest003, TestSize.Level1)
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
 * @tc.desc: extern module discover，use the same parameter again.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, StartDiscoveryTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();

    ret = DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: UnPublishServiceTest001
 * @tc.desc: extern module stop publish，The module is not initialized.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, UnPublishServiceTest001, TestSize.Level1)
{
    int ret;
    ret = DiscUnPublishService("pkgname1", TEST_PUBLISH_ID);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: UnPublishServiceTest002
 * @tc.desc: extern module stop publish，use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, UnPublishServiceTest002, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscPublishService("pkgname1", &g_pInfo, &g_publishCb);

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
 * @tc.desc: extern module stop publish，use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, UnPublishServiceTest003, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscPublishService("pkgname1", &g_pInfo, &g_publishCb);
    DiscPublishService("pkgname1", &g_pInfo1, &g_publishCb);
    DiscPublishService(g_corrPkgName, &g_pInfo, &g_publishCb);

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
 * @tc.desc: extern module stop publish，release the same parameter again,
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, UnPublishServiceTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscPublishService("pkgname1", &g_pInfo, &g_publishCb);

    ret = DiscUnPublishService("pkgname1", TEST_PUBLISH_ID);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscUnPublishService("pkgname1", TEST_PUBLISH_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: StopDiscoveryTest001
 * @tc.desc: extern module stop discover，The module is not initialized.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, StopDiscoveryTest001, TestSize.Level1)
{
    int ret;
    ret = DiscStopDiscovery("pkgname1", TEST_SUBSCRIBE_ID);
    TEST_ASSERT_TRUE(ret != 0);
}

/**
 * @tc.name: StopDiscoveryTest002
 * @tc.desc: extern module stop discover，use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, StopDiscoveryTest002, TestSize.Level1)
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
 * @tc.desc: extern module stop discover，use the normal parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, StopDiscoveryTest003, TestSize.Level1)
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
 * @tc.desc: extern module stop discover，release the same parameter again,
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, StopDiscoveryTest004, TestSize.Level1)
{
    int ret;
    DiscMgrInit();
    DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);

    ret = DiscStopDiscovery("pkgname1", TEST_SUBSCRIBE_ID);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscStopDiscovery("pkgname1", TEST_SUBSCRIBE_ID);
    TEST_ASSERT_TRUE(ret != 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSetDiscoverCallbackTest001
 * @tc.desc: callback set process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscSetDiscoverCallbackTest001, TestSize.Level1)
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
 * @tc.desc: callback set process
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscSetDiscoverCallbackTest002, TestSize.Level1)
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
 * @tc.desc: extern onDeviceFound test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscSetDiscoverCallbackTest003, TestSize.Level1)
{
    DeviceInfo devInfo;
    DiscMgrInit();
    DiscStartDiscovery("pkgname1", &g_sInfo, &g_subscribeCb);
    devInfo.capabilityBitmap[0] = TEST_BITMAP_CAP;
    DiscOnDeviceFound(&devInfo);
    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSetDiscoverCallbackTest004
 * @tc.desc: inner onDeviceFound test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscSetDiscoverCallbackTest004, TestSize.Level1)
{
    int ret;
    DeviceInfo devInfo;
    DiscMgrInit();

    ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    ret = DiscSetDiscoverCallback(MODULE_CONN, &g_innerCallback);
    TEST_ASSERT_TRUE(ret == 0);

    devInfo.capabilityBitmap[0] = TEST_BITMAP_CAP;
    DiscOnDeviceFound(&devInfo);

    ret = DiscStopAdvertise(MODULE_CONN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}

/**
 * @tc.name: DiscSetDiscoverCallbackTest005
 * @tc.desc: inner onDeviceFound test with no callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_ManagerTest, DiscSetDiscoverCallbackTest005, TestSize.Level1)
{
    int ret;
    DeviceInfo devInfo;
    DiscMgrInit();

    ret = DiscStartAdvertise(MODULE_CONN, &g_sInnerInfo);
    TEST_ASSERT_TRUE(ret == 0);

    devInfo.capabilityBitmap[0] = TEST_BITMAP_CAP;
    DiscOnDeviceFound(&devInfo);

    ret = DiscStopAdvertise(MODULE_CONN, TEST_SUBSCRIBEINNER_ID);
    TEST_ASSERT_TRUE(ret == 0);

    DiscMgrDeinit();
}
}