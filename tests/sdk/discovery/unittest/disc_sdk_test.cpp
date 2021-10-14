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
#include "client_disc_manager.h"
#include "softbus_common.h"
#include "softbus_log.h"

using namespace testing::ext;

#define TEST_ERRO_MOUDULE       ((MODULE_LNN) + 3)

namespace OHOS {
static int g_subscribeId = 0;
static int g_publishId = 0;
static const char *g_pkgName = "Softbus_Kits";
static const char *g_erroPkgName = "Softbus_Erro_Kits";

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
{}

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
    .medium = COAP,
    .mode = DISCOVER_MODE_ACTIVE,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata3",
    .dataLen = sizeof("capdata3"),
    .isSameAccount = true,
    .isWakeRemote = false
};

static PublishInfo g_pInfo = {
    .publishId = 1,
    .medium = COAP,
    .mode = DISCOVER_MODE_ACTIVE,
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
    .capability = "hicall",
    .capabilityData = NULL,
    .dataLen = 0,
    .isSameAccount = true,
    .isWakeRemote = false
};

static void TestDeviceFound(const DeviceInfo *device)
{
    LOG_INFO("[client]TestDeviceFound\n");
}

static void TestDiscoverFailed(int subscribeId, DiscoveryFailReason failReason)
{
    LOG_INFO("[client]TestDiscoverFailed\n");
}

static void TestDiscoverySuccess(int subscribeId)
{
    LOG_INFO("[client]TestDiscoverySuccess\n");
}

static void TestPublishSuccess(int publishId)
{
    LOG_INFO("[client]TestPublishSuccess\n");
}

static void TestPublishFail(int publishId, PublishFailReason reason)
{
    LOG_INFO("[client]TestPublishFail\n");
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
 * @tc.desc: Verify wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, PublishServiceTest001, TestSize.Level1)
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

    testInfo.medium = (ExchanageMedium)(COAP + 1);
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

    testInfo.capability = "test";
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.capability = "dvKit";

    testInfo.capabilityData = NULL;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = PublishService(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
    testInfo.dataLen = sizeof("capdata1");

    ret = PublishService(g_erroPkgName, &testInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
}
/**
 * @tc.name: PublishServiceTest002
 * @tc.desc: Verify normal case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, PublishServiceTest002, TestSize.Level1)
{
    int ret;

    g_pInfo.publishId = GetPublishId();
    ret = PublishService(g_pkgName, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);

    g_pInfo1.publishId = GetPublishId();
    ret = PublishService(g_pkgName, &g_pInfo1, &g_publishCb);
    EXPECT_TRUE(ret == 0);
}
/**
 * @tc.name: PublishServiceTest003
 * @tc.desc: Verify same parameter again
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, PublishServiceTest003, TestSize.Level1)
{
    int ret;

    g_pInfo.publishId = GetPublishId();
    ret = PublishService(g_pkgName, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    ret = PublishService(g_pkgName, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret != 0);
}
/**
 * @tc.name: StartDiscoveryTest001
 * @tc.desc: Verify wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, StartDiscoveryTest001, TestSize.Level1)
{
    int ret;
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .medium = COAP,
        .mode = DISCOVER_MODE_ACTIVE,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3"),
        .isSameAccount = true,
        .isWakeRemote = false
    };

    ret = StartDiscovery(NULL, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret != 0);

    ret = StartDiscovery(g_erroPkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret != 0);

    ret = StartDiscovery(g_pkgName, NULL, &g_subscribeCb);
    EXPECT_TRUE(ret != 0);

    ret = StartDiscovery(g_pkgName, &testInfo, NULL);
    EXPECT_TRUE(ret != 0);

    testInfo.medium = (ExchanageMedium)(COAP + 1);
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

    testInfo.capability = "test";
    ret = StartDiscovery(g_pkgName, &testInfo, &g_subscribeCb);
    EXPECT_TRUE(ret != 0);
    testInfo.capability = "dvKit";

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
 * @tc.desc: Verify normal case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, StartDiscoveryTest002, TestSize.Level1)
{
    int ret;


    g_sInfo.subscribeId = GetSubscribeId();
    ret = StartDiscovery(g_pkgName, &g_sInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);

    g_sInfo1.subscribeId = GetSubscribeId();
    ret = StartDiscovery(g_pkgName, &g_sInfo1, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
}
/**
 * @tc.name: StartDiscoveryTest003
 * @tc.desc: Verify same parameter again
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, StartDiscoveryTest003, TestSize.Level1)
{
    int ret;

    g_sInfo.subscribeId = GetSubscribeId();
    ret = StartDiscovery(g_pkgName, &g_sInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    ret = StartDiscovery(g_pkgName, &g_sInfo, &g_subscribeCb);
    EXPECT_TRUE(ret != 0);
}
/**
 * @tc.name: UnPublishServiceTest001
 * @tc.desc: Verify wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, UnPublishServiceTest001, TestSize.Level1)
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
 * @tc.desc: Verify normal case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, UnPublishServiceTest002, TestSize.Level1)
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
 * @tc.desc: Verify same parameter again
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, UnPublishServiceTest003, TestSize.Level1)
{
    int ret;
    int tmpId = GetPublishId();

    g_pInfo.publishId = tmpId;
    PublishService(g_pkgName, &g_pInfo, &g_publishCb);
    ret = UnPublishService(g_pkgName, tmpId);
    EXPECT_TRUE(ret == 0);
    ret = UnPublishService(g_pkgName, tmpId);
    EXPECT_TRUE(ret != 0);
}
/**
 * @tc.name: StopDiscoveryTest001
 * @tc.desc: Verify wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, StopDiscoveryTest001, TestSize.Level1)
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
 * @tc.desc: Verify normal case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, StopDiscoveryTest002, TestSize.Level1)
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
 * @tc.desc: Verify same parameter again
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(Disc_Test, StopDiscoveryTest003, TestSize.Level1)
{
    int ret;
    int tmpId = GetSubscribeId();

    g_sInfo.subscribeId = tmpId;
    StartDiscovery(g_pkgName, &g_sInfo, &g_subscribeCb);
    ret = StopDiscovery(g_pkgName, tmpId);
    EXPECT_TRUE(ret == 0);
    ret = StopDiscovery(g_pkgName, tmpId);
    EXPECT_TRUE(ret != 0);
}
}