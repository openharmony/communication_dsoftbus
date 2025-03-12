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

#include <cstdio>
#include <ctime>
#include <gtest/gtest.h>
#include <sys/time.h>
#include <unistd.h>

#include "client_bus_center_manager.h"
#include "disc_sdk_test_bt_status.h"
#include "softbus_access_token_test.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

using namespace testing::ext;

namespace OHOS {
static int32_t g_subscribeId = 0;
static int32_t g_publishId = 0;
static const char *g_pkgName = "Softbus_Kits";
static const char *g_pkgName_1 = "Softbus_Kits_1";
static const char *g_erroPkgName = "Softbus_Erro_Kits";
static const char *g_erroPkgName1 = "ErroErroErroErroErroErroErroErroErroErroErroErroErroErroErroErroEErroE";

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
    SetAccessTokenPermission("discTest");
}

void DiscSdkTest::TearDownTestCase(void)
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
    .dataLen = (unsigned int) strlen("capdata3")
};

static PublishInfo g_pInfo = {
    .publishId = 1,
    .mode = DISCOVER_MODE_PASSIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata4",
    .dataLen = (unsigned int) strlen("capdata4")
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
    .capability = "hicall",
    .capabilityData = nullptr,
    .dataLen = 0
};

static PublishInfo g_publishInfo = {
    .publishId = 1,
    .mode = DISCOVER_MODE_PASSIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = nullptr,
    .dataLen = 0
};

static SubscribeInfo g_subscribeInfo = {
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
    (void)device;
    printf("[client]TestDeviceFound\n");
}

static void TestOnDiscoverResult(int32_t refreshId, RefreshResult reason)
{
    (void)refreshId;
    (void)reason;
    printf("[client]TestDiscoverResult\n");
}

static const IRefreshCallback g_refreshCb = {
    .OnDeviceFound = TestDeviceFound,
    .OnDiscoverResult = TestOnDiscoverResult
};

static void TestOnPublishResult(int32_t publishId, PublishResult reason)
{
    (void)publishId;
    (void)reason;
    printf("[client]TestPublishResult\n");
}

static const IPublishCb g_publishCb = {
    .OnPublishResult = TestOnPublishResult,
};

/**
 * @tc.name: PublishLNNTest001
 * @tc.desc: Test for invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, PublishLNNTest001, TestSize.Level1)
{
    int32_t ret = PublishLNN(nullptr, &g_pInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = PublishLNN(g_pkgName, nullptr, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = PublishLNN(g_pkgName, &g_pInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: PublishLNNTest002
 * @tc.desc: Test for invalid packageName.
 * @tc.type: FUNC
 * @tc.require:The PublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, PublishLNNTest002, TestSize.Level1)
{
    g_pInfo.publishId = GetPublishId();
    int32_t ret = PublishLNN(g_erroPkgName1, &g_pInfo, &g_publishCb);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/**
 * @tc.name: PublishLNNTest003
 * @tc.desc: Test for invalid PublishInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, PublishLNNTest003, TestSize.Level1)
{
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = (unsigned int) strlen("capdata2"),
        .ranging = false
    };

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    int32_t ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_PASSIVE - 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    testInfo.mode = DISCOVER_MODE_PASSIVE;

    testInfo.medium = (ExchangeMedium)(COAP + 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    testInfo.freq = LOW;

    testInfo.capabilityData = nullptr;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: PublishLNNTest004
 * @tc.desc: Test GetPublishId and PublishLNN to see if they are running properly.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, PublishLNNTest004, TestSize.Level1)
{
    g_pInfo.publishId = GetPublishId();
    int32_t ret = PublishLNN(g_pkgName, &g_pInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, g_pInfo.publishId);

    g_pInfo1.publishId = GetPublishId();
    ret = PublishLNN(g_pkgName, &g_pInfo1, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, g_pInfo1.publishId);

    g_pInfo1.publishId = GetPublishId();
    ret = PublishLNN(g_pkgName_1, &g_pInfo1, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName_1, g_pInfo1.publishId);
}

/**
 * @tc.name: PublishLNNTest005
 * @tc.desc: Test different freq with passive CoAP publish.
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, PublishLNNTest005, TestSize.Level1)
{
    g_publishInfo.publishId = GetPublishId();
    g_publishInfo.mode = DISCOVER_MODE_PASSIVE;
    g_publishInfo.medium = COAP;

    int32_t ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_publishInfo.freq = MID;
    ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_publishInfo.freq = HIGH;
    ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_publishInfo.freq = SUPER_HIGH;
    ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_publishInfo.freq = EXTREME_HIGH;
    ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: PublishLNNTest006
 * @tc.desc: Test different freq with passive BLE publish.
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, PublishLNNTest006, TestSize.Level1)
{
    g_publishInfo.publishId = GetPublishId();
    g_publishInfo.mode = DISCOVER_MODE_PASSIVE;
    g_publishInfo.medium = BLE;

    bool isBtOn = SoftbusTestGetBtStatus();
    printf("bt status %s\n", isBtOn ? "on" : "off");

    int32_t ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    g_publishInfo.freq = MID;
    ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    g_publishInfo.freq = HIGH;
    ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    g_publishInfo.freq = SUPER_HIGH;
    ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    g_publishInfo.freq = EXTREME_HIGH;
    ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
}

/**
 * @tc.name: PublishLNNTest007
 * @tc.desc: Test different capability with passive CoAP publish.
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, PublishLNNTest007, TestSize.Level1)
{
    g_publishInfo.publishId = GetPublishId();
    g_publishInfo.mode = DISCOVER_MODE_PASSIVE;
    g_publishInfo.medium = COAP;

    int32_t ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);

    g_publishInfo.capability = "hicall";
    ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);

    g_publishInfo.capability = "profile";
    ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);

    g_publishInfo.capability = "homevisionPic";
    ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);

    g_publishInfo.capability = "castPlus";
    g_publishInfo.capabilityData = (unsigned char *)"{\"castPlus\":\"capdata2\"}";
    g_publishInfo.dataLen = (unsigned int) strlen("{\"castPlus\":\"capdata2\"}");
    ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    g_publishInfo.capabilityData = (unsigned char *)"capdata2";
    g_publishInfo.dataLen = (unsigned int) strlen("capdata2");
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);

    g_publishInfo.capability = "aaCapability";
    ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);

    g_publishInfo.capability = "ddmpCapability";
    ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);

    g_publishInfo.capability = "osdCapability";
    ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
}

/**
 * @tc.name: PublishLNNTest008
 * @tc.desc: Test different capability with passive BLE publish: dvKit, castPlus, osdCapability
 * @tc.type: FUNC
 * @tc.require: The PublishLNN and StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, PublishLNNTest008, TestSize.Level1)
{
    g_publishInfo.publishId = GetPublishId();
    g_publishInfo.mode = DISCOVER_MODE_PASSIVE;
    g_publishInfo.medium = BLE;

    bool isBtOn = SoftbusTestGetBtStatus();
    printf("bt status %s\n", isBtOn ? "on" : "off");

    g_publishInfo.capability = "dvKit";
    int32_t ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);

    g_publishInfo.capability = "castPlus";
    g_publishInfo.capabilityData = (unsigned char *)"{\"castPlus\":\"capdata2\"}";
    g_publishInfo.dataLen = (unsigned int) strlen("{\"castPlus\":\"capdata2\"}");
    ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    g_publishInfo.capabilityData = (unsigned char *)"capdata2";
    g_publishInfo.dataLen = (unsigned int) strlen("capdata2");
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);

    g_publishInfo.capability = "osdCapability";
    ret = PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
}

/**
 * @tc.name: RefreshLNNTest001
 * @tc.desc: Test for invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest001, TestSize.Level1)
{
    int32_t ret = RefreshLNN(nullptr, &g_sInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = RefreshLNN(g_pkgName, nullptr, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = RefreshLNN(g_pkgName, &g_sInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: RefreshLNNTest002
 * @tc.desc: Test for invalid packageName.
 * @tc.type: FUNC
 * @tc.require:The PublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest002, TestSize.Level1)
{
    g_sInfo.subscribeId = GetSubscribeId();
    int32_t ret = RefreshLNN(g_erroPkgName1, &g_sInfo, &g_refreshCb);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/**
 * @tc.name: RefreshLNNTest003
 * @tc.desc: Test for invalid SubscribeInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest003, TestSize.Level1)
{
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = (unsigned int) strlen("capdata3")
    };

    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_ACTIVE + 1);
    int32_t ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    testInfo.mode = (DiscoverMode)(DISCOVER_MODE_PASSIVE - 1);
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    testInfo.mode = DISCOVER_MODE_PASSIVE;

    testInfo.medium = (ExchangeMedium)(COAP1);
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    testInfo.medium = (ExchangeMedium)(USB);
    testInfo.mode = DISCOVER_MODE_ACTIVE;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    testInfo.medium = (ExchangeMedium)(AUTO - 1);
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    testInfo.medium = COAP;

    testInfo.freq = (ExchangeFreq)(FREQ_BUTT);
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    testInfo.freq = (ExchangeFreq)(LOW - 1);
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    testInfo.freq = LOW;

    testInfo.capabilityData = nullptr;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    testInfo.capabilityData = (unsigned char *)"capdata1";

    testInfo.dataLen = ERRO_CAPDATA_LEN;
    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: RefreshLNNTest004
 * @tc.desc: Verify the RefreshLNN normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest004, TestSize.Level1)
{
    g_sInfo.subscribeId = GetSubscribeId();
    int32_t ret = RefreshLNN(g_pkgName, &g_sInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopRefreshLNN(g_pkgName, g_sInfo.subscribeId);

    g_sInfo1.subscribeId = GetSubscribeId();
    ret = RefreshLNN(g_pkgName, &g_sInfo1, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopRefreshLNN(g_pkgName, g_sInfo1.subscribeId);

    g_sInfo1.subscribeId = GetSubscribeId();
    ret = RefreshLNN(g_pkgName_1, &g_sInfo1, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopRefreshLNN(g_pkgName, g_sInfo1.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest005
 * @tc.desc: Test different freq with passive CoAP discovery.
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest005, TestSize.Level1)
{
    g_subscribeInfo.subscribeId = GetSubscribeId();
    g_subscribeInfo.mode = DISCOVER_MODE_PASSIVE;
    g_subscribeInfo.medium = COAP;

    int32_t ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_subscribeInfo.freq = MID;
    ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_subscribeInfo.freq = HIGH;
    ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_subscribeInfo.freq = SUPER_HIGH;
    ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_subscribeInfo.freq = EXTREME_HIGH;
    ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: RefreshLNNTest006
 * @tc.desc: Test different freq with passive BLE discovery.
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest006, TestSize.Level1)
{
    g_subscribeInfo.subscribeId = GetSubscribeId();
    g_subscribeInfo.mode = DISCOVER_MODE_PASSIVE;
    g_subscribeInfo.medium = BLE;

    bool isBtOn = SoftbusTestGetBtStatus();
    printf("bt status %s\n", isBtOn ? "on" : "off");

    int32_t ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    g_subscribeInfo.freq = MID;
    ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    g_subscribeInfo.freq = HIGH;
    ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    g_subscribeInfo.freq = SUPER_HIGH;
    ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    g_subscribeInfo.freq = EXTREME_HIGH;
    ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
}

/**
 * @tc.name: RefreshLNNTest007
 * @tc.desc: Test different capability with passive CoAP discovery.
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest007, TestSize.Level1)
{
    g_subscribeInfo.subscribeId = GetSubscribeId();
    g_subscribeInfo.mode = DISCOVER_MODE_PASSIVE;
    g_subscribeInfo.medium = COAP;

    int32_t ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);

    g_subscribeInfo.capability = "hicall";
    ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);

    g_subscribeInfo.capability = "profile";
    ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);

    g_subscribeInfo.capability = "homevisionPic";
    ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);

    g_subscribeInfo.capability = "castPlus";
    ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);

    g_subscribeInfo.capability = "aaCapability";
    ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);

    g_subscribeInfo.capability = "ddmpCapability";
    ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);

    g_subscribeInfo.capability = "osdCapability";
    ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest008
 * @tc.desc: Test different capability with passive BLE discovery: dvKit, castPlus, osdCapability
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest008, TestSize.Level1)
{
    g_subscribeInfo.subscribeId = GetSubscribeId();
    g_subscribeInfo.mode = DISCOVER_MODE_PASSIVE;
    g_subscribeInfo.medium = BLE;

    bool isBtOn = SoftbusTestGetBtStatus();
    printf("bt status %s\n", isBtOn ? "on" : "off");

    g_subscribeInfo.capability = "dvKit";
    int32_t ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);

    g_subscribeInfo.capability = "castPlus";
    ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);

    g_subscribeInfo.capability = "osdCapability";
    ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
}

/**
 * @tc.name: RefreshLNNTest009
 * @tc.desc: Test usb capability with passive usb discovery
 * @tc.type: FUNC
 * @tc.require: The RefreshLNN and StopRefreshLNN operates normally.
 */
HWTEST_F(DiscSdkTest, RefreshLNNTest009, TestSize.Level1)
{
    g_subscribeInfo.subscribeId = GetSubscribeId();
    g_subscribeInfo.mode = DISCOVER_MODE_PASSIVE;
    g_subscribeInfo.medium = USB;
    g_subscribeInfo.capability = "approach";

    int32_t ret = RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);

    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_NE(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: StopPublishLNNTest001
 * @tc.desc: Verify StopPublishLNN invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, StopPublishLNNTest001, TestSize.Level1)
{
    int32_t tmpId = GetPublishId();
    g_pInfo.publishId = tmpId;
    PublishLNN(g_pkgName, &g_pInfo, &g_publishCb);

    int32_t ret = StopPublishLNN(nullptr, tmpId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = StopPublishLNN(g_erroPkgName, tmpId);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/**
 * @tc.name: StopPublishLNNTest002
 * @tc.desc: Verify PublishLNN and StopPublishLNN normal case.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, StopPublishLNNTest002, TestSize.Level1)
{
    int32_t tmpId1 = GetPublishId();
    int32_t tmpId2 = GetPublishId();

    g_pInfo.publishId = tmpId1;
    PublishLNN(g_pkgName, &g_pInfo, &g_publishCb);
    g_pInfo1.publishId = tmpId2;
    PublishLNN(g_pkgName, &g_pInfo1, &g_publishCb);

    int32_t ret = StopPublishLNN(g_pkgName, tmpId1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, tmpId2);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: StopPublishLNNTest003
 * @tc.desc: Verify PublishLNN and StopPublishLNN same parameter again.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, StopPublishLNNTest003, TestSize.Level1)
{
    int32_t tmpId = GetPublishId();
    g_pInfo.publishId = tmpId;
    PublishLNN(g_pkgName, &g_pInfo, &g_publishCb);

    int32_t ret = StopPublishLNN(g_pkgName, tmpId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: StopPublishLNNTest004
 * @tc.desc: Test different freq with stop passive CoAP publish.
 * @tc.type: FUNC
 * @tc.require: The StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, StopPublishLNNTest004, TestSize.Level1)
{
    g_publishInfo.publishId = GetPublishId();
    g_publishInfo.mode = DISCOVER_MODE_PASSIVE;
    g_publishInfo.medium = COAP;

    PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    int32_t ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_publishInfo.freq = MID;
    PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_publishInfo.freq = HIGH;
    PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_publishInfo.freq = SUPER_HIGH;
    PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_publishInfo.freq = EXTREME_HIGH;
    PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: StopPublishLNNTest005
 * @tc.desc: Test different freq with stop passive BLE publish.
 * @tc.type: FUNC
 * @tc.require: The StopPublishLNN operates normally.
 */
HWTEST_F(DiscSdkTest, StopPublishLNNTest005, TestSize.Level1)
{
    g_publishInfo.publishId = GetPublishId();
    g_publishInfo.mode = DISCOVER_MODE_PASSIVE;
    g_publishInfo.medium = BLE;

    bool isBtOn = SoftbusTestGetBtStatus();
    printf("bt status %s\n", isBtOn ? "on" : "off");

    PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    int32_t ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    g_publishInfo.freq = MID;
    PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    g_publishInfo.freq = HIGH;
    PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    g_publishInfo.freq = SUPER_HIGH;
    PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    g_publishInfo.freq = EXTREME_HIGH;
    PublishLNN(g_pkgName, &g_publishInfo, &g_publishCb);
    ret = StopPublishLNN(g_pkgName, g_publishInfo.publishId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
}

/**
 * @tc.name: StopRefreshLNNTest001
 * @tc.desc: Verify StopRefreshLNN invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, StopRefreshLNNTest001, TestSize.Level1)
{
    int32_t tmpId = GetSubscribeId();
    g_sInfo.subscribeId = tmpId;
    RefreshLNN(g_pkgName, &g_sInfo, &g_refreshCb);

    int32_t ret = StopRefreshLNN(nullptr, tmpId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = StopRefreshLNN(g_erroPkgName, tmpId);
    EXPECT_NE(ret, SOFTBUS_OK);
}

/**
 * @tc.name: StopRefreshLNNTest002
 * @tc.desc: test under normal conditions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, StopRefreshLNNTest002, TestSize.Level1)
{
    int32_t tmpId1 = GetSubscribeId();
    int32_t tmpId2 = GetSubscribeId();

    g_sInfo.subscribeId = tmpId1;
    RefreshLNN(g_pkgName, &g_sInfo, &g_refreshCb);
    g_sInfo1.subscribeId = tmpId2;
    RefreshLNN(g_pkgName, &g_sInfo1, &g_refreshCb);

    int32_t ret = StopRefreshLNN(g_pkgName, tmpId1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopRefreshLNN(g_pkgName, tmpId2);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: StopRefreshLNNTest003
 * @tc.desc: Verify RefreshLNN and StopRefreshLNN same parameter again.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscSdkTest, StopRefreshLNNTest003, TestSize.Level1)
{
    int32_t tmpId = GetSubscribeId();
    g_sInfo.subscribeId = tmpId;
    RefreshLNN(g_pkgName, &g_sInfo, &g_refreshCb);

    int32_t ret = StopRefreshLNN(g_pkgName, tmpId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: StopRefreshLNNTest004
 * @tc.desc:Test different freq with stop passive CoAP discovery.
 * @tc.type: FUNC
 * @tc.require: The StopRefreshLNN operates normally
 */
HWTEST_F(DiscSdkTest, StopRefreshLNNTest004, TestSize.Level1)
{
    g_subscribeInfo.subscribeId = GetSubscribeId();
    g_subscribeInfo.mode = DISCOVER_MODE_PASSIVE;
    g_subscribeInfo.medium = COAP;
    g_subscribeInfo.capability = "osdCapability";

    RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    int32_t ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_subscribeInfo.freq = MID;
    RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_subscribeInfo.freq = HIGH;
    RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_subscribeInfo.freq = SUPER_HIGH;
    RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_subscribeInfo.freq = EXTREME_HIGH;
    RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: StopRefreshLNNTest005
 * @tc.desc:Test different freq with stop passive BLE discovery.
 * @tc.type: FUNC
 * @tc.require: The StopRefreshLNN operates normally
 */
HWTEST_F(DiscSdkTest, StopRefreshLNNTest005, TestSize.Level1)
{
    g_subscribeInfo.subscribeId = GetSubscribeId();
    g_subscribeInfo.mode = DISCOVER_MODE_PASSIVE;
    g_subscribeInfo.medium = BLE;

    bool isBtOn = SoftbusTestGetBtStatus();
    printf("bt status %s\n", isBtOn ? "on" : "off");

    RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    int32_t ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    g_subscribeInfo.freq = MID;
    RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    g_subscribeInfo.freq = HIGH;
    RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    g_subscribeInfo.freq = SUPER_HIGH;
    RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));

    g_subscribeInfo.freq = EXTREME_HIGH;
    RefreshLNN(g_pkgName, &g_subscribeInfo, &g_refreshCb);
    ret = StopRefreshLNN(g_pkgName, g_subscribeInfo.subscribeId);
    EXPECT_EQ(isBtOn, (ret == SOFTBUS_OK));
}

/**
 * @tc.name:DiscRecoveryPublishTest01
 * @tc.desc: Test recovery publish.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:The DiscRecoveryPublish operates normally
 */
HWTEST_F(DiscSdkTest, DiscRecoveryPublishTest01, TestSize.Level1)
{
    int32_t ret;
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = (unsigned int) strlen("capdata2")
    };
    BusCenterClientDeinit();
    BusCenterClientInit();
    ret = DiscRecoveryPublish();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DiscRecoveryPublish();
    EXPECT_TRUE(ret != 0);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);

    ret = PublishLNN(g_pkgName, &testInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopPublishLNN(g_pkgName, testInfo.publishId);
    ret = DiscRecoveryPublish();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name:DiscRecoverySubscribeTest01
 * @tc.desc: Test recovery subscribe.
 * @tc.in: Test module, Test number, Test levels.
 * @tc.out: Zero
 * @tc.type: FUNC
 * @tc.require:The DiscRecoverySubscribe operates normally
 */
HWTEST_F(DiscSdkTest, DiscRecoverySubscribeTest01, TestSize.Level1)
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
        .dataLen = (unsigned int) strlen("capdata3")
    };
    BusCenterClientDeinit();
    BusCenterClientInit();
    ret = DiscRecoverySubscribe();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DiscRecoverySubscribe();
    EXPECT_TRUE(ret != 0);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);

    ret = RefreshLNN(g_pkgName, &testInfo, &g_refreshCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = StopRefreshLNN(g_pkgName, testInfo.subscribeId);
    ret = DiscRecoverySubscribe();
    EXPECT_EQ(ret, SOFTBUS_OK);
}
} // namespace OHOS