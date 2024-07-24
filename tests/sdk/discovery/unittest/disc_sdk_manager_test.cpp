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
#include <gtest/gtest.h>

#include "client_disc_manager.h"
#include "disc_server_proxy.h"
#include "softbus_errcode.h"

using namespace testing::ext;

namespace OHOS {
static int32_t g_subscribeId = 0;
static int32_t g_publishId = 0;
static char g_pkgName[] = "Softbus_Kits";
static bool g_isFound = false;
static bool g_discSuccessFlag = false;
static bool g_discFailedFlag = false;
static bool g_pubSuccessFlag = false;
static bool g_pubFailedFlag = false;

class DiscSdkManagerTest : public testing::Test {
public:
    DiscSdkManagerTest()
    {}
    ~DiscSdkManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void DiscSdkManagerTest::SetUpTestCase(void)
{}

void DiscSdkManagerTest::TearDownTestCase(void)
{}

static SubscribeInfo g_subscribeInfo = {
    .subscribeId = 1,
    .mode = DISCOVER_MODE_PASSIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata",
    .dataLen = strlen("capdata")
};

static PublishInfo g_publishInfo = {
    .publishId = 1,
    .mode = DISCOVER_MODE_PASSIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata",
    .dataLen = strlen("capdata")
};

static void TestDeviceFound(const DeviceInfo *device)
{
    printf("[client]TestDeviceFound\n");
    g_isFound = true;
}

static void TestDiscoverFailed(int32_t subscribeId, DiscoveryFailReason failReason)
{
    printf("[client]TestDiscoverFailed\n");
    g_discFailedFlag = true;
}

static void TestDiscoverySuccess(int32_t subscribeId)
{
    printf("[client]TestDiscoverySuccess\n");
    g_discSuccessFlag = true;
}

static void TestPublishSuccess(int32_t publishId)
{
    printf("[client]TestPublishSuccess\n");
    g_pubSuccessFlag = true;
}

static void TestPublishFail(int32_t publishId, PublishFailReason reason)
{
    printf("[client]TestPublishFail\n");
    g_pubFailedFlag = true;
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
 * @tc.name: PublishServiceInnerTest001
 * @tc.desc: Test PublishServiceInner when ServerIpcPublishService failed.
 * @tc.in: Test Moudle, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The g_serverProxy is not initialized and return SOFTBUS_NO_INIT.
 */
HWTEST_F(DiscSdkManagerTest, PublishServiceInnerTest001, TestSize.Level1)
{
    int32_t ret = DiscClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DiscServerProxyDeInit();
    ret = PublishServiceInner(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    DiscClientDeinit();
}

/**
 * @tc.name: UnpublishServiceInnerTest001
 * @tc.desc: Test UnpublishServiceInner when ServerIpcUnPublishService failed.
 * @tc.in: Test Moudle, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The g_serverProxy is not initialized and return SOFTBUS_NO_INIT.
 */
HWTEST_F(DiscSdkManagerTest, UnpublishServiceInnerTest001, TestSize.Level1)
{
    int32_t ret = UnpublishServiceInner(g_pkgName, g_publishId);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/**
 * @tc.name: StartDiscoveryInnerTest001
 * @tc.desc: Test StartDiscoveryInner when ServerIpcStartDiscovery failed.
 * @tc.in: Test Moudle, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The g_serverProxy is not initialized and return SOFTBUS_NO_INIT.
 */
HWTEST_F(DiscSdkManagerTest, StartDiscoveryInnerTest001, TestSize.Level1)
{
    int32_t ret = DiscClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DiscServerProxyDeInit();
    ret = StartDiscoveryInner(g_pkgName, &g_subscribeInfo, &g_subscribeCb);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    DiscClientDeinit();
}

/**
 * @tc.name: StopDiscoveryInnerTest001
 * @tc.desc: Test StopDiscoveryInner when ServerIpcStopDiscovery failed.
 * @tc.in: Test Moudle, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The g_serverProxy is not initialized and return SOFTBUS_NO_INIT.
 */
HWTEST_F(DiscSdkManagerTest, StopDiscoveryInnerTest001, TestSize.Level1)
{
    int32_t ret = StopDiscoveryInner(g_pkgName, g_subscribeId);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/**
 * @tc.name: DiscClientOnDeviceFoundTest001
 * @tc.desc: The first call to DiscClientOnDeviceFound parameter is null, the second call g_discInfo is not
 *           initialized, and the third call is normal.
 * @tc.in: Test Moudle, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: Test DiscClientOnDeviceFound when g_discInfo is null and normal.
 */
HWTEST_F(DiscSdkManagerTest, DiscClientOnDeviceFoundTest001, TestSize.Level1)
{
    DeviceInfo device;
    DiscClientOnDeviceFound(nullptr);
    EXPECT_FALSE(g_isFound);
    DiscClientOnDeviceFound(&device);
    EXPECT_FALSE(g_isFound);
    int32_t ret = DiscClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DiscServerProxyDeInit();
    ret = StartDiscoveryInner(g_pkgName, &g_subscribeInfo, &g_subscribeCb);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    DiscClientOnDeviceFound(&device);
    EXPECT_TRUE(g_isFound);
    DiscClientDeinit();
}

/**
 * @tc.name: DiscClientOnDiscoverySuccessTest001
 * @tc.desc: The first call to DiscClientOnDiscoverySuccess g_discInfo is null, the second call is normal.
 * @tc.in: Test Moudle, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: Test DiscClientOnDiscoverySuccess when g_discInfo is null and normal.
 */
HWTEST_F(DiscSdkManagerTest, DiscClientOnDiscoverySuccessTest001, TestSize.Level1)
{
    DiscClientOnDiscoverySuccess(g_subscribeId);
    EXPECT_FALSE(g_discSuccessFlag);
    int32_t ret = DiscClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DiscServerProxyDeInit();
    ret = StartDiscoveryInner(g_pkgName, &g_subscribeInfo, &g_subscribeCb);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    DiscClientOnDiscoverySuccess(g_subscribeId);
    EXPECT_TRUE(g_discSuccessFlag);
    DiscClientDeinit();
}

/**
 * @tc.name: DiscClientOnDiscoverFailedTest001
 * @tc.desc: The first call to DiscClientOnDiscoverFailed g_discInfo is null, the second call is normal.
 * @tc.in: Test Moudle, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: Test DiscClientOnDiscoverFailed when g_discInfo is null and normal.
 */
HWTEST_F(DiscSdkManagerTest, DiscClientOnDiscoverFailedTest001, TestSize.Level1)
{
    DiscClientOnDiscoverFailed(g_subscribeId, DISCOVERY_FAIL_REASON_NOT_SUPPORT_MEDIUM);
    EXPECT_FALSE(g_discFailedFlag);
    int32_t ret = DiscClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DiscServerProxyDeInit();
    ret = StartDiscoveryInner(g_pkgName, &g_subscribeInfo, &g_subscribeCb);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    DiscClientOnDiscoverFailed(g_subscribeId, DISCOVERY_FAIL_REASON_NOT_SUPPORT_MEDIUM);
    EXPECT_TRUE(g_discFailedFlag);
    DiscClientDeinit();
}

/**
 * @tc.name: DiscClientOnPublishSuccessTest001
 * @tc.desc: The first call to DiscClientOnPublishSuccess g_discInfo is null, the second call is normal.
 * @tc.in: Test Moudle, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: Test DiscClientOnPublishSuccess when g_discInfo is null and normal.
 */
HWTEST_F(DiscSdkManagerTest, DiscClientOnPublishSuccessTest001, TestSize.Level1)
{
    DiscClientOnPublishSuccess(g_publishId);
    EXPECT_FALSE(g_pubSuccessFlag);
    int32_t ret = DiscClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DiscServerProxyDeInit();
    ret = PublishServiceInner(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    DiscClientOnPublishSuccess(g_publishId);
    EXPECT_TRUE(g_pubSuccessFlag);
    DiscClientDeinit();
}

/**
 * @tc.name: DiscClientOnPublishFailTest001
 * @tc.desc: The first call to DiscClientOnPublishFail g_discInfo is null, the second call is normal.
 * @tc.in: Test Moudle, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: Test DiscClientOnPublishFail when g_discInfo is null and normal.
 */
HWTEST_F(DiscSdkManagerTest, DiscClientOnPublishFailTest001, TestSize.Level1)
{
    DiscClientOnPublishFail(g_publishId, PUBLISH_FAIL_REASON_NOT_SUPPORT_MEDIUM);
    EXPECT_FALSE(g_pubFailedFlag);
    int32_t ret = DiscClientInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DiscServerProxyDeInit();
    ret = PublishServiceInner(g_pkgName, &g_publishInfo, &g_publishCb);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
    DiscClientOnPublishFail(g_publishId, PUBLISH_FAIL_REASON_NOT_SUPPORT_MEDIUM);
    EXPECT_TRUE(g_pubFailedFlag);
    DiscClientDeinit();
}

/**
 * @tc.name: DiscServerProxyInitTest001
 * @tc.desc: Test DiscServerProxyInit again.
 * @tc.in: Test Moudle, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The g_serverProxy is initialized and return SOFTBUS_OK.
 */
HWTEST_F(DiscSdkManagerTest, DiscServerProxyInitTest001, TestSize.Level1)
{
    int32_t ret = DiscServerProxyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DiscServerProxyInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DiscServerProxyDeInit();
}

/**
 * @tc.name: ServerIpcPublishServiceTest001
 * @tc.desc: Test the first call to ServerIpcPublishService.
 * @tc.in: Test Moudle, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The g_serverProxy is not initialized and return SOFTBUS_NO_INIT.
 */
HWTEST_F(DiscSdkManagerTest, ServerIpcPublishServiceTest001, TestSize.Level1)
{
    int32_t ret = ServerIpcPublishService(g_pkgName, &g_publishInfo);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/**
 * @tc.name: ServerIpcUnPublishServiceTest001
 * @tc.desc: Test the first call to ServerIpcUnPublishService.
 * @tc.in: Test Moudle, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The g_serverProxy is not initialized and return SOFTBUS_NO_INIT.
 */
HWTEST_F(DiscSdkManagerTest, ServerIpcUnPublishServiceTest001, TestSize.Level1)
{
    int32_t ret = ServerIpcUnPublishService(g_pkgName, g_publishId);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/**
 * @tc.name: ServerIpcStartDiscoveryTest001
 * @tc.desc: Test the first call to ServerIpcStartDiscovery.
 * @tc.in: Test Moudle, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The g_serverProxy is not initialized and return SOFTBUS_NO_INIT.
 */
HWTEST_F(DiscSdkManagerTest, ServerIpcStartDiscoveryTest001, TestSize.Level1)
{
    int32_t ret = ServerIpcStartDiscovery(g_pkgName, &g_subscribeInfo);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}

/**
 * @tc.name: ServerIpcStopDiscoveryTest001
 * @tc.desc: Test the first call to ServerIpcStopDiscovery.
 * @tc.in: Test Moudle, Test Number, Test Levels.
 * @tc.out: NonZero
 * @tc.type: FUNC
 * @tc.require: The g_serverProxy is not initialized and return SOFTBUS_NO_INIT.
 */
HWTEST_F(DiscSdkManagerTest, ServerIpcStopDiscoveryTest001, TestSize.Level1)
{
    int32_t ret = ServerIpcStopDiscovery(g_pkgName, g_subscribeId);
    EXPECT_EQ(ret, SOFTBUS_NO_INIT);
}
} // namespace OHOS
