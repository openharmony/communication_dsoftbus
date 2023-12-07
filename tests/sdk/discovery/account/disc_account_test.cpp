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
#include <securec.h>
#include <sys/time.h>
#include <unistd.h>

#include "discovery_service.h"
#include "inner_session.h"
#include "session.h"
#include "softbus_utils.h"

using namespace testing::ext;

namespace OHOS {
int32_t g_testWay = -1;
int32_t g_accountWay = -1;
int32_t g_publishId = 1;
int32_t g_subscribeId = 1;
enum TEST_WAY {
    STARTDISCOVERY_WAY = 0,
    PUBLISHSERVICE_WAY
};

enum ACCOUNT_MODE {
    SAMEACCOUNT_TRUE = 0,
    SAMEACCOUNT_FALSE
};

const char *g_pkgName = "com.objectstore.foundation";
bool g_state = false;
static void Wait(void);

ConnectionAddr g_addr;
ConnectionAddr g_addr1;

static SubscribeInfo g_sInfo = {
    .subscribeId = g_subscribeId,
    .medium = BLE,
    .mode = DISCOVER_MODE_ACTIVE,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata3",
    .dataLen = sizeof("capdata3"),
    .isSameAccount = false,
    .isWakeRemote = false
};

static PublishInfo g_pInfo = {
    .publishId = g_publishId,
    .medium = BLE,
    .mode = DISCOVER_MODE_PASSIVE,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata4",
    .dataLen = sizeof("capdata4")
};

static void TestDeviceFound(const DeviceInfo *device)
{
    if (ConvertBtMacToStr(g_addr.info.ble.bleMac, 18, (const uint8_t *)&(device->addr[0].info.ble.bleMac[0]), 6) != 0) {
        return;
    }
    if (strcmp(g_addr1.info.ble.bleMac, g_addr.info.ble.bleMac) != 0) {
        strcpy_s(g_addr1.info.ble.bleMac, BT_MAC_LEN, g_addr.info.ble.bleMac);
        printf("[client]TestDeviceFound\r\n");
        g_state = true;
    }
}

static void TestDiscoverFailed(int subscribeId, DiscoveryFailReason failReason)
{
    printf("[test]TestDiscoverFailed\r\n");
}

static void TestDiscoverySuccess(int subscribeId)
{
    printf("[test]TestDiscoverySuccess\r\n");
}

static void TestPublishSuccess(int publishId)
{
    printf("[test]TestPublishSuccess\r\n");
}

static void TestPublishFail(int publishId, PublishFailReason reason)
{
    printf("[test]TestPublishFail\r\n");
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

class DiscAccountTest : public testing::Test {
public:
    DiscAccountTest()
    {}
    ~DiscAccountTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void DiscAccountTest::SetUpTestCase(void)
{
    printf("********Ble Test Begin*********\r\n");
    printf("*       0.discovery           *\r\n");
    printf("*       1.publish             *\r\n");
    printf("*******************************\r\n");
    printf("input the num:");
    if (scanf_s("%d", &g_testWay, sizeof(g_testWay)) < 0) {
        printf("input error!\n");
    }
    getchar();
    if (g_testWay == PUBLISHSERVICE_WAY) {
        return;
    }
    printf("***********Account*************\r\n");
    printf("*          0.true             *\r\n");
    printf("*          1.false            *\r\n");
    printf("*******************************\r\n");
    printf("input the num:");
    if (scanf_s("%d", &g_accountWay, sizeof(g_accountWay)) < 0) {
        printf("input error!\n");
    }
    getchar();
    if (g_accountWay == SAMEACCOUNT_TRUE) {
        g_sInfo.isSameAccount = true;
        return;
    }
    g_sInfo.isSameAccount = false;
}

void DiscAccountTest::TearDownTestCase(void)
{
    if (g_testWay == STARTDISCOVERY_WAY) {
        StopDiscovery(g_pkgName, g_subscribeId);
        return;
    }
    UnPublishService(g_pkgName, g_publishId);
}

static void Wait(void)
{
    printf("[test]wait enter...\r\n");
    do {
        sleep(1);
    } while (!g_state);
    printf("[test]wait end!\r\n");
    g_state = false;
}

static int32_t TestPublishServer()
{
    printf("[test]TestPublishServer enter\r\n");
    g_pInfo.mode = DISCOVER_MODE_ACTIVE;
    int32_t ret = PublishService(g_pkgName, &g_pInfo, &g_publishCb);
    EXPECT_TRUE(ret == 0);
    printf("[test]TestPublishServer end\r\n");
    return ret;
}

static int32_t TestStartDiscovery()
{
    printf("[test]TestStartDiscovery enter\r\n");
    g_sInfo.mode = DISCOVER_MODE_ACTIVE;
    int32_t ret = StartDiscovery(g_pkgName, &g_sInfo, &g_subscribeCb);
    EXPECT_TRUE(ret == 0);
    printf("[test]TestStartDiscovery end\r\n");
    return ret;
}

/**
 * @tc.name: StartDiscovery001
 * @tc.desc: Verify wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscAccountTest, StartDiscovery001, TestSize.Level0)
{
    if (g_testWay != STARTDISCOVERY_WAY) {
        printf("[test]start dsicovery test skip...\r\n");
        EXPECT_TRUE(0 == 0);
        return;
    }
    int32_t ret = TestStartDiscovery();
    EXPECT_TRUE(ret == 0);
    Wait();
};


/**
 * @tc.name: PublishServiceTest001
 * @tc.desc: Verify wrong parameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscAccountTest, PublishServiceTest001, TestSize.Level0)
{
    if (g_testWay != PUBLISHSERVICE_WAY) {
        printf("[test]passive test skip...\r\n");
        EXPECT_TRUE(0 == 0);
        return;
    }
    int32_t ret = TestPublishServer();
    EXPECT_TRUE(ret == 0);
    Wait();
};
}
