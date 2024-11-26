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

#include <gtest/gtest.h>

#include <securec.h>

#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "softbus_wifi_api_adapter.h"

namespace OHOS {
using namespace testing::ext;

class WifiSoftBusTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void WifiSoftBusTest::SetUpTestCase() { }

void WifiSoftBusTest::TearDownTestCase() { }

void WifiSoftBusTest::SetUp() { }

void WifiSoftBusTest::TearDown() { }

static void OnWifiScanStateChangedHandler(int32_t state, int32_t size);
static bool g_stateScanSuccess = false;

constexpr int32_t DEF_TIMEOUT = 5;
constexpr int32_t ONE_SECOND = 1;

static void OnWifiScanStateChangedHandler(int32_t state, int32_t size)
{
    if (size > 0) {
        g_stateScanSuccess = true;
    }
    return;
}

static ISoftBusScanResult g_scanResultCb = { .onSoftBusWifiScanResult = OnWifiScanStateChangedHandler };

static void WaitSacnResult(void)
{
    int32_t scanTimeout = DEF_TIMEOUT;
    while (scanTimeout > 0) {
        sleep(ONE_SECOND);
        scanTimeout--;
        if (g_stateScanSuccess) {
            break;
        }
    }
    if (scanTimeout <= 0) {
        printf("WaitSacnResult:timeout!\n");
    }
}

HWTEST_F(WifiSoftBusTest, WifiSoftBusGetWifiScanListTest001, TestSize.Level0)
{
    SoftBusWifiScanInfo *result = NULL;
    unsigned int size = WIFI_MAX_SCAN_HOTSPOT_LIMIT;
    int32_t ret;

    EXPECT_TRUE(SoftBusRegisterWifiEvent(&g_scanResultCb) == SOFTBUS_OK);

    ret = IsWifiActive();
    if (ret != WIFI_STA_ACTIVE) {
        ret = EnableWifi();
        if (ret != WIFI_SUCCESS) {
            printf("SoftBus Enable Wifi failed.");
        }
        sleep(ONE_SECOND);
    }

    EXPECT_TRUE(IsWifiActive() == WIFI_STA_ACTIVE);

    EXPECT_TRUE(SoftBusStartWifiScan() == SOFTBUS_OK);

    WaitSacnResult();

    EXPECT_TRUE(SoftBusGetWifiScanList(&result, &size) == SOFTBUS_OK);

    EXPECT_TRUE(result != NULL);
    SoftBusFree(result);
    EXPECT_TRUE(SoftBusUnRegisterWifiEvent(&g_scanResultCb) == SOFTBUS_OK);
}
} // namespace OHOS
