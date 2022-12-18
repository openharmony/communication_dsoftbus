/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <unistd.h>

#include "bus_center_info_key.h"
#include "disc_manager.h"
#include "disc_nstackx_adapter.c"
#include "disc_nstackx_adapter.h"
#include "lnn_local_net_ledger.h"
#include "nstackx.h"
#include "nstackx_error.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

using namespace testing::ext;
namespace OHOS {

static bool isDeviceFound = false;
class DiscNstackxAdapterTest : public testing::Test {
public:
    DiscNstackxAdapterTest()
    {}
    ~DiscNstackxAdapterTest()
    {}
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

static void OnDeviceFoundTest(const DeviceInfo *device, const InnerDeviceInfoAddtions *addtions)
{
    (void)device;
    (void)addtions;
    DLOGI("OnDeviceFoundTest in");
    isDeviceFound = true;
}

static DiscInnerCallback g_discInnerCb = {
    .OnDeviceFound = OnDeviceFoundTest
};

/*
 * @tc.name: testDiscCoapAdapterInit001
 * @tc.desc: test DiscCoapAdapterInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, testDiscCoapAdapterInit001, TestSize.Level1)
{
    DiscNstackxDeinit();
    int32_t ret = DiscNstackxInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    // repeat init
    ret = DiscNstackxInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: testDiscCoapAdapterRegCb001
 * @tc.desc: test DiscCoapAdapterRegCb
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, testDiscCoapAdapterRegCb001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = DiscCoapRegisterCb(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DiscCoapRegisterCb(&g_discInnerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: testDiscCoapAdapterRegCapa001
 * @tc.desc: test DiscCoapAdapterRegCapa
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, testDiscCoapAdapterRegCapa001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    uint32_t capaBitmap[] = {128};
    uint32_t bitmapCount = 1;
    uint32_t invalidCount = 3;
    ret = DiscCoapRegisterCapability(0, capaBitmap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DiscCoapRegisterCapability(invalidCount, capaBitmap);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL);

    ret = DiscCoapRegisterCapability(bitmapCount, capaBitmap);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: testDiscCoapAdapterSetFilter001
 * @tc.desc: test DiscCoapAdapterSetFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, testDiscCoapAdapterSetFilter001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    uint32_t capaBitmap[] = {128};
    uint32_t bitmapCount = 1;
    uint32_t invalidCount = 3;
    ret = DiscCoapSetFilterCapability(0, capaBitmap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DiscCoapSetFilterCapability(invalidCount, capaBitmap);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL);

    ret = DiscCoapSetFilterCapability(bitmapCount, capaBitmap);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: testDiscCoapAdapterRegData001
 * @tc.desc: test DiscCoapAdapterRegData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, testDiscCoapAdapterRegData001, TestSize.Level1)
{
    DiscNstackxDeinit();
    int32_t ret = DiscCoapRegisterServiceData(nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_INIT_FAIL);

    ret = DiscNstackxInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DiscCoapRegisterServiceData(nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: testDiscCoapAdapterStartDisc001
 * @tc.desc: test DiscCoapAdapterStartDisc
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, testDiscCoapAdapterStartDisc001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscCoapOption testCoapOption = {
        .freq = LOW,
        .mode = INVALID_MODE
    };
    ret = DiscCoapStartDiscovery(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DiscCoapStartDiscovery(&testCoapOption);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    testCoapOption.mode = (DiscCoapMode)(ACTIVE_DISCOVERY + 1);
    ret = DiscCoapStartDiscovery(&testCoapOption);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    testCoapOption.mode = ACTIVE_PUBLISH;
    ret = DiscCoapStartDiscovery(&testCoapOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DiscCoapStopDiscovery();
    EXPECT_EQ(ret, SOFTBUS_OK);

    testCoapOption.mode = ACTIVE_DISCOVERY;
    ret = DiscCoapStartDiscovery(&testCoapOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DiscCoapStopDiscovery();
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscNstackxDeinit();
    ret = DiscCoapStopDiscovery();
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL);
}

/*
 * @tc.name: testDiscCoapAdapterUpdate001
 * @tc.desc: test DiscCoapAdapterUpdate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, testDiscCoapAdapterUpdate001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscCoapOption testCoapOption = {
        .freq = LOW,
        .mode = ACTIVE_DISCOVERY
    };
    DiscCoapUpdateLocalIp(LINK_STATUS_UP);
    DiscCoapUpdateDevName();
    ret = DiscCoapStartDiscovery(&testCoapOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscCoapUpdateLocalIp(LINK_STATUS_DOWN);
    ret = DiscCoapStartDiscovery(&testCoapOption);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscCoapUpdateLocalIp((LinkStatus)(-1));
    ret = DiscCoapStartDiscovery(&testCoapOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

static NSTACKX_DeviceInfo testNstackxInfo = {
    .deviceId = "{UDID:123456789012345}",
    .deviceName = "OpenHarmonyDevice",
    .capabilityBitmapNum = 1,
    .capabilityBitmap = {128},
    .deviceType = 0,
    .mode = DISCOVER_MODE,
    .update = 1,
    .reserved = 0,
    .networkName = "wlan0",
    .discoveryType = NSTACKX_DISCOVERY_TYPE_ACTIVE,
    .businessType = NSTACKX_BUSINESS_TYPE_NULL,
    .version = "hm1.0.0",
    .reservedInfo = "reserved"
};

/*
 * @tc.name: testDiscCoapAdapterFound001
 * @tc.desc: test DiscCoapAdapterFound invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, testDiscCoapAdapterFound001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DiscCoapRegisterCb(&g_discInnerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    OnDeviceFound(&testNstackxInfo, 0);
    ASSERT_TRUE(!isDeviceFound);

    OnDeviceFound(nullptr, 1);
    ASSERT_TRUE(!isDeviceFound);

    testNstackxInfo.update = 0;
    OnDeviceFound(&testNstackxInfo, 1);
    ASSERT_TRUE(!isDeviceFound);
    testNstackxInfo.update = 1;

    testNstackxInfo.discoveryType = NSTACKX_DISCOVERY_TYPE_PASSIVE;
    testNstackxInfo.mode = DISCOVER_MODE;
    OnDeviceFound(&testNstackxInfo, 1);
    ASSERT_TRUE(!isDeviceFound);

    testNstackxInfo.mode = PUBLISH_MODE_PROACTIVE;
    OnDeviceFound(&testNstackxInfo, 1);
    ASSERT_TRUE(!isDeviceFound);

    testNstackxInfo.discoveryType = NSTACKX_DISCOVERY_TYPE_ACTIVE;
    OnDeviceFound(&testNstackxInfo, 1);
    ASSERT_TRUE(!isDeviceFound);
}
}
