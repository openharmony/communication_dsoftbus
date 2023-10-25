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

static InnerDeviceInfoAddtions g_testAddtions = {
    .medium = AUTO
};

static void OnDeviceFoundTest(const DeviceInfo *device, const InnerDeviceInfoAddtions *addtions)
{
    (void)device;
    (void)addtions;
    DLOGI("OnDeviceFoundTest in");
    isDeviceFound = true;
    g_testAddtions.medium = addtions->medium;
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
 * @tc.name: TestDiscCoapAdapterStartDisc002
 * @tc.desc: Test DiscCoapStartDiscovery should return
 *           SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL when given invalid DiscCoapOption.freq,
 *           SOFTBUS_DISCOVER_COAP_START_DISCOVER_FAIL when given invalid DiscCoapOption.freq and
 *           ACTIVE_DISCOVERY DiscCoapOption.mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterStartDisc002, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    DiscCoapOption testOption = {
        .freq = LOW,
        .mode = ACTIVE_PUBLISH
    };
    ret = DiscCoapStartDiscovery(&testOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DiscCoapStopDiscovery();
    EXPECT_EQ(ret, SOFTBUS_OK);

    testOption.freq = LOW - 1;
    ret = DiscCoapStartDiscovery(&testOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL);

    testOption.mode = ACTIVE_DISCOVERY;
    ret = DiscCoapStartDiscovery(&testOption);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_START_DISCOVER_FAIL);

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

/*
 * @tc.name: TestDiscCoapAdapterFound002
 * @tc.desc: Test DiscOnDeviceFound should reach the branch when given valid NSTACKX_DeviceInfo and DeviceCount
 *           when DiscCoapRegisterCb was given vaild and nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterFound002, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    NSTACKX_DeviceInfo testDeviceList;
    uint32_t testDeviceCount = 1;
    testDeviceList.update = 1;
    testDeviceList.mode = PUBLISH_MODE_PROACTIVE;
    ret = strcpy_s(testDeviceList.deviceId, sizeof(testDeviceList.deviceId), "{\"UDID\":\"abcde\"}");
    EXPECT_EQ(ret, EOK);
    ret = strcpy_s(testDeviceList.reservedInfo, sizeof(testDeviceList.reservedInfo), "{\"version\":\"1.0.0\"}");
    EXPECT_EQ(ret, EOK);
    g_discInnerCb.OnDeviceFound = OnDeviceFoundTest;
    ret = DiscCoapRegisterCb(&g_discInnerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    OnDeviceFound(&testDeviceList, testDeviceCount);
    EXPECT_EQ(g_testAddtions.medium, COAP);

    g_discInnerCb.OnDeviceFound = nullptr;
    ret = DiscCoapRegisterCb(&g_discInnerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    g_testAddtions.medium = AUTO;
    OnDeviceFound(&testDeviceList, testDeviceCount);
    EXPECT_EQ(g_testAddtions.medium, AUTO);

    ret = DiscCoapRegisterCb(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    g_testAddtions.medium = AUTO;
    OnDeviceFound(&testDeviceList, testDeviceCount);
    EXPECT_EQ(g_testAddtions.medium, AUTO);
}

/*
 * @tc.name: TestDiscCoapAdapterParseResInfo001
 * @tc.desc: Test DiscParseReservedInfo should return SOFTBUS_OK when given Json NSTACKX_DeviceInfo.reservedInfo,
 *           should return SOFTBUS_PARSE_JSON_ERR when given non-Json format NSTACKX_DeviceInfo.reservedInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterParseResInfo001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
	
    NSTACKX_DeviceInfo testNstackxDevice;
    DeviceInfo testDevice;
    ret = strcpy_s(testNstackxDevice.reservedInfo, sizeof(testNstackxDevice.reservedInfo), "{\"version\":\"1.0.0\"}");
    EXPECT_EQ(ret, EOK);
    ret = ParseReservedInfo(&testNstackxDevice, &testDevice);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = strcpy_s(testNstackxDevice.reservedInfo, sizeof(testNstackxDevice.reservedInfo), "test");
    EXPECT_EQ(ret, EOK);
    ret = ParseReservedInfo(&testNstackxDevice, &testDevice);
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
}

/*
 * @tc.name: TestDiscCoapAdapterParseResInfo002
 * @tc.desc: Test DiscParseReservedInfo should return SOFTBUS_OK when given nullptr DeviceInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterParseResInfo002, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    
    NSTACKX_DeviceInfo testNstackxDevice;
    DeviceInfo testDevice;
    ret = strcpy_s(testNstackxDevice.reservedInfo, sizeof(testNstackxDevice.reservedInfo), "{\"version\":\"1.0.0\"}");
    EXPECT_EQ(ret, EOK);
    ret = ParseReservedInfo(&testNstackxDevice, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = ParseReservedInfo(&testNstackxDevice, &testDevice);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TestDiscCoapAdapterParseDevInfo001
 * @tc.desc: Test DiscParseDiscDevInfo DeviceInfo.addr[0].type should be
 *           CONNECTION_ADDR_WLAN and CONNECTION_ADDR_ETH when given PUBLISH_MODE_PROACTIVE NSTACKX_DeviceInfo.mode,
 *           and when NSTACKX_DeviceInfo.networkName are "wlan" and "eth"
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterParseDevInfo001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    
    NSTACKX_DeviceInfo testNstackxDevice;
    DeviceInfo testDiscDevInfo;
    testNstackxDevice.mode = PUBLISH_MODE_PROACTIVE;
    ret = strcpy_s(testNstackxDevice.networkName, sizeof(testNstackxDevice.networkName), "wlan");
    EXPECT_EQ(ret, EOK);
    ParseDiscDevInfo(&testNstackxDevice, &testDiscDevInfo);
    EXPECT_EQ(testDiscDevInfo.addr[0].type, CONNECTION_ADDR_WLAN);

    ret = strcpy_s(testNstackxDevice.networkName, sizeof(testNstackxDevice.networkName), "eth");
    EXPECT_EQ(ret, EOK);
    ParseDiscDevInfo(&testNstackxDevice, &testDiscDevInfo);
    EXPECT_EQ(testDiscDevInfo.addr[0].type, CONNECTION_ADDR_ETH);
}

/*
 * @tc.name: TestDiscCoapAdapterParseDevInfo002
 * @tc.desc: Test DiscParseDiscDevInfo should return SOFTBUS_ERR when given non-Json NSTACKX_DeviceInfo.reservedInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterParseDevInfo002, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    
    NSTACKX_DeviceInfo testNstackxDevInfo {
        .deviceId = "{\"UDID\":\"abcde\"}",
        .reservedInfo = "{\"version\":\"1.0.0\"}",
        .mode = PUBLISH_MODE_PROACTIVE,
    };
    DeviceInfo testDiscDevInfo {
        .devId = "test",
    };
    ret = ParseDiscDevInfo(&testNstackxDevInfo, &testDiscDevInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = strcpy_s(testNstackxDevInfo.reservedInfo, sizeof(testNstackxDevInfo.reservedInfo), "test");
    EXPECT_EQ(ret, EOK);
    ret = ParseDiscDevInfo(&testNstackxDevInfo, &testDiscDevInfo);
    EXPECT_EQ(ret, SOFTBUS_ERR);
}

/*
 * @tc.name: TestDiscCoapAdapterParseDevInfo003
 * @tc.desc: Test DiscParseDiscDevInfo should return SOFTBUS_ERR when given NSTACKX_DISCOVERY_TYPE_PASSIVE,
 *           should return SOFTBUS_OK when given NSTACKX_DISCOVERY_TYPE_ACTIVE NSTACKX_DeviceInfo.discoveryType,
 *           should return SOFTBUS_OK when given PUBLISH_MODE_PROACTIVE NSTACKX_DeviceInfo.mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterParseDevInfo003, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    
    NSTACKX_DeviceInfo testNstackxDevInfo {
        .deviceId = "{\"UDID\":\"abcde\"}",
        .reservedInfo = "{\"version\":\"1.0.0\"}",
        .mode = DEFAULT_MODE,
        .discoveryType = NSTACKX_DISCOVERY_TYPE_PASSIVE,
    };
    DeviceInfo testDiscDevInfo;
    ret = ParseDiscDevInfo(&testNstackxDevInfo, &testDiscDevInfo);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    testNstackxDevInfo.discoveryType = NSTACKX_DISCOVERY_TYPE_ACTIVE;
    ret = ParseDiscDevInfo(&testNstackxDevInfo, &testDiscDevInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testNstackxDevInfo.mode = PUBLISH_MODE_PROACTIVE;
    ret = ParseDiscDevInfo(&testNstackxDevInfo, &testDiscDevInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TestDiscCoapAdapterRegisterCb001
 * @tc.desc: Test DiscCoapRegisterCb should return SOFTBUS_OK when given valid,
 *           should return SOFTBUS_INVALID_PARAM when given nullptr DiscInnerCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterRegisterCb001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = DiscCoapRegisterCb(&g_discInnerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = DiscCoapRegisterCb(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
}
