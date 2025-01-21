/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "disc_log.h"
#include "disc_manager.h"
#include "disc_nstackx_adapter.c"
#include "disc_nstackx_adapter.h"
#include "lnn_local_net_ledger.h"
#include "nstackx.h"
#include "nstackx_error.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

using namespace testing::ext;

#define NSTACKX_EFAILED (-1)
namespace OHOS {

static bool isDeviceFound = false;
class DiscNstackxAdapterTest : public testing::Test {
public:
    DiscNstackxAdapterTest() { }
    ~DiscNstackxAdapterTest() { }
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

static InnerDeviceInfoAddtions g_testAddtions = { .medium = AUTO };

static void OnDeviceFoundTest(const DeviceInfo *device, const InnerDeviceInfoAddtions *additions)
{
    (void)device;
    (void)additions;
    DISC_LOGI(DISC_TEST, "OnDeviceFoundTest in");
    isDeviceFound = true;
    g_testAddtions.medium = additions->medium;
}

static DiscInnerCallback g_discInnerCb = { .OnDeviceFound = OnDeviceFoundTest };

static constexpr uint32_t OSD_CAPABILITY = 128;

static NSTACKX_DeviceInfo g_testNstackxInfo = { .deviceId = "{UDID:123456789012345}",
    .deviceName = "OpenHarmonyDevice",
    .capabilityBitmapNum = 1,
    .capabilityBitmap = { OSD_CAPABILITY },
    .deviceType = 0,
    .mode = DISCOVER_MODE,
    .update = 1,
    .reserved = 0,
    .networkName = "wlan0",
    .discoveryType = NSTACKX_DISCOVERY_TYPE_ACTIVE,
    .businessType = NSTACKX_BUSINESS_TYPE_NULL,
    .reservedInfo = "reserved" };

/*
 * @tc.name: TestDiscCoapAdapterInit001
 * @tc.desc: Test DiscNstackxInit should return SOFTBUS_OK when repeat init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterInit001, TestSize.Level1)
{
    DiscNstackxDeinit();
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    // repeat init
    ret = DiscNstackxInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TestDiscCoapAdapterDeInit001
 * @tc.desc: Test DiscNstackxInit should return SOFTBUS_OK after repeat deinit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterDeInit001, TestSize.Level1)
{
    DiscNstackxDeinit();
    DiscNstackxDeinit();
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    // repeat init
    ret = DiscNstackxInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscNstackxDeinit();
}

/*
 * @tc.name: TestDiscCoapModifyNstackThread001
 * @tc.desc: Test start discovery.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapModifyNstackThread001, TestSize.Level1)
{
    DiscCoapModifyNstackThread(LINK_STATUS_DOWN);
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    DiscCoapOption testCoapOption = {
        .freq = LOW,
        .mode = ACTIVE_PUBLISH
    };
    ret = DiscCoapStartDiscovery(&testCoapOption);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_FOUND);
    ret = DiscCoapStopDiscovery();
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL);

    DiscCoapModifyNstackThread(LINK_STATUS_UP);
    ret = DiscCoapStopDiscovery();
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscNstackxDeinit();
}

/*
 * @tc.name: TestDiscCoapModifyNstackThread002
 * @tc.desc: Test send coap rsp.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapModifyNstackThread002, TestSize.Level1)
{
    DiscCoapModifyNstackThread(LINK_STATUS_DOWN);
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    DeviceInfo testDiscDevInfo {
        .devId = "test",
    };
    uint8_t bType = 0;
    ret = LnnInitLocalLedger();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DiscCoapSendRsp(&testDiscDevInfo, bType);
    EXPECT_EQ(ret, NSTACKX_EFAILED);

    DiscCoapModifyNstackThread(LINK_STATUS_UP);
    ret = DiscCoapSendRsp(&testDiscDevInfo, bType);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscNstackxDeinit();
    LnnDeinitLocalLedger();
}

/*
 * @tc.name: TestDiscCoapAdapterRegCb001
 * @tc.desc: Test DiscCoapRegisterCb should return SOFTBUS_INVALID_PARAM when given invalid DiscInnerCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterRegCb001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = DiscCoapRegisterCb(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DiscCoapRegisterCb(&g_discInnerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TestDiscCoapAdapterRegCapa001
 * @tc.desc: Test DiscCoapRegisterCapability should return SOFTBUS_INVALID_PARAM
 *           when given invalid capabilityBitmapNum,
 *           should return SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL when given exceed max capabilityBitmapNum,
 *           should return SOFTBUS_OK when given valid capabilityBitmapNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterRegCapa001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    uint32_t capaBitmap[] = { 128 };
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
 * @tc.name: TestDiscCoapAdapterSetFilter001
 * @tc.desc: Test DiscCoapSetFilterCapability should return SOFTBUS_INVALID_PARAM
 *           when given invalid capabilityBitmapNum,
 *           should return SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL when given exceed max capabilityBitmapNum,
 *           should return SOFTBUS_OK when given valid capabilityBitmapNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterSetFilter001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    uint32_t capaBitmap[] = { 128 };
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
 * @tc.name: TestDiscCoapAdapterRegData001
 * @tc.desc: Test DiscCoapRegisterServiceData should return SOFTBUS_OK when DiscNstackxInit has started
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterRegData001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    PublishOption option = {
        .freq = LOW,
    };
    ret = DiscCoapRegisterServiceData(&option, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

#ifdef DSOFTBUS_FEATURE_DISC_SHARE_COAP
/*
 * @tc.name: TestDiscCoapAdapterRegCapaData001
 * @tc.desc: Test DiscCoapRegisterCapabilityData should return SOFTBUS_OK when DiscNstackxInit has started
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterRegCapaData001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    const unsigned char capabilityData[] = "test";
    uint32_t dataLen = 4;
    uint32_t capability = 1;

    ret = DiscCoapRegisterCapabilityData(nullptr, dataLen, capability);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DiscCoapRegisterCapabilityData(capabilityData, 0, capability);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = DiscCoapRegisterCapabilityData(capabilityData, dataLen, capability);
    EXPECT_EQ(ret, SOFTBUS_OK);
}
#endif /* DSOFTBUS_FEATURE_DISC_SHARE_COAP */

/*
 * @tc.name: TestDiscCoapAdapterStartDisc001
 * @tc.desc: Test DiscCoapStartDiscovery should return SOFTBUS_INVALID_PARAM when given invalid DiscCoapOption
 *           should return SOFTBUS_OK when given valid DiscCoapOption
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterStartDisc001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    DiscCoapModifyNstackThread(LINK_STATUS_UP);

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
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_FOUND);
    ret = DiscCoapStopDiscovery();
    EXPECT_EQ(ret, SOFTBUS_OK);

    testCoapOption.mode = ACTIVE_DISCOVERY;
    ret = DiscCoapStartDiscovery(&testCoapOption);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_FOUND);
    ret = DiscCoapStopDiscovery();
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscNstackxDeinit();
    ret = DiscCoapStopDiscovery();
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL);
}

/*
 * @tc.name: TestDiscCoapAdapterStartDisc002
 * @tc.desc: Test DiscCoapStartDiscovery should return SOFTBUS_OK when given valid DiscCoapOption.freq,
 *           should return not SOFTBUS_OK when given invalid DiscCoapOption.freq
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterStartDisc002, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    DiscCoapModifyNstackThread(LINK_STATUS_UP);

    DiscCoapOption testOption = { 0 };
    testOption.freq = LOW;
    testOption.mode = ACTIVE_PUBLISH;

    ret = DiscCoapStartDiscovery(&testOption);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_FOUND);
    ret = DiscCoapStopDiscovery();
    EXPECT_EQ(ret, SOFTBUS_OK);

    testOption.freq = MID;
    ret = DiscCoapStartDiscovery(&testOption);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_FOUND);
    ret = DiscCoapStopDiscovery();
    EXPECT_EQ(ret, SOFTBUS_OK);

    testOption.freq = HIGH;
    ret = DiscCoapStartDiscovery(&testOption);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_FOUND);
    ret = DiscCoapStopDiscovery();
    EXPECT_EQ(ret, SOFTBUS_OK);

    testOption.freq = SUPER_HIGH;
    ret = DiscCoapStartDiscovery(&testOption);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_FOUND);
    ret = DiscCoapStopDiscovery();
    EXPECT_EQ(ret, SOFTBUS_OK);

    testOption.freq = EXTREME_HIGH;
    ret = DiscCoapStartDiscovery(&testOption);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_FOUND);
    ret = DiscCoapStopDiscovery();
    EXPECT_EQ(ret, SOFTBUS_OK);

    testOption.freq = LOW - 1;
    ret = DiscCoapStartDiscovery(&testOption);
    EXPECT_NE(ret, SOFTBUS_OK);
    testOption.freq = FREQ_BUTT;
    ret = DiscCoapStartDiscovery(&testOption);
    EXPECT_NE(ret, SOFTBUS_OK);

    DiscNstackxDeinit();
    ret = DiscCoapStopDiscovery();
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL);
}

/*
 * @tc.name: TestDiscCoapAdapterUpdate001
 * @tc.desc: Test DiscCoapUpdateLocalIp should return SOFTBUS_OK when given LINK_STATUS_UP LinkStatus,
 *           should return SOFTBUS_OK when given LINK_STATUS_DOWN LinkStatus,
 *           should return SOFTBUS_OK when given invalid LinkStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterUpdate001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    DiscCoapOption testCoapOption = {
        .freq = LOW,
        .mode = ACTIVE_DISCOVERY
    };
    DiscCoapUpdateLocalIp(LINK_STATUS_UP);
    DiscCoapUpdateDevName();
    ret = DiscCoapStartDiscovery(&testCoapOption);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_FOUND);

    DiscCoapUpdateLocalIp(LINK_STATUS_DOWN);
    ret = DiscCoapStartDiscovery(&testCoapOption);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_FOUND);

    DiscCoapUpdateLocalIp((LinkStatus)(-1));
    ret = DiscCoapStartDiscovery(&testCoapOption);
    EXPECT_EQ(ret, SOFTBUS_NETWORK_NOT_FOUND);
}

/*
 * @tc.name: TestDiscCoapAdapterFound001
 * @tc.desc: Test OnDeviceFound should be called when given invalid NSTACKX_DeviceInfo and deviceCount,
 *           should be called when given valid NSTACKX_DeviceInfo and deviceCount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterFound001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = DiscCoapRegisterCb(&g_discInnerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    OnDeviceFound(&g_testNstackxInfo, 0);
    ASSERT_TRUE(!isDeviceFound);

    OnDeviceFound(nullptr, 1);
    ASSERT_TRUE(!isDeviceFound);

    g_testNstackxInfo.update = 0;
    OnDeviceFound(&g_testNstackxInfo, 1);
    ASSERT_TRUE(!isDeviceFound);
    g_testNstackxInfo.update = 1;

    g_testNstackxInfo.discoveryType = NSTACKX_DISCOVERY_TYPE_PASSIVE;
    g_testNstackxInfo.mode = DISCOVER_MODE;
    OnDeviceFound(&g_testNstackxInfo, 1);
    ASSERT_TRUE(!isDeviceFound);

    g_testNstackxInfo.mode = PUBLISH_MODE_PROACTIVE;
    OnDeviceFound(&g_testNstackxInfo, 1);
    ASSERT_TRUE(!isDeviceFound);

    g_testNstackxInfo.discoveryType = NSTACKX_DISCOVERY_TYPE_ACTIVE;
    OnDeviceFound(&g_testNstackxInfo, 1);
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
    char nickname[DISC_MAX_NICKNAME_LEN] = { 0 };
    ret = strcpy_s(testNstackxDevice.reservedInfo, sizeof(testNstackxDevice.reservedInfo), "{\"version\":\"1.0.0\"}");
    EXPECT_EQ(ret, EOK);
    ret = ParseReservedInfo(&testNstackxDevice, &testDevice, nickname);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = strcpy_s(testNstackxDevice.reservedInfo, sizeof(testNstackxDevice.reservedInfo), "test");
    EXPECT_EQ(ret, EOK);
    ret = ParseReservedInfo(&testNstackxDevice, &testDevice, nickname);
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
    char nickname[DISC_MAX_NICKNAME_LEN] = { 0 };
    ret = strcpy_s(testNstackxDevice.reservedInfo, sizeof(testNstackxDevice.reservedInfo),
        "{\"version\":\"1.0.0\",\"bData\":{\"nickname\":\"Jane\"}}");
    EXPECT_EQ(ret, EOK);
    ret = ParseReservedInfo(&testNstackxDevice, &testDevice, nickname);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = ParseReservedInfo(&testNstackxDevice, &testDevice, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: TestDiscCoapAdapterParseResInfo003
 * @tc.desc: Test DiscParseReservedInfo should return SOFTBUS_OK when given nickname or not
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterParseResInfo003, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    NSTACKX_DeviceInfo testNstackxDevice;
    DeviceInfo testDevice;
    char nickname[DISC_MAX_NICKNAME_LEN] = { 0 };
    ret = strcpy_s(testNstackxDevice.reservedInfo, sizeof(testNstackxDevice.reservedInfo), "{\"version\":\"1.0.0\"}");
    EXPECT_EQ(ret, EOK);
    ret = ParseReservedInfo(&testNstackxDevice, nullptr, nickname);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = ParseReservedInfo(&testNstackxDevice, &testDevice, nickname);
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
    LnnInitLocalLedger();
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
    LnnDeinitLocalLedger();
}

/*
 * @tc.name: TestDiscCoapAdapterParseDevInfo002
 * @tc.desc: Test DiscParseDiscDevInfo should return SOFTBUS_PARSE_JSON_ERR
 *           when given non-Json NSTACKX_DeviceInfo.reservedInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterParseDevInfo002, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    LnnInitLocalLedger();
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
    EXPECT_EQ(ret, SOFTBUS_PARSE_JSON_ERR);
    LnnDeinitLocalLedger();
}

/*
 * @tc.name: TestDiscCoapAdapterParseDevInfo003
 * @tc.desc: Test DiscParseDiscDevInfo should return SOFTBUS_OK
 *           when given NSTACKX_DISCOVERY_TYPE_ACTIVE NSTACKX_DeviceInfo.discoveryType,
 *           should return SOFTBUS_OK when given PUBLISH_MODE_PROACTIVE NSTACKX_DeviceInfo.mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapAdapterParseDevInfo003, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    LnnInitLocalLedger();
    ASSERT_EQ(ret, SOFTBUS_OK);
    
    NSTACKX_DeviceInfo testNstackxDevInfo {
        .deviceId = "{\"UDID\":\"abcde\"}",
        .reservedInfo = "{\"version\":\"1.0.0\"}",
        .mode = DEFAULT_MODE,
        .discoveryType = NSTACKX_DISCOVERY_TYPE_ACTIVE,
    };
    DeviceInfo testDiscDevInfo;
    ret = ParseDiscDevInfo(&testNstackxDevInfo, &testDiscDevInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    testNstackxDevInfo.mode = PUBLISH_MODE_PROACTIVE;
    ret = ParseDiscDevInfo(&testNstackxDevInfo, &testDiscDevInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);
    LnnDeinitLocalLedger();
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

/*
 * @tc.name: TestDiscCoapSendRsp001
 * @tc.desc: Test DiscCoapSendRsp should return SOFTBUS_OK when given valid,
 *           should return SOFTBUS_INVALID_PARAM when given nullptr DeviceInfo
 *           should return SOFTBUS_LOCK_ERR when localledger not init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, TestDiscCoapSendRsp001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    DiscCoapModifyNstackThread(LINK_STATUS_UP);

    DeviceInfo testDiscDevInfo {
        .devId = "test",
    };
    uint8_t bType = 0;

    ret = DiscCoapSendRsp(nullptr, bType);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DiscCoapSendRsp(&testDiscDevInfo, bType);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);

    ret = LnnInitLocalLedger();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = DiscCoapSendRsp(&testDiscDevInfo, bType);
    EXPECT_EQ(ret, SOFTBUS_OK);
    LnnDeinitLocalLedger();
}
} // namespace OHOS
