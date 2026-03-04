/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "disc_nstackx_adapter.h"
#include "disc_nstackx_adapter_mock.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using testing::Return;

static bool isDeviceFound = false;
namespace OHOS {

class DiscNstackxAdapterTest : public testing::Test {
public:
    DiscNstackxAdapterTest() { }
    ~DiscNstackxAdapterTest() { }
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

static constexpr uint32_t OSD_CAPABILITY = 128;

static NSTACKX_DeviceInfo g_testNstackxInfo = {
    .deviceId = "{UDID:123456789012345}",
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
    .reservedInfo = "reserved"
};

static void OnDeviceFoundTest(const DeviceInfo *device, const InnerDeviceInfoAddtions *additions)
{
    (void)device;
    (void)additions;
    DISC_LOGI(DISC_TEST, "OnDeviceFoundTest in");
    isDeviceFound = true;
}

static DiscInnerCallback g_discInnerCb = {
    .OnDeviceFound = OnDeviceFoundTest,
};

/*
 * @tc.name: DiscCoapAdapterInit001
 * @tc.desc: Test DiscNstackxInit should return SOFTBUS_OK when repeat init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, DiscCoapAdapterInit001, TestSize.Level1)
{
    DiscNstackxDeinit();
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    // repeat init
    ret = DiscNstackxInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: DiscCoapAdapterDeInit001
 * @tc.desc: Test DiscNstackxInit should return SOFTBUS_OK after repeat deinit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, DiscCoapAdapterDeInit001, TestSize.Level1)
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
 * @tc.name: DiscCoapAdapterRegCb001
 * @tc.desc: Test DiscCoapRegisterCb should return SOFTBUS_INVALID_PARAM when given invalid DiscInnerCallback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, DiscCoapAdapterRegCb001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = DiscCoapRegisterCb(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DiscCoapRegisterCb(&g_discInnerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscNstackxDeinit();
}

/*
 * @tc.name: DiscCoapAdapterRegCapa001
 * @tc.desc: Test DiscCoapRegisterCapability should return SOFTBUS_INVALID_PARAM
 *           when given invalid capabilityBitmapNum,
 *           should return SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL when given exceed max capabilityBitmapNum,
 *           should return SOFTBUS_OK when given valid capabilityBitmapNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, DiscCoapAdapterRegCapa001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    uint32_t capaBitmap[] = { 128 };
    uint32_t bitmapCount = 1;
    uint32_t invalidCount = 3;
    ret = DiscCoapRegisterCapability(0, capaBitmap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DiscCoapRegisterCapability(invalidCount, capaBitmap);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = DiscCoapRegisterCapability(bitmapCount, capaBitmap);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscNstackxDeinit();
}

/*
 * @tc.name: DiscCoapAdapterSetFilter001
 * @tc.desc: Test DiscCoapSetFilterCapability should return SOFTBUS_INVALID_PARAM
 *           when given invalid capabilityBitmapNum,
 *           should return SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL when given exceed max capabilityBitmapNum,
 *           should return SOFTBUS_OK when given valid capabilityBitmapNum
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, DiscCoapAdapterSetFilter001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    uint32_t capaBitmap[] = { 128 };
    uint32_t bitmapCount = 1;
    uint32_t invalidCount = 3;
    ret = DiscCoapSetFilterCapability(0, capaBitmap);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = DiscCoapSetFilterCapability(invalidCount, capaBitmap);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = DiscCoapSetFilterCapability(bitmapCount, capaBitmap);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscNstackxDeinit();
}

/*
 * @tc.name: DiscCoapRegisterServiceData001
 * @tc.desc: Test DiscCoapRegisterServiceData should return SOFTBUS_OK when DiscNstackxInit has started
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, DiscCoapRegisterServiceData001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    PublishOption option = {
        .freq = LOW,
    };
    ret = DiscCoapRegisterServiceData(&option, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscNstackxDeinit();
}

/*
 * @tc.name: DiscCoapRegisterCapabilityData001
 * @tc.desc: Test DiscCoapRegisterCapabilityData should return SOFTBUS_OK when DiscNstackxInit has started
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, DiscCoapRegisterCapabilityData001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    const unsigned char capData[] = "{\"devHash\":\"1122334455667788990011223344556677889900\",\"nbVer\":9,"
                          "\"nick\":\"Mark\",\"OH\":1,\"abl\":2,\"icon\":0}";
    uint32_t len = strlen((const char *)capData);

    ret = DiscCoapRegisterCapabilityData(nullptr, len, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = DiscCoapRegisterCapabilityData(capData, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);

    uint32_t capability = (1 << HICALL_CAPABILITY_BITMAP);
    ret = DiscCoapRegisterCapabilityData(capData, len, capability);
    EXPECT_EQ(ret, SOFTBUS_OK);

    capability = (1 << PROFILE_CAPABILITY_BITMAP);
    ret = DiscCoapRegisterCapabilityData(capData, len, capability);
    EXPECT_EQ(ret, SOFTBUS_OK);

    capability = (1 << HOMEVISIONPIC_CAPABILITY_BITMAP);
    ret = DiscCoapRegisterCapabilityData(capData, len, capability);
    EXPECT_EQ(ret, SOFTBUS_OK);

    capability = (1 << CASTPLUS_CAPABILITY_BITMAP);
    ret = DiscCoapRegisterCapabilityData(capData, len, capability);
    EXPECT_EQ(ret, SOFTBUS_OK);

    capability = (1 << AA_CAPABILITY_BITMAP);
    ret = DiscCoapRegisterCapabilityData(capData, len, capability);
    EXPECT_EQ(ret, SOFTBUS_OK);

    capability = (1 << DVKIT_CAPABILITY_BITMAP);
    ret = DiscCoapRegisterCapabilityData(capData, len, capability);
    EXPECT_EQ(ret, SOFTBUS_OK);

    capability = (1 << DDMP_CAPABILITY_BITMAP);
    ret = DiscCoapRegisterCapabilityData(capData, len, capability);
    EXPECT_EQ(ret, SOFTBUS_OK);

    capability = (1 << OSD_CAPABILITY_BITMAP);
    ret = DiscCoapRegisterCapabilityData(capData, len, capability);
    EXPECT_EQ(ret, SOFTBUS_OK);

    capability = (1 << SHARE_CAPABILITY_BITMAP);
    ret = DiscCoapRegisterCapabilityData(capData, len, capability);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/*
 * @tc.name: DiscCoapModifyNstackThread001
 * @tc.desc: Test DiscCoapModifyNstackThread
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, DiscCoapModifyNstackThread001, TestSize.Level1)
{
    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    DiscCoapModifyNstackThread(LINK_STATUS_UP, WLAN_IF);

    DiscCoapRecordLinkStatus(LINK_STATUS_UP, WLAN_IF);
    DiscCoapModifyNstackThread(LINK_STATUS_UP, WLAN_IF);

    DiscCoapRecordLinkStatus(LINK_STATUS_UP, USB_IF);
    DiscCoapModifyNstackThread(LINK_STATUS_UP, USB_IF);

    DiscCoapModifyNstackThread(LINK_STATUS_DOWN, USB_IF);

    DiscCoapRecordLinkStatus(LINK_STATUS_DOWN, USB_IF);
    DiscCoapModifyNstackThread(LINK_STATUS_DOWN, USB_IF);

    DiscCoapRecordLinkStatus(LINK_STATUS_DOWN, WLAN_IF);
    DiscCoapModifyNstackThread(LINK_STATUS_DOWN, WLAN_IF);

    DiscNstackxDeinit();
}

/*
 * @tc.name: DiscCoapSendRsp001
 * @tc.desc: Test DiscCoapSendRsp should return SOFTBUS_OK when linkup
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, DiscCoapSendRsp001, TestSize.Level1)
{
    AdapterMock adapterMock;
    EXPECT_CALL(adapterMock, LnnGetLocalStrInfoByIfnameIdx).
        WillRepeatedly(AdapterMock::ActionOfLnnGetLocalStrInfoByIfnameIdx);

    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    ret = DiscCoapSendRsp(nullptr, 0, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    DeviceInfo devInfo = {};
    ret = DiscCoapSendRsp(&devInfo, 0, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    DiscCoapRecordLinkStatus(LINK_STATUS_UP, WLAN_IF);
    strcpy_s(devInfo.addr[0].info.ip.ip, IP_STR_MAX_LEN, "test");
    ret = DiscCoapSendRsp(&devInfo, 0, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    strcpy_s(devInfo.addr[0].info.ip.ip, IP_STR_MAX_LEN, "fe80::1111:2222:3333:4444");
    ret = DiscCoapSendRsp(&devInfo, 0, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    DiscCoapRecordLinkStatus(LINK_STATUS_DOWN, WLAN_IF);
    DiscCoapRecordLinkStatus(LINK_STATUS_UP, USB_IF);
    ret = DiscCoapSendRsp(&devInfo, 0, false);
    EXPECT_EQ(ret, SOFTBUS_OK);

    strcpy_s(devInfo.addr[0].info.ip.ip, IP_STR_MAX_LEN, "192.168.1.1");
    ret = DiscCoapSendRsp(&devInfo, 0, false);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    DiscNstackxDeinit();
}

/*
 * @tc.name: DiscCoapAdapterFound001
 * @tc.desc: Test OnDeviceFound should be called when given invalid NSTACKX_DeviceInfo and deviceCount,
 *           should be called when given valid NSTACKX_DeviceInfo and deviceCount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, DiscCoapAdapterFound001, TestSize.Level1)
{
    AdapterMock adapterMock;
    EXPECT_CALL(adapterMock, NSTACKX_Init).WillRepeatedly(AdapterMock::ActionOfNstackInit);

    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = DiscCoapRegisterCb(&g_discInnerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    adapterMock.InjectDeviceFoundEvent(nullptr, 0);
    EXPECT_TRUE(!isDeviceFound);

    adapterMock.InjectDeviceFoundEvent(&g_testNstackxInfo, 0);
    EXPECT_TRUE(!isDeviceFound);

    g_testNstackxInfo.update = 0;
    adapterMock.InjectDeviceFoundEvent(&g_testNstackxInfo, 1);
    EXPECT_TRUE(!isDeviceFound);

    g_testNstackxInfo.update = 1;
    g_testNstackxInfo.discoveryType = NSTACKX_DISCOVERY_TYPE_PASSIVE;
    g_testNstackxInfo.mode = DISCOVER_MODE;
    adapterMock.InjectDeviceFoundEvent(&g_testNstackxInfo, 1);
    EXPECT_TRUE(!isDeviceFound);

    g_testNstackxInfo.mode = PUBLISH_MODE_PROACTIVE;
    adapterMock.InjectDeviceFoundEvent(&g_testNstackxInfo, 1);
    EXPECT_TRUE(!isDeviceFound);

    g_testNstackxInfo.discoveryType = NSTACKX_DISCOVERY_TYPE_ACTIVE;
    adapterMock.InjectDeviceFoundEvent(&g_testNstackxInfo, 1);
    EXPECT_TRUE(!isDeviceFound);
}

/*
 * @tc.name: DiscCoapAdapterFound002
 * @tc.desc: Test DiscOnDeviceFound should reach the branch when given valid NSTACKX_DeviceInfo and DeviceCount
 *           when DiscCoapRegisterCb was given vaild callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, DiscCoapAdapterFound002, TestSize.Level1)
{
    AdapterMock adapterMock;
    EXPECT_CALL(adapterMock, NSTACKX_Init).WillRepeatedly(AdapterMock::ActionOfNstackInit);

    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);

    NSTACKX_DeviceInfo testDeviceList;
    testDeviceList.update = 1;
    testDeviceList.mode = PUBLISH_MODE_PROACTIVE;
    ret = strcpy_s(testDeviceList.deviceId, sizeof(testDeviceList.deviceId), "{\"UDID\":\"abcde\"}");
    EXPECT_EQ(ret, EOK);
    ret = strcpy_s(testDeviceList.reservedInfo, sizeof(testDeviceList.reservedInfo), "{\"version\":\"1.0.0\"}");
    EXPECT_EQ(ret, EOK);

    g_discInnerCb.OnDeviceFound = nullptr;
    ret = DiscCoapRegisterCb(&g_discInnerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    adapterMock.InjectDeviceFoundEvent(&testDeviceList, 1);
    EXPECT_TRUE(!isDeviceFound);

    g_discInnerCb.OnDeviceFound = OnDeviceFoundTest;
    ret = DiscCoapRegisterCb(&g_discInnerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);
    adapterMock.InjectDeviceFoundEvent(&testDeviceList, 1);
    EXPECT_TRUE(isDeviceFound);
}

/*
 * @tc.name: DiscCoapAdapterFound003
 * @tc.desc: Test DiscOnDeviceFound should reach the branch when given different network
 *           when DiscCoapRegisterCb was given vaild callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, DiscCoapAdapterFound003, TestSize.Level1)
{
    AdapterMock adapterMock;
    EXPECT_CALL(adapterMock, NSTACKX_Init).WillRepeatedly(AdapterMock::ActionOfNstackInit);

    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = DiscCoapRegisterCb(&g_discInnerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NSTACKX_DeviceInfo testDeviceList;
    testDeviceList.update = 1;
    ret = strcpy_s(testDeviceList.deviceId, sizeof(testDeviceList.deviceId), "{\"UDID\":\"abcde\"}");
    EXPECT_EQ(ret, EOK);
    ret = strcpy_s(testDeviceList.reservedInfo, sizeof(testDeviceList.reservedInfo), "{\"version\":\"1.0.0\"}");
    EXPECT_EQ(ret, EOK);

    ret = strcpy_s(testDeviceList.networkName, sizeof(testDeviceList.networkName), "wlan0");
    EXPECT_EQ(ret, EOK);
    adapterMock.InjectDeviceFoundEvent(&testDeviceList, 1);
    EXPECT_TRUE(isDeviceFound);

    ret = strcpy_s(testDeviceList.networkName, sizeof(testDeviceList.networkName), "ncm0");
    EXPECT_EQ(ret, EOK);
    adapterMock.InjectDeviceFoundEvent(&testDeviceList, 1);
    EXPECT_TRUE(isDeviceFound);

    ret = strcpy_s(testDeviceList.networkName, sizeof(testDeviceList.networkName), "wwan0");
    EXPECT_EQ(ret, EOK);
    adapterMock.InjectDeviceFoundEvent(&testDeviceList, 1);
    EXPECT_TRUE(isDeviceFound);

    ret = strcpy_s(testDeviceList.networkName, sizeof(testDeviceList.networkName), "eth0");
    EXPECT_EQ(ret, EOK);
    adapterMock.InjectDeviceFoundEvent(&testDeviceList, 1);
    EXPECT_TRUE(isDeviceFound);

    ret = strcpy_s(testDeviceList.networkName, sizeof(testDeviceList.networkName), "net");
    EXPECT_EQ(ret, EOK);
    adapterMock.InjectDeviceFoundEvent(&testDeviceList, 1);
    EXPECT_TRUE(isDeviceFound);
}

/*
 * @tc.name: DiscCoapAdapterParseResInfo001
 * @tc.desc: Test DiscParseReservedInfo when given different NSTACKX_DeviceInfo.reservedInfo,
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscNstackxAdapterTest, DiscCoapAdapterParseResInfo001, TestSize.Level1)
{
    AdapterMock adapterMock;
    EXPECT_CALL(adapterMock, NSTACKX_Init).WillRepeatedly(AdapterMock::ActionOfNstackInit);

    int32_t ret = DiscNstackxInit();
    ASSERT_EQ(ret, SOFTBUS_OK);
    ret = DiscCoapRegisterCb(&g_discInnerCb);
    EXPECT_EQ(ret, SOFTBUS_OK);

    NSTACKX_DeviceInfo testDeviceList;
    testDeviceList.update = 1;
    ret = strcpy_s(testDeviceList.deviceId, sizeof(testDeviceList.deviceId), "test");
    EXPECT_EQ(ret, EOK);
    adapterMock.InjectDeviceFoundEvent(&testDeviceList, 1);
    EXPECT_TRUE(isDeviceFound);

    ret = strcpy_s(testDeviceList.deviceId, sizeof(testDeviceList.deviceId), "{\"UDID\":\"abcde\"}");
    EXPECT_EQ(ret, EOK);
    adapterMock.InjectDeviceFoundEvent(&testDeviceList, 1);
    EXPECT_TRUE(isDeviceFound);

    ret = strcpy_s(testDeviceList.reservedInfo, sizeof(testDeviceList.reservedInfo), "test");
    EXPECT_EQ(ret, EOK);
    adapterMock.InjectDeviceFoundEvent(&testDeviceList, 1);
    EXPECT_TRUE(isDeviceFound);

    ret = strcpy_s(testDeviceList.reservedInfo, sizeof(testDeviceList.reservedInfo), "{\"version\":\"1.0.0\"}");
    EXPECT_EQ(ret, EOK);
    adapterMock.InjectDeviceFoundEvent(&testDeviceList, 1);
    EXPECT_TRUE(isDeviceFound);

    ret = strcpy_s(testDeviceList.reservedInfo, sizeof(testDeviceList.reservedInfo),
        "{\"version\":\"1.0.0\",\"bData\":{\"nickname\":\"Jane\"}}");
    EXPECT_EQ(ret, EOK);
    adapterMock.InjectDeviceFoundEvent(&testDeviceList, 1);
    EXPECT_TRUE(isDeviceFound);
}
} // namespace OHOS