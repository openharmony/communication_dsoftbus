/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <cmath>
#include <gtest/gtest.h>

#include "disc_ble.c"
#include "disc_log.h"
#include "message_handler.h"
#include "softbus_broadcast_utils.h"
#include "softbus_error_code.h"

using namespace testing::ext;
namespace OHOS {
class DiscDistributedBleTest : public testing::Test {
public:
    DiscDistributedBleTest() { }
    ~DiscDistributedBleTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override { }
    void TearDown() override { }
};

void DiscDistributedBleTest::SetUpTestCase(void)
{
    LooperInit();
}

void DiscDistributedBleTest::TearDownTestCase(void)
{
    LooperDeinit();
}

static void TestOnDeviceFound(const DeviceInfo *device, const InnerDeviceInfoAddtions *additions)
{
    DISC_LOGI(DISC_TEST, "TestOnDeviceFound in");
    (void)device;
    (void)additions;
}

static DiscInnerCallback g_testDiscInnerCallBack = {
    .OnDeviceFound = TestOnDeviceFound,
};

static DiscoveryBleDispatcherInterface *g_testDiscBleDispatcherInterface = nullptr;

/*
 * @tc.name: TestGetNeedUpdateAdvertiser001
 * @tc.desc: Test GetNeedUpdateAdvertiser should return false when never execute UpdateInfoManager
 *           should return true/false when UpdateInfoManager's needUpdate param is true/false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscDistributedBleTest, TestGetNeedUpdateAdvertiser001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestGetNeedUpdateAdvertiser001, Start");
    g_testDiscBleDispatcherInterface = DiscSoftBusBleInit(&g_testDiscInnerCallBack);
    ASSERT_NE(g_testDiscBleDispatcherInterface, nullptr);

    int32_t adv = NON_ADV_ID;
    int32_t ret = GetNeedUpdateAdvertiser(adv);
    EXPECT_EQ(ret, false);
    UpdateInfoManager(adv, true);
    ret = GetNeedUpdateAdvertiser(adv);
    EXPECT_EQ(ret, true);
    UpdateInfoManager(adv, false);
    ret = GetNeedUpdateAdvertiser(adv);
    EXPECT_EQ(ret, false);

    adv = CON_ADV_ID;
    ret = GetNeedUpdateAdvertiser(adv);
    EXPECT_EQ(ret, false);
    UpdateInfoManager(adv, true);
    ret = GetNeedUpdateAdvertiser(adv);
    EXPECT_EQ(ret, true);
    UpdateInfoManager(adv, false);
    ret = GetNeedUpdateAdvertiser(adv);
    EXPECT_EQ(ret, false);

    DiscSoftBusBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestGetNeedUpdateAdvertiser001, End");
}

/*
 * @tc.name: TestCheckScanner001
 * @tc.desc: Test CheckScanner should return false when given 0x0 g_bleInfoManager[0],[1],[2].capBitMap[0]
 *           should return true when given 0x1 one of g_bleInfoManager[0],[1],[2].capBitMap[0]
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscDistributedBleTest, TestCheckScanner001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestCheckScanner001, Start");
    g_testDiscBleDispatcherInterface = DiscSoftBusBleInit(&g_testDiscInnerCallBack);
    ASSERT_NE(g_testDiscBleDispatcherInterface, nullptr);

    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x0;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].capBitMap[0] = 0x0;
    g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap[0] = 0x0;
    bool ret = CheckScanner();
    EXPECT_EQ(ret, false);

    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x1;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].capBitMap[0] = 0x0;
    g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap[0] = 0x0;
    ret = CheckScanner();
    EXPECT_EQ(ret, true);

    DiscSoftBusBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestCheckScanner001, End");
}

/*
 * @tc.name: TestScanFilter001
 * @tc.desc: Test ScanFilter should not return SOFTBUS_OK when given invalid reportInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscDistributedBleTest, TestScanFilter001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestScanFilter001, Start");
    g_testDiscBleDispatcherInterface = DiscSoftBusBleInit(&g_testDiscInnerCallBack);
    ASSERT_NE(g_testDiscBleDispatcherInterface, nullptr);

    BroadcastReportInfo reportInfo = { 0 };

    reportInfo.dataStatus = SOFTBUS_BC_DATA_INCOMPLETE_MORE_TO_COME;
    int32_t ret = ScanFilter(&reportInfo);
    EXPECT_NE(ret, SOFTBUS_OK);

    // when not advData != NULL
    reportInfo.dataStatus = SOFTBUS_BC_DATA_COMPLETE;
    ret = ScanFilter(&reportInfo);
    EXPECT_NE(ret, SOFTBUS_OK);

    // when not advLen >= POS_TLV
    uint8_t payload[POS_TLV] = { 0 };
    reportInfo.packet.bcData.payload = &payload[0];
    reportInfo.packet.bcData.payloadLen = POS_TLV - 1;
    ret = ScanFilter(&reportInfo);
    EXPECT_NE(ret, SOFTBUS_OK);

    // when not rspData != NULL
    reportInfo.packet.bcData.payloadLen = POS_TLV;
    ret = ScanFilter(&reportInfo);
    EXPECT_NE(ret, SOFTBUS_OK);

    // when not rspLen > 0
    reportInfo.packet.rspData.payload = &payload[0];
    reportInfo.packet.rspData.payloadLen = -1;
    ret = ScanFilter(&reportInfo);
    EXPECT_NE(ret, SOFTBUS_OK);

    DiscSoftBusBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestScanFilter001, End");
}

/*
 * @tc.name: TestScanFilter002
 * @tc.desc: Test ScanFilter should not return SOFTBUS_OK when given invalid reportInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscDistributedBleTest, TestScanFilter002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestScanFilter002, Start");
    g_testDiscBleDispatcherInterface = DiscSoftBusBleInit(&g_testDiscInnerCallBack);
    ASSERT_NE(g_testDiscBleDispatcherInterface, nullptr);

    uint8_t payload[POS_TLV] = { 0 };
    BroadcastReportInfo reportInfo = {
        .dataStatus = SOFTBUS_BC_DATA_COMPLETE,
        .packet = {
            .bcData = {
                .payload = &payload[0],
                .payloadLen = POS_TLV,
            },
            .rspData = {
                .payload = &payload[0],
                .payloadLen = POS_TLV,
            },
        },
    };

    // when not reportInfo->packet.bcData.type == BC_DATA_TYPE_SERVICE
    reportInfo.packet.bcData.type = BC_DATA_TYPE_MANUFACTURER;
    int32_t ret = ScanFilter(&reportInfo);
    EXPECT_NE(ret, SOFTBUS_OK);

    // when not reportInfo->packet.bcData.id == SERVICE_UUID
    reportInfo.packet.bcData.type = BC_DATA_TYPE_SERVICE;
    reportInfo.packet.bcData.id = SERVICE_UUID + 1;
    ret = ScanFilter(&reportInfo);
    EXPECT_NE(ret, SOFTBUS_OK);

    // when not advData[POS_VERSION] == BLE_VERSION
    reportInfo.packet.bcData.id = SERVICE_UUID;
    reportInfo.packet.bcData.payload[POS_VERSION] = BLE_VERSION + 1;
    ret = ScanFilter(&reportInfo);
    EXPECT_NE(ret, SOFTBUS_OK);

    // when not reportInfo->packet.rspData.type == BC_DATA_TYPE_SERVICE
    reportInfo.packet.bcData.payload[POS_VERSION] = BLE_VERSION;
    reportInfo.packet.rspData.type = BC_DATA_TYPE_MANUFACTURER;
    ret = ScanFilter(&reportInfo);
    EXPECT_NE(ret, SOFTBUS_OK);

    // when not reportInfo->packet.rspData.id == MANU_COMPANY_ID
    reportInfo.packet.rspData.type = BC_DATA_TYPE_SERVICE;
    reportInfo.packet.rspData.id = MANU_COMPANY_ID + 1;
    ret = ScanFilter(&reportInfo);
    EXPECT_NE(ret, SOFTBUS_OK);

    DiscSoftBusBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestScanFilter002, End");
}

/*
 * @tc.name: TestScanFilter003
 * @tc.desc: Test ScanFilter should return SOFTBUS_OK when given valid reportInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscDistributedBleTest, TestScanFilter003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestScanFilter003, Start");
    g_testDiscBleDispatcherInterface = DiscSoftBusBleInit(&g_testDiscInnerCallBack);
    ASSERT_NE(g_testDiscBleDispatcherInterface, nullptr);

    uint8_t payload[POS_TLV] = { 0 };
    BroadcastReportInfo reportInfo = {
        .dataStatus = SOFTBUS_BC_DATA_COMPLETE,
        .packet = {
            .bcData = {
                .payload = &payload[0],
                .payloadLen = POS_TLV,
                .type = BC_DATA_TYPE_SERVICE,
                .id = SERVICE_UUID,
            },
            .rspData = {
                .payload = &payload[0],
                .payloadLen = POS_TLV,
                .type = BC_DATA_TYPE_MANUFACTURER,
                .id = MANU_COMPANY_ID,
            },
        },
    };
    reportInfo.packet.bcData.payload[POS_VERSION] = BLE_VERSION;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x1;

    int32_t ret = ScanFilter(&reportInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscSoftBusBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestScanFilter003, End");
}

/*
 * @tc.name: TestProcessHwHashAccout001
 * @tc.desc: Test ProcessHwHashAccout should return true when given 0x1 testFoundInfo.capabilityBitmap[0] and
 *           given false g_bleInfoManager[2],[3].isSameAccount[0]
 *           should return false when given true one of g_bleInfoManager[2],[3].isSameAccount[0]
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscDistributedBleTest, TestProcessHwHashAccout001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestProcessHwHashAccout001, Start");
    g_testDiscBleDispatcherInterface = DiscSoftBusBleInit(&g_testDiscInnerCallBack);
    ASSERT_NE(g_testDiscBleDispatcherInterface, nullptr);

    DeviceInfo testFoundInfo = { { 0 } };
    testFoundInfo.capabilityBitmap[0] = 0x1;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].isSameAccount[0] = false;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].isSameAccount[0] = false;
    bool ret = ProcessHashAccount(&testFoundInfo);
    EXPECT_EQ(ret, true);

    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].isSameAccount[0] = true;
    ret = ProcessHashAccount(&testFoundInfo);
    EXPECT_EQ(ret, false);

    DiscSoftBusBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestProcessHwHashAccout001, End");
}

/*
 * @tc.name: TestRangeDevice001
 * @tc.desc: Test RangeDevice foundInfoTest.range should return -1 when given SOFTBUS_ILLEGAL_BLE_POWER powerTest
 *           should return 0 when given not SOFTBUS_ILLEGAL_BLE_POWER powerTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscDistributedBleTest, TestRangeDevice001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestRangeDevice001, Start");
    constexpr char validRssi = static_cast<char>(-38);
    constexpr int8_t validAdvPower = -13;
    constexpr int32_t invalidRange = -1;

    DeviceInfo foundInfoTest = { .range = 0 };
    int32_t ret = RangeDevice(&foundInfoTest, validRssi, validAdvPower);
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NE(foundInfoTest.range, invalidRange);
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestRangeDevice001, End");
}

/*
 * @tc.name: TestGetConDeviceInfo001
 * @tc.desc: Test GetConDeviceInfo should return SOFTBUS_DISCOVER_BLE_GET_DEVICE_INFO_FAIL
 *           when given 0x0 g_bleInfoManager[2].capBitMap[0]
 *           should return SOFTBUS_OK when given 0x1 g_bleInfoManager[2].capBitMap[0]
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscDistributedBleTest, TestGetConDeviceInfo001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestGetConDeviceInfo001, Start");
    g_testDiscBleDispatcherInterface = DiscSoftBusBleInit(&g_testDiscInnerCallBack);
    ASSERT_NE(g_testDiscBleDispatcherInterface, nullptr);

    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x0;
    DeviceInfo foundInfoTest;
    int32_t ret = GetConDeviceInfo(&foundInfoTest);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_BLE_GET_DEVICE_INFO_FAIL);

    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x1;
    ret = GetConDeviceInfo(&foundInfoTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscSoftBusBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestGetConDeviceInfo001, End");
}

/*
 * @tc.name: TestGetNonDeviceInfo001
 * @tc.desc: Test GetNonDeviceInfo should return SOFTBUS_DISCOVER_BLE_GET_DEVICE_INFO_FAIL
 *           when given 0x0 g_bleInfoManager[0].capBitMap[0]
 *           should return SOFTBUS_OK when given 0x1 g_bleInfoManager[0].capBitMap[0]
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscDistributedBleTest, TestGetNonDeviceInfo001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestGetNonDeviceInfo001, Start");
    g_testDiscBleDispatcherInterface = DiscSoftBusBleInit(&g_testDiscInnerCallBack);
    ASSERT_NE(g_testDiscBleDispatcherInterface, nullptr);

    DeviceInfo foundInfoTest;
    g_bleInfoManager[BLE_PUBLISH | BLE_ACTIVE].capBitMap[0] = 0x0;
    int32_t ret = GetNonDeviceInfo(&foundInfoTest);
    EXPECT_EQ(ret, SOFTBUS_DISCOVER_BLE_GET_DEVICE_INFO_FAIL);

    g_bleInfoManager[BLE_PUBLISH | BLE_ACTIVE].capBitMap[0] = 0x1;
    ret = GetNonDeviceInfo(&foundInfoTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscSoftBusBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestGetNonDeviceInfo001, End");
}

/*
 * @tc.name: TestBuildBleConfigAdvData001
 * @tc.desc: Test BuildBleConfigAdvData should return SOFTBUS_INVALID_PARAM when given invalid param
 *           should return SOFTBUS_OK when given ADV_DATA_MAX_LEN BroadcastData.dataLen
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscDistributedBleTest, TestBuildBleConfigAdvData001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestBuildBleConfigAdvData001, Start");
    g_testDiscBleDispatcherInterface = DiscSoftBusBleInit(&g_testDiscInnerCallBack);
    ASSERT_NE(g_testDiscBleDispatcherInterface, nullptr);

    BroadcastPacket broadcastPacket = {};
    BroadcastData broadcastData = {};

    broadcastData.dataLen = ADV_DATA_MAX_LEN;
    int32_t ret = BuildBleConfigAdvData(&broadcastPacket, &broadcastData);
    EXPECT_EQ(broadcastPacket.rspData.type, 0);
    EXPECT_EQ(broadcastPacket.rspData.id, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);

    broadcastData.dataLen = ADV_DATA_MAX_LEN + 1;
    ret = BuildBleConfigAdvData(&broadcastPacket, &broadcastData);
    EXPECT_EQ(broadcastPacket.rspData.type, BC_DATA_TYPE_MANUFACTURER);
    EXPECT_EQ(broadcastPacket.rspData.id, MANU_COMPANY_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscSoftBusBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestBuildBleConfigAdvData001, End");
}

/*
 * @tc.name: TestGetBroadcastData001
 * @tc.desc: Test GetBroadcastData should return SOFTBUS_OK when given CON_ADV_ID and NON_ADV_ID advId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscDistributedBleTest, TestGetBroadcastData001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestGetBroadcastData001, Start");
    g_testDiscBleDispatcherInterface = DiscSoftBusBleInit(&g_testDiscInnerCallBack);
    ASSERT_NE(g_testDiscBleDispatcherInterface, nullptr);

    int32_t advId = CON_ADV_ID;
    DeviceInfo infoTest;
    BroadcastData broadcastDataTest;
    int32_t ret = GetBroadcastData(&infoTest, advId, &broadcastDataTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    advId = NON_ADV_ID;
    ret = GetBroadcastData(&infoTest, advId, &broadcastDataTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscSoftBusBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestGetBroadcastData001, End");
}

/*
 * @tc.name: TestGetScannerParam001
 * @tc.desc: Test GetScannerParam should return SOFTBUS_OK when given valid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscDistributedBleTest, TestGetScannerParam001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestGetScannerParam001, Start");
    g_testDiscBleDispatcherInterface = DiscSoftBusBleInit(&g_testDiscInnerCallBack);
    ASSERT_NE(g_testDiscBleDispatcherInterface, nullptr);

    int32_t freq = LOW;
    BcScanParams scanParam;
    int32_t ret = GetScannerParam(freq, &scanParam);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscSoftBusBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestGetScannerParam001, End");
}

/*
 * @tc.name: TestStopScaner001
 * @tc.desc: Test StopScaner should return SOFTBUS_OK when given false g_isScanning
 *           should not return SOFTBUS_OK when given true g_isScanning and SCAN_MAX_NUM g_bleListener.scanListenerId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscDistributedBleTest, TestStopScaner001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestStopScaner001, Start");
    g_testDiscBleDispatcherInterface = DiscSoftBusBleInit(&g_testDiscInnerCallBack);
    ASSERT_NE(g_testDiscBleDispatcherInterface, nullptr);

    g_isScanning = false;
    int32_t ret = StopScaner();
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_isScanning = true;
    g_bleListener.scanListenerId = SCAN_NUM_MAX;
    ret = StopScaner();
    EXPECT_NE(ret, SOFTBUS_OK);

    DiscSoftBusBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestStopScaner001, End");
}

} // namespace OHOS
