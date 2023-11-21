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
#include "softbus_errcode.h"

using namespace testing::ext;
namespace OHOS {
class DiscDistributedBleTest : public testing::Test {
public:
    DiscDistributedBleTest()
    {}
    ~DiscDistributedBleTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override {}
    void TearDown() override {}
};

void DiscDistributedBleTest::SetUpTestCase(void)
{
    LooperInit();
}

void DiscDistributedBleTest::TearDownTestCase(void)
{
    LooperDeinit();
}

static void TestOnDeviceFound(const DeviceInfo *device, const InnerDeviceInfoAddtions *addtions)
{
    DISC_LOGI(DISC_TEST, "TestOnDeviceFound in");
    (void)device;
    (void)addtions;
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
    int ret = GetNeedUpdateAdvertiser(adv);
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
 * @tc.desc: Test ScanFilter should return SOFTBUS_ERR
 *           when given not SOFTBUS_BLE_DATA_COMPLETE testScanResultData.dataStatus
 *           should return SOFTBUS_ERR when don't suit the appointed lenth testScanResultData.advLen
 *           should return SOFTBUS_ERR when don't suit the appointed value testScanResultData.advData
 *           should return SOFTBUS_OK when given 0x1 one of g_bleInfoManager[0],[1],[2].capBitMap[0]
 *           and have correct testScanResultData
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscDistributedBleTest, TestScanFilter001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestScanFilter001, Start");
    g_testDiscBleDispatcherInterface = DiscSoftBusBleInit(&g_testDiscInnerCallBack);
    ASSERT_NE(g_testDiscBleDispatcherInterface, nullptr);

    uint8_t advDataTest[INT32_MAX_BIT_NUM];
    uint32_t advLenTest = sizeof(advDataTest);
    (void)advLenTest;
    SoftBusBleScanResult testScanResultData{
        .dataStatus = SOFTBUS_BLE_DATA_INCOMPLETE_MORE_TO_COME,
        .advLen = POS_TLV,
        .advData = advDataTest,
    };
    int32_t ret = ScanFilter(&testScanResultData);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    testScanResultData.dataStatus = SOFTBUS_BLE_DATA_COMPLETE;
    ret = ScanFilter(&testScanResultData);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    testScanResultData.advLen = POS_TLV + ADV_HEAD_LEN;
    testScanResultData.advData[POS_PACKET_LENGTH] = ADV_HEAD_LEN;
    ret = ScanFilter(&testScanResultData);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    testScanResultData.advData[POS_PACKET_LENGTH] = ADV_HEAD_LEN + RSP_HEAD_LEN - 1;
    ret = ScanFilter(&testScanResultData);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    testScanResultData.advLen = POS_PACKET_LENGTH + ADV_HEAD_LEN + RSP_HEAD_LEN + 1;
    testScanResultData.advData[POS_PACKET_LENGTH + ADV_HEAD_LEN + RSP_HEAD_LEN] = 1;
    ret = ScanFilter(&testScanResultData);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    testScanResultData.advLen = advLenTest;
    ret = ScanFilter(&testScanResultData);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    testScanResultData.advData[POS_UUID] = (uint8_t)(BLE_UUID & BYTE_MASK);
    ret = ScanFilter(&testScanResultData);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    testScanResultData.advData[POS_UUID + 1] = (uint8_t)((BLE_UUID >> BYTE_SHIFT_BIT) & BYTE_MASK);
    ret = ScanFilter(&testScanResultData);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    testScanResultData.advData[POS_VERSION + ADV_HEAD_LEN] = BLE_VERSION;
    ret = ScanFilter(&testScanResultData);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x1;
    ret = ScanFilter(&testScanResultData);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscSoftBusBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestScanFilter001, End");
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

    DeviceInfo testFoundInfo;
    (void)memset_s(&testFoundInfo, sizeof(testFoundInfo), 0, sizeof(testFoundInfo));
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
    DeviceInfo foundInfoTest;
    const char rssiTest = 's';
    int8_t powerTest = SOFTBUS_ILLEGAL_BLE_POWER;
    RangeDevice(&foundInfoTest, rssiTest, powerTest);
    EXPECT_EQ(foundInfoTest.range, -1);

    powerTest = SOFTBUS_ILLEGAL_BLE_POWER - 1;
    RangeDevice(&foundInfoTest, rssiTest, powerTest);
    EXPECT_EQ(foundInfoTest.range, 0);
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestRangeDevice001, End");
}

/*
 * @tc.name: TestGetConDeviceInfo001
 * @tc.desc: Test GetConDeviceInfo should return SOFTBUS_ERR when given 0x0 g_bleInfoManager[2].capBitMap[0]
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
    EXPECT_EQ(ret, SOFTBUS_ERR);

    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x1;
    ret = GetConDeviceInfo(&foundInfoTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscSoftBusBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestGetConDeviceInfo001, End");
}

/*
 * @tc.name: TestGetNonDeviceInfo001
 * @tc.desc: Test GetNonDeviceInfo should return SOFTBUS_ERR when given 0x0 g_bleInfoManager[0].capBitMap[0]
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
    EXPECT_EQ(ret, SOFTBUS_ERR);

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

    SoftBusBleAdvData advDataTest;
    BroadcastData broadcastDataTest;
    int32_t ret = BuildBleConfigAdvData(nullptr, &broadcastDataTest);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = BuildBleConfigAdvData(&advDataTest, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    broadcastDataTest.dataLen = ADV_DATA_MAX_LEN;
    ret = BuildBleConfigAdvData(&advDataTest, &broadcastDataTest);
    EXPECT_EQ(advDataTest.scanRspData[POS_RSP_TYPE], RSP_TYPE);
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
 * @tc.name: TestStartAdvertiser001
 * @tc.desc: Test StartAdvertiser should return SOFTBUS_OK when given true/false g_bleAdvertiser[adv].isAdvertising
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscDistributedBleTest, TestStartAdvertiser001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestStartAdvertiser001, Start");
    g_testDiscBleDispatcherInterface = DiscSoftBusBleInit(&g_testDiscInnerCallBack);
    ASSERT_NE(g_testDiscBleDispatcherInterface, nullptr);

    int32_t adv = CON_ADV_ID;
    g_bleAdvertiser[adv].isAdvertising = true;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].needUpdate = true;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].needUpdate = true;
    int32_t ret = StartAdvertiser(adv);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_bleAdvertiser[adv].isAdvertising = true;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].needUpdate = false;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].needUpdate = false;
    ret = StartAdvertiser(adv);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_bleAdvertiser[adv].isAdvertising = false;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x1;
    ret = StartAdvertiser(adv);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x0;
    ret = StartAdvertiser(adv);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscSoftBusBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestStartAdvertiser001, End");
}

/*
 * @tc.name: TestStopAdvertiser001
 * @tc.desc: Test StopAdvertiser should return SOFTBUS_OK when given CON_ADV_ID/NON_ADV_ID adv
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscDistributedBleTest, TestStopAdvertiser001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestStopAdvertiser001, Start");
    g_testDiscBleDispatcherInterface = DiscSoftBusBleInit(&g_testDiscInnerCallBack);
    ASSERT_NE(g_testDiscBleDispatcherInterface, nullptr);

    int32_t adv = CON_ADV_ID;
    g_bleAdvertiser[adv].isAdvertising = true;
    int32_t ret = StopAdvertiser(adv);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_bleAdvertiser[adv].isAdvertising = false;
    ret = StopAdvertiser(adv);
    EXPECT_EQ(ret, SOFTBUS_OK);

    adv = NON_ADV_ID;
    g_bleAdvertiser[adv].isAdvertising = true;
    ret = StopAdvertiser(adv);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_bleAdvertiser[adv].isAdvertising = false;
    ret = StopAdvertiser(adv);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscSoftBusBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestStopAdvertiser001, End");
}

/*
 * @tc.name: TestUpdateAdvertiser001
 * @tc.desc: Test UpdateAdvertiser should return SOFTBUS_OK when given 1/0 g_bleInfoManager[2].capBitMap[0]
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DiscDistributedBleTest, TestUpdateAdvertiser001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestUpdateAdvertiser001, Start");
    g_testDiscBleDispatcherInterface = DiscSoftBusBleInit(&g_testDiscInnerCallBack);
    ASSERT_NE(g_testDiscBleDispatcherInterface, nullptr);

    int32_t adv = CON_ADV_ID;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x1;
    int32_t ret = UpdateAdvertiser(adv);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x0;
    ret = UpdateAdvertiser(adv);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscSoftBusBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestUpdateAdvertiser001, End");
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

    int32_t freqTest = 0;
    SoftBusBleScanParams scanParamTest;
    int32_t ret = GetScannerParam(freqTest, &scanParamTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    DiscSoftBusBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestGetScannerParam001, End");
}

/*
 * @tc.name: TestStopScaner001
 * @tc.desc: Test StopScaner should return SOFTBUS_OK when given false g_isScanning
 *           should return SOFTBUS_ERR when given true g_isScanning and SCAN_MAX_NUM g_bleListener.scanListenerId
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
    g_bleListener.scanListenerId = SCAN_MAX_NUM;
    ret = StopScaner();
    EXPECT_EQ(ret, SOFTBUS_ERR);

    DiscSoftBusBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscDistributedBleTest, TestStopScaner001, End");
}

} // namespace OHOS
