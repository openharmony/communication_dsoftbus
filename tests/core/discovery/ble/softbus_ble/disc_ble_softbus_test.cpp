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

#include <cmath>
#include <gtest/gtest.h>

#include "disc_ble.c"
#include "disc_log.h"
#include "softbus_errcode.h"
#include "message_handler.h"

using namespace testing::ext;
namespace OHOS {
class DiscSoftBusBleTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

static int g_info = 0;
static bool g_softbusBtState = BLE_ENABLE;
static InnerDeviceInfoAddtions addtionsTest;

static void TestOnDeviceFound(const DeviceInfo *device, const InnerDeviceInfoAddtions *addtions)
{
    addtionsTest.medium = addtions->medium;
}

static DiscInnerCallback g_discInnerCallback = {
    .OnDeviceFound = TestOnDeviceFound,
};

static DiscInnerCallback g_discInnerCallBack = {
    .OnDeviceFound = nullptr,
};

int SoftBusGetBtState()
{
    if (g_softbusBtState) {
        return BLE_ENABLE;
    }
    return BLE_DISABLE;
}

int32_t GetDeviceInfo(DeviceInfo *info)
{
    (void)info;
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, GetDeviceInfo, START");
    if (g_info == 0) {
        return 0;
    }
    return -1;
}

int SoftBusSetAdvData(int advId, const SoftBusBleAdvData *data)
{
    (void)data;
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, SoftBusSetAdvData, START");
    if (advId == 1 || advId == 2) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

int SoftBusStartAdv(int advId, const SoftBusBleAdvParams *param)
{
    (void)param;
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, SoftBusBleAdvParams, START");
    if (advId == 2) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

/*
* @tc.name: GetNeedUpdateAdvertiser001
* @tc.desc: test GetNeedUpdateAdvertiser
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, GetNeedUpdateAdvertiser001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, GetNeedUpdateAdvertiser001, Start");
    int32_t adv = NON_ADV_ID;
    ResetInfoUpdate(adv);
    int ret = GetNeedUpdateAdvertiser(adv);
    EXPECT_EQ(ret, SOFTBUS_OK);

    adv = CON_ADV_ID;
    ResetInfoUpdate(CON_ADV_ID);
    ret = GetNeedUpdateAdvertiser(CON_ADV_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, GetNeedUpdateAdvertiser001, End");
}

/*
* @tc.name: CheckScanner001
* @tc.desc: test CheckScanner
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, CheckScanner001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, CheckScanner001, Start");
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x0;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].capBitMap[0] = 0x0;
    g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap[0] = 0x0;
    bool ret = CheckScanner();
    EXPECT_EQ(ret, false);

    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x1;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].capBitMap[0] = 0x1;
    g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap[0] = 0x1;
    ret = CheckScanner();
    EXPECT_EQ(ret, true);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, CheckScanner001, End");
}

/*
* @tc.name: ScanFilter001
* @tc.desc: test ScanFilter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, ScanFilter001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, ScanFilter001, Start");
    int32_t ret = ScanFilter(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    unsigned char advDataTest[INT32_MAX_BIT_NUM];
    unsigned char advLenTest = sizeof(advDataTest);
    SoftBusBleScanResult scanResultDataTest{
        .dataStatus = SOFTBUS_BLE_DATA_COMPLETE,
        .advLen = advLenTest,
        .advData = advDataTest,
    };
    scanResultDataTest.dataStatus = SOFTBUS_BLE_DATA_INCOMPLETE_MORE_TO_COME;
    ret = ScanFilter(&scanResultDataTest);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    scanResultDataTest.dataStatus = SOFTBUS_BLE_DATA_COMPLETE;
    scanResultDataTest.advData[POS_UUID] = (unsigned char) BYTE_MASK;
    scanResultDataTest.advData[POS_UUID + 1] = (unsigned char) ((BLE_UUID >> BYTE_SHIFT_BIT) & BYTE_MASK);
    ret = ScanFilter(&scanResultDataTest);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    scanResultDataTest.advData[POS_UUID] = (unsigned char) (BLE_UUID & BYTE_MASK);
    scanResultDataTest.advData[POS_UUID + 1] = (unsigned char) BYTE_MASK;
    ret = ScanFilter(&scanResultDataTest);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    scanResultDataTest.advData[POS_UUID] = (unsigned char) BYTE_MASK;
    scanResultDataTest.advData[POS_UUID + 1] = (unsigned char) BYTE_MASK;
    ret = ScanFilter(&scanResultDataTest);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    scanResultDataTest.advData[POS_UUID] = (unsigned char) (BLE_UUID & BYTE_MASK);
    scanResultDataTest.advData[POS_UUID + 1] = (unsigned char) ((BLE_UUID >> BYTE_SHIFT_BIT) & BYTE_MASK);
    scanResultDataTest.advData[POS_VERSION + ADV_HEAD_LEN] = BLE_VERSION;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x0;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].capBitMap[0] = 0x0;
    g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap[0] = 0x0;
    ret = ScanFilter(&scanResultDataTest);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x1;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].capBitMap[0] = 0x1;
    g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap[0] = 0x1;
    ret = ScanFilter(&scanResultDataTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, ScanFilter001, End");
}

/*
* @tc.name: ProcessHwHashAccout001
* @tc.desc: test ProcessHwHashAccout
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, ProcessHwHashAccout001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, ProcessHwHashAccout001, Start");
    uint32_t pos = 1;
    DeviceInfo foundInfoTest;
    foundInfoTest.capabilityBitmap[0] = 1 << pos;
    foundInfoTest.capabilityBitmap[1] = 0x0;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].isSameAccount[pos] = false;
    bool ret = ProcessHashAccount(&foundInfoTest);
    EXPECT_EQ(ret, true);

    foundInfoTest.capabilityBitmap[0] = 1 << pos;
    foundInfoTest.capabilityBitmap[1] = 0x0;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].isSameAccount[pos] = true;
    ret = ProcessHashAccount(&foundInfoTest);
    EXPECT_EQ(ret, false);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, ProcessHwHashAccout001, End");
}

/*
* @tc.name: RangeDevice001
* @tc.desc: test RangeDevice
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, RangeDevice001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, RangeDevice001, Start");
    DeviceInfo foundInfoTest;
    const char rssiTest = 's';
    int8_t powerTest = SOFTBUS_ILLEGAL_BLE_POWER;
    RangeDevice(&foundInfoTest, rssiTest, powerTest);
    EXPECT_EQ(foundInfoTest.range, -1);

    powerTest = 10;
    foundInfoTest.devId[0] = 's';
    RangeDevice(&foundInfoTest, rssiTest, powerTest);
    EXPECT_NE(foundInfoTest.range, 1);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, RangeDevice001, End");
}

/*
* @tc.name: ProcessDisNonPacket001
* @tc.desc: test ProcessDisNonPacket
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, ProcessDisNonPacket001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, ProcessDisNonPacket001, Start");
    uint8_t advDataTest[100];
    uint8_t advLenTest = sizeof(advDataTest);
    const char rssiTest = 's';
    DeviceInfo foundInfoTest;
    ProcessDisNonPacket(nullptr, advLenTest, rssiTest, &foundInfoTest);

    foundInfoTest.capabilityBitmap[0] = 0x0;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x1;
    ProcessDisNonPacket(advDataTest, advLenTest, rssiTest, &foundInfoTest);

    g_discBleInnerCb = &g_discInnerCallback;
    ListInit(&g_recvMessageInfo.node);
    uint32_t pos = 0;
    foundInfoTest.capabilityBitmap[0] = 1 << pos;
    foundInfoTest.capabilityBitmap[1] = 0x0;
    advDataTest[POS_CAPABLITY + ADV_HEAD_LEN] = 1 << pos;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x1;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].isSameAccount[pos] = false;
    ProcessDisNonPacket(advDataTest, advLenTest, rssiTest, &foundInfoTest);

    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].isSameAccount[pos] = true;
    ProcessDisNonPacket(advDataTest, advLenTest, rssiTest, &foundInfoTest);
    EXPECT_NE(addtionsTest.medium, BLE);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, ProcessDisNonPacket001, End");
}

/*
* @tc.name: BleScanResultCallback001
* @tc.desc: test BleScanResultCallback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, BleScanResultCallback001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, BleScanResultCallback001, Start");
    int listenerIdTest = 1;
    BleScanResultCallback(listenerIdTest, nullptr);

    uint8_t advDataTest[INT32_MAX_BIT_NUM];
    uint8_t advLenTest = sizeof(advDataTest);
    SoftBusBleScanResult scanResultDataTest = {
        .dataStatus = SOFTBUS_BLE_DATA_COMPLETE,
        .advLen = advLenTest,
        .advData = advDataTest,
    };
    scanResultDataTest.dataStatus = SOFTBUS_BLE_DATA_COMPLETE;
    scanResultDataTest.advData[POS_UUID] = (unsigned char) (BLE_UUID & BYTE_MASK);
    scanResultDataTest.advData[POS_UUID + 1] = (unsigned char) ((BLE_UUID >> BYTE_SHIFT_BIT) & BYTE_MASK);
    scanResultDataTest.advData[POS_VERSION + ADV_HEAD_LEN] = BLE_VERSION;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x1;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].capBitMap[0] = 0x1;
    g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap[0] = 0x1;
    BleScanResultCallback(listenerIdTest, &scanResultDataTest);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, BleScanResultCallback001, End");
}

/*
* @tc.name: BleOnStateChanged001
* @tc.desc: test BleOnStateChanged
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, BleOnStateChanged001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, BleOnStateChanged001, Start");
    LooperInit();
    EXPECT_TRUE(DiscBleLooperInit() == SOFTBUS_OK);

    int listenerIdTest = 1;
    BleOnStateChanged(listenerIdTest, SOFTBUS_BT_STATE_TURN_ON);
    BleOnStateChanged(listenerIdTest, SOFTBUS_BT_STATE_TURN_OFF);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, BleOnStateChanged001, End");
}

/*
* @tc.name: GetWakeRemote001
* @tc.desc: test GetWakeRemote
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, GetWakeRemote001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, GetWakeRemote001, Start");
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].isWakeRemote[0] = true;
    EXPECT_TRUE(GetWakeRemote() == true);
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].isWakeRemote[0] = false;
    EXPECT_TRUE(GetWakeRemote() == false);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, GetWakeRemote001, End");
}

/*
* @tc.name: GetConDeviceInfo001
* @tc.desc: test GetConDeviceInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, GetConDeviceInfo001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, GetConDeviceInfo001, Start");
    int32_t ret = GetConDeviceInfo(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x0;
    DeviceInfo foundInfoTest;
    ret = GetConDeviceInfo(&foundInfoTest);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x1;
    ret = GetConDeviceInfo(&foundInfoTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, GetConDeviceInfo001, End");
}

/*
* @tc.name: GetNonDeviceInfo001
* @tc.desc: test GetNonDeviceInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, GetNonDeviceInfo001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, GetNonDeviceInfo001, Start");
    int32_t ret = GetNonDeviceInfo(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    DeviceInfo foundInfoTest;
    g_bleInfoManager[BLE_PUBLISH | BLE_ACTIVE].capBitMap[0] = 0x0;
    ret = GetNonDeviceInfo(&foundInfoTest);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    g_bleInfoManager[BLE_PUBLISH | BLE_ACTIVE].capBitMap[0] = 0x1;
    ret = GetNonDeviceInfo(&foundInfoTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, GetNonDeviceInfo001, End");
}

/*
* @tc.name: BuildBleConfigAdvData001
* @tc.desc: test BuildBleConfigAdvData
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, BuildBleConfigAdvData001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, BuildBleConfigAdvData001, Start");
    int32_t ret = BuildBleConfigAdvData(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    SoftBusBleAdvData advDataTest {};
    BroadcastData broadcastDataTest {};
    broadcastDataTest.dataLen = ADV_DATA_MAX_LEN;
    ret = BuildBleConfigAdvData(&advDataTest, &broadcastDataTest);
    EXPECT_EQ(advDataTest.scanRspData[POS_RSP_TYPE], RSP_TYPE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, BuildBleConfigAdvData001, End");
}

/*
* @tc.name: GetBroadcastData001
* @tc.desc: test GetBroadcastData
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, GetBroadcastData001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, GetBroadcastData001, Start");
    int32_t ret = GetBroadcastData(nullptr, NUM_ADVERTISER, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    int32_t advId = CON_ADV_ID;
    DeviceInfo infoTest {};
    BroadcastData broadcastDataTest {};
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].isWakeRemote[0] = true;
    ret = GetBroadcastData(&infoTest, advId, &broadcastDataTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    advId = NON_ADV_ID;
    ret = GetBroadcastData(&infoTest, advId, &broadcastDataTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, GetBroadcastData001, End");
}

/*
* @tc.name: StartAdvertiser001
* @tc.desc: test StartAdvertiser
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, StartAdvertiser001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, StartAdvertiser001, Start");
    InitAdvertiser();
    int32_t adv = NON_ADV_ID;
    g_bleAdvertiser[adv].isAdvertising = true;
    g_bleInfoManager[BLE_PUBLISH | BLE_ACTIVE].needUpdate = true;
    g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].needUpdate = true;
    int32_t ret = StartAdvertiser(adv);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    g_bleAdvertiser[adv].isAdvertising = true;
    g_bleInfoManager[BLE_PUBLISH | BLE_ACTIVE].needUpdate = false;
    g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].needUpdate = false;
    ret = StartAdvertiser(adv);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    g_bleAdvertiser[adv].isAdvertising = false;
    g_info = -1;
    g_bleAdvertiser[adv].GetDeviceInfo = GetDeviceInfo;
    g_bleAdvertiser[adv].advId = 0;
    ret = StartAdvertiser(adv);
    EXPECT_EQ(ret, SOFTBUS_OK);

    g_info = 0;
    ret = StartAdvertiser(adv);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    g_bleAdvertiser[adv].advId = 1;
    ret = StartAdvertiser(adv);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    g_bleAdvertiser[adv].advId = 2;
    ret = StartAdvertiser(adv);
    EXPECT_NE(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, StartAdvertiser001, End");
}

/*
* @tc.name: GetScannerParam001
* @tc.desc: test GetScannerParam
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, GetScannerParam001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, GetScannerParam001, Start");
    constexpr int32_t FREQ = -1;
    int32_t ret = GetScannerParam(FREQ, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, GetScannerParam001, End");
}

/*
* @tc.name: RegisterCapability001
* @tc.desc: test RegisterCapability
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, RegisterCapability001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, RegisterCapability001, Start");
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
    ASSERT_TRUE(capabilityDate != nullptr);
    capabilityDate[0] = 'a';
    SubscribeOption subscribeOption = {};
    PublishOption publishOption = {
        .ranging = true,
    };
    DiscBleInfo infoTest = {};
    DiscBleOption optionTest = {
        .publishOption = &publishOption,
        .subscribeOption = &subscribeOption,
    };
    int32_t ret = RegisterCapability(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = RegisterCapability(nullptr, &optionTest);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = RegisterCapability(&infoTest, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    RegisterCapability(&infoTest, &optionTest);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, RegisterCapability001, End");
}

/*
* @tc.name: UnregisterCapability001
* @tc.desc: test dispatcher
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, UnregisterCapability001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest UnregisterCapability001 Start");
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
    ASSERT_TRUE(capabilityDate != nullptr);
    capabilityDate[0] = 'a';
    SubscribeOption subscribeOption = {
        .freq = LOW,
        .isSameAccount = false,
        .isWakeRemote = false,
        .capabilityBitmap = { 0x1 },
        .capabilityData = capabilityDate,
        .dataLen = 1,
    };
    DiscBleOption discBleOption = {
        .publishOption = nullptr,
        .subscribeOption = &subscribeOption,
    };
    DiscBleInfo discBleInfo  = {
        .needUpdate = false,
        .capBitMap = { 0x01 },
        .capCount = { 1 },
        .capabilityData = {capabilityDate},
        .capDataLen = { 1 },
        .isSameAccount = { false },
        .isWakeRemote = { false },
        .freq = { LOW },
        .rangingRefCnt = 1,
    };

    UnregisterCapability(&discBleInfo, &discBleOption);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest UnregisterCapability001 End");
}

/*
* @tc.name: UnregisterCapability002
* @tc.desc: test UnregisterCapability
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, UnregisterCapability002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest UnregisterCapability002 Start");
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
    ASSERT_TRUE(capabilityDate != nullptr);
    capabilityDate[0] = 'a';
    PublishOption publishOption = {
        .freq = LOW,
        .capabilityBitmap = { 0x01 },
        .capabilityData = capabilityDate,
        .dataLen = 1,
        .ranging = false,
    };
    DiscBleInfo discBleInfo  = {
        .needUpdate = false,
        .capBitMap = { 0x01 },
        .capCount = { 1 },
        .capabilityData = { capabilityDate },
        .capDataLen = { 1 },
        .isSameAccount = { false },
        .isWakeRemote = { false },
        .freq = { LOW },
        .rangingRefCnt = 1,
    };
    DiscBleOption discBleOption = {
        .publishOption = &publishOption,
        .subscribeOption = nullptr,
    };
    UnregisterCapability(&discBleInfo, &discBleOption);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest UnregisterCapability002 End");
}

/*
* @tc.name: UnregisterCapability003
* @tc.desc: test UnregisterCapability
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, UnregisterCapability003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest UnregisterCapability003 Start");
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
    ASSERT_TRUE(capabilityDate != nullptr);
    capabilityDate[0] = 'a';
    PublishOption publishOption = {
        .freq = LOW,
        .capabilityBitmap = { 0x01 },
        .capabilityData = capabilityDate,
        .dataLen = 1,
        .ranging = true,
    };
    DiscBleInfo discBleInfo  = {
        .needUpdate = false,
        .capBitMap = { 0x01 },
        .capCount = { 1 },
        .capabilityData = { capabilityDate },
        .capDataLen = { 1 },
        .isSameAccount = { false },
        .isWakeRemote = { false },
        .freq = { LOW },
        .rangingRefCnt = -1,
    };
    DiscBleOption discBleOption = {
        .publishOption = &publishOption,
        .subscribeOption = nullptr,
    };
    UnregisterCapability(&discBleInfo, &discBleOption);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest UnregisterCapability003 End");
}

/*
* @tc.name: UnregisterCapability004
* @tc.desc: test UnregisterCapability
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, UnregisterCapability004, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest UnregisterCapability004 Start");
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
    ASSERT_TRUE(capabilityDate != nullptr);
    capabilityDate[0] = 'a';
    PublishOption publishOption = {
        .freq = LOW,
        .capabilityBitmap = { 0x01 },
        .capabilityData = capabilityDate,
        .dataLen = 1,
        .ranging = false,
    };
    DiscBleInfo discBleInfo  = {
        .needUpdate = false,
        .capBitMap = { 0x01 },
        .capCount = { 1 },
        .capabilityData = { capabilityDate },
        .capDataLen = { 1 },
        .isSameAccount = { false },
        .isWakeRemote = { false },
        .freq = { LOW },
        .rangingRefCnt = -1,
    };
    DiscBleOption discBleOption = {
        .publishOption = &publishOption,
        .subscribeOption = nullptr,
    };
    UnregisterCapability(&discBleInfo, &discBleOption);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest UnregisterCapability004 End");
}

/*
* @tc.name: UnregisterCapability005
* @tc.desc: test UnregisterCapability
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, UnregisterCapability005, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest UnregisterCapability005 Start");
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
    ASSERT_TRUE(capabilityDate != nullptr);
    capabilityDate[0] = 'a';

    PublishOption publishOption = {
        .freq = LOW,
        .capabilityBitmap = { 0x1 },
        .capabilityData = capabilityDate,
        .dataLen = 1,
        .ranging = true,
    };
    DiscBleInfo discBleInfo  = {
        .needUpdate = false,
        .capBitMap = { 0x01 },
        .capCount = { 1 },
        .capabilityData = { capabilityDate },
        .capDataLen = { 1 },
        .isSameAccount = { false },
        .isWakeRemote = { false },
        .freq = { LOW },
        .rangingRefCnt = 1,
    };
    DiscBleOption discBleOption = {
        .publishOption = &publishOption,
        .subscribeOption = nullptr,
    };
    UnregisterCapability(&discBleInfo, &discBleOption);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest UnregisterCapability005 End");
}

/*
* @tc.name: ProcessBleInfoManager001
* @tc.desc: test ProcessBleInfoManager
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, ProcessBleInfoManager001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest ProcessBleInfoManager001 Start");
    bool isStart = false;
    uint8_t publishFlag = 1;
    uint8_t activeFlag = 1;
    void *option = nullptr;
    auto ret = ProcessBleInfoManager(isStart, publishFlag, activeFlag, option);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest ProcessBleInfoManager001 End");
}

/*
* @tc.name: BleStartActivePublish001
* @tc.desc: test BleStartActivePublish
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, BleStartActivePublish001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleStartActivePublish001 Start");
    ListInit(&g_recvMessageInfo.node);
    SoftBusMutexInit(&g_recvMessageInfo.lock, nullptr);
    BleGattLockInit();
    SoftBusMutexInit(&g_bleInfoLock, nullptr);
    LooperInit();
    DiscBleLooperInit();
    uint8_t capabilityDate[] = {'a'};
    PublishOption publishOption = {
        .freq = LOW,
        .capabilityBitmap = { 0x01 },
        .capabilityData = capabilityDate,
        .dataLen = 1,
        .ranging = false,
    };
    g_softbusBtState = false;
    auto ret = BleStartActivePublish(&publishOption);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleStartActivePublish001 End");
}

/*
* @tc.name: BleStartActivePublish002
* @tc.desc: test BleStartActivePublish
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, BleStartActivePublish002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleStartActivePublish002 Start");
    ListInit(&g_recvMessageInfo.node);
    SoftBusMutexInit(&g_recvMessageInfo.lock, nullptr);
    BleGattLockInit();
    SoftBusMutexInit(&g_bleInfoLock, nullptr);
    DiscBleLooperInit();
    uint8_t capabilityDate[] = { 'a' };
    PublishOption publishOption = {
        .freq = LOW,
        .capabilityBitmap = { 0x01 },
        .capabilityData = capabilityDate,
        .dataLen = 1,
        .ranging = false,
    };
    g_softbusBtState = true;
    auto ret = BleStartActivePublish(&publishOption);
    EXPECT_NE(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleStartActivePublish002 End");
}

/*
* @tc.name: BleStartPassivePublish001
* @tc.desc: test BleStartPassivePublish
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, BleStartPassivePublish001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleStartPassivePublish001 Start");
    ListInit(&g_recvMessageInfo.node);
    SoftBusMutexInit(&g_recvMessageInfo.lock, nullptr);
    BleGattLockInit();
    SoftBusMutexInit(&g_bleInfoLock, nullptr);
    DiscBleLooperInit();
    uint8_t capabilityDate[] = { 'a' };
    PublishOption publishOption = {
        .freq = LOW,
        .capabilityBitmap = { 0x01 },
        .capabilityData = capabilityDate,
        .dataLen = 1,
        .ranging = false,
    };
    auto ret = BleStartPassivePublish(&publishOption);
    EXPECT_NE(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleStartPassivePublish001 End");
}

/*
* @tc.name: BleStopActivePublish001
* @tc.desc: test BleStopActivePublish
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, BleStopActivePublish001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleStopActivePublish001 Start");
    ListInit(&g_recvMessageInfo.node);
    SoftBusMutexInit(&g_recvMessageInfo.lock, nullptr);
    BleGattLockInit();
    SoftBusMutexInit(&g_bleInfoLock, nullptr);
    DiscBleLooperInit();
    uint8_t capabilityDate[] = { 'a' };
    PublishOption publishOption = {
        .freq = LOW,
        .capabilityBitmap = { 0x01 },
        .capabilityData = capabilityDate,
        .dataLen = 1,
        .ranging = false,
    };
    auto ret = BleStopActivePublish(&publishOption);
    EXPECT_NE(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleStopActivePublish001 End");
}

/*
* @tc.name: BleStopPassivePublish001
* @tc.desc: test BleStopPassivePublish
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, BleStopPassivePublish001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleStopPassivePublish001 Start");
    ListInit(&g_recvMessageInfo.node);
    SoftBusMutexInit(&g_recvMessageInfo.lock, nullptr);
    BleGattLockInit();
    SoftBusMutexInit(&g_bleInfoLock, nullptr);
    DiscBleLooperInit();
    uint8_t capabilityDate[] = {'a'};
    PublishOption publishOption = {
        .freq = LOW,
        .capabilityBitmap = { 0x01 },
        .capabilityData = capabilityDate,
        .dataLen = 1,
        .ranging = false,
    };
    auto ret = BleStopPassivePublish(&publishOption);
    EXPECT_NE(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleStopPassivePublish001 End");
}

/*
* @tc.name: BleStartActiveDiscovery001
* @tc.desc: test BleStartActiveDiscovery
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, BleStartActiveDiscovery001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleStartActiveDiscovery001 Start");
    ListInit(&g_recvMessageInfo.node);
    SoftBusMutexInit(&g_recvMessageInfo.lock, nullptr);
    BleGattLockInit();
    SoftBusMutexInit(&g_bleInfoLock, nullptr);
    DiscBleLooperInit();
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
    ASSERT_TRUE(capabilityDate != nullptr);
    capabilityDate[0] = 'a';
    SubscribeOption subscribeOption = {
        .freq = LOW,
        .isSameAccount = false,
        .isWakeRemote = false,
        .capabilityBitmap = { 0x1 },
        .capabilityData = capabilityDate,
        .dataLen = 1,
    };
    auto ret = BleStartActiveDiscovery(&subscribeOption);
    EXPECT_NE(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleStartActiveDiscovery001 End");
}

/*
* @tc.name: BleStartPassiveDiscovery001
* @tc.desc: test BleStartPassiveDiscovery
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, BleStartPassiveDiscovery001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleStartPassiveDiscovery001 Start");
    ListInit(&g_recvMessageInfo.node);
    SoftBusMutexInit(&g_recvMessageInfo.lock, nullptr);
    BleGattLockInit();
    SoftBusMutexInit(&g_bleInfoLock, nullptr);
    DiscBleLooperInit();
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
    ASSERT_TRUE(capabilityDate != nullptr);
    capabilityDate[0] = 'a';
    SubscribeOption subscribeOption = {
        .freq = LOW,
        .isSameAccount = false,
        .isWakeRemote = false,
        .capabilityBitmap = { 0x1 },
        .capabilityData = capabilityDate,
        .dataLen = 1,
    };
    auto ret = BleStartPassiveDiscovery(&subscribeOption);
    EXPECT_NE(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleStartPassiveDiscovery001 End");
}

/*
* @tc.name: BleStopActiveDiscovery001
* @tc.desc: test BleStopActiveDiscovery
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, BleStopActiveDiscovery001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleStopActiveDiscovery001 Start");
    ListInit(&g_recvMessageInfo.node);
    SoftBusMutexInit(&g_recvMessageInfo.lock, nullptr);
    BleGattLockInit();
    SoftBusMutexInit(&g_bleInfoLock, nullptr);
    DiscBleLooperInit();
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
    ASSERT_TRUE(capabilityDate != nullptr);
    capabilityDate[0] = 'a';
    SubscribeOption subscribeOption = {
        .freq = LOW,
        .isSameAccount = false,
        .isWakeRemote = false,
        .capabilityBitmap = { 0x1 },
        .capabilityData = capabilityDate,
        .dataLen = 1,
    };
    auto ret = BleStopActiveDiscovery(&subscribeOption);
    EXPECT_NE(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleStopActiveDiscovery001 End");
}
void OnDeviceFound1(const DeviceInfo *device, const InnerDeviceInfoAddtions *addtions) {}

/*
* @tc.name: BleStopPassiveDiscovery001
* @tc.desc: test BleStopPassiveDiscovery
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, BleStopPassiveDiscovery001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleStopPassiveDiscovery001 Start");
    ListInit(&g_recvMessageInfo.node);
    SoftBusMutexInit(&g_recvMessageInfo.lock, nullptr);
    BleGattLockInit();
    SoftBusMutexInit(&g_bleInfoLock, nullptr);
    DiscBleLooperInit();
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
    ASSERT_TRUE(capabilityDate != nullptr);
    capabilityDate[0] = 'a';
    SubscribeOption subscribeOption = {
        .freq = LOW,
        .isSameAccount = false,
        .isWakeRemote = false,
        .capabilityBitmap = { 0x1 },
        .capabilityData = capabilityDate,
        .dataLen = 1,
    };
    auto ret = BleStopPassiveDiscovery(&subscribeOption);
    EXPECT_NE(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleStopPassiveDiscovery001 End");
}

/*
* @tc.name: BleIsConcern001
* @tc.desc: test BleIsConcern
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, BleIsConcern001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleIsConcern001 Start");
    auto ret = BleIsConcern(0);
    EXPECT_EQ (ret, false);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleIsConcern001 End");
}

/*
* @tc.name: BleIsConcern002
* @tc.desc: test BleIsConcern
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, BleIsConcern002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleIsConcern002 Start");
    auto ret = BleIsConcern(1);
    EXPECT_NE (ret, true);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleIsConcern002 End");
}

/*
* @tc.name: DiscSoftbusBleInit001
* @tc.desc: test DiscSoftbusBleInit
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, DiscSoftbusBleInit001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, DiscSoftbusBleInit001, Start");
    auto *ret = DiscSoftBusBleInit(nullptr);
    EXPECT_EQ(ret, nullptr);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, DiscSoftbusBleInit001, End");
}

/*
* @tc.name: DiscSoftbusBleInit002
* @tc.desc: test DiscSoftbusBleInit
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, DiscSoftbusBleInit002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest DiscSoftbusBleInit002 Start");
    auto *ret = DiscSoftBusBleInit(&g_discInnerCallBack);
    EXPECT_EQ(ret, nullptr);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest DiscSoftbusBleInit002 End");
}

/*
* @tc.name: DiscSoftbusBleInit003
* @tc.desc: test DiscSoftbusBleInit
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, DiscSoftbusBleInit003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest DiscSoftbusBleInit003 Start");
    auto *ret = DiscSoftBusBleInit(&g_discInnerCallback);
    EXPECT_EQ(ret, &g_discBleDispatcherInterface);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest DiscSoftbusBleInit003 End");
}

/*
* @tc.name: DiscBleLooperInit001
* @tc.desc: test DiscBleLooperInit
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, DiscBleLooperInit001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest DiscBleLooperInit001 Start");
    auto ret = DiscBleLooperInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest DiscBleLooperInit001 End");
}

/*
* @tc.name: InitBleListener001
* @tc.desc: test InitBleListener
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, InitBleListener001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest InitBleListener001 Start");
    auto ret = InitBleListener();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest InitBleListener001 End");
}

/*
* @tc.name: UpdateAdvertiserDeviceInfo001
* @tc.desc: test UpdateAdvertiserDeviceInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, UpdateAdvertiserDeviceInfo001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest UpdateAdvertiserDeviceInfo001 Start");
    auto ret = UpdateAdvertiserDeviceInfo(1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest UpdateAdvertiserDeviceInfo001 End");
}

/*
* @tc.name: UpdateAdvertiserDeviceInfo002
* @tc.desc: test UpdateAdvertiserDeviceInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, UpdateAdvertiserDeviceInfo002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest UpdateAdvertiserDeviceInfo002 Start");
    uint32_t capabilityBitmap = 0x01;
    ConnectionAddr connectionAddr = {
        .type = CONNECTION_ADDR_BLE,
        .info = {
            .ble = {
                .bleMac = "123456789abc",
                .udidHash = { 0x01 },
            },
        },
        .peerUid = "abcd",
    };
    DeviceInfo deviceInfo = {
        .devId = "bac",
        .accountHash = "abc",
        .devType = DESKTOP_PC,
        .devName = "abc",
        .isOnline = true,
        .addrNum = 1,
        .addr = { connectionAddr },
        .capabilityBitmapNum = 1,
        .capabilityBitmap = { capabilityBitmap },
        .custData = { "hello" },
        .range = 1,
    };
    DiscBleAdvertiser discBleAdvertiser = {
        .advId = 1,
        .isAdvertising = true,
        .deviceInfo = deviceInfo,
        .GetDeviceInfo = GetDeviceInfo,
    };
    g_bleAdvertiser[1] = discBleAdvertiser;
    auto ret = UpdateAdvertiserDeviceInfo(1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest UpdateAdvertiserDeviceInfo002 End");
}

/*
* @tc.name: ProcessBleDiscFunc001
* @tc.desc: test ProcessBleDiscFunc
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, ProcessBleDiscFunc001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest ProcessBleDiscFunc001 Start");
    auto ret = ProcessBleDiscFunc(true, BLE_PUBLISH, BLE_ACTIVE, PUBLISH_ACTIVE_SERVICE, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest ProcessBleDiscFunc001 End");
}

/*
* @tc.name: ProcessBleDiscFunc002
* @tc.desc: test ProcessBleDiscFunc
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, ProcessBleDiscFunc002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest ProcessBleDiscFunc002 Start");
    uint8_t capabilityDate[] = { 'a' };
    PublishOption publishOption = {
        .freq = LOW,
        .capabilityBitmap = {0x01},
        .capabilityData = capabilityDate,
        .dataLen = 1,
        .ranging = false,
    };
    PublishOption publishOption1 [] = {publishOption};
    g_softbusBtState = false;
    auto ret = ProcessBleDiscFunc(true, BLE_PUBLISH, BLE_ACTIVE, PUBLISH_ACTIVE_SERVICE, (void *)publishOption1);
    EXPECT_EQ(ret, SOFTBUS_ERR);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest ProcessBleDiscFunc002 End");
}

/*
* @tc.name: StartPassiveDiscovery001
* @tc.desc: test ProcessBleDiscFunc
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, StartPassiveDiscovery001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest ProcessBleDiscFunc001 Start");
    StartPassiveDiscovery(nullptr);
    SoftBusMessage softBusMessage = {
        .what = START_PASSIVE_DISCOVERY,
        .arg1 = 1,
        .arg2 = 2,
        .time = 12,
        .obj = nullptr,
        .handler = nullptr,
        .FreeMessage = nullptr,
    };
    g_isScanning = true;
    StartActiveDiscovery(&softBusMessage);
    softBusMessage.what = START_ACTIVE_DISCOVERY;
    StartActiveDiscovery(&softBusMessage);
    g_softbusBtState = true;
    EXPECT_TRUE(DiscSoftBusBleInit(&g_discInnerCallback) != nullptr);
    softBusMessage.what = START_PASSIVE_DISCOVERY;
    StartActiveDiscovery(&softBusMessage);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest ProcessBleDiscFunc001 End");
}

/*
* @tc.name: Recovery001
* @tc.desc: test Recovery
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, Recovery001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest Recovery001 Start");
    Recovery(nullptr);
    SoftBusMessage softBusMessage = {
        .what = START_PASSIVE_DISCOVERY,
        .arg1 = 1,
        .arg2 = 2,
        .time = 12,
        .obj = nullptr,
        .handler = nullptr,
        .FreeMessage = nullptr,
    };
    Recovery(&softBusMessage);
    g_softbusBtState = true;
    EXPECT_TRUE(DiscSoftBusBleInit(&g_discInnerCallback) != nullptr);
    softBusMessage.what = RECOVERY;
    Recovery(&softBusMessage);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest Recovery001 End");
}

/*
* @tc.name: BleDiscTurnOff001
* @tc.desc: test BleDiscTurnOff
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, BleDiscTurnOff001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleDiscTurnOff001 Start");
    BleDiscTurnOff(nullptr);
    SoftBusMessage softBusMessage = {
        .what = START_PASSIVE_DISCOVERY,
        .arg1 = 1,
        .arg2 = 2,
        .time = 12,
        .obj = nullptr,
        .handler = nullptr,
        .FreeMessage = nullptr,
    };
    BleDiscTurnOff(&softBusMessage);
    g_softbusBtState = true;
    EXPECT_TRUE(DiscSoftBusBleInit(&g_discInnerCallback) != nullptr);
    softBusMessage.what = RECOVERY;
    BleDiscTurnOff(&softBusMessage);
    DiscBleDeinit();
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleDiscTurnOff001 End");
}

/*
* @tc.name: ReplyPassiveNonBroadcast001
* @tc.desc: test ReplyPassiveNonBroadcast
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, ReplyPassiveNonBroadcast001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest ReplyPassiveNonBroadcast001 Start");
    auto ret = ReplyPassiveNonBroadcast();
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest ReplyPassiveNonBroadcast001 End");
}

/*
* @tc.name: RemoveRecvMsgFunc001
* @tc.desc: test RemoveRecvMsgFunc
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, RemoveRecvMsgFunc001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest RemoveRecvMsgFunc001 Start");
    SoftBusMessage softBusMessage = {
        .what = START_PASSIVE_DISCOVERY,
        .arg1 = 1,
        .arg2 = 2,
        .time = 12,
        .obj = nullptr,
        .handler = nullptr,
        .FreeMessage = nullptr,
    };
    auto args = softBusMessage.arg1;
    auto ret = MessageRemovePredicate(&softBusMessage, (void *) &args);
    EXPECT_EQ(ret, 1);
    args = args + 1;
    auto ans = MessageRemovePredicate(&softBusMessage, (void *) &args);
    EXPECT_EQ(ans, 1);
    softBusMessage.what = PROCESS_TIME_OUT;
    auto tmp = MessageRemovePredicate(&softBusMessage, (void *) &args);
    EXPECT_EQ(tmp, 1);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest RemoveRecvMsgFunc001 End");
}

/*
* @tc.name: GetRecvMessage001
* @tc.desc: test GetRecvMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, GetRecvMessage001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest GetRecvMessage001 Start");
    auto ret = GetRecvMessage(nullptr);
    EXPECT_EQ(ret, nullptr);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest GetRecvMessage001 End");
}

/*
* @tc.name: MatchRecvMessage001
* @tc.desc: test MatchRecvMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, MatchRecvMessage001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest MatchRecvMessage001 Start");
    auto ret = MatchRecvMessage(nullptr, nullptr, 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest MatchRecvMessage001 End");
}

/*
* @tc.name: MatchRecvMessage002
* @tc.desc: test MatchRecvMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, MatchRecvMessage002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest MatchRecvMessage002 Start");
    uint32_t publishInfo[] = { 0x1, 0xa };
    uint32_t capBitMap[] = { 0x1 };
    DiscSoftBusBleInit(&g_discInnerCallback);
    auto ret = MatchRecvMessage(publishInfo, capBitMap, 1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest MatchRecvMessage002 End");
}

/*
* @tc.name: StartTimeout001
* @tc.desc: test StartTimeout
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, StartTimeout001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest StartTimeout001 Start");
    StartTimeout(nullptr);
    StartTimeout("123");
    EXPECT_TRUE(DiscSoftBusBleInit(&g_discInnerCallback) != nullptr);
    StartTimeout("123");
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest StartTimeout001 End");
}

/*
* @tc.name: RemoveTimeout001
* @tc.desc: test RemoveTimeout
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, RemoveTimeout001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest RemoveTimeout001 Start");
    RemoveTimeout(nullptr);
    RemoveTimeout("123");
    EXPECT_TRUE(DiscSoftBusBleInit(&g_discInnerCallback) != nullptr);
    RemoveTimeout("123");
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest RemoveTimeout001 End");
}

/*
* @tc.name: AddRecvMessage001
* @tc.desc: test AddRecvMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, AddRecvMessage001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest AddRecvMessage001 Start");
    SoftBusMutexInit(&g_recvMessageInfo.lock, nullptr);
    BleGattLockInit();
    SoftBusMutexInit(&g_bleInfoLock, nullptr);
    DiscSoftBusBleInit(&g_discInnerCallback);
    auto ret = AddRecvMessage(nullptr, nullptr, true);
    EXPECT_EQ (ret, SOFTBUS_INVALID_PARAM);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest AddRecvMessage001 End");
}

/*
* @tc.name: AddRecvMessage002
* @tc.desc: test AddRecvMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, AddRecvMessage002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest AddRecvMessage002 Start");
    SoftBusMutexInit(&g_recvMessageInfo.lock, nullptr);
    BleGattLockInit();
    SoftBusMutexInit(&g_bleInfoLock, nullptr);
    uint32_t capbitmap[] = { 0x1 };
    auto ret = AddRecvMessage("123", capbitmap, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest AddRecvMessage002 End");
}

/*
* @tc.name: RemoveRecvMessage001
* @tc.desc: test RemoveRecvMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, RemoveRecvMessage001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest RemoveRecvMessage001 Start");
    EXPECT_TRUE(DiscSoftBusBleInit(&g_discInnerCallback) != nullptr);
    RemoveRecvMessage(0X01);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest RemoveRecvMessage001 End");
}

/*
* @tc.name: BleInfoDump001
* @tc.desc: test BleInfoDump
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, BleInfoDump001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleInfoDump001 Start");
    DiscSoftBusBleInit(&g_discInnerCallback);
    EXPECT_TRUE(BleInfoDump(9) == SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest BleInfoDump001 End");
}

/*
* @tc.name: RegisterCapability002
* @tc.desc: test RegisterCapability
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, RegisterCapability002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest RegisterCapability002 Start");
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
    ASSERT_TRUE(capabilityDate != nullptr);
    capabilityDate[0] = 'a';
    SubscribeOption subscribeOption = {
        .freq = LOW,
        .isSameAccount = false,
        .isWakeRemote = false,
        .capabilityBitmap = { 0x0 },
        .capabilityData = capabilityDate,
        .dataLen = 1,
    };
    DiscBleOption discBleOption = {
        .publishOption = nullptr,
        .subscribeOption = &subscribeOption,
    };
    DiscBleInfo discBleInfo  = {
        .needUpdate = false,
        .capBitMap = { 0x01 },
        .capCount = { 1 },
        .capabilityData = {capabilityDate},
        .capDataLen = { 1 },
        .isSameAccount = { false },
        .isWakeRemote = { false },
        .freq = { LOW },
        .rangingRefCnt = 1,
    };
    auto ret = RegisterCapability(&discBleInfo, &discBleOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest RegisterCapability002 End");
}

/*
* @tc.name: RegisterCapability002
* @tc.desc: test RegisterCapability
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, RegisterCapability003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest RegisterCapability003 Start");
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
    ASSERT_TRUE(capabilityDate != nullptr);
    capabilityDate[0] = 'a';
    SubscribeOption subscribeOption = {
        .freq = LOW,
        .isSameAccount = false,
        .isWakeRemote = false,
        .capabilityBitmap = { 0x1 },
        .capabilityData = capabilityDate,
        .dataLen = 1,
    };
    DiscBleOption discBleOption = {
        .publishOption = nullptr,
        .subscribeOption = &subscribeOption,
    };
    DiscBleInfo discBleInfo  = {
        .needUpdate = false,
        .capBitMap = { 0x0 },
        .capCount = { 1 },
        .capabilityData = {capabilityDate},
        .capDataLen = { 1 },
        .isSameAccount = { false },
        .isWakeRemote = { false },
        .freq = { LOW },
        .rangingRefCnt = 1,
    };
    auto ret = RegisterCapability(&discBleInfo, &discBleOption);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest RegisterCapability003 End");
}

/*
* @tc.name: ProcessBleInfoManager002
* @tc.desc: test ProcessBleInfoManager
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, ProcessBleInfoManager002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest ProcessBleInfoManager002 Start");
    bool isStart = false;
    uint8_t publishFlag = BLE_PUBLISH;
    uint8_t activeFlag = 1;
    uint8_t capabilityDate[] = { 'a' };
    PublishOption publishOption = {
        .freq = LOW,
        .capabilityBitmap = {0x01},
        .capabilityData = capabilityDate,
        .dataLen = 1,
        .ranging = false,
    };
    PublishOption publishOption2[] = {publishOption};
    auto ret = ProcessBleInfoManager(isStart, publishFlag, activeFlag, (void *)publishOption2);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest ProcessBleInfoManager002 End");
}
/*
* @tc.name: ProcessBleInfoManager002
* @tc.desc: test ProcessBleInfoManager
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, ProcessBleInfoManager003, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest ProcessBleInfoManager003 Start");
    bool isStart = false;
    uint8_t publishFlag = BLE_PUBLISH;
    uint8_t activeFlag = 1;
    uint8_t capabilityDate[] = { 'a' };
    SubscribeOption subscribeOption = {
        .freq = LOW,
        .isSameAccount = false,
        .isWakeRemote = false,
        .capabilityBitmap = { 0x0 },
        .capabilityData = capabilityDate,
        .dataLen = 1,
    };
    SubscribeOption subscribeOption1[] = { subscribeOption };
    auto ret = ProcessBleInfoManager(isStart, publishFlag, activeFlag, (void *)subscribeOption1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest ProcessBleInfoManager003 End");
}

/*
* @tc.name: InitDiscBleInfo001
* @tc.desc: test InitDiscBleInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, InitDiscBleInfo001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest InitDiscBleInfo001 Start");
    auto ret = InitDiscBleInfo(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest InitDiscBleInfo001 End");
}
/*
* @tc.name: RemoveRecvMsgFunc002
* @tc.desc: test RemoveRecvMsgFunc
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, RemoveRecvMsgFunc002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest RemoveRecvMsgFunc002 Start");
    uintptr_t args = 12;
    SoftBusMessage msg = {
        .what = PROCESS_TIME_OUT,
        .arg1 = reinterpret_cast<uint64_t>(&args),
        .arg2 = args,
        .time = 13,
        .obj = nullptr,
        .handler = nullptr,
        .FreeMessage = nullptr,
    };
    auto ret = MessageRemovePredicate(&msg, &args);
    EXPECT_EQ(ret, 0);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest RemoveRecvMsgFunc002 End");
}

/*
* @tc.name: UpdateAdvertiser001
* @tc.desc: test UpdateAdvertiser
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, UpdateAdvertiser001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, UpdateAdvertiser001, Start");
    int32_t advTest = 0;
    g_bleAdvertiser[advTest] = {
        .advId = 0,
        .isAdvertising = true,
        .GetDeviceInfo = GetDeviceInfo,
    };
    g_info = 0;
    EXPECT_TRUE(UpdateAdvertiser(advTest) == SOFTBUS_OK);

    g_info = -1;
    EXPECT_TRUE(UpdateAdvertiser(advTest) != SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest, UpdateAdvertiser001, End");
}

/*
* @tc.name: UpdateAdvertiser001
* @tc.desc: test UpdateAdvertiser
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DiscSoftBusBleTest, DiscFreeBleScanFilter001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest DiscFreeBleScanFilter001 Start");
    SoftBusBleScanFilter *filter = nullptr;
    DiscFreeBleScanFilter(&filter);

    filter = static_cast<SoftBusBleScanFilter *>(SoftBusMalloc(sizeof(SoftBusBleScanFilter)));
    ASSERT_TRUE(filter != nullptr);
    filter->serviceData = nullptr;
    filter->serviceDataMask = nullptr;
    DiscFreeBleScanFilter(&filter);

    filter = static_cast<SoftBusBleScanFilter *>(SoftBusMalloc(sizeof(SoftBusBleScanFilter)));
    ASSERT_TRUE(filter != nullptr);
    filter->serviceData = static_cast<uint8_t *>(SoftBusMalloc(128));
    ASSERT_TRUE(filter->serviceData != nullptr);
    filter->serviceDataMask = nullptr;
    DiscFreeBleScanFilter(&filter);

    filter = static_cast<SoftBusBleScanFilter *>(SoftBusMalloc(sizeof(SoftBusBleScanFilter)));
    ASSERT_TRUE(filter != nullptr);
    filter->serviceData = nullptr;
    filter->serviceDataMask = static_cast<uint8_t *>(SoftBusMalloc(128));
    ASSERT_TRUE(filter->serviceDataMask != nullptr);
    DiscFreeBleScanFilter(&filter);

    DISC_LOGI(DISC_TEST, "DiscSoftBusBleTest DiscFreeBleScanFilter001 End");
}
}