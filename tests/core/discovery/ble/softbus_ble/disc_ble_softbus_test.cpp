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
#include "softbus_errcode.h"
#include "message_handler.h"

using namespace testing::ext;
namespace OHOS {
class SoftBusDiscBleTest : public testing::Test {
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
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, GetDeviceInfo, START");
    if (g_info == 0) {
        return 0;
    }
    return -1;
}

int SoftBusSetAdvData(int advId, const SoftBusBleAdvData *data)
{
    (void)data;
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, SoftBusSetAdvData, START");
    if (advId == 1 || advId == 2) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

int SoftBusStartAdv(int advId, const SoftBusBleAdvParams *param)
{
    (void)param;
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, SoftBusBleAdvParams, START");
    if (advId == 2) {
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

/*
* @tc.name: DeConvertBitMap001
* @tc.desc: test DeConvertBitMap
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, DeConvertBitMap001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, DeConvertBitMap001, Start");
    uint32_t tempCap = 0;
    int32_t capabilityBitmapNum = 1;
    uint32_t capabilityBitmap[DISC_MAX_CAPABILITY_NUM] = { 0x10 };
    DeConvertBitMap(&tempCap, capabilityBitmap, capabilityBitmapNum);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, DeConvertBitMap001, End");
}

/*
* @tc.name: ResetInfoUpdate001
* @tc.desc: test ResetInfoUpdate
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, ResetInfoUpdate001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, ResetInfoUpdate001, Start");
    int32_t adv = NON_ADV_ID;
    ResetInfoUpdate(adv);

    adv = CON_ADV_ID;
    ResetInfoUpdate(adv);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, ResetInfoUpdate001, End");
}

/*
* @tc.name: GetNeedUpdateAdvertiser001
* @tc.desc: test GetNeedUpdateAdvertiser
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, GetNeedUpdateAdvertiser001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, GetNeedUpdateAdvertiser001, Start");
    int32_t adv = NON_ADV_ID;
    ResetInfoUpdate(adv);
    int ret = GetNeedUpdateAdvertiser(adv);
    EXPECT_EQ(ret, SOFTBUS_OK);

    adv = CON_ADV_ID;
    ResetInfoUpdate(CON_ADV_ID);
    ret = GetNeedUpdateAdvertiser(CON_ADV_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, GetNeedUpdateAdvertiser001, End");
}

/*
* @tc.name: BleAdvEnableCallback001
* @tc.desc: test BleAdvEnableCallback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BleAdvEnableCallback001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, BleAdvEnableCallback001, Start");
    int32_t adv = NON_ADV_ID;
    int status = SOFTBUS_BT_STATUS_SUCCESS;
    BleAdvEnableCallback(adv, status);

    adv = NUM_ADVERTISER;
    status = SOFTBUS_BT_STATUS_BUSY;
    BleAdvEnableCallback(adv, status);

    adv = NON_ADV_ID;
    status = SOFTBUS_BT_STATUS_BUSY;
    BleAdvEnableCallback(adv, status);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, BleAdvEnableCallback001, End");
}

/*
* @tc.name: BleAdvDisableCallback001
* @tc.desc: test BleAdvDisableCallback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BleAdvDisableCallback001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, BleAdvDisableCallback001, Start");
    int32_t adv = NON_ADV_ID;
    int status = SOFTBUS_BT_STATUS_SUCCESS;
    BleAdvDisableCallback(adv, status);

    adv = NUM_ADVERTISER;
    status = SOFTBUS_BT_STATUS_BUSY;
    BleAdvDisableCallback(adv, status);

    adv = NON_ADV_ID;
    status = SOFTBUS_BT_STATUS_BUSY;
    BleAdvDisableCallback(adv, status);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, BleAdvDisableCallback001, End");
}

/*
* @tc.name: BleAdvDataCallback001
* @tc.desc: test BleAdvDataCallback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BleAdvDataCallback001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, BleAdvDataCallback001, Start");
    int32_t adv = NON_ADV_ID;
    int status = SOFTBUS_BT_STATUS_SUCCESS;
    BleAdvDataCallback(adv, status);

    adv = NUM_ADVERTISER;
    status = SOFTBUS_BT_STATUS_BUSY;
    BleAdvDataCallback(adv, status);

    adv = NON_ADV_ID;
    status = SOFTBUS_BT_STATUS_BUSY;
    BleAdvDataCallback(adv, status);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, BleAdvDataCallback001, End");
}


/*
* @tc.name: BleAdvUpdateCallback001
* @tc.desc: test BleAdvUpdateCallback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BleAdvUpdateCallback001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, BleAdvUpdateCallback001, Start");
    int32_t adv = NON_ADV_ID;
    int status = SOFTBUS_BT_STATUS_SUCCESS;
    BleAdvUpdateCallback(adv, status);

    adv = NUM_ADVERTISER;
    status = SOFTBUS_BT_STATUS_BUSY;
    BleAdvUpdateCallback(adv, status);

    adv = NON_ADV_ID;
    status = SOFTBUS_BT_STATUS_BUSY;
    BleAdvUpdateCallback(adv, status);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, BleAdvUpdateCallback001, End");
}
/*
* @tc.name: CheckScanner001
* @tc.desc: test CheckScanner
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, CheckScanner001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, CheckScanner001, Start");
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
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, CheckScanner001, End");
}

/*
* @tc.name: ScanFilter001
* @tc.desc: test ScanFilter
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, ScanFilter001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, ScanFilter001, Start");
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
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, ScanFilter001, End");
}

/*
* @tc.name: ProcessDisConPacket001
* @tc.desc: test ProcessDisConPacket
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, ProcessDisConPacket001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, ProcessDisConPacket001, Start");
    DeviceInfo foundInfoTest;
    uint8_t advDataTest[100];
    uint8_t advLenTest = sizeof(advDataTest);
    ProcessDisConPacket(nullptr, advLenTest, &foundInfoTest);

    foundInfoTest.capabilityBitmap[0] = 0x0;
    g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap[0] = 0x0;
    ProcessDisConPacket(advDataTest, advLenTest, &foundInfoTest);

    foundInfoTest.capabilityBitmap[0] = 0x1;
    advDataTest[POS_CAPABLITY + ADV_HEAD_LEN] = 0x1;
    g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap[0] = 0x1;
    ProcessDisConPacket(advDataTest, advLenTest, &foundInfoTest);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, ProcessDisConPacket001, End");
}

/*
* @tc.name: ProcessHwHashAccout001
* @tc.desc: test ProcessHwHashAccout
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, ProcessHwHashAccout001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, ProcessHwHashAccout001, Start");
    uint32_t pos = 1;
    DeviceInfo foundInfoTest;
    foundInfoTest.capabilityBitmap[0] = 1 << pos;
    foundInfoTest.capabilityBitmap[1] = 0x0;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].isSameAccount[pos] = false;
    bool ret = ProcessHwHashAccout(&foundInfoTest);
    EXPECT_EQ(ret, true);

    foundInfoTest.capabilityBitmap[0] = 1 << pos;
    foundInfoTest.capabilityBitmap[1] = 0x0;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].isSameAccount[pos] = true;
    ret = ProcessHwHashAccout(&foundInfoTest);
    EXPECT_EQ(ret, false);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, ProcessHwHashAccout001, End");
}

/*
* @tc.name: RangeDevice001
* @tc.desc: test RangeDevice
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, RangeDevice001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, RangeDevice001, Start");
    static constexpr double DB_BASE = 10.0;
    static constexpr double DB_COEFFICIENT = 20.0;

    DeviceInfo foundInfoTest;
    const char rssiTest = 's';
    int8_t powerTest = SOFTBUS_ILLEGAL_BLE_POWER;
    RangeDevice(&foundInfoTest, rssiTest, powerTest);
    EXPECT_EQ(foundInfoTest.range, -1);

    powerTest = 10;
    foundInfoTest.devId[0] = 's';
    RangeDevice(&foundInfoTest, rssiTest, powerTest);
    EXPECT_EQ(foundInfoTest.range, (int32_t)pow(DB_BASE, rssiTest * -1 / DB_COEFFICIENT));
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, RangeDevice001, End");
}

/*
* @tc.name: ProcessDisNonPacket001
* @tc.desc: test ProcessDisNonPacket
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, ProcessDisNonPacket001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, ProcessDisNonPacket001, Start");
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
    EXPECT_EQ(addtionsTest.medium, BLE);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, ProcessDisNonPacket001, End");
}

/*
* @tc.name: BleScanResultCallback001
* @tc.desc: test BleScanResultCallback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BleScanResultCallback001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, BleScanResultCallback001, Start");
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
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, BleScanResultCallback001, End");
}

/*
* @tc.name: BleOnStateChanged001
* @tc.desc: test BleOnStateChanged
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BleOnStateChanged001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, BleOnStateChanged001, Start");
    LooperInit();
    DiscBleLooperInit();

    int listenerIdTest = 1;
    BleOnStateChanged(listenerIdTest, SOFTBUS_BT_STATE_TURN_ON);
    BleOnStateChanged(listenerIdTest, SOFTBUS_BT_STATE_TURN_OFF);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, BleOnStateChanged001, End");
}

/*
* @tc.name: GetWakeRemote001
* @tc.desc: test GetWakeRemote
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, GetWakeRemote001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, GetWakeRemote001, Start");
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].isWakeRemote[0] = true;
    GetWakeRemote();
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].isWakeRemote[0] = false;
    GetWakeRemote();
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, GetWakeRemote001, End");
}

/*
* @tc.name: GetConDeviceInfo001
* @tc.desc: test GetConDeviceInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, GetConDeviceInfo001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, GetConDeviceInfo001, Start");
    int32_t ret = GetConDeviceInfo(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x0;
    DeviceInfo foundInfoTest;
    ret = GetConDeviceInfo(&foundInfoTest);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x1;
    ret = GetConDeviceInfo(&foundInfoTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, GetConDeviceInfo001, End");
}

/*
* @tc.name: ProcessDistributePacket001
* @tc.desc: test ProcessDistributePacket
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, ProcessDistributePacket001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, ProcessDistributePacket001, Start");
    uint8_t advDataTest[INT32_MAX_BIT_NUM];
    uint8_t advLenTest = sizeof(advDataTest);
    SoftBusBleScanResult scanResultDataTest = {
        .dataStatus = SOFTBUS_BLE_DATA_COMPLETE,
        .advLen = advLenTest,
        .advData = advDataTest,
    };
    ProcessDistributePacket(&scanResultDataTest);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, ProcessDistributePacket001, End");
}

/*
* @tc.name: GetNonDeviceInfo001
* @tc.desc: test GetNonDeviceInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, GetNonDeviceInfo001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, GetNonDeviceInfo001, Start");
    int32_t ret = GetNonDeviceInfo(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    DeviceInfo foundInfoTest;
    g_bleInfoManager[BLE_PUBLISH | BLE_ACTIVE].capBitMap[0] = 0x0;
    ret = GetNonDeviceInfo(&foundInfoTest);
    EXPECT_EQ(ret, SOFTBUS_ERR);

    g_bleInfoManager[BLE_PUBLISH | BLE_ACTIVE].capBitMap[0] = 0x1;
    ret = GetNonDeviceInfo(&foundInfoTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, GetNonDeviceInfo001, End");
}


/*
* @tc.name: BuildBleConfigAdvData001
* @tc.desc: test BuildBleConfigAdvData
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BuildBleConfigAdvData001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, BuildBleConfigAdvData001, Start");
    int32_t ret = BuildBleConfigAdvData(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    SoftBusBleAdvData advDataTest {};
    BoardcastData broadcastDataTest {};
    broadcastDataTest.dataLen = ADV_DATA_MAX_LEN;
    ret = BuildBleConfigAdvData(&advDataTest, &broadcastDataTest);
    EXPECT_EQ(advDataTest.scanRspData[POS_RSP_TYPE], RSP_TYPE);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, BuildBleConfigAdvData001, End");
}

/*
* @tc.name: AssembleNonOptionalTlv001
* @tc.desc: test AssembleNonOptionalTlv
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, AssembleNonOptionalTlv001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, AssembleNonOptionalTlv001, Start");
    DeviceInfo infoTest;
    infoTest.range = 1;
    BoardcastData broadcastDataTest {};
    AssembleNonOptionalTlv(&infoTest, &broadcastDataTest);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, AssembleNonOptionalTlv001, End");
}

/*
* @tc.name: GetBroadcastData001
* @tc.desc: test GetBroadcastData
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, GetBroadcastData001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, GetBroadcastData001, Start");
    int32_t ret = GetBroadcastData(nullptr, NUM_ADVERTISER, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    int32_t advId = CON_ADV_ID;
    DeviceInfo infoTest {};
    BoardcastData broadcastDataTest {};
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].isWakeRemote[0] = true;
    ret = GetBroadcastData(&infoTest, advId, &broadcastDataTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    advId = NON_ADV_ID;
    ret = GetBroadcastData(&infoTest, advId, &broadcastDataTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, GetBroadcastData001, End");
}

/*
* @tc.name: StartAdvertiser001
* @tc.desc: test StartAdvertiser
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, StartAdvertiser001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, StartAdvertiser001, Start");
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
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, StartAdvertiser001, End");
}

/*
* @tc.name: GetScannerParam001
* @tc.desc: test GetScannerParam
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, GetScannerParam001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, GetScannerParam001, Start");
    constexpr int32_t FREQ = -1;
    int32_t ret = GetScannerParam(FREQ, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, GetScannerParam001, End");
}

/*
* @tc.name: StartScaner001
* @tc.desc: test StartScaner
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, StartScaner001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, StartScaner001, Start");
    for (uint32_t pos = 0; pos < CAPABILITY_MAX_BITNUM; pos++) {
        for (uint32_t index = 0; index < BLE_INFO_COUNT; index++) {
            g_bleInfoManager[index].freq[pos] = 0;
        }
    }
    StartScaner();

    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x0;
    g_bleInfoManager[BLE_SUBSCRIBE | BLE_PASSIVE].capBitMap[0] = 0x0;
    g_bleInfoManager[BLE_PUBLISH | BLE_PASSIVE].capBitMap[0] = 0x0;
    StartScaner();

    g_bleInfoManager[BLE_SUBSCRIBE | BLE_ACTIVE].capBitMap[0] = 0x1;
    g_isScanning = false;
    StartScaner();

    g_bleInfoManager[0].freq[0] = FREQ_BUTT;
    StartScaner();
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, StartScaner001, End");
}

/*
* @tc.name: RegisterCapability001
* @tc.desc: test RegisterCapability
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, RegisterCapability001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, RegisterCapability001, Start");
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
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
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest, RegisterCapability001, End");
}

/*
* @tc.name: UnregisterCapability001
* @tc.desc: test dispatcher
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, UnregisterCapability001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest UnregisterCapability001 Start");
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
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
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest UnregisterCapability001 End");
}

/*
* @tc.name: UnregisterCapability002
* @tc.desc: test UnregisterCapability
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, UnregisterCapability002, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest UnregisterCapability002 Start");
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
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
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest UnregisterCapability002 End");
}

/*
* @tc.name: UnregisterCapability003
* @tc.desc: test UnregisterCapability
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, UnregisterCapability003, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest UnregisterCapability003 Start");
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
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
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest UnregisterCapability003 End");
}

/*
* @tc.name: UnregisterCapability004
* @tc.desc: test UnregisterCapability
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, UnregisterCapability004, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest UnregisterCapability004 Start");
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
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
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest UnregisterCapability004 End");
}

/*
* @tc.name: UnregisterCapability005
* @tc.desc: test UnregisterCapability
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, UnregisterCapability005, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest UnregisterCapability005 Start");
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
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
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest UnregisterCapability005 End");
}

/*
* @tc.name: ProcessBleInfoManager001
* @tc.desc: test ProcessBleInfoManager
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, ProcessBleInfoManager001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest ProcessBleInfoManager001 Start");
    bool isStart = false;
    uint8_t publishFlag = 1;
    uint8_t activeFlag = 1;
    void *option = nullptr;
    auto ret = ProcessBleInfoManager(isStart, publishFlag, activeFlag, option);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest ProcessBleInfoManager001 End");
}

/*
* @tc.name: BleStartActivePublish001
* @tc.desc: test BleStartActivePublish
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BleStartActivePublish001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleStartActivePublish001 Start");
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
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleStartActivePublish001 End");
}

/*
* @tc.name: BleStartActivePublish002
* @tc.desc: test BleStartActivePublish
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BleStartActivePublish002, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleStartActivePublish002 Start");
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
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleStartActivePublish002 End");
}

/*
* @tc.name: BleStartPassivePublish001
* @tc.desc: test BleStartPassivePublish
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BleStartPassivePublish001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleStartPassivePublish001 Start");
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
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleStartPassivePublish001 End");
}

/*
* @tc.name: BleStopActivePublish001
* @tc.desc: test BleStopActivePublish
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BleStopActivePublish001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleStopActivePublish001 Start");
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
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleStopActivePublish001 End");
}

/*
* @tc.name: BleStopPassivePublish001
* @tc.desc: test BleStopPassivePublish
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BleStopPassivePublish001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleStopPassivePublish001 Start");
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
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleStopPassivePublish001 End");
}

/*
* @tc.name: BleStartActiveDiscovery001
* @tc.desc: test BleStartActiveDiscovery
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BleStartActiveDiscovery001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleStartActiveDiscovery001 Start");
    ListInit(&g_recvMessageInfo.node);
    SoftBusMutexInit(&g_recvMessageInfo.lock, nullptr);
    BleGattLockInit();
    SoftBusMutexInit(&g_bleInfoLock, nullptr);
    DiscBleLooperInit();
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
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
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleStartActiveDiscovery001 End");
}

/*
* @tc.name: BleStartPassiveDiscovery001
* @tc.desc: test BleStartPassiveDiscovery
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BleStartPassiveDiscovery001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleStartPassiveDiscovery001 Start");
    ListInit(&g_recvMessageInfo.node);
    SoftBusMutexInit(&g_recvMessageInfo.lock, nullptr);
    BleGattLockInit();
    SoftBusMutexInit(&g_bleInfoLock, nullptr);
    DiscBleLooperInit();
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
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
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleStartPassiveDiscovery001 End");
}

/*
* @tc.name: BleStopActiveDiscovery001
* @tc.desc: test BleStopActiveDiscovery
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BleStopActiveDiscovery001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleStopActiveDiscovery001 Start");
    ListInit(&g_recvMessageInfo.node);
    SoftBusMutexInit(&g_recvMessageInfo.lock, nullptr);
    BleGattLockInit();
    SoftBusMutexInit(&g_bleInfoLock, nullptr);
    DiscBleLooperInit();
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
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
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleStopActiveDiscovery001 End");
}
void OnDeviceFound1(const DeviceInfo *device, const InnerDeviceInfoAddtions *addtions) {}

/*
* @tc.name: BleStopPassiveDiscovery001
* @tc.desc: test BleStopPassiveDiscovery
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BleStopPassiveDiscovery001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleStopPassiveDiscovery001 Start");
    ListInit(&g_recvMessageInfo.node);
    SoftBusMutexInit(&g_recvMessageInfo.lock, nullptr);
    BleGattLockInit();
    SoftBusMutexInit(&g_bleInfoLock, nullptr);
    DiscBleLooperInit();
    uint8_t *capabilityDate = (uint8_t *)SoftBusMalloc(sizeof(uint8_t));
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
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleStopPassiveDiscovery001 End");
}

/*
* @tc.name: BleIsConcern001
* @tc.desc: test BleIsConcern
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BleIsConcern001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleIsConcern001 Start");
    auto ret = BleIsConcern(0);
    EXPECT_EQ (ret, false);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleIsConcern001 End");
}

/*
* @tc.name: BleIsConcern002
* @tc.desc: test BleIsConcern
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BleIsConcern002, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleIsConcern002 Start");
    auto ret = BleIsConcern(1);
    EXPECT_EQ (ret, true);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleIsConcern002 End");
}

/*
* @tc.name: DiscSoftbusBleInit001
* @tc.desc: test DiscSoftbusBleInit
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, DiscSoftbusBleInit001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest,DiscSoftbusBleInit001,Start");
    auto *ret = DiscSoftbusBleInit(nullptr);
    EXPECT_EQ(ret, nullptr);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest,DiscSoftbusBleInit001,End");
}

/*
* @tc.name: DiscSoftbusBleInit002
* @tc.desc: test DiscSoftbusBleInit
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, DiscSoftbusBleInit002, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest DiscSoftbusBleInit002 Start");
    auto *ret = DiscSoftbusBleInit(&g_discInnerCallBack);
    EXPECT_EQ(ret, nullptr);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest DiscSoftbusBleInit002 End");
}

/*
* @tc.name: DiscSoftbusBleInit003
* @tc.desc: test DiscSoftbusBleInit
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, DiscSoftbusBleInit003, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest DiscSoftbusBleInit003 Start");
    auto *ret = DiscSoftbusBleInit(&g_discInnerCallback);
    EXPECT_EQ(ret, &g_discBleDispatcherInterface);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest DiscSoftbusBleInit003 End");
}

/*
* @tc.name: DiscBleLooperInit001
* @tc.desc: test DiscBleLooperInit
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, DiscBleLooperInit001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest DiscBleLooperInit001 Start");
    auto ret = DiscBleLooperInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest DiscBleLooperInit001 End");
}

/*
* @tc.name: InitBleListener001
* @tc.desc: test InitBleListener
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, InitBleListener001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest InitBleListener001 Start");
    auto ret = InitBleListener();
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest InitBleListener001 End");
}

/*
* @tc.name: DiscSoftbusBleDeinit001
* @tc.desc: test DiscSoftbusBleDeinit
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, DiscSoftbusBleDeinit001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest DiscSoftbusBleDeinit001 Start");
    g_isScanning = true;
    DiscSoftbusBleDeinit();
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest DiscSoftbusBleDeinit001 End");
}

/*
* @tc.name: UpdateAdvertiserDeviceInfo001
* @tc.desc: test UpdateAdvertiserDeviceInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, UpdateAdvertiserDeviceInfo001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest UpdateAdvertiserDeviceInfo001 Start");
    auto ret = UpdateAdvertiserDeviceInfo(1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest UpdateAdvertiserDeviceInfo001 End");
}

/*
* @tc.name: UpdateAdvertiserDeviceInfo002
* @tc.desc: test UpdateAdvertiserDeviceInfo
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, UpdateAdvertiserDeviceInfo002, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest UpdateAdvertiserDeviceInfo002 Start");
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
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest UpdateAdvertiserDeviceInfo002 End");
}

/*
* @tc.name: ProcessBleDiscFunc001
* @tc.desc: test ProcessBleDiscFunc
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, ProcessBleDiscFunc001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest ProcessBleDiscFunc001 Start");
    auto ret = ProcessBleDiscFunc(true, BLE_PUBLISH, BLE_ACTIVE, PUBLISH_ACTIVE_SERVICE, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest ProcessBleDiscFunc001 End");
}

/*
* @tc.name: ProcessBleDiscFunc002
* @tc.desc: test ProcessBleDiscFunc
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, ProcessBleDiscFunc002, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest ProcessBleDiscFunc002 Start");
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
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest ProcessBleDiscFunc002 End");
}

/*
* @tc.name: StartPassiveDiscovery001
* @tc.desc: test ProcessBleDiscFunc
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, StartPassiveDiscovery001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest ProcessBleDiscFunc001 Start");
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
    DiscSoftbusBleInit(&g_discInnerCallback);
    softBusMessage.what = START_PASSIVE_DISCOVERY;
    StartActiveDiscovery(&softBusMessage);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest ProcessBleDiscFunc001 End");
}

/*
* @tc.name: Recovery001
* @tc.desc: test Recovery
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, Recovery001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest Recovery001 Start");
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
    DiscSoftbusBleInit(&g_discInnerCallback);
    softBusMessage.what = RECOVERY;
    Recovery(&softBusMessage);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest Recovery001 End");
}

/*
* @tc.name: BleDiscTurnOff001
* @tc.desc: test BleDiscTurnOff
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BleDiscTurnOff001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleDiscTurnOff001 Start");
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
    DiscSoftbusBleInit(&g_discInnerCallback);
    softBusMessage.what = RECOVERY;
    BleDiscTurnOff(&softBusMessage);
    DiscBleDeinit();
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleDiscTurnOff001 End");
}

/*
* @tc.name: ReplyPassiveNonBroadcast001
* @tc.desc: test ReplyPassiveNonBroadcast
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, ReplyPassiveNonBroadcast001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest ReplyPassiveNonBroadcast001 Start");
    auto ret = ReplyPassiveNonBroadcast();
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest ReplyPassiveNonBroadcast001 End");
}

/*
* @tc.name: RemoveRecvMsgFunc001
* @tc.desc: test RemoveRecvMsgFunc
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, RemoveRecvMsgFunc001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest RemoveRecvMsgFunc001 Start");
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
    auto ret = RemoveRecvMsgFunc(&softBusMessage, (void*)&args);
    EXPECT_EQ(ret, 1);
    args = args + 1;
    auto ans = RemoveRecvMsgFunc(&softBusMessage, (void*)&args);
    EXPECT_EQ(ans, 1);
    softBusMessage.what = PROCESS_TIME_OUT;
    auto tmp = RemoveRecvMsgFunc(&softBusMessage, (void*)&args);
    EXPECT_EQ(tmp, 1);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest RemoveRecvMsgFunc001 End");
}

/*
* @tc.name: GetRecvMessage001
* @tc.desc: test GetRecvMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, GetRecvMessage001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest GetRecvMessage001 Start");
    auto ret = GetRecvMessage(nullptr);
    EXPECT_EQ(ret, nullptr);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest GetRecvMessage001 End");
}

/*
* @tc.name: MatchRecvMessage001
* @tc.desc: test MatchRecvMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, MatchRecvMessage001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest MatchRecvMessage001 Start");
    auto ret = MatchRecvMessage(nullptr, nullptr, 1);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest MatchRecvMessage001 End");
}

/*
* @tc.name: MatchRecvMessage002
* @tc.desc: test MatchRecvMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, MatchRecvMessage002, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest MatchRecvMessage002 Start");
    uint32_t publishInfo[] = { 0x1, 0xa };
    uint32_t capBitMap[] = { 0x1 };
    DiscSoftbusBleInit(&g_discInnerCallback);
    auto ret = MatchRecvMessage(publishInfo, capBitMap, 1);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest MatchRecvMessage002 End");
}

/*
* @tc.name: StartTimeout001
* @tc.desc: test StartTimeout
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, StartTimeout001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest StartTimeout001 Start");
    StartTimeout(nullptr);
    StartTimeout("123");
    DiscSoftbusBleInit(&g_discInnerCallback);
    StartTimeout("123");
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest StartTimeout001 End");
}

/*
* @tc.name: RemoveTimeout001
* @tc.desc: test RemoveTimeout
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, RemoveTimeout001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest RemoveTimeout001 Start");
    RemoveTimeout(nullptr);
    RemoveTimeout("123");
    DiscSoftbusBleInit(&g_discInnerCallback);
    RemoveTimeout("123");
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest RemoveTimeout001 End");
}

/*
* @tc.name: AddRecvMessage001
* @tc.desc: test AddRecvMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, AddRecvMessage001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest AddRecvMessage001 Start");
    SoftBusMutexInit(&g_recvMessageInfo.lock, nullptr);
    BleGattLockInit();
    SoftBusMutexInit(&g_bleInfoLock, nullptr);
    DiscSoftbusBleInit(&g_discInnerCallback);
    auto ret = AddRecvMessage(nullptr, nullptr, true);
    EXPECT_EQ (ret, SOFTBUS_INVALID_PARAM);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest AddRecvMessage001 End");
}

/*
* @tc.name: AddRecvMessage002
* @tc.desc: test AddRecvMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, AddRecvMessage002, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest AddRecvMessage002 Start");
    SoftBusMutexInit(&g_recvMessageInfo.lock, nullptr);
    BleGattLockInit();
    SoftBusMutexInit(&g_bleInfoLock, nullptr);
    uint32_t capbitmap[] = { 0x1 };
    auto ret = AddRecvMessage("123", capbitmap, true);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest AddRecvMessage002 End");
}

/*
* @tc.name: RemoveRecvMessage001
* @tc.desc: test RemoveRecvMessage
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, RemoveRecvMessage001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest RemoveRecvMessage001 Start");
    DiscSoftbusBleInit(&g_discInnerCallback);
    RemoveRecvMessage(0X01);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest RemoveRecvMessage001 End");
}

/*
* @tc.name: DiscBleMsgHandler001
* @tc.desc: test DiscBleMsgHandler
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, DiscBleMsgHandler001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest DiscBleMsgHandler001 Start");
    SoftBusMutexInit(&g_recvMessageInfo.lock, nullptr);
    BleGattLockInit();
    SoftBusMutexInit(&g_bleInfoLock, nullptr);
    SoftBusMessage softBusMessage = {
        .what = START_PASSIVE_DISCOVERY,
        .arg1 = 1,
        .arg2 = 2,
        .time = 12,
        .obj = nullptr,
        .handler = nullptr,
        .FreeMessage = nullptr,
    };
    softBusMessage.what = START_PASSIVE_DISCOVERY;
    DiscBleMsgHandler(&softBusMessage);
    softBusMessage.what = STOP_DISCOVERY;
    DiscBleMsgHandler(&softBusMessage);
    softBusMessage.what = REPLY_PASSIVE_NON_BROADCAST;
    DiscBleMsgHandler(&softBusMessage);
    softBusMessage.what = PROCESS_TIME_OUT;
    DiscBleMsgHandler(&softBusMessage);
    softBusMessage.what = RECOVERY;
    DiscBleMsgHandler(&softBusMessage);
    softBusMessage.what = TURN_OFF;
    DiscBleMsgHandler(&softBusMessage);
    softBusMessage.what = 20;
    DiscBleMsgHandler(&softBusMessage);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest DiscBleMsgHandler001 End");
}

/*
* @tc.name: BleInfoDump001
* @tc.desc: test BleInfoDump
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(SoftBusDiscBleTest, BleInfoDump001, TestSize.Level1)
{
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleInfoDump001 Start");
    DiscSoftbusBleInit(&g_discInnerCallback);
    BleInfoDump(9);
    SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "SoftBusDiscBleTest BleInfoDump001 End");
}
}