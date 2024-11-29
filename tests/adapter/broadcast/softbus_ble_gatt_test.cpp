/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "assert_helper.h"
#include "bluetooth_mock.h"
#include "c_header/ohos_bt_gatt.h"
#include "disc_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_ble_gatt.h"
#include "softbus_broadcast_type.h"
#include "softbus_error_code.h"

#define GATT_ADV_MAX_NUM  16
#define GATT_SCAN_MAX_NUM 2

using namespace testing::ext;
using ::testing::AtMost;
using ::testing::Return;

namespace OHOS {

class ScanResultCtx : public RecordCtx {
public:
    explicit ScanResultCtx(const char *identifier);
    ~ScanResultCtx();
    bool Update(int32_t scannerId, const SoftBusBcScanResult *reportData);
    testing::AssertionResult Expect(int32_t scannerId, const SoftBusBcScanResult *reportData);

private:
    SoftBusBcScanResult scanResult;
    void Reset();
};

class SoftbusBleGattTest : public testing::Test {
public:
    static ScanResultCtx scanResultCtx;

    static StRecordCtx advEnableCtx;
    static StRecordCtx advDisableCtx;
    static StRecordCtx advDataCtx;
    static StRecordCtx advUpdateCtx;
    static int32_t btInnerAdvId;

    static void SetUpTestCase(void);
};

ScanResultCtx SoftbusBleGattTest::scanResultCtx("OnReportScanDataCallback");

StRecordCtx SoftbusBleGattTest::advEnableCtx("AdvEnableCallback");
StRecordCtx SoftbusBleGattTest::advDisableCtx("AdvDisableCallback");
StRecordCtx SoftbusBleGattTest::advDataCtx("AdvDataCallback");
StRecordCtx SoftbusBleGattTest::advUpdateCtx("AdvUpdateCallback");
int32_t SoftbusBleGattTest::btInnerAdvId = -1;

void SoftbusBleGattTest::SetUpTestCase()
{
    MockBluetooth mocker;
    SoftbusBleAdapterInit();
    MockBluetooth::interface->Init();
}

static void StubOnScanResult(int32_t scannerId, const SoftBusBcScanResult *reportData)
{
    SoftbusBleGattTest::scanResultCtx.Update(scannerId, reportData);
}

static SoftbusScanCallback *GetStubScanListener()
{
    static SoftbusScanCallback listener = { .OnStartScanCallback = nullptr,
        .OnStopScanCallback = nullptr,
        .OnReportScanDataCallback = StubOnScanResult,
        .OnScanStateChanged = nullptr };
    return &listener;
}

static void StubAdvEnableCallback(int32_t advId, int32_t status)
{
    SoftbusBleGattTest::advEnableCtx.Update(advId, status);
}

static void StubAdvDisableCallback(int32_t advId, int32_t status)
{
    SoftbusBleGattTest::advDisableCtx.Update(advId, status);
}

static void StubAdvUpdateCallback(int32_t advId, int32_t status)
{
    SoftbusBleGattTest::advUpdateCtx.Update(advId, status);
}

static void StubAdvDataCallback(int32_t advId, int32_t status)
{
    SoftbusBleGattTest::advDataCtx.Update(advId, status);
}

SoftbusBroadcastCallback *GetStubAdvCallback()
{
    static SoftbusBroadcastCallback callback = {
        .OnStartBroadcastingCallback = StubAdvEnableCallback,
        .OnStopBroadcastingCallback = StubAdvDisableCallback,
        .OnUpdateBroadcastingCallback = StubAdvUpdateCallback,
        .OnSetBroadcastingCallback = StubAdvDataCallback,
    };
    return &callback;
}

static testing::AssertionResult PrepareScanListener(int32_t *scannerId)
{
    int32_t ret = MockBluetooth::interface->RegisterScanListener(scannerId, GetStubScanListener());
    if (ret != SOFTBUS_OK) {
        return testing::AssertionFailure() << "RegisterScanListener failed";
    }
    if (MockBluetooth::bleScanCallback == nullptr) {
        return testing::AssertionFailure() << "RegisterScanListener is not invoke";
    }
    return testing::AssertionSuccess();
}

static SoftBusBcScanFilter *CreateScanFilter()
{
    unsigned char serviceData[] = { 0xE, 0xE, 0xF, 0xF, 0x04, 0x05 };
    int32_t len = sizeof(serviceData);

    SoftBusBcScanFilter *filter = static_cast<SoftBusBcScanFilter *>(SoftBusCalloc(sizeof(SoftBusBcScanFilter)));
    unsigned char *serviceDataPtr = static_cast<unsigned char *>(SoftBusCalloc(len));
    unsigned char *serviceDataMaskPtr = static_cast<unsigned char *>(SoftBusCalloc(len));
    if (filter == nullptr || serviceDataPtr == nullptr || serviceDataMaskPtr == nullptr) {
        goto EXIT;
    }
    if (memcpy_s(serviceDataPtr, len, serviceData, len) != EOK) {
        goto EXIT;
    }
    if (memset_s(serviceDataMaskPtr, len, 0xFF, len) != EOK) {
        goto EXIT;
    }
    filter->serviceData = serviceDataPtr;
    filter->serviceDataMask = serviceDataMaskPtr;
    filter->serviceDataLength = len;
    return filter;
EXIT:
    SoftBusFree(filter);
    SoftBusFree(serviceDataPtr);
    SoftBusFree(serviceDataMaskPtr);
    return nullptr;
}

/**
 * @tc.name: TestSoftbusGattInit
 * @tc.desc: Test lnit will return SOFTBUS_OK when called more than once
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusGattInit001, TestSize.Level1)
{
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestSoftbusGattDeInit
 * @tc.desc: Test DeInit will return SOFTBUS_OK when called more than once
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusGattDeInit001, TestSize.Level1)
{
    int32_t ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestSoftbusRegisterAdvCb
 * @tc.desc: Test SoftbusRegisterAdvCb will return SOFTBUS_INVALID_PARAM when called more than once
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusRegisterAdvCb001, TestSize.Level1)
{
    int32_t ret = MockBluetooth::interface->RegisterBroadcaster(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

// 充当参数
static void FakeBcBleCallback(int32_t adapterBcld, int32_t status)
{
    (void)adapterBcld;
    (void)status;
}

static SoftbusBroadcastCallback g_softbusBcBleCbTest = {
    .OnStartBroadcastingCallback = FakeBcBleCallback,
    .OnStopBroadcastingCallback = FakeBcBleCallback,
    .OnUpdateBroadcastingCallback = FakeBcBleCallback,
    .OnSetBroadcastingCallback = FakeBcBleCallback,
};

/**
 * @tc.name: TestSoftbusRegisterAdvCb002
 * @tc.desc: Test SoftbusRegisterAdvCb will return SOFTBUS_LOCK_ERR when called more than once
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusRegisterAdvCb002, TestSize.Level1)
{
    int32_t advld = 0;
    int32_t ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/**
 * @tc.name: TestSoftbusRegisterAdvCb003
 * @tc.desc: Test SoftbusRegisterAdvCb will return OHOS_BT_STATUS_FAIL
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusRegisterAdvCb003, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t advld = 0;
    EXPECT_CALL(mocker, BleGattRegisterCallbacks).WillRepeatedly(Return(OHOS_BT_STATUS_FAIL));
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, OHOS_BT_STATUS_FAIL);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestSoftbusRegisterAdvCb004
 * @tc.desc: Test SoftbusRegisterAdvCb will return SOFTBUS_OK when BleGattRegisterCallbacks
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusRegisterAdvCb004, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t advld = 0;
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestSoftbusUnRegisterAdvCb001
 * @tc.desc: Test SoftbusUnRegisterAdvCb will return SOFTBUS_INVALID_PARAM when given invalid param
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusUnRegisterAdvCb001, TestSize.Level1)
{
    int32_t ret = MockBluetooth::interface->UnRegisterBroadcaster(GATT_ADV_MAX_NUM);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    int32_t advld = -1;
    ret = MockBluetooth::interface->UnRegisterBroadcaster(advld);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: TestSoftbusUnRegisterAdvCb002
 * @tc.desc: Test SoftbusUnRegisterAdvCb will return SOFTBUS_LOCK_ERR when never called init
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusUnRegisterAdvCb002, TestSize.Level1)
{
    int32_t advld = 0;
    int32_t ret = MockBluetooth::interface->UnRegisterBroadcaster(advld);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/**
 * @tc.name: TestSoftbusUnRegisterAdvCb003
 * @tc.desc: Test SoftbusUnRegisterAdvCb will return SOFTBUS_OK when given vaild param
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusUnRegisterAdvCb003, TestSize.Level1)
{
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t advld = 0;
    ret = MockBluetooth::interface->UnRegisterBroadcaster(advld);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->UnRegisterBroadcaster(advld);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestSoftbusRegisterScanCb001
 * @tc.desc: Test SoftbusRegisterScanCb will return SOFTBUS_INVALID_PARAM when given invalid param
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusRegisterScanCb001, TestSize.Level1)
{
    int32_t ret = MockBluetooth::interface->RegisterScanListener(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

// 充当参数
static void FakeScanCallback(int32_t adapterScanld, int32_t status)
{
    (void)adapterScanld;
    (void)status;
}

static void FakeReportScanDataCallback(int32_t adapterScanld, const SoftBusBcScanResult *reportData)
{
    (void)adapterScanld;
    (void)reportData;
}

static void FakeScanStateChanged(int32_t resultCode, bool isStartScan)
{
    (void)resultCode;
    (void)isStartScan;
}

static void FakeLpDeviceInfoCallback(const SoftbusBroadcastUuid *uuid, int32_t type, uint8_t *data, uint32_t dataSize)
{
    (void)uuid;
    (void)type;
    (void)data;
    (void)dataSize;
}

static SoftbusScanCallback g_softbusBcBleScanCbTest = {
    .OnStartScanCallback = FakeScanCallback,
    .OnStopScanCallback = FakeScanCallback,
    .OnReportScanDataCallback = FakeReportScanDataCallback,
    .OnScanStateChanged = FakeScanStateChanged,
    .OnLpDeviceInfoCallback = FakeLpDeviceInfoCallback,
};

/**
 * @tc.name: TestSoftbusRegisterScanCb002
 * @tc.desc: Test SoftbusRegisterScanCb will return SOFTBUS_LOCK_ERR when never called init
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusRegisterScanCb002, TestSize.Level1)
{
    int32_t scannerld = 0;
    int32_t ret = MockBluetooth::interface->RegisterScanListener(&scannerld, &g_softbusBcBleScanCbTest);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/**
 * @tc.name: TestSoftbusRegisterScanCb003
 * @tc.desc: Test SoftbusRegisterScanCb will return OHOS_BT_STATUS_FAIL
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusRegisterScanCb003, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t scannerld = 0;
    EXPECT_CALL(mocker, BleRegisterScanCallbacks).WillRepeatedly(Return(OHOS_BT_STATUS_FAIL));
    ret = MockBluetooth::interface->RegisterScanListener(&scannerld, &g_softbusBcBleScanCbTest);
    EXPECT_EQ(ret, OHOS_BT_STATUS_FAIL);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestSoftbusRegisterScanCb004
 * @tc.desc: Test SoftbusRegisterScanCb will return SOFTBUS_BC_ADAPTER_REGISTER_FAIL when scan channel are all uesd
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusRegisterScanCb004, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t scannerld = 0;
    EXPECT_CALL(mocker, BleRegisterScanCallbacks).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ret = MockBluetooth::interface->RegisterScanListener(&scannerld, &g_softbusBcBleScanCbTest);
    EXPECT_EQ(ret, OHOS_BT_STATUS_SUCCESS);

    ret = MockBluetooth::interface->RegisterScanListener(&scannerld, &g_softbusBcBleScanCbTest);
    EXPECT_EQ(ret, OHOS_BT_STATUS_SUCCESS);

    ret = MockBluetooth::interface->RegisterScanListener(&scannerld, &g_softbusBcBleScanCbTest);
    EXPECT_EQ(ret, SOFTBUS_BC_ADAPTER_REGISTER_FAIL);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestSoftbusUnRegisterScanCb001
 * @tc.desc: Test SoftbusUnRegisterScanCb will return SOFTBUS_INVALID_PARAM when given invalid param
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusUnRegisterScanCb001, TestSize.Level1)
{
    int32_t scannerld = -1;
    int32_t ret = MockBluetooth::interface->UnRegisterScanListener(GATT_SCAN_MAX_NUM);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = MockBluetooth::interface->UnRegisterScanListener(scannerld);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: TestSoftbusUnRegisterScanCb002
 * @tc.desc: Test SoftbusUnRegisterScanCb will return SOFTBUS_LOCK_ERR when never called init
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusUnRegisterScanCb002, TestSize.Level1)
{
    int32_t scannerld = 0;
    int32_t ret = MockBluetooth::interface->UnRegisterScanListener(scannerld);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/**
 * @tc.name: TestSoftbusUnRegisterScanCb003
 * @tc.desc: Test SoftbusUnRegisterScanCb will return SOFTBUS_OK when successfully unregistered
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusUnRegisterScanCb003, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t scannerld = 0;
    EXPECT_CALL(mocker, BleRegisterScanCallbacks).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ret = MockBluetooth::interface->UnRegisterScanListener(scannerld);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->UnRegisterScanListener(scannerld);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestSoftbusStartAdv001
 * @tc.desc: Test SoftbusStartAdv will return SOFTBUS_INVALID_PARAM when given invalid param
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusStartAdv001, TestSize.Level1)
{
    int32_t advld = 0;
    int32_t ret = MockBluetooth::interface->StartBroadcasting(advld, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

// SoftbusBroadcastData类型的数据填充
const char ADV_DATA_EXAMPLE[] = {
    0x02,
    0x01,
    0x02,
    0x15,
    0x16,
    0xEE,
    0xFD,
    0x04,
    0x05,
    0x90,
    0x00,
    0x00,
    0x04,
    0x00,
    0x18,
    0x33,
    0x39,
    0x36,
    0x62,
    0x33,
    0x61,
    0x33,
    0x31,
    0x21,
    0x00,
    0x02,
    0x0A,
    0xEF,
};
const unsigned char SCAN_RSP_DATA_EXAMPLE[] = { 0x03, 0xFF, 0x7D, 0x02 };

/**
 * @tc.name: TestSoftbusStartAdv002
 * @tc.desc: Test SoftbusStartAdv will return SOFTBUS_LOCK_ERR when never called init
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusStartAdv002, TestSize.Level1)
{
    int32_t advld = 0;
    SoftbusBroadcastParam params = {};
    SoftbusBroadcastData data = {};
    data.bcData.payloadLen = sizeof(ADV_DATA_EXAMPLE);
    data.bcData.payload = (uint8_t *)ADV_DATA_EXAMPLE;
    data.rspData.payloadLen = sizeof(SCAN_RSP_DATA_EXAMPLE);
    data.rspData.payload = (uint8_t *)SCAN_RSP_DATA_EXAMPLE;

    int32_t ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/**
 * @tc.name: TestSoftbusStartAdv003
 * @tc.desc: Test SoftbusStartAdv will return SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL when advld is not used
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusStartAdv003, TestSize.Level1)
{
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t advld = 0;
    SoftbusBroadcastParam params = {};
    SoftbusBroadcastData data = {};
    data.bcData.payloadLen = sizeof(ADV_DATA_EXAMPLE);
    data.bcData.payload = (uint8_t *)ADV_DATA_EXAMPLE;
    data.rspData.payloadLen = sizeof(SCAN_RSP_DATA_EXAMPLE);
    data.rspData.payload = (uint8_t *)SCAN_RSP_DATA_EXAMPLE;

    ret = MockBluetooth::interface->StartBroadcasting(GATT_ADV_MAX_NUM, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL);

    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestSoftbusStopAdv001
 * @tc.desc: Test SoftbusStopAdv will return SOFTBUS_LOCK_ERR when never called lnit
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusStopAdv001, TestSize.Level1)
{
    int32_t advld = 0;
    int32_t ret = MockBluetooth::interface->StopBroadcasting(advld);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/**
 * @tc.name: TestSoftbusStopAdv002
 * @tc.desc: Test SoftbusStopAdv will return SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL when advld never registed
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusStopAdv002, TestSize.Level1)
{
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->StopBroadcasting(GATT_ADV_MAX_NUM);
    EXPECT_EQ(ret, SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestSoftbusStopAdv004
 * @tc.desc: Test SoftbusStopAdv will return SOFTBUS_OK when advld has been registed
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusStopAdv004, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t advld = 0;
    EXPECT_CALL(mocker, BleRegisterScanCallbacks).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mocker, BleStopAdv).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ret = MockBluetooth::interface->StopBroadcasting(advld);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestSoftbusStopAdv005
 * @tc.desc: Test SoftbusStopAdv will return SOFTBUS_OK when advld has been stopped
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusStopAdv005, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t advld = 0;
    EXPECT_CALL(mocker, BleRegisterScanCallbacks).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mocker, BleStopAdv).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ret = MockBluetooth::interface->StopBroadcasting(advld);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->StopBroadcasting(advld);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestSoftbusSetAdvData001
 * @tc.desc: Test SoftbusSetAdvData will return SOFTBUS_INVALID_PARAM when given invalid param
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusSetAdvData001, TestSize.Level1)
{
    int32_t advld = 0;
    int32_t ret = MockBluetooth::interface->SetBroadcastingData(advld, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: TestSoftbusSetAdvData002
 * @tc.desc: Test SoftbusSetAdvData will return SOFTBUS_LOCK_ERR when never lnit
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusSetAdvData002, TestSize.Level1)
{
    int32_t advld = 0;
    SoftbusBroadcastData data = {};
    data.bcData.payloadLen = sizeof(ADV_DATA_EXAMPLE);
    data.bcData.payload = (uint8_t *)ADV_DATA_EXAMPLE;
    data.rspData.payloadLen = sizeof(SCAN_RSP_DATA_EXAMPLE);
    data.rspData.payload = (uint8_t *)SCAN_RSP_DATA_EXAMPLE;

    int32_t ret = MockBluetooth::interface->SetBroadcastingData(advld, &data);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/**
 * @tc.name: TestSoftbusSetAdvData003
 * @tc.desc: Test SoftbusSetAdvData will return SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL when advld is not used
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusSetAdvData003, TestSize.Level1)
{
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusBroadcastData data = {};
    data.bcData.payloadLen = sizeof(ADV_DATA_EXAMPLE);
    data.bcData.payload = (uint8_t *)ADV_DATA_EXAMPLE;
    data.rspData.payloadLen = sizeof(SCAN_RSP_DATA_EXAMPLE);
    data.rspData.payload = (uint8_t *)SCAN_RSP_DATA_EXAMPLE;

    ret = MockBluetooth::interface->SetBroadcastingData(GATT_ADV_MAX_NUM, &data);
    EXPECT_EQ(ret, SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestSoftbusSetAdvData005
 * @tc.desc: Test SoftbusSetAdvData will return SOFTBUS_ALREADY_TRIGGERED when broadcast has already registed
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusSetAdvData005, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t advld = 0;
    EXPECT_CALL(mocker, BleGattRegisterCallbacks).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusBroadcastData data = {};
    data.bcData.payloadLen = sizeof(ADV_DATA_EXAMPLE);
    data.bcData.payload = (uint8_t *)ADV_DATA_EXAMPLE;
    data.rspData.payloadLen = sizeof(SCAN_RSP_DATA_EXAMPLE);
    data.rspData.payload = (uint8_t *)SCAN_RSP_DATA_EXAMPLE;

    ret = MockBluetooth::interface->SetBroadcastingData(advld, &data);
    EXPECT_EQ(ret, SOFTBUS_ALREADY_TRIGGERED);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestSoftbusUpdateAdvData001
 * @tc.desc: Test SoftbusUpdateAdvData will return SOFTBUS_LOCK_ERR when never called init
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusUpdateAdvData001, TestSize.Level1)
{
    int32_t advld = 0;
    int32_t ret = MockBluetooth::interface->UpdateBroadcasting(advld, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/**
 * @tc.name: TestSoftbusUpdateAdvData002
 * @tc.desc: Test SoftbusUpdateAdvData will return SOFTBUS_INVALID_PARAM when given invalid params
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusUpdateAdvData002, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t advld = 0;
    EXPECT_CALL(mocker, BleGattRegisterCallbacks).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mocker, BleStopAdv).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ret = MockBluetooth::interface->UpdateBroadcasting(advld, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestSoftbusStartScan001
 * @tc.desc: Test SoftbusStartScan will return SOFTBUS_INVALID_PARAM when given invalid params
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusStartScan001, TestSize.Level1)
{
    int32_t scannerld = 0;
    int32_t ret = MockBluetooth::interface->StartScan(scannerld, nullptr, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: TestSoftbusStartScan002
 * @tc.desc: Test SoftbusStartScan will return SOFTBUS_LOCK_ERR when never called init
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusStartScan002, TestSize.Level1)
{
    SoftBusBcScanParams scanParam = {
        .scanInterval = SOFTBUS_BC_SCAN_WINDOW_P10,
        .scanWindow = SOFTBUS_BC_SCAN_INTERVAL_P10,
        .scanType = SOFTBUS_BC_SCAN_TYPE_ACTIVE,
        .scanPhy = SOFTBUS_BC_SCAN_PHY_1M,
        .scanFilterPolicy = SOFTBUS_BC_SCAN_FILTER_POLICY_ACCEPT_ALL,
    };

    SoftBusBcScanFilter softBusBcScanFilter = {};
    softBusBcScanFilter.address = (int8_t *)"address";
    softBusBcScanFilter.deviceName = (int8_t *)"deviceName";
    softBusBcScanFilter.serviceUuid = 1;
    softBusBcScanFilter.serviceDataLength = 1;
    softBusBcScanFilter.manufactureId = 1;
    softBusBcScanFilter.manufactureDataLength = 1;

    int32_t scannerld = 0;
    int32_t filterSize = 1;
    int32_t ret = MockBluetooth::interface->StartScan(scannerld, &scanParam, &softBusBcScanFilter, filterSize);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/**
 * @tc.name: TestSoftbusStartScan003
 * @tc.desc: Test SoftbusStartScan will return SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL when given invalid params scannerld
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusStartScan003, TestSize.Level1)
{
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusBcScanParams scanParam = {
        .scanInterval = SOFTBUS_BC_SCAN_WINDOW_P10,
        .scanWindow = SOFTBUS_BC_SCAN_INTERVAL_P10,
        .scanType = SOFTBUS_BC_SCAN_TYPE_ACTIVE,
        .scanPhy = SOFTBUS_BC_SCAN_PHY_1M,
        .scanFilterPolicy = SOFTBUS_BC_SCAN_FILTER_POLICY_ACCEPT_ALL,
    };

    SoftBusBcScanFilter softBusBcScanFilter = {};
    softBusBcScanFilter.address = (int8_t *)"address";
    softBusBcScanFilter.deviceName = (int8_t *)"deviceName";
    softBusBcScanFilter.serviceUuid = 1;
    softBusBcScanFilter.serviceDataLength = 1;
    softBusBcScanFilter.manufactureId = 1;
    softBusBcScanFilter.manufactureDataLength = 1;

    int32_t filterSize = 1;
    ret = MockBluetooth::interface->StartScan(GATT_SCAN_MAX_NUM, &scanParam, &softBusBcScanFilter, filterSize);
    EXPECT_EQ(ret, SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusGetBroadcastHandle001
 * @tc.desc: Test SoftbusGetBroadcastHandle is  SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusGetBroadcastHandle001, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t bchand = 0;

    ret = MockBluetooth::interface->GetBroadcastHandle(GATT_ADV_MAX_NUM, &bchand);
    EXPECT_EQ(ret, SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusGetBroadcastHandle002
 * @tc.desc: Test SoftbusGetBroadcastHandle is  SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusGetBroadcastHandle002, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t advld = 0;
    int32_t bchand = 0;

    EXPECT_CALL(mocker, BleRegisterScanCallbacks).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mocker, GetAdvHandle).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ret = MockBluetooth::interface->GetBroadcastHandle(advld, &bchand);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusEnableSyncDataToLp
 * @tc.desc: Test SoftbusEnableSyncDataToLp is  SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusEnableSyncDataToLp, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mocker, EnableSyncDataToLpDevice).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ret = MockBluetooth::interface->EnableSyncDataToLpDevice();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusDisableSyncDataToLp
 * @tc.desc: Test DisableSyncDataToLpDevice is  SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, DisableSyncDataToLpDevice, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mocker, DisableSyncDataToLpDevice).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ret = MockBluetooth::interface->DisableSyncDataToLpDevice();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusSetScanReportChanToLp001
 * @tc.desc: Test SoftbusSetScanReportChanToLp is  SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusSetScanReportChanToLp001, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->SetScanReportChannelToLpDevice(GATT_ADV_MAX_NUM, false);
    EXPECT_EQ(ret, SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusSetLpAdvParam
 * @tc.desc: Test SoftbusSetLpAdvParam is  SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusSetLpAdvParam, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t duration = 0;
    int32_t maxExtAdvEvents = 0;
    int32_t window = 0;
    int32_t interval = 0;
    int32_t bcHandle = 0;

    EXPECT_CALL(mocker, SetLpDeviceAdvParam).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ret = MockBluetooth::interface->SetLpDeviceParam(duration, maxExtAdvEvents, window, interval, bcHandle);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusStopScan001
 * @tc.desc: Test SoftbusStopScan is  SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusStopScan001, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->StopScan(GATT_ADV_MAX_NUM);
    EXPECT_EQ(ret, SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestWrapperAdvEnableCb
 * @tc.desc: Test WrapperAdvEnableCb
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestWrapperAdvEnableCb, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "TestWrapperAdvEnableCb enter");
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t advld = 0;

    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    MockBluetooth::btGattCallback->advDataCb(advld, 1);

    MockBluetooth::btGattCallback->advUpdateCb(advld, 1);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestWrapperScanStateChangeCb0
 * @tc.desc: Test WrapperScanStateChangeCb0
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestWrapperScanStateChangeCb0, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "TestWrapperAdvEnableCb enter");
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t scannerld = 0;

    ret = MockBluetooth::interface->RegisterScanListener(&scannerld, &g_softbusBcBleScanCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    MockBluetooth::bleScanCallback->scanStateChangeCb(scannerld, true);
    MockBluetooth::bleScanCallback->scanStateChangeCb(scannerld, false);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestWrapperLpDeviceInfoCb
 * @tc.desc: Test WrapperLpDeviceInfoCb
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestWrapperLpDeviceInfoCb, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "TestWrapperAdvEnableCb enter");
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t scannerld = 0;
    BtUuid uuid = {};
    int32_t type = 0;
    uint8_t data = 0;
    uint32_t dataSize = 0;

    ret = MockBluetooth::interface->RegisterScanListener(&scannerld, &g_softbusBcBleScanCbTest);
    EXPECT_EQ(ret, SOFTBUS_BC_ADAPTER_REGISTER_FAIL);

    MockBluetooth::bleScanCallback->lpDeviceInfoCb(&uuid, type, &data, dataSize);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestIsLpAvailable
 * @tc.desc: Test IsLpAvailable
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestIsLpAvailable, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->IsLpDeviceAvailable();
    EXPECT_EQ(ret, false);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TestSoftbusSetLpParam
 * @tc.desc: Test SoftbusSetLpParam
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, TestSoftbusSetLpParam, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusLpBroadcastParam bcParam = {};
    SoftBusLpScanParam scanParam = {};

    ret = MockBluetooth::interface->SetAdvFilterParam(SOFTBUS_BURST_TYPE, &bcParam, &scanParam);
    EXPECT_EQ(ret, false);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattTest_RegisterScanListener
 * @tc.desc: test register scan listener
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, RegisterScanListener, TestSize.Level3)
{
    MockBluetooth mocker;
    int32_t scannerId = -1;
    ASSERT_EQ(MockBluetooth::interface->RegisterScanListener(&scannerId, nullptr), SOFTBUS_INVALID_PARAM);
    int32_t scanListerIds[GATT_SCAN_MAX_NUM] = {};
    int32_t ret = SOFTBUS_ERR;
    for (size_t i = 0; i < GATT_SCAN_MAX_NUM; i++) {
        ret = MockBluetooth::interface->RegisterScanListener(&scanListerIds[i], GetStubScanListener());
        ASSERT_EQ(ret, SOFTBUS_LOCK_ERR);
    }

    ASSERT_EQ(MockBluetooth::interface->RegisterScanListener(&scannerId, GetStubScanListener()), SOFTBUS_LOCK_ERR);

    for (size_t i = 0; i < GATT_SCAN_MAX_NUM; i++) {
        ASSERT_EQ(MockBluetooth::interface->UnRegisterScanListener(scanListerIds[i]), SOFTBUS_LOCK_ERR);
    }
}

/**
 * @tc.name: AdapterBleGattTest_UnRegisterScanListener
 * @tc.desc: test unregister scan listener
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, UnRegisterScanListener, TestSize.Level3)
{
    MockBluetooth mocker;
    int32_t scannerId = -1;
    auto result = PrepareScanListener(&scannerId);

    ASSERT_EQ(MockBluetooth::interface->UnRegisterScanListener(-1), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(MockBluetooth::interface->UnRegisterScanListener(GATT_SCAN_MAX_NUM), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(MockBluetooth::interface->UnRegisterScanListener(scannerId), SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: AdapterBleGattTest_ScanLifecycle
 * @tc.desc: test complete scan life cycle
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, ScanLifecycle, TestSize.Level3)
{
    MockBluetooth mocker;
    int32_t scannerId = -1;
    auto result = PrepareScanListener(&scannerId);

    auto filter = CreateScanFilter();
    ASSERT_NE(filter, nullptr);

    SoftBusBcScanParams scanParam = {
        .scanInterval = SOFTBUS_BC_SCAN_WINDOW_P10,
        .scanWindow = SOFTBUS_BC_SCAN_INTERVAL_P10,
        .scanType = SOFTBUS_BC_SCAN_TYPE_ACTIVE,
        .scanPhy = SOFTBUS_BC_SCAN_PHY_1M,
        .scanFilterPolicy = SOFTBUS_BC_SCAN_FILTER_POLICY_ACCEPT_ALL,
    };

    EXPECT_CALL(mocker, BleStartScanEx).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ASSERT_EQ(MockBluetooth::interface->StartScan(scannerId, &scanParam, filter, 1), SOFTBUS_LOCK_ERR);

    EXPECT_CALL(mocker, BleStopScan).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ASSERT_EQ(MockBluetooth::interface->StopScan(scannerId), SOFTBUS_LOCK_ERR);

    ASSERT_EQ(MockBluetooth::interface->UnRegisterScanListener(scannerId), SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: AdapterBleGattTest_ScanResultCb
 * @tc.desc: test scan result callback
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, ScanResultCb, TestSize.Level3)
{
    MockBluetooth mocker;
    int32_t scannerId = -1;
    auto result = PrepareScanListener(&scannerId);

    auto filter = CreateScanFilter();
    ASSERT_NE(filter, nullptr);

    SoftBusBcScanParams scanParam = {
        .scanInterval = SOFTBUS_BC_SCAN_WINDOW_P10,
        .scanWindow = SOFTBUS_BC_SCAN_INTERVAL_P10,
        .scanType = SOFTBUS_BC_SCAN_TYPE_ACTIVE,
        .scanPhy = SOFTBUS_BC_SCAN_PHY_1M,
        .scanFilterPolicy = SOFTBUS_BC_SCAN_FILTER_POLICY_ACCEPT_ALL,
    };

    EXPECT_CALL(mocker, BleStartScanEx).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ASSERT_EQ(MockBluetooth::interface->StartScan(scannerId, nullptr, filter, 1), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(MockBluetooth::interface->StartScan(scannerId, &scanParam, nullptr, 1), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(MockBluetooth::interface->StartScan(scannerId, &scanParam, filter, 0), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(MockBluetooth::interface->StartScan(scannerId, &scanParam, filter, 1), SOFTBUS_LOCK_ERR);

    const unsigned char scanDataExample[] = { 0x02, 0x01, 0x02, 0x15, 0x16, 0xEE, 0xFD, 0x04, 0x05, 0x90, 0x00, 0x00,
        0x04, 0x00, 0x18, 0x33, 0x39, 0x36, 0x62, 0x33, 0x61, 0x33, 0x31, 0x21, 0x00, 0x02, 0x0A, 0xEF, 0x03, 0xFF,
        0x7D, 0x02 };
    SoftBusBcScanResult expectScanResult = { 0 };
    expectScanResult.data.bcData.payloadLen = sizeof(scanDataExample);
    expectScanResult.data.bcData.payload = (unsigned char *)scanDataExample;
    BtScanResultData mockScanResult = { 0 };
    mockScanResult.advLen = sizeof(scanDataExample);
    mockScanResult.advData = (unsigned char *)scanDataExample;

    mockScanResult.eventType = OHOS_BLE_EVT_NON_CONNECTABLE_NON_SCANNABLE;
    mockScanResult.dataStatus = OHOS_BLE_DATA_COMPLETE;
    mockScanResult.addrType = OHOS_BLE_PUBLIC_DEVICE_ADDRESS;
    mockScanResult.primaryPhy = OHOS_BLE_SCAN_PHY_NO_PACKET;
    mockScanResult.secondaryPhy = OHOS_BLE_SCAN_PHY_NO_PACKET;
    mockScanResult.directAddrType = OHOS_BLE_PUBLIC_DEVICE_ADDRESS;
    ASSERT_FALSE(scanResultCtx.Expect(scannerId, &expectScanResult));

    mockScanResult.eventType = OHOS_BLE_EVT_NON_CONNECTABLE_NON_SCANNABLE_DIRECTED;
    mockScanResult.dataStatus = OHOS_BLE_DATA_INCOMPLETE_MORE_TO_COME;
    mockScanResult.addrType = OHOS_BLE_RANDOM_DEVICE_ADDRESS;
    mockScanResult.primaryPhy = OHOS_BLE_SCAN_PHY_1M;
    mockScanResult.secondaryPhy = OHOS_BLE_SCAN_PHY_1M;
    mockScanResult.directAddrType = OHOS_BLE_RANDOM_DEVICE_ADDRESS;
    ASSERT_FALSE(scanResultCtx.Expect(scannerId, &expectScanResult));
}

/**
 * @tc.name: AdapterBleGattTest_RegisterBroadcaster
 * @tc.desc: test register adv callback
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, RegisterBroadcaster, TestSize.Level3)
{
    int32_t advId = -1;
    ASSERT_EQ(MockBluetooth::interface->RegisterBroadcaster(&advId, nullptr), SOFTBUS_INVALID_PARAM);
    int32_t advIds[GATT_ADV_MAX_NUM];
    for (size_t i = 0; i < GATT_ADV_MAX_NUM; i++) {
        ASSERT_EQ(MockBluetooth::interface->RegisterBroadcaster(&advIds[i], GetStubAdvCallback()), SOFTBUS_LOCK_ERR);
    }
    ASSERT_EQ(MockBluetooth::interface->RegisterBroadcaster(&advId, GetStubAdvCallback()), SOFTBUS_LOCK_ERR);
    for (size_t i = 0; i < GATT_ADV_MAX_NUM; i++) {
        ASSERT_EQ(MockBluetooth::interface->UnRegisterBroadcaster(advIds[i]), SOFTBUS_LOCK_ERR);
    }
}

ScanResultCtx::ScanResultCtx(const char *identifier) : RecordCtx(identifier)
{
    Reset();
}
ScanResultCtx::~ScanResultCtx()
{
    Reset();
}

void ScanResultCtx::Reset()
{
    SoftBusFree(scanResult.data.bcData.payload);
    SoftBusFree(scanResult.data.rspData.payload);
    scanResult.data.bcData.payload = nullptr;
    scanResult.data.rspData.payload = nullptr;
}

bool ScanResultCtx::Update(int32_t id, const SoftBusBcScanResult *scanResult)
{
    if (!RecordCtx::Update(id)) {
        return false;
    }
    this->scanResult = *scanResult;
    unsigned char *cpyAdvData = static_cast<unsigned char *>(SoftBusCalloc(this->scanResult.data.bcData.payloadLen));
    if (cpyAdvData == nullptr) {
        DISC_LOGE(DISC_TEST, "malloc failed in OnReportScanDataCallback, can not save ctx, id=%{public}d", id);
        return false;
    }

    if (memcpy_s(cpyAdvData, this->scanResult.data.bcData.payloadLen, scanResult->data.bcData.payload,
        scanResult->data.bcData.payloadLen) != EOK) {
        DISC_LOGE(DISC_TEST, "malloc failed in OnReportScanDataCallback, can not save ctx, id=%{public}d", id);
        SoftBusFree(cpyAdvData);
        return false;
    }
    this->scanResult.data.bcData.payload = cpyAdvData;
    return true;
}

testing::AssertionResult ScanResultCtx::Expect(int32_t id, const SoftBusBcScanResult *scanResultParam)
{
    auto result = RecordCtx::Expect(id);
    if (!result) {
        goto ClEANUP;
    }

    if (this->scanResult.data.bcData.payloadLen == scanResultParam->data.bcData.payloadLen &&
        memcmp(this->scanResult.data.bcData.payload, scanResultParam->data.bcData.payload,
            scanResultParam->data.bcData.payloadLen) == 0) {
        result = testing::AssertionSuccess();
        goto ClEANUP;
    }
    result = testing::AssertionFailure() << identifier << " is call by unexpectedly scan result.";
ClEANUP:
    Reset();
    return result;
}

} // namespace OHOS