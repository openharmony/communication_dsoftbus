/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "assert_helper.h"
#include "bluetooth_mock.h"
#include "c_header/ohos_bt_gatt.h"
#include "disc_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_ble_gatt_public.h"
#include "softbus_broadcast_type.h"
#include "softbus_error_code.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#define GATT_ADV_MAX_NUM  20

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
    static int32_t g_status;
    static int32_t g_adapterBcld;

    static void SetUpTestCase(void);
};

ScanResultCtx SoftbusBleGattTest::scanResultCtx("OnReportScanDataCallback");

StRecordCtx SoftbusBleGattTest::advEnableCtx("AdvEnableCallback");
StRecordCtx SoftbusBleGattTest::advDisableCtx("AdvDisableCallback");
StRecordCtx SoftbusBleGattTest::advDataCtx("AdvDataCallback");
StRecordCtx SoftbusBleGattTest::advUpdateCtx("AdvUpdateCallback");
int32_t SoftbusBleGattTest::btInnerAdvId = -1;
int32_t SoftbusBleGattTest::g_status = -1;
int32_t SoftbusBleGattTest::g_adapterBcld = -1;

void SoftbusBleGattTest::SetUpTestCase()
{
    MockBluetooth mocker;
    SoftbusBleAdapterInit();
    ASSERT_NE(MockBluetooth::interface, nullptr);
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
 * @tc.name: SoftbusGattInit001
 * @tc.desc: Test lnit will return SOFTBUS_OK when called more than once
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusGattInit001, TestSize.Level1)
{
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusGattDeInit001
 * @tc.desc: Test DeInit will return SOFTBUS_OK when called more than once
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusGattDeInit001, TestSize.Level1)
{
    int32_t ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusRegisterAdvCb001
 * @tc.desc: Test SoftbusRegisterAdvCb will return SOFTBUS_INVALID_PARAM when called more than once
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusRegisterAdvCb001, TestSize.Level1)
{
    int32_t ret = MockBluetooth::interface->RegisterBroadcaster(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

// 充当参数
static void FakeBcBleCallback(int32_t adapterBcld, int32_t status)
{
    SoftbusBleGattTest::g_adapterBcld = adapterBcld;
    SoftbusBleGattTest::g_status = status;
}

static SoftbusBroadcastCallback g_softbusBcBleCbTest = {
    .OnStartBroadcastingCallback = FakeBcBleCallback,
    .OnStopBroadcastingCallback = FakeBcBleCallback,
    .OnUpdateBroadcastingCallback = FakeBcBleCallback,
    .OnSetBroadcastingCallback = FakeBcBleCallback,
    .OnSetBroadcastingParamCallback = FakeBcBleCallback,
    .OnDisableBroadcastingCallback = FakeBcBleCallback,
    .OnEnableBroadcastingCallback = FakeBcBleCallback,
};

/**
 * @tc.name: SoftbusRegisterAdvCb002
 * @tc.desc: Test SoftbusRegisterAdvCb will return SOFTBUS_LOCK_ERR when called more than once
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusRegisterAdvCb002, TestSize.Level1)
{
    int32_t advld = 0;
    int32_t ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/**
 * @tc.name: SoftbusRegisterAdvCb003
 * @tc.desc: Test SoftbusRegisterAdvCb will return OHOS_BT_STATUS_FAIL
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusRegisterAdvCb003, TestSize.Level1)
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
 * @tc.name: SoftbusRegisterAdvCb004
 * @tc.desc: Test SoftbusRegisterAdvCb will return SOFTBUS_OK when BleGattRegisterCallbacks
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusRegisterAdvCb004, TestSize.Level1)
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
 * @tc.name: SoftbusUnRegisterAdvCb001
 * @tc.desc: Test SoftbusUnRegisterAdvCb will return SOFTBUS_INVALID_PARAM when given invalid param
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusUnRegisterAdvCb001, TestSize.Level1)
{
    int32_t ret = MockBluetooth::interface->UnRegisterBroadcaster(GATT_ADV_MAX_NUM);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    int32_t advld = -1;
    ret = MockBluetooth::interface->UnRegisterBroadcaster(advld);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: SoftbusUnRegisterAdvCb002
 * @tc.desc: Test SoftbusUnRegisterAdvCb will return SOFTBUS_LOCK_ERR when never called init
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusUnRegisterAdvCb002, TestSize.Level1)
{
    int32_t advld = 0;
    int32_t ret = MockBluetooth::interface->UnRegisterBroadcaster(advld);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/**
 * @tc.name: SoftbusUnRegisterAdvCb003
 * @tc.desc: Test SoftbusUnRegisterAdvCb will return SOFTBUS_OK when given vaild param
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusUnRegisterAdvCb003, TestSize.Level1)
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
 * @tc.name: SoftbusRegisterScanCb001
 * @tc.desc: Test SoftbusRegisterScanCb will return SOFTBUS_INVALID_PARAM when given invalid param
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusRegisterScanCb001, TestSize.Level1)
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
 * @tc.name: SoftbusRegisterScanCb002
 * @tc.desc: Test SoftbusRegisterScanCb will return SOFTBUS_LOCK_ERR when never called init
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusRegisterScanCb002, TestSize.Level1)
{
    int32_t scannerld = 0;
    int32_t ret = MockBluetooth::interface->RegisterScanListener(&scannerld, &g_softbusBcBleScanCbTest);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/**
 * @tc.name: SoftbusRegisterScanCb003
 * @tc.desc: Test SoftbusRegisterScanCb will return OHOS_BT_STATUS_FAIL
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusRegisterScanCb003, TestSize.Level1)
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
 * @tc.name: SoftbusRegisterScanCb004
 * @tc.desc: Test SoftbusRegisterScanCb will return SOFTBUS_BC_ADAPTER_REGISTER_FAIL when scan channel are all uesd
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusRegisterScanCb004, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t scannerld = 0;
    EXPECT_CALL(mocker, BleRegisterScanCallbacks).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));

    for (size_t i = 0; i < GATT_SCAN_MAX_NUM; i++) {
        ret = MockBluetooth::interface->RegisterScanListener(&scannerld, &g_softbusBcBleScanCbTest);
        EXPECT_EQ(ret, OHOS_BT_STATUS_SUCCESS);
    }

    ret = MockBluetooth::interface->RegisterScanListener(&scannerld, &g_softbusBcBleScanCbTest);
    EXPECT_EQ(ret, SOFTBUS_BC_ADAPTER_REGISTER_FAIL);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusUnRegisterScanCb001
 * @tc.desc: Test SoftbusUnRegisterScanCb will return SOFTBUS_INVALID_PARAM when given invalid param
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusUnRegisterScanCb001, TestSize.Level1)
{
    int32_t scannerld = -1;
    int32_t ret = MockBluetooth::interface->UnRegisterScanListener(GATT_SCAN_MAX_NUM);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = MockBluetooth::interface->UnRegisterScanListener(scannerld);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: SoftbusUnRegisterScanCb002
 * @tc.desc: Test SoftbusUnRegisterScanCb will return SOFTBUS_LOCK_ERR when never called init
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusUnRegisterScanCb002, TestSize.Level1)
{
    int32_t scannerld = 0;
    int32_t ret = MockBluetooth::interface->UnRegisterScanListener(scannerld);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/**
 * @tc.name: SoftbusUnRegisterScanCb003
 * @tc.desc: Test SoftbusUnRegisterScanCb will return SOFTBUS_OK when successfully unregistered
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusUnRegisterScanCb003, TestSize.Level1)
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
 * @tc.name: SoftbusStartAdv001
 * @tc.desc: Test SoftbusStartAdv will return SOFTBUS_INVALID_PARAM when given invalid param
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusStartAdv001, TestSize.Level1)
{
    int32_t advld = 0;
    int32_t ret = MockBluetooth::interface->StartBroadcasting(advld, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

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

static SoftbusBroadcastData BuildBcData(void)
{
    SoftbusBroadcastData data = {};
    data.bcData.payloadLen = sizeof(ADV_DATA_EXAMPLE);
    data.bcData.payload = (uint8_t *)ADV_DATA_EXAMPLE;
    data.rspData.payloadLen = sizeof(SCAN_RSP_DATA_EXAMPLE);
    data.rspData.payload = (uint8_t *)SCAN_RSP_DATA_EXAMPLE;
    return data;
}

/**
 * @tc.name: SoftbusStartAdv002
 * @tc.desc: Test SoftbusStartAdv will return SOFTBUS_LOCK_ERR when never called init
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusStartAdv002, TestSize.Level1)
{
    int32_t advld = 0;
    SoftbusBroadcastParam params = {};
    SoftbusBroadcastData data = BuildBcData();

    int32_t ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/**
 * @tc.name: SoftbusStartAdv003
 * @tc.desc: Test SoftbusStartAdv will return SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL when advld is not used
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusStartAdv003, TestSize.Level1)
{
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t advld = 0;
    SoftbusBroadcastParam params = {};
    SoftbusBroadcastData data = BuildBcData();

    ret = MockBluetooth::interface->StartBroadcasting(GATT_ADV_MAX_NUM, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL);

    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusStartAdv004
 * @tc.desc: Test SoftbusStartAdv will return SOFTBUS_ALREADY_TRIGGERED
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusStartAdv004, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t advld = 0;
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    EXPECT_CALL(mocker, BleStartAdvEx).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    SoftbusBroadcastParam params = {};
    SoftbusBroadcastData data = BuildBcData();

    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_ALREADY_TRIGGERED);
    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusStopAdv001
 * @tc.desc: Test SoftbusStopAdv will return SOFTBUS_LOCK_ERR when never called lnit
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusStopAdv001, TestSize.Level1)
{
    int32_t advld = 0;
    int32_t ret = MockBluetooth::interface->StopBroadcasting(advld);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/**
 * @tc.name: SoftbusStopAdv002
 * @tc.desc: Test SoftbusStopAdv will return SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL when advld never registed
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusStopAdv002, TestSize.Level1)
{
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->StopBroadcasting(GATT_ADV_MAX_NUM);
    EXPECT_EQ(ret, SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusStopAdv004
 * @tc.desc: Test SoftbusStopAdv will return SOFTBUS_OK when advld has been registed
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusStopAdv004, TestSize.Level1)
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
 * @tc.name: SoftbusStopAdv005
 * @tc.desc: Test SoftbusStopAdv will return SOFTBUS_OK when advld has been stopped
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusStopAdv005, TestSize.Level1)
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
 * @tc.name: SoftbusSetAdvData001
 * @tc.desc: Test SoftbusSetAdvData will return SOFTBUS_INVALID_PARAM when given invalid param
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusSetAdvData001, TestSize.Level1)
{
    int32_t advld = 0;
    int32_t ret = MockBluetooth::interface->SetBroadcastingData(advld, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: SoftbusSetAdvData002
 * @tc.desc: Test SoftbusSetAdvData will return SOFTBUS_LOCK_ERR when never lnit
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusSetAdvData002, TestSize.Level1)
{
    int32_t advld = 0;
    SoftbusBroadcastData data = BuildBcData();

    int32_t ret = MockBluetooth::interface->SetBroadcastingData(advld, &data);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/**
 * @tc.name: SoftbusSetAdvData003
 * @tc.desc: Test SoftbusSetAdvData will return SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL when advld is not used
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusSetAdvData003, TestSize.Level1)
{
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusBroadcastData data = BuildBcData();
    ret = MockBluetooth::interface->SetBroadcastingData(GATT_ADV_MAX_NUM, &data);
    EXPECT_EQ(ret, SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusSetAdvData005
 * @tc.desc: Test SoftbusSetAdvData will return SOFTBUS_ALREADY_TRIGGERED when broadcast has already registed
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusSetAdvData005, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t advld = 0;
    EXPECT_CALL(mocker, BleGattRegisterCallbacks).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusBroadcastData data = BuildBcData();
    ret = MockBluetooth::interface->SetBroadcastingData(advld, &data);
    EXPECT_EQ(ret, SOFTBUS_ALREADY_TRIGGERED);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusUpdateAdvData001
 * @tc.desc: Test SoftbusUpdateAdvData will return SOFTBUS_LOCK_ERR when never called init
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusUpdateAdvData001, TestSize.Level1)
{
    int32_t advld = 0;
    SoftbusBroadcastParam param;
    SoftbusBroadcastData packet;
    int32_t ret = MockBluetooth::interface->UpdateBroadcasting(advld, &param, &packet);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/**
 * @tc.name: SoftbusUpdateAdvData002
 * @tc.desc: Test SoftbusUpdateAdvData will return SOFTBUS_INVALID_PARAM when given invalid params
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusUpdateAdvData002, TestSize.Level1)
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
 * @tc.name: SoftbusStartScan001
 * @tc.desc: Test SoftbusStartScan will return SOFTBUS_INVALID_PARAM when given invalid params
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusStartScan001, TestSize.Level1)
{
    int32_t scannerld = 0;
    int32_t ret = MockBluetooth::interface->StartScan(scannerld, nullptr, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: SoftbusStartScan002
 * @tc.desc: Test SoftbusStartScan will return SOFTBUS_LOCK_ERR when never called init
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusStartScan002, TestSize.Level1)
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
 * @tc.name: SoftbusStartScan003
 * @tc.desc: Test SoftbusStartScan will return SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL when given invalid params scannerld
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusStartScan003, TestSize.Level1)
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
 * @tc.name: SoftbusEnableSyncDataToLp001
 * @tc.desc: Test SoftbusEnableSyncDataToLp is  SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusEnableSyncDataToLp001, TestSize.Level1)
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
 * @tc.name: DisableSyncDataToLpDevice001
 * @tc.desc: Test DisableSyncDataToLpDevice is  SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, DisableSyncDataToLpDevice001, TestSize.Level1)
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
 * @tc.name: SoftbusSetLpAdvParam001
 * @tc.desc: Test SoftbusSetLpAdvParam is  SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusSetLpAdvParam001, TestSize.Level1)
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
 * @tc.name: WrapperAdvEnableCb001
 * @tc.desc: WrapperAdvEnableCb will traverse when not Regist, will traverse when btAdvId is invalid
    will make true isAdvertising when BtStatus=OHOS_BT_STATUS_SUCCESS,
    will make false isAdvertising when BtStatus=OHOS_BT_STATUS_FAIL
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, WrapperAdvEnableCb001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "WrapperAdvEnableCb001 enter");
    MockBluetooth mock;
    ASSERT_NE(MockBluetooth::interface, nullptr);
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusBleGattTest::g_adapterBcld = -1;
    SoftbusBleGattTest::g_status = -1;
    int32_t advld = -1;
    int32_t invalidBtAdvId = -1;
    MockBluetooth::btGattCallback->advEnableCb(invalidBtAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "advld = %{public}d", advld);

    SoftbusBroadcastParam params = {};
    SoftbusBroadcastData data = BuildBcData();
    EXPECT_CALL(mock, BleStartAdvEx).WillRepeatedly(MockBluetooth::ActionBleStartAdvEx);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    MockBluetooth::btGattCallback->advEnableCb(invalidBtAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::btGattCallback->advEnableCb(MockBluetooth::g_btAdvId, OHOS_BT_STATUS_FAIL);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);
    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: WrapperAdvEnableCb002
 * @tc.desc: WrapperAdvEnableCb will keep traverse when advCallback.OnStartBroadcastingCallback=nullptr
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, WrapperAdvEnableCb002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "WrapperAdvEnableCb002 enter");
    MockBluetooth mock;
    ASSERT_NE(MockBluetooth::interface, nullptr);
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusBleGattTest::g_adapterBcld = -1;
    SoftbusBleGattTest::g_status = -1;
    int32_t advld = -1;
    g_softbusBcBleCbTest.OnStartBroadcastingCallback = nullptr;
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "advld = %{public}d", advld);

    SoftbusBroadcastParam params = {};
    SoftbusBroadcastData data = BuildBcData();
    EXPECT_CALL(mock, BleStartAdvEx).WillRepeatedly(MockBluetooth::ActionBleStartAdvEx);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    MockBluetooth::btGattCallback->advEnableCb(MockBluetooth::g_btAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);

    g_softbusBcBleCbTest.OnStartBroadcastingCallback = FakeBcBleCallback;
    MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    MockBluetooth::btGattCallback->advEnableCb(MockBluetooth::g_btAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_TRUE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);
    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: WrapperAdvDisableCb001
 * @tc.desc: WrapperAdvDisableCb will keep traverse when not Regist, will keep traverse when btAdvId is invalid
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, WrapperAdvDisableCb001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "WrapperAdvDisableCb001 enter");
    MockBluetooth mock;
    ASSERT_NE(MockBluetooth::interface, nullptr);
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusBleGattTest::g_adapterBcld = -1;
    SoftbusBleGattTest::g_status = -1;
    int32_t advld = -1;
    int32_t invalidBtAdvId = -1;
    MockBluetooth::btGattCallback->advDisableCb(invalidBtAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "advld = %{public}d", advld);

    SoftbusBroadcastParam params = {};
    SoftbusBroadcastData data = BuildBcData();
    EXPECT_CALL(mock, BleStartAdvEx).WillRepeatedly(MockBluetooth::ActionBleStartAdvEx);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    MockBluetooth::btGattCallback->advDisableCb(invalidBtAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);
    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: WrapperAdvDisableCb002
 * @tc.desc: WrapperAdvDisableCb will keep traverse when advCallback.OnStopBroadcastingCallback=nullptr
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, WrapperAdvDisableCb002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "WrapperAdvDisableCb002 enter");
    MockBluetooth mock;
    ASSERT_NE(MockBluetooth::interface, nullptr);
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusBleGattTest::g_adapterBcld = -1;
    SoftbusBleGattTest::g_status = -1;
    int32_t advld = -1;
    g_softbusBcBleCbTest.OnStopBroadcastingCallback = nullptr;
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "advld = %{public}d", advld);

    SoftbusBroadcastParam params = {};
    SoftbusBroadcastData data = BuildBcData();
    EXPECT_CALL(mock, BleStartAdvEx).WillRepeatedly(MockBluetooth::ActionBleStartAdvEx);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    MockBluetooth::btGattCallback->advDisableCb(MockBluetooth::g_btAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);

    g_softbusBcBleCbTest.OnStopBroadcastingCallback = FakeBcBleCallback;
    MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    MockBluetooth::btGattCallback->advDisableCb(MockBluetooth::g_btAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_TRUE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);
    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: WrapperAdvSetDataCb001
 * @tc.desc: WrapperAdvSetDataCb will keep traverse when not Regist, will keep traverse when btAdvId is invalid
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, WrapperAdvSetDataCb001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "WrapperAdvSetDataCb001 enter");
    MockBluetooth mock;
    ASSERT_NE(MockBluetooth::interface, nullptr);
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusBleGattTest::g_adapterBcld = -1;
    SoftbusBleGattTest::g_status = -1;
    int32_t advld = -1;
    int32_t invalidBtAdvId = -1;
    MockBluetooth::btGattCallback->advDataCb(invalidBtAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "advld = %{public}d", advld);

    SoftbusBroadcastParam params = {};
    SoftbusBroadcastData data = BuildBcData();
    EXPECT_CALL(mock, BleStartAdvEx).WillRepeatedly(MockBluetooth::ActionBleStartAdvEx);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);

    MockBluetooth::btGattCallback->advDataCb(invalidBtAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);
    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: WrapperAdvSetDataCb002
 * @tc.desc: WrapperAdvSetDataCb will keep traverse when advCallback.OnSetBroadcastingCallback=nullptr
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, WrapperAdvSetDataCb002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "WrapperAdvSetDataCb002 enter");
    MockBluetooth mock;
    ASSERT_NE(MockBluetooth::interface, nullptr);
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusBleGattTest::g_adapterBcld = -1;
    SoftbusBleGattTest::g_status = -1;
    int32_t advld = -1;
    g_softbusBcBleCbTest.OnSetBroadcastingCallback = nullptr;
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "advld = %{public}d", advld);

    SoftbusBroadcastParam params = {};
    SoftbusBroadcastData data = BuildBcData();
    EXPECT_CALL(mock, BleStartAdvEx).WillRepeatedly(MockBluetooth::ActionBleStartAdvEx);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    MockBluetooth::btGattCallback->advDataCb(MockBluetooth::g_btAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);

    g_softbusBcBleCbTest.OnSetBroadcastingCallback = FakeBcBleCallback;
    MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    MockBluetooth::btGattCallback->advDataCb(MockBluetooth::g_btAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_TRUE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);
    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: WrapperAdvUpdateDataCb001
 * @tc.desc: WrapperAdvUpdateDataCb will keep traverse when not Regist, will keep traverse when btAdvId is invalid
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, WrapperAdvUpdateDataCb001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "WrapperAdvUpdateDataCb001 enter");
    MockBluetooth mock;
    ASSERT_NE(MockBluetooth::interface, nullptr);
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusBleGattTest::g_adapterBcld = -1;
    SoftbusBleGattTest::g_status = -1;
    int32_t advld = -1;
    int32_t invalidBtAdvId = -1;
    MockBluetooth::btGattCallback->advUpdateCb(invalidBtAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "advld = %{public}d", advld);

    SoftbusBroadcastParam params = {};
    SoftbusBroadcastData data = BuildBcData();
    EXPECT_CALL(mock, BleStartAdvEx).WillRepeatedly(MockBluetooth::ActionBleStartAdvEx);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);

    MockBluetooth::btGattCallback->advUpdateCb(invalidBtAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);
    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: WrapperAdvUpdateDataCb002
 * @tc.desc: WrapperAdvUpdateDataCb will keep traverse when advCallback.OnUpdateBroadcastingCallback=nullptr
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, WrapperAdvUpdateDataCb002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "WrapperAdvUpdateDataCb002 enter");
    MockBluetooth mock;
    ASSERT_NE(MockBluetooth::interface, nullptr);
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusBleGattTest::g_adapterBcld = -1;
    SoftbusBleGattTest::g_status = -1;
    int32_t advld = -1;
    g_softbusBcBleCbTest.OnUpdateBroadcastingCallback = nullptr;
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "advld = %{public}d", advld);

    SoftbusBroadcastParam params = {};
    SoftbusBroadcastData data = BuildBcData();
    EXPECT_CALL(mock, BleStartAdvEx).WillRepeatedly(MockBluetooth::ActionBleStartAdvEx);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    MockBluetooth::btGattCallback->advUpdateCb(MockBluetooth::g_btAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);

    g_softbusBcBleCbTest.OnUpdateBroadcastingCallback = FakeBcBleCallback;
    MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    MockBluetooth::btGattCallback->advUpdateCb(MockBluetooth::g_btAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_TRUE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);
    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: WrapperAdvUpdateParamCb001
 * @tc.desc: WrapperAdvUpdateParamCb will keep traverse when not regist, will keep traverse when btAdvId is invalid
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, WrapperAdvUpdateParamCb001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "WrapperAdvUpdateParamCb001 enter");
    MockBluetooth mock;
    ASSERT_NE(MockBluetooth::interface, nullptr);
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusBleGattTest::g_adapterBcld = -1;
    SoftbusBleGattTest::g_status = -1;
    int32_t advld = -1;
    int32_t invalidBtAdvId = -1;
    MockBluetooth::btGattCallback->advChangeCb(invalidBtAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "advld = %{public}d", advld);

    SoftbusBroadcastParam params = {};
    SoftbusBroadcastData data = BuildBcData();
    EXPECT_CALL(mock, BleStartAdvEx).WillRepeatedly(MockBluetooth::ActionBleStartAdvEx);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    MockBluetooth::btGattCallback->advChangeCb(invalidBtAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);
    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: WrapperAdvUpdateParamCb002
 * @tc.desc: WrapperAdvUpdateParamCb will keep traverse when advCallback.OnSetBroadcastingParamCallback=nullptr
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, WrapperAdvUpdateParamCb002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "WrapperAdvUpdateParamCb002 enter");
    MockBluetooth mock;
    ASSERT_NE(MockBluetooth::interface, nullptr);
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusBleGattTest::g_adapterBcld = -1;
    SoftbusBleGattTest::g_status = -1;
    int32_t advld = -1;
    g_softbusBcBleCbTest.OnSetBroadcastingParamCallback = nullptr;
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "advld = %{public}d", advld);

    SoftbusBroadcastParam params = {};
    SoftbusBroadcastData data = BuildBcData();
    EXPECT_CALL(mock, BleStartAdvEx).WillRepeatedly(MockBluetooth::ActionBleStartAdvEx);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    MockBluetooth::btGattCallback->advChangeCb(MockBluetooth::g_btAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);

    g_softbusBcBleCbTest.OnSetBroadcastingParamCallback = FakeBcBleCallback;
    MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);

    MockBluetooth::btGattCallback->advChangeCb(MockBluetooth::g_btAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_TRUE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);
    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: WrapperOnAdvEnableExCb001
 * @tc.desc: WrapperOnAdvEnableExCb will keep traverse when not regist, will keep traverse when btAdvId is invalid
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, WrapperOnAdvEnableExCb001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "WrapperOnAdvEnableExCb001 enter");
    MockBluetooth mock;
    ASSERT_NE(MockBluetooth::interface, nullptr);
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusBleGattTest::g_adapterBcld = -1;
    SoftbusBleGattTest::g_status = -1;
    int32_t advld = -1;
    int32_t invalidBtAdvId = -1;
    MockBluetooth::btGattCallback->onEnableExCb(invalidBtAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "advld = %{public}d", advld);

    SoftbusBroadcastParam params = {};
    SoftbusBroadcastData data = BuildBcData();
    EXPECT_CALL(mock, BleStartAdvEx).WillRepeatedly(MockBluetooth::ActionBleStartAdvEx);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    MockBluetooth::btGattCallback->onEnableExCb(invalidBtAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);
    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: WrapperOnAdvEnableExCb002
 * @tc.desc: WrapperOnAdvEnableExCb will keep traverse when advCallback.OnSetBroadcastingParamCallback=nullptr
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, WrapperOnAdvEnableExCb002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "WrapperOnAdvEnableExCb002 enter");
    MockBluetooth mock;
    ASSERT_NE(MockBluetooth::interface, nullptr);
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusBleGattTest::g_adapterBcld = -1;
    SoftbusBleGattTest::g_status = -1;
    int32_t advld = -1;
    g_softbusBcBleCbTest.OnEnableBroadcastingCallback = nullptr;
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "advld = %{public}d", advld);

    SoftbusBroadcastParam params = {};
    SoftbusBroadcastData data = BuildBcData();
    EXPECT_CALL(mock, BleStartAdvEx).WillRepeatedly(MockBluetooth::ActionBleStartAdvEx);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    MockBluetooth::btGattCallback->onEnableExCb(MockBluetooth::g_btAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);

    g_softbusBcBleCbTest.OnEnableBroadcastingCallback = FakeBcBleCallback;
    MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    MockBluetooth::btGattCallback->onEnableExCb(MockBluetooth::g_btAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_TRUE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);
    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: WrapperOnAdvDisableExCb001
 * @tc.desc: WrapperOnAdvDisableExCb will keep traverse when not regist, will keep traverse when btAdvId is invalid
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, WrapperOnAdvDisableExCb001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "WrapperOnAdvDisableExCb001 enter");
    MockBluetooth mock;
    ASSERT_NE(MockBluetooth::interface, nullptr);
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusBleGattTest::g_adapterBcld = -1;
    SoftbusBleGattTest::g_status = -1;
    int32_t advld = -1;
    int32_t invalidBtAdvId = -1;
    MockBluetooth::btGattCallback->onDisableExCb(invalidBtAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "advld = %{public}d", advld);

    SoftbusBroadcastParam params = {};
    SoftbusBroadcastData data = BuildBcData();
    EXPECT_CALL(mock, BleStartAdvEx).WillRepeatedly(MockBluetooth::ActionBleStartAdvEx);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    MockBluetooth::btGattCallback->onDisableExCb(invalidBtAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);
    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: WrapperOnAdvDisableExCb002
 * @tc.desc: WrapperOnAdvDisableExCb will keep traverse when advCallback.OnDisableBroadcastingCallback=nullptr
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, WrapperOnAdvDisableExCb002, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "WrapperOnAdvDisableExCb002 enter");
    MockBluetooth mock;
    ASSERT_NE(MockBluetooth::interface, nullptr);
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusBleGattTest::g_adapterBcld = -1;
    SoftbusBleGattTest::g_status = -1;
    int32_t advld = -1;
    g_softbusBcBleCbTest.OnDisableBroadcastingCallback = nullptr;
    ret = MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DISC_LOGI(DISC_TEST, "advld = %{public}d", advld);

    SoftbusBroadcastParam params = {};
    SoftbusBroadcastData data = BuildBcData();
    EXPECT_CALL(mock, BleStartAdvEx).WillRepeatedly(MockBluetooth::ActionBleStartAdvEx);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    MockBluetooth::btGattCallback->onDisableExCb(MockBluetooth::g_btAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_FALSE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);

    g_softbusBcBleCbTest.OnDisableBroadcastingCallback = FakeBcBleCallback;
    MockBluetooth::interface->RegisterBroadcaster(&advld, &g_softbusBcBleCbTest);
    ret = MockBluetooth::interface->StartBroadcasting(advld, &params, &data);
    EXPECT_EQ(ret, SOFTBUS_OK);
    MockBluetooth::btGattCallback->onDisableExCb(MockBluetooth::g_btAdvId, OHOS_BT_STATUS_SUCCESS);
    EXPECT_TRUE(SoftbusBleGattTest::g_adapterBcld == advld && SoftbusBleGattTest::g_status == OHOS_BT_STATUS_SUCCESS);

    MockBluetooth::interface->StopBroadcasting(advld);
    MockBluetooth::interface->UnRegisterBroadcaster(advld);
    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: WrapperScanStateChangeCb0001
 * @tc.desc: Test WrapperScanStateChangeCb
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, WrapperScanStateChangeCb0001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "WrapperScanStateChangeCb enter");
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
 * @tc.name: WrapperLpDeviceInfoCb001
 * @tc.desc: Test WrapperLpDeviceInfoCb
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, WrapperLpDeviceInfoCb001, TestSize.Level1)
{
    DISC_LOGI(DISC_TEST, "WrapperLpDeviceInfoCb enter");
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
 * @tc.name: IsLpAvailable001
 * @tc.desc: Test IsLpAvailable
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, IsLpAvailable001, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->IsLpDeviceAvailable();
    EXPECT_EQ(ret, true);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusSetLpParam001
 * @tc.desc: Test SoftbusSetLpParam
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusSetLpParam001, TestSize.Level1)
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
 * @tc.name: SoftbusSetLpParam002
 * @tc.desc: Test SoftbusSetLpParam when SetBtUuidByBroadCastType return error
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusSetLpParam002, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusLpBroadcastParam bcParam = {};
    SoftBusLpScanParam scanParam = {};
    scanParam.filterSize = 1;

    ret = MockBluetooth::interface->SetAdvFilterParam(SOFTBUS_UNKNOW_TYPE, &bcParam, &scanParam);
    EXPECT_EQ(ret, false);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: RegisterScanListener001
 * @tc.desc: test register scan listener
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, RegisterScanListener001, TestSize.Level3)
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
 * @tc.name: UnRegisterScanListener001
 * @tc.desc: test unregister scan listener
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, UnRegisterScanListener001, TestSize.Level3)
{
    MockBluetooth mocker;
    int32_t scannerId = -1;
    auto result = PrepareScanListener(&scannerId);

    ASSERT_EQ(MockBluetooth::interface->UnRegisterScanListener(-1), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(MockBluetooth::interface->UnRegisterScanListener(GATT_SCAN_MAX_NUM), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(MockBluetooth::interface->UnRegisterScanListener(scannerId), SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: ScanLifecycle001
 * @tc.desc: test complete scan life cycle
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, ScanLifecycle001, TestSize.Level3)
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
 * @tc.name: ScanResultCb001
 * @tc.desc: test scan result callback
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, ScanResultCb001, TestSize.Level3)
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
 * @tc.name: RegisterBroadcaster001
 * @tc.desc: test register adv callback
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, RegisterBroadcaster001, TestSize.Level3)
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

/**
 * @tc.name: SoftbusSetAdvParamterTest001
 * @tc.desc: Test SoftbusSetAdvParamter when param == NULL
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusSetAdvParamterTest001, TestSize.Level1)
{
    int32_t advId = 0;
    int32_t ret = MockBluetooth::interface->SetBroadcastingParam(advId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: SoftbusSetAdvParamterTest002
 * @tc.desc: Test SoftbusSetAdvParamter when CheckAdvChanInUsed return false
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusSetAdvParamterTest002, TestSize.Level1)
{
    int32_t advId = GATT_ADV_MAX_NUM;
    SoftbusBroadcastParam params = {};
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->SetBroadcastingParam(advId, &params);
    EXPECT_EQ(ret, SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusSetAdvParamterTest003
 * @tc.desc: Test SoftbusSetAdvParamter when isAdvertising is false
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusSetAdvParamterTest003, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t advId = 0;
    EXPECT_CALL(mocker, BleGattRegisterCallbacks).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ret = MockBluetooth::interface->RegisterBroadcaster(&advId, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftbusBroadcastParam params = {};

    ret = MockBluetooth::interface->SetBroadcastingParam(advId, &params);
    EXPECT_EQ(ret, SOFTBUS_ALREADY_TRIGGERED);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusEnableBroadcasting001
 * @tc.desc: Test SoftbusEnableBroadcasting when CheckAdvChanInUsed return false
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusEnableBroadcasting001, TestSize.Level1)
{
    int32_t advId = GATT_ADV_MAX_NUM;
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->EnableBroadcasting(advId);
    EXPECT_EQ(ret, SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusEnableBroadcastingTest002
 * @tc.desc: Test SoftbusEnableBroadcasting when isAdvertising is false
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusEnableBroadcastingTest002, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t advId = 0;
    EXPECT_CALL(mocker, BleGattRegisterCallbacks).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ret = MockBluetooth::interface->RegisterBroadcaster(&advId, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->EnableBroadcasting(advId);
    EXPECT_EQ(ret, SOFTBUS_ALREADY_TRIGGERED);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusDisableBroadcasting001
 * @tc.desc: Test SoftbusDisableBroadcasting when CheckAdvChanInUsed return false
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusDisableBroadcasting001, TestSize.Level1)
{
    int32_t advId = GATT_ADV_MAX_NUM;
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->DisableBroadcasting(advId);
    EXPECT_EQ(ret, SOFTBUS_BC_ADAPTER_NOT_IN_USED_FAIL);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusDisableBroadcastingTest002
 * @tc.desc: Test SoftbusDisableBroadcasting when isAdvertising is false
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusDisableBroadcastingTest002, TestSize.Level1)
{
    MockBluetooth mocker;
    int32_t ret = MockBluetooth::interface->Init();
    EXPECT_EQ(ret, SOFTBUS_OK);

    int32_t advId = 0;
    EXPECT_CALL(mocker, BleGattRegisterCallbacks).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ret = MockBluetooth::interface->RegisterBroadcaster(&advId, &g_softbusBcBleCbTest);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = MockBluetooth::interface->DisableBroadcasting(advId);
    EXPECT_EQ(ret, SOFTBUS_ALREADY_TRIGGERED);

    ret = MockBluetooth::interface->DeInit();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusSetScanParamsTest001
 * @tc.desc: Test SoftbusSetScanParams when param is nullptr
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, SoftbusSetScanParamsTest001, TestSize.Level1)
{
    int32_t scannerId = 0;
    SoftBusBcScanFilter scanFilter = {};
    int32_t filterSize = 0;
    SoftbusSetFilterCmd cmdId = {};
    int32_t ret = MockBluetooth::interface->SetScanParams(scannerId, nullptr, &scanFilter, filterSize, cmdId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}
} // namespace OHOS