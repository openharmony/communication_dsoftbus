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

#include "softbus_ble_gatt.h"
#include "softbus_broadcast_type.h"
#include "disc_log.h"
#include "c_header/ohos_bt_gatt.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "assert_helper.h"
#include "bluetooth_mock.h"

#define GATT_ADV_MAX_NUM 16
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
    static int btInnerAdvId;

    static void SetUpTestCase(void);
};

ScanResultCtx SoftbusBleGattTest::scanResultCtx("OnReportScanDataCallback");

StRecordCtx SoftbusBleGattTest::advEnableCtx("AdvEnableCallback");
StRecordCtx SoftbusBleGattTest::advDisableCtx("AdvDisableCallback");
StRecordCtx SoftbusBleGattTest::advDataCtx("AdvDataCallback");
StRecordCtx SoftbusBleGattTest::advUpdateCtx("AdvUpdateCallback");
int SoftbusBleGattTest::btInnerAdvId = -1;

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
    static SoftbusScanCallback listener = {
        .OnStartScanCallback = nullptr,
        .OnStopScanCallback = nullptr,
        .OnReportScanDataCallback = StubOnScanResult,
        .OnScanStateChanged = nullptr
    };
    return &listener;
}

static void StubAdvEnableCallback(int advId, int status)
{
    SoftbusBleGattTest::advEnableCtx.Update(advId, status);
}

static void StubAdvDisableCallback(int advId, int status)
{
    SoftbusBleGattTest::advDisableCtx.Update(advId, status);
}

static void StubAdvUpdateCallback(int advId, int status)
{
    SoftbusBleGattTest::advUpdateCtx.Update(advId, status);
}

static void StubAdvDataCallback(int advId, int status)
{
    SoftbusBleGattTest::advDataCtx.Update(advId, status);
}

static int ActionSuccessBleStartAdvEx(int *advId, const StartAdvRawData rawData, BleAdvParams advParam)
{
    static int advIdGenerator = 0;
    *advId = advIdGenerator++;
    SoftbusBleGattTest::btInnerAdvId = *advId;
    return OHOS_BT_STATUS_SUCCESS;
}

static int ActionSuccessBleStopAdv(int advId)
{
    DISC_LOGI(DISC_BLE_ADAPTER, "ActionSuccessBleStopAdv, advId=%{public}d", advId);
    MockBluetooth::btGattCallback->advDisableCb(advId, OHOS_BT_STATUS_SUCCESS);
    DISC_LOGI(DISC_BLE_ADAPTER, "ActionSuccessBleStopAdv, advId=%{public}d", advId);
    return OHOS_BT_STATUS_SUCCESS;
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

static testing::AssertionResult PrepareScanListener(int *scannerId)
{
    int32_t ret = MockBluetooth::interface->RegisterScanListener(scannerId, GetStubScanListener());
    if (ret == SOFTBUS_ERR) {
        return testing::AssertionFailure() << "RegisterScanListener failed";
    }
    if (MockBluetooth::bleScanCallback == nullptr) {
        return testing::AssertionFailure() << "RegisterScanListener is not invoke";
    }
    return testing::AssertionSuccess();
}

static testing::AssertionResult PrepareAdvCallback(int *advId)
{
    auto ret = MockBluetooth::interface->RegisterBroadcaster(advId, GetStubAdvCallback());
    if (ret == SOFTBUS_ERR) {
        return testing::AssertionFailure() << "RegisterBroadcaster failed";
    }
    if (MockBluetooth::btGattCallback == nullptr) {
        return testing::AssertionFailure() << "RegisterBroadcaster is not invoke";
    }
    return testing::AssertionSuccess();
}

static SoftBusBcScanFilter *CreateScanFilter()
{
    unsigned char serviceData[] = {0xE, 0xE, 0xF, 0xF, 0x04, 0x05};
    int len = sizeof(serviceData);

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
 * @tc.name: AdapterBleGattTest_RegisterScanListener
 * @tc.desc: test register scan listener
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, RegisterScanListener, TestSize.Level3)
{
    MockBluetooth mocker;
    int scannerId = -1;
    ASSERT_EQ(MockBluetooth::interface->RegisterScanListener(&scannerId, nullptr), SOFTBUS_ERR);
    int32_t scanListerIds[GATT_SCAN_MAX_NUM] = {};
    int32_t ret = SOFTBUS_ERR;
    for (size_t i = 0; i < GATT_SCAN_MAX_NUM; i++) {
        ret = MockBluetooth::interface->RegisterScanListener(&scanListerIds[i], GetStubScanListener());
        ASSERT_EQ(ret, SOFTBUS_OK);
    }

    ASSERT_EQ(MockBluetooth::interface->RegisterScanListener(&scannerId, GetStubScanListener()), SOFTBUS_ERR);

    for (size_t i = 0; i < GATT_SCAN_MAX_NUM; i++) {
        ASSERT_EQ(MockBluetooth::interface->UnRegisterScanListener(scanListerIds[i]), SOFTBUS_OK);
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
    int scannerId = -1;
    auto result = PrepareScanListener(&scannerId);
    ASSERT_TRUE(result);

    ASSERT_EQ(MockBluetooth::interface->UnRegisterScanListener(-1), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(MockBluetooth::interface->UnRegisterScanListener(GATT_SCAN_MAX_NUM), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(MockBluetooth::interface->UnRegisterScanListener(scannerId), SOFTBUS_OK);
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
    int scannerId = -1;
    auto result = PrepareScanListener(&scannerId);
    ASSERT_TRUE(result);

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
    ASSERT_EQ(MockBluetooth::interface->StartScan(scannerId, &scanParam, filter, 1), SOFTBUS_OK);

    EXPECT_CALL(mocker, BleStopScan).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ASSERT_EQ(MockBluetooth::interface->StopScan(scannerId), SOFTBUS_OK);

    ASSERT_EQ(MockBluetooth::interface->UnRegisterScanListener(scannerId), SOFTBUS_OK);
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
    int scannerId = -1;
    auto result = PrepareScanListener(&scannerId);
    ASSERT_TRUE(result);

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
    ASSERT_EQ(MockBluetooth::interface->StartScan(scannerId, &scanParam, filter, 1), SOFTBUS_OK);

    const unsigned char scanDataExample[] = {0x02, 0x01, 0x02, 0x15, 0x16, 0xEE, 0xFD, 0x04, 0x05, 0x90, 0x00, 0x00,
        0x04, 0x00, 0x18, 0x33, 0x39, 0x36, 0x62, 0x33, 0x61, 0x33, 0x31, 0x21, 0x00, 0x02, 0x0A, 0xEF, 0x03, 0xFF,
        0x7D, 0x02};
    SoftBusBcScanResult expectScanResult = {0};
    expectScanResult.data.bcData.payloadLen = sizeof(scanDataExample);
    expectScanResult.data.bcData.payload = (unsigned char *)scanDataExample;
    BtScanResultData mockScanResult = {0};
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
 * @tc.name: AdapterBleGattTest_AdvertiseLifecycle
 * @tc.desc: test complete Advertisement life cycle
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, AdvertiseLifecycle, TestSize.Level3)
{
    MockBluetooth mocker;
    int advId = 0;
    auto result = PrepareAdvCallback(&advId);
    ASSERT_TRUE(result);

    EXPECT_CALL(mocker, BleStartAdvEx).WillRepeatedly(ActionSuccessBleStartAdvEx);
    ON_CALL(mocker, BleStopAdv).WillByDefault(ActionSuccessBleStopAdv);
    const char advDataExample[] = {0x02, 0x01, 0x02, 0x15, 0x16, 0xEE, 0xFD, 0x04, 0x05, 0x90, 0x00, 0x00, 0x04, 0x00,
        0x18, 0x33, 0x39, 0x36, 0x62, 0x33, 0x61, 0x33, 0x31, 0x21, 0x00, 0x02, 0x0A, 0xEF};
    const unsigned char scanRspDataExample[] = {0x03, 0xFF, 0x7D, 0x02};
    SoftbusBroadcastData data = {};
    data.bcData.payloadLen = sizeof(advDataExample);
    data.bcData.payload = (uint8_t *)advDataExample;
    data.rspData.payloadLen = sizeof(scanRspDataExample);
    data.rspData.payload = (uint8_t *)scanRspDataExample;

    SoftbusBroadcastParam params = {};
    DISC_LOGI(DISC_BLE_ADAPTER, "start to StartBroadcasting");
    ASSERT_EQ(MockBluetooth::interface->StartBroadcasting(advId, &params, &data), SOFTBUS_OK);
    ASSERT_FALSE(advEnableCtx.Expect(advId, OHOS_BT_STATUS_SUCCESS));
    DISC_LOGI(DISC_BLE_ADAPTER, "start to advEnableCb");
    MockBluetooth::btGattCallback->advEnableCb(btInnerAdvId, OHOS_BT_STATUS_SUCCESS);
    ASSERT_TRUE(advEnableCtx.Expect(advId, OHOS_BT_STATUS_SUCCESS));

    DISC_LOGI(DISC_BLE_ADAPTER, "start to advDataCb");
    MockBluetooth::btGattCallback->advDataCb(btInnerAdvId, OHOS_BT_STATUS_SUCCESS);
    ASSERT_TRUE(advDataCtx.Expect(advId, OHOS_BT_STATUS_SUCCESS));

    DISC_LOGI(DISC_BLE_ADAPTER, "start to UpdateBroadcasting");
    ASSERT_EQ(MockBluetooth::interface->UpdateBroadcasting(advId, &params, nullptr), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(MockBluetooth::interface->UpdateBroadcasting(advId, nullptr, &data), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(MockBluetooth::interface->UpdateBroadcasting(advId, &params, &data), SOFTBUS_OK);
    ASSERT_FALSE(advEnableCtx.Expect(advId, OHOS_BT_STATUS_SUCCESS));
    DISC_LOGI(DISC_BLE_ADAPTER, "start to advEnableCb");
    MockBluetooth::btGattCallback->advEnableCb(btInnerAdvId, OHOS_BT_STATUS_SUCCESS);
    ASSERT_TRUE(advEnableCtx.Expect(advId, OHOS_BT_STATUS_SUCCESS));

    DISC_LOGI(DISC_BLE_ADAPTER, "start to advUpdateCb");
    MockBluetooth::btGattCallback->advUpdateCb(btInnerAdvId, OHOS_BT_STATUS_SUCCESS);
    ASSERT_TRUE(advUpdateCtx.Expect(advId, OHOS_BT_STATUS_SUCCESS));

    DISC_LOGI(DISC_BLE_ADAPTER, "start to StopBroadcasting");
    ASSERT_EQ(MockBluetooth::interface->StopBroadcasting(advId), SOFTBUS_OK);

    DISC_LOGI(DISC_BLE_ADAPTER, "start to UnRegisterBroadcaster");
    ASSERT_EQ(MockBluetooth::interface->UnRegisterBroadcaster(-1), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(MockBluetooth::interface->UnRegisterBroadcaster(GATT_ADV_MAX_NUM), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(MockBluetooth::interface->UnRegisterBroadcaster(advId), SOFTBUS_OK);
    ASSERT_EQ(MockBluetooth::interface->UnRegisterBroadcaster(advId), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattTest_RegisterBroadcaster
 * @tc.desc: test register adv callback
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(SoftbusBleGattTest, RegisterBroadcaster, TestSize.Level3)
{
    int advId = -1;
    ASSERT_EQ(MockBluetooth::interface->RegisterBroadcaster(&advId, nullptr), SOFTBUS_INVALID_PARAM);
    int advIds[GATT_ADV_MAX_NUM];
    for (size_t i = 0; i < GATT_ADV_MAX_NUM; i++) {
        ASSERT_EQ(MockBluetooth::interface->RegisterBroadcaster(&advIds[i], GetStubAdvCallback()), SOFTBUS_OK);
    }
    ASSERT_EQ(MockBluetooth::interface->RegisterBroadcaster(&advId, GetStubAdvCallback()), SOFTBUS_ERR);
    for (size_t i = 0; i < GATT_ADV_MAX_NUM; i++) {
        ASSERT_EQ(MockBluetooth::interface->UnRegisterBroadcaster(advIds[i]), SOFTBUS_OK);
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

bool ScanResultCtx::Update(int id, const SoftBusBcScanResult *scanResult)
{
    if (!RecordCtx::Update(id)) {
        return false;
    }
    this->scanResult = *scanResult;
    unsigned char *cpyAdvData = static_cast<unsigned char *>(SoftBusCalloc(this->scanResult.data.bcData.payloadLen));
    if (cpyAdvData == nullptr) {
        DISC_LOGE(DISC_BLE_ADAPTER, "malloc failed in OnReportScanDataCallback, can not save ctx, id=%{public}d", id);
        return false;
    }

    if (memcpy_s(cpyAdvData, this->scanResult.data.bcData.payloadLen, scanResult->data.bcData.payload,
        scanResult->data.bcData.payloadLen) != EOK) {
        DISC_LOGE(DISC_BLE_ADAPTER, "malloc failed in OnReportScanDataCallback, can not save ctx, id=%{public}d", id);
        SoftBusFree(cpyAdvData);
        return false;
    }
    this->scanResult.data.bcData.payload = cpyAdvData;
    return true;
}

testing::AssertionResult ScanResultCtx::Expect(int id, const SoftBusBcScanResult *scanResultParam)
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
