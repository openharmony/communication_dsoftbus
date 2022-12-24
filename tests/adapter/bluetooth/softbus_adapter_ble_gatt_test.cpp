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

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "ohos_bt_gatt.h"
#include "softbus_adapter_ble_gatt.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

#include "assert_helper.h"
#include "bluetooth_mock.h"

using namespace testing::ext;
using ::testing::AtMost;
using ::testing::Return;

namespace OHOS {

class ScanResultCtx : public RecordCtx {
public:
    explicit ScanResultCtx(const char *identifier);
    ~ScanResultCtx();
    bool Update(int id, const SoftBusBleScanResult *scanResult);
    testing::AssertionResult Expect(int id, const SoftBusBleScanResult *scanResult);
private:
    SoftBusBleScanResult scanResult;
    void Reset();
};

class AdapterBleGattTest : public testing::Test {
public:
    static StRecordCtx scanStartCtx;
    static StRecordCtx scanStopCtx;
    static ScanResultCtx scanResultCtx;

    static StRecordCtx advEnableCtx;
    static StRecordCtx advDisableCtx;
    static StRecordCtx advDataCtx;
    static StRecordCtx advUpdateCtx;
    // btInnerAdvId 模拟蓝牙生成的广播id
    static int btInnerAdvId;

    static void SetUpTestCase(void);
};

StRecordCtx AdapterBleGattTest::scanStartCtx("OnScanStart");
StRecordCtx AdapterBleGattTest::scanStopCtx("OnScanStop");
ScanResultCtx AdapterBleGattTest::scanResultCtx("OnScanResult");

StRecordCtx AdapterBleGattTest::advEnableCtx("AdvEnableCallback");
StRecordCtx AdapterBleGattTest::advDisableCtx("AdvDisableCallback");
StRecordCtx AdapterBleGattTest::advDataCtx("AdvDataCallback");
StRecordCtx AdapterBleGattTest::advUpdateCtx("AdvUpdateCallback");
int AdapterBleGattTest::btInnerAdvId = -1;

void AdapterBleGattTest::SetUpTestCase()
{
    BleGattLockInit();
}

static void StubOnScanStart(int listenerId, int status)
{
    AdapterBleGattTest::scanStartCtx.Update(listenerId, status);
}

static void StubOnScanStop(int listenerId, int status)
{
    AdapterBleGattTest::scanStopCtx.Update(listenerId, status);
}

static void StubOnScanResult(int listenerId, const SoftBusBleScanResult *scanResultdata)
{
    AdapterBleGattTest::scanResultCtx.Update(listenerId, scanResultdata);
}

SoftBusScanListener *GetStubScanListener()
{
    static SoftBusScanListener listener = {
        .OnScanStart = StubOnScanStart,
        .OnScanStop = StubOnScanStop,
        .OnScanResult = StubOnScanResult,
    };
    return &listener;
}

static void StubAdvEnableCallback(int advId, int status)
{
    AdapterBleGattTest::advEnableCtx.Update(advId, status);
}

static void StubAdvDisableCallback(int advId, int status)
{
    AdapterBleGattTest::advDisableCtx.Update(advId, status);
}

static void StubAdvDataCallback(int advId, int status)
{
    AdapterBleGattTest::advDataCtx.Update(advId, status);
}

static void StubAdvUpdateCallback(int advId, int status)
{
    AdapterBleGattTest::advUpdateCtx.Update(advId, status);
}

// Notice：考虑到BleStartAdvEx的回调需要异步触发，实现会导致专注点不在用来本身。这里不手动mock，
// ！！！IMPORANT: 一定需要手动触发成功回调，否则回导致adapter状态异常！！！
static int ActionSuccessBleStartAdvEx(int *advId, const StartAdvRawData rawData, BleAdvParams advParam)
{
    static int advIdGenerator = 0;
    *advId = advIdGenerator++;
    AdapterBleGattTest::btInnerAdvId = *advId;
    return OHOS_BT_STATUS_SUCCESS;
}

static int ActionSuccessBleStopAdv(int advId)
{
    MockBluetooth::btGattCallback->advDisableCb(advId, SOFTBUS_BT_STATUS_SUCCESS);
    return OHOS_BT_STATUS_SUCCESS;
}

SoftBusAdvCallback *GetStubAdvCallback()
{
    static SoftBusAdvCallback callback = {.AdvEnableCallback = StubAdvEnableCallback,
        .AdvDisableCallback = StubAdvDisableCallback,
        .AdvDataCallback = StubAdvDataCallback,
        .AdvUpdateCallback = StubAdvUpdateCallback};
    return &callback;
}

static testing::AssertionResult PrepareScanListener(MockBluetooth &mocker, int *outId)
{
    auto id = SoftBusAddScanListener(GetStubScanListener());
    if (id == SOFTBUS_ERR) {
        return testing::AssertionFailure() << "SoftBusAddScanListener failed";
    }
    if (MockBluetooth::btGattCallback == nullptr) {
        return testing::AssertionFailure() << "BleGattRegisterCallbacks is not invoke";
    }
    *outId = id;
    return testing::AssertionSuccess();
}

static testing::AssertionResult PrepareAdvCallback(MockBluetooth &mocker, int *outId)
{
    EXPECT_CALL(mocker, BleStartAdvEx).WillRepeatedly(ActionSuccessBleStartAdvEx);
    EXPECT_CALL(mocker, BleStopAdv).WillRepeatedly(ActionSuccessBleStopAdv);
    auto id = SoftBusGetAdvChannel(GetStubAdvCallback());
    if (id == SOFTBUS_ERR) {
        return testing::AssertionFailure() << "GetStubAdvCallback failed";
    }
    if (MockBluetooth::btGattCallback == nullptr) {
        return testing::AssertionFailure() << "BleGattRegisterCallbacks is not invoke";
    }
    *outId = id;
    return testing::AssertionSuccess();
}

static SoftBusBleScanFilter *CreateScanFilter()
{
    unsigned char serviceData[] = {0xE, 0xE, 0xF, 0xF, 0x04, 0x05};
    int len = sizeof(serviceData);

    SoftBusBleScanFilter *filter = (SoftBusBleScanFilter *)SoftBusCalloc(sizeof(SoftBusBleScanFilter));
    unsigned char *serviceDataPtr = (unsigned char *)SoftBusCalloc(len);
    unsigned char *serviceDataMaskPtr = (unsigned char *)SoftBusCalloc(len);
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
 * @tc.name: AdapterBleGattTest_SoftBusAddScanListener
 * @tc.desc: test add scan listener
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattTest, SoftBusAddScanListener, TestSize.Level3)
{
    MockBluetooth mocker;

    ASSERT_EQ(SoftBusAddScanListener(nullptr), SOFTBUS_ERR);

    int scanListerIds[SCAN_MAX_NUM];
    for (size_t i = 0; i < SCAN_MAX_NUM; i++) {
        scanListerIds[i] = SoftBusAddScanListener(GetStubScanListener());
        ASSERT_NE(scanListerIds[i], SOFTBUS_ERR);
    }

    ASSERT_EQ(SoftBusAddScanListener(GetStubScanListener()), SOFTBUS_ERR);

    for (size_t i = 0; i < SCAN_MAX_NUM; i++) {
        ASSERT_EQ(SoftBusRemoveScanListener(scanListerIds[i]), SOFTBUS_OK);
    }
}

/**
 * @tc.name: AdapterBleGattTest_SoftBusRemoveScanListener
 * @tc.desc: test remove scan listener
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattTest, SoftBusRemoveScanListener, TestSize.Level3)
{
    MockBluetooth mocker;
    int listenerId = -1;
    auto result = PrepareScanListener(mocker, &listenerId);
    ASSERT_TRUE(result);

    ASSERT_EQ(SoftBusRemoveScanListener(-1), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(SoftBusRemoveScanListener(SCAN_MAX_NUM), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(SoftBusRemoveScanListener(listenerId), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattTest_SoftBusSetScanFilter
 * @tc.desc: test set scan filter
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattTest, SoftBusSetScanFilter, TestSize.Level3)
{
    MockBluetooth mocker;
    int listenerId = -1;
    auto result = PrepareScanListener(mocker, &listenerId);
    ASSERT_TRUE(result);

    auto filter = CreateScanFilter();
    ASSERT_NE(filter, nullptr);

    ASSERT_EQ(SoftBusSetScanFilter(listenerId, nullptr, 0), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(SoftBusSetScanFilter(listenerId, filter, 0), SOFTBUS_INVALID_PARAM);

    // not exist scaner
    ASSERT_EQ(SoftBusSetScanFilter(SCAN_MAX_NUM - 1, filter, 1), SOFTBUS_ERR);
    ASSERT_EQ(SoftBusSetScanFilter(listenerId, filter, 1), SOFTBUS_OK);
    ASSERT_EQ(SoftBusRemoveScanListener(listenerId), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattTest_ScanLifecycle
 * @tc.desc: test complete scan life cycle
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattTest, ScanLifecycle, TestSize.Level3)
{
    MockBluetooth mocker;
    int listenerId = -1;
    auto result = PrepareScanListener(mocker, &listenerId);
    ASSERT_TRUE(result);

    auto filter = CreateScanFilter();
    ASSERT_NE(filter, nullptr);
    auto ret = SoftBusSetScanFilter(listenerId, filter, 1);
    ASSERT_EQ(ret, SOFTBUS_OK);

    SoftBusBleScanParams scanParam = {
        .scanInterval = 60,
        .scanWindow = 600,
        .scanType = 1,
        .scanPhy = 1,
        .scanFilterPolicy = 0,
    };

    EXPECT_CALL(mocker, BleStartScanEx).Times(1).WillOnce(Return(OHOS_BT_STATUS_SUCCESS));
    ret = SoftBusStartScan(listenerId, &scanParam);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ASSERT_TRUE(scanStartCtx.Expect(listenerId, SOFTBUS_BT_STATUS_SUCCESS));

    const unsigned char scanDataExample[] = {0x02, 0x01, 0x02, 0x15, 0x16, 0xEE, 0xFD, 0x04, 0x05, 0x90, 0x00, 0x00,
        0x04, 0x00, 0x18, 0x33, 0x39, 0x36, 0x62, 0x33, 0x61, 0x33, 0x31, 0x21, 0x00, 0x02, 0x0A, 0xEF, 0x03, 0xFF,
        0x7D, 0x02};
    BtScanResultData mockScanResult = {0};
    mockScanResult.advLen = sizeof(scanDataExample);
    mockScanResult.advData = (unsigned char *)scanDataExample;
    MockBluetooth::btGattCallback->scanResultCb(&mockScanResult);

    SoftBusBleScanResult expectScanResult = {0};
    expectScanResult.advLen = sizeof(scanDataExample);
    expectScanResult.advData = (unsigned char *)scanDataExample;
    ASSERT_TRUE(scanResultCtx.Expect(listenerId, &expectScanResult));

    EXPECT_CALL(mocker, BleStopScan).Times(1).WillOnce(Return(OHOS_BT_STATUS_SUCCESS));
    ret = SoftBusStopScan(listenerId);
    ASSERT_EQ(ret, SOFTBUS_OK);
    ASSERT_TRUE(scanStopCtx.Expect(listenerId, SOFTBUS_BT_STATUS_SUCCESS));

    ASSERT_EQ(SoftBusRemoveScanListener(listenerId), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattTest_ScanResultCb
 * @tc.desc: test scan result callback
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattTest, ScanResultCb, TestSize.Level3)
{
    MockBluetooth mocker;
    int listenerId = -1;
    auto result = PrepareScanListener(mocker, &listenerId);
    ASSERT_TRUE(result);

    auto filter = CreateScanFilter();
    ASSERT_NE(filter, nullptr);
    auto ret = SoftBusSetScanFilter(listenerId, filter, 1);
    ASSERT_EQ(ret, SOFTBUS_OK);

    SoftBusBleScanParams scanParam = {
        .scanInterval = 60,
        .scanWindow = 600,
        .scanType = 1,
        .scanPhy = 1,
        .scanFilterPolicy = 0,
    };
    EXPECT_CALL(mocker, BleStartScanEx).Times(1).WillOnce(Return(OHOS_BT_STATUS_SUCCESS));
    ASSERT_EQ(SoftBusStartScan(listenerId, nullptr), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(SoftBusStartScan(listenerId, &scanParam), SOFTBUS_OK);
    ASSERT_TRUE(scanStartCtx.Expect(listenerId, SOFTBUS_BT_STATUS_SUCCESS));

    const unsigned char scanDataExample[] = {0x02, 0x01, 0x02, 0x15, 0x16, 0xEE, 0xFD, 0x04, 0x05, 0x90, 0x00, 0x00,
        0x04, 0x00, 0x18, 0x33, 0x39, 0x36, 0x62, 0x33, 0x61, 0x33, 0x31, 0x21, 0x00, 0x02, 0x0A, 0xEF, 0x03, 0xFF,
        0x7D, 0x02};
    SoftBusBleScanResult expectScanResult = {0};
    expectScanResult.advLen = sizeof(scanDataExample);
    expectScanResult.advData = (unsigned char *)scanDataExample;
    BtScanResultData mockScanResult = {0};
    mockScanResult.advLen = sizeof(scanDataExample);
    mockScanResult.advData = (unsigned char *)scanDataExample;

    mockScanResult.eventType = OHOS_BLE_EVT_NON_CONNECTABLE_NON_SCANNABLE;
    mockScanResult.dataStatus = OHOS_BLE_DATA_COMPLETE;
    mockScanResult.addrType = OHOS_BLE_PUBLIC_DEVICE_ADDRESS;
    mockScanResult.primaryPhy = OHOS_BLE_SCAN_PHY_NO_PACKET;
    mockScanResult.secondaryPhy = OHOS_BLE_SCAN_PHY_NO_PACKET;
    mockScanResult.directAddrType = OHOS_BLE_PUBLIC_DEVICE_ADDRESS;
    MockBluetooth::btGattCallback->scanResultCb(&mockScanResult);
    ASSERT_TRUE(scanResultCtx.Expect(listenerId, &expectScanResult));

    mockScanResult.eventType = OHOS_BLE_EVT_NON_CONNECTABLE_NON_SCANNABLE_DIRECTED;
    mockScanResult.dataStatus = OHOS_BLE_DATA_INCOMPLETE_MORE_TO_COME;
    mockScanResult.addrType = OHOS_BLE_RANDOM_DEVICE_ADDRESS;
    mockScanResult.primaryPhy = OHOS_BLE_SCAN_PHY_1M;
    mockScanResult.secondaryPhy = OHOS_BLE_SCAN_PHY_1M;
    mockScanResult.directAddrType = OHOS_BLE_RANDOM_DEVICE_ADDRESS;
    MockBluetooth::btGattCallback->scanResultCb(&mockScanResult);
    ASSERT_TRUE(scanResultCtx.Expect(listenerId, &expectScanResult));

    mockScanResult.eventType = OHOS_BLE_EVT_CONNECTABLE;
    mockScanResult.dataStatus = OHOS_BLE_DATA_INCOMPLETE_TRUNCATED;
    mockScanResult.addrType = OHOS_BLE_PUBLIC_IDENTITY_ADDRESS;
    mockScanResult.primaryPhy = OHOS_BLE_SCAN_PHY_2M;
    mockScanResult.secondaryPhy = OHOS_BLE_SCAN_PHY_2M;
    mockScanResult.directAddrType = OHOS_BLE_PUBLIC_IDENTITY_ADDRESS;
    MockBluetooth::btGattCallback->scanResultCb(&mockScanResult);
    ASSERT_TRUE(scanResultCtx.Expect(listenerId, &expectScanResult));

    mockScanResult.eventType = OHOS_BLE_EVT_CONNECTABLE_DIRECTED;
    mockScanResult.dataStatus = UINT8_MAX;
    mockScanResult.addrType = OHOS_BLE_RANDOM_STATIC_IDENTITY_ADDRESS;
    mockScanResult.primaryPhy = OHOS_BLE_SCAN_PHY_CODED;
    mockScanResult.secondaryPhy = OHOS_BLE_SCAN_PHY_CODED;
    mockScanResult.directAddrType = OHOS_BLE_RANDOM_STATIC_IDENTITY_ADDRESS;
    MockBluetooth::btGattCallback->scanResultCb(&mockScanResult);
    ASSERT_TRUE(scanResultCtx.Expect(listenerId, &expectScanResult));

    mockScanResult.eventType = OHOS_BLE_EVT_SCANNABLE;
    mockScanResult.addrType = OHOS_BLE_UNRESOLVABLE_RANDOM_DEVICE_ADDRESS;
    mockScanResult.primaryPhy = UINT8_MAX;
    mockScanResult.secondaryPhy = UINT8_MAX;
    mockScanResult.directAddrType = OHOS_BLE_UNRESOLVABLE_RANDOM_DEVICE_ADDRESS;
    MockBluetooth::btGattCallback->scanResultCb(&mockScanResult);
    ASSERT_TRUE(scanResultCtx.Expect(listenerId, &expectScanResult));

    mockScanResult.eventType = OHOS_BLE_EVT_SCANNABLE_DIRECTED;
    mockScanResult.addrType = OHOS_BLE_NO_ADDRESS;
    mockScanResult.directAddrType = OHOS_BLE_NO_ADDRESS;
    MockBluetooth::btGattCallback->scanResultCb(&mockScanResult);
    ASSERT_TRUE(scanResultCtx.Expect(listenerId, &expectScanResult));

    mockScanResult.eventType = OHOS_BLE_EVT_LEGACY_NON_CONNECTABLE;
    mockScanResult.addrType = UINT8_MAX;
    mockScanResult.directAddrType = UINT8_MAX;
    MockBluetooth::btGattCallback->scanResultCb(&mockScanResult);
    ASSERT_TRUE(scanResultCtx.Expect(listenerId, &expectScanResult));

    mockScanResult.eventType = OHOS_BLE_EVT_LEGACY_SCANNABLE;
    MockBluetooth::btGattCallback->scanResultCb(&mockScanResult);
    ASSERT_TRUE(scanResultCtx.Expect(listenerId, &expectScanResult));

    mockScanResult.eventType = OHOS_BLE_EVT_LEGACY_CONNECTABLE;
    MockBluetooth::btGattCallback->scanResultCb(&mockScanResult);
    ASSERT_TRUE(scanResultCtx.Expect(listenerId, &expectScanResult));

    mockScanResult.eventType = OHOS_BLE_EVT_LEGACY_CONNECTABLE_DIRECTED;
    MockBluetooth::btGattCallback->scanResultCb(&mockScanResult);
    ASSERT_TRUE(scanResultCtx.Expect(listenerId, &expectScanResult));

    mockScanResult.eventType = OHOS_BLE_EVT_LEGACY_SCAN_RSP_TO_ADV_SCAN;
    MockBluetooth::btGattCallback->scanResultCb(&mockScanResult);
    ASSERT_TRUE(scanResultCtx.Expect(listenerId, &expectScanResult));

    mockScanResult.eventType = OHOS_BLE_EVT_LEGACY_SCAN_RSP_TO_ADV;
    MockBluetooth::btGattCallback->scanResultCb(&mockScanResult);
    ASSERT_TRUE(scanResultCtx.Expect(listenerId, &expectScanResult));

    mockScanResult.eventType = UINT8_MAX;
    MockBluetooth::btGattCallback->scanResultCb(&mockScanResult);
    ASSERT_TRUE(scanResultCtx.Expect(listenerId, &expectScanResult));
}

/**
 * @tc.name: AdapterBleGattTest_AdvertiseLifecycle
 * @tc.desc: test complete Advertisement life cycle
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattTest, AdvertiseLifecycle, TestSize.Level3)
{
    MockBluetooth mocker;
    int advId = -1;
    auto result = PrepareAdvCallback(mocker, &advId);
    ASSERT_TRUE(result);

    const char advDataExample[] = {0x02, 0x01, 0x02, 0x15, 0x16, 0xEE, 0xFD, 0x04, 0x05, 0x90, 0x00, 0x00, 0x04, 0x00,
        0x18, 0x33, 0x39, 0x36, 0x62, 0x33, 0x61, 0x33, 0x31, 0x21, 0x00, 0x02, 0x0A, 0xEF};
    const unsigned char scanRspDataExample[] = {0x03, 0xFF, 0x7D, 0x02};
    SoftBusBleAdvData data = {.advLength = sizeof(advDataExample),
        .advData = (char *)advDataExample,
        .scanRspLength = sizeof(scanRspDataExample),
        .scanRspData = (char *)scanRspDataExample};
    ASSERT_EQ(SoftBusSetAdvData(advId, &data), SOFTBUS_OK);
    ASSERT_TRUE(advDataCtx.Expect(advId, SOFTBUS_BT_STATUS_SUCCESS));

    SoftBusBleAdvParams params = {0};
    ASSERT_EQ(SoftBusStartAdv(advId, &params), SOFTBUS_OK);
    ASSERT_TRUE(advEnableCtx.Expect(advId, SOFTBUS_BT_STATUS_SUCCESS));
    // 模拟蓝牙广播成功回调, 广播成功会被再次回调, adapter状态才能恢复正常
    MockBluetooth::btGattCallback->advEnableCb(btInnerAdvId, SOFTBUS_BT_STATUS_SUCCESS);
    ASSERT_TRUE(advEnableCtx.Expect(advId, SOFTBUS_BT_STATUS_SUCCESS));

    MockBluetooth::btGattCallback->advDataCb(btInnerAdvId, SOFTBUS_BT_STATUS_SUCCESS);
    ASSERT_TRUE(advDataCtx.Expect(advId, SOFTBUS_BT_STATUS_SUCCESS));

    ASSERT_EQ(SoftBusUpdateAdv(advId, nullptr, &params), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(SoftBusUpdateAdv(advId, &data, nullptr), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(SoftBusUpdateAdv(advId, &data, &params), SOFTBUS_OK);
    ASSERT_TRUE(advEnableCtx.Expect(advId, SOFTBUS_BT_STATUS_SUCCESS));
    ASSERT_TRUE(advDisableCtx.Expect(advId, SOFTBUS_BT_STATUS_SUCCESS));
    // 模拟蓝牙广播成功回调, 广播成功会被再次回调, adapter状态才能恢复正常
    MockBluetooth::btGattCallback->advEnableCb(btInnerAdvId, SOFTBUS_BT_STATUS_SUCCESS);
    ASSERT_TRUE(advEnableCtx.Expect(advId, SOFTBUS_BT_STATUS_SUCCESS));

    MockBluetooth::btGattCallback->advUpdateCb(btInnerAdvId, SOFTBUS_BT_STATUS_SUCCESS);
    ASSERT_TRUE(advUpdateCtx.Expect(advId, SOFTBUS_BT_STATUS_SUCCESS));

    MockBluetooth::btGattCallback->securityRespondCb(nullptr);
    MockBluetooth::btGattCallback->scanParamSetCb(btInnerAdvId, SOFTBUS_BT_STATUS_SUCCESS);

    ASSERT_EQ(SoftBusStopAdv(advId), SOFTBUS_OK);
    ASSERT_TRUE(advDisableCtx.Expect(advId, SOFTBUS_BT_STATUS_SUCCESS));

    ASSERT_EQ(SoftBusReleaseAdvChannel(advId), SOFTBUS_OK);
    ASSERT_EQ(SoftBusReleaseAdvChannel(advId), SOFTBUS_ERR);
    ASSERT_EQ(SoftBusReleaseAdvChannel(-1), SOFTBUS_ERR);
    ASSERT_EQ(SoftBusReleaseAdvChannel(ADV_MAX_NUM), SOFTBUS_ERR);
}

/**
 * @tc.name: AdapterBleGattTest_SoftBusGetAdvChannel
 * @tc.desc: test get adv channel
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattTest, SoftBusGetAdvChannel, TestSize.Level3)
{
    ASSERT_EQ(SoftBusGetAdvChannel(nullptr), SOFTBUS_INVALID_PARAM);
    MockBluetooth mocker;
    int advIds[ADV_MAX_NUM];
    for (size_t i = 0; i < ADV_MAX_NUM; i++) {
        advIds[i] = SoftBusGetAdvChannel(GetStubAdvCallback());
        ASSERT_NE(advIds[i], SOFTBUS_ERR);
    }
    ASSERT_EQ(SoftBusGetAdvChannel(GetStubAdvCallback()), SOFTBUS_ERR);
    for (size_t i = 0; i < ADV_MAX_NUM; i++) {
        ASSERT_EQ(SoftBusReleaseAdvChannel(advIds[i]), SOFTBUS_OK);
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
    SoftBusFree(scanResult.advData);
    scanResult.advData = nullptr;
    memset_s(&scanResult, sizeof(SoftBusBtAddr), 0, sizeof(SoftBusBtAddr));
}

bool ScanResultCtx::Update(int id, const SoftBusBleScanResult *scanResult)
{
    if (!RecordCtx::Update(id)) {
        return false;
    }
    this->scanResult = *scanResult;
    unsigned char *cpyAdvData = (unsigned char *)SoftBusCalloc(this->scanResult.advLen);
    if (cpyAdvData == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "malloc failed in OnScanResult, can not save ctx, id: %d", id);
        return false;
    }

    if (memcpy_s(cpyAdvData, this->scanResult.advLen, scanResult->advData, scanResult->advLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "malloc failed in OnScanResult, can not save ctx, id: %d", id);
        SoftBusFree(cpyAdvData);
        return false;
    }
    this->scanResult.advData = cpyAdvData;
    return true;
}

testing::AssertionResult ScanResultCtx::Expect(int id, const SoftBusBleScanResult *scanResultParam)
{
    auto result = RecordCtx::Expect(id);
    if (!result) {
        goto ClEANUP;
    }

    if (this->scanResult.advLen == scanResultParam->advLen &&
        memcmp(this->scanResult.advData, scanResultParam->advData, scanResultParam->advLen) == 0) {
        result = testing::AssertionSuccess();
        goto ClEANUP;
    }
    result = testing::AssertionFailure() << identifier << " is call by unexpectedly scan result.";
ClEANUP:
    Reset();
    return result;
}

} // namespace OHOS