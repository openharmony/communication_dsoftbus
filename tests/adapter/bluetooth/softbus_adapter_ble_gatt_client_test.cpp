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
#include <cstdint>

#include "bluetooth_mock.h"
#include "c_header/ohos_bt_def.h"
#include "softbus_adapter_ble_gatt_client.h"
#include "softbus_error_code.h"

#include "assert_helper.h"

using namespace testing::ext;
using ::testing::Return;

namespace OHOS {

// 调用上下文存储辅助对象
class GattcNotifyRecordCtx : public StRecordCtx {
public:
    explicit GattcNotifyRecordCtx(const char *identifier) : StRecordCtx(identifier)
    {
        Reset();
    }
    ~GattcNotifyRecordCtx()
    {
        Reset();
    }

    bool Update(int32_t id, int32_t st, SoftBusGattcNotify *param);
    testing::AssertionResult Expect(int32_t id, int32_t st, SoftBusGattcNotify *param);

private:
    SoftBusGattcNotify notify;
    void Reset();
};

class AdapterBleGattClientTest : public testing::Test {
public:
    static BtGattClientCallbacks *gattClientCallback;

    static IntRecordCtx connectionStateCtx;
    static StRecordCtx serviceCompleteStateCtx;
    static StRecordCtx registNotificationCtx;
    static IntRecordCtx configureMtuSizeCtx;
    static GattcNotifyRecordCtx notificationReceiveCtx;
};

static SoftBusGattcCallback *GetStubGattcCallback();

int32_t ActionBleGattcRegister(BtUuid appUuid)
{
    (void)appUuid;
    static int32_t idGenerator = 0;
    return ++idGenerator;
}

int32_t ActionBleGattcConnect(
    int32_t clientId, BtGattClientCallbacks *func, const BdAddr *bdAddr, bool isAutoConnect, BtTransportType transport)
{
    (void)clientId;
    (void)bdAddr;
    (void)isAutoConnect;
    (void)transport;
    AdapterBleGattClientTest::gattClientCallback = func;
    return OHOS_BT_STATUS_SUCCESS;
}

static void MockAll(MockBluetooth &mocker)
{
    EXPECT_CALL(mocker, BleGattcRegister).WillRepeatedly(ActionBleGattcRegister);
    EXPECT_CALL(mocker, BleGattcConnect).WillRepeatedly(ActionBleGattcConnect);
    EXPECT_CALL(mocker, BleGattcDisconnect).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_CALL(mocker, BleGattcSearchServices).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_CALL(mocker, BleGattcGetService).WillRepeatedly(Return(true));
    EXPECT_CALL(mocker, BleGattcRegisterNotification).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_CALL(mocker, BleGattcConfigureMtuSize).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_CALL(mocker, BleGattcWriteCharacteristic).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_CALL(mocker, BleGattcUnRegister).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_CALL(mocker, BleGattcSetFastestConn).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_CALL(mocker, BleGattcSetPriority).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
}

/**
 * @tc.name: AdapterBleGattClientTest_SoftbusGattcRegister
 * @tc.desc: test gatt client register
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattClientTest, SoftbusGattcRegister, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);
    EXPECT_CALL(mocker, BleGattcRegister).Times(1).WillOnce(Return(0));
    EXPECT_EQ(SoftbusGattcRegister(), -1);

    EXPECT_CALL(mocker, BleGattcRegister).WillRepeatedly(ActionBleGattcRegister);
    EXPECT_NE(SoftbusGattcRegister(), -1);
}

/**
 * @tc.name: AdapterBleGattClientTest_SoftbusGattcUnRegister
 * @tc.desc: test gatt client unregister
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattClientTest, SoftbusGattcUnRegister, TestSize.Level3)
{
    InitSoftbusAdapterClient();
    MockBluetooth mocker;
    MockAll(mocker);
    EXPECT_CALL(mocker, BleGattcUnRegister).Times(1).WillOnce(Return(OHOS_BT_STATUS_FAIL));
    EXPECT_EQ(SoftbusGattcUnRegister(1), SOFTBUS_GATTC_INTERFACE_FAILED);

    int32_t clientId = 10;
    SoftbusGattcRegisterCallback(GetStubGattcCallback(), clientId);
    EXPECT_CALL(mocker, BleGattcUnRegister).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_EQ(SoftbusGattcUnRegister(clientId), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattClientTest_SoftbusGattcConnect
 * @tc.desc: test gatt client connect
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattClientTest, SoftbusGattcConnect, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);

    SoftBusBtAddr addr = {
        .addr = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }
    };
    EXPECT_CALL(mocker, BleGattcConnect).Times(1).WillOnce(Return(OHOS_BT_STATUS_FAIL));
    EXPECT_EQ(SoftbusGattcConnect(1, &addr), SOFTBUS_GATTC_INTERFACE_FAILED);

    EXPECT_CALL(mocker, BleGattcConnect).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_EQ(SoftbusGattcConnect(1, &addr), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattClientTest_SoftbusBleGattcDisconnect
 * @tc.desc: test gatt client disconnect
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattClientTest, SoftbusBleGattcDisconnect, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);
    EXPECT_CALL(mocker, BleGattcDisconnect).Times(1).WillOnce(Return(OHOS_BT_STATUS_FAIL));
    EXPECT_EQ(SoftbusBleGattcDisconnect(1, false), SOFTBUS_GATTC_INTERFACE_FAILED);

    EXPECT_CALL(mocker, BleGattcDisconnect).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_EQ(SoftbusBleGattcDisconnect(1, false), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattClientTest_SoftbusGattcSearchServices
 * @tc.desc: test gatt client search service
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattClientTest, SoftbusGattcSearchServices, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);
    EXPECT_CALL(mocker, BleGattcSearchServices).Times(1).WillOnce(Return(OHOS_BT_STATUS_FAIL));
    EXPECT_EQ(SoftbusGattcSearchServices(1), SOFTBUS_GATTC_INTERFACE_FAILED);

    EXPECT_CALL(mocker, BleGattcSearchServices).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_EQ(SoftbusGattcSearchServices(1), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattClientTest_SoftbusGattcGetService
 * @tc.desc: test gatt client get service
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattClientTest, SoftbusGattcGetService, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);
    const char *serviceUuidExample = "11C8B310-80E4-4276-AFC0-F81590B2177F";
    SoftBusBtUuid serverUuid = {
        .uuidLen = strlen(serviceUuidExample),
        .uuid = (char *)serviceUuidExample,
    };

    EXPECT_CALL(mocker, BleGattcGetService).Times(1).WillOnce(Return(false));
    EXPECT_EQ(SoftbusGattcGetService(1, &serverUuid), SOFTBUS_GATTC_INTERFACE_FAILED);

    EXPECT_CALL(mocker, BleGattcGetService).WillRepeatedly(Return(true));
    EXPECT_EQ(SoftbusGattcGetService(1, &serverUuid), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattClientTest_SoftbusGattcRegisterNotification
 * @tc.desc: test gatt client register notification
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattClientTest, SoftbusGattcRegisterNotification, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);

    const char *serviceUuidExample = "11C8B310-80E4-4276-AFC0-F81590B2177F";
    SoftBusBtUuid serverUuid = {
        .uuidLen = strlen(serviceUuidExample),
        .uuid = (char *)serviceUuidExample,
    };
    const char *charaNetUuidExample = "00002B00-0000-1000-8000-00805F9B34FB";
    SoftBusBtUuid netUuid = {
        .uuidLen = strlen(charaNetUuidExample),
        .uuid = (char *)charaNetUuidExample,
    };
    EXPECT_CALL(mocker, BleGattcRegisterNotification).Times(1).WillOnce(Return(OHOS_BT_STATUS_FAIL));
    EXPECT_EQ(SoftbusGattcRegisterNotification(1, &serverUuid, &netUuid, NULL), SOFTBUS_GATTC_INTERFACE_FAILED);

    EXPECT_CALL(mocker, BleGattcRegisterNotification).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_EQ(SoftbusGattcRegisterNotification(1, &serverUuid, &netUuid, NULL), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattClientTest_SoftbusGattcWriteCharacteristic
 * @tc.desc: test gatt client write characteristic
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattClientTest, SoftbusGattcWriteCharacteristic, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);

    const char *serviceUuidExample = "11C8B310-80E4-4276-AFC0-F81590B2177F";
    SoftBusBtUuid serverUuid = {
        .uuidLen = strlen(serviceUuidExample),
        .uuid = (char *)serviceUuidExample,
    };
    const char *charaNetUuidExample = "00002B00-0000-1000-8000-00805F9B34FB";
    SoftBusBtUuid netUuid = {
        .uuidLen = strlen(charaNetUuidExample),
        .uuid = (char *)charaNetUuidExample,
    };
    const char *valueExample = "hello dsoftbus";
    SoftBusGattcData data = {
        .serviceUuid = serverUuid,
        .characterUuid = netUuid,
        .valueLen = strlen(valueExample),
        .value = (uint8_t *)valueExample,
    };
    EXPECT_CALL(mocker, BleGattcWriteCharacteristic).Times(1).WillOnce(Return(OHOS_BT_STATUS_FAIL));
    EXPECT_EQ(SoftbusGattcWriteCharacteristic(1, &data), SOFTBUS_GATTC_INTERFACE_FAILED);

    EXPECT_CALL(mocker, BleGattcWriteCharacteristic).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_EQ(SoftbusGattcWriteCharacteristic(1, &data), SOFTBUS_OK);

    data.writeType = SOFTBUS_GATT_WRITE_NO_RSP;
    EXPECT_EQ(SoftbusGattcWriteCharacteristic(1, &data), SOFTBUS_OK);

    data.writeType = SOFTBUS_GATT_WRITE_PREPARE;
    EXPECT_EQ(SoftbusGattcWriteCharacteristic(1, &data), SOFTBUS_OK);

    data.writeType = SOFTBUS_GATT_WRITE_DEFAULT;
    EXPECT_EQ(SoftbusGattcWriteCharacteristic(1, &data), SOFTBUS_OK);

    data.writeType = SOFTBUS_GATT_WRITE_SIGNED;
    EXPECT_EQ(SoftbusGattcWriteCharacteristic(1, &data), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattClientTest_SoftbusGattcConfigureMtuSize
 * @tc.desc: test gatt client write characteristic
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattClientTest, SoftbusGattcConfigureMtuSize, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);

    EXPECT_CALL(mocker, BleGattcConfigureMtuSize).Times(1).WillOnce(Return(OHOS_BT_STATUS_FAIL));
    EXPECT_EQ(SoftbusGattcConfigureMtuSize(1, 512), SOFTBUS_GATTC_INTERFACE_FAILED);

    EXPECT_CALL(mocker, BleGattcConfigureMtuSize).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_EQ(SoftbusGattcConfigureMtuSize(1, 512), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattClientTest_ScanLifecycle
 * @tc.desc: test complete gatt client connect life cycle
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattClientTest, GattClientConnectCycle1, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);

    auto clientId = SoftbusGattcRegister();
    ASSERT_NE(clientId, -1);
    SoftbusGattcRegisterCallback(GetStubGattcCallback(), clientId);
    SoftBusBtAddr addr = {
        .addr = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }
    };
    ASSERT_EQ(SoftbusGattcConnect(clientId, &addr), SOFTBUS_OK);
    gattClientCallback->ConnectionStateCb(clientId, OHOS_STATE_CONNECTED, OHOS_BT_STATUS_SUCCESS);
    ASSERT_TRUE(connectionStateCtx.Expect(clientId, OHOS_BT_STATUS_SUCCESS, OHOS_STATE_CONNECTED));

    ASSERT_EQ(SoftbusGattcSearchServices(clientId), SOFTBUS_OK);
    gattClientCallback->searchServiceCompleteCb(clientId, OHOS_BT_STATUS_SUCCESS);
    ASSERT_TRUE(serviceCompleteStateCtx.Expect(clientId, OHOS_BT_STATUS_SUCCESS));

    const char *serviceUuidExample = "11C8B310-80E4-4276-AFC0-F81590B2177F";
    SoftBusBtUuid serverUuid = {
        .uuidLen = strlen(serviceUuidExample),
        .uuid = (char *)serviceUuidExample,
    };
    ASSERT_EQ(SoftbusGattcGetService(clientId, &serverUuid), SOFTBUS_OK);

    const char *charaNetUuidExample = "00002B00-0000-1000-8000-00805F9B34FB";
    SoftBusBtUuid netUuid = {
        .uuidLen = strlen(charaNetUuidExample),
        .uuid = (char *)charaNetUuidExample,
    };
    ASSERT_EQ(SoftbusGattcRegisterNotification(clientId, &serverUuid, &netUuid, NULL), SOFTBUS_OK);
    gattClientCallback->registerNotificationCb(clientId, OHOS_BT_STATUS_SUCCESS);
    ASSERT_TRUE(registNotificationCtx.Expect(clientId, OHOS_BT_STATUS_SUCCESS));

    const char *charaConnUuidExample = "00002B00-0000-1000-8000-00805F9B34FB";
    SoftBusBtUuid connUuid = {
        .uuidLen = strlen(charaConnUuidExample),
        .uuid = (char *)charaConnUuidExample,
    };
    ASSERT_EQ(SoftbusGattcRegisterNotification(clientId, &serverUuid, &connUuid, NULL), SOFTBUS_OK);
    gattClientCallback->registerNotificationCb(clientId, OHOS_BT_STATUS_SUCCESS);
    ASSERT_TRUE(registNotificationCtx.Expect(clientId, OHOS_BT_STATUS_SUCCESS));

    int32_t mtu = 512;
    ASSERT_EQ(SoftbusGattcConfigureMtuSize(clientId, mtu), SOFTBUS_OK);
    gattClientCallback->configureMtuSizeCb(clientId, mtu, OHOS_BT_STATUS_SUCCESS);
    ASSERT_TRUE(configureMtuSizeCtx.Expect(clientId, OHOS_BT_STATUS_SUCCESS, mtu));
}

/**
 * @tc.name: AdapterBleGattClientTest_ScanLifecycle
 * @tc.desc: test complete gatt client connect life cycle
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattClientTest, GattClientConnectCycle2, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);

    auto clientId = SoftbusGattcRegister();
    SoftbusGattcRegisterCallback(GetStubGattcCallback(), clientId);

    const char *serviceUuidExample = "11C8B310-80E4-4276-AFC0-F81590B2177F";
    SoftBusBtUuid serverUuid = {
        .uuidLen = strlen(serviceUuidExample),
        .uuid = (char *)serviceUuidExample,
    };

    const char *charaNetUuidExample = "00002B00-0000-1000-8000-00805F9B34FB";
    SoftBusBtUuid netUuid = {
        .uuidLen = strlen(charaNetUuidExample),
        .uuid = (char *)charaNetUuidExample,
    };

    const char *valueExample = "hello dsoftbus";
    SoftBusGattcData data = {
        .serviceUuid = serverUuid,
        .characterUuid = netUuid,
        .valueLen = strlen(valueExample),
        .value = (uint8_t *)valueExample,
    };
    ASSERT_EQ(SoftbusGattcWriteCharacteristic(clientId, &data), SOFTBUS_OK);
    BtGattCharacteristic characteristic {
        .serviceUuid = {
            .uuidLen = strlen(serviceUuidExample),
            .uuid = (char *)serviceUuidExample,
        },
        .characteristicUuid = {
            .uuidLen = strlen(charaNetUuidExample),
            .uuid = (char *)charaNetUuidExample,
        },
    };
    BtGattReadData readData = {
        .attribute.characteristic = characteristic,
        .dataLen = strlen(valueExample),
        .data = (unsigned char *)valueExample,
    };
    gattClientCallback->notificationCb(clientId, &readData, OHOS_BT_STATUS_SUCCESS);

    SoftBusGattcNotify notify = {
        .charaUuid = {
            .uuidLen = strlen(charaNetUuidExample),
            .uuid = (char *)charaNetUuidExample,
        },
        .dataLen = strlen(valueExample),
        .data = (unsigned char *)valueExample,
    };
    ASSERT_TRUE(notificationReceiveCtx.Expect(clientId, OHOS_BT_STATUS_SUCCESS, &notify));
    ASSERT_EQ(SoftbusGattcUnRegister(clientId), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattClientTest_EnableFastestConn
 * @tc.desc: test ennable ble fatest connect
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattClientTest, EnableFastestConn, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);

    ASSERT_EQ(SoftbusGattcSetFastestConn(-1), SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(mocker, BleGattcSetFastestConn)
        .Times(2)
        .WillOnce(Return(OHOS_BT_STATUS_FAIL))
        .WillOnce(Return(OHOS_BT_STATUS_SUCCESS));
    ASSERT_EQ(SoftbusGattcSetFastestConn(1), SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_SET_FASTEST_ERR);
    ASSERT_EQ(SoftbusGattcSetFastestConn(1), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattClientTest_SetBleConnectionPriority
 * @tc.desc: test ennable ble fatest connect
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattClientTest, SetBleConnectionPriority, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);

    SoftBusBtAddr addr = {
        .addr = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }
    };
    ASSERT_EQ(SoftbusGattcSetPriority(-1, &addr, SOFTBUS_GATT_PRIORITY_BALANCED), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(SoftbusGattcSetPriority(1, nullptr, SOFTBUS_GATT_PRIORITY_BALANCED), SOFTBUS_INVALID_PARAM);
    ASSERT_EQ(SoftbusGattcSetPriority(-1, nullptr, SOFTBUS_GATT_PRIORITY_BALANCED), SOFTBUS_INVALID_PARAM);
    EXPECT_CALL(mocker, BleGattcSetPriority)
        .Times(2)
        .WillOnce(Return(OHOS_BT_STATUS_FAIL))
        .WillOnce(Return(OHOS_BT_STATUS_SUCCESS));
    ASSERT_EQ(SoftbusGattcSetPriority(1, &addr, SOFTBUS_GATT_PRIORITY_BALANCED),
        SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_SET_PRIORITY_ERR);
    ASSERT_EQ(SoftbusGattcSetPriority(1, &addr, SOFTBUS_GATT_PRIORITY_BALANCED), SOFTBUS_OK);
}

void GattcNotifyRecordCtx::Reset()
{
    SoftBusFree(notify.charaUuid.uuid);
    notify.charaUuid.uuid = nullptr;
    SoftBusFree(notify.data);
    notify.data = nullptr;
    (void)memset_s(&notify, sizeof(SoftBusGattcNotify), 0, sizeof(SoftBusGattcNotify));
}

bool GattcNotifyRecordCtx::Update(int32_t id, int32_t st, SoftBusGattcNotify *param)
{
    if (!StRecordCtx::Update(id, st)) {
        return false;
    }
    this->notify = *param;
    notify.charaUuid.uuid = (char *)SoftBusCalloc(param->charaUuid.uuidLen);
    notify.data = (uint8_t *)SoftBusCalloc(param->dataLen);
    if (notify.charaUuid.uuid == nullptr || notify.data == nullptr) {
        SoftBusFree(notify.charaUuid.uuid);
        SoftBusFree(notify.data);
        return false;
    }
    if (memcpy_s(notify.charaUuid.uuid, notify.charaUuid.uuidLen, param->charaUuid.uuid, param->charaUuid.uuidLen) !=
        EOK) {
        SoftBusFree(notify.charaUuid.uuid);
        SoftBusFree(notify.data);
        return false;
    }
    if (memcpy_s(notify.data, notify.dataLen, param->data, param->dataLen) != EOK) {
        SoftBusFree(notify.charaUuid.uuid);
        SoftBusFree(notify.data);
        return false;
    }
    return true;
}

testing::AssertionResult GattcNotifyRecordCtx::Expect(int32_t id, int32_t st, SoftBusGattcNotify *param)
{
    auto result = StRecordCtx::Expect(id, st);
    if (!result) {
        goto ClEANUP;
    }

    if (notify.dataLen != param->dataLen || memcmp(notify.data, param->data, notify.dataLen) != 0) {
        result = testing::AssertionFailure() << identifier << " is call by unexpectedly SoftBusGattcNotify data";
        goto ClEANUP;
    }

    if (notify.charaUuid.uuidLen != param->charaUuid.uuidLen ||
        memcmp(notify.charaUuid.uuid, param->charaUuid.uuid, notify.charaUuid.uuidLen) != 0) {
        result = testing::AssertionFailure() << identifier << " is call by unexpectedly SoftBusGattcNotify charaUuid";
        goto ClEANUP;
    }
    result = testing::AssertionSuccess();
ClEANUP:
    Reset();
    return result;
}

BtGattClientCallbacks *AdapterBleGattClientTest::gattClientCallback = nullptr;
IntRecordCtx AdapterBleGattClientTest::connectionStateCtx("ConnectionStateCallback");
StRecordCtx AdapterBleGattClientTest::serviceCompleteStateCtx("ServiceCompleteCallback");
StRecordCtx AdapterBleGattClientTest::registNotificationCtx("RegistNotificationCallback");
IntRecordCtx AdapterBleGattClientTest::configureMtuSizeCtx("ConfigureMtuSizeCallback");
GattcNotifyRecordCtx AdapterBleGattClientTest::notificationReceiveCtx("NotificationReceiveCallback");

void StubConnectionStateCallback(int32_t clientId, int32_t connState, int32_t status)
{
    AdapterBleGattClientTest::connectionStateCtx.Update(clientId, status, connState);
}

void StubServiceCompleteCallback(int32_t clientId, int32_t status)
{
    AdapterBleGattClientTest::serviceCompleteStateCtx.Update(clientId, status);
}

void StubRegistNotificationCallback(int32_t clientId, int32_t status)
{
    AdapterBleGattClientTest::registNotificationCtx.Update(clientId, status);
}

void StubNotificationReceiveCallback(int32_t clientId, SoftBusGattcNotify *param, int32_t status)
{
    AdapterBleGattClientTest::notificationReceiveCtx.Update(clientId, status, param);
}

void StubConfigureMtuSizeCallback(int32_t clientId, int32_t mtuSize, int32_t status)
{
    AdapterBleGattClientTest::configureMtuSizeCtx.Update(clientId, status, mtuSize);
}

static SoftBusGattcCallback *GetStubGattcCallback()
{
    static SoftBusGattcCallback callback = {
        .connectionStateCallback = StubConnectionStateCallback,
        .serviceCompleteCallback = StubServiceCompleteCallback,
        .registNotificationCallback = StubRegistNotificationCallback,
        .notificationReceiveCallback = StubNotificationReceiveCallback,
        .configureMtuSizeCallback = StubConfigureMtuSizeCallback,
    };
    return &callback;
}

} // namespace OHOS
