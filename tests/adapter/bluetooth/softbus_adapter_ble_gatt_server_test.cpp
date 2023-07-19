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

#include "bluetooth_mock.h"
#include "c_header/ohos_bt_def.h"
#include "c_header/ohos_bt_gatt_server.h"
#include "softbus_adapter_ble_gatt_server.h"
#include "softbus_error_code.h"

#include "assert_helper.h"

using namespace testing::ext;
using ::testing::Return;

#define MOCK_GATT_SERVER_HANDLE     0
#define MOCK_GATT_SERVICE_HANDLE    1
#define MOCK_GATT_CHARA_HANDLE      2
#define MOCK_GATT_DESCRIPTOR_HANDLE 3

namespace OHOS {

class BtUuidRecordCtx : public StRecordCtx {
public:
    explicit BtUuidRecordCtx(const char *identifier);
    ~BtUuidRecordCtx();
    bool Update(int id, int st, SoftBusBtUuid *param);
    testing::AssertionResult Expect(int id, int st, SoftBusBtUuid *param);
private:
    SoftBusBtUuid uuid;
    void Reset();
};

class BtGattRecordCtx : public BtUuidRecordCtx {
public:
    explicit BtGattRecordCtx(const char *identifier);
    bool Update(int id, int st, int handle, SoftBusBtUuid *param);
    testing::AssertionResult Expect(int id, int st, int handle, SoftBusBtUuid *param);
private:
    int handle;
};

class AdapterBleGattServerTest : public testing::Test {
public:
    static BtGattServerCallbacks *gattServerCallback;
    static BtUuidRecordCtx serviceAddCtx;
    static BtGattRecordCtx characteristicAddCtx;
    static BtGattRecordCtx descriptorAddCtx;
    static StRecordCtx serviceStartCtx;
    static StRecordCtx serviceStopCtx;
    static StRecordCtx serviceDeleteCtx;
    static BtAddrRecordCtx connectServerCtx;
    static BtAddrRecordCtx disconnectServerCtx;
    static SoftBusGattReadRequest requestReadCtx;
    static SoftBusGattWriteRequest requestWriteCtx;
    static StRecordCtx responseConfirmationCtx;
    static StRecordCtx notifySentCtx;
    static StRecordCtx mtuChangeCtx;
};

static SoftBusGattsCallback *GetStubGattsCallback();
static testing::AssertionResult ExpectGattReadRequest(SoftBusGattReadRequest actual, SoftBusGattReadRequest want);
static testing::AssertionResult ExpectGattWriteRequest(SoftBusGattWriteRequest actual, SoftBusGattWriteRequest want);

int ActionBleGattsRegisterCallbacks(BtGattServerCallbacks *func)
{
    AdapterBleGattServerTest::gattServerCallback = func;
    return OHOS_BT_STATUS_SUCCESS;
}

// 回绕到注册通知中
int ActionBleGattsRegister(BtUuid appUuid)
{
    AdapterBleGattServerTest::gattServerCallback->registerServerCb(0, MOCK_GATT_SERVER_HANDLE, &appUuid);
    return OHOS_BT_STATUS_SUCCESS;
}

static void MockAll(MockBluetooth &mocker)
{
    EXPECT_CALL(mocker, BleGattsRegisterCallbacks).WillRepeatedly(ActionBleGattsRegisterCallbacks);
    EXPECT_CALL(mocker, BleGattsRegister).WillRepeatedly(ActionBleGattsRegister);
    EXPECT_CALL(mocker, BleGattsAddService).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_CALL(mocker, BleGattsUnRegister).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_CALL(mocker, BleGattsAddCharacteristic).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_CALL(mocker, BleGattsAddDescriptor).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_CALL(mocker, BleGattsStartService).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_CALL(mocker, BleGattsStopService).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_CALL(mocker, BleGattsDeleteService).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_CALL(mocker, BleGattsDisconnect).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_CALL(mocker, BleGattsSendResponse).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    EXPECT_CALL(mocker, BleGattsSendIndication).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
}

/**
 * @tc.name: AdapterBleGattServerTest_SoftBusRegisterGattsCallbacks
 * @tc.desc: test register gatt server callbacks
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattServerTest, SoftBusRegisterGattsCallbacks, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);
    ASSERT_EQ(SoftBusRegisterGattsCallbacks(nullptr), SOFTBUS_BLECONNECTION_REG_GATTS_CALLBACK_FAIL)
        << "nullptr gatts callback scenor";
    // 清空状态，允许重入
    SoftBusUnRegisterGattsCallbacks();
    EXPECT_CALL(mocker, BleGattsRegisterCallbacks).WillRepeatedly(Return(OHOS_BT_STATUS_FAIL));
    ASSERT_EQ(SoftBusRegisterGattsCallbacks(GetStubGattsCallback()), SOFTBUS_BLECONNECTION_REG_GATTS_CALLBACK_FAIL)
        << "BleGattsRegisterCallbacks fail scenor";

    EXPECT_CALL(mocker, BleGattsRegisterCallbacks).WillRepeatedly(ActionBleGattsRegisterCallbacks);
    EXPECT_CALL(mocker, BleGattsRegister).WillRepeatedly(Return(OHOS_BT_STATUS_FAIL));
    ASSERT_EQ(SoftBusRegisterGattsCallbacks(GetStubGattsCallback()), SOFTBUS_BLECONNECTION_REG_GATTS_CALLBACK_FAIL)
        << "BleGattsRegister fail scenor";

    EXPECT_CALL(mocker, BleGattsRegister).WillRepeatedly(ActionBleGattsRegister);
    ASSERT_EQ(SoftBusRegisterGattsCallbacks(GetStubGattsCallback()), SOFTBUS_OK);
    // 清空状态
    SoftBusUnRegisterGattsCallbacks();
}

/**
 * @tc.name: AdapterBleGattServerTest_SoftBusUnRegisterGattsCallbacks
 * @tc.desc: test unregister gatt server callbacks
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattServerTest, SoftBusUnRegisterGattsCallbacks, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);
    ASSERT_EQ(SoftBusRegisterGattsCallbacks(GetStubGattsCallback()), SOFTBUS_OK);

    EXPECT_CALL(mocker, BleGattsUnRegister).Times(1).WillOnce(Return(OHOS_BT_STATUS_FAIL));
    SoftBusUnRegisterGattsCallbacks();

    EXPECT_CALL(mocker, BleGattsUnRegister).Times(1).WillOnce(Return(OHOS_BT_STATUS_SUCCESS));
    SoftBusUnRegisterGattsCallbacks();
}

/**
 * @tc.name: AdapterBleGattServerTest_SoftBusGattsAddService
 * @tc.desc: test add gatt service
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattServerTest, SoftBusGattsAddService, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);
    ASSERT_EQ(SoftBusRegisterGattsCallbacks(GetStubGattsCallback()), SOFTBUS_OK);

    // 注册service
    const char *serviceUuid = "11C8B310-80E4-4276-AFC0-F81590B2177F";
    SoftBusBtUuid service = {
        .uuidLen = 0,
        .uuid = nullptr,
    };
    ASSERT_EQ(SoftBusGattsAddService(service, true, 1), SOFTBUS_ERR);

    EXPECT_CALL(mocker, BleGattsAddService).Times(1).WillOnce(Return(OHOS_BT_STATUS_FAIL));
    service.uuid = (char *)serviceUuid;
    service.uuidLen = strlen(serviceUuid);
    ASSERT_EQ(SoftBusGattsAddService(service, true, 1), SOFTBUS_ERR);

    EXPECT_CALL(mocker, BleGattsAddService).WillRepeatedly(Return(OHOS_BT_STATUS_SUCCESS));
    ASSERT_EQ(SoftBusGattsAddService(service, true, 1), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattServerTest_SoftBusGattsAddCharacteristic
 * @tc.desc: test add gatt characteristic
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattServerTest, SoftBusGattsAddCharacteristic, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);
    ASSERT_EQ(SoftBusRegisterGattsCallbacks(GetStubGattsCallback()), SOFTBUS_OK);

    SoftBusBtUuid characteristic = {
        .uuidLen = 0,
        .uuid = nullptr,
    };
    int properties = SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_READ | SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_WRITE_NO_RSP |
        SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_WRITE | SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_NOTIFY |
        SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_INDICATE;
    int permissions = SOFTBUS_GATT_PERMISSION_READ | SOFTBUS_GATT_PERMISSION_WRITE;
    ASSERT_EQ(
        SoftBusGattsAddCharacteristic(MOCK_GATT_SERVICE_HANDLE, characteristic, properties, permissions), SOFTBUS_ERR);

    const char *netCharacteristic = "00002B00-0000-1000-8000-00805F9B34FB";
    characteristic.uuid = (char *)netCharacteristic;
    characteristic.uuidLen = strlen(netCharacteristic);
    EXPECT_CALL(mocker, BleGattsAddCharacteristic).Times(1).WillOnce(Return(OHOS_BT_STATUS_FAIL));
    ASSERT_EQ(
        SoftBusGattsAddCharacteristic(MOCK_GATT_SERVICE_HANDLE, characteristic, properties, permissions), SOFTBUS_ERR);

    EXPECT_CALL(mocker, BleGattsAddCharacteristic).Times(1).WillOnce(Return(OHOS_BT_STATUS_SUCCESS));
    ASSERT_EQ(
        SoftBusGattsAddCharacteristic(MOCK_GATT_SERVICE_HANDLE, characteristic, properties, permissions), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattServerTest_SoftBusGattsAddDescriptor
 * @tc.desc: test add gatt descriptor
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattServerTest, SoftBusGattsAddDescriptor, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);
    ASSERT_EQ(SoftBusRegisterGattsCallbacks(GetStubGattsCallback()), SOFTBUS_OK);

    SoftBusBtUuid desciptor = {
        .uuidLen = 0,
        .uuid = nullptr,
    };
    int permissions = SOFTBUS_GATT_PERMISSION_READ | SOFTBUS_GATT_PERMISSION_WRITE;
    ASSERT_EQ(SoftBusGattsAddDescriptor(MOCK_GATT_SERVICE_HANDLE, desciptor, permissions), SOFTBUS_ERR);

    const char *connDesciptor = "00002902-0000-1000-8000-00805F9B34FB";
    desciptor.uuid = (char *)connDesciptor;
    desciptor.uuidLen = strlen(connDesciptor);

    EXPECT_CALL(mocker, BleGattsAddDescriptor).Times(1).WillOnce(Return(OHOS_BT_STATUS_FAIL));
    ASSERT_EQ(SoftBusGattsAddDescriptor(MOCK_GATT_SERVICE_HANDLE, desciptor, permissions), SOFTBUS_ERR);
    EXPECT_CALL(mocker, BleGattsAddDescriptor).Times(1).WillOnce(Return(OHOS_BT_STATUS_SUCCESS));
    ASSERT_EQ(SoftBusGattsAddDescriptor(MOCK_GATT_SERVICE_HANDLE, desciptor, permissions), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattServerTest_SoftBusGattsStartService
 * @tc.desc: test start gatt service
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattServerTest, SoftBusGattsStartService, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);
    ASSERT_EQ(SoftBusRegisterGattsCallbacks(GetStubGattsCallback()), SOFTBUS_OK);

    EXPECT_CALL(mocker, BleGattsStartService).Times(1).WillOnce(Return(OHOS_BT_STATUS_FAIL));
    ASSERT_EQ(SoftBusGattsStartService(MOCK_GATT_SERVICE_HANDLE), SOFTBUS_ERR);

    EXPECT_CALL(mocker, BleGattsStartService).Times(1).WillOnce(Return(OHOS_BT_STATUS_SUCCESS));
    ASSERT_EQ(SoftBusGattsStartService(MOCK_GATT_SERVICE_HANDLE), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattServerTest_SoftBusGattsStopService
 * @tc.desc: test stop gatt service
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattServerTest, SoftBusGattsStopService, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);
    ASSERT_EQ(SoftBusRegisterGattsCallbacks(GetStubGattsCallback()), SOFTBUS_OK);

    EXPECT_CALL(mocker, BleGattsStopService).Times(1).WillOnce(Return(OHOS_BT_STATUS_FAIL));
    ASSERT_EQ(SoftBusGattsStopService(MOCK_GATT_SERVICE_HANDLE), SOFTBUS_ERR);

    EXPECT_CALL(mocker, BleGattsStopService).Times(1).WillOnce(Return(OHOS_BT_STATUS_SUCCESS));
    ASSERT_EQ(SoftBusGattsStopService(MOCK_GATT_SERVICE_HANDLE), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattServerTest_SoftBusGattsDeleteService
 * @tc.desc: test delete gatt service
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattServerTest, SoftBusGattsDeleteService, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);
    ASSERT_EQ(SoftBusRegisterGattsCallbacks(GetStubGattsCallback()), SOFTBUS_OK);

    EXPECT_CALL(mocker, BleGattsDeleteService).Times(1).WillOnce(Return(OHOS_BT_STATUS_FAIL));
    ASSERT_EQ(SoftBusGattsDeleteService(MOCK_GATT_SERVICE_HANDLE), SOFTBUS_ERR);

    EXPECT_CALL(mocker, BleGattsDeleteService).Times(1).WillOnce(Return(OHOS_BT_STATUS_SUCCESS));
    ASSERT_EQ(SoftBusGattsDeleteService(MOCK_GATT_SERVICE_HANDLE), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattServerTest_SoftBusGattsDisconnect
 * @tc.desc: test disconnect gatt connection
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattServerTest, SoftBusGattsDisconnect, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);
    ASSERT_EQ(SoftBusRegisterGattsCallbacks(GetStubGattsCallback()), SOFTBUS_OK);

    int connId = 1;
    SoftBusBtAddr addr = {
        .addr = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
    };
    EXPECT_CALL(mocker, BleGattsDisconnect).Times(1).WillOnce(Return(OHOS_BT_STATUS_FAIL));
    ASSERT_EQ(SoftBusGattsDisconnect(addr, connId), SOFTBUS_ERR);

    EXPECT_CALL(mocker, BleGattsDisconnect).Times(1).WillOnce(Return(OHOS_BT_STATUS_SUCCESS));
    ASSERT_EQ(SoftBusGattsDisconnect(addr, connId), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattServerTest_SoftBusGattsSendResponse
 * @tc.desc: test send gatt response
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattServerTest, SoftBusGattsSendResponse, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);
    ASSERT_EQ(SoftBusRegisterGattsCallbacks(GetStubGattsCallback()), SOFTBUS_OK);

    SoftBusGattsResponse resp = {0};
    EXPECT_CALL(mocker, BleGattsSendResponse).Times(1).WillOnce(Return(OHOS_BT_STATUS_FAIL));
    ASSERT_EQ(SoftBusGattsSendResponse(&resp), SOFTBUS_ERR);

    EXPECT_CALL(mocker, BleGattsSendResponse).Times(1).WillOnce(Return(OHOS_BT_STATUS_SUCCESS));
    ASSERT_EQ(SoftBusGattsSendResponse(&resp), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattServerTest_SoftBusGattsSendNotify
 * @tc.desc: test send gatt notify
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattServerTest, SoftBusGattsSendNotify, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);
    ASSERT_EQ(SoftBusRegisterGattsCallbacks(GetStubGattsCallback()), SOFTBUS_OK);

    SoftBusGattsNotify notify = {0};
    EXPECT_CALL(mocker, BleGattsSendIndication).Times(1).WillOnce(Return(OHOS_BT_STATUS_FAIL));
    ASSERT_EQ(SoftBusGattsSendNotify(&notify), SOFTBUS_ERR);

    EXPECT_CALL(mocker, BleGattsSendIndication).Times(1).WillOnce(Return(OHOS_BT_STATUS_SUCCESS));
    ASSERT_EQ(SoftBusGattsSendNotify(&notify), SOFTBUS_OK);
}

/**
 * @tc.name: AdapterBleGattServerTest_GattServerLifeCycle
 * @tc.desc: test gatt server complete life cyclel, from a real usage perspective, important
 * @tc.type: FUNC
 * @tc.require: NONE
 */
HWTEST_F(AdapterBleGattServerTest, GattServerLifeCycle, TestSize.Level3)
{
    MockBluetooth mocker;
    MockAll(mocker);
    ASSERT_EQ(SoftBusRegisterGattsCallbacks(GetStubGattsCallback()), SOFTBUS_OK);

    // 注册service
    const char *serviceUuid = "11C8B310-80E4-4276-AFC0-F81590B2177F";
    SoftBusBtUuid service = {
        .uuidLen = strlen(serviceUuid),
        .uuid = (char *)serviceUuid,
    };
    ASSERT_EQ(SoftBusGattsAddService(service, true, 8), SOFTBUS_OK);
    BtUuid btService = {
        .uuidLen = strlen(serviceUuid),
        .uuid = (char *)serviceUuid,
    };
    gattServerCallback->serviceAddCb(
        OHOS_BT_STATUS_SUCCESS, MOCK_GATT_SERVER_HANDLE, &btService, MOCK_GATT_SERVICE_HANDLE);
    ASSERT_TRUE(serviceAddCtx.Expect(MOCK_GATT_SERVICE_HANDLE, SOFTBUS_OK, &service));

    // 注册charateristic
    const char *netCharacteristic = "00002B00-0000-1000-8000-00805F9B34FB";
    SoftBusBtUuid characteristic = {
        .uuidLen = strlen(netCharacteristic),
        .uuid = (char *)netCharacteristic,
    };
    int properties = SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_READ | SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_WRITE_NO_RSP |
        SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_WRITE | SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_NOTIFY |
        SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_INDICATE;
    int charaPermissions = SOFTBUS_GATT_PERMISSION_READ | SOFTBUS_GATT_PERMISSION_WRITE;
    ASSERT_EQ(SoftBusGattsAddCharacteristic(MOCK_GATT_SERVICE_HANDLE, characteristic, properties, charaPermissions),
        SOFTBUS_OK);
    BtUuid btCharacteristic = {
        .uuidLen = strlen(netCharacteristic),
        .uuid = (char *)netCharacteristic,
    };
    gattServerCallback->characteristicAddCb(OHOS_BT_STATUS_SUCCESS, MOCK_GATT_SERVER_HANDLE, &btCharacteristic,
        MOCK_GATT_SERVICE_HANDLE, MOCK_GATT_CHARA_HANDLE);
    ASSERT_TRUE(
        characteristicAddCtx.Expect(MOCK_GATT_SERVICE_HANDLE, SOFTBUS_OK, MOCK_GATT_CHARA_HANDLE, &characteristic));

    // 注册desciptor
    const char *connDesciptor = "00002902-0000-1000-8000-00805F9B34FB";
    int descriptorPermissions = SOFTBUS_GATT_PERMISSION_READ | SOFTBUS_GATT_PERMISSION_WRITE;
    SoftBusBtUuid descriptor = {
        .uuidLen = strlen(connDesciptor),
        .uuid = (char *)connDesciptor,
    };
    ASSERT_EQ(SoftBusGattsAddDescriptor(MOCK_GATT_SERVICE_HANDLE, descriptor, descriptorPermissions), SOFTBUS_OK);
    BtUuid btDescriptor = {
        .uuidLen = strlen(connDesciptor),
        .uuid = (char *)connDesciptor,
    };
    gattServerCallback->descriptorAddCb(OHOS_BT_STATUS_SUCCESS, MOCK_GATT_SERVER_HANDLE, &btDescriptor,
        MOCK_GATT_SERVICE_HANDLE, MOCK_GATT_DESCRIPTOR_HANDLE);
    ASSERT_TRUE(
        descriptorAddCtx.Expect(MOCK_GATT_SERVICE_HANDLE, SOFTBUS_OK, MOCK_GATT_DESCRIPTOR_HANDLE, &descriptor));

    // 启动Listen
    ASSERT_EQ(SoftBusGattsStartService(MOCK_GATT_SERVICE_HANDLE), SOFTBUS_OK);
    gattServerCallback->serviceStartCb(OHOS_BT_STATUS_SUCCESS, MOCK_GATT_SERVER_HANDLE, MOCK_GATT_SERVICE_HANDLE);
    ASSERT_TRUE(serviceStartCtx.Expect(MOCK_GATT_SERVICE_HANDLE, SOFTBUS_OK));

    // server建链
    int connectionId = 1;
    BdAddr bdAddr = {
        .addr = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
    };
    gattServerCallback->connectServerCb(connectionId, MOCK_GATT_SERVER_HANDLE, &bdAddr);
    SoftBusBtAddr addr = {
        .addr = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
    };
    ASSERT_TRUE(connectServerCtx.Expect(connectionId, &addr));

    // 读写数据，及响应回复
    const char *valueExample = "hello gatt server, this is client";
    BtReqWriteCbPara btWriteParam = {
        .connId = connectionId,
        .transId = 0,
        .bdAddr = &bdAddr,
        .attrHandle = MOCK_GATT_CHARA_HANDLE,
        .offset = 0,
        .length = strlen(valueExample),
        .needRsp = true,
        .isPrep = false,
        .value = (unsigned char *)valueExample,
    };
    gattServerCallback->requestWriteCb(btWriteParam);
    SoftBusGattWriteRequest writeParam = {
        .connId = connectionId,
        .transId = 0,
        .btAddr = &addr,
        .attrHandle = MOCK_GATT_CHARA_HANDLE,
        .offset = 0,
        .length = strlen(valueExample),
        .needRsp = true,
        .isPrep = false,
        .value = (unsigned char *)valueExample,
    };
    ASSERT_TRUE(ExpectGattWriteRequest(requestWriteCtx, writeParam));
    SoftBusGattsResponse resp = {0};
    ASSERT_EQ(SoftBusGattsSendResponse(&resp), SOFTBUS_OK);

    BtReqReadCbPara btReadParam = {
        .connId = connectionId,
        .transId = 0,
        .bdAddr = &bdAddr,
        .attrHandle = MOCK_GATT_CHARA_HANDLE,
        .offset = 0,
        .isLong = false,
    };
    gattServerCallback->requestReadCb(btReadParam);
    SoftBusGattReadRequest readParam = {
        .connId = connectionId,
        .transId = 0,
        .btAddr = &addr,
        .attrHandle = MOCK_GATT_CHARA_HANDLE,
        .offset = 0,
        .isLong = false,
    };
    ASSERT_TRUE(ExpectGattReadRequest(requestReadCtx, readParam));
    SoftBusGattsNotify notify = {0};
    ASSERT_EQ(SoftBusGattsSendNotify(&notify), SOFTBUS_OK);

    // server断链
    ASSERT_EQ(SoftBusGattsDisconnect(addr, connectionId), SOFTBUS_OK);
    gattServerCallback->disconnectServerCb(connectionId, MOCK_GATT_SERVER_HANDLE, &bdAddr);
    ASSERT_TRUE(disconnectServerCtx.Expect(connectionId, &addr));

    // 停止GATT service
    ASSERT_EQ(SoftBusGattsStopService(MOCK_GATT_SERVER_HANDLE), SOFTBUS_OK);
    gattServerCallback->serviceStopCb(OHOS_BT_STATUS_SUCCESS, MOCK_GATT_SERVER_HANDLE, MOCK_GATT_SERVICE_HANDLE);
    ASSERT_TRUE(serviceStopCtx.Expect(MOCK_GATT_SERVICE_HANDLE, SOFTBUS_OK));

    // 删除GATT service
    ASSERT_EQ(SoftBusGattsDeleteService(MOCK_GATT_SERVER_HANDLE), SOFTBUS_OK);
    gattServerCallback->serviceDeleteCb(OHOS_BT_STATUS_SUCCESS, MOCK_GATT_SERVER_HANDLE, MOCK_GATT_SERVICE_HANDLE);
    ASSERT_TRUE(serviceDeleteCtx.Expect(MOCK_GATT_SERVICE_HANDLE, SOFTBUS_OK));
}

BtUuidRecordCtx::BtUuidRecordCtx(const char *identifier) : StRecordCtx(identifier)
{
    Reset();
}
BtUuidRecordCtx::~BtUuidRecordCtx()
{
    Reset();
}

void BtUuidRecordCtx::Reset()
{
    SoftBusFree(uuid.uuid);
    uuid.uuid = nullptr;
    uuid.uuidLen = 0;
}

bool BtUuidRecordCtx::Update(int id, int st, SoftBusBtUuid *param)
{
    if (!StRecordCtx::Update(id, st)) {
        return false;
    }
    uuid.uuid = (char *)SoftBusCalloc(param->uuidLen);
    if (uuid.uuid == nullptr) {
        return false;
    }
    if (memcpy_s(uuid.uuid, param->uuidLen, param->uuid, param->uuidLen) != EOK) {
        return false;
    }
    uuid.uuidLen = param->uuidLen;
    return true;
}

testing::AssertionResult BtUuidRecordCtx::Expect(int id, int st, SoftBusBtUuid *param)
{
    auto result = StRecordCtx::Expect(id, st);
    if (!result) {
        goto ClEANUP;
    }
    if (uuid.uuidLen != param->uuidLen || memcmp(uuid.uuid, param->uuid, uuid.uuidLen) != 0) {
        result = testing::AssertionFailure() << identifier << " is call by unexpectedly uuid";
        goto ClEANUP;
    }
    result = testing::AssertionSuccess();
ClEANUP:
    Reset();
    return result;
}

BtGattRecordCtx::BtGattRecordCtx(const char *identifier) : BtUuidRecordCtx(identifier)
{
    handle = -1;
}

bool BtGattRecordCtx::Update(int id, int st, int handleParam, SoftBusBtUuid *param)
{
    if (!BtUuidRecordCtx::Update(id, st, param)) {
        return false;
    }
    this->handle = handleParam;
    return true;
}

testing::AssertionResult BtGattRecordCtx::Expect(int id, int st, int handleParam, SoftBusBtUuid *param)
{
    auto result = BtUuidRecordCtx::Expect(id, st, param);
    if (!result) {
        goto ClEANUP;
    }
    if (this->handle != handleParam) {
        result = testing::AssertionFailure() << identifier << " is call by unexpectedly state,"
                                             << "want: " << handleParam << ", actual: " << this->handle;
        goto ClEANUP;
    }
    result = testing::AssertionSuccess();
ClEANUP:
    this->handle = -1;
    return result;
}

BtGattServerCallbacks *AdapterBleGattServerTest::gattServerCallback = nullptr;
BtUuidRecordCtx AdapterBleGattServerTest::serviceAddCtx("ServiceAddCallback");
BtGattRecordCtx AdapterBleGattServerTest::characteristicAddCtx("CharacteristicAddCallback");
BtGattRecordCtx AdapterBleGattServerTest::descriptorAddCtx("DescriptorAddCallback");
StRecordCtx AdapterBleGattServerTest::serviceStartCtx("ServiceStartCallback");
StRecordCtx AdapterBleGattServerTest::serviceStopCtx("ServiceStopCallback");
StRecordCtx AdapterBleGattServerTest::serviceDeleteCtx("ServiceDeleteCallback");
BtAddrRecordCtx AdapterBleGattServerTest::connectServerCtx("ConnectServerCallback");
BtAddrRecordCtx AdapterBleGattServerTest::disconnectServerCtx("DisconnectServerCallback");
SoftBusGattReadRequest AdapterBleGattServerTest::requestReadCtx = {0};
SoftBusGattWriteRequest AdapterBleGattServerTest::requestWriteCtx = {0};
StRecordCtx AdapterBleGattServerTest::responseConfirmationCtx("ResponseConfirmationCallback");
StRecordCtx AdapterBleGattServerTest::notifySentCtx("NotifySentCallback");
StRecordCtx AdapterBleGattServerTest::mtuChangeCtx("MtuChangeCallback");

static void StubServiceAddCallback(int status, SoftBusBtUuid *uuid, int srvcHandle)
{
    AdapterBleGattServerTest::serviceAddCtx.Update(srvcHandle, status, uuid);
}

static void StubCharacteristicAddCallback(int status, SoftBusBtUuid *uuid, int srvcHandle, int characteristicHandle)
{
    AdapterBleGattServerTest::characteristicAddCtx.Update(srvcHandle, status, characteristicHandle, uuid);
}

static void StubDescriptorAddCallback(int status, SoftBusBtUuid *uuid, int srvcHandle, int descriptorHandle)
{
    AdapterBleGattServerTest::descriptorAddCtx.Update(srvcHandle, status, descriptorHandle, uuid);
}

static void StubServiceStartCallback(int status, int srvcHandle)
{
    AdapterBleGattServerTest::serviceStartCtx.Update(srvcHandle, status);
}

static void StubServiceStopCallback(int status, int srvcHandle)
{
    AdapterBleGattServerTest::serviceStopCtx.Update(srvcHandle, status);
}

static void StubServiceDeleteCallback(int status, int srvcHandle)
{
    AdapterBleGattServerTest::serviceDeleteCtx.Update(srvcHandle, status);
}

static void StubConnectServerCallback(int connId, const SoftBusBtAddr *btAddr)
{
    AdapterBleGattServerTest::connectServerCtx.Update(connId, btAddr);
}

static void StubDisconnectServerCallback(int connId, const SoftBusBtAddr *btAddr)
{
    AdapterBleGattServerTest::disconnectServerCtx.Update(connId, btAddr);
}

static void StubRequestReadCallback(SoftBusGattReadRequest readCbPara)
{
    AdapterBleGattServerTest::requestReadCtx = readCbPara;
}

static void StubRequestWriteCallback(SoftBusGattWriteRequest writeCbPara)
{
    AdapterBleGattServerTest::requestWriteCtx = writeCbPara;
}

static void StubResponseConfirmationCallback(int status, int handle)
{
    AdapterBleGattServerTest::responseConfirmationCtx.Update(handle, status);
}
static void StubNotifySentCallback(int connId, int status)
{
    AdapterBleGattServerTest::notifySentCtx.Update(connId, status);
}
static void StubMtuChangeCallback(int connId, int mtu)
{
    AdapterBleGattServerTest::mtuChangeCtx.Update(connId, mtu);
}

static SoftBusGattsCallback *GetStubGattsCallback()
{
    static SoftBusGattsCallback callbacks = {
        .ServiceAddCallback = StubServiceAddCallback,
        .CharacteristicAddCallback = StubCharacteristicAddCallback,
        .DescriptorAddCallback = StubDescriptorAddCallback,
        .ServiceStartCallback = StubServiceStartCallback,
        .ServiceStopCallback = StubServiceStopCallback,
        .ServiceDeleteCallback = StubServiceDeleteCallback,
        .ConnectServerCallback = StubConnectServerCallback,
        .DisconnectServerCallback = StubDisconnectServerCallback,
        .RequestReadCallback = StubRequestReadCallback,
        .RequestWriteCallback = StubRequestWriteCallback,
        .ResponseConfirmationCallback = StubResponseConfirmationCallback,
        .NotifySentCallback = StubNotifySentCallback,
        .MtuChangeCallback = StubMtuChangeCallback,
    };
    return &callbacks;
}

static testing::AssertionResult ExpectGattWriteRequest(SoftBusGattWriteRequest actual, SoftBusGattWriteRequest want)
{
    if (want.connId != actual.connId ||
        want.transId != actual.transId ||
        memcmp(want.btAddr->addr, actual.btAddr->addr, BT_ADDR_LEN) != 0 ||
        want.attrHandle != actual.attrHandle ||
        want.offset != actual.offset ||
        want.length != actual.length ||
        !(want.needRsp ? actual.needRsp : !actual.needRsp) ||
        !(want.isPrep ? actual.isPrep : !actual.isPrep) ||
        memcmp(want.value, actual.value, want.length) != 0) {
        return testing::AssertionFailure() << "SoftBusGattWriteRequest is unexpected";
    }
    return testing::AssertionSuccess();
}

static testing::AssertionResult ExpectGattReadRequest(SoftBusGattReadRequest actual, SoftBusGattReadRequest want)
{
    if (want.connId != actual.connId ||
        want.transId != actual.transId ||
        memcmp(want.btAddr->addr, actual.btAddr->addr, BT_ADDR_LEN) != 0 ||
        want.attrHandle != actual.attrHandle ||
        want.offset != actual.offset ||
        !(want.isLong ? actual.isLong : !actual.isLong)) {
        return testing::AssertionFailure() << "SoftBusGattReadRequest is unexpected";
    }
    return testing::AssertionSuccess();
}

} // namespace OHOS