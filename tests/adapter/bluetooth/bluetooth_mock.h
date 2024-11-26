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

#ifndef BLUETOOTH_MOCK_H
#define BLUETOOTH_MOCK_H

#include "gmock/gmock.h"

#include "c_header/ohos_bt_gap.h"
#include "c_header/ohos_bt_gatt.h"
#include "c_header/ohos_bt_gatt_client.h"
#include "c_header/ohos_bt_gatt_server.h"

#include "softbus_adapter_bt_common.h"

// declare mock symbols explicitly which hava C implement, redirected to mocker when linking
class BluetoothInterface {
public:
    // 蓝牙公共能力
    virtual bool EnableBle() = 0;
    virtual bool DisableBle() = 0;
    virtual bool IsBleEnabled() = 0;
    virtual bool GetLocalAddr(unsigned char *mac, unsigned int len) = 0;
    virtual bool SetLocalName(unsigned char *localName, unsigned char length) = 0;
    virtual int GapRegisterCallbacks(BtGapCallBacks *func) = 0;
    virtual bool PairRequestReply(const BdAddr *bdAddr, int transport, bool accept) = 0;
    virtual bool SetDevicePairingConfirmation(const BdAddr *bdAddr, int transport, bool accept) = 0;

    // BLE广播相关
    virtual int BleGattRegisterCallbacks(BtGattCallbacks *func) = 0;
    virtual int BleStartScanEx(
        int scannerId, BleScanConfigs *configs, BleScanNativeFilter *filter, unsigned int filterSize) = 0;
    virtual int BleStopScan(int scannerId) = 0;
    virtual int BleStartAdvEx(int *advId, const StartAdvRawData rawData, BleAdvParams advParam) = 0;
    virtual int BleStopAdv(int advId) = 0;

    // GATT Client相关
    virtual int BleGattcRegister(BtUuid appUuid) = 0;
    virtual int BleGattcConnect(int clientId, BtGattClientCallbacks *func, const BdAddr *bdAddr, bool isAutoConnect,
        BtTransportType transport) = 0;
    virtual int BleGattcDisconnect(int clientId) = 0;
    virtual int BleGattcSearchServices(int clientId) = 0;
    virtual bool BleGattcGetService(int clientId, BtUuid serviceUuid) = 0;
    virtual int BleGattcRegisterNotification(int clientId, BtGattCharacteristic characteristic, bool enable) = 0;
    virtual int BleGattcConfigureMtuSize(int clientId, int mtuSize) = 0;
    virtual int BleGattcWriteCharacteristic(
        int clientId, BtGattCharacteristic characteristic, BtGattWriteType writeType, int len, const char *value) = 0;
    virtual int BleGattcUnRegister(int clientId) = 0;
    virtual int BleGattcSetFastestConn(int clientId, bool fastestConnFlag) = 0;
    virtual int BleGattcSetPriority(int clientId, const BdAddr *bdAddr, BtGattPriority priority) = 0;

    // GATT Server相关
    virtual int BleGattsRegisterCallbacks(BtGattServerCallbacks *func) = 0;
    virtual int BleGattsRegister(BtUuid appUuid);
    virtual int BleGattsAddService(int serverId, BtUuid srvcUuid, bool isPrimary, int number) = 0;
    virtual int BleGattsUnRegister(int serverId);
    virtual int BleGattsAddCharacteristic(
        int serverId, int srvcHandle, BtUuid characUuid, int properties, int permissions) = 0;
    virtual int BleGattsAddDescriptor(int serverId, int srvcHandle, BtUuid descUuid, int permissions) = 0;
    virtual int BleGattsStartService(int serverId, int srvcHandle) = 0;
    virtual int BleGattsStopService(int serverId, int srvcHandle) = 0;
    virtual int BleGattsDeleteService(int serverId, int srvcHandle) = 0;
    virtual int BleGattsDisconnect(int serverId, BdAddr bdAddr, int connId) = 0;
    virtual int BleGattsSendResponse(int serverId, GattsSendRspParam *param) = 0;
    virtual int BleGattsSendIndication(int serverId, GattsSendIndParam *param) = 0;
};

class MockBluetooth : public BluetoothInterface {
public:
    MockBluetooth();
    ~MockBluetooth();

    MOCK_METHOD(bool, EnableBle, (), (override));
    MOCK_METHOD(bool, DisableBle, (), (override));
    MOCK_METHOD(bool, IsBleEnabled, (), (override));
    MOCK_METHOD(bool, GetLocalAddr, (unsigned char *mac, unsigned int len), (override));
    MOCK_METHOD(bool, SetLocalName, (unsigned char *localName, unsigned char length), (override));
    MOCK_METHOD(int32_t, GapRegisterCallbacks, (BtGapCallBacks * func), (override));
    MOCK_METHOD(bool, PairRequestReply, (const BdAddr *bdAddr, int transport, bool accept), (override));
    MOCK_METHOD(bool, SetDevicePairingConfirmation, (const BdAddr *bdAddr, int transport, bool accept), (override));

    MOCK_METHOD(int32_t, BleGattRegisterCallbacks, (BtGattCallbacks * func), (override));
    MOCK_METHOD(int32_t, BleStartScanEx,
        (int scannerId, BleScanConfigs *configs, BleScanNativeFilter *filter, unsigned int filterSize), (override));
    MOCK_METHOD(int32_t, BleStopScan, (int scannerId), (override));
    MOCK_METHOD(int32_t, BleStartAdvEx, (int *advId, const StartAdvRawData rawData, BleAdvParams advParam), (override));
    MOCK_METHOD(int32_t, BleStopAdv, (int advId), (override));

    MOCK_METHOD(int32_t, BleGattcRegister, (BtUuid appUuid), (override));
    MOCK_METHOD(int32_t, BleGattcConnect,
        (int clientId, BtGattClientCallbacks *func, const BdAddr *bdAddr, bool isAutoConnect,
            BtTransportType transport),
        (override));
    MOCK_METHOD(int32_t, BleGattcDisconnect, (int clientId), (override));
    MOCK_METHOD(int32_t, BleGattcSearchServices, (int clientId), (override));
    MOCK_METHOD(bool, BleGattcGetService, (int clientId, BtUuid serviceUuid), (override));
    MOCK_METHOD(int32_t, BleGattcRegisterNotification, (int clientId, BtGattCharacteristic characteristic, bool enable),
        (override));
    MOCK_METHOD(int32_t, BleGattcConfigureMtuSize, (int clientId, int mtuSize), (override));
    MOCK_METHOD(int32_t, BleGattcWriteCharacteristic,
        (int clientId, BtGattCharacteristic characteristic, BtGattWriteType writeType, int len, const char *value),
        (override));
    MOCK_METHOD(int32_t, BleGattcUnRegister, (int clientId), (override));
    MOCK_METHOD(int32_t, BleGattcSetFastestConn, (int clientId, bool fastestConnFlag), (override));
    MOCK_METHOD(
        int32_t, BleGattcSetPriority, (int clientId, const BdAddr *bdAddr, BtGattPriority priority), (override));

    MOCK_METHOD(int32_t, BleGattsRegisterCallbacks, (BtGattServerCallbacks * func), (override));
    MOCK_METHOD(int32_t, BleGattsRegister, (BtUuid appUuid), (override));
    MOCK_METHOD(int32_t, BleGattsAddService, (int serverId, BtUuid srvcUuid, bool isPrimary, int number), (override));
    MOCK_METHOD(int32_t, BleGattsUnRegister, (int serverId), (override));
    MOCK_METHOD(int32_t, BleGattsAddCharacteristic,
        (int serverId, int srvcHandle, BtUuid characUuid, int properties, int permissions), (override));
    MOCK_METHOD(
        int32_t, BleGattsAddDescriptor, (int serverId, int srvcHandle, BtUuid descUuid, int permissions), (override));
    MOCK_METHOD(int32_t, BleGattsStartService, (int serverId, int srvcHandle), (override));
    MOCK_METHOD(int32_t, BleGattsStopService, (int serverId, int srvcHandle), (override));
    MOCK_METHOD(int32_t, BleGattsDeleteService, (int serverId, int srvcHandle), (override));
    MOCK_METHOD(int32_t, BleGattsDisconnect, (int serverId, BdAddr bdAddr, int connId), (override));
    MOCK_METHOD(int32_t, BleGattsSendResponse, (int serverId, GattsSendRspParam *param), (override));
    MOCK_METHOD(int32_t, BleGattsSendIndication, (int serverId, GattsSendIndParam *param), (override));

    static MockBluetooth *GetMocker();

    static BtGapCallBacks *btGapCallback;
    static BtGattCallbacks *btGattCallback;
    static BleScanCallbacks *bleScanCallback;

private:
    static MockBluetooth *targetMocker;
};

#endif