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

#ifndef BLUETOOTH_MOCK_H
#define BLUETOOTH_MOCK_H

#include "gmock/gmock.h"

#include "c_header/ohos_bt_gap.h"
#include "c_header/ohos_bt_gatt.h"
#include "c_header/ohos_bt_gatt_client.h"
#include "c_header/ohos_bt_gatt_server.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_broadcast_adapter_interface.h"

// declare mock symbols explicitly which hava C implement, redirected to mocker when linking
class BluetoothInterface {
public:
    // 蓝牙公共能力
    virtual bool EnableBle() = 0;
    virtual bool DisableBle() = 0;
    virtual bool IsBleEnabled() = 0;
    virtual bool GetLocalAddr(unsigned char *mac, unsigned int len) = 0;
    virtual bool SetLocalName(unsigned char *localName, unsigned char length) = 0;
    virtual int32_t GapRegisterCallbacks(BtGapCallBacks *func) = 0;
    virtual bool PairRequestReply(const BdAddr *bdAddr, int32_t transport, bool accept) = 0;
    virtual bool SetDevicePairingConfirmation(const BdAddr *bdAddr, int32_t transport, bool accept) = 0;

    // BLE广播相关
    virtual int32_t BleGattRegisterCallbacks(BtGattCallbacks *func) = 0;
    virtual int32_t BleRegisterScanCallbacks(BleScanCallbacks *func, int32_t *scannerId) = 0;
    virtual int32_t BleDeregisterScanCallbacks(int32_t scannerId) = 0;
    virtual int32_t BleStartScanEx(
        int32_t scannerId, const BleScanConfigs *configs, const BleScanNativeFilter *filter, uint32_t filterSize) = 0;
    virtual int32_t BleStopScan(int32_t scannerId) = 0;
    virtual int32_t BleStartAdvEx(int32_t *advId, const StartAdvRawData rawData, BleAdvParams advParam) = 0;
    virtual int32_t BleStopAdv(int32_t advId) = 0;
    virtual int32_t GetAdvHandle(int32_t btAdvId, int32_t *bcHandle) = 0;
    virtual int32_t EnableSyncDataToLpDevice() = 0;
    virtual int32_t DisableSyncDataToLpDevice() = 0;
    virtual int32_t SetLpDeviceAdvParam(
        int32_t duration, int32_t maxExtAdvEvents, int32_t window, int32_t interval, int32_t bcHandle) = 0;

    // GATT Client相关
    virtual int32_t BleGattcRegister(BtUuid appUuid) = 0;
    virtual int32_t BleGattcConnect(int32_t clientId, BtGattClientCallbacks *func, const BdAddr *bdAddr,
        bool isAutoConnect, BtTransportType transport) = 0;
    virtual int32_t BleGattcDisconnect(int32_t clientId) = 0;
    virtual int32_t BleGattcSearchServices(int32_t clientId) = 0;
    virtual bool BleGattcGetService(int32_t clientId, BtUuid serviceUuid) = 0;
    virtual int32_t BleGattcRegisterNotification(
        int32_t clientId, BtGattCharacteristic characteristic, bool enable) = 0;
    virtual int32_t BleGattcConfigureMtuSize(int32_t clientId, int32_t mtuSize) = 0;
    virtual int32_t BleGattcWriteCharacteristic(int32_t clientId, BtGattCharacteristic characteristic,
        BtGattWriteType writeType, int32_t len, const char *value) = 0;
    virtual int32_t BleGattcUnRegister(int32_t clientId) = 0;
    virtual int32_t BleGattcSetFastestConn(int32_t clientId, bool fastestConnFlag) = 0;
    virtual int32_t BleGattcSetPriority(int32_t clientId, const BdAddr *bdAddr, BtGattPriority priority) = 0;

    // GATT Server相关
    virtual int32_t BleGattsRegisterCallbacks(BtGattServerCallbacks *func) = 0;
    virtual int32_t BleGattsRegister(BtUuid appUuid);
    virtual int32_t BleGattsAddService(int32_t serverId, BtUuid srvcUuid, bool isPrimary, int32_t number) = 0;
    virtual int32_t BleGattsUnRegister(int32_t serverId);
    virtual int32_t BleGattsAddCharacteristic(
        int32_t serverId, int32_t srvcHandle, BtUuid characUuid, int32_t properties, int32_t permissions) = 0;
    virtual int32_t BleGattsAddDescriptor(
        int32_t serverId, int32_t srvcHandle, BtUuid descUuid, int32_t permissions) = 0;
    virtual int32_t BleGattsStartService(int32_t serverId, int32_t srvcHandle) = 0;
    virtual int32_t BleGattsStopService(int32_t serverId, int32_t srvcHandle) = 0;
    virtual int32_t BleGattsDeleteService(int32_t serverId, int32_t srvcHandle) = 0;
    virtual int32_t BleGattsDisconnect(int32_t serverId, BdAddr bdAddr, int32_t connId) = 0;
    virtual int32_t BleGattsSendResponse(int32_t serverId, GattsSendRspParam *param) = 0;
    virtual int32_t BleGattsSendIndication(int32_t serverId, GattsSendIndParam *param) = 0;

    virtual int32_t RegisterBroadcastMediumFunction(
        SoftbusMediumType type, const SoftbusBroadcastMediumInterface *interface) = 0;
    virtual int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener) = 0;
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
    MOCK_METHOD(bool, PairRequestReply, (const BdAddr *bdAddr, int32_t transport, bool accept), (override));
    MOCK_METHOD(
        bool, SetDevicePairingConfirmation, (const BdAddr *bdAddr, int32_t transport, bool accept), (override));

    MOCK_METHOD(int32_t, BleGattRegisterCallbacks, (BtGattCallbacks * func), (override));
    MOCK_METHOD(int32_t, BleRegisterScanCallbacks, (BleScanCallbacks * func, int32_t *scannerId), (override));
    MOCK_METHOD(int32_t, BleDeregisterScanCallbacks, (int32_t scannerId), (override));
    MOCK_METHOD(int32_t, BleStartScanEx,
        (int32_t scannerId, const BleScanConfigs *configs, const BleScanNativeFilter *filter, uint32_t filterSize),
        (override));
    MOCK_METHOD(int32_t, BleStopScan, (int32_t scannerId), (override));
    MOCK_METHOD(
        int32_t, BleStartAdvEx, (int32_t * advId, const StartAdvRawData rawData, BleAdvParams advParam), (override));
    MOCK_METHOD(int32_t, BleStopAdv, (int32_t advId), (override));
    MOCK_METHOD(int32_t, GetAdvHandle, (int32_t btAdvId, int32_t *bcHandle), (override));
    MOCK_METHOD(int32_t, EnableSyncDataToLpDevice, (), (override));
    MOCK_METHOD(int32_t, DisableSyncDataToLpDevice, (), (override));
    MOCK_METHOD(int32_t, SetLpDeviceAdvParam,
        (int32_t duration, int32_t maxExtAdvEvents, int32_t window, int32_t interval, int32_t bcHandle), (override));

    MOCK_METHOD(int32_t, BleGattcRegister, (BtUuid appUuid), (override));
    MOCK_METHOD(int32_t, BleGattcConnect,
        (int32_t clientId, BtGattClientCallbacks *func, const BdAddr *bdAddr, bool isAutoConnect,
            BtTransportType transport),
        (override));
    MOCK_METHOD(int32_t, BleGattcDisconnect, (int32_t clientId), (override));
    MOCK_METHOD(int32_t, BleGattcSearchServices, (int32_t clientId), (override));
    MOCK_METHOD(bool, BleGattcGetService, (int32_t clientId, BtUuid serviceUuid), (override));
    MOCK_METHOD(int32_t, BleGattcRegisterNotification,
        (int32_t clientId, BtGattCharacteristic characteristic, bool enable), (override));
    MOCK_METHOD(int32_t, BleGattcConfigureMtuSize, (int32_t clientId, int32_t mtuSize), (override));
    MOCK_METHOD(int32_t, BleGattcWriteCharacteristic,
        (int32_t clientId, BtGattCharacteristic characteristic, BtGattWriteType writeType, int32_t len,
            const char *value),
        (override));
    MOCK_METHOD(int32_t, BleGattcUnRegister, (int32_t clientId), (override));
    MOCK_METHOD(int32_t, BleGattcSetFastestConn, (int32_t clientId, bool fastestConnFlag), (override));
    MOCK_METHOD(
        int32_t, BleGattcSetPriority, (int32_t clientId, const BdAddr *bdAddr, BtGattPriority priority), (override));

    MOCK_METHOD(int32_t, BleGattsRegisterCallbacks, (BtGattServerCallbacks * func), (override));
    MOCK_METHOD(int32_t, BleGattsRegister, (BtUuid appUuid), (override));
    MOCK_METHOD(
        int32_t, BleGattsAddService, (int32_t serverId, BtUuid srvcUuid, bool isPrimary, int32_t number), (override));
    MOCK_METHOD(int32_t, BleGattsUnRegister, (int32_t serverId), (override));
    MOCK_METHOD(int32_t, BleGattsAddCharacteristic,
        (int32_t serverId, int32_t srvcHandle, BtUuid characUuid, int32_t properties, int32_t permissions),
        (override));
    MOCK_METHOD(int32_t, BleGattsAddDescriptor,
        (int32_t serverId, int32_t srvcHandle, BtUuid descUuid, int32_t permissions), (override));
    MOCK_METHOD(int32_t, BleGattsStartService, (int32_t serverId, int32_t srvcHandle), (override));
    MOCK_METHOD(int32_t, BleGattsStopService, (int32_t serverId, int32_t srvcHandle), (override));
    MOCK_METHOD(int32_t, BleGattsDeleteService, (int32_t serverId, int32_t srvcHandle), (override));
    MOCK_METHOD(int32_t, BleGattsDisconnect, (int32_t serverId, BdAddr bdAddr, int32_t connId), (override));
    MOCK_METHOD(int32_t, BleGattsSendResponse, (int32_t serverId, GattsSendRspParam *param), (override));
    MOCK_METHOD(int32_t, BleGattsSendIndication, (int32_t serverId, GattsSendIndParam *param), (override));
    MOCK_METHOD(int32_t, RegisterBroadcastMediumFunction,
        (SoftbusMediumType type, const SoftbusBroadcastMediumInterface *interface), (override));
    MOCK_METHOD(int32_t, SoftBusAddBtStateListener, (const SoftBusBtStateListener *listener), (override));
    static MockBluetooth *GetMocker();

    static BtGapCallBacks *btGapCallback;
    static BtGattCallbacks *btGattCallback;
    static BleScanCallbacks *bleScanCallback;
    static const SoftbusBroadcastMediumInterface *interface;

private:
    static MockBluetooth *targetMocker;
};

#endif
