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

#include <securec.h>

#include "bluetooth_mock.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

MockBluetooth *MockBluetooth::targetMocker = nullptr;
BtGapCallBacks *MockBluetooth::btGapCallback = nullptr;
BtGattCallbacks *MockBluetooth::btGattCallback = nullptr;
BleScanCallbacks *MockBluetooth::bleScanCallback = nullptr;

static int32_t ActionGapRegisterCallbacks(BtGapCallBacks *func)
{
    MockBluetooth::btGapCallback = func;
    return OHOS_BT_STATUS_SUCCESS;
}

static int32_t ActionBleGattRegisterCallbacks(BtGattCallbacks *func)
{
    MockBluetooth::btGattCallback = func;
    return OHOS_BT_STATUS_SUCCESS;
}

MockBluetooth *MockBluetooth::GetMocker()
{
    return targetMocker;
}

MockBluetooth::MockBluetooth()
{
    MockBluetooth::targetMocker = this;
    // common callback is register glabal
    EXPECT_CALL(*this, GapRegisterCallbacks).WillRepeatedly(ActionGapRegisterCallbacks);
    EXPECT_CALL(*this, BleGattRegisterCallbacks).WillRepeatedly(ActionBleGattRegisterCallbacks);
}

MockBluetooth::~MockBluetooth()
{
    MockBluetooth::targetMocker = nullptr;
}

bool EnableBle(void)
{
    return MockBluetooth::GetMocker()->EnableBle();
}

bool DisableBle(void)
{
    return MockBluetooth::GetMocker()->DisableBle();
}

bool IsBleEnabled()
{
    return MockBluetooth::GetMocker()->IsBleEnabled();
}

bool GetLocalAddr(unsigned char *mac, unsigned int len)
{
    return MockBluetooth::GetMocker()->GetLocalAddr(mac, len);
}

bool SetLocalName(unsigned char *localName, unsigned char length)
{
    return MockBluetooth::GetMocker()->SetLocalName(localName, length);
}

int32_t GapRegisterCallbacks(BtGapCallBacks *func)
{
    return MockBluetooth::GetMocker()->GapRegisterCallbacks(func);
}

bool PairRequestReply(const BdAddr *bdAddr, int32_t transport, bool accept)
{
    return MockBluetooth::GetMocker()->PairRequestReply(bdAddr, transport, accept);
}

bool SetDevicePairingConfirmation(const BdAddr *bdAddr, int32_t transport, bool accept)
{
    return MockBluetooth::GetMocker()->SetDevicePairingConfirmation(bdAddr, transport, accept);
}

int32_t BleGattRegisterCallbacks(BtGattCallbacks *func)
{
    return MockBluetooth::GetMocker()->BleGattRegisterCallbacks(func);
}

int32_t BleStartScanEx(int32_t scannerId, BleScanConfigs *configs, BleScanNativeFilter *filter, unsigned int filterSize)
{
    return MockBluetooth::GetMocker()->BleStartScanEx(scannerId, configs, filter, filterSize);
}

int32_t BleStopScan(int32_t scannerId)
{
    return MockBluetooth::GetMocker()->BleStopScan(scannerId);
}

int32_t BleStartAdvEx(int32_t *advId, const StartAdvRawData rawData, BleAdvParams advParam)
{
    return MockBluetooth::GetMocker()->BleStartAdvEx(advId, rawData, advParam);
}

int32_t BleStopAdv(int32_t advId)
{
    return MockBluetooth::GetMocker()->BleStopAdv(advId);
}

int32_t BleGattcRegister(BtUuid appUuid)
{
    return MockBluetooth::GetMocker()->BleGattcRegister(appUuid);
}

int32_t BleGattcConnect(
    int32_t clientId, BtGattClientCallbacks *func, const BdAddr *bdAddr, bool isAutoConnect, BtTransportType transport)
{
    return MockBluetooth::GetMocker()->BleGattcConnect(clientId, func, bdAddr, isAutoConnect, transport);
}

int32_t BleGattcDisconnect(int32_t clientId)
{
    return MockBluetooth::GetMocker()->BleGattcDisconnect(clientId);
}

int32_t BleGattcSearchServices(int32_t clientId)
{
    return MockBluetooth::GetMocker()->BleGattcSearchServices(clientId);
}

bool BleGattcGetService(int32_t clientId, BtUuid serviceUuid)
{
    return MockBluetooth::GetMocker()->BleGattcGetService(clientId, serviceUuid);
}

int32_t BleGattcRegisterNotification(int32_t clientId, BtGattCharacteristic characteristic, bool enable)
{
    return MockBluetooth::GetMocker()->BleGattcRegisterNotification(clientId, characteristic, enable);
}

int32_t BleGattcConfigureMtuSize(int32_t clientId, int32_t mtuSize)
{
    return MockBluetooth::GetMocker()->BleGattcConfigureMtuSize(clientId, mtuSize);
}

int32_t BleGattcWriteCharacteristic(
    int32_t clientId, BtGattCharacteristic characteristic, BtGattWriteType writeType, int32_t len, const char *value)
{
    return MockBluetooth::GetMocker()->BleGattcWriteCharacteristic(clientId, characteristic, writeType, len, value);
}

int32_t BleGattcUnRegister(int32_t clientId)
{
    return MockBluetooth::GetMocker()->BleGattcUnRegister(clientId);
}

int32_t BleGattcSetFastestConn(int32_t clientId, bool fastestConnFlag)
{
    return MockBluetooth::GetMocker()->BleGattcSetFastestConn(clientId, fastestConnFlag);
}

int32_t BleGattcSetPriority(int32_t clientId, const BdAddr *bdAddr, BtGattPriority priority)
{
    return MockBluetooth::GetMocker()->BleGattcSetPriority(clientId, bdAddr, priority);
}

int32_t BleGattsRegisterCallbacks(BtGattServerCallbacks *func)
{
    return MockBluetooth::GetMocker()->BleGattsRegisterCallbacks(func);
}

int32_t BleGattsRegister(BtUuid appUuid)
{
    return MockBluetooth::GetMocker()->BleGattsRegister(appUuid);
}

int32_t BleGattsAddService(int32_t serverId, BtUuid srvcUuid, bool isPrimary, int32_t number)
{
    return MockBluetooth::GetMocker()->BleGattsAddService(serverId, srvcUuid, isPrimary, number);
}

int32_t BleGattsUnRegister(int32_t serverId)
{
    return MockBluetooth::GetMocker()->BleGattsUnRegister(serverId);
}

int32_t BleGattsAddCharacteristic(
    int32_t serverId, int32_t srvcHandle, BtUuid characUuid, int32_t properties, int32_t permissions)
{
    return MockBluetooth::GetMocker()->BleGattsAddCharacteristic(
        serverId, srvcHandle, characUuid, properties, permissions);
}

int32_t BleGattsAddDescriptor(int32_t serverId, int32_t srvcHandle, BtUuid descUuid, int32_t permissions)
{
    return MockBluetooth::GetMocker()->BleGattsAddDescriptor(serverId, srvcHandle, descUuid, permissions);
}

int32_t BleGattsStartService(int32_t serverId, int32_t srvcHandle)
{
    return MockBluetooth::GetMocker()->BleGattsStartService(serverId, srvcHandle);
}

int32_t BleGattsStopService(int32_t serverId, int32_t srvcHandle)
{
    return MockBluetooth::GetMocker()->BleGattsStopService(serverId, srvcHandle);
}

int32_t BleGattsDeleteService(int32_t serverId, int32_t srvcHandle)
{
    return MockBluetooth::GetMocker()->BleGattsDeleteService(serverId, srvcHandle);
}

int32_t BleGattsDisconnect(int32_t serverId, BdAddr bdAddr, int32_t connId)
{
    return MockBluetooth::GetMocker()->BleGattsDisconnect(serverId, bdAddr, connId);
}

int32_t BleGattsSendResponse(int32_t serverId, GattsSendRspParam *param)
{
    return MockBluetooth::GetMocker()->BleGattsSendResponse(serverId, param);
}

int32_t BleGattsSendIndication(int32_t serverId, GattsSendIndParam *param)
{
    return MockBluetooth::GetMocker()->BleGattsSendIndication(serverId, param);
}
