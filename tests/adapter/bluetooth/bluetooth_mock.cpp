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

#include "bluetooth_mock.h"

#include <securec.h>

#include "softbus_common.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

MockBluetooth *MockBluetooth::targetMocker = nullptr;

MockBluetooth::MockBluetooth()
{
    MockBluetooth::targetMocker = this;
}

MockBluetooth::~MockBluetooth() {}

bool EnableBle(void)
{
    return MockBluetooth::targetMocker->EnableBle();
}

bool DisableBle(void)
{
    return MockBluetooth::targetMocker->DisableBle();
}

bool IsBleEnabled()
{
    return MockBluetooth::targetMocker->IsBleEnabled();
}

bool GetLocalAddr(unsigned char *mac, unsigned int len)
{
    return MockBluetooth::targetMocker->GetLocalAddr(mac, len);
}

bool SetLocalName(unsigned char *localName, unsigned char length)
{
    return MockBluetooth::targetMocker->SetLocalName(localName, length);
}

int GapRegisterCallbacks(BtGapCallBacks *func)
{
    return MockBluetooth::targetMocker->GapRegisterCallbacks(func);
}

bool PairRequestReply(const BdAddr *bdAddr, int transport, bool accept)
{
    return MockBluetooth::targetMocker->PairRequestReply(bdAddr, transport, accept);
}

bool SetDevicePairingConfirmation(const BdAddr *bdAddr, int transport, bool accept)
{
    return MockBluetooth::targetMocker->SetDevicePairingConfirmation(bdAddr, transport, accept);
}

int BleGattRegisterCallbacks(BtGattCallbacks *func)
{
    return MockBluetooth::targetMocker->BleGattRegisterCallbacks(func);
}

int BleStartScanEx(BleScanConfigs *configs, BleScanNativeFilter *filter, unsigned int filterSize)
{
    return MockBluetooth::targetMocker->BleStartScanEx(configs, filter, filterSize);
}

int BleStopScan(void)
{
    return MockBluetooth::targetMocker->BleStopScan();
}

int BleStartAdvEx(int *advId, const StartAdvRawData rawData, BleAdvParams advParam)
{
    return MockBluetooth::targetMocker->BleStartAdvEx(advId, rawData, advParam);
}

int BleStopAdv(int advId)
{
    return MockBluetooth::targetMocker->BleStopAdv(advId);
}

int BleGattcRegister(BtUuid appUuid)
{
    return MockBluetooth::targetMocker->BleGattcRegister(appUuid);
}

int BleGattcConnect(
    int clientId, BtGattClientCallbacks *func, const BdAddr *bdAddr, bool isAutoConnect, BtTransportType transport)
{
    return MockBluetooth::targetMocker->BleGattcConnect(clientId, func, bdAddr, isAutoConnect, transport);
}

int BleGattcDisconnect(int clientId)
{
    return MockBluetooth::targetMocker->BleGattcDisconnect(clientId);
}

int BleGattcSearchServices(int clientId)
{
    return MockBluetooth::targetMocker->BleGattcSearchServices(clientId);
}

bool BleGattcGetService(int clientId, BtUuid serviceUuid)
{
    return MockBluetooth::targetMocker->BleGattcGetService(clientId, serviceUuid);
}

int BleGattcRegisterNotification(int clientId, BtGattCharacteristic characteristic, bool enable)
{
    return MockBluetooth::targetMocker->BleGattcRegisterNotification(clientId, characteristic, enable);
}

int BleGattcConfigureMtuSize(int clientId, int mtuSize)
{
    return MockBluetooth::targetMocker->BleGattcConfigureMtuSize(clientId, mtuSize);
}

int BleGattcWriteCharacteristic(
    int clientId, BtGattCharacteristic characteristic, BtGattWriteType writeType, int len, const char *value)
{
    return MockBluetooth::targetMocker->BleGattcWriteCharacteristic(clientId, characteristic, writeType, len, value);
}

int BleGattcUnRegister(int clientId)
{
    return MockBluetooth::targetMocker->BleGattcUnRegister(clientId);
}

int BleGattsRegisterCallbacks(BtGattServerCallbacks *func)
{
    return MockBluetooth::targetMocker->BleGattsRegisterCallbacks(func);
}

int BleGattsRegister(BtUuid appUuid)
{
    return MockBluetooth::targetMocker->BleGattsRegister(appUuid);
}

int BleGattsAddService(int serverId, BtUuid srvcUuid, bool isPrimary, int number)
{
    return MockBluetooth::targetMocker->BleGattsAddService(serverId, srvcUuid, isPrimary, number);
}

int BleGattsUnRegister(int serverId)
{
    return MockBluetooth::targetMocker->BleGattsUnRegister(serverId);
}

int BleGattsAddCharacteristic(int serverId, int srvcHandle, BtUuid characUuid, int properties, int permissions)
{
    return MockBluetooth::targetMocker->BleGattsAddCharacteristic(
        serverId, srvcHandle, characUuid, properties, permissions);
}

int BleGattsAddDescriptor(int serverId, int srvcHandle, BtUuid descUuid, int permissions)
{
    return MockBluetooth::targetMocker->BleGattsAddDescriptor(serverId, srvcHandle, descUuid, permissions);
}

int BleGattsStartService(int serverId, int srvcHandle)
{
    return MockBluetooth::targetMocker->BleGattsStartService(serverId, srvcHandle);
}

int BleGattsStopService(int serverId, int srvcHandle)
{
    return MockBluetooth::targetMocker->BleGattsStopService(serverId, srvcHandle);
}

int BleGattsDeleteService(int serverId, int srvcHandle)
{
    return MockBluetooth::targetMocker->BleGattsDeleteService(serverId, srvcHandle);
}

int BleGattsDisconnect(int serverId, BdAddr bdAddr, int connId)
{
    return MockBluetooth::targetMocker->BleGattsDisconnect(serverId, bdAddr, connId);
}

int BleGattsSendResponse(int serverId, GattsSendRspParam *param)
{
    return MockBluetooth::targetMocker->BleGattsSendResponse(serverId, param);
}

int BleGattsSendIndication(int serverId, GattsSendIndParam *param)
{
    return MockBluetooth::targetMocker->BleGattsSendIndication(serverId, param);
}