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
#include "softbus_utils.h"

MockBluetooth *MockBluetooth::targetMocker = nullptr;
BtGapCallBacks *MockBluetooth::btGapCallback = nullptr;
BtGattCallbacks *MockBluetooth::btGattCallback = nullptr;
BleScanCallbacks  *MockBluetooth::bleScanCallback  = nullptr;

static int ActionGapRegisterCallbacks(BtGapCallBacks *func)
{
    MockBluetooth::btGapCallback = func;
    return OHOS_BT_STATUS_SUCCESS;
}

static int ActionBleGattRegisterCallbacks(BtGattCallbacks *func)
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

int GapRegisterCallbacks(BtGapCallBacks *func)
{
    return MockBluetooth::GetMocker()->GapRegisterCallbacks(func);
}

bool PairRequestReply(const BdAddr *bdAddr, int transport, bool accept)
{
    return MockBluetooth::GetMocker()->PairRequestReply(bdAddr, transport, accept);
}

bool SetDevicePairingConfirmation(const BdAddr *bdAddr, int transport, bool accept)
{
    return MockBluetooth::GetMocker()->SetDevicePairingConfirmation(bdAddr, transport, accept);
}

int BleGattRegisterCallbacks(BtGattCallbacks *func)
{
    return MockBluetooth::GetMocker()->BleGattRegisterCallbacks(func);
}

int BleStartScanEx(int scannerId, BleScanConfigs *configs, BleScanNativeFilter *filter, unsigned int filterSize)
{
    return MockBluetooth::GetMocker()->BleStartScanEx(scannerId, configs, filter, filterSize);
}

int BleStopScan(int scannerId)
{
    return MockBluetooth::GetMocker()->BleStopScan(scannerId);
}

int BleStartAdvEx(int *advId, const StartAdvRawData rawData, BleAdvParams advParam)
{
    return MockBluetooth::GetMocker()->BleStartAdvEx(advId, rawData, advParam);
}

int BleStopAdv(int advId)
{
    return MockBluetooth::GetMocker()->BleStopAdv(advId);
}

int BleGattcRegister(BtUuid appUuid)
{
    return MockBluetooth::GetMocker()->BleGattcRegister(appUuid);
}

int BleGattcConnect(
    int clientId, BtGattClientCallbacks *func, const BdAddr *bdAddr, bool isAutoConnect, BtTransportType transport)
{
    return MockBluetooth::GetMocker()->BleGattcConnect(clientId, func, bdAddr, isAutoConnect, transport);
}

int BleGattcDisconnect(int clientId)
{
    return MockBluetooth::GetMocker()->BleGattcDisconnect(clientId);
}

int BleGattcSearchServices(int clientId)
{
    return MockBluetooth::GetMocker()->BleGattcSearchServices(clientId);
}

bool BleGattcGetService(int clientId, BtUuid serviceUuid)
{
    return MockBluetooth::GetMocker()->BleGattcGetService(clientId, serviceUuid);
}

int BleGattcRegisterNotification(int clientId, BtGattCharacteristic characteristic, bool enable)
{
    return MockBluetooth::GetMocker()->BleGattcRegisterNotification(clientId, characteristic, enable);
}

int BleGattcConfigureMtuSize(int clientId, int mtuSize)
{
    return MockBluetooth::GetMocker()->BleGattcConfigureMtuSize(clientId, mtuSize);
}

int BleGattcWriteCharacteristic(
    int clientId, BtGattCharacteristic characteristic, BtGattWriteType writeType, int len, const char *value)
{
    return MockBluetooth::GetMocker()->BleGattcWriteCharacteristic(clientId, characteristic, writeType, len, value);
}

int BleGattcUnRegister(int clientId)
{
    return MockBluetooth::GetMocker()->BleGattcUnRegister(clientId);
}

int BleGattcSetFastestConn(int clientId, bool fastestConnFlag)
{
    return MockBluetooth::GetMocker()->BleGattcSetFastestConn(clientId, fastestConnFlag);
}

int BleGattcSetPriority(int clientId, const BdAddr *bdAddr, BtGattPriority priority)
{
    return MockBluetooth::GetMocker()->BleGattcSetPriority(clientId, bdAddr, priority);
}

int BleGattsRegisterCallbacks(BtGattServerCallbacks *func)
{
    return MockBluetooth::GetMocker()->BleGattsRegisterCallbacks(func);
}

int BleGattsRegister(BtUuid appUuid)
{
    return MockBluetooth::GetMocker()->BleGattsRegister(appUuid);
}

int BleGattsAddService(int serverId, BtUuid srvcUuid, bool isPrimary, int number)
{
    return MockBluetooth::GetMocker()->BleGattsAddService(serverId, srvcUuid, isPrimary, number);
}

int BleGattsUnRegister(int serverId)
{
    return MockBluetooth::GetMocker()->BleGattsUnRegister(serverId);
}

int BleGattsAddCharacteristic(int serverId, int srvcHandle, BtUuid characUuid, int properties, int permissions)
{
    return MockBluetooth::GetMocker()->BleGattsAddCharacteristic(
        serverId, srvcHandle, characUuid, properties, permissions);
}

int BleGattsAddDescriptor(int serverId, int srvcHandle, BtUuid descUuid, int permissions)
{
    return MockBluetooth::GetMocker()->BleGattsAddDescriptor(serverId, srvcHandle, descUuid, permissions);
}

int BleGattsStartService(int serverId, int srvcHandle)
{
    return MockBluetooth::GetMocker()->BleGattsStartService(serverId, srvcHandle);
}

int BleGattsStopService(int serverId, int srvcHandle)
{
    return MockBluetooth::GetMocker()->BleGattsStopService(serverId, srvcHandle);
}

int BleGattsDeleteService(int serverId, int srvcHandle)
{
    return MockBluetooth::GetMocker()->BleGattsDeleteService(serverId, srvcHandle);
}

int BleGattsDisconnect(int serverId, BdAddr bdAddr, int connId)
{
    return MockBluetooth::GetMocker()->BleGattsDisconnect(serverId, bdAddr, connId);
}

int BleGattsSendResponse(int serverId, GattsSendRspParam *param)
{
    return MockBluetooth::GetMocker()->BleGattsSendResponse(serverId, param);
}

int BleGattsSendIndication(int serverId, GattsSendIndParam *param)
{
    return MockBluetooth::GetMocker()->BleGattsSendIndication(serverId, param);
}