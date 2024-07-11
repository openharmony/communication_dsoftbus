/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "connection_ble_client_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_connectionBleClientInterface;
ConnectionBleClientInterfaceMock::ConnectionBleClientInterfaceMock()
{
    g_connectionBleClientInterface = reinterpret_cast<void *>(this);
}

ConnectionBleClientInterfaceMock::~ConnectionBleClientInterfaceMock()
{
    g_connectionBleClientInterface = nullptr;
}

static ConnectionBleClientInterface *GetConnectionBleClientInterface()
{
    return reinterpret_cast<ConnectionBleClientInterface *>(g_connectionBleClientInterface);
}

extern "C" {
int32_t SoftbusGattcSetFastestConn(int32_t clientId)
{
    return GetConnectionBleClientInterface()->SoftbusGattcSetFastestConn(clientId);
}

int32_t SoftbusGattcRefreshServices(int32_t clientId)
{
    return GetConnectionBleClientInterface()->SoftbusGattcRefreshServices(clientId);
}

int32_t SoftbusGattcConnect(int32_t clientId, SoftBusBtAddr *addr)
{
    return GetConnectionBleClientInterface()->SoftbusGattcConnect(clientId, addr);
}

uint8_t *ConnGattTransRecv(uint32_t connectionId, uint8_t *data,
    uint32_t dataLen, ConnBleReadBuffer *buffer, uint32_t *outLen)
{
    return GetConnectionBleClientInterface()->ConnGattTransRecv(connectionId, data, dataLen, buffer, outLen);
}

int32_t SoftbusGattcSearchServices(int32_t clientId)
{
    return GetConnectionBleClientInterface()->SoftbusGattcSearchServices(clientId);
}

int32_t SoftbusGattcRegisterNotification(int32_t clientId, SoftBusBtUuid *serverUuid,
    SoftBusBtUuid *charaUuid, SoftBusBtUuid *descriptorUuid)
{
    return GetConnectionBleClientInterface()->SoftbusGattcRegisterNotification(clientId,
        serverUuid, charaUuid, descriptorUuid);
}

int32_t SoftbusGattcConfigureMtuSize(int32_t clientId, int mtuSize)
{
    return GetConnectionBleClientInterface()->SoftbusGattcConfigureMtuSize(clientId, mtuSize);
}

int32_t SoftbusGattcGetService(int32_t clientId, SoftBusBtUuid *serverUuid)
{
    return GetConnectionBleClientInterface()->SoftbusGattcGetService(clientId, serverUuid);
}

int32_t SoftbusBleGattcDisconnect(int32_t clientId, bool refreshGatt)
{
    return GetConnectionBleClientInterface()->SoftbusBleGattcDisconnect(clientId, refreshGatt);
}

int32_t SoftbusGattcWriteCharacteristic(int32_t clientId, SoftBusGattcData *clientData)
{
    return GetConnectionBleClientInterface()->SoftbusGattcWriteCharacteristic(clientId, clientData);
}

int32_t SoftbusGattcSetPriority(int32_t clientId, SoftBusBtAddr *addr, SoftbusBleGattPriority priority)
{
    return GetConnectionBleClientInterface()->SoftbusGattcSetPriority(clientId, addr, priority);
}
}
}
