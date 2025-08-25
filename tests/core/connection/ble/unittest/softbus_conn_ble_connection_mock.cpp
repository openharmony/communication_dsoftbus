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

#include "softbus_conn_ble_connection_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_connectionBleInterface;
ConnectionBleInterfaceMock::ConnectionBleInterfaceMock()
{
    g_connectionBleInterface = reinterpret_cast<void *>(this);
}

ConnectionBleInterfaceMock::~ConnectionBleInterfaceMock()
{
    g_connectionBleInterface = nullptr;
}

static ConnectionBleInterface *GetConnectionBleInterface()
{
    return reinterpret_cast<ConnectionBleInterface *>(g_connectionBleInterface);
}

extern "C" {
bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num)
{
    return GetConnectionBleInterface()->AddNumberToJsonObject(json, string, num);
}

int32_t ConvertBtMacToBinary(const char *strMac, uint32_t strMacLen, uint8_t *binMac, uint32_t binMacLen)
{
    return GetConnectionBleInterface()->ConvertBtMacToBinary(strMac, strMacLen, binMac, binMacLen);
}

int32_t SoftbusGattcConnect(int32_t clientId, SoftBusBtAddr *addr)
{
    return GetConnectionBleInterface()->SoftbusGattcConnect(clientId, addr);
}

int32_t BleGattcDisconnect(int32_t clientId)
{
    return GetConnectionBleInterface()->BleGattcDisconnect(clientId);
}

int32_t SoftBusGattsAddService(SoftBusBtUuid srvcUuid, bool isPrimary, int32_t number)
{
    return GetConnectionBleInterface()->SoftBusGattsAddService(srvcUuid, isPrimary, number);
}

int32_t SoftBusGattsStopService(int32_t srvcHandle)
{
    return GetConnectionBleInterface()->SoftBusGattsStopService(srvcHandle);
}

int32_t SoftBusGattsDisconnect(SoftBusBtAddr btAddr, int32_t connId)
{
    return GetConnectionBleInterface()->SoftBusGattsDisconnect(btAddr, connId);
}

int32_t SoftbusGattcRefreshServices(int32_t clientId)
{
    return GetConnectionBleInterface()->SoftbusGattcRefreshServices(clientId);
}

int32_t SoftbusGattcSearchServices(int32_t clientId)
{
    return GetConnectionBleInterface()->SoftbusGattcSearchServices(clientId);
}

bool GetJsonObjectSignedNumberItem(const cJSON *json, const char * const string, int32_t *target)
{
    return GetConnectionBleInterface()->GetJsonObjectSignedNumberItem(json, string, target);
}

int32_t BleGattsAddService(int32_t serverId, BtUuid srvcUuid, bool isPrimary, int32_t number)
{
    return GetConnectionBleInterface()->BleGattsAddService(serverId, srvcUuid, isPrimary, number);
}
 
int32_t BleGattcUnRegister(int32_t clientId)
{
    return GetConnectionBleInterface()->BleGattcUnRegister(clientId);
}

int BleGattcSetPriority(int clientId, const BdAddr *bdAddr, BtGattPriority priority)
{
    return GetConnectionBleInterface()->BleGattcSetPriority(clientId, bdAddr, priority);
}

int32_t BleHiDumperRegister(void)
{
    return SOFTBUS_OK;
}
}
}