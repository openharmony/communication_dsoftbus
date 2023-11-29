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

#include "connection_ble_mock.h"

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
bool AddNumberToJsonObject(cJSON *json, const char * const string, int num)
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

int BleGattcDisconnect(int clientId)
{
    return GetConnectionBleInterface()->BleGattcDisconnect(clientId);
}

int SoftBusGattsAddService(SoftBusBtUuid srvcUuid, bool isPrimary, int number)
{
    return GetConnectionBleInterface()->SoftBusGattsAddService(srvcUuid, isPrimary, number);
}

int SoftBusGattsStopService(int srvcHandle)
{
    return GetConnectionBleInterface()->SoftBusGattsStopService(srvcHandle);
}

int SoftBusGattsDisconnect(SoftBusBtAddr btAddr, int connId)
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

bool GetJsonObjectSignedNumberItem(const cJSON *json, const char * const string, int *target)
{
    return GetConnectionBleInterface()->GetJsonObjectSignedNumberItem(json, string, target);
}
}
}
