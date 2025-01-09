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

#include "softbus_conn_ble_manager_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_connectionBleManagerInterface;
ConnectionBleManagerInterfaceMock::ConnectionBleManagerInterfaceMock()
{
    g_connectionBleManagerInterface = reinterpret_cast<void *>(this);
}

ConnectionBleManagerInterfaceMock::~ConnectionBleManagerInterfaceMock()
{
    g_connectionBleManagerInterface = nullptr;
}

static ConnectionBleManagerInterface *GetConnectionBleInterface()
{
    return reinterpret_cast<ConnectionBleManagerInterface *>(g_connectionBleManagerInterface);
}

bool ConnectionBleManagerInterfaceMock::ActionOfGetdelta(
    const cJSON *json, const char * const str, int32_t *target)
{
    (void)json;
    (void)str;
    if (target != NULL) {
        *target = -1;
    }
    return true;
}

bool ConnectionBleManagerInterfaceMock::ActionOfGetPeerRc1(
    const cJSON *json, const char * const str, int32_t *target)
{
    (void)json;
    (void)str;
    if (target != NULL) {
        *target = 1;
    }
    return true;
}

bool ConnectionBleManagerInterfaceMock::ActionOfGetPeerRc0(
    const cJSON *json, const char * const str, int32_t *target)
{
    (void)json;
    (void)str;
    if (target != NULL) {
        *target = 0;
    }
    return true;
}

extern "C" {
int ConnBlePostBytesInner(uint32_t connectionId, uint8_t *data, uint32_t dataLen, int32_t pid, int32_t flag,
    int32_t module, int64_t seq, PostBytesFinishAction postBytesFinishAction)
{
    return GetConnectionBleInterface()->ConnBlePostBytesInner(
        connectionId, data, dataLen, pid, flag, module, seq, postBytesFinishAction);
}

int32_t ConnBleTransConfigPostLimit(const LimitConfiguration *configuration)
{
    return 0;
}

int32_t LnnGetConnSubFeatureByUdidHashStr(const char *udidHashStr, uint64_t *connSubFeature)
{
    return GetConnectionBleInterface()->LnnGetConnSubFeatureByUdidHashStr(udidHashStr, connSubFeature);
}

int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetConnectionBleInterface()->LnnRegisterEventHandler(event, handler);
}

int64_t ConnBlePackCtlMessage(BleCtlMessageSerializationContext ctx, uint8_t **outData, uint32_t *outLen)
{
    return GetConnectionBleInterface()->ConnBlePackCtlMessage(ctx, outData, outLen);
}

int32_t LnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len)
{
    return GetConnectionBleInterface()->LnnGetRemoteStrInfo(netWorkId, key, info, len);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetConnectionBleInterface()->LnnGetLocalStrInfo(key, info, len);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return GetConnectionBleInterface()->LnnGetLocalNumInfo(key, info);
}

int SoftBusGattsAddDescriptor(int srvcHandle, SoftBusBtUuid descUuid, int permissions)
{
    return GetConnectionBleInterface()->SoftBusGattsAddDescriptor(srvcHandle, descUuid, permissions);
}

int SoftBusGattsStartService(int srvcHandle)
{
    return GetConnectionBleInterface()->SoftBusGattsStartService(srvcHandle);
}

int SoftBusGattsSendResponse(SoftBusGattsResponse *param)
{
    return GetConnectionBleInterface()->SoftBusGattsSendResponse(param);
}

ConnBleConnection *LegacyBleCreateConnection(
    const char *addr, ConnSideType side, int32_t underlayerHandle, bool fastestConnectEnable)
{
    return GetConnectionBleInterface()->LegacyBleCreateConnection(addr, side, underlayerHandle, fastestConnectEnable);
}

int32_t LegacyBleSaveConnection(ConnBleConnection *connection)
{
    return GetConnectionBleInterface()->LegacyBleSaveConnection(connection);
}

int SoftBusGattsAddCharacteristic(int srvcHandle, SoftBusBtUuid characUuid, int properties, int permissions)
{
    return GetConnectionBleInterface()->SoftBusGattsAddCharacteristic(srvcHandle, characUuid, properties, permissions);
}

int32_t ConnGattClientConnect(ConnBleConnection *connection)
{
    return GetConnectionBleInterface()->ConnGattClientConnect(connection);
}

int32_t ConnGattClientDisconnect(ConnBleConnection *connection, bool grace, bool refreshGatt)
{
    return GetConnectionBleInterface()->ConnGattClientDisconnect(connection, grace, refreshGatt);
}

int32_t ConnGattClientSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    return GetConnectionBleInterface()->ConnGattClientSend(connection, data, dataLen, module);
}

int32_t ConnGattClientUpdatePriority(ConnBleConnection *connection, ConnectBlePriority priority)
{
    return GetConnectionBleInterface()->ConnGattClientUpdatePriority(connection, priority);
}

int32_t ConnGattServerStartService()
{
    return GetConnectionBleInterface()->ConnGattServerStartService();
}

int32_t ConnGattServerStopService()
{
    return GetConnectionBleInterface()->ConnGattServerStopService();
}

int32_t ConnGattServerSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    return GetConnectionBleInterface()->ConnGattServerSend(connection, data, dataLen, module);
}

int32_t ConnGattServerConnect(ConnBleConnection *connection)
{
    return GetConnectionBleInterface()->ConnGattServerConnect(connection);
}

int32_t ConnGattServerDisconnect(ConnBleConnection *connection)
{
    return GetConnectionBleInterface()->ConnGattServerDisconnect(connection);
}

int32_t ConnGattInitClientModule(SoftBusLooper *looper, const ConnBleClientEventListener *listener)
{
    return GetConnectionBleInterface()->ConnGattInitClientModule(looper, listener);
}

int32_t ConnGattInitServerModule(SoftBusLooper *looper, const ConnBleServerEventListener *listener)
{
    return GetConnectionBleInterface()->ConnGattInitServerModule(looper, listener);
}

bool GetJsonObjectSignedNumberItem(const cJSON *json, const char * const str, int32_t *target)
{
    return GetConnectionBleInterface()->GetJsonObjectSignedNumberItem(json, str, target);
}

bool GetJsonObjectNumber16Item(const cJSON *json, const char * const str, uint16_t *target)
{
    return GetConnectionBleInterface()->GetJsonObjectNumber16Item(json, str, target);
}

int32_t BleHiDumperRegister(void)
{
    return SOFTBUS_OK;
}
}
} // namespace OHOS