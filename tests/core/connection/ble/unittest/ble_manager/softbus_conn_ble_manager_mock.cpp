/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "softbus_adapter_ble_conflict_struct.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::SoftBus {
void *g_bleManagerInterface;

BleManagerTestMock::BleManagerTestMock()
{
    g_bleManagerInterface = reinterpret_cast<void *>(this);
    mock.store(this);
}

BleManagerTestMock::~BleManagerTestMock()
{
    g_bleManagerInterface = nullptr;
    mock.store(nullptr);
}

static BleManagerTestMockInterface *GetBleManagerInterface()
{
    return reinterpret_cast<BleManagerTestMockInterface *>(g_bleManagerInterface);
}

extern "C" {
int ConnBlePostBytesInner(uint32_t connectionId, uint8_t *data, uint32_t dataLen, int32_t pid, int32_t flag,
    int32_t module, int64_t seq, PostBytesFinishAction postBytesFinishAction)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->ConnBlePostBytesInner(connectionId, data, dataLen, pid, flag, module, seq, postBytesFinishAction);
    }
    return SOFTBUS_OK;
}

int32_t ConnBleTransConfigPostLimit(const LimitConfiguration *configuration)
{
    (void)configuration;
    return SOFTBUS_OK;
}

int32_t LnnGetConnSubFeatureByUdidHashStr(const char *udidHashStr, uint64_t *connSubFeature)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->LnnGetConnSubFeatureByUdidHashStr(udidHashStr, connSubFeature);
    }
    return SOFTBUS_OK;
}

int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->LnnRegisterEventHandler(event, handler);
    }
    return SOFTBUS_OK;
}

int64_t ConnBlePackCtlMessage(BleCtlMessageSerializationContext ctx, uint8_t **outData, uint32_t *outLen)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->ConnBlePackCtlMessage(ctx, outData, outLen);
    }
    return 0;
}

int32_t LnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->LnnGetRemoteStrInfo(netWorkId, key, info, len);
    }
    return SOFTBUS_OK;
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->LnnGetLocalStrInfo(key, info, len);
    }
    return SOFTBUS_OK;
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->LnnGetLocalNumInfo(key, info);
    }
    return SOFTBUS_OK;
}

int SoftBusGattsAddDescriptor(int srvcHandle, SoftBusBtUuid descUuid, int permissions)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->SoftBusGattsAddDescriptor(srvcHandle, descUuid, permissions);
    }
    return 0;
}

int SoftBusGattsStartService(int srvcHandle)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->SoftBusGattsStartService(srvcHandle);
    }
    return 0;
}

int SoftBusGattsSendResponse(SoftBusGattsResponse *param)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->SoftBusGattsSendResponse(param);
    }
    return 0;
}

ConnBleConnection *LegacyBleCreateConnection(
    const char *addr, ConnSideType side, int32_t underlayerHandle, bool fastestConnectEnable)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->LegacyBleCreateConnection(addr, side, underlayerHandle, fastestConnectEnable);
    }
    return nullptr;
}

int32_t LegacyBleSaveConnection(ConnBleConnection *connection)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->LegacyBleSaveConnection(connection);
    }
    return SOFTBUS_OK;
}

int SoftBusGattsAddCharacteristic(int srvcHandle, SoftBusBtUuid characUuid, int properties, int permissions)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->SoftBusGattsAddCharacteristic(srvcHandle, characUuid, properties, permissions);
    }
    return 0;
}

int32_t ConnGattClientConnect(ConnBleConnection *connection)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->ConnGattClientConnect(connection);
    }
    return SOFTBUS_OK;
}

int32_t ConnGattClientDisconnect(ConnBleConnection *connection, bool grace, bool refreshGatt)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->ConnGattClientDisconnect(connection, grace, refreshGatt);
    }
    return SOFTBUS_OK;
}

int32_t ConnGattClientSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->ConnGattClientSend(connection, data, dataLen, module);
    }
    return SOFTBUS_OK;
}

int32_t ConnGattClientUpdatePriority(ConnBleConnection *connection, ConnectBlePriority priority)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->ConnGattClientUpdatePriority(connection, priority);
    }
    return SOFTBUS_OK;
}

int32_t ConnGattServerStartService()
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->ConnGattServerStartService();
    }
    return SOFTBUS_OK;
}

int32_t ConnGattServerStopService()
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->ConnGattServerStopService();
    }
    return SOFTBUS_OK;
}

int32_t ConnGattServerSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->ConnGattServerSend(connection, data, dataLen, module);
    }
    return SOFTBUS_OK;
}

int32_t ConnGattServerConnect(ConnBleConnection *connection)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->ConnGattServerConnect(connection);
    }
    return SOFTBUS_OK;
}

int32_t ConnGattServerDisconnect(ConnBleConnection *connection)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->ConnGattServerDisconnect(connection);
    }
    return SOFTBUS_OK;
}

int32_t ConnGattInitClientModule(SoftBusLooper *looper, const ConnBleClientEventListener *listener)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->ConnGattInitClientModule(looper, listener);
    }
    return SOFTBUS_OK;
}

int32_t ConnGattInitServerModule(SoftBusLooper *looper, const ConnBleServerEventListener *listener)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->ConnGattInitServerModule(looper, listener);
    }
    return SOFTBUS_OK;
}

bool GetJsonObjectSignedNumberItem(const cJSON *json, const char * const str, int32_t *target)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->GetJsonObjectSignedNumberItem(json, str, target);
    }
    return false;
}

bool GetJsonObjectNumber16Item(const cJSON *json, const char * const str, uint16_t *target)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->GetJsonObjectNumber16Item(json, str, target);
    }
    return false;
}

int32_t BleHiDumperRegister(void)
{
    auto mock = GetBleManagerInterface();
    if (mock != nullptr) {
        return mock->BleHiDumperRegister();
    }
    return SOFTBUS_OK;
}

void SoftbusBleConflictNotifyDateReceivePacked(int32_t underlayerHandle, const uint8_t *data, uint32_t dataLen)
{
    (void)underlayerHandle;
    (void)data;
    (void)dataLen;
}

void SoftbusBleConflictNotifyDisconnectPacked(const char *addr, const char *udid)
{
    (void)addr;
    (void)udid;
}

void SoftbusBleConflictNotifyConnectResultPacked(uint32_t requestId, int32_t underlayerHandle, bool status)
{
    (void)requestId;
    (void)underlayerHandle;
    (void)status;
}

void SoftbusBleConflictRegisterListenerPacked(SoftBusBleConflictListener *listener)
{
    (void)listener;
}
}
} // namespace OHOS::SoftBus
