/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef G_ENHANCE_CONN_FUNC_H
#define G_ENHANCE_CONN_FUNC_H

#include "softbus_conn_ble_connection_struct.h"
#include "softbus_conn_interface_struct.h"
#include "stdint.h"
#include "stdbool.h"
#include "softbus_common.h"
#include "softbus_adapter_ble_conflict_struct.h"
#include "softbus_conn_manager_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t (*ConnCocClientConnectFunc)(ConnBleConnection *connection);
typedef int32_t (*ConnCocClientDisconnectFunc)(ConnBleConnection *connection, bool ignore1, bool ignore2);
typedef int32_t (*ConnCocClientSendFunc)(ConnBleConnection *connection, const uint8_t *data,
    uint32_t dataLen, int32_t module);
typedef int32_t (*ConnCocClientUpdatePriorityFunc)(ConnBleConnection *connection, ConnectBlePriority priority);
typedef int32_t (*ConnCocServerStartServiceFunc)(void);
typedef int32_t (*ConnCocServerStopServiceFunc)(void);
typedef int32_t (*ConnCocServerSendFunc)(ConnBleConnection *connection, const uint8_t *data,
    uint32_t dataLen, int32_t module);
typedef int32_t (*ConnCocServerDisconnectFunc)(ConnBleConnection *connection);
typedef int32_t (*ConnCocServerConnectFunc)(ConnBleConnection *connection);
typedef int32_t (*ConnCocInitClientModuleFunc)(SoftBusLooper *looper, const ConnBleClientEventListener *cListener);
typedef int32_t (*ConnCocInitServerModuleFunc)(SoftBusLooper *looper, const ConnBleServerEventListener *sListener);

typedef int32_t (*ConnBleDirectConnectDeviceFunc)(const ConnectOption *option, uint32_t requestId, const ConnectResult *result);
typedef bool (*ConnBleDirectIsEnableFunc)(BleProtocolType protocol);
typedef int32_t (*ConnBleDirectInitFunc)(void);

typedef void (*ConnCoapStopServerListenFunc)(void);
typedef int32_t (*ConnCoapStartServerListenFunc)(void);
typedef void (*SoftbusBleConflictRegisterListenerFunc)(SoftBusBleConflictListener *listener);
typedef void (*SoftbusBleConflictNotifyDateReceiveFunc)(int32_t underlayerHandle, const uint8_t *data,
    uint32_t dataLen);
typedef void (*SoftbusBleConflictNotifyDisconnectFunc)(const char *addr, const char *udid);
typedef void (*SoftbusBleConflictNotifyConnectResultFunc)(uint32_t requestId, int32_t underlayerHandle, bool status);
typedef ConnectFuncInterface *(*ConnSleInitFunc)(const ConnectCallback *callback);
typedef int32_t (*ConnDirectConnectDeviceFunc)(const ConnectOption *option, uint32_t reqId, const ConnectResult* result);
typedef int32_t (*ConnPagingConnectInitFunc)(void);

typedef struct TagConnEnhanceFuncList {
    // Coc
    ConnCocClientConnectFunc connCocClientConnect;
    ConnCocClientDisconnectFunc connCocClientDisconnect;
    ConnCocClientSendFunc connCocClientSend;
    ConnCocClientUpdatePriorityFunc connCocClientUpdatePriority;
    ConnCocServerStartServiceFunc connCocServerStartService;
    ConnCocServerStopServiceFunc connCocServerStopService;
    ConnCocServerSendFunc connCocServerSend;
    ConnCocServerDisconnectFunc connCocServerDisconnect;
    ConnCocServerConnectFunc connCocServerConnect;
    ConnCocInitClientModuleFunc connCocInitClientModule;
    ConnCocInitServerModuleFunc connCocInitServerModule;

    // ble_direct
    ConnBleDirectConnectDeviceFunc connBleDirectConnectDevice;
    ConnBleDirectIsEnableFunc connBleDirectIsEnable;
    ConnBleDirectInitFunc connBleDirectInit;
    ConnDirectConnectDeviceFunc connDirectConnectDevice;

    // coap
    ConnCoapStopServerListenFunc connCoapStopServerListen;
    ConnCoapStartServerListenFunc connCoapStartServerListen;
    // adapter
    SoftbusBleConflictRegisterListenerFunc softbusBleConflictRegisterListener;
    SoftbusBleConflictNotifyDateReceiveFunc softbusBleConflictNotifyDateReceive;
    SoftbusBleConflictNotifyDisconnectFunc softbusBleConflictNotifyDisconnect;
    SoftbusBleConflictNotifyConnectResultFunc softbusBleConflictNotifyConnectResult;

    //paging
    ConnPagingConnectInitFunc connPagingConnectInit;
    // sle
    ConnSleInitFunc connSleInit;
} ConnEnhanceFuncList;

ConnEnhanceFuncList *ConnEnhanceFuncListGet(void);
int32_t ConnRegisterEnhanceFunc(void *soHandle);

#ifdef __cplusplus
}
#endif

#endif