/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_CONN_BLE_CONNECTION_H
#define SOFTBUS_CONN_BLE_CONNECTION_H

#include "common_list.h"
#include "message_handler.h"
#include "softbus_adapter_thread.h"
#include "softbus_conn_ble_trans.h"
#include "softbus_conn_interface.h"
#include "softbus_conn_manager.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "softbus_conn_ble_connection_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

ConnBleConnection *ConnBleCreateConnection(
    const char *addr, BleProtocolType protocol, ConnSideType side, int32_t underlayerHandle, bool fastestConnectEnable);
void ConnBleFreeConnection(ConnBleConnection *connection);
int32_t ConnBleStartServer(void);
int32_t ConnBleStopServer(void);
int32_t ConnBleConnect(ConnBleConnection *connection);
int32_t ConnBleDisconnectNow(ConnBleConnection *connection, enum ConnBleDisconnectReason reason);
int32_t ConnBleUpdateConnectionRc(ConnBleConnection *connection, uint16_t challengeCode, int32_t delta);
int32_t ConnBleOnReferenceRequest(ConnBleConnection *connection, const cJSON *json);
int32_t ConnBleUpdateConnectionPriority(ConnBleConnection *connection, ConnectBlePriority priority);
int32_t ConnBleSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module);
// connection will be disconnected forcely when idle more than CONNECTION_IDLE_DISCONNECT_TIMEOUT_MILLIS
void ConnBleRefreshIdleTimeout(ConnBleConnection *connection);
void ConnBleCancelIdleTimeout(ConnBleConnection *connection);
void ConnBleOccupy(ConnBleConnection *connection);

// complement connection device id
// NOTICE: MUST ONLY used in ble connection inner module
void ConnBleInnerComplementDeviceId(ConnBleConnection *connection);

void ConnBleRemoveExchangeBasicInfoTimeoutEvent(ConnBleConnection *connection);

int32_t ConnBleInitConnectionMudule(SoftBusLooper *looper, ConnBleConnectionEventListener *listener);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SOFTBUS_CONN_BLE_CONNECTION_H */
