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

#ifndef SOFTBUS_CONN_BLE_SERVER_H
#define SOFTBUS_CONN_BLE_SERVER_H

#include "message_handler.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_error_code.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SERVER_WAIT_START_SERVER_TIMEOUT_MILLIS (5 * 1000)
#define SERVER_WAIT_STOP_SERVER_TIMEOUT_MILLIS  (5 * 1000)
#define SERVER_WAIT_MTU_TIMEOUT_MILLIS          (10 * 1000)

int32_t ConnGattServerStartService(void);
int32_t ConnGattServerStopService(void);
int32_t ConnGattServerSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module);
int32_t ConnGattServerDisconnect(ConnBleConnection *connection);
int32_t ConnGattServerConnect(ConnBleConnection *connection);
int32_t ConnGattInitServerModule(SoftBusLooper *looper, const ConnBleServerEventListener *listener);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SOFTBUS_CONN_BLE_SERVER_H */