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

#ifndef SOFTBUS_CONN_BLE_COC_H
#define SOFTBUS_CONN_BLE_COC_H

#include "message_handler.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_interface.h"
#include "softbus_adapter_coc.h"
#include "softbus_error_code.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_COC_READ_BUFFER_CAPACITY                (40 * 1000)
#define MAX_COC_MTU_SIZE                            (3 * 1024)

int32_t ConnCocClientConnect(ConnBleConnection *connection);
int32_t ConnCocClientDisconnect(ConnBleConnection *connection, bool ignore1, bool ignore2);
int32_t ConnCocClientSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module);
int32_t ConnCocClientUpdatePriority(ConnBleConnection *connection, ConnectBlePriority priority);
int32_t ConnCocServerStartService();
int32_t ConnCocServerStopService();
int32_t ConnCocServerSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module);
int32_t ConnCocServerDisconnect(ConnBleConnection *connection);
int32_t ConnCocServerConnect(ConnBleConnection *connection);
int32_t ConnCocGetServerPsm();

int32_t ConnCocInitModule(SoftBusLooper *looper, const ConnBleClientEventListener *cListener,
    const ConnBleServerEventListener *sListener);
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SOFTBUS_CONN_BLE_COC_H */