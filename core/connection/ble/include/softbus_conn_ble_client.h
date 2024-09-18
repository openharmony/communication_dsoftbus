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

#ifndef SOFTBUS_CONN_BLE_CLIENT_H
#define SOFTBUS_CONN_BLE_CLIENT_H

#include "message_handler.h"
#include "softbus_conn_ble_connection.h"
#include "softbus_conn_interface.h"
#include "softbus_error_code.h"

/* In the fastest connection mode, the underlying connection timeout and notifications is set to 3500 milliseconds */
#define BLE_FAST_CONNECT_TIMEOUT 3500

#ifdef __cplusplus
extern "C" {
#endif

enum RetrySearchServiceReason {
    BLE_CLIENT_REGISTER_NOTIFICATION_ERR,
    BLE_CLIENT_REGISTER_NOTIFICATION_FAIL,
    BLE_CLIENT_SEARCH_SERVICE_ERR,
    BLE_CLIENT_GET_SERVICE_ERR,
};

typedef struct {
    int32_t underlayerHandle;
    int32_t status;
} CommonStatusContext;

int32_t ConnGattClientConnect(ConnBleConnection *connection);
int32_t ConnGattClientDisconnect(ConnBleConnection *connection, bool grace, bool refreshGatt);
int32_t ConnGattClientSend(ConnBleConnection *connection, const uint8_t *data, uint32_t dataLen, int32_t module);
int32_t ConnGattClientUpdatePriority(ConnBleConnection *connection, ConnectBlePriority priority);
int32_t ConnGattInitClientModule(SoftBusLooper *looper, const ConnBleClientEventListener *listener);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SOFTBUS_CONN_BLE_CLIENT_H */
