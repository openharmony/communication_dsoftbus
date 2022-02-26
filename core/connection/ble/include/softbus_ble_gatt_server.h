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

#ifndef BLE_GATT_SERVER_H
#define BLE_GATT_SERVER_H

#include "softbus_adapter_ble_gatt_server.h"
#include "softbus_ble_connection_inner.h"
#include "softbus_conn_manager.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t SoftBusGattServerInit(SoftBusBleConnCalback *cb);
int32_t SoftBusGattServerStartService(void);
int32_t SoftBusGattServerStopService(void);
void SoftBusGattServerOnBtStateChanged(int state);
int32_t SoftBusGattServerSend(int32_t halConnId, const char *data, int32_t len, int32_t module);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif