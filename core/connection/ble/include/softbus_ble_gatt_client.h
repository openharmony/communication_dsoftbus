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

#ifndef BLE_GATT_CLIENT_H
#define BLE_GATT_CLIENT_H

#include "common_list.h"
#include "softbus_adapter_ble_gatt_client.h"
#include "softbus_ble_connection_inner.h"
#include "softbus_conn_manager.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t SoftBusGattClientInit(SoftBusBleConnCalback *cb);
int32_t SoftBusGattClientConnect(SoftBusBtAddr *bleAddr, bool fastestConnectEnable);
int32_t SoftBusGattClientDisconnect(int32_t clientId);
int32_t SoftBusGattClientSend(const int32_t clientId, const char *data, int32_t len, int32_t module);
void SoftbusGattcHandShakeEvent(int32_t clientId);
void SoftbusGattcOnRecvHandShakeRespon(int32_t clientId);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* BLE_GATT_CLIENT_H */