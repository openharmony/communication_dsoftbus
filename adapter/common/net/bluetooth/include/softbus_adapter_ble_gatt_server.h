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

#ifndef SOFTBUS_ADAPTER_BLE_GATT_SERVER_H
#define SOFTBUS_ADAPTER_BLE_GATT_SERVER_H

#include "softbus_adapter_bt_common.h"
#include "softbus_def.h"
#include "softbus_adapter_ble_gatt_server_struct.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int SoftBusRegisterGattsCallbacks(SoftBusGattsCallback *callback, SoftBusBtUuid srvcUuid);
void SoftBusUnRegisterGattsCallbacks(SoftBusBtUuid srvcUuid);
int SoftBusGattsAddService(SoftBusBtUuid srvcUuid, bool isPrimary, int number);
int SoftBusGattsAddCharacteristic(int srvcHandle, SoftBusBtUuid characUuid, int properties, int permissions);
int SoftBusGattsAddDescriptor(int srvcHandle, SoftBusBtUuid descUuid, int permissions);
int SoftBusGattsStartService(int srvcHandle);
int SoftBusGattsStopService(int srvcHandle);
int SoftBusGattsDeleteService(int srvcHandle);
int SoftBusGattsConnect(SoftBusBtAddr btAddr);
int SoftBusGattsDisconnect(SoftBusBtAddr btAddr, int connId);
int SoftBusGattsSendResponse(SoftBusGattsResponse *param);
int SoftBusGattsSendNotify(SoftBusGattsNotify *param);
void RemoveConnId(int32_t connId);
int InitSoftbusAdapterServer(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif
