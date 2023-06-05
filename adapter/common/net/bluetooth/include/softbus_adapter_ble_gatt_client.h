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

#ifndef SOFTBUS_ADAPTER_BLE_GATT_CLIENT_H
#define SOFTBUS_ADAPTER_BLE_GATT_CLIENT_H

#include "stdbool.h"
#include "stdint.h"

#include "softbus_adapter_bt_common.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    SoftBusBtUuid charaUuid;
    uint32_t dataLen;
    uint8_t *data;
} SoftBusGattcNotify;

typedef struct {
    SoftBusBtUuid serviceUuid;
    SoftBusBtUuid characterUuid;
    uint32_t valueLen;
    const uint8_t *value;
} SoftBusGattcData;

typedef struct {
    void (*ConnectionStateCallback)(int32_t clientId, int32_t connState, int32_t status);
    void (*ServiceCompleteCallback)(int32_t clientId, int32_t status);
    void (*RegistNotificationCallback)(int32_t clientId, int status);
    void (*NotificationReceiveCallback)(int32_t clientId, SoftBusGattcNotify *param, int32_t status);
    void (*ConfigureMtuSizeCallback)(int clientId, int mtuSize, int status);
} SoftBusGattcCallback;

typedef enum {
    SOFTBUS_GATT_PRIORITY_BALANCED = 0x0,
    SOFTBUS_GATT_PRIORITY_HIGH,
    SOFTBUS_GATT_PRIORITY_LOW_POWER,
} SoftbusBleGattPriority;

void SoftbusGattcRegisterCallback(SoftBusGattcCallback *cb);
int32_t SoftbusGattcRegister(void);
int32_t SoftbusGattcUnRegister(int32_t clientId);
int32_t SoftbusGattcConnect(int32_t clientId, SoftBusBtAddr *addr);
int32_t SoftbusBleGattcDisconnect(int32_t clientId, bool refreshGatt);
int32_t SoftbusGattcSearchServices(int32_t clientId);
int32_t SoftbusGattcRefreshServices(int32_t clientId);
int32_t SoftbusGattcGetService(int32_t clientId, SoftBusBtUuid *serverUuid);
int32_t SoftbusGattcRegisterNotification(
    int32_t clientId, SoftBusBtUuid *serverUuid, SoftBusBtUuid *charaUuid, SoftBusBtUuid *descriptorUuid);
int32_t SoftbusGattcWriteCharacteristic(int32_t clientId, SoftBusGattcData *clientData);
int32_t SoftbusGattcConfigureMtuSize(int32_t clientId, int mtuSize);

int32_t SoftbusGattcSetFastestConn(int32_t clientId);
int32_t SoftbusGattcSetPriority(int32_t clientId, SoftBusBtAddr *addr, SoftbusBleGattPriority priority);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* SOFTBUS_ADAPTER_BLE_GATT_CLIENT_H */
