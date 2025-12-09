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

#ifndef SOFTBUS_ADAPTER_BLE_GATT_CLIENT_STRUCT_H
#define SOFTBUS_ADAPTER_BLE_GATT_CLIENT_STRUCT_H

#include "stdbool.h"
#include "stdint.h"

#include "common_list.h"
#include "softbus_adapter_bt_common_struct.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    uint32_t dataLen;
    uint8_t *data;
    SoftBusBtUuid charaUuid;
} SoftBusGattcNotify;

typedef enum {
    SOFTBUS_GATT_WRITE_NO_RSP = 0x1,
    SOFTBUS_GATT_WRITE_DEFAULT,
    SOFTBUS_GATT_WRITE_PREPARE,
    SOFTBUS_GATT_WRITE_SIGNED,
    SOFTBUS_GATT_WRITE_TYPE_UNKNOWN,
} SoftBusGattWriteType;

typedef struct {
    uint32_t valueLen;
    SoftBusGattWriteType writeType;
    const uint8_t *value;
    SoftBusBtUuid serviceUuid;
    SoftBusBtUuid characterUuid;
} SoftBusGattcData;

typedef struct {
    void (*connectionStateCallback)(int32_t clientId, int32_t connState, int32_t status);
    void (*serviceCompleteCallback)(int32_t clientId, int32_t status);
    void (*registNotificationCallback)(int32_t clientId, int32_t status);
    void (*notificationReceiveCallback)(int32_t clientId, SoftBusGattcNotify *param, int32_t status);
    void (*configureMtuSizeCallback)(int32_t clientId, int32_t mtuSize, int32_t status);
    void (*onServiceChanged)(int32_t clientId);
} SoftBusGattcCallback;

typedef enum {
    SOFTBUS_GATT_PRIORITY_BALANCED = 0x0,
    SOFTBUS_GATT_PRIORITY_HIGH,
    SOFTBUS_GATT_PRIORITY_LOW_POWER,
} SoftbusBleGattPriority;

typedef struct {
    int32_t clientId;
    ListNode node;
    SoftBusGattcCallback callback;
} SoftBusGattcManager;

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* SOFTBUS_ADAPTER_BLE_GATT_CLIENT_STRUCT_H */