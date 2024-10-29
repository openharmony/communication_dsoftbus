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

#include "stdbool.h"
#include "stdint.h"
#include "common_list.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    SOFTBUS_GATT_SUCCESS = 0x00,
    SOFTBUS_GATT_INVALID_HANDLE = 0x01,
    SOFTBUS_GATT_READ_NOT_PERMITTED = 0x02,
    SOFTBUS_GATT_WRITE_NOT_PERMITTED = 0x03,
    SOFTBUS_GATT_INVALID_PDU = 0x04,
    SOFTBUS_GATT_INSUFFICIENT_AUTHENTICATION = 0x05,
    SOFTBUS_GATT_REQUEST_NOT_SUPPORTED = 0x06,
    SOFTBUS_GATT_INVALID_OFFSET = 0x07,
    SOFTBUS_GATT_INSUFFICIENT_AUTHORIZATION = 0x08,
    SOFTBUS_GATT_PREPARE_QUEUE_FULL = 0x09,
    SOFTBUS_GATT_ATTRIBUTE_NOT_FOUND = 0x0A,
    SOFTBUS_GATT_ATTRIBUTE_NOT_LONG = 0x0B,
    SOFTBUS_GATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE = 0x0C,
    SOFTBUS_GATT_INVALID_ATTRIBUTE_VALUE_LENGTH = 0x0D,
    SOFTBUS_GATT_UNLIKELY_ERROR = 0x0E,
    SOFTBUS_GATT_INSUFFICIENT_ENCRYPTION = 0x0F,
    SOFTBUS_GATT_UNSUPPORTED_GROUP_TYPE = 0x10,
    SOFTBUS_GATT_INSUFFICIENT_RESOURCES = 0x11,
    SOFTBUS_GATT_DATABASE_OUT_OF_SYNC = 0x12,
    SOFTBUS_GATT_VALUE_NOT_ALLOWED = 0x13,
} SoftBusGattStatus;

typedef enum {
    SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_BROADCAST = 0x01,
    SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_READ = 0x02,
    SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_WRITE_NO_RSP = 0x04,
    SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_WRITE = 0x08,
    SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_NOTIFY = 0x10,
    SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_INDICATE = 0x20,
    SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_SIGNED_WRITE = 0x40,
    SOFTBUS_GATT_CHARACTER_PROPERTY_BIT_EXTENDED_PROPERTY = 0x80
} SoftBusGattCharaProperty;

typedef enum {
    SOFTBUS_GATT_PERMISSION_READ = 0x01,
    SOFTBUS_GATT_PERMISSION_READ_ENCRYPTED = 0x02,
    SOFTBUS_GATT_PERMISSION_READ_ENCRYPTED_MITM = 0x04,
    SOFTBUS_GATT_PERMISSION_WRITE = 0x10,
    SOFTBUS_GATT_PERMISSION_WRITE_ENCRYPTED = 0x20,
    SOFTBUS_GATT_PERMISSION_WRITE_ENCRYPTED_MITM = 0x40,
    SOFTBUS_GATT_PERMISSION_WRITE_SIGNED = 0x80,
    SOFTBUS_GATT_PERMISSION_WRITE_SIGNED_MITM = 0x100
} SoftBusGattAttrPermission;

typedef struct {
    bool isLong;
    int connId;
    int transId;
    int attrHandle;
    int offset;
    SoftBusBtAddr *btAddr;
} SoftBusGattReadRequest;

typedef struct {
    bool needRsp;
    bool isPrep;
    int connId;
    int transId;
    int attrHandle;
    int offset;
    int length;
    unsigned char *value;
    SoftBusBtAddr *btAddr;
} SoftBusGattWriteRequest;


typedef struct {
    void (*serviceAddCallback)(int status, SoftBusBtUuid *uuid, int srvcHandle);
    void (*characteristicAddCallback)(int status, SoftBusBtUuid *uuid, int srvcHandle, int characteristicHandle);
    void (*descriptorAddCallback)(int status, SoftBusBtUuid *uuid, int srvcHandle, int descriptorHandle);
    void (*serviceStartCallback)(int status, int srvcHandle);
    void (*serviceStopCallback)(int status, int srvcHandle);
    void (*serviceDeleteCallback)(int status, int srvcHandle);
    void (*connectServerCallback)(int connId, const SoftBusBtAddr *btAddr);
    void (*disconnectServerCallback)(int connId, const SoftBusBtAddr *btAddr);
    void (*requestReadCallback)(SoftBusGattReadRequest readCbPara);
    void (*requestWriteCallback)(SoftBusGattWriteRequest writeCbPara);
    void (*responseConfirmationCallback)(int status, int handle);
    void (*notifySentCallback)(int connId, int status);
    void (*mtuChangeCallback)(int connId, int mtu);
    bool (*isConcernedAttrHandle)(int srvcHandle, int attrHandle);
} SoftBusGattsCallback;

typedef struct {
    int connectId;
    int transId;
    int status;
    int attrHandle;
    int offset;
    int valueLen;
    char *value;
} SoftBusGattsResponse;

typedef struct {
    int connectId;
    int attrHandle;
    int confirm;
    int valueLen;
    char *value;
} SoftBusGattsNotify;

typedef struct {
    ListNode node;
    int32_t connId;
    SoftBusBtAddr btAddr;
    int32_t mtu;
    int32_t handle;  // the id of start server
    bool notifyConnected;
} ServerConnection;

typedef struct {
    SoftBusGattsCallback callback;
    ListNode node;
    SoftBusBtUuid serviceUuid;
    int32_t handle;  // the id of start server
} ServerService;

typedef struct {
    ListNode services;
    ListNode connections; // as server connected
    SoftBusMutex lock;
} SoftBusGattsManager;

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
#endif /* SOFTBUS_ADAPTER_BLE_GATT_SERVER_H */
