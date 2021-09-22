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
#include "softbus_adapter_bt_common.h"

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
    /** 连接索引 */
    int connId;
    /** transport Id，reserved */
    int transId;
    /** 设备地址 */
    SoftBusBtAddr *btAddr;
    /** 请求读的attribute的handle号 */
    int attrHandle;
    /** 从第一个字节偏移offset个字节开始读，从头读则设置为0 */
    int offset;
    /** 如果设置为true则这个请求读是Long Read方式 */
    bool isLong;
} SoftBusGattReadRequest;

typedef struct {
    /** 连接索引 */
    int connId;
    /** transport Id，reserved */
    int transId;
    /** 设备地址 */
    SoftBusBtAddr *btAddr;
    /** 请求写的attribute的handle号 */
    int attrHandle;
    /** 从第一个字节偏移offset个字节开始写，从头写则设置为0 */
    int offset;
    /** 写的数据长度 */
    int length;
    /** 设置为true表示需要给远端client回复响应，设置为false则不需要回复响应 */
    bool needRsp;
    /** 设置为true表示Prepare write，设置为false表示立即写 */
    bool isPrep;
    /** 写的数据 */
    unsigned char *value;
} SoftBusGattWriteRequest;


typedef struct {
    /** 添加service后回调 */
    void (*ServiceAddCallback)(int status, SoftBusBtUuid *uuid, int srvcHandle);
    /** 添加characteristic后回调 */
    void (*CharacteristicAddCallback)(int status, SoftBusBtUuid *uuid, int srvcHandle, int characteristicHandle);
    /** 添加descriptor后回调 */
    void (*DescriptorAddCallback)(int status, SoftBusBtUuid *uuid, int srvcHandle, int descriptorHandle);
    /** 启动service后回调 */
    void (*ServiceStartCallback)(int status, int srvcHandle);
    /** 停止service后回调 */
    void (*ServiceStopCallback)(int status, int srvcHandle);
    /** 删除service后回调 */
    void (*ServiceDeleteCallback)(int status, int srvcHandle);
    /** 和远端client连接上回调 */
    void (*ConnectServerCallback)(int connId, const SoftBusBtAddr *btAddr);
    /** 和远端client断连回调 */
    void (*DisconnectServerCallback)(int connId, const SoftBusBtAddr *btAddr);
    /** 收到client请求读回调 */
    void (*RequestReadCallback)(SoftBusGattReadRequest readCbPara);
    /** 收到client请求写回调 */
    void (*RequestWriteCallback)(SoftBusGattWriteRequest writeCbPara);
    /** 发送响应给远端client后回调 */
    void (*ResponseConfirmationCallback)(int status, int handle);
    /** 发送indication/notification的回调 */
    void (*NotifySentCallback)(int connId, int status);
    /** MTU发生变化时回调 */
    void (*MtuChangeCallback)(int connId, int mtu);
} SoftBusGattsCallback;

typedef struct {
    /** 连接索引 */
    int connectId;
    /** 读/写的结果状态，{@link SoftBusGattStatus} */
    int status;
    /** attribute的handle号 */
    int attrHandle;
    /** 响应的数据长度 */
    int valueLen;
    /** 响应的数据 */
    char *value;
} SoftBusGattsResponse;

typedef struct {
    /** 连接索引 */
    int connectId;
    /** attribute的handle号 */
    int attrHandle;
    /** 1表示发送indication且client需要回复确认，0表示发送notification */
    int confirm;
    /** 发送的数据长度 */
    int valueLen;
    /** 发送的数据 */
    char *value;
} SoftBusGattsNotify;

int SoftBusRegisterGattsCallbacks(SoftBusGattsCallback *callback);
int SoftBusGattsAddService(SoftBusBtUuid srvcUuid, bool isPrimary, int number);
int SoftBusGattsAddCharacteristic(int srvcHandle, SoftBusBtUuid characUuid, int properties, int permissions);
int SoftBusGattsAddDescriptor(int srvcHandle, SoftBusBtUuid descUuid, int permissions);
int SoftBusGattsStartService(int srvcHandle);
int SoftBusGattsStopService(int srvcHandle);
int SoftBusGattsDeleteService(int srvcHandle);
int SoftBusGattsDisconnect(SoftBusBtAddr btAddr, int connId);
int SoftBusGattsSendResponse(SoftBusGattsResponse *param);
int SoftBusGattsSendNotify(SoftBusGattsNotify *param);

#endif
