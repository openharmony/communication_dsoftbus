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

/**
 * @file softbus_broadcast_adapter_type.h
 * @brief Declare functions and constants for the soft bus broadcast adaptation
 *
 * @since 4.1
 * @version 1.0
 */

#ifndef SOFTBUS_BROADCAST_ADAPTER_TYPE_H
#define SOFTBUS_BROADCAST_ADAPTER_TYPE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"{
#endif

/**
 * @brief Defines mac address length
 *
 * @since 4.1
 * @version 1.0
 */
#define SOFTBUS_ADDR_MAC_LEN 6

#define SOFTBUS_IRK_LEN   16
#define SOFTBUS_UDID_HASH_LEN 32

/**
 * @brief Defines the length of local name, the maximum length of complete local name is 30 bytes.
 *
 * @since 4.1
 * @version 1.0
 */
#define SOFTBUS_LOCAL_NAME_LEN_MAX 30

/**
 * @brief Defines different broadcast media protocol stacks
 *
 * @since 4.1
 * @version 1.0
 */
typedef enum {
    BROADCAST_MEDIUM_TYPE_BLE,
    BROADCAST_MEDIUM_TYPE_SLE,
    BROADCAST_MEDIUM_TYPE_BUTT,
} SoftbusMediumType;

/**
 * @brief Defines the broadcast service type.
 *
 * @since 4.1
 * @version 1.0
 */
typedef enum {
    BROADCAST_DATA_TYPE_SERVICE, // The broadcast data type is service data.
    BROADCAST_DATA_TYPE_MANUFACTURER, // The broadcast data type is manufacturer data.
    BROADCAST_DATA_TYPE_BUTT,
} SoftbusBcDataType;

/**
 * @brief Defines the broadcast data information
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    SoftbusBcDataType type; // broadcast data type {@link SoftbusBcDataType}.
    uint16_t id; // broadcast data id, uuid or company id.
    uint16_t payloadLen;
    uint8_t *payload; // if pointer defines rsp payload, pointer may be null
} SoftbusBroadcastPayload;

/**
 * @brief Defines the broadcast packet.
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    // By default, the flag behavior is supported. If the flag behavior is not supported, the value must be set to false
    bool isSupportFlag;
    uint8_t flag;
    SoftbusBroadcastPayload bcData;
    SoftbusBroadcastPayload rspData;
} SoftbusBroadcastData;

/**
 * @brief Defines mac address information
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    uint8_t addr[SOFTBUS_ADDR_MAC_LEN];
} SoftbusMacAddr;

typedef struct {
    uint8_t uuidLen;
    uint8_t *uuid;
} SoftbusBroadcastUuid;

/**
 * @brief Defines the device information returned by <b>SoftbusBroadcastCallback</b>.
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    uint8_t eventType;
    uint8_t dataStatus;
    uint8_t primaryPhy;
    uint8_t secondaryPhy;
    uint8_t advSid;
    int8_t txPower;
    int8_t rssi;
    uint8_t addrType;
    SoftbusMacAddr addr;
    uint8_t localName[SOFTBUS_LOCAL_NAME_LEN_MAX];
    int8_t *deviceName;
    SoftbusBroadcastData data;
} SoftBusBcScanResult;

/**
 * @brief Defines the broadcast parameters
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    uint8_t advType;
    uint8_t advFilterPolicy;
    uint8_t ownAddrType;
    uint8_t peerAddrType;
    int8_t txPower;
    bool isSupportRpa;
    uint8_t ownIrk[SOFTBUS_IRK_LEN];
    uint8_t ownUdidHash[SOFTBUS_UDID_HASH_LEN];
    SoftbusMacAddr peerAddr;
    SoftbusMacAddr localAddr;
    int32_t minInterval;
    int32_t maxInterval;
    int32_t channelMap;
    int32_t duration;
} SoftbusBroadcastParam;

/**
 * @brief Defines broadcast scan filters
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    bool advIndReport;
    uint16_t serviceUuid;
    uint32_t serviceDataLength;
    uint16_t manufactureId;
    uint32_t manufactureDataLength;
    int8_t *address;
    int8_t *deviceName;
    uint8_t *serviceData;
    uint8_t *serviceDataMask;
    uint8_t *manufactureData;
    uint8_t *manufactureDataMask;
} SoftBusBcScanFilter;

/**
 * @brief Defines broadcast scan parameters
 *
 * @since 4.1
 * @version 1.0
 */
typedef struct {
    uint8_t scanType;
    uint8_t scanPhy;
    uint8_t scanFilterPolicy;
    uint16_t scanInterval;
    uint16_t scanWindow;
} SoftBusBcScanParams;

typedef struct {
    int32_t advHandle;
    SoftbusBroadcastData advData;
    SoftbusBroadcastParam advParam;
} SoftBusLpBroadcastParam;

typedef struct {
    uint8_t filterSize;
    SoftBusBcScanParams scanParam;
    SoftBusBcScanFilter *filter;
} SoftBusLpScanParam;

#ifdef __cplusplus
}
#endif

#endif /* SOFTBUS_BROADCAST_ADAPTER_TYPE_H */
