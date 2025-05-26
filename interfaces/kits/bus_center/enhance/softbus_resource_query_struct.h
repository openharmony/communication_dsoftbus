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

#ifndef SOFTBUS_RESOURCE_QUERY_STRUCT_H
#define SOFTBUS_RESOURCE_QUERY_STRUCT_H

#include <stdint.h>
#include "softbus_common.h"
#include "trans_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RESOURCE_IP_LEN 32
#define UDIDHASH_HEX_STR_LEN 16

typedef enum {
    TRIGGER_TYPE_ACTION,
    TRIGGER_TYPE_COAP,
    TRIGGER_TYPE_BLE,
    TRIGGER_TYPE_BR,
    TRIGGER_TYPE_BUTT,
} TriggerType;

typedef struct {
    TriggerType type;
    union {
        uint32_t actionMac;
        char brMac[BT_MAC_LEN];
        char ip[IP_STR_MAX_LEN];
        char bleMac[BT_MAC_LEN];
    } addrInfo;
    char udidHash[UDIDHASH_HEX_STR_LEN + 1];
} TriggerAddr;

typedef enum {
    IDENTIFY_DEV_ID,
    IDENTIFY_DEV_ADDR,
    IDENTIFY_DEV_BUTT,
} DevIdentifier;

typedef struct {
    DevIdentifier devIdentifier;
    union {
        TriggerAddr peerAddr;
        char peerNetworkId[NETWORK_ID_BUF_LEN];
    } identifyInfo;
    TransDataType dataType[DATA_TYPE_BUTT];
} SoftBusResourceRequest;

typedef struct {
    uint8_t peerNetworkIdCnt;
    char (*peerNetworkIdArr)[NETWORK_ID_BUF_LEN];
    uint8_t peerIpCnt;
    char (*peerIpArr)[RESOURCE_IP_LEN];
} ConflictInfo;

#ifdef __cplusplus
}
#endif

#endif // SOFTBUS_RESOURCE_QUERY_STRUCT_H