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

#ifndef DISC_BLE_UTILS_STRUCT_H
#define DISC_BLE_UTILS_STRUCT_H

#include <stdbool.h>
#include <stdint.h>

#include "broadcast_protocol_constant_struct.h"
#include "disc_action_common.h"
#include "disc_ble_constant_struct.h"
#include "softbus_common.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define ADV_DATA_MAX_LEN                   24
#define RESP_DATA_MAX_LEN                  26
#define REAL_RESP_DATA_MAX_LEN             27
#define CUST_CAPABILITY_LEN                2
#define CUST_CAPABILITY_TYPE_LEN           1
#define BROADCAST_MAX_LEN                  (ADV_DATA_MAX_LEN + RESP_DATA_MAX_LEN)
#define ACTION_CHANNEL_SIZE                1

#define DIST_ACTION_DEV_NAME_LEN           64
#define DIST_ACTION_CUST_LEN               2
#define DIST_ACTION_EXT_CUST_MAX_LEN       127
#define LEN_UDID                           8

typedef struct {
    union {
        unsigned char data[BROADCAST_MAX_LEN];
        struct {
            unsigned char advData[ADV_DATA_MAX_LEN];
            unsigned char rspData[RESP_DATA_MAX_LEN];
        };
    } data;
    // for total mode
    unsigned short dataLen;
    
    // for separate mode
    unsigned short advDataLen;
    unsigned short rspDataLen;
} BroadcastData;

typedef struct {
    DeviceInfo *info;
    int8_t power;
    char devName[DISC_MAX_DEVICE_NAME_LEN];
    uint32_t devNameLen;
    char nickname[DISC_MAX_NICKNAME_LEN];
    uint32_t nicknameLen;
    uint8_t channelId;
    uint8_t mac[ACTION_MAC_SIZE];
} DeviceWrapper;

typedef enum {
    HEART_BEAT = 0,
    CAST_PLUS,
    DV_KIT,
    PC_COLLABORATION,
    OSD
} CustDataCapability;

typedef struct {
    uint8_t cust[DIST_ACTION_CUST_LEN];
    uint8_t extCust[DIST_ACTION_EXT_CUST_MAX_LEN];
    uint8_t extCustLen;
    bool isPublish;
} DistInputContext;

typedef struct {
    uint8_t uidHash[SHORT_USER_ID_HASH_LEN];
    uint8_t devId[SHORT_DEVICE_ID_HASH_LENGTH];
    char devName[DIST_ACTION_DEV_NAME_LEN];
    uint8_t devNameLen;
    uint16_t deviceType;
    DiscActionParam localAction;
    DiscActionParam remoteAction;
    DistInputContext inputCtx;
} DistActionContext;

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif