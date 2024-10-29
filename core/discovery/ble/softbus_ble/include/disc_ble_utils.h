/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef DISC_BLE_UTILS_H
#define DISC_BLE_UTILS_H

#include <stdbool.h>
#include <stdint.h>

#include "softbus_common.h"
#include "broadcast_protocol_constant.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define ADV_DATA_MAX_LEN 24
#define RESP_DATA_MAX_LEN 26
#define REAL_RESP_DATA_MAX_LEN 27
#define CUST_CAPABILITY_LEN 2
#define CUST_CAPABILITY_TYPE_LEN 1
#define BROADCAST_MAX_LEN (ADV_DATA_MAX_LEN + RESP_DATA_MAX_LEN)

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
} DeviceWrapper;

typedef enum {
    HEART_BEAT = 0,
    CAST_PLUS,
    DV_KIT,
    PC_COLLABORATION,
    OSD
} CustDataCapability;

bool CheckBitMapEmpty(uint32_t capBitMapNum, const uint32_t *capBitMap);
bool CheckCapBitMapExist(uint32_t capBitMapNum, const uint32_t *capBitMap, uint32_t pos);
void SetCapBitMapPos(uint32_t capBitMapNum, uint32_t *capBitMap, uint32_t pos);
void UnsetCapBitMapPos(uint32_t capBitMapNum, uint32_t *capBitMap, uint32_t pos);

int32_t DiscBleGetDeviceName(char *deviceName, uint32_t size);
uint16_t DiscBleGetDeviceType(void);
int32_t DiscBleGetDeviceIdHash(unsigned char *devIdHash, uint32_t len);
int32_t DiscBleGetShortUserIdHash(unsigned char *hashStr, uint32_t len);

int32_t AssembleTLV(BroadcastData *broadcastData, unsigned char dataType, const void *data, uint32_t dataLen);
int32_t GetDeviceInfoFromDisAdvData(DeviceWrapper *device, const uint8_t *data, uint32_t dataLen);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif
