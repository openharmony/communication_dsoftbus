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

#ifndef BROADCAST_STRUCT_H
#define BROADCAST_STRUCT_H

#include <stdint.h>
#include <stdbool.h>

#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t BroadCastAddr;
#define BROADCAST_TARGET_AREA 0xfffffffe

typedef enum : uint8_t {
    CLIP_BROAD_COPIED = 0,
    FOREGROUND_APP,
    ORIENTATION_RANGE,
    EVENT_TYPE_MAX,
} EventType;

typedef enum : uint8_t {
    EVENT_LOW_FREQ = 0,     // send 200ms or receive 2%
    EVENT_MID_FREQ,         // send 100ms or receive 10%
    EVENT_HIGH_FREQ,        // send 60ms or receive 25%
    EVENT_SUPER_HIGH_FREQ,  // send 20ms or receive 50%
    EVENT_FREQ_BUTT,
} EventFreq;

typedef struct {
    EventType event;
    EventFreq freq;
    unsigned char *data;
    uint32_t dataLen;
    bool screenOff;
} EventData;

typedef struct {
    EventType event;
    char senderNetworkId[NETWORK_ID_BUF_LEN];
    char uidHash[MAX_ACCOUNT_HASH_LEN];
    char version;
    bool isEncrpted;
    uint16_t seqNo;
    unsigned char *data;
    uint32_t dataLen;
} EventNotify;

typedef struct {
    EventType event;
    EventFreq freq;
    bool deduplicate;
    void (*OnEventRecived)(const EventNotify *event);
} EventListener;

typedef struct {
    void (*OnLinkEventReceived)(const char *networkId, const char *localNetworkId, uint16_t seqNum);
} LinkEventListener;

#ifdef __cplusplus
}
#endif
#endif  // BROADCAST_STRUCT_H