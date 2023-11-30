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

#ifndef DISC_EVENT_FORM_H
#define DISC_EVENT_FORM_H

#include <stdint.h>

#include "event_form_enum.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EVENT_SCENE_BROADCAST = 1,
    EVENT_SCENE_SCAN = 2,
} DiscEventScene;

typedef enum {
    EVENT_STAGE_BROADCAST = 1,
} DiscEventBroadcastStage;

typedef enum {
    EVENT_STAGE_SCAN_START = 1,
    EVENT_STAGE_SCAN_END = 2,
} DiscEventScanStage;

typedef struct {
    int32_t result;              // STAGE_RES
    int32_t errcode;             // ERROR_CODE
    int32_t broadcastType;       // BROADCAST_TYPE
    int32_t broadcastFreq;       // BROADCAST_FREQ
    int32_t scanType;            // SCAN_TYPE
    const char *scanCycle;       // SCAN_CYCLE
    int32_t discType;            // DISC_TYPE
    int32_t discMode;            // DISC_MODE
    int32_t costTime;            // FIRST_DISCOVERY_TIME
    const char *localNetworkId;  // LOCAL_NET_ID
    const char *localUdid;       // LOCAL_UDID
    const char *localDeviceType; // LOCAL_DEV_TYPE
    const char *peerIp;          // PEER_IP
    const char *peerBrMac;       // PEER_BR_MAC
    const char *peerBleMac;      // PEER_BLE_MAC
    const char *peerWifiMac;     // PEER_WIFI_MAC
    const char *peerPort;        // PEER_PORT
    const char *peerUdid;        // PEER_UDID
    const char *peerNetworkId;   // PEER_NET_ID
    const char *peerDeviceType;  // PEER_DEV_TYPE
    const char *callerPkg;       // HOST_PKG
} DiscEventExtra;

typedef enum {
    ALARM_SCENE_DISC_RESERVED = 1,
} DiscAlarmScene;

typedef struct {
    int32_t errcode;
    int32_t result;
    int32_t originalFreq;
    int32_t abnormalFreq;
    int32_t duration;
} DiscAlarmExtra;

typedef enum {
    STATS_SCENE_DISC_RESERVED = 1,
} DiscStatsScene;

typedef struct {
    int32_t reserved;
} DiscStatsExtra;

typedef enum {
    AUDIT_SCENE_DISC_RESERVED = 1,
} DiscAuditScene;

typedef struct {
    int32_t reserved;
} DiscAuditExtra;

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // DISC_EVENT_FORM_H
