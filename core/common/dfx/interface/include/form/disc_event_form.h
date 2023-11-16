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

#include <stdlib.h>

typedef enum {
    SCENE_BROADCAST = 1,
    SCENE_SCAN = 2,
} DiscEventScene;

typedef enum {
    STAGE_BROADCAST = 1,
} DiscEventBroadcastStage;

typedef enum {
    STAGE_SCAN_START = 1,
    STAGE_SCAN_END = 2,
} DiscEventScanStage;

typedef struct {
    int32_t broadcastType;   // BROADCAST_TYPE
    int32_t broadcastFreq;   // BROADCAST_FREQ
    int32_t scanType;        // SCAN_TYPE
    int32_t discMode;        // DISC_MODE
    int32_t discType;        // DISC_TYPE
    int32_t localNetworkId;  // LOCAL_NET_ID
    int32_t localDeviceType; // LOCAL_DEV_TYPE
    int32_t costTime;        // FIRST_DISCOVERY_TIME
    int32_t peerNetworkId;   // PEER_NETID
    int32_t peerDeviceType;  // PEER_DEV_TYPE
    int32_t errcode;         // ERROR_CODE
    const char *callerPkg;   // HOST_PKG
    const char *scanCycle;   // SCAN_CYCLE
    const char *peerBrMac;   // PEER_BR_MAC
    const char *peerBleMac;  // PEER_BLE_MAC
    const char *peerWifiMac; // PEER_WIFI_MAC
    const char *peerIp;      // PEER_IP
    const char *peerPort;    // PEER_PORT
} DiscEventExtra;

#endif // DISC_EVENT_FORM_H
