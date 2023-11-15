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

#ifndef LNN_EVENT_FORM_H
#define LNN_EVENT_FORM_H

#include <stdlib.h>

typedef enum {
    SCENE_JION_LNN = 1,
    SCENE_LEAVE_LNN = 2,
} LnnEventScene;

typedef enum {
    STAGE_JOIN_LNN_START = 1,
    STAGE_AUTH_CONNECTION = 2,
    STAGE_AUTH_DEVICE = 3,
    STAGE_EXCHANGE_CIPHER = 4,
    STAGE_EXCHANGE_DEVICE_INFO = 5,
    STAGE_JOIN_LNN_END = 6,
} LnnEventJoinLnnStage;

typedef enum {
    STAGE_LEAVE_LNN_START = 1,
    STAGE_LEAVE_LNN_END = 2,
} LnnEventLeaveLnnStage;

typedef struct {
    int32_t peerNetworkId;     // PEER_NETID
    int32_t connectionId;      // CONN_ID
    int32_t authType;          // AUTH_TYPE
    int32_t authId;            // AUTH_ID
    int32_t peerDeviceType;    // PEER_DEV_TYPE
    int32_t peerDeviceAbility; // PEER_DEV_ABILITY
    int32_t peerDeviceInfo;    // PEER_DEV_INFO
    int32_t onlineNum;         // ONLINE_NUM
    int32_t errcode;           // ERROR_CODE
    const char *callerPkg;     // HOST_PKG
    const char *calleePkg;     // TO_CALL_PKG
    const char *peerBrMac;     // PEER_BR_MAC
    const char *peerBleMac;    // PEER_BLE_MAC
    const char *peerWifiMac;   // PEER_WIFI_MAC
    const char *peerIp;        // PEER_IP
    const char *peerPort;      // PEER_PORT
} LnnEventExtra;

#endif // LNN_EVENT_FORM_H
