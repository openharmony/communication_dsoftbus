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

#include <stdint.h>

#include "event_form_enum.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EVENT_SCENE_JOIN_LNN = 1,
    EVENT_SCENE_LEAVE_LNN = 2,
} LnnEventScene;

typedef enum {
    EVENT_STAGE_JOIN_LNN_START = 1,
    EVENT_STAGE_AUTH_CONNECTION = 2,
    EVENT_STAGE_AUTH_DEVICE = 3,
    EVENT_STAGE_EXCHANGE_CIPHER = 4,
    EVENT_STAGE_EXCHANGE_DEVICE_INFO = 5,
    EVENT_STAGE_JOIN_LNN_END = 6,
} LnnEventJoinLnnStage;

typedef enum {
    EVENT_STAGE_LEAVE_LNN_START = 1,
    EVENT_STAGE_LEAVE_LNN_END = 2,
} LnnEventLeaveLnnStage;

typedef struct {
    int32_t result;             // STAGE_RES
    int32_t errcode;            // ERROR_CODE
    int32_t connectionId;       // CONN_ID
    int32_t authType;           // AUTH_TYPE
    int32_t authId;             // AUTH_ID
    int32_t lnnType;            // LNN_TYPE
    int32_t onlineNum;          // ONLINE_NUM
    int32_t peerDeviceAbility;  // PEER_DEV_ABILITY
    const char *peerDeviceInfo; // PEER_DEV_INFO
    const char *peerIp;         // PEER_IP
    const char *peerBrMac;      // PEER_BR_MAC
    const char *peerBleMac;     // PEER_BLE_MAC
    const char *peerWifiMac;    // PEER_WIFI_MAC
    const char *peerPort;       // PEER_PORT
    const char *peerUdid;       // PEER_UDID
    const char *peerNetworkId;  // PEER_NET_ID
    const char *peerDeviceType; // PEER_DEV_TYPE
    const char *callerPkg;      // HOST_PKG
    const char *calleePkg;      // TO_CALL_PKG
} LnnEventExtra;

typedef enum {
    ALARM_SCENE_LNN_RESERVED = 1,
} LnnAlarmScene;

typedef struct {
    int32_t errcode;
    int32_t result;
} LnnAlarmExtra;

typedef enum {
    STATS_SCENE_LNN_RESERVED = 1,
} LnnStatsScene;

typedef struct {
    int32_t reserved;
} LnnStatsExtra;

typedef enum {
    AUDIT_SCENE_LNN_RESERVED = 1,
} LnnAuditScene;

typedef struct {
    int32_t errcode;             // ERROR_CODE
    SoftbusAuditType auditType;  // AUDIT_TYPE
    int32_t connectionId;        // CONN_ID
    int32_t authLinkType;        // AUTH_LINK_TYPE
    int32_t authId;              // AUTH_ID
    int32_t onlineNum;           // ONLINE_NUM
    const char *peerIp;          // PEER_IP
    const char *peerBrMac;       // PEER_BR_MAC
    const char *peerBleMac;      // PEER_BLE_MAC
    const char *peerAuthPort;    // PEER_AUTH_PORT
    const char *peerUdid;        // PEER_UDID
    const char *peerNetworkId;   // PEER_NETWORK_ID
    int32_t peerDeviceType;      // PEER_DEV_TYPE
    const char *extra;           // EXTRA
    const char *callerPkg;       // HOST_PKG
    const char *calleePkg;       // TO_CALL_PKG
} LnnAuditExtra;

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // LNN_EVENT_FORM_H
