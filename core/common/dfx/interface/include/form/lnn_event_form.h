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
#include "softbus_bus_center.h"
#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EVENT_SCENE_LNN = 1,
    EVENT_SCENE_JOIN_LNN = 2,
    EVENT_SCENE_LEAVE_LNN = 3,
} LnnEventScene;

typedef enum {
    EVENT_STAGE_LNN_DISC_SDK = 1,
    EVENT_STAGE_LNN_DISC_SERVICE = 2,
    EVENT_STAGE_LNN_JOIN_SDK = 3,
    EVENT_STAGE_LNN_LEAVE_SDK = 4,
    EVENT_STAGE_LNN_REG_NODE = 5,
    EVENT_STAGE_LNN_SHIFT_GEAR = 6,
} LnnEventLnnStage;

typedef enum {
    EVENT_STAGE_JOIN_LNN_START = 1,
    EVENT_STAGE_AUTH = 2,
    EVENT_STAGE_AUTH_CONNECTION = 3,
    EVENT_STAGE_AUTH_DEVICE_ID_POST = 4,
    EVENT_STAGE_AUTH_DEVICE_ID_PROCESS = 5,
    EVENT_STAGE_AUTH_HICHAIN_START = 6,
    EVENT_STAGE_AUTH_HICHAIN_END = 7,
    EVENT_STAGE_AUTH_EXCHANGE_CIPHER = 8,
    EVENT_STAGE_AUTH_DEVICE_INFO_POST = 9,
    EVENT_STAGE_AUTH_DEVICE_INFO_PROCESS = 10,
    EVENT_STAGE_JOIN_LNN_END = 11,
} LnnEventJoinLnnStage;

typedef enum {
    EVENT_STAGE_LEAVE_LNN = 1,
} LnnEventLeaveLnnStage;

typedef enum {
    DISC_SERVER_PUBLISH = 1,
    DISC_SERVER_STOP_PUBLISH = 2,
    DISC_SERVER_DISCOVERY = 3,
    DISC_SERVER_STOP_DISCOVERY = 4,
} LnnDiscServerType;

typedef struct {
    int32_t result;             // STAGE_RES
    int32_t errcode;            // ERROR_CODE
    int32_t authId;             // AUTH_ID
    int32_t discServerType;     // DISC_SERVER_TYPE
    int32_t gearCycle;          // GEAR_CYCLE
    int32_t gearDuration;       // GEAR_DURATION
    int32_t connectionId;       // CONN_ID
    int32_t authLinkType;       // AUTH_LINK_TYPE
    int32_t authCostTime;       // AUTH_COST_TIME
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
    AUDIT_SCENE_DECRYPT_CONN_DATA = 1,
    AUDIT_SCENE_DECRYPT_DEV_INFO_MSG = 2,
    AUDIT_SCENE_HANDLE_MSG_DEV_ID = 3,
    AUDIT_SCENE_HANDLE_MSG_DEV_INFO = 4,
    AUDIT_SCENE_HANDLE_MSG_AUTH_DATA = 5,
} LnnAuditScene;

typedef enum {
    AUDIT_DECRYPT_FAIL_END_AUTH = 1,
    AUDIT_HANDLE_MSG_FAIL_END_AUTH = 2,
} LnnAuditProcessResult;

typedef struct {
    int32_t result;               // RESULT
    int32_t errCode;              // ERROR_CODE
    SoftbusAuditType auditType;   // AUDIT_TYPE
    uint64_t connId;              // CONN_ID
    int32_t authLinkType;         // AUTH_LINK_TYPE
    uint32_t authRequestId;       // AUTH_REQUEST_ID
    int32_t onlineNum;            // ONLINE_NUM
    const char hostPkg[DISC_MAX_DEVICE_NAME_LEN];  // HOST_PKG
    const char localIp[IP_STR_MAX_LEN];            // LOCAL_IP
    const char localBrMac[BT_MAC_LEN];             // LOCAL_BR_MAC
    const char localBleMac[BT_MAC_LEN];            // LOCAL_BLE_MAC
    const char localUdid[UDID_BUF_LEN];            // LOCAL_UDID
    const char localNetworkId[NETWORK_ID_BUF_LEN]; // LOCAL_NETWORK_ID
    const char localDevName[DEVICE_NAME_BUF_LEN];  // LOCAL_DEV_NAME
    const char peerIp[IP_STR_MAX_LEN];             // PEER_IP
    const char peerBrMac[BT_MAC_LEN];              // PEER_BR_MAC
    const char peerBleMac[BT_MAC_LEN];             // PEER_BLE_MAC
    const char peerUdid[UDID_BUF_LEN];             // PEER_UDID
    const char peerNetworkId[NETWORK_ID_BUF_LEN];  // PEER_NETWORK_ID
    const char peerDevName[DEVICE_NAME_BUF_LEN];   // PEER_DEV_NAME
    int32_t localAuthPort;       // LOCAL_AUTH_PORT
    int32_t localProxyPort;      // LOCAL_PROXY_PORT
    int32_t localSessionPort;    // LOCAL_SESSION_PORT
    int32_t localDevType;        // LOCAL_DEV_TYPE
    int32_t peerAuthPort;        // PEER_AUTH_PORT
    int32_t peerProxyPort;       // PEER_PROXY_PORT
    int32_t peerSessionPort;     // PEER_SESSION_PORT
    int32_t peerDevType;         // PEER_DEV_TYPE
    int32_t attackTimes;         // ATTACK_TIMES
    int32_t beAttackedPort;      // BE_ATTACKED_PORT
} LnnAuditExtra;

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // LNN_EVENT_FORM_H
