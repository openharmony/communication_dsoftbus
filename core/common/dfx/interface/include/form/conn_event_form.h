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

#ifndef CONN_EVENT_FORM_H
#define CONN_EVENT_FORM_H

#include <stdint.h>

#include "event_form_enum.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EVENT_SCENE_CONNECT = 1,
} ConnEventScene;

typedef enum {
    EVENT_STAGE_CONNECT_START = 1,
    EVENT_STAGE_CONNECT_INVOKE_PROTOCOL = 2,
    EVENT_STAGE_CONNECT_END = 3,
} ConnEventConnectStage;

typedef struct {
    int32_t result;            // STAGE_RES
    int32_t errcode;           // ERROR_CODE
    int32_t connectionId;      // CONN_ID
    int32_t requestId;         // REQ_ID
    int32_t linkType;          // LINK_TYPE
    int32_t authType;          // AUTH_TYPE
    int32_t authId;            // AUTH_ID
    const char *lnnType;       // LNN_TYPE
    int32_t expectRole;        // EXPECT_ROLE
    int32_t costTime;          // TIME_CONSUMING
    int32_t rssi;              // RSSI
    int32_t load;              // CHLOAD
    int32_t frequency;         // FREQ
    const char *peerIp;        // PEER_IP
    const char *peerBrMac;     // PEER_BR_MAC
    const char *peerBleMac;    // PEER_BLE_MAC
    const char *peerWifiMac;   // PEER_WIFI_MAC
    const char *peerPort;      // PEER_PORT
    const char *callerPkg;     // HOST_PKG
    const char *calleePkg;     // TO_CALL_PKG
    int32_t bootLinkType;      // BOOT_LINK_TYPE
    int32_t isRenegotiate;     // IS_RENEGOTIATE
    int32_t isReuse;           // IS_REUSE
    uint64_t negotiateTime;    // NEGOTIATE_TIME_COSUMING
    uint64_t linkTime;         // LINK_TIME_COSUMING
} ConnEventExtra;

typedef enum {
    ALARM_SCENE_CONN_RESERVED = 1,
} ConnAlarmScene;

typedef struct {
    int32_t errcode;
    int32_t result;
    int32_t linkType;
    int32_t duration;
    int32_t netType;
} ConnAlarmExtra;

typedef enum {
    STATS_SCENE_CONN_RESERVED = 1,
    STATS_SCENE_CONN_BT_POST_FAILED,
    STATS_SCENE_CONN_BT_RECV_FAILED,
    STATS_SCENE_CONN_WIFI_CONN_FAILED,
    STATS_SCENE_CONN_WIFI_SEND_FAILED,
    STATS_SCENE_CONN_WIFI_POST_FAILED,
    STATS_SCENE_CONN_WIFI_RECV_FAILED,
} ConnStatsScene;

typedef enum {
    CONN_RESULT_OK = 0,
    CONN_RESULT_DISCONNECTED,
    CONN_RESULT_REFUSED,
} ConnResult;

typedef struct {
    int32_t reserved;
} ConnStatsExtra;

typedef enum {
    AUDIT_SCENE_CONN_RESERVED = 1,
} ConnAuditScene;

typedef struct {
    int32_t errcode;             // ERROR_CODE
    SoftbusAuditType auditType;  // AUDIT_TYPE
    int32_t connectionId;        // CONN_ID
    int32_t requestId;           // REQ_ID
    int32_t linkType;            // LINK_TYPE
    int32_t expectRole;          // EXPECT_ROLE
    int32_t costTime;            // COST_TIME
    int32_t connectTimes;        // CONN_TIMES
    const char *frequency;       // FREQ
    const char *peerBrMac;       // PEER_BR_MAC
    const char *localBrMac;      // LOCAL_BR_MAC
    const char *peerBleMac;      // PEER_BLE_MAC
    const char *localBleMac;     // LOCAL_BLE_MAC
    const char *peerDeviceType;  // PEER_DEV_TYPE
    const char *peerUdid;        // PEER_UDID
    const char *localUdid;       // LOCAL_UDID
    const char *connPayload;     // CONN_PAYLOAD
    const char *localDeviceName; // LOCAL_DEV_NAME
    const char *peerIp;          // PEER_IP
    const char *localIp;         // LOCAL_IP
    const char *callerPkg;       // HOST_PKG
    const char *calleePkg;       // TO_CALL_PKG
    const char *peerPort;        // PEER_PORT
    const char *localPort;       // LOCAL_PORT
} ConnAuditExtra;

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // CONN_EVENT_FORM_H
