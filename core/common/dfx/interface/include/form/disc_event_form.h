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
    EVENT_SCENE_INIT = 1,
    EVENT_SCENE_DISC = 2,
    EVENT_SCENE_BLE = 3,
    EVENT_SCENE_SHARE_BLE = 4,
    EVENT_SCENE_APPROACH_BLE = 5,
    EVENT_SCENE_COAP = 6,
} DiscEventScene;

typedef enum {
    EVENT_STAGE_INIT = 1,
    EVENT_STAGE_SOFTBUS_BLE_INIT = 2,
    EVENT_STAGE_SHARE_BLE_INIT = 3,
    EVENT_STAGE_APPROACH_BLE_INIT = 4,
} DiscEventInitStage;

typedef enum {
    EVENT_STAGE_DISC_SDK = 1,
    EVENT_STAGE_DISC_SERVICE = 2,
    EVENT_STAGE_ADD_INFO = 3,
    EVENT_STAGE_CALL_INTERFACE = 4,
    EVENT_STAGE_DEVICE_FOUND = 5,
} DiscEventDiscStage;

typedef enum {
    EVENT_STAGE_BLE_PROCESS = 1,
    EVENT_STAGE_BLE_HANDLER = 2,
    EVENT_STAGE_STATE_TURN = 3,
    EVENT_STAGE_BROADCAST = 4,
    EVENT_STAGE_SCAN = 5,
    EVENT_STAGE_SCAN_RECV = 6,
} DiscEventBleStage;

typedef enum {
    EVENT_STAGE_SHARE_BLE_PROCESS = 1,
    EVENT_STAGE_SHARE_BLE_UPDATE_DEVICE = 2,
} DiscEventShareBleStage;

typedef enum {
    EVENT_STAGE_APPROACH_BLE_PROCESS = 1,
} DiscEventApproachBleStage;

typedef enum {
    EVENT_STAGE_COAP = 1,
    EVENT_STAGE_UPDATE_IP = 2,
    EVENT_STAGE_UPDATE_DEVICE = 3,
    EVENT_STAGE_REGISTER = 4,
    EVENT_STAGE_SET_FILTER = 5,
    EVENT_STAGE_DISCOVERY_START = 6,
    EVENT_STAGE_DISCOVERY_STOP = 7,
} DiscEventCoapStage;

typedef enum {
    SERVER_PUBLISH = 1,
    SERVER_STOP_PUBLISH = 2,
    SERVER_DISCOVERY = 3,
    SERVER_STOP_DISCOVERY = 4,
} DiscServerType;

typedef struct {
    int32_t result;              // STAGE_RES
    int32_t errcode;             // ERROR_CODE
    int32_t initType;            // INIT_TYPE
    int32_t serverType;          // SERVER_TYPE
    int32_t interFuncType;       // INTERFACE_FUNC_TYPE
    int32_t capabilityBit;       // CAPABILITY_BIT
    const char *capabilityData;  // CAPABILITY_DATA
    int32_t bleTurnState;        // BLE_TURN_STATE
    int32_t ipLinkStatus;        // IP_LINK_STATUS
    int32_t coapChangeType;      // COAP_CHANGE_TYPE
    int32_t broadcastType;       // BROADCAST_TYPE
    int32_t broadcastFreq;       // BROADCAST_FREQ
    int32_t scanType;            // SCAN_TYPE
    const char *scanCycle;       // SCAN_CYCLE
    int32_t discType;            // DISC_TYPE
    int32_t discMode;            // DISC_MODE
    int32_t costTime;            // FIRST_DISCOVERY_TIME
    const char *localNetworkId;  // LOCAL_NET_ID
    const char *peerIp;          // PEER_IP
    const char *peerBrMac;       // PEER_BR_MAC
    const char *peerBleMac;      // PEER_BLE_MAC
    const char *peerWifiMac;     // PEER_WIFI_MAC
    const char *peerPort;        // PEER_PORT
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
    AUDIT_SCENE_BLE_PUBLISH = 1,
    AUDIT_SCENE_BLE_SUBSCRIBE = 2,
    AUDIT_SCENE_BLE_ADVERTISE = 3,
    AUDIT_SCENE_BLE_SCAN = 4,
    AUDIT_SCENE_COAP_PUBLISH = 5,
    AUDIT_SCENE_COAP_DISCOVERY = 6,
} DiscAuditScene;

typedef enum {
    DISC_AUDIT_CONTINUE = 1,
    DISC_AUDIT_DISCONTINUE = 2,
    DISC_AUDIT_TRY_AGAIN = 3,
} DiscAuditResult;

typedef struct {
    const char *callerPkg;         // HOST_PKG
    int32_t result;                // RESULT
    int32_t errcode;               // ERROR_CODE
    SoftbusAuditType auditType;    // AUDIT_TYPE
    int32_t broadcastType;         // BROADCAST_TYPE
    int32_t broadcastFreq;         // BROADCAST_FREQ
    int32_t advCount;              // ADV_COUNT
    int32_t advDuration;           // ADV_DURATION
    int32_t scanInterval;          // SCAN_INTERVAL
    int32_t scanWindow;            // SCAN_WINDOW
    int32_t discMode;              // DISC_MODE
    int32_t mediumType;            // MEDIUM_TYPE
    int32_t advChannel;            // ADV_CHANNEL
    int32_t scanType;              // SCAN_TYPE
    int32_t scanId;                // SCAN_ID
    int32_t scanListenerId;        // SCAN_LISTENER_ID
    const char *localUdid;         // LOCAL_UDID
    const char *localDeviceName;   // LOCAL_DEV_NAME
    const char *localDeviceType;   // LOCAL_DEV_TYPE
    const char *localAccountHash;  // LOCAL_ACCOUNT_HASH
    int32_t localCapabilityBitmap; // LOCAL_CAPABILITY_BITMAP
    const char *localCustData;     // LOCAL_CUST_DATA
    const char *localIp;           // LOCAL_IP
    int32_t localPort;             // LOCAL_PORT
    const char *localBrMac;        // LOCAL_BR_MAC
    const char *localBleMac;       // LOCAL_BLE_MAC
    const char *peerUdid;          // PEER_UDID
    const char *peerDeviceName;    // PEER_DEV_NAME
    const char *peerDeviceType;    // PEER_DEV_TYPE
    const char *peerAccountHash;   // PEER_ACCOUNT_HASH
    int32_t peerCapabilityBitmap;  // PEER_CAPABILITY_BITMAP
    const char *peerCustData;      // PEER_CUST_DATA
    const char *peerIp;            // PEER_IP
    int32_t peerPort;              // PEER_PORT
    const char *peerBrMac;         // PEER_BR_MAC
    const char *peerBleMac;        // PEER_BLE_MAC
    const char *errMsg;            // ERR_MSG
    const char *additionalInfo;    // ADDITIONAL_INFO
} DiscAuditExtra;

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // DISC_EVENT_FORM_H
