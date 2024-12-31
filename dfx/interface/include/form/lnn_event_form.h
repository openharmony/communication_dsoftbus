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
#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LNN_DEFAULT_PKG_NAME "MODULE_LNN"
#define DEVICE_TYPE_SIZE_LEN 3
#define HB_SHORT_UDID_HASH_HEX_LEN 16
#define BROADCAST_INTERVAL_DEFAULT 50
#define MAX_TIME_LATENCY 30000
#define DEVICE_NAME_BUF_LEN 128

typedef enum {
    EVENT_SCENE_LNN = 1,
    EVENT_SCENE_JOIN_LNN = 2,
    EVENT_SCENE_LEAVE_LNN = 3,
    EVENT_SCENE_LANE = 4,
} LnnEventScene;

typedef enum {
    EVENT_STAGE_LNN_DISC_SDK = 1,
    EVENT_STAGE_LNN_DISC_SERVICE = 2,
    EVENT_STAGE_LNN_JOIN_SDK = 3,
    EVENT_STAGE_LNN_LEAVE_SDK = 4,
    EVENT_STAGE_LNN_REG_NODE = 5,
    EVENT_STAGE_LNN_SHIFT_GEAR = 6,
    EVENT_STAGE_LNN_LANE_SELECT_START = 7,
    EVENT_STAGE_LNN_LANE_SELECT_END = 8,
    EVENT_STAGE_LNN_CTRL_BLE = 9,
    EVENT_STAGE_LNN_DATA_LEVEL = 10,
    EVENT_STAGE_LNN_BLE_TRIGGER = 11,
    EVENT_STAGE_LNN_WIFI_TRIGGER = 12,
    EVENT_STAGE_LNN_SCREEN_STATE_CHANGED = 13,
    EVENT_STAGE_LNN_USER_SWITCHED = 14,
    EVENT_STAGE_LNN_UPDATE_ACCOUNT = 15,
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
    EVENT_STAGE_JOIN_LNN_RECEIVE_BROADCAST = 12,
    EVENT_STAGE_JOIN_LNN_DEVICE_FOUND = 13,
} LnnEventJoinLnnStage;

typedef enum {
    EVENT_STAGE_LEAVE_LNN = 1,
} LnnEventLeaveLnnStage;

typedef enum {
    EVENT_STAGE_LANE_CONFLICT = 1,
} LnnEventLaneStage;

typedef enum {
    DB_TRIGGER = 0,
    DM_TRIGGER = 1,
    UPDATE_ACCOUNT = 2,
    SCREEN_ON = 3,
    SCREEN_OFF = 4,
    BLE_TURN_ON = 5,
    BLE_TURN_OFF = 6,
    BLE_MULTISCREEN_COLLABORATION = 7,
    BLE_LANE_VAP_CHANGED = 8,
    USER_SWITCHED = 9,
    MSDP_MOVEMENT_AND_STATIONARY = 10,
    TRIGGER_CLOUD_SYNC_HEARTBEAT = 11,
    WIFI_STATE_CHANGED = 12,
    WIFI_USER_FOREGROUND = 13,
    WIFI_NET_LOCK_STATE_CHANGED = 14,
    WIFI_FACK_OOBE = 15,
    WIFI_NIGHT_MODE_CHANGED = 16,
    WIFI_NET_ACCOUNT_STATE_CHANGED = 17,
    WIFI_IP_ADDR_CHANGED = 18,
    WIFI_GROUP_CREATED = 19,
    WIFI_DEVICE_BOUND = 20,
    OTHER,
}LnnTriggerReason;

typedef struct {
    uint64_t triggerTime;        // TRIGGER_LNN_TIME
    int32_t deviceCnt;           // DEVICE_CNT
    int32_t triggerReason;       // TRIGGER_REASON
}LnnTriggerInfo;

typedef enum {
    DISC_SERVER_PUBLISH = 1,
    DISC_SERVER_STOP_PUBLISH = 2,
    DISC_SERVER_DISCOVERY = 3,
    DISC_SERVER_STOP_DISCOVERY = 4,
} LnnDiscServerType;

typedef enum {
    LNN_TYPE_BLE_BROADCAST_ONLINE = 1,   // ble online by broadcast
    LNN_TYPE_BLE_CONNECT_ONLINE = 2,   // ble online by connection
    LNN_TYPE_WIFI_CONNECT_ONLINE = 101,  // wifi online by connection
    LNN_TYPE_BR_CONNECT_ONLINE = 201,    // br online by connection
    LNN_TYPE_OTHER_CONNECT_ONLINE = 301, // device online by other type connection
} LnnType;

typedef enum {
    CONNECT_INITIAL_VALUE = 0,
    BLE_FIRST_CONNECT = 1,
    LOCAL_STATE_VERSION_CHANGED = 2,
    PEER_STATE_VERSION_CHANGED = 4,
    DEVICEKEY_NOT_EXISTED = 8,
    UPDATE_REMOTE_DEVICE_INFO_FAILED = 16,
    FIND_REMOTE_CIPHERKEY_FAILED = 32,
} ConnectOnlineReason;

typedef struct {
    int32_t result;             // STAGE_RES
    int32_t errcode;            // ERROR_CODE
    int32_t authId;             // AUTH_ID
    int32_t discServerType;     // DISC_SERVER_TYPE
    int32_t gearCycle;          // GEAR_CYCLE
    int32_t gearDuration;       // GEAR_DURATION
    int32_t connectionId;       // CONN_ID
    int32_t authLinkType;       // AUTH_LINK_TYPE
    int32_t authRequestId;      // AUTH_REQUEST_ID
    int32_t authCostTime;       // AUTH_COST_TIME
    int32_t lnnType;            // LNN_TYPE
    int32_t onlineNum;          // ONLINE_NUM
    int32_t peerDeviceAbility;  // PEER_DEV_ABILITY
    int32_t onlineType;         // ONLINE_TYPE
    int32_t osType;             // OS_TYPE
    uint32_t connOnlineReason;  // CONN_ONLINE_REASON
    int32_t laneId;             // LANE_ID
    int32_t chanReqId;          // CHAN_REQ_ID
    int32_t connReqId;          // CONN_REQ_ID
    int32_t strategy;           // STRATEGY_FOR_LNN_BLE
    uint64_t timeLatency;       // TIME_LATENCY
    int32_t triggerReason;      // TRIGGER_REASON
    int64_t authSeq;            // AUTH_SEQ
    int32_t onlineDevCnt;       // ONLINE_DEV_CNT_FOR_LNN_TIME_LATENCY
    int32_t interval;           // BROADCAST_INTERVAL
    int32_t laneLinkType;       // LANE_LINK_TYPE
    int32_t hmlChannelId;       // HML_CHANNEL_ID
    int32_t p2pChannelId;       // P2P_CHANNEL_ID
    int32_t staChannelId;       // STA_CHANNEL_ID
    int32_t apChannelId;        // AP_CHANNEL_ID
    int32_t laneReqId;          // LANE_REQ_ID
    int32_t minBW;              // MIN_BW
    int32_t maxLaneLatency;     // MAX_LANE_LATENCY
    int32_t minLaneLatency;     // MIN_LANE_LATENCY
    int32_t isWifiDirectReuse;  // IS_WIFI_DIRECT_REUSE
    int32_t bandWidth;          // BAND_WIDTH
    int32_t guideType;          // GUIDE_TYPE
    const char *peerDeviceInfo; // PEER_DEV_INFO
    const char *peerIp;         // PEER_IP
    const char *peerBrMac;      // PEER_BR_MAC
    const char *peerBleMac;     // PEER_BLE_MAC
    const char *peerWifiMac;    // PEER_WIFI_MAC
    const char *peerPort;       // PEER_PORT
    const char *peerUdid;       // PEER_UDID
    const char *peerNetworkId;  // PEER_NET_ID
    const char *localDeviceType; // LOCAL_DEV_TYPE
    const char *peerDeviceType; // PEER_DEV_TYPE
    const char *localUdidHash;  // LOCAL_UDID_HASH
    const char *peerUdidHash;   // PEER_UDID_HASH
    const char *callerPkg;      // HOST_PKG
    const char *calleePkg;      // TO_CALL_PKG
} LnnEventExtra;

typedef struct {
    int32_t result;                                           // STAGE_RES
    int32_t errcode;                                          // ERROR_CODE
    int32_t lnnType;                                          // LNN_TYPE
    int32_t onlineNum;                                        // ONLINE_NUM
    int32_t onlineType;                                       // ONLINE_TYPE
    int32_t osType;                                           // OS_TYPE
    uint32_t connOnlineReason;                                // CONN_ONLINE_REASON
    char peerBleMac[BT_MAC_LEN];                              // PEER_BLE_MAC
    char peerUdid[UDID_BUF_LEN];                              // PEER_UDID
    char peerNetworkId[NETWORK_ID_BUF_LEN];                   // PEER_NET_ID
    char localDeviceType[DEVICE_TYPE_SIZE_LEN + 1];           // LOCAL_DEV_TYPE
    char peerDeviceType[DEVICE_TYPE_SIZE_LEN + 1];            // PEER_DEV_TYPE
    char localUdidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1];       // LOCAL_UDID_HASH
    char peerUdidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1];        // PEER_UDID_HASH
} LnnReportEventExtra;

typedef struct {
    DeviceType type;
    int32_t osType;
    ConnectOnlineReason bleConnectReason;
} LnnDfxDeviceInfoReport;

typedef enum {
    BLE_REPORT_EVENT_INIT = 1,
    BLE_REPORT_EVENT_FAIL = 2,
    BLE_REPORT_EVENT_SUCCESS = 3,
} ReportStatus;

typedef struct {
    LnnReportEventExtra extra;
    ReportStatus status;
} LnnBleReportExtra;

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
    AUDIT_SCENE_HEARTBEAT_FREQ = 6,
    AUDIT_SCENE_HEARTBEAT_MSG = 7,
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
    int32_t hbEventType;         // HEARTBEAT_EVENT_TYPE
} LnnAuditExtra;

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // LNN_EVENT_FORM_H
