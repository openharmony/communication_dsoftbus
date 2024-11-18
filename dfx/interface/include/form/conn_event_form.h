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
    EVENT_SCENE_START_BASE_LISTENER = 2,
    EVENT_SCENE_STOP_BASE_LISTENER = 3,
    EVENT_SCENE_SOCKET_CREATE = 4,
    EVENT_SCENE_SOCKET_LISTEN = 5,
    EVENT_SCENE_SOCKET_ACCEPT = 6,
    EVENT_SCENE_SOCKET_CONNECT = 7,
    EVENT_SCENE_SOCKET_SHUTDOWN = 8,
    EVENT_SCENE_SOCKET_CLOSE = 9,
    EVENT_SCENE_LEGACY_CONNECT = 10,
    EVENT_SCENE_PASSIVE_CONNECT = 11,
} ConnEventScene;

typedef enum {
    EVENT_STAGE_CONNECT_START = 1,
    EVENT_STAGE_CONNECT_INVOKE_PROTOCOL = 2,
    EVENT_STAGE_CONNECT_END = 3,
    EVENT_STAGE_CONNECT_SEND_MESSAGE = 10,
    EVENT_STAGE_CONNECT_CHECK_HML = 11,
    EVENT_STAGE_CONNECT_CREATE_GROUP = 12,
    EVENT_STAGE_CONNECT_CONNECT_NOTIFY = 13,
    EVENT_STAGE_CONNECT_POST_RENEGOTIATE_REQ = 14,
    EVENT_STAGE_CONNECT_RENEGOTIATE_CONNECT = 15,
    EVENT_STAGE_CONNECT_SWITCH_NOTIFY = 16,
    EVENT_STAGE_CONNECT_POST_RENEGOTIATE_RESP = 17,
    EVENT_STAGE_CONNECT_CONNECT_GROUP = 18,
    EVENT_STAGE_CONNECT_CONFIG_INFO = 19,
    EVENT_STAGE_CONNECT_START_LISTENING = 20,
    EVENT_STAGE_CONNECT_DEVICE = 2101,
    EVENT_STAGE_CONNECT_DEVICE_DIRECTLY = 2102,
    EVENT_STAGE_CONNECT_UPDATE_CONNECTION_RC = 2103,
    EVENT_STAGE_CONNECT_SERVER_ACCEPTED = 2104,
    EVENT_STAGE_CONNECT_SEND_BASIC_INFO = 2105,
    EVENT_STAGE_CONNECT_PARSE_BASIC_INFO = 2106,
} ConnEventConnectStage;

typedef enum {
    EVENT_STAGE_TCP_COMMON_ONE = 1,
} ConnEventTcpCommonStage;

typedef struct {
    int32_t result;             // STAGE_RES
    int32_t errcode;            // ERROR_CODE
    int32_t connectionId;       // CONN_ID
    int32_t requestId;          // CONN_REQ_ID
    int32_t linkType;           // LINK_TYPE
    int32_t authType;           // AUTH_TYPE
    int32_t authId;             // AUTH_ID
    const char *lnnType;        // LNN_TYPE
    int32_t expectRole;         // EXPECT_ROLE
    int32_t costTime;           // TIME_CONSUMING
    int32_t rssi;               // RSSI
    int32_t load;               // CHLOAD
    int32_t frequency;          // FREQ
    int32_t connProtocol;       // CONN_PROTOCOL
    int32_t connRole;           // CONN_ROLE
    int32_t connRcDelta;        // CONN_RC_DELTA
    int32_t connRc;             // CONN_RC
    int32_t supportFeature;     // SUPT_FEATURE
    int32_t moduleId;           // MODULE_ID
    uint32_t proType;           // PROTOCOL_TYPE
    int32_t fd;                 // FD
    int32_t cfd;                // CFD
    const char *challengeCode;  // CHALLENGE_CODE
    const char *peerIp;         // PEER_IP
    const char *peerBrMac;      // PEER_BR_MAC
    const char *peerBleMac;     // PEER_BLE_MAC
    const char *peerWifiMac;    // PEER_WIFI_MAC
    const char *peerPort;       // PEER_PORT
    const char *peerNetworkId;  // PEER_NET_ID
    const char *peerUdid;       // PEER_UDID
    const char *peerDeviceType; // PEER_DEV_TYPE
    const char *localNetworkId; // LOCAL_NET_ID
    const char *callerPkg;      // HOST_PKG
    const char *calleePkg;      // TO_CALL_PKG
    int32_t bootLinkType;       // BOOT_LINK_TYPE
    int32_t isRenegotiate;      // IS_RENEGOTIATE
    int32_t isReuse;            // IS_REUSE
    uint64_t negotiateTime;     // NEGOTIATE_TIME_COSUMING
    uint64_t linkTime;          // LINK_TIME_COSUMING
    int32_t osType;             // OS_TYPE
    const char *localDeviceType;  // LOCAL_DEVICE_TYPE
    const char *remoteDeviceType; // REMOTE_DEVICE_TYPE
    int32_t p2pChannel;           // P2P_CHAN
    int32_t hmlChannel;           // HML_CHAN
    int32_t staChannel;           // STA_CHAN
    int32_t apChannel;            // HOTSPOT_CHAN
    const char *peerDevVer;       // REMOTE_OS_VERSION
    int32_t remoteScreenStatus;   // REMOTE_SCREEN_STATUS
    int32_t businessType;         // BUSINESS_TYPE
    int32_t businessId;           // BUSINESS_ID
    int32_t timeout;              // TIME_OUT
    int32_t fastestConnectEnable; // FASTEST_CONNECT_ENABLE
    int32_t coapDataChannel;      // COAP_DATA_CHANNEL
    int32_t enableWideBandwidth;  // ENABLE_WIDE_BANDWIDTH
    int32_t p2pRole;              // P2P_ROLE
    int32_t needHmlConnect;       // NEED_HML_CONNECT
    const char *businessTag;      // BUSINESS_TAG
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
    AUDIT_SCENE_CONN_HML_GROUP_TIMEOUT = 1,
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
    const char *challengeCode;   // CHALLENGE_CODE
    const char *peerBrMac;       // PEER_BR_MAC
    const char *localBrMac;      // LOCAL_BR_MAC
    const char *peerBleMac;      // PEER_BLE_MAC
    const char *localBleMac;     // LOCAL_BLE_MAC
    const char *peerWifiMac;     // PEER_WIFI_MAC
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
