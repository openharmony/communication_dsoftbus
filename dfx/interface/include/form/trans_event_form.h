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

#ifndef TRANS_EVENT_ATOM_FORM_H
#define TRANS_EVENT_ATOM_FORM_H

#include <stdint.h>

#include "event_form_enum.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EVENT_SCENE_OPEN_CHANNEL = 1,
    EVENT_SCENE_CLOSE_CHANNEL_ACTIVE = 2,
    EVENT_SCENE_CLOSE_CHANNEL_PASSIVE = 3,
    EVENT_SCENE_CLOSE_CHANNEL_TIMEOUT = 4,
    EVENT_SCENE_BT_FLOW = 5,
    EVENT_SCENE_LANE_SCORE = 6,
    EVENT_SCENE_ACTIVATION = 7,
    EVENT_SCENE_DETECTION = 8,
    EVENT_SCENE_OPEN_CHANNEL_SERVER = 9,
    EVENT_SCENE_TRANS_CREATE_SESS_SERVER = 10,
    EVENT_SCENE_TRANS_REMOVE_SESS_SERVER = 11,
    EVENT_SCENE_TRANS_PROXY_RESET_PEER = 12,
    EVENT_SCENE_TRANS_CHANNEL_STATISTICS = 13,
    EVENT_SCENE_TRANS_CHANNEL_INSTANT = 14,
    EVENT_SCENE_TRANS_MESSAGE_PARSE = 15,
    EVENT_SCENE_TRANS_RECEIVED_DATA = 16,
    EVENT_SCENE_TRANS_SEND_DATA = 17,
    EVENT_SCENE_CHANNEL_REQUEST = 18,
    EVENT_SCENE_TRANS_RECV_STREAM = 19,
    EVENT_SCENE_TRANS_REPORT_WIFIINFO = 20,
    EVENT_SCENE_PAGING_CONNECT = 21,
    EVENT_SCENE_TALKIE = 22,
    EVENT_SCENE_TRANS_FILE_RATE = 23,
    EVENT_SCENE_FAST_WAKE_UP = 24,
    EVENT_SCENE_SESSION_INFO = 25,
    EVENT_SCENE_TRANS_BR_PROXY = 26,
} TransEventScene;

typedef enum {
    EVENT_STAGE_PAGING_START_CONNECT = 1,
    EVENT_STAGE_PAGING_END_CONNECT = 2,
    EVENT_STAGE_PAGING_AUTH_START = 3,
    EVENT_STAGE_PAGING_AUTH_END = 4,
    EVENT_STAGE_PAGING_SOURCE_HANDSHAKE_START = 5,
    EVENT_STAGE_PAGING_SOURCE_HANDSHAKE_END = 6,
    EVENT_STAGE_PAGING_SINK_HANDSHAKE_START = 7,
    EVENT_STAGE_PAGING_SINK_HANDSHAKE_END = 8,
} TransEventPagingChannelStage;

typedef enum {
    EVENT_STAGE_TALKIE_BROADCAST_SEND = 1,
    EVENT_STAGE_TALKIE_BROADCAST_STOP = 2,
    EVENT_STAGE_TALKIE_BROADCAST_RECV = 3,
    EVENT_STAGE_TALKIE_PULL_UP_START = 4,
    EVENT_STAGE_TALKIE_PULL_UP_END = 5,
} TransEventTalkieStage;

typedef enum {
    EVENT_STAGE_OPEN_CHANNEL_START = 1,
    EVENT_STAGE_SELECT_LANE = 2,
    EVENT_STAGE_START_CONNECT = 3,
    EVENT_STAGE_HANDSHAKE_START = 4,
    EVENT_STAGE_HANDSHAKE_REPLY = 5,
    EVENT_STAGE_OPEN_CHANNEL_END = 6,
    EVENT_SCENE_FAST_WAKE_UP_SINGLE = 7,
    EVENT_SCENE_FAST_WAKE_UP_PERIODIC = 8,
} TransEventOpenChannelStage;

typedef enum {
    EVENT_STAGE_CLOSE_CHANNEL = 1,
} TransEventCloseChannelStage;

typedef enum {
    EVENT_STAGE_TRANS_COMMON_ONE = 1,
} TransEventCommonStage;

typedef enum {
    EVENT_STAGE_TRANS_RECV_STREAM = 1,
} TransEventStreamStage;

typedef enum {
    EVENT_STAGE_GENERAL_SESSION_INFO = 1,
    EVENT_STAGE_FILE_STEAM_STATISTIC = 2,
} TransEventSessionInfo;
 
typedef enum {
    EVENT_STAGE_ABNORMAL_DATA_SEND = 1,
    EVENT_STAGE_DATA_SEND_RATE = 2,
} TransEventSendData;

typedef enum {
    DEVICE_STATE_INVALID = 1,
    DEVICE_STATE_LOCAL_BT_HALF_OFF,
    DEVICE_STATE_REMOTE_BT_HALF_OFF,
    DEVICE_STATE_LOCAL_WIFI_HALF_OFF,
    DEVICE_STATE_REMOTE_WIFI_HALF_OFF,
    DEVICE_STATE_NOT_CARE,
    DEVICE_STATE_BUTT,
} TransDeviceState;

typedef enum {
    EVENT_STAGE_TOTAL_RATE = 1,     // Total data rate in multipath scenarios
    EVENT_STAGE_CHANNEL_RATE,       // Data rate of a single channel in multipath scenarios
    EVENT_STAGE_AVERAGE_RATE,       // Average data rate in non-multipath scenarios
    EVENT_STATE_BUTT,
} TransFileRateState;

typedef enum {
    WAKE_UP_STATE_DISABLE = 1,
    WAKE_UP_STATE_ENABLE,
    WAKE_UP_STATE_BUTT,
} WakeUpState;

typedef enum {
    EVENT_STAGE_OPEN_CHANNEL = 1,
    EVENT_STAGE_SEND_DATA = 2,
    EVENT_STAGE_CHANNEL_STATUS = 3,
    EVENT_STAGE_INTERNAL_STATE = 4,
    EVENT_STAGE_RECV_DATA = 5,
    EVENT_STAGE_CLOSE_BR_PROXY = 6,
    EVENT_STAGE_DISCONNECT = 7,
    EVENT_STAGE_RECONNECT = 8,
} TransEventBrProxy;

typedef struct {
    uint8_t talkieFreq;        // TALKIE_FREQ
    uint8_t talkieType;        // TALKIE_TYPE
    uint8_t talkieLevel;       // TALKIE_LEVEL
    uint8_t wakeUpState;       // WAKE_UP_STATE
    int32_t result;            // STAGE_RES
    int32_t errcode;           // ERROR_CODE
    const char *socketName;    // SESSION_NAME
    int32_t dataType;          // DATA_TYPE
    int32_t channelType;       // LOGIC_CHAN_TYPE
    int32_t laneId;            // LANE_ID
    int32_t preferLinkType;    // PREFER_LINK_TYPE
    int32_t laneTransType;     // LANE_TRANS_TYPE
    int32_t channelId;         // CHAN_ID
    int32_t requestId;         // REQ_ID
    int32_t connectionId;      // CONN_ID
    int32_t linkType;          // LINK_TYPE
    int32_t authId;            // AUTH_ID
    int32_t socketFd;          // SOCKET_FD
    int32_t costTime;          // TIME_CONSUMING
    int32_t channelScore;      // CHAN_SCORE
    int32_t peerChannelId;     // PEER_CHAN_ID
    int32_t btFlow;            // BT_FLOW
    int32_t pagingId;          // PAGING_ID
    int32_t callPid;         // CALLER_PID
    int32_t saId;              // SA_ID
    int32_t businessFlag;      // BUSINESS_FLAG
    const char *groupId;    // GROUP_ID
    const char *subGroupId; // SUB_GROUP_ID
    const char *peerNetworkId; // PEER_NET_ID
    const char *peerUdid;      // PEER_UDID
    const char *peerDevVer;    // PEER_DEV_VER
    const char *localUdid;     // LOCAL_UDID
    const char *callerPkg;     // HOST_PKG
    const char *calleePkg;     // TO_CALL_PKG
    const char *firstTokenName; // FIRST_TOKEN_NAME
    const char *callerAccountId; //CALLER_ACCOUNT_ID
    const char *calleeAccountId; //CALLEE_ACCOUNT_ID
    uint64_t firstTokenId;     // FIRST_TOKEN_ID
    int32_t  firstTokenType;   // FIRST_TOKEN_TYPE
    const char *trafficStats;  // TRAFFIC_STATS
    int32_t  osType;           // OS_TYPE
    int32_t  deviceState;      // DEVICE_STATE
    int32_t businessId;        // BUSINESS_ID
    int32_t businessType;      // BUSINESS_TYPE
    int32_t sessionId;         // SESSION_ID
    int32_t minBW;             // MIN_BW
    int32_t maxLatency;        // MAX_LATENCY
    int32_t minLatency;        // MIN_LATENCY
    uint16_t localStaChload;    // LOCAL_STA_CHLOAD
    uint16_t remoteStaChload;   // REMOTE_STA_CHLOAD
    uint16_t localHmlChload;    // LOCAL_HML_CHLOAD
    uint16_t remoteHmlChload;   // REMOTE_HML_CHLOAD
    uint16_t localP2pChload;    // LOCAL_P2P_CHLOAD
    uint16_t remoteP2pChload;   // REMOTE_P2P_CHLOAD
    uint8_t localStaChannel;   // LOCAL_STA_CHANNEL
    uint8_t remoteStaChannel;  // REMOTE_STA_CHANNEL
    uint8_t hmlChannel;        // HML_CHANNEL
    uint8_t localP2pChannel;   // LOCAL_P2P_CHANNEL
    uint8_t remoteP2pChannel;  // REMOTE_P2P_CHANNEL
    int32_t localIsDbac;       // LOCAL_IS_DBAC
    int32_t remoteIsDbac;      // REMOTE_IS_DBAC
    int32_t localIsDbdc;       // LOCAL_IS_DBDC
    int32_t remoteIsDbdc;      // REMOTE_IS_DBDC
    const char *conCurrentId;  // CONCURRENT_ID
    int32_t multipathTag;      // MULTIPATH_TAG
    uint32_t fileRate;         // FILE_RATE
    uint32_t fileWirelessRate; // FILE_WIRELESS_RATE
    uint32_t fileWiredRate;    // FILE_WIRED_RATE
    uint32_t bytesRate;
    int32_t fileChannelCnt;
    int32_t streamChannelCnt;
    int32_t dataLen;
    uint64_t sessionDuration;   // SESSION_DURATION
    uint8_t channelStatus;      // BR_PROXY_CHANNEL_STATUS
    int32_t userId;             // USER_ID
    int32_t appIndex;           // APP_INDEX
} TransEventExtra;

typedef enum {
    ALARM_SCENE_TRANS_RESERVED = 1,
} TransAlarmScene;

typedef struct {
    int32_t errcode;
    int32_t result;
    int32_t callerPid;
    int32_t linkType;
    int32_t minBw;
    int32_t methodId;
    int32_t duration;
    int32_t curFlow;
    int32_t limitFlow;
    int32_t limitTime;
    int32_t occupyRes;
    int32_t syncType;
    int32_t syncData;
    int32_t retryCount;
    int32_t retryReason;
    const char *conflictName;
    const char *conflictedName;
    const char *occupyedName;
    const char *permissionName;
    const char *sessionName;
} TransAlarmExtra;

typedef enum {
    STATS_SCENE_TRANS_RESERVED = 1,
} TransStatsScene;

typedef struct {
    int32_t reserved;
} TransStatsExtra;

typedef enum {
    AUDIT_SCENE_OPEN_SESSION = 1,
    AUDIT_SCENE_SEND_FILE,
    AUDIT_SCENE_SEND_BYTES,
    AUDIT_SCENE_SEND_MSG,
    AUDIT_SCENE_SEND_STREAM,
} TransAuditScene;

typedef enum {
    TRANS_AUDIT_CONTINUE = 1,
    TRANS_AUDIT_DISCONTINUE,
    TRANS_AUDIT_TRY_AGAIN,
} TransAuditResult;

typedef struct {
    const char *hostPkg;         // HOST_PKG
    int32_t result;              // RESULT
    int32_t errcode;             // ERROR_CODE
    SoftbusAuditType auditType;  // AUDIT_TYPE
    const char *localIp;         // LOCAL_IP
    const char *localPort;       // LOCAL_PORT
    const char *localDevId;      // LOCAL_DEV_ID
    int32_t localDevType;        // LOCAL_DEV_TYPE
    const char *localSessName;   // LOCAL_SESS_NAME
    int32_t localChannelId;      // LOCAL_CHANNEL_ID
    const char *peerIp;          // PEER_IP
    const char *peerPort;        // PEER_PORT
    const char *peerDevId;       // PEER_DEV_ID
    int32_t peerDevType;         // PEER_DEV_TYPE
    const char *peerSessName;    // PEER_SESS_NAME
    int32_t peerChannelId;       // PEER_CHANNEL_ID
    int32_t channelType;         // LOGIC_CHAN_TYPE
    int32_t authId;              // AUTH_ID
    int32_t reqId;               // REQ_ID
    int32_t linkType;            // LINK_TYPE
    int32_t connId;              // CONN_ID
    int32_t socketFd;            // SOCKET_FD
    int32_t dataType;            // DATA_TYPE
    int32_t dataLen;             // DATA_LENGTH
    int32_t dataSeq;             // DATA_SEQ
    int32_t costTime;            // TIME_CONSUMING
    int32_t dataTraffic;         // DATA_TRAFFIC
    int32_t reqCount;            // REQ_COUNT
} TransAuditExtra;

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // TRANS_EVENT_ATOM_FORM_H
