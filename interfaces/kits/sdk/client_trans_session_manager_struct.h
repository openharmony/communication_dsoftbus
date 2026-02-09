/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_SESSION_MANAGER_STRUCT_H
#define CLIENT_TRANS_SESSION_MANAGER_STRUCT_H

#include "session.h"
#include "socket.h"
#include "softbus_app_info.h"
#include "softbus_def.h"
#include "softbus_trans_def.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IS_SERVER 0
#define IS_CLIENT 1
#define ISHARE_AUTH_SESSION "IShareAuthSession"
#define DM_AUTH_SESSION "ohos.distributedhardware.devicemanager.resident"
#define ISHARE_AUTH_SESSION_MAX_IDLE_TIME 5000 // 5s
#define DM_AUTH_SESSION_MAX_IDLE_TIME 275000 // 275s

typedef struct {
    char peerSessionName[SESSION_NAME_SIZE_MAX];
    char peerDeviceId[DEVICE_ID_SIZE_MAX];
    char groupId[GROUP_ID_SIZE_MAX];
    int flag; // TYPE_MESSAGE & TYPE_BYTES & TYPE_FILE
    int streamType;
} SessionTag;

typedef enum {
    SESSION_ROLE_INIT,
    SESSION_ROLE_CLIENT,
    SESSION_ROLE_SERVER,
    SESSION_ROLE_BUTT,
} SessionRole;

typedef enum {
    SESSION_STATE_INIT,
    SESSION_STATE_OPENING,
    SESSION_STATE_OPENED,
    SESSION_STATE_CALLBACK_FINISHED,
    SESSION_STATE_CANCELLING,
    SESSION_STATE_BUTT,
} SessionState;

typedef struct {
    SessionState sessionState;
    SoftBusCond callbackCond;
    bool condIsWaiting;
    int32_t bindErrCode;
    uint32_t maxWaitTime; // 0 means no check time out, for Bind end
    uint32_t waitTime;
} SocketLifecycleData;

typedef enum {
    ENABLE_STATUS_INIT,
    ENABLE_STATUS_SUCCESS,
    ENABLE_STATUS_FAILED,
    ENABLE_STATUS_BUTT,
} SessionEnableStatus;

typedef struct {
    QoSEvent event;
    QosTV qos[QOS_TYPE_BUTT];
    uint32_t count;
} CachedQosEvent;

typedef enum {
    MULTIPATH_STRATEGY_PARALLEL,        /**< 并行传输策略 （多径同时传输）*/
    MULTIPATH_STRATEGY_MASTER_SLAVE,    /**< 主从传输策略  (主路径优先，备用路径容灾) */
    MULTIPATH_STRATEGY_MAX,             /**< 策略类型上限标记 */
} MultipathStrategy;

typedef enum {
    NOT_MULTIPATH = 0,
    MULTIPATH_FIRST_CHANNEL,
    MULTIPATH_BOTH_CHANNEL,
    MULTIPATH_ONLY_SECOND_CHANNEL,
    LINK_DOWN_MAX_NUM_TYPE,
} LinkDownType;

typedef struct {
    ListNode node;
    int32_t sessionId;
    int32_t channelId;
    ChannelType channelType;
    SessionTag info;
    bool isServer;
    bool isD2D;
    bool isEncyptedRawStream;
    bool isAsync;
    bool isClosing;
    bool isPagingRoot;
    SessionRole role;
    uint32_t maxIdleTime;
    uint32_t timeout;
    SessionEnableStatus enableStatus;
    int32_t peerUid;
    int32_t peerPid;
    bool isEncrypt;
    int32_t routeType;
    int32_t businessType;
    int32_t fileEncrypt;
    int32_t algorithm;
    int32_t crc;
    LinkType linkType[LINK_TYPE_MAX];
    uint32_t dataConfig;
    SocketLifecycleData lifecycle;
    uint32_t actionId;
    int32_t osType;
    CachedQosEvent cachedQosEvent;
    bool isSupportTlv;
    bool needAck;
    int32_t tokenType;
    int32_t peerUserId;
    uint64_t peerTokenId;
    uint32_t dataLen;
    char extraData[EXTRA_DATA_MAX_LEN];
    char peerBusinessAccountId[ACCOUNT_UID_LEN_MAX];
    char peerExtraAccessInfo[EXTRA_ACCESS_INFO_LEN_MAX];
    char peerPagingAccountId[ACCOUNT_UID_LEN_MAX];
    bool isLowLatency;
    TransFlowInfo flowInfo;
    MultipathStrategy multipathStrategy;
    bool enableMultipath;
    int32_t channelIdReserve;
    ChannelType channelTypeReserve;
    LinkType linkTypeReserve[LINK_TYPE_MAX];
    bool isClosingReserve;
    int32_t routeTypeReserve;
    uint64_t startTimestamp;
} SessionInfo;

typedef struct {
    bool isSocketListener;
    ISessionListener session;
    ISocketListener socketClient;
    ISocketListener socketServer;
} SessionListenerAdapter;

typedef struct {
    ListNode node;
    SoftBusSecType type;
    char sessionName[SESSION_NAME_SIZE_MAX];
    char pkgName[PKG_NAME_SIZE_MAX];
    SessionListenerAdapter listener;
    ListNode sessionList;
    bool permissionState;
    bool isSrvEncryptedRawStream;
    int32_t sessionAddingCnt;
    int64_t serviceId;
} ClientSessionServer;

typedef enum {
    KEY_SESSION_NAME = 1,
    KEY_PEER_SESSION_NAME,
    KEY_PEER_DEVICE_ID,
    KEY_IS_SERVER,
    KEY_PEER_PID,
    KEY_PEER_UID,
    KEY_PKG_NAME,
    KEY_ACTION_ID,
} TransSessionKey;

typedef struct {
    ListNode node;
    char pkgName[PKG_NAME_SIZE_MAX];
    char sessionName[SESSION_NAME_SIZE_MAX];
} SessionServerInfo;

typedef enum {
    TIMER_ACTION_START,
    TIMER_ACTION_STOP,
    TIMER_ACTION_BUTT
} TimerAction;

typedef struct {
    ListNode node;
    int32_t sessionId;
    int32_t channelId;
    int32_t routeType;
    LinkDownType linkDownType;
    ChannelType channelType;
    bool isAsync;
    void (*OnSessionClosed)(int sessionId);
    void (*OnShutdown)(int32_t socket, ShutdownReason reason);
    char sessionName[SESSION_NAME_SIZE_MAX];
    char pkgName[PKG_NAME_SIZE_MAX];
    SocketLifecycleData lifecycle;
} DestroySessionInfo;

typedef struct {
    ListNode node;
    int32_t sessionId;
    int32_t channelId;
    ChannelType ChannelType;
    bool isAsync;
    bool mainChannel;
    void (*OnSessionClose)(int sessionId);
    void (*OnShutdown)(int32_t socket, ShutdownReason reason);
    char sessionName[SESSION_NAME_SIZE_MAX];
    char pkgName[PKG_NAME_SIZE_MAX];
    SocketLifecycleData liftcycle;
} DestroyMultiPathSessionInfo;
#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_SESSION_MANAGER_STRUCT_H
