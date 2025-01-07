/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef CLIENT_TRANS_SESSION_MANAGER_H
#define CLIENT_TRANS_SESSION_MANAGER_H

#include "session.h"
#include "socket.h"
#include "softbus_def.h"
#include "softbus_trans_def.h"
#include "client_trans_session_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IS_SERVER 0
#define IS_CLIENT 1
#define ISHARE_AUTH_SESSION "IShareAuthSession"
#define ISHARE_AUTH_SESSION_MAX_IDLE_TIME 5000 // 5s

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

typedef struct {
    ListNode node;
    int32_t sessionId;
    int32_t channelId;
    ChannelType channelType;
    SessionTag info;
    bool isServer;
    bool isEncyptedRawStream;
    bool isAsync;
    bool isClosing;
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
} SessionKey;

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
    ChannelType channelType;
    bool isAsync;
    void (*OnSessionClosed)(int sessionId);
    void (*OnShutdown)(int32_t socket, ShutdownReason reason);
    char sessionName[SESSION_NAME_SIZE_MAX];
    char pkgName[PKG_NAME_SIZE_MAX];
    SocketLifecycleData lifecycle;
} DestroySessionInfo;

int32_t ClientAddNewSession(const char *sessionName, SessionInfo *session);

/**
 * @brief Add session.
 * @return if the operation is successful, return SOFTBUS_OK.
 * @return if session already added, return SOFTBUS_TRANS_SESSION_REPEATED.
 * @return return other error codes.
 */
int32_t ClientAddSession(const SessionParam *param, int32_t *sessionId, SessionEnableStatus *isEnabled);

int32_t ClientAddAuthSession(const char *sessionName, int32_t *sessionId);

int32_t ClientDeleteSessionServer(SoftBusSecType type, const char *sessionName);

int32_t ClientDeleteSession(int32_t sessionId);

int32_t ClientGetSessionDataById(int32_t sessionId, char *data, uint16_t len, SessionKey key);

int32_t ClientGetSessionIntegerDataById(int32_t sessionId, int *data, SessionKey key);

int32_t ClientGetChannelBySessionId(
    int32_t sessionId, int32_t *channelId, int32_t *type, SessionEnableStatus *enableStatus);

int32_t ClientSetChannelBySessionId(int32_t sessionId, TransInfo *transInfo);

int32_t ClientGetChannelBusinessTypeBySessionId(int32_t sessionId, int32_t *businessType);

int32_t GetEncryptByChannelId(int32_t channelId, int32_t channelType, int32_t *data);

int32_t GetSupportTlvAndNeedAckById(int32_t channelId, int32_t channelType, bool *supportTlv, bool *needAck);

int32_t ClientGetSessionStateByChannelId(int32_t channelId, int32_t channelType, SessionState *sessionState);

int32_t ClientGetSessionIdByChannelId(int32_t channelId, int32_t channelType, int32_t *sessionId, bool isClosing);

int32_t ClientGetSessionIsAsyncBySessionId(int32_t sessionId, bool *isAsync);

int32_t ClientGetRouteTypeByChannelId(int32_t channelId, int32_t channelType, int32_t *routeType);

int32_t ClientGetDataConfigByChannelId(int32_t channelId, int32_t channelType, uint32_t *dataConfig);

int32_t ClientEnableSessionByChannelId(const ChannelInfo *channel, int32_t *sessionId);

int32_t ClientGetSessionCallbackById(int32_t sessionId, ISessionListener *callback);

int32_t ClientGetSessionCallbackByName(const char *sessionName, ISessionListener *callback);

int32_t ClientAddSessionServer(SoftBusSecType type, const char *pkgName, const char *sessionName,
    const ISessionListener *listener);

int32_t ClientGetSessionSide(int32_t sessionId);

int32_t ClientGetFileConfigInfoById(int32_t sessionId, int32_t *fileEncrypt, int32_t *algorithm, int32_t *crc);

int TransClientInit(void);
void TransClientDeinit(void);

void ClientTransRegLnnOffline(void);

void ClientTransOnUserSwitch(void);

void ClientTransOnLinkDown(const char *networkId, int32_t routeType);

void ClientCleanAllSessionWhenServerDeath(ListNode *sessionServerInfoList);

int32_t CheckPermissionState(int32_t sessionId);

void PermissionStateChange(const char *pkgName, int32_t state);

int32_t ClientAddSocketServer(SoftBusSecType type, const char *pkgName, const char *sessionName);

int32_t ClientAddSocketSession(
    const SessionParam *param, bool isEncyptedRawStream, int32_t *sessionId, SessionEnableStatus *isEnabled);

int32_t ClientSetListenerBySessionId(int32_t sessionId, const ISocketListener *listener, bool isServer);

int32_t ClientIpcOpenSession(
    int32_t sessionId, const QosTV *qos, uint32_t qosCount, TransInfo *transInfo, bool isAsync);

int32_t ClientSetActionIdBySessionId(int32_t sessionId, uint32_t actionId);

int32_t ClientSetSocketState(int32_t socket, uint32_t maxIdleTimeout, SessionRole role);

int32_t ClientGetSessionCallbackAdapterByName(const char *sessionName, SessionListenerAdapter *callbackAdapter);

int32_t ClientGetSessionCallbackAdapterById(int32_t sessionId, SessionListenerAdapter *callbackAdapter, bool *isServer);

int32_t ClientGetPeerSocketInfoById(int32_t sessionId, PeerSocketInfo *peerSocketInfo);

bool IsSessionExceedLimit(void);

int32_t ClientResetIdleTimeoutById(int32_t sessionId);

int32_t ClientGetSessionNameByChannelId(int32_t channelId, int32_t channelType, char *sessionName, int32_t len);

int32_t ClientRawStreamEncryptDefOptGet(const char *sessionName, bool *isEncrypt);

int32_t ClientRawStreamEncryptOptGet(int32_t channelId, int32_t channelType, bool *isEncrypt);

int32_t SetSessionIsAsyncById(int32_t sessionId, bool isAsync);

int32_t ClientTransSetChannelInfo(const char *sessionName, int32_t sessionId, int32_t channelId, int32_t channelType);

void DelSessionStateClosing(void);

void AddSessionStateClosing(void);

int32_t ClientHandleBindWaitTimer(int32_t socket, uint32_t maxWaitTime, TimerAction action);

inline bool IsValidQosInfo(const QosTV qos[], uint32_t qosCount)
{
    return (qos == NULL) ? (qosCount == 0) : (qosCount <= QOS_TYPE_BUTT);
}

int32_t SetSessionInitInfoById(int32_t sessionId);

int32_t ClientSetEnableStatusBySocket(int32_t socket, SessionEnableStatus enableStatus);

int32_t TryDeleteEmptySessionServer(const char *pkgName, const char *sessionName);

int32_t DeleteSocketSession(int32_t sessionId, char *pkgName, char *sessionName);

int32_t SetSessionStateBySessionId(int32_t sessionId, SessionState sessionState, int32_t optional);

int32_t GetSocketLifecycleAndSessionNameBySessionId(
    int32_t sessionId, char *sessionName, SocketLifecycleData *lifecycle);

int32_t ClientWaitSyncBind(int32_t socket);

int32_t ClientSignalSyncBind(int32_t socket, int32_t errCode);

int32_t ClientDfsIpcOpenSession(int32_t sessionId, TransInfo *transInfo);

void SocketServerStateUpdate(const char *sessionName);

int32_t ClientCancelAuthSessionTimer(int32_t sessionId);

int32_t ClientSetStatusClosingBySocket(int32_t socket, bool isClosing);

int32_t ClientGetChannelOsTypeBySessionId(int32_t sessionId, int32_t *osType);

int32_t ClientCacheQosEvent(int32_t socket, QoSEvent event, const QosTV *qos, uint32_t count);

int32_t ClientGetCachedQosEventBySocket(int32_t socket, CachedQosEvent *cachedQosEvent);

int32_t GetMaxIdleTimeBySocket(int32_t socket, uint32_t *maxIdleTime);

int32_t SetMaxIdleTimeBySocket(int32_t socket, uint32_t maxIdleTime);

void ClientTransOnPrivilegeClose(const char *peerNetworkId);

int32_t TransGetSupportTlvBySocket(int32_t socket, bool *supportTlv, int32_t *optValueSize);

int32_t TransSetNeedAckBySocket(int32_t socket, bool needAck);
#ifdef __cplusplus
}
#endif
#endif // CLIENT_TRANS_SESSION_MANAGER_H
