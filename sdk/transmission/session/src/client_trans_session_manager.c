/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "client_trans_session_manager.h"

#include <securec.h>

#include "client_trans_channel_manager.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_utils.h"

#define ID_NOT_USED 0
#define ID_USED 1
#define SHIFT_3 3
#define SESSION_MAP_COUNT ((MAX_SESSION_ID + 0x7) >> SHIFT_3)

static uint8_t g_idFlagBitmap[SESSION_MAP_COUNT];

static SoftBusList *g_clientSessionServerList = NULL;

void TransSessionTimer(void);

int TransClientInit(void)
{
    if (g_clientSessionServerList != NULL) {
        LOG_INFO("already init");
        return SOFTBUS_OK;
    }

    if (memset_s(g_idFlagBitmap, sizeof(g_idFlagBitmap), 0, sizeof(g_idFlagBitmap)) != EOK) {
        LOG_ERR("init id bitmap failed");
        return SOFTBUS_ERR;
    }

    g_clientSessionServerList = CreateSoftBusList();
    if (g_clientSessionServerList == NULL) {
        LOG_ERR("init list failed");
        return SOFTBUS_ERR;
    }

    if (RegisterTimeoutCallback(SOFTBUS_SESSION_TIMER_FUN, TransSessionTimer) != SOFTBUS_OK) {
        LOG_ERR("init trans timer failed");
        return SOFTBUS_ERR;
    }

    if (ClientTransChannelInit() != SOFTBUS_OK) {
        LOG_ERR("init trans channel failed");
        return SOFTBUS_ERR;
    }

    LOG_INFO("init succ");
    return SOFTBUS_OK;
}

static int32_t GenerateSessionId(void)
{
    /* need get lock before */
    for (uint32_t id = 0; id < MAX_SESSION_ID; id++) {
        if (((g_idFlagBitmap[(id >> SHIFT_3)] >> (id & 0x7)) & ID_USED) == ID_NOT_USED) {
            g_idFlagBitmap[(id >> SHIFT_3)] |= (ID_USED << (id & 0x7));
            return (int32_t)id;
        }
    }
    return INVALID_SESSION_ID;
}

static void DestroySessionId(int32_t sessionId)
{
    uint32_t id = (uint32_t)sessionId;
    g_idFlagBitmap[(id >> SHIFT_3)] &= (~(ID_USED << (id & 0x7)));
}

static void DestroyClientSessionServer(ClientSessionServer *server)
{
    if (server == NULL) {
        LOG_ERR("invalid param");
        return;
    }

    if (!IsListEmpty(&(server->sessionList))) {
        SessionInfo *sessionNode = NULL;
        SessionInfo *sessionNodeNext = NULL;
        LIST_FOR_EACH_ENTRY_SAFE(sessionNode, sessionNodeNext, &(server->sessionList), SessionInfo, node) {
            (void)ClientTransCloseChannel(sessionNode->channelId, sessionNode->channelType);
            ListDelete(&(sessionNode->node));
            DestroySessionId(sessionNode->sessionId);
            server->listener.session.OnSessionClosed(sessionNode->sessionId);
            SoftBusFree(sessionNode);
        }
    }

    ListDelete(&(server->node));
    LOG_INFO("destroy session server [%s]", server->sessionName);
    SoftBusFree(server);
}

void TransClientDeinit(void)
{
    if (g_clientSessionServerList == NULL) {
        return;
    }
    if (pthread_mutex_lock(&(g_clientSessionServerList->lock)) != 0) {
        LOG_ERR("lock failed");
        return;
    }
    ClientSessionServer *serverNode = NULL;
    ClientSessionServer *serverNodeNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(serverNode, serverNodeNext, &(g_clientSessionServerList->list),
        ClientSessionServer, node) {
        DestroyClientSessionServer(serverNode);
    }
    (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));

    DestroySoftBusList(g_clientSessionServerList);
    g_clientSessionServerList = NULL;
    ClientTransChannelDeinit();
}

void TransSessionTimer(void)
{
#define TRANS_SESSION_TIMEOUT (7 * 24) // hour
#define TRANS_SESSION_COUNT_TIMEOUT (60 * 60) // count per hour
    static int32_t count = 0;
    count++;
    if (count < TRANS_SESSION_COUNT_TIMEOUT) {
        return;
    }
    count = 0;

    if (g_clientSessionServerList == NULL) {
        LOG_ERR("not init");
        return;
    }

    if (pthread_mutex_lock(&(g_clientSessionServerList->lock)) != 0) {
        LOG_ERR("lock failed");
        return;
    }

    ClientSessionServer *serverNode = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&(serverNode->sessionList))) {
            continue;
        }
        SessionInfo *sessionNode = NULL;
        SessionInfo *sessionNodeNext = NULL;
        LIST_FOR_EACH_ENTRY_SAFE(sessionNode, sessionNodeNext, &(serverNode->sessionList), SessionInfo, node) {
            sessionNode->timeout++;
            if (sessionNode->timeout >= TRANS_SESSION_TIMEOUT) {
                (void)ClientTransCloseChannel(sessionNode->channelId, sessionNode->channelType);
                ListDelete(&(sessionNode->node));
                DestroySessionId(sessionNode->sessionId);
                serverNode->listener.session.OnSessionClosed(sessionNode->sessionId);
                SoftBusFree(sessionNode);
            }
        }
    }
    (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
    return;
}

static bool SessionServerIsExist(const char *sessionName)
{
    /* need get lock before */
    ListNode *pos = NULL;
    ListNode *tmp = NULL;
    ClientSessionServer *node = NULL;
    LIST_FOR_EACH_SAFE(pos, tmp, &g_clientSessionServerList->list) {
        node = (ClientSessionServer *)pos;
        if (strcmp(node->sessionName, sessionName) == 0) {
            return true;
        }
    }
    return false;
}

static ClientSessionServer *GetNewSessionServer(SoftBusSecType type, const char *sessionName,
    const char *pkgName, const ISessionListener *listener)
{
    ClientSessionServer *server = SoftBusCalloc(sizeof(ClientSessionServer));
    if (server == NULL) {
        return NULL;
    }
    server->type = type;
    if (strcpy_s(server->pkgName, sizeof(server->pkgName), pkgName) != EOK) {
        goto EXIT_ERR;
    }
    if (strcpy_s(server->sessionName, sizeof(server->sessionName), sessionName) != EOK) {
        goto EXIT_ERR;
    }
    if (memcpy_s(&server->listener.session, sizeof(ISessionListener), listener, sizeof(ISessionListener)) != EOK) {
        goto EXIT_ERR;
    }

    ListInit(&server->node);
    ListInit(&server->sessionList);
    return server;
EXIT_ERR:
    if (server != NULL) {
        SoftBusFree(server);
    }
    return NULL;
}

int32_t ClientAddSessionServer(SoftBusSecType type, const char *pkgName, const char *sessionName,
    const ISessionListener *listener)
{
    if (pkgName == NULL || sessionName == NULL || listener == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        LOG_ERR("not init");
        return SOFTBUS_ERR;
    }
    if (pthread_mutex_lock(&(g_clientSessionServerList->lock)) != 0) {
        LOG_ERR("lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (SessionServerIsExist(sessionName)) {
        (void)pthread_mutex_unlock(&g_clientSessionServerList->lock);
        return SOFTBUS_SERVER_NAME_REPEATED;
    }

    if (g_clientSessionServerList->cnt >= MAX_SESSION_SERVER_NUMBER) {
        (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
        LOG_ERR("server num reach max");
        return SOFTBUS_INVALID_NUM;
    }

    ClientSessionServer *server = GetNewSessionServer(type, sessionName, pkgName, listener);
    if (server == NULL) {
        (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
        return SOFTBUS_MEM_ERR;
    }
    ListAdd(&g_clientSessionServerList->list, &server->node);
    g_clientSessionServerList->cnt++;

    (void)pthread_mutex_unlock(&g_clientSessionServerList->lock);
    LOG_INFO("session name [%s], pkg name [%s]", server->sessionName, server->pkgName);
    return SOFTBUS_OK;
}

static bool IsValidSessionParam(const SessionParam *param)
{
    if ((param == NULL) ||
        (param->sessionName == NULL) ||
        (param->peerSessionName == NULL) ||
        (param->peerDeviceId == NULL) ||
        (param->groupId == NULL) ||
        (param->attr == NULL)) {
        return false;
    }
    return true;
}

static SessionInfo *CreateNewSession(const SessionParam *param)
{
    SessionInfo *session = (SessionInfo*)SoftBusCalloc(sizeof(SessionInfo));
    if (session == NULL) {
        LOG_ERR("calloc failed");
        return NULL;
    }

    if (strcpy_s(session->info.peerSessionName, SESSION_NAME_SIZE_MAX, param->peerSessionName) != EOK ||
        strcpy_s(session->info.peerDeviceId, DEVICE_ID_SIZE_MAX, param->peerDeviceId) != EOK ||
        strcpy_s(session->info.groupId, GROUP_ID_SIZE_MAX, param->groupId) != EOK) {
        LOG_ERR("strcpy failed");
        SoftBusFree(session);
        return NULL;
    }

    session->sessionId = INVALID_SESSION_ID;
    session->channelId = INVALID_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_BUTT;
    session->info.flag = param->attr->dataType;

    return session;
}

static SessionInfo *GetExistSession(const SessionParam *param)
{
    /* need get lock before */
    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    SessionTag *tagInfo = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if ((strcmp(serverNode->sessionName, param->sessionName) != 0) || IsListEmpty(&serverNode->sessionList)) {
            continue;
        }
        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            tagInfo = &sessionNode->info;
            if ((strcmp(tagInfo->peerSessionName, param->peerSessionName) != 0) ||
                (strcmp(tagInfo->peerDeviceId, param->peerDeviceId) != 0) ||
                (strcmp(tagInfo->groupId, param->groupId) != 0) ||
                (tagInfo->flag != param->attr->dataType)) {
                continue;
            }
            return sessionNode;
        }
    }
    return NULL;
}

static int32_t GetSessionById(int32_t sessionId, ClientSessionServer **server, SessionInfo **session)
{
    /* need get lock before */
    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }
        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->sessionId == sessionId) {
                *server = serverNode;
                *session = sessionNode;
                return SOFTBUS_OK;
            }
        }
    }
    return SOFTBUS_ERR;
}

static int32_t AddSession(const char *sessionName, SessionInfo *session)
{
    /* need get lock before */
    session->sessionId = GenerateSessionId();
    if (session->sessionId < 0) {
        return SOFTBUS_TRANS_SESSION_CNT_EXCEEDS_LIMIT;
    }
    ClientSessionServer *serverNode = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (strcmp(serverNode->sessionName, sessionName) != 0) {
            continue;
        }
        ListAdd(&serverNode->sessionList, &session->node);
        return SOFTBUS_OK;
    }
    DestroySessionId(session->sessionId);
    return SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED;
}

int32_t ClientAddNewSession(const char *sessionName, SessionInfo *session)
{
    if (session == NULL) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        LOG_ERR("not init");
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&(g_clientSessionServerList->lock)) != 0) {
        LOG_ERR("lock failed");
        return SOFTBUS_ERR;
    }

    int32_t ret = AddSession(sessionName, session);
    if (ret != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
        LOG_ERR("add session failed, ret [%d]", ret);
        return ret;
    }
    (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

int32_t ClientAddSession(const SessionParam *param, int32_t *sessionId, bool *isEnabled)
{
    if (!IsValidSessionParam(param) || (sessionId == NULL) || (isEnabled == NULL)) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        LOG_ERR("not init");
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&(g_clientSessionServerList->lock)) != 0) {
        LOG_ERR("lock failed");
        return SOFTBUS_ERR;
    }

    SessionInfo *session = GetExistSession(param);
    if (session != NULL) {
        *sessionId = session->sessionId;
        *isEnabled = (session->channelType != CHANNEL_TYPE_BUTT);
        (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
        return SOFTBUS_TRANS_SESSION_REPEATED;
    }

    session = CreateNewSession(param);
    if (session == NULL) {
        (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
        LOG_ERR("create session failed");
        return SOFTBUS_ERR;
    }

    int32_t ret = AddSession(param->sessionName, session);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(session);
        (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
        LOG_ERR("Add Session failed, ret [%d]", ret);
        return ret;
    }

    *sessionId = session->sessionId;
    (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

int32_t ClientDeleteSessionServer(SoftBusSecType type, const char *sessionName)
{
    if ((type == SEC_TYPE_UNKNOWN) || (sessionName == NULL)) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        LOG_ERR("not init");
        return SOFTBUS_NO_INIT;
    }

    if (pthread_mutex_lock(&(g_clientSessionServerList->lock)) != 0) {
        LOG_ERR("lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if ((strcmp(serverNode->sessionName, sessionName) == 0) && (serverNode->type == type)) {
            DestroyClientSessionServer(serverNode);
            g_clientSessionServerList->cnt--;
            (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
            return SOFTBUS_OK;
        }
    }
    (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
    LOG_ERR("not found [%s]", sessionName);
    return SOFTBUS_ERR;
}

int32_t ClientDeleteSession(int32_t sessionId)
{
    if (sessionId < 0) {
        return SOFTBUS_ERR;
    }

    if (g_clientSessionServerList == NULL) {
        LOG_ERR("not init");
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&(g_clientSessionServerList->lock)) != 0) {
        LOG_ERR("lock failed");
        return SOFTBUS_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }
        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->sessionId != sessionId) {
                continue;
            }
            ListDelete(&(sessionNode->node));
            DestroySessionId(sessionId);
            (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
            SoftBusFree(sessionNode);
            return SOFTBUS_OK;
        }
    }

    (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
    LOG_ERR("not found");
    return SOFTBUS_ERR;
}

int32_t ClientGetSessionDataById(int32_t sessionId, char *data, uint16_t len, SessionKey key)
{
    if ((sessionId < 0) || (data == NULL) || (len == 0)) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        LOG_ERR("not init");
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&(g_clientSessionServerList->lock)) != 0) {
        LOG_ERR("lock failed");
        return SOFTBUS_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    int32_t ret = GetSessionById(sessionId, &serverNode, &sessionNode);
    if (ret != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
        LOG_ERR("not found");
        return SOFTBUS_ERR;
    }

    switch (key) {
        case KEY_SESSION_NAME:
            ret = strcpy_s(data, len, serverNode->sessionName);
            break;
        case KEY_PEER_SESSION_NAME:
            ret = strcpy_s(data, len, sessionNode->info.peerSessionName);
            break;
        case KEY_PEER_DEVICE_ID:
            ret = strcpy_s(data, len, sessionNode->info.peerDeviceId);
            break;
        default:
            (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
            return SOFTBUS_ERR;
    }

    (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
    if (ret != EOK) {
        LOG_ERR("copy data failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientGetSessionIntegerDataById(int32_t sessionId, int *data, SessionKey key)
{
    if ((sessionId < 0) || (data == NULL)) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        LOG_ERR("not init");
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&(g_clientSessionServerList->lock)) != 0) {
        LOG_ERR("lock failed");
        return SOFTBUS_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    int32_t ret = GetSessionById(sessionId, &serverNode, &sessionNode);
    if (ret != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
        LOG_ERR("not found");
        return SOFTBUS_ERR;
    }
    switch (key) {
        case KEY_IS_SERVER:
            *data = sessionNode->isServer;
            break;
        case KEY_PEER_PID:
            *data = sessionNode->peerPid;
            break;
        case KEY_PEER_UID:
            *data = sessionNode->peerUid;
            break;
        default:
            (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
            return SOFTBUS_ERR;
    }

    (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
    if (ret != EOK) {
        LOG_ERR("copy data failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientGetChannelBySessionId(int32_t sessionId, int32_t *channelId, int32_t *type)
{
    if ((sessionId < 0) || (channelId == NULL) || (type == NULL)) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        LOG_ERR("not init");
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&(g_clientSessionServerList->lock)) != 0) {
        LOG_ERR("lock failed");
        return SOFTBUS_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    int32_t ret = GetSessionById(sessionId, &serverNode, &sessionNode);
    if (ret != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
        LOG_ERR("not found");
        return SOFTBUS_ERR;
    }

    *channelId = sessionNode->channelId;
    *type = sessionNode->channelType;
    (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

int32_t ClientSetChannelBySessionId(int32_t sessionId, int32_t channelId)
{
    if ((sessionId < 0) || (channelId < 0)) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        LOG_ERR("not init");
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&(g_clientSessionServerList->lock)) != 0) {
        LOG_ERR("lock failed");
        return SOFTBUS_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    int32_t ret = GetSessionById(sessionId, &serverNode, &sessionNode);
    if (ret != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
        LOG_ERR("not found");
        return SOFTBUS_ERR;
    }
    sessionNode->channelId = channelId;

    (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

int32_t ClientGetSessionIdByChannelId(int32_t channelId, int32_t *sessionId)
{
    if ((channelId < 0) || (sessionId == NULL)) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        LOG_ERR("not init");
        return SOFTBUS_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    if (pthread_mutex_lock(&(g_clientSessionServerList->lock)) != 0) {
        LOG_ERR("lock failed");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }

        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->channelId == channelId) {
                *sessionId = sessionNode->sessionId;
                (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
                return SOFTBUS_OK;
            }
        }
    }

    (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
    LOG_ERR("not found session with channelId [%d]", channelId);
    return SOFTBUS_ERR;
}

int32_t ClientEnableSessionByChannelId(const ChannelInfo *channel, int32_t *sessionId)
{
    if ((channel == NULL) || (sessionId == NULL)) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        LOG_ERR("not init");
        return SOFTBUS_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    if (pthread_mutex_lock(&(g_clientSessionServerList->lock)) != 0) {
        LOG_ERR("lock failed");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }

        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->channelId == channel->channelId) {
                sessionNode->channelType = channel->channelType;
                sessionNode->peerPid = channel->peerPid;
                sessionNode->peerUid = channel->peerUid;
                sessionNode->isServer = channel->isServer;
                *sessionId = sessionNode->sessionId;
                (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
                return SOFTBUS_OK;
            }
        }
    }

    (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
    LOG_ERR("not found session with channelId [%d]", channel->channelId);
    return SOFTBUS_ERR;
}

int32_t ClientGetSessionCallbackById(int32_t sessionId, ISessionListener *callback)
{
    if (sessionId < 0 || callback == NULL) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        LOG_ERR("not init");
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&(g_clientSessionServerList->lock)) != 0) {
        LOG_ERR("lock failed");
        return SOFTBUS_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    int32_t ret = GetSessionById(sessionId, &serverNode, &sessionNode);
    if (ret != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
        LOG_ERR("not found");
        return SOFTBUS_ERR;
    }

    ret = memcpy_s(callback, sizeof(ISessionListener), &serverNode->listener.session, sizeof(ISessionListener));

    (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
    if (ret != EOK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientGetSessionCallbackByName(const char *sessionName, ISessionListener *callback)
{
    if (sessionName == NULL || callback == NULL) {
        LOG_ERR("Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        LOG_ERR("not init");
        return SOFTBUS_ERR;
    }

    ClientSessionServer *serverNode = NULL;

    if (pthread_mutex_lock(&(g_clientSessionServerList->lock)) != 0) {
        LOG_ERR("lock failed");
        return SOFTBUS_ERR;
    }

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (strcmp(serverNode->sessionName, sessionName) != 0) {
            continue;
        }

        int32_t ret = memcpy_s(callback, sizeof(ISessionListener),
                               &serverNode->listener.session, sizeof(ISessionListener));
        (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
        if (ret != EOK) {
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    }

    (void)pthread_mutex_unlock(&(g_clientSessionServerList->lock));
    LOG_ERR("not found");
    return SOFTBUS_ERR;
}