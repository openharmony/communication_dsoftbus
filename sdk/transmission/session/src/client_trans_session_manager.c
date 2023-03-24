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

#include "client_bus_center_manager.h"
#include "client_trans_channel_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"
#include "trans_server_proxy.h"

static int32_t g_sessionIdNum = 0;
static int32_t g_sessionId = 1;
static SoftBusList *g_clientSessionServerList = NULL;

typedef struct {
    ListNode node;
    int32_t sessionId;
    int32_t channelId;
    ChannelType channelType;
    void (*OnSessionClosed)(int sessionId);
} DestroySessionInfo;

int32_t CheckPermissionState(int32_t sessionId)
{
    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }
        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->sessionId == sessionId) {
                (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
                return serverNode->permissionState ? SOFTBUS_OK : SOFTBUS_PERMISSION_DENIED;
            }
        }
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_TRANS_INVALID_SESSION_ID;
}

void PermissionStateChange(const char *pkgName, int32_t state)
{
    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return;
    }
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    ClientSessionServer *serverNode = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if ((strcmp(serverNode->pkgName, pkgName) == 0)) {
            serverNode->permissionState = state > 0 ? true : false;
            SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "%s permission change, state = %d", pkgName, state);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
}

int TransClientInit(void)
{
    g_clientSessionServerList = CreateSoftBusList();
    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "init list failed");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (TransServerProxyInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "init trans ipc proxy failed");
        return SOFTBUS_ERR;
    }

    if (ClientTransChannelInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "init trans channel failed");
        return SOFTBUS_ERR;
    }

    ClientTransRegLnnOffline();
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "init trans client success");
    return SOFTBUS_OK;
}

static bool SessionIdIsAvailable(int32_t sessionId)
{
    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }
        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->sessionId == sessionId) {
                return false;
            }
        }
    }

    return true;
}

static int32_t GenerateSessionId(void)
{
    if (g_sessionIdNum >= MAX_SESSION_ID) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "sessionid num cross the line error");
        return INVALID_SESSION_ID;
    }
    int32_t cnt = MAX_SESSION_ID + 1;
    int32_t id = INVALID_SESSION_ID;

    while (cnt) {
        id = g_sessionId++;
        if (g_sessionId < 0) {
            g_sessionId = 1;
        }
        if (SessionIdIsAvailable(id)) {
            g_sessionIdNum++;
            return id;
        }
        cnt--;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "generate id error");
    return id;
}

static void DestroySessionId(void)
{
    if (g_sessionIdNum > 0) {
        g_sessionIdNum--;
    }
    return;
}

static DestroySessionInfo *CreateDestroySessionNode(SessionInfo *sessionNode, const ClientSessionServer *server)
{
    DestroySessionInfo *destroyNode = (DestroySessionInfo *)SoftBusMalloc(sizeof(DestroySessionInfo));
    if (destroyNode == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "destroyList malloc fail.");
        return NULL;
    }
    destroyNode->sessionId = sessionNode->sessionId;
    destroyNode->channelId = sessionNode->channelId;
    destroyNode->channelType = sessionNode->channelType;
    destroyNode->OnSessionClosed = server->listener.session.OnSessionClosed;
    return destroyNode;
}

static void ClientDestroySession(const ListNode *destroyList)
{
    if (IsListEmpty(destroyList)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "destroyList is empty fail.");
        return;
    }
    DestroySessionInfo *destroyNode = NULL;
    DestroySessionInfo *destroyNodeNext = NULL;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "DestroyClientSession start");
    LIST_FOR_EACH_ENTRY_SAFE(destroyNode, destroyNodeNext, destroyList, DestroySessionInfo, node) {
        int32_t id = destroyNode->sessionId;
        (void)ClientTransCloseChannel(destroyNode->channelId, destroyNode->channelType);
        if (destroyNode->OnSessionClosed != NULL) {
            destroyNode->OnSessionClosed(id);
        }
        ListDelete(&(destroyNode->node));
        SoftBusFree(destroyNode);
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "DestroyClientSession end");
}

static void DestroyClientSessionServer(ClientSessionServer *server, ListNode *destroyList)
{
    if (server == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param");
        return;
    }

    if (!IsListEmpty(&(server->sessionList))) {
        SessionInfo *sessionNode = NULL;
        SessionInfo *sessionNodeNext = NULL;
        LIST_FOR_EACH_ENTRY_SAFE(sessionNode, sessionNodeNext, &(server->sessionList), SessionInfo, node) {
            DestroySessionInfo *destroyNode = CreateDestroySessionNode(sessionNode, server);
            if (destroyNode == NULL) {
                continue;
            }
            DestroySessionId();
            ListDelete(&sessionNode->node);
            ListAdd(destroyList, &(destroyNode->node));
            SoftBusFree(sessionNode);
        }
    }

    ListDelete(&(server->node));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "destroy session server [%s]", server->sessionName);
    SoftBusFree(server);
}

void TransClientDeinit(void)
{
    if (g_clientSessionServerList == NULL) {
        return;
    }
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    ClientSessionServer *serverNode = NULL;
    ClientSessionServer *serverNodeNext = NULL;
    ListNode destroyList;
    ListInit(&destroyList);
    LIST_FOR_EACH_ENTRY_SAFE(serverNode, serverNodeNext, &(g_clientSessionServerList->list),
        ClientSessionServer, node) {
        DestroyClientSessionServer(serverNode, &destroyList);
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    ClientDestroySession(&destroyList);

    DestroySoftBusList(g_clientSessionServerList);
    g_clientSessionServerList = NULL;
    ClientTransChannelDeinit();
    TransServerProxyDeInit();
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
    ClientSessionServer *server = (ClientSessionServer *)SoftBusCalloc(sizeof(ClientSessionServer));
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (SessionServerIsExist(sessionName)) {
        (void)SoftBusMutexUnlock(&g_clientSessionServerList->lock);
        return SOFTBUS_SERVER_NAME_REPEATED;
    }

    if (g_clientSessionServerList->cnt >= MAX_SESSION_SERVER_NUMBER) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "server num reach max");
        return SOFTBUS_INVALID_NUM;
    }

    ClientSessionServer *server = GetNewSessionServer(type, sessionName, pkgName, listener);
    if (server == NULL) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        return SOFTBUS_MEM_ERR;
    }
    server->permissionState = true;
    ListAdd(&g_clientSessionServerList->list, &server->node);
    g_clientSessionServerList->cnt++;

    (void)SoftBusMutexUnlock(&g_clientSessionServerList->lock);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "session name [%s], pkg name [%s]",
        server->sessionName, server->pkgName);
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
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "calloc failed");
        return NULL;
    }

    if (strcpy_s(session->info.peerSessionName, SESSION_NAME_SIZE_MAX, param->peerSessionName) != EOK ||
        strcpy_s(session->info.peerDeviceId, DEVICE_ID_SIZE_MAX, param->peerDeviceId) != EOK ||
        strcpy_s(session->info.groupId, GROUP_ID_SIZE_MAX, param->groupId) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "strcpy failed");
        SoftBusFree(session);
        return NULL;
    }

    session->sessionId = INVALID_SESSION_ID;
    session->channelId = INVALID_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_BUTT;
    session->isServer = false;
    session->isEnable = false;
    session->info.flag = param->attr->dataType;
    session->isEncrypt = true;

    return session;
}

static SessionInfo *GetExistSession(const SessionParam *param)
{
    /* need get lock before */
    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if ((strcmp(serverNode->sessionName, param->sessionName) != 0) || IsListEmpty(&serverNode->sessionList)) {
            continue;
        }
        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->isServer ||
                (strcmp(sessionNode->info.peerSessionName, param->peerSessionName) != 0) ||
                (strcmp(sessionNode->info.peerDeviceId, param->peerDeviceId) != 0) ||
                (strcmp(sessionNode->info.groupId, param->groupId) != 0) ||
                (sessionNode->info.flag != param->attr->dataType)) {
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
    DestroySessionId();
    return SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED;
}

int32_t ClientAddNewSession(const char *sessionName, SessionInfo *session)
{
    if (session == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    int32_t ret = AddSession(sessionName, session);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "add session failed, ret [%d]", ret);
        return ret;
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

int32_t ClientAddSession(const SessionParam *param, int32_t *sessionId, bool *isEnabled)
{
    if (!IsValidSessionParam(param) || (sessionId == NULL) || (isEnabled == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    SessionInfo *session = GetExistSession(param);
    if (session != NULL) {
        *sessionId = session->sessionId;
        *isEnabled = session->isEnable;
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        return SOFTBUS_TRANS_SESSION_REPEATED;
    }

    session = CreateNewSession(param);
    if (session == NULL) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "create session failed");
        return SOFTBUS_TRANS_SESSION_CREATE_FAILED;
    }

    int32_t ret = AddSession(param->sessionName, session);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(session);
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Add Session failed, ret [%d]", ret);
        return ret;
    }

    *sessionId = session->sessionId;
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

static SessionInfo *CreateNonEncryptSessionInfo(const char *sessionName)
{
    if (!IsValidString(sessionName, SESSION_NAME_SIZE_MAX - 1)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return NULL;
    }
    SessionInfo *session = (SessionInfo *)SoftBusCalloc(sizeof(SessionInfo));
    if (session == NULL) {
        return NULL;
    }
    session->channelType = CHANNEL_TYPE_AUTH;
    session->isEncrypt = false;
    if (strcpy_s(session->info.peerSessionName, SESSION_NAME_SIZE_MAX, sessionName) != EOK) {
        SoftBusFree(session);
        return NULL;
    }
    return session;
}

int32_t ClientAddAuthSession(const char *sessionName, int32_t *sessionId)
{
    if (!IsValidString(sessionName, SESSION_NAME_SIZE_MAX - 1) || (sessionId == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    SessionInfo *session = CreateNonEncryptSessionInfo(sessionName);
    if (session == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = ClientAddNewSession(sessionName, session);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(session);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "client add new session failed, ret=%d.", ret);
        return ret;
    }
    *sessionId = session->sessionId;
    return SOFTBUS_OK;
}

int32_t ClientDeleteSessionServer(SoftBusSecType type, const char *sessionName)
{
    if ((type == SEC_TYPE_UNKNOWN) || (sessionName == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    ListNode destroyList;
    ListInit(&destroyList);
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if ((strcmp(serverNode->sessionName, sessionName) == 0) && (serverNode->type == type)) {
            DestroyClientSessionServer(serverNode, &destroyList);
            g_clientSessionServerList->cnt--;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    (void)ClientDestroySession(&destroyList);
    return SOFTBUS_OK;
}

int32_t ClientDeleteSession(int32_t sessionId)
{
    if (sessionId < 0) {
        return SOFTBUS_ERR;
    }

    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
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
            DestroySessionId();
            SoftBusFree(sessionNode);
            (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "%s:not found", __func__);
    return SOFTBUS_ERR;
}

int32_t ClientGetSessionDataById(int32_t sessionId, char *data, uint16_t len, SessionKey key)
{
    if ((sessionId < 0) || (data == NULL) || (len == 0)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    int32_t ret = GetSessionById(sessionId, &serverNode, &sessionNode);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "%s: sid[%d] not found", __func__, sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
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
        case KEY_PKG_NAME:
            ret = strcpy_s(data, len, serverNode->pkgName);
            break;
        default:
            (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
            return SOFTBUS_ERR;
    }

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    if (ret != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "copy data failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientGetSessionIntegerDataById(int32_t sessionId, int *data, SessionKey key)
{
    if ((sessionId < 0) || (data == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    int32_t ret = GetSessionById(sessionId, &serverNode, &sessionNode);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "%s:not found", __func__);
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
            (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
            return SOFTBUS_ERR;
    }

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    if (ret != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "copy data failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientGetChannelBySessionId(int32_t sessionId, int32_t *channelId, int32_t *type, bool *isEnable)
{
    if (sessionId < 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "%s:not found", __func__);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    if (channelId != NULL) {
        *channelId = sessionNode->channelId;
    }
    if (type != NULL) {
        *type = sessionNode->channelType;
    }
    if (isEnable != NULL) {
        *isEnable = sessionNode->isEnable;
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

int32_t ClientGetChannelBusinessTypeBySessionId(int32_t sessionId, int32_t *businessType)
{
    if ((sessionId < 0) || (businessType == NULL)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "%s:not found", __func__);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    *businessType = sessionNode->businessType;

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}


int32_t ClientSetChannelBySessionId(int32_t sessionId, TransInfo *transInfo)
{
    if ((sessionId < 0) || (transInfo->channelId < 0)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    int32_t ret = GetSessionById(sessionId, &serverNode, &sessionNode);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "%s:not found", __func__);
        return SOFTBUS_ERR;
    }
    sessionNode->channelId = transInfo->channelId;
    sessionNode->channelType = (ChannelType)transInfo->channelType;

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

int32_t GetEncryptByChannelId(int32_t channelId, int32_t channelType, int32_t *data)
{
    if ((channelId < 0) || (data == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }

        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->channelId == channelId && (int32_t)sessionNode->channelType == channelType) {
                *data = (int32_t)sessionNode->isEncrypt;
                (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
                return SOFTBUS_OK;
            }
        }
    }

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not found session with channelId [%d]", channelId);
    return SOFTBUS_ERR;
}

int32_t ClientGetSessionIdByChannelId(int32_t channelId, int32_t channelType, int32_t *sessionId)
{
    if ((channelId < 0) || (sessionId == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }

        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->channelId == channelId && sessionNode->channelType == (ChannelType)channelType) {
                *sessionId = sessionNode->sessionId;
                (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
                return SOFTBUS_OK;
            }
        }
    }

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not found session with channelId [%d]", channelId);
    return SOFTBUS_ERR;
}

int32_t ClientEnableSessionByChannelId(const ChannelInfo *channel, int32_t *sessionId)
{
    if ((channel == NULL) || (sessionId == NULL)) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }

        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if ((sessionNode->channelId == channel->channelId) &&
                (sessionNode->channelType == (ChannelType)(channel->channelType))) {
                sessionNode->peerPid = channel->peerPid;
                sessionNode->peerUid = channel->peerUid;
                sessionNode->isServer = channel->isServer;
                sessionNode->isEnable = true;
                sessionNode->routeType = channel->routeType;
                sessionNode->businessType = channel->businessType;
                sessionNode->fileEncrypt = channel->encrypt;
                sessionNode->algorithm = channel->algorithm;
                sessionNode->crc = channel->crc;
                *sessionId = sessionNode->sessionId;
                if (channel->channelType == CHANNEL_TYPE_AUTH || !sessionNode->isEncrypt) {
                    if (memcpy_s(sessionNode->info.peerDeviceId, DEVICE_ID_SIZE_MAX,
                            channel->peerDeviceId, DEVICE_ID_SIZE_MAX) != EOK) {
                        (void)SoftBusMutexUnlock(&g_clientSessionServerList->lock);
                        return SOFTBUS_MEM_ERR;
                    }
                }
                (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
                return SOFTBUS_OK;
            }
        }
    }

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not found session with channelId [%d], channelType [%d]",
        channel->channelId, channel->channelType);
    return SOFTBUS_ERR;
}

int32_t ClientGetSessionCallbackById(int32_t sessionId, ISessionListener *callback)
{
    if (sessionId < 0 || callback == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    int32_t ret = GetSessionById(sessionId, &serverNode, &sessionNode);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "%s:not found", __func__);
        return SOFTBUS_ERR;
    }

    ret = memcpy_s(callback, sizeof(ISessionListener), &serverNode->listener.session, sizeof(ISessionListener));

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    if (ret != EOK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientGetSessionCallbackByName(const char *sessionName, ISessionListener *callback)
{
    if (sessionName == NULL || callback == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    ClientSessionServer *serverNode = NULL;

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (strcmp(serverNode->sessionName, sessionName) != 0) {
            continue;
        }

        int32_t ret = memcpy_s(callback, sizeof(ISessionListener),
                               &serverNode->listener.session, sizeof(ISessionListener));
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        if (ret != EOK) {
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    }

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "%s:not found", __func__);
    return SOFTBUS_ERR;
}

int32_t ClientGetSessionSide(int32_t sessionId)
{
    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    int32_t side = -1;
    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }
        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->sessionId != sessionId) {
                continue;
            }
            side = sessionNode->isServer ? IS_SERVER : IS_CLIENT;
            (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
            return side;
        }
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return side;
}

static void DestroyClientSessionByNetworkId(const ClientSessionServer *server,
    const char *networkId, int32_t routeType, ListNode *destroyList)
{
    SessionInfo *sessionNode = NULL;
    SessionInfo *sessionNodeNext = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(sessionNode, sessionNodeNext, &(server->sessionList), SessionInfo, node) {
        if (strcmp(sessionNode->info.peerDeviceId, networkId) != 0) {
            continue;
        }
        if (routeType != ROUTE_TYPE_ALL && sessionNode->routeType != routeType) {
            continue;
        }

        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "DestroyClientSessionByNetworkId info={%d, %d, %d}",
            sessionNode->channelId, sessionNode->channelType, sessionNode->routeType);
        DestroySessionInfo *destroyNode = CreateDestroySessionNode(sessionNode, server);
        if (destroyNode == NULL) {
            continue;
        }
        DestroySessionId();
        ListDelete(&sessionNode->node);
        ListAdd(destroyList, &(destroyNode->node));
        SoftBusFree(sessionNode);
    }
}

static void ClientTransLnnOfflineProc(NodeBasicInfo *info)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "device offline callback enter.");
    if (info == NULL) {
        return;
    }
    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }

    ClientSessionServer *serverNode = NULL;
    ListNode destroyList;
    ListInit(&destroyList);
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        DestroyClientSessionByNetworkId(serverNode, info->networkId, ROUTE_TYPE_ALL, &destroyList);
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    (void)ClientDestroySession(&destroyList);
    return;
}

static INodeStateCb g_transLnnCb = {
    .events = EVENT_NODE_STATE_OFFLINE,
    .onNodeOffline = ClientTransLnnOfflineProc,
};

int32_t ReCreateSessionServerToServer(void)
{
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ReCreateSessionServerToServer");
    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_ERR;
    }
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        int32_t ret = ServerIpcCreateSessionServer(serverNode->pkgName, serverNode->sessionName);
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "session name [%s], pkg name [%s], ret [%d]",
            serverNode->sessionName, serverNode->pkgName, ret);
    }

    (void)SoftBusMutexUnlock(&g_clientSessionServerList->lock);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ReCreateSessionServerToServer ok");
    return SOFTBUS_OK;
}


void ClientTransRegLnnOffline(void)
{
    int32_t ret;
    ret = RegNodeDeviceStateCbInner("trans", &g_transLnnCb);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "reg lnn offline fail");
    }
}

void ClientTransOnLinkDown(const char *networkId, int32_t routeType)
{
    if (networkId == NULL || g_clientSessionServerList == NULL) {
        return;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ClientTransOnLinkDown: routeType=%d", routeType);

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    ClientSessionServer *serverNode = NULL;
    ListNode destroyList;
    ListInit(&destroyList);
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        DestroyClientSessionByNetworkId(serverNode, networkId, routeType, &destroyList);
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    (void)ClientDestroySession(&destroyList);
    return;
}

int32_t ClientGrantPermission(int uid, int pid, const char *busName)
{
    if (uid < 0 || pid < 0 || busName == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid parameter");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ClientGrantPermission: sessionName=%s", busName);

    int32_t ret = ServerIpcGrantPermission(uid, pid, busName);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "server grant permission failed, ret=%d", ret);
    }
    return ret;
}

int32_t ClientRemovePermission(const char *busName)
{
    if (busName == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid parameter");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "ClientRemovePermission: sessionName=%s", busName);

    int32_t ret = ServerIpcRemovePermission(busName);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "server remove permission failed, ret=%d", ret);
    }
    return ret;
}

int32_t ClientGetFileConfigInfoById(int32_t sessionId, int32_t *fileEncrypt, int32_t *algorithm, int32_t *crc)
{
    if (sessionId < 0 || fileEncrypt == NULL || algorithm == NULL || crc == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "not init");
        return SOFTBUS_ERR;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    int32_t ret = GetSessionById(sessionId, &serverNode, &sessionNode);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "%s:not found", __func__);
        return SOFTBUS_NOT_FIND;
    }
    *fileEncrypt = sessionNode->fileEncrypt;
    *algorithm = sessionNode->algorithm;
    *crc = sessionNode->crc;
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

void ClientCleanAllSessionWhenServerDeath(void)
{
    if (g_clientSessionServerList == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "client session server list not init.");
        return;
    }
    uint32_t destroyCnt = 0;
    ListNode destroyList;
    ListInit(&destroyList);
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "client get session server list lock failed.");
        return;
    }
    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    SessionInfo *nextSessionNode = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }
        LIST_FOR_EACH_ENTRY_SAFE(sessionNode, nextSessionNode, &(serverNode->sessionList), SessionInfo, node) {
            DestroySessionInfo *destroyNode = CreateDestroySessionNode(sessionNode, serverNode);
            if (destroyNode == NULL) {
                continue;
            }
            ListAdd(&destroyList, &(destroyNode->node));
            DestroySessionId();
            ListDelete(&sessionNode->node);
            SoftBusFree(sessionNode);
            ++destroyCnt;
        }
    }
    (void)SoftBusMutexUnlock(&g_clientSessionServerList->lock);
    (void)ClientDestroySession(&destroyList);
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "client destroy session cnt[%d].", destroyCnt);
}
