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

#include "client_trans_session_manager.h"

#include <securec.h>

#include "anonymizer.h"
#include "client_bus_center_manager.h"
#include "client_trans_channel_manager.h"
#include "client_trans_file_listener.h"
#include "client_trans_proxy_file_manager.h"
#include "client_trans_tcp_direct_manager.h"
#include "client_trans_udp_manager.h"
#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_socket.h"
#include "softbus_utils.h"
#include "trans_log.h"
#include "trans_server_proxy.h"

#define NETWORK_ID_LEN 7
#define HML_IP_PREFIX "172.30."
#define GET_ROUTE_TYPE(type) ((type) & 0xff)
#define GET_CONN_TYPE(type) (((type) >> 8) & 0xff)

#define DISTRIBUTED_DATA_SESSION "distributeddata-default"

static void ClientTransSessionTimerProc(void);

static int32_t g_sessionIdNum = 0;
static int32_t g_sessionId = 1;
static int32_t g_closingNum = 0;
static SoftBusList *g_clientSessionServerList = NULL;

typedef struct {
    ListNode node;
    int32_t sessionId;
    int32_t channelId;
    ChannelType channelType;
    void (*OnSessionClosed)(int sessionId);
    void (*OnShutdown)(int32_t socket, ShutdownReason reason);
    char sessionName[SESSION_NAME_SIZE_MAX];
} DestroySessionInfo;

int32_t CheckPermissionState(int32_t sessionId)
{
    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }
        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->sessionId == sessionId) {
                bool permissionState = serverNode->permissionState;
                (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
                return permissionState ? SOFTBUS_OK : SOFTBUS_PERMISSION_DENIED;
            }
        }
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

void PermissionStateChange(const char *pkgName, int32_t state)
{
    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list not init");
        return;
    }
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return;
    }
    ClientSessionServer *serverNode = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if ((strcmp(serverNode->pkgName, pkgName) == 0)) {
            serverNode->permissionState = state > 0 ? true : false;
            TRANS_LOGI(TRANS_SDK, "permission change, pkgName=%{public}s, state=%{public}d", pkgName, state);
            break;
        }
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
}

int TransClientInit(void)
{
    g_clientSessionServerList = CreateSoftBusList();
    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "init entry list failed");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (TransServerProxyInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "init trans ipc proxy failed");
        return SOFTBUS_TRANS_SERVER_INIT_FAILED;
    }

    if (ClientTransChannelInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "init trans channel failed");
        return SOFTBUS_TRANS_SERVER_INIT_FAILED;
    }

    if (RegisterTimeoutCallback(SOFTBUS_TRNAS_IDLE_TIMEOUT_TIMER_FUN, ClientTransSessionTimerProc) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "init trans idle timer failed");
        return SOFTBUS_TRANS_SERVER_INIT_FAILED;
    }

    ClientTransRegLnnOffline();
    TRANS_LOGI(TRANS_INIT, "init trans client success");
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
    if (g_sessionIdNum >= g_closingNum && g_sessionIdNum - g_closingNum >= MAX_SESSION_ID) {
        TRANS_LOGE(TRANS_SDK, "sessionid num cross the line error");
        return INVALID_SESSION_ID;
    }
    int32_t cnt = MAX_SESSION_ID + g_closingNum + 1;
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
    TRANS_LOGE(TRANS_SDK, "generate id error");
    return id;
}

static void DestroySessionId(void)
{
    if (g_sessionIdNum > 0) {
        g_sessionIdNum--;
    }
    if (g_closingNum > 0) {
        g_closingNum--;
    }
    return;
}

NO_SANITIZE("cfi") static DestroySessionInfo *CreateDestroySessionNode(SessionInfo *sessionNode,
    const ClientSessionServer *server)
{
    DestroySessionInfo *destroyNode = (DestroySessionInfo *)SoftBusMalloc(sizeof(DestroySessionInfo));
    if (destroyNode == NULL) {
        TRANS_LOGE(TRANS_SDK, "destroyList malloc fail.");
        return NULL;
    }
    destroyNode->sessionId = sessionNode->sessionId;
    destroyNode->channelId = sessionNode->channelId;
    destroyNode->channelType = sessionNode->channelType;
    if (memcpy_s(destroyNode->sessionName, SESSION_NAME_SIZE_MAX, server->sessionName, SESSION_NAME_SIZE_MAX) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy_s sessionName fail.");
        return NULL;
    }
    destroyNode->OnSessionClosed = server->listener.session.OnSessionClosed;
    destroyNode->OnShutdown = sessionNode->isServer ? server->listener.socketServer.OnShutdown :
        server->listener.socketClient.OnShutdown;
    return destroyNode;
}

static int32_t TryDeleteEmptySessionServer(const char *sessionName)
{
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    ClientSessionServer *serverNode = NULL;
    ClientSessionServer *serverNodeNext = NULL;
    ListNode destroyList;
    ListInit(&destroyList);
    LIST_FOR_EACH_ENTRY_SAFE(
        serverNode, serverNodeNext, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (strcmp(serverNode->sessionName, sessionName) == 0 && IsListEmpty(&serverNode->sessionList)) {
            ListDelete(&(serverNode->node));
            SoftBusFree(serverNode);
            g_clientSessionServerList->cnt--;
            (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
            TRANS_LOGI(TRANS_SDK, "delete empty session server, sessionName=%{public}s", tmpName);
            AnonymizeFree(tmpName);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    TRANS_LOGE(TRANS_SDK, "not found session server or session list is not empty, sessionName=%{public}s", tmpName);
    AnonymizeFree(tmpName);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

NO_SANITIZE("cfi") static void ClientDestroySession(const ListNode *destroyList, ShutdownReason reason)
{
    if (IsListEmpty(destroyList)) {
        TRANS_LOGD(TRANS_SDK, "destroyList is empty fail.");
        return;
    }
    DestroySessionInfo *destroyNode = NULL;
    DestroySessionInfo *destroyNodeNext = NULL;
    TRANS_LOGD(TRANS_SDK, "enter.");
    LIST_FOR_EACH_ENTRY_SAFE(destroyNode, destroyNodeNext, destroyList, DestroySessionInfo, node) {
        int32_t id = destroyNode->sessionId;
        (void)ClientDeleteRecvFileList(id);
        (void)ClientTransCloseChannel(destroyNode->channelId, destroyNode->channelType);
        if (destroyNode->OnSessionClosed != NULL) {
            destroyNode->OnSessionClosed(id);
        } else if (destroyNode->OnShutdown != NULL) {
            destroyNode->OnShutdown(id, reason);
            (void)TryDeleteEmptySessionServer(destroyNode->sessionName);
        }
        ListDelete(&(destroyNode->node));
        SoftBusFree(destroyNode);
    }
    TRANS_LOGD(TRANS_SDK, "ok");
}

static void DestroyClientSessionServer(ClientSessionServer *server, ListNode *destroyList)
{
    if (server == NULL) {
        TRANS_LOGW(TRANS_SDK, "invalid param");
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
    char *tmpName = NULL;
    Anonymize(server->sessionName, &tmpName);
    TRANS_LOGI(TRANS_SDK, "destroy session server sessionName=%{public}s", tmpName);
    AnonymizeFree(tmpName);
    SoftBusFree(server);
}

void TransClientDeinit(void)
{
    if (g_clientSessionServerList == NULL) {
        return;
    }
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
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
    ClientDestroySession(&destroyList, SHUTDOWN_REASON_LOCAL);

    DestroySoftBusList(g_clientSessionServerList);
    g_clientSessionServerList = NULL;
    ClientTransChannelDeinit();
    TransServerProxyDeInit();
    (void)RegisterTimeoutCallback(SOFTBUS_TRNAS_IDLE_TIMEOUT_TIMER_FUN, NULL);
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
    server->listener.isSocketListener = false;
    server->isSrvEncryptedRawStream = false;

    ListInit(&server->node);
    ListInit(&server->sessionList);
    return server;
EXIT_ERR:
    if (server != NULL) {
        SoftBusFree(server);
    }
    return NULL;
}

static void ShowClientSessionServer(void)
{
    ClientSessionServer *pos = NULL;
    ClientSessionServer *tmp = NULL;
    int count = 0;
    char *tmpName = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(pos, tmp, &g_clientSessionServerList->list, ClientSessionServer, node) {
        Anonymize(pos->sessionName, &tmpName);
        TRANS_LOGE(TRANS_SDK,
            "client session server is exist. count=%{public}d, sessionName=%{public}s", count, tmpName);
        AnonymizeFree(tmpName);
        count++;
    }
}

int32_t ClientAddSessionServer(SoftBusSecType type, const char *pkgName, const char *sessionName,
    const ISessionListener *listener)
{
    if (pkgName == NULL || sessionName == NULL || listener == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (SessionServerIsExist(sessionName)) {
        (void)SoftBusMutexUnlock(&g_clientSessionServerList->lock);
        return SOFTBUS_SERVER_NAME_REPEATED;
    }

    if (g_clientSessionServerList->cnt >= MAX_SESSION_SERVER_NUMBER) {
        (void)ShowClientSessionServer();
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "ClientAddSessionServer: client server num reach max");
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
    char *tmpName = NULL;
    Anonymize(server->sessionName, &tmpName);
    TRANS_LOGI(TRANS_SDK, "sessionName=%{public}s, pkgName=%{public}s", tmpName, server->pkgName);
    AnonymizeFree(tmpName);
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
        TRANS_LOGE(TRANS_SDK, "calloc failed");
        return NULL;
    }

    if (strcpy_s(session->info.peerSessionName, SESSION_NAME_SIZE_MAX, param->peerSessionName) != EOK ||
        strcpy_s(session->info.peerDeviceId, DEVICE_ID_SIZE_MAX, param->peerDeviceId) != EOK ||
        strcpy_s(session->info.groupId, GROUP_ID_SIZE_MAX, param->groupId) != EOK ||
        memcpy_s(session->linkType, sizeof(param->attr->linkType), param->attr->linkType,
            sizeof(param->attr->linkType)) != EOK) {
        TRANS_LOGE(TRANS_SDK, "strcpy failed");
        SoftBusFree(session);
        return NULL;
    }

    session->sessionId = INVALID_SESSION_ID;
    session->channelId = INVALID_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_BUTT;
    session->isServer = false;
    session->role = SESSION_ROLE_INIT;
    session->enableStatus = ENABLE_STATUS_INIT;
    session->info.flag = param->attr->dataType;
    session->isEncrypt = true;
    session->isAsync = false;
    session->lifecycle.sessionState = SESSION_STATE_INIT;
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
            if (sessionNode->isServer || (strcmp(sessionNode->info.peerSessionName, param->peerSessionName) != 0) ||
                (strcmp(sessionNode->info.peerDeviceId, param->peerDeviceId) != 0) ||
                (strcmp(sessionNode->info.groupId, param->groupId) != 0) ||
                (memcmp(sessionNode->linkType, param->attr->linkType, sizeof(param->attr->linkType)) != 0) ||
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
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
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
        TRANS_LOGI(TRANS_SDK, "add sessionId=%{public}d", session->sessionId);
        return SOFTBUS_OK;
    }
    DestroySessionId();
    return SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED;
}

int32_t ClientAddNewSession(const char *sessionName, SessionInfo *session)
{
    if (session == NULL) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    int32_t ret = AddSession(sessionName, session);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "add session failed, ret=%{public}d", ret);
        return ret;
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

int32_t ClientAddSession(const SessionParam *param, int32_t *sessionId, SessionEnableStatus *isEnabled)
{
    if (!IsValidSessionParam(param) || (sessionId == NULL) || (isEnabled == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    SessionInfo *session = GetExistSession(param);
    if (session != NULL) {
        *sessionId = session->sessionId;
        *isEnabled = session->enableStatus;
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        return SOFTBUS_TRANS_SESSION_REPEATED;
    }

    session = CreateNewSession(param);
    if (session == NULL) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "create session failed");
        return SOFTBUS_TRANS_SESSION_CREATE_FAILED;
    }

    int32_t ret = AddSession(param->sessionName, session);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(session);
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "Add Session failed, ret=%{public}d", ret);
        return ret;
    }

    *sessionId = session->sessionId;
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

static SessionInfo *CreateNonEncryptSessionInfo(const char *sessionName)
{
    if (!IsValidString(sessionName, SESSION_NAME_SIZE_MAX - 1)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
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
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    SessionInfo *session = CreateNonEncryptSessionInfo(sessionName);
    if (session == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = ClientAddNewSession(sessionName, session);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(session);
        TRANS_LOGE(TRANS_SDK, "client add new session failed, ret=%{public}d.", ret);
        return ret;
    }
    *sessionId = session->sessionId;
    return SOFTBUS_OK;
}

int32_t ClientDeleteSessionServer(SoftBusSecType type, const char *sessionName)
{
    if ((type == SEC_TYPE_UNKNOWN) || (sessionName == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
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
    (void)ClientDestroySession(&destroyList, SHUTDOWN_REASON_LOCAL);
    return SOFTBUS_OK;
}

int32_t ClientDeleteSession(int32_t sessionId)
{
    TRANS_LOGI(TRANS_SDK, "sessionId=%{public}d", sessionId);
    if (sessionId < 0) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
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
            TRANS_LOGI(TRANS_SDK, "delete session by sessionId=%{public}d success", sessionId);
            DestroySessionId();
            SoftBusFree(sessionNode);
            (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    TRANS_LOGE(TRANS_SDK, "not found session by sessionId=%{public}d", sessionId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientGetSessionDataById(int32_t sessionId, char *data, uint16_t len, SessionKey key)
{
    if ((sessionId < 0) || (data == NULL) || (len == 0)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }
    int32_t ret = EOK;
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
        TRANS_LOGE(TRANS_SDK, "strcpy_s data info failed, ret=%{public}d", ret);
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientGetSessionIntegerDataById(int32_t sessionId, int *data, SessionKey key)
{
    if ((sessionId < 0) || (data == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    int32_t ret = GetSessionById(sessionId, &serverNode, &sessionNode);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
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
        TRANS_LOGE(TRANS_SDK, "copy data failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientGetChannelBySessionId(int32_t sessionId, int32_t *channelId,
                                    int32_t *type, SessionEnableStatus *enableStatus)
{
    if (sessionId < 0) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list  not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    if (channelId != NULL) {
        *channelId = sessionNode->channelId;
    }
    if (type != NULL) {
        *type = sessionNode->channelType;
    }
    if (enableStatus != NULL) {
        *enableStatus = sessionNode->enableStatus;
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

int32_t ClientSetEnableStatusBySocket(int32_t socket, SessionEnableStatus enableStatus)
{
    if (socket < 0) {
        TRANS_LOGE(TRANS_INIT, "invalid socket=%{public}d", socket);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list  not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "socket not found. socket=%{public}d", socket);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    sessionNode->enableStatus = enableStatus;
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

int32_t ClientGetChannelBusinessTypeBySessionId(int32_t sessionId, int32_t *businessType)
{
    if ((sessionId < 0) || (businessType == NULL)) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list  not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    *businessType = sessionNode->businessType;

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

int32_t ClientSetChannelBySessionId(int32_t sessionId, TransInfo *transInfo)
{
    if ((sessionId < 0) || (transInfo->channelId < 0)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list  not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }
    sessionNode->channelId = transInfo->channelId;
    sessionNode->channelType = (ChannelType)transInfo->channelType;

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

int32_t GetEncryptByChannelId(int32_t channelId, int32_t channelType, int32_t *data)
{
    if ((channelId < 0) || (data == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list  not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
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
    TRANS_LOGE(TRANS_SDK, "not found session by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientGetSessionIdByChannelId(int32_t channelId, int32_t channelType, int32_t *sessionId)
{
    if ((channelId < 0) || (sessionId == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list  not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
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
    TRANS_LOGE(TRANS_SDK, "not found session by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientGetSessionIsAsyncBySessionId(int32_t sessionId, bool *isAsync)
{
    if ((sessionId < 0) || (isAsync == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list  not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }

        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->sessionId == sessionId) {
                *isAsync = sessionNode->isAsync;
                (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
                return SOFTBUS_OK;
            }
        }
    }

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    TRANS_LOGE(TRANS_SDK, "not found session with sessionId=%{public}d", sessionId);
    return SOFTBUS_ERR;
}

int32_t ClientGetRouteTypeByChannelId(int32_t channelId, int32_t channelType, int32_t *routeType)
{
    if ((channelId < 0) || (routeType == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list  not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }

        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->channelId == channelId && sessionNode->channelType == (ChannelType)channelType) {
                *routeType = sessionNode->routeType;
                (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
                return SOFTBUS_OK;
            }
        }
    }

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    TRANS_LOGE(TRANS_SDK, "not found session by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientGetDataConfigByChannelId(int32_t channelId, int32_t channelType, uint32_t *dataConfig)
{
    if ((channelId < 0) || (dataConfig == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list  not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }

        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->channelId == channelId && sessionNode->channelType == (ChannelType)channelType) {
                *dataConfig = sessionNode->dataConfig;
                (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
                return SOFTBUS_OK;
            }
        }
    }

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    TRANS_LOGE(TRANS_SDK, "not found session by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientEnableSessionByChannelId(const ChannelInfo *channel, int32_t *sessionId)
{
    if ((channel == NULL) || (sessionId == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list  not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
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
                sessionNode->enableStatus = ENABLE_STATUS_SUCCESS;
                sessionNode->routeType = channel->routeType;
                sessionNode->businessType = channel->businessType;
                sessionNode->fileEncrypt = channel->fileEncrypt;
                sessionNode->dataConfig = channel->dataConfig;
                sessionNode->algorithm = channel->algorithm;
                sessionNode->crc = channel->crc;
                sessionNode->isEncrypt = channel->isEncrypt;
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
    TRANS_LOGE(TRANS_SDK, "not found session by channelId=%{public}d, channelType=%{public}d",
        channel->channelId, channel->channelType);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientGetSessionCallbackById(int32_t sessionId, ISessionListener *callback)
{
    if (sessionId < 0 || callback == NULL) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list  not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    int32_t ret = memcpy_s(callback, sizeof(ISessionListener), &serverNode->listener.session, sizeof(ISessionListener));

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    if (ret != EOK) {
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientGetSessionCallbackByName(const char *sessionName, ISessionListener *callback)
{
    if (sessionName == NULL || callback == NULL) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list  not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    ClientSessionServer *serverNode = NULL;

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
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
            return SOFTBUS_MEM_ERR;
        }
        return SOFTBUS_OK;
    }

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGE(TRANS_SDK, "not found session by sessionName=%{public}s", tmpName);
    AnonymizeFree(tmpName);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientGetSessionSide(int32_t sessionId)
{
    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list  not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    int32_t side = -1;
    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
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

static int32_t ClientTransGetTdcIp(int32_t channelId, char *myIp, int32_t ipLen)
{
    TcpDirectChannelInfo channel;
    if (TransTdcGetInfoById(channelId, &channel) == NULL) {
        TRANS_LOGE(TRANS_SDK, "not found Tdc channel by channelId=%{public}d", channelId);
        return SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND;
    }

    if (strcpy_s(myIp, ipLen, channel.detail.myIp) != EOK) {
        TRANS_LOGE(TRANS_SDK, "strcpy_s ip failed, len=%{public}zu", strlen(channel.detail.myIp));
        return SOFTBUS_STRCPY_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t ClientTransGetUdpIp(int32_t channelId, char *myIp, int32_t ipLen)
{
    UdpChannel channel;
    if (TransGetUdpChannel(channelId, &channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "not found Udp channel by channelId=%{public}d", channelId);
        return SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND;
    }

    if (strcpy_s(myIp, ipLen, channel.info.myIp) != EOK) {
        TRANS_LOGE(TRANS_SDK, "strcpy_s ip failed, len=%{public}zu", strlen(channel.info.myIp));
        return SOFTBUS_STRCPY_ERR;
    }

    return SOFTBUS_OK;
}

// determine connection type based on IP
static bool ClientTransCheckHmlIp(const char *ip)
{
    if (strncmp(ip, HML_IP_PREFIX, NETWORK_ID_LEN) == 0) {
        return true;
    }

    return false;
}

// determine connection type based on IP, delete session when connection type and parameter connType are consistent
static bool ClientTransCheckNeedDel(SessionInfo *sessionNode, int32_t routeType, int32_t connType)
{
    if (connType == TRANS_CONN_ALL) {
        if (routeType != ROUTE_TYPE_ALL && sessionNode->routeType != routeType) {
            return false;
        }
        return true;
    }
    /*
    * only when the function OnWifiDirectDeviceOffLine is called can reach this else branch,
    * and routeType is WIFI_P2P, the connType is hml or p2p
    */
    if (sessionNode->routeType != routeType) {
        return false;
    }

    char myIp[IP_LEN] = {0};
    if (sessionNode->channelType == CHANNEL_TYPE_UDP) {
        if (ClientTransGetUdpIp(sessionNode->channelId, myIp, sizeof(myIp)) != SOFTBUS_OK) {
            return false;
        }
    } else if (sessionNode->channelType == CHANNEL_TYPE_TCP_DIRECT) {
        if (ClientTransGetTdcIp(sessionNode->channelId, myIp, sizeof(myIp)) != SOFTBUS_OK) {
            return false;
        }
    } else {
        TRANS_LOGW(TRANS_SDK, "check channelType=%{public}d", sessionNode->channelType);
        return false;
    }

    bool isHml = ClientTransCheckHmlIp(myIp);
    if (connType == TRANS_CONN_HML && isHml) {
        return true;
    } else if (connType == TRANS_CONN_P2P && !isHml) {
        return true;
    }

    return false;
}

static void DestroyClientSessionByNetworkId(const ClientSessionServer *server,
    const char *networkId, int32_t type, ListNode *destroyList)
{
    SessionInfo *sessionNode = NULL;
    SessionInfo *sessionNodeNext = NULL;
    // connType is set only in function OnWifiDirectDeviceOffLine, others is TRANS_CONN_ALL, and routeType is WIFI_P2P
    int32_t routeType = GET_ROUTE_TYPE(type);
    int32_t connType = GET_CONN_TYPE(type);

    LIST_FOR_EACH_ENTRY_SAFE(sessionNode, sessionNodeNext, &(server->sessionList), SessionInfo, node) {
        if (strcmp(sessionNode->info.peerDeviceId, networkId) != 0) {
            continue;
        }

        if (!ClientTransCheckNeedDel(sessionNode, routeType, connType)) {
            continue;
        }

        TRANS_LOGI(TRANS_SDK, "channelId=%{public}d, channelType=%{public}d, routeType=%{public}d, type=%{public}d",
            sessionNode->channelId, sessionNode->channelType, sessionNode->routeType, type);
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
    TRANS_LOGD(TRANS_SDK, "device offline callback enter.");
    if (info == NULL) {
        return;
    }
    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list  not init");
        return;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return;
    }

    ClientSessionServer *serverNode = NULL;
    ListNode destroyList;
    ListInit(&destroyList);
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        DestroyClientSessionByNetworkId(serverNode, info->networkId, ROUTE_TYPE_ALL, &destroyList);
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    (void)ClientDestroySession(&destroyList, SHUTDOWN_REASON_LNN_OFFLINE);
    return;
}

static INodeStateCb g_transLnnCb = {
    .events = EVENT_NODE_STATE_OFFLINE,
    .onNodeOffline = ClientTransLnnOfflineProc,
};

int32_t ReCreateSessionServerToServer(ListNode *sessionServerInfoList)
{
    TRANS_LOGD(TRANS_SDK, "enter.");
    if (sessionServerInfoList == NULL) {
        TRANS_LOGE(TRANS_INIT, "session server list not init");
        return SOFTBUS_INVALID_PARAM;
    }

    SessionServerInfo *infoNode = NULL;
    SessionServerInfo *infoNodeNext = NULL;
    char *tmpName = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(infoNode, infoNodeNext, sessionServerInfoList, SessionServerInfo, node) {
        int32_t ret = ServerIpcCreateSessionServer(infoNode->pkgName, infoNode->sessionName);
        Anonymize(infoNode->sessionName, &tmpName);
        TRANS_LOGI(TRANS_SDK, "sessionName=%{public}s, pkgName=%{public}s, ret=%{public}d",
            tmpName, infoNode->pkgName, ret);
        AnonymizeFree(tmpName);
        ListDelete(&infoNode->node);
        SoftBusFree(infoNode);
    }

    TRANS_LOGI(TRANS_SDK, "ok");
    return SOFTBUS_OK;
}

void ClientTransRegLnnOffline(void)
{
    int32_t ret;
    ret = RegNodeDeviceStateCbInner("trans", &g_transLnnCb);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "reg lnn offline fail");
    }
}

void ClientTransOnLinkDown(const char *networkId, int32_t routeType)
{
    if (networkId == NULL || g_clientSessionServerList == NULL) {
        return;
    }
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    TRANS_LOGD(TRANS_SDK, "routeType=%{public}d, networkId=%{public}s", routeType, anonyNetworkId);
    AnonymizeFree(anonyNetworkId);

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return;
    }
    ClientSessionServer *serverNode = NULL;
    ListNode destroyList;
    ListInit(&destroyList);
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        DestroyClientSessionByNetworkId(serverNode, networkId, routeType, &destroyList);
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    (void)ClientDestroySession(&destroyList, SHUTDOWN_REASON_LINK_DOWN);
    return;
}

int32_t ClientGrantPermission(int uid, int pid, const char *busName)
{
    if (uid < 0 || pid < 0 || busName == NULL) {
        TRANS_LOGW(TRANS_SDK, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    char *tmpName = NULL;
    Anonymize(busName, &tmpName);
    TRANS_LOGI(TRANS_SDK, "sessionName=%{public}s", tmpName);
    AnonymizeFree(tmpName);
    int32_t ret = ServerIpcGrantPermission(uid, pid, busName);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "server grant permission failed, ret=%{public}d", ret);
    }
    return ret;
}

int32_t ClientRemovePermission(const char *busName)
{
    if (busName == NULL) {
        TRANS_LOGW(TRANS_SDK, "invalid parameter");
        return SOFTBUS_INVALID_PARAM;
    }
    char *tmpName = NULL;
    Anonymize(busName, &tmpName);
    TRANS_LOGI(TRANS_SDK, "sessionName=%{public}s", tmpName);
    AnonymizeFree(tmpName);
    int32_t ret = ServerIpcRemovePermission(busName);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "server remove permission failed, ret=%{public}d", ret);
    }
    return ret;
}

int32_t ClientGetFileConfigInfoById(int32_t sessionId, int32_t *fileEncrypt, int32_t *algorithm, int32_t *crc)
{
    if (sessionId < 0 || fileEncrypt == NULL || algorithm == NULL || crc == NULL) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "session server list not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }
    *fileEncrypt = sessionNode->fileEncrypt;
    *algorithm = sessionNode->algorithm;
    *crc = sessionNode->crc;
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

static SessionServerInfo *CreateSessionServerInfoNode(const ClientSessionServer *clientSessionServer)
{
    if (clientSessionServer == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param.");
        return NULL;
    }

    SessionServerInfo *infoNode = (SessionServerInfo *)SoftBusCalloc(sizeof(SessionServerInfo));
    if (infoNode == NULL) {
        TRANS_LOGE(TRANS_SDK, "failed to malloc SessionServerInfo.");
        return NULL;
    }

    if (strcpy_s(infoNode->pkgName, SESSION_NAME_SIZE_MAX, clientSessionServer->pkgName) != EOK) {
        SoftBusFree(infoNode);
        TRANS_LOGE(TRANS_SDK, "failed to strcpy pkgName.");
        return NULL;
    }

    if (strcpy_s(infoNode->sessionName, SESSION_NAME_SIZE_MAX, clientSessionServer->sessionName) != EOK) {
        SoftBusFree(infoNode);
        TRANS_LOGE(TRANS_SDK, "failed to strcpy sessionName.");
        return NULL;
    }

    return infoNode;
}

void ClientCleanAllSessionWhenServerDeath(ListNode *sessionServerInfoList)
{
    if (sessionServerInfoList == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param.");
        return;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_SDK, "client session server list not init.");
        return;
    }
    uint32_t destroyCnt = 0;
    ListNode destroyList;
    ListInit(&destroyList);
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "client get session server list lock failed.");
        return;
    }
    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    SessionInfo *nextSessionNode = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        SessionServerInfo *info = CreateSessionServerInfoNode(serverNode);
        if (info != NULL) {
            ListAdd(sessionServerInfoList, &info->node);
        }
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }
        LIST_FOR_EACH_ENTRY_SAFE(sessionNode, nextSessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->role == SESSION_ROLE_SERVER) {
                TRANS_LOGD(TRANS_SDK, "cannot delete socket for listening, socket=%{public}d", sessionNode->sessionId);
                continue;
            }
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
    (void)ClientDestroySession(&destroyList, SHUTDOWN_REASON_SERVICE_DIED);
    TRANS_LOGI(TRANS_SDK, "client destroy session cnt=%{public}d.", destroyCnt);
}

static ClientSessionServer *GetNewSocketServer(SoftBusSecType type, const char *sessionName, const char *pkgName)
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
    server->isSrvEncryptedRawStream = false;
    ListInit(&server->node);
    ListInit(&server->sessionList);
    return server;
EXIT_ERR:
    if (server != NULL) {
        SoftBusFree(server);
    }
    return NULL;
}

int32_t ClientAddSocketServer(SoftBusSecType type, const char *pkgName, const char *sessionName)
{
    if (pkgName == NULL || sessionName == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_SDK, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (SessionServerIsExist(sessionName)) {
        (void)SoftBusMutexUnlock(&g_clientSessionServerList->lock);
        return SOFTBUS_SERVER_NAME_REPEATED;
    }

    if (g_clientSessionServerList->cnt >= MAX_SESSION_SERVER_NUMBER) {
        (void)ShowClientSessionServer();
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "ClientAddSocketServer: client server num reach max");
        return SOFTBUS_INVALID_NUM;
    }

    ClientSessionServer *server = GetNewSocketServer(type, sessionName, pkgName);
    if (server == NULL) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        return SOFTBUS_MEM_ERR;
    }
    server->permissionState = true;
    ListAdd(&g_clientSessionServerList->list, &server->node);
    g_clientSessionServerList->cnt++;

    (void)SoftBusMutexUnlock(&g_clientSessionServerList->lock);
    TRANS_LOGE(TRANS_SDK, "sessionName=%{public}s, pkgName=%{public}s", server->sessionName, server->pkgName);
    return SOFTBUS_OK;
}

static int32_t DeleteSocketSession(int32_t sessionId, char *pkgName, char *sessionName)
{
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    if (strcpy_s(pkgName, PKG_NAME_SIZE_MAX, serverNode->pkgName) != EOK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "strcpy pkgName failed");
        return SOFTBUS_STRCPY_ERR;
    }

    if (strcpy_s(sessionName, SESSION_NAME_SIZE_MAX, serverNode->sessionName) != EOK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "strcpy sessionName failed");
        return SOFTBUS_STRCPY_ERR;
    }
    (void)SoftBusCondDestroy(&sessionNode->lifecycle.callbackCond);
    ListDelete(&(sessionNode->node));
    TRANS_LOGI(TRANS_SDK, "delete session, sessionId=%{public}d", sessionId);
    DestroySessionId();
    SoftBusFree(sessionNode);
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

int32_t ClientDeleteSocketSession(int32_t sessionId)
{
    if (sessionId <= 0) {
        TRANS_LOGE(TRANS_SDK, "Invalid sessionId=%{public}d", sessionId);
        return SOFTBUS_INVALID_PARAM;
    }

    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    char sessionName[SESSION_NAME_SIZE_MAX] = { 0 };
    int32_t ret = DeleteSocketSession(sessionId, pkgName, sessionName);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "failed delete session");
        return ret;
    }

    ret = TryDeleteEmptySessionServer(sessionName);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "delete empty session server failed, ret=%{public}d", ret);
        return ret;
    }

    // calling the ipc interface by locking here may block other threads for a long time
    ret = ServerIpcRemoveSessionServer(pkgName, sessionName);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "remove session server failed, ret=%{public}d", ret);
        return ret;
    }

    return SOFTBUS_OK;
}

static bool IsDistributedDataSession(const char *sessionName)
{
    uint32_t distributedDataSessionLen = strlen(DISTRIBUTED_DATA_SESSION);
    if (strlen(sessionName) < distributedDataSessionLen ||
        strncmp(sessionName, DISTRIBUTED_DATA_SESSION, distributedDataSessionLen) != 0) {
        return false;
    }
    return true;
}

static bool IsDifferentDataType(const SessionInfo *sessionInfo, int dataType, bool isEncyptedRawStream)
{
    if (sessionInfo->info.flag != dataType) {
        return true;
    }

    if (dataType != RAW_STREAM) {
        return false;
    }

    return sessionInfo->isEncyptedRawStream != isEncyptedRawStream;
}

static SessionInfo *GetSocketExistSession(const SessionParam *param, bool isEncyptedRawStream)
{
    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionInfo = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        // distributeddata module can create different socket of whether the SocketInfo is same or not
        if ((strcmp(serverNode->sessionName, param->sessionName) != 0) || IsListEmpty(&serverNode->sessionList) ||
            IsDistributedDataSession(param->sessionName)) {
            continue;
        }
        LIST_FOR_EACH_ENTRY(sessionInfo, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionInfo->isServer || (strcmp(sessionInfo->info.peerSessionName, param->peerSessionName) != 0) ||
                (strcmp(sessionInfo->info.peerDeviceId, param->peerDeviceId) != 0) ||
                (strcmp(sessionInfo->info.groupId, param->groupId) != 0) ||
                IsDifferentDataType(sessionInfo, param->attr->dataType, isEncyptedRawStream)) {
                continue;
            }
            return sessionInfo;
        }
    }
    return NULL;
}

static void ClientInitSession(SessionInfo *session, const SessionParam *param)
{
    session->sessionId = INVALID_SESSION_ID;
    session->channelId = INVALID_CHANNEL_ID;
    session->channelType = CHANNEL_TYPE_BUTT;
    session->isServer = false;
    session->role = SESSION_ROLE_INIT;
    session->enableStatus = ENABLE_STATUS_INIT;
    session->info.flag = param->attr->dataType;
    session->info.streamType = param->attr->attr.streamAttr.streamType;
    session->isEncrypt = true;
    session->isAsync = false;
    session->lifecycle.sessionState = SESSION_STATE_INIT;
}

static SessionInfo *CreateNewSocketSession(const SessionParam *param)
{
    SessionInfo *session = (SessionInfo *)SoftBusCalloc(sizeof(SessionInfo));
    if (session == NULL) {
        TRANS_LOGE(TRANS_SDK, "calloc failed");
        return NULL;
    }

    if (param->peerSessionName != NULL &&
        strcpy_s(session->info.peerSessionName, SESSION_NAME_SIZE_MAX, param->peerSessionName) != EOK) {
        char *anonySessionName = NULL;
        Anonymize(param->peerSessionName, &anonySessionName);
        TRANS_LOGI(TRANS_SDK, "strcpy peerName failed, peerName=%{public}s, peerNameLen=%{public}zu",
            anonySessionName, strlen(param->peerSessionName));
        AnonymizeFree(anonySessionName);
        SoftBusFree(session);
        return NULL;
    }

    if (param->peerDeviceId != NULL &&
        strcpy_s(session->info.peerDeviceId, DEVICE_ID_SIZE_MAX, param->peerDeviceId) != EOK) {
        char *anonyNetworkId = NULL;
        Anonymize(param->peerDeviceId, &anonyNetworkId);
        TRANS_LOGI(TRANS_SDK, "strcpy peerDeviceId failed, peerDeviceId=%{public}s, peerDeviceIdLen=%{public}zu",
            anonyNetworkId, strlen(param->peerDeviceId));
        AnonymizeFree(anonyNetworkId);
        SoftBusFree(session);
        return NULL;
    }

    if (strcpy_s(session->info.groupId, GROUP_ID_SIZE_MAX, param->groupId) != EOK ||
        memcpy_s(session->linkType, sizeof(param->attr->linkType), param->attr->linkType,
            sizeof(param->attr->linkType)) != EOK) {
        TRANS_LOGE(TRANS_SDK, "strcpy failed");
        SoftBusFree(session);
        return NULL;
    }

    if (SoftBusCondInit(&session->lifecycle.callbackCond) != SOFTBUS_OK) {
        SoftBusFree(session);
        TRANS_LOGE(TRANS_SDK, "callbackCond Init failed");
        return NULL;
    }

    ClientInitSession(session, param);
    return session;
}

int32_t ClientAddSocketSession(
    const SessionParam *param, bool isEncyptedRawStream, int32_t *sessionId, SessionEnableStatus *isEnabled)
{
    if (param == NULL || param->sessionName == NULL || param->groupId == NULL || param->attr == NULL ||
        sessionId == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_SDK, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    SessionInfo *session = GetSocketExistSession(param, isEncyptedRawStream);
    if (session != NULL) {
        *sessionId = session->sessionId;
        *isEnabled = session->enableStatus;
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        return SOFTBUS_TRANS_SESSION_REPEATED;
    }

    session = CreateNewSocketSession(param);
    if (session == NULL) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "create session failed");
        return SOFTBUS_TRANS_SESSION_CREATE_FAILED;
    }
    session->isEncyptedRawStream = isEncyptedRawStream;
    int32_t ret = AddSession(param->sessionName, session);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(session);
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "Add Session failed, ret=%{public}d", ret);
        return ret;
    }

    *sessionId = session->sessionId;
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

int32_t ClientSetListenerBySessionId(int32_t sessionId, const ISocketListener *listener, bool isServer)
{
    if ((sessionId < 0) || listener == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_SDK, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    if (sessionNode->role != SESSION_ROLE_INIT) {
        TRANS_LOGE(TRANS_SDK, "socket in use, currentRole=%{public}d", sessionNode->role);
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        return SOFTBUS_TRANS_SOCKET_IN_USE;
    }
    ISocketListener *socketListener = isServer ? &(serverNode->listener.socketServer) :
        &(serverNode->listener.socketClient);
    int32_t ret = memcpy_s(socketListener, sizeof(ISocketListener), listener, sizeof(ISocketListener));
    if (ret != EOK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "memcpy_s socketListener failed, ret=%{public}d", ret);
        return SOFTBUS_MEM_ERR;
    }
    serverNode->listener.isSocketListener = true;
    if (socketListener->OnFile == NULL) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        return SOFTBUS_OK;
    }
    ret = TransSetSocketFileListener(serverNode->sessionName, socketListener->OnFile, isServer);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "register socket file listener failed");
        return ret;
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

static int32_t CheckBindSocketInfo(const SessionInfo *session)
{
    if (!IsValidString(session->info.peerSessionName, SESSION_NAME_SIZE_MAX - 1) ||
        !IsValidString(session->info.peerDeviceId, DEVICE_ID_SIZE_MAX - 1)) {
        char *anonySessionName = NULL;
        char *anonyNetworkId = NULL;
        Anonymize(session->info.peerSessionName, &anonySessionName);
        Anonymize(session->info.peerDeviceId, &anonyNetworkId);
        TRANS_LOGI(TRANS_SDK, "invalid peerName=%{public}s, peerNameLen=%{public}zu, peerNetworkId=%{public}s, "
                              "peerNetworkIdLen=%{public}zu", anonySessionName,
            strlen(session->info.peerSessionName), anonyNetworkId, strlen(session->info.peerDeviceId));
        AnonymizeFree(anonyNetworkId);
        AnonymizeFree(anonySessionName);
        return SOFTBUS_INVALID_PARAM;
    }

    if (session->info.flag < TYPE_MESSAGE || session->info.flag >= TYPE_BUTT) {
        TRANS_LOGE(TRANS_SDK, "invalid dataType");
        return SOFTBUS_INVALID_PARAM;
    }

    return SOFTBUS_OK;
}

static void FillSessionParam(SessionParam *param, SessionAttribute *tmpAttr,
    ClientSessionServer *serverNode, SessionInfo *sessionNode)
{
    tmpAttr->fastTransData = NULL;
    tmpAttr->fastTransDataSize = 0;
    tmpAttr->dataType = sessionNode->info.flag;
    tmpAttr->attr.streamAttr.streamType = sessionNode->info.streamType;
    tmpAttr->linkTypeNum = 0;
    param->sessionName = serverNode->sessionName;
    param->peerSessionName = sessionNode->info.peerSessionName;
    param->peerDeviceId = sessionNode->info.peerDeviceId;
    param->groupId = "reserved";
    param->attr = tmpAttr;
    param->isQosLane = true;
}

static void ClientConvertRetVal(int32_t socket, int32_t *retOut)
{
    SocketLifecycleData lifecycle;
    (void)memset_s(&lifecycle, sizeof(SocketLifecycleData), 0, sizeof(SocketLifecycleData));
    int32_t ret = GetSocketLifecycleAndSessionNameBySessionId(socket, NULL, &lifecycle);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get info fail, socket=%{public}d", socket);
        return;
    }

    if (lifecycle.bindErrCode == SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "bindErrCode is SOFTBUS_OK, socket=%{public}d", socket);
        return;
    }
    *retOut = lifecycle.bindErrCode;
}

int32_t ClientIpcOpenSession(int32_t sessionId, const QosTV *qos, uint32_t qosCount, TransInfo *transInfo, bool isAsync)
{
    if (sessionId < 0 || transInfo == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_SDK, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }
    int32_t ret = CheckBindSocketInfo(sessionNode);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "check socekt info failed, ret=%{public}d", ret);
        return ret;
    }

    SessionAttribute tmpAttr;
    (void)memset_s(&tmpAttr, sizeof(SessionAttribute), 0, sizeof(SessionAttribute));
    SessionParam param;
    FillSessionParam(&param, &tmpAttr, serverNode, sessionNode);
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));

    param.qosCount = qosCount;
    if (param.qosCount > 0 && memcpy_s(param.qos, sizeof(param.qos), qos, sizeof(QosTV) * qosCount) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy qos failed");
        return SOFTBUS_MEM_ERR;
    }
    param.isAsync = isAsync;
    param.sessionId = sessionId;
    ret = SetSessionStateBySessionId(param.sessionId, SESSION_STATE_OPENING, 0);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, TRANS_SDK, "set session state failed, maybe cancel, ret=%{public}d", ret);
    ret = ServerIpcOpenSession(&param, transInfo);
    if (ret != SOFTBUS_OK) {
        ClientConvertRetVal(sessionId, &ret);
        TRANS_LOGE(TRANS_SDK, "open session ipc err: ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ClientHandleBindWaitTimer(int32_t socket, uint32_t maxWaitTime, TimerAction action)
{
    if (socket <= 0) {
        TRANS_LOGE(TRANS_SDK, "Invalid socket=%{public}d", socket);
        return SOFTBUS_INVALID_PARAM;
    }

    if (action < TIMER_ACTION_START || action >= TIMER_ACTION_BUTT) {
        TRANS_LOGE(TRANS_SDK, "Invalid action=%{public}d", action);
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_SDK, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "socket not found. socket=%{public}d", socket);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }
    if (action == TIMER_ACTION_START) {
        bool binding = (sessionNode->lifecycle.maxWaitTime != 0);
        bool bindSuccess = (sessionNode->lifecycle.maxWaitTime == 0 &&
                            sessionNode->enableStatus == ENABLE_STATUS_SUCCESS);
        if (binding) {
            (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
            TRANS_LOGE(TRANS_SDK, "socket=%{public}d The socket is binding", socket);
            return SOFTBUS_TRANS_SOCKET_IN_USE;
        }
        if (bindSuccess) {
            (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
            TRANS_LOGW(TRANS_SDK, "socket=%{public}d The socket was bound successfully", socket);
            return SOFTBUS_OK;
        }
    }

    sessionNode->lifecycle.maxWaitTime = (action == TIMER_ACTION_START) ? maxWaitTime : 0;
    sessionNode->lifecycle.waitTime = 0;
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

int32_t ClientSetSocketState(int32_t socket, uint32_t maxIdleTimeout, SessionRole role)
{
    if (socket < 0) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_SDK, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "socket not found. socketFd=%{public}d", socket);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    sessionNode->role = role;
    if (sessionNode->role == SESSION_ROLE_CLIENT) {
        sessionNode->maxIdleTime = maxIdleTimeout;
    }
    if (sessionNode->role == SESSION_ROLE_SERVER) {
        serverNode->isSrvEncryptedRawStream = sessionNode->isEncyptedRawStream;
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

int32_t ClientGetSessionCallbackAdapterByName(const char *sessionName, SessionListenerAdapter *callbackAdapter)
{
    if (sessionName == NULL || callbackAdapter == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_SDK, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    ClientSessionServer *serverNode = NULL;

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (strcmp(serverNode->sessionName, sessionName) != 0) {
            continue;
        }

        int32_t ret = memcpy_s(callbackAdapter, sizeof(SessionListenerAdapter),
            &serverNode->listener, sizeof(SessionListenerAdapter));
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        if (ret != EOK) {
            TRANS_LOGE(TRANS_SDK,
                "memcpy SessionListenerAdapter failed, sessionName=%{public}s, ret=%{public}d", sessionName, ret);
            return SOFTBUS_MEM_ERR;
        }
        return SOFTBUS_OK;
    }

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    TRANS_LOGE(TRANS_SDK, "SessionCallbackAdapter not found, sessionName=%{public}s", sessionName);
    return SOFTBUS_ERR;
}

int32_t ClientGetSessionCallbackAdapterById(int32_t sessionId, SessionListenerAdapter *callbackAdapter, bool *isServer)
{
    if (sessionId < 0 || callbackAdapter == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_SDK, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    int32_t ret = memcpy_s(callbackAdapter, sizeof(SessionListenerAdapter), &serverNode->listener,
        sizeof(SessionListenerAdapter));
    *isServer = sessionNode->isServer;
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    if (ret != EOK) {
        TRANS_LOGE(TRANS_SDK,
            "memcpy SessionListenerAdapter failed, socket=%{public}d, ret=%{public}d", sessionId, ret);
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ClientGetPeerSocketInfoById(int32_t socket, PeerSocketInfo *peerSocketInfo)
{
    if (socket < 0 || peerSocketInfo == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_SDK, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "socket not found. socketFd=%{public}d", socket);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    peerSocketInfo->name = sessionNode->info.peerSessionName;
    peerSocketInfo->networkId = sessionNode->info.peerDeviceId;
    peerSocketInfo->pkgName = serverNode->pkgName;
    peerSocketInfo->dataType = (TransDataType)sessionNode->info.flag;
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

bool IsSessionExceedLimit(void)
{
    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return true;
    }
    if (g_sessionIdNum >= MAX_SESSION_ID) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "sessionId num exceed limit.");
        return true;
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return false;
}

static void ClientCleanUpIdleTimeoutSocket(const ListNode *destroyList)
{
    if (IsListEmpty(destroyList)) {
        TRANS_LOGD(TRANS_SDK, "destroyList is empty.");
        return;
    }
    DestroySessionInfo *destroyNode = NULL;
    DestroySessionInfo *destroyNodeNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(destroyNode, destroyNodeNext, destroyList, DestroySessionInfo, node) {
        int32_t id = destroyNode->sessionId;
        (void)ClientDeleteRecvFileList(id);
        (void)ClientTransCloseChannel(destroyNode->channelId, destroyNode->channelType);
        TRANS_LOGI(TRANS_SDK, "session is idle, sessionId=%{public}d", id);
        if (destroyNode->OnShutdown != NULL) {
            destroyNode->OnShutdown(id, SHUTDOWN_REASON_TIMEOUT);
            (void)TryDeleteEmptySessionServer(destroyNode->sessionName);
        }
        ListDelete(&(destroyNode->node));
        SoftBusFree(destroyNode);
    }
    TRANS_LOGD(TRANS_SDK, "ok");
}

static void ClientCheckWaitTimeOut(SessionInfo *sessionNode, int32_t waitOutSocket[], uint32_t capacity, uint32_t *num)
{
    if (sessionNode->enableStatus == ENABLE_STATUS_SUCCESS) {
        return;
    }

    sessionNode->lifecycle.waitTime += TIMER_TIMEOUT;
    if (sessionNode->lifecycle.maxWaitTime == 0 ||
        sessionNode->lifecycle.waitTime <= sessionNode->lifecycle.maxWaitTime) {
        TRANS_LOGD(TRANS_SDK, "no wait timeout, socket=%{public}d", sessionNode->sessionId);
        return;
    }

    TRANS_LOGW(TRANS_SDK, "bind time out socket=%{public}d", sessionNode->sessionId);
    // stop check time out
    sessionNode->lifecycle.maxWaitTime = 0;

    uint32_t tmpNum = *num;
    if (tmpNum + 1 > capacity) {
        TRANS_LOGE(TRANS_SDK, "socket num invalid tmpNum=%{public}u, capacity=%{public}u", tmpNum, capacity);
        return;
    }
    waitOutSocket[tmpNum] = sessionNode->sessionId;
    *num = tmpNum + 1;
}

static void ClientCleanUpWaitTimeoutSocket(int32_t waitOutSocket[], uint32_t waitOutNum)
{
    bool tmpIsServer = false;
    SessionListenerAdapter callback = { 0 };
    for (uint32_t i = 0; i < waitOutNum; ++i) {
        TRANS_LOGI(TRANS_SDK, "time out shutdown socket=%{public}d", waitOutSocket[i]);
        ClientGetSessionCallbackAdapterById(waitOutSocket[i], &callback, &tmpIsServer);
        if (callback.socketClient.OnError != NULL) {
            (void)callback.socketClient.OnError(waitOutSocket[i], SOFTBUS_TRANS_STOP_BIND_BY_TIMEOUT);
        }
        ClientShutdown(waitOutSocket[i], SOFTBUS_TRANS_STOP_BIND_BY_TIMEOUT);
    }
}

static void ClientUpdateIdleTimeout(
    const ClientSessionServer *serverNode, SessionInfo *sessionNode, ListNode *destroyList)
{
    if (sessionNode->role != SESSION_ROLE_CLIENT || sessionNode->enableStatus != ENABLE_STATUS_SUCCESS) {
        return;
    }

    sessionNode->timeout += TIMER_TIMEOUT;
    if (sessionNode->maxIdleTime == 0 || sessionNode->timeout <= sessionNode->maxIdleTime) {
        return;
    }

    DestroySessionInfo *destroyNode = CreateDestroySessionNode(sessionNode, serverNode);
    if (destroyNode == NULL) {
        TRANS_LOGE(TRANS_SDK, "failed to create destory session Node, sessionId=%{public}d", sessionNode->sessionId);
        return;
    }
    ListAdd(destroyList, &(destroyNode->node));
    DestroySessionId();
    ListDelete(&sessionNode->node);
    SoftBusFree(sessionNode);
}

static void ClientTransSessionTimerProc(void)
{
    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_SDK, "not init");
        return;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    SessionInfo *nextSessionNode = NULL;
    ListNode destroyList;
    ListInit(&destroyList);
    int32_t waitOutSocket[MAX_SESSION_ID] = { 0 };
    uint32_t waitOutNum = 0;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }
        LIST_FOR_EACH_ENTRY_SAFE(sessionNode, nextSessionNode, &(serverNode->sessionList), SessionInfo, node) {
            ClientUpdateIdleTimeout(serverNode, sessionNode, &destroyList);
            ClientCheckWaitTimeOut(sessionNode, waitOutSocket, MAX_SESSION_ID, &waitOutNum);
        }
    }
    (void)SoftBusMutexUnlock(&g_clientSessionServerList->lock);
    (void)ClientCleanUpIdleTimeoutSocket(&destroyList);
    (void)ClientCleanUpWaitTimeoutSocket(waitOutSocket, waitOutNum);
}

int32_t ClientResetIdleTimeoutById(int32_t sessionId)
{
    if (sessionId <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid sessionId");
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_SDK, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    SessionInfo *nextSessionNode = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }
        LIST_FOR_EACH_ENTRY_SAFE(sessionNode, nextSessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->sessionId == sessionId) {
                sessionNode->timeout = 0;
                (void)SoftBusMutexUnlock(&g_clientSessionServerList->lock);
                TRANS_LOGD(TRANS_SDK, "reset timeout of sessionId=%{public}d", sessionId);
                return SOFTBUS_OK;
            }
        }
    }
    (void)SoftBusMutexUnlock(&g_clientSessionServerList->lock);
    TRANS_LOGE(TRANS_SDK, "not found session by sessionId=%{public}d", sessionId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientGetSessionNameByChannelId(int32_t channelId, int32_t channelType, char *sessionName, int32_t len)
{
    if (channelId < 0 || sessionName == NULL || len <= 0 || len > SESSION_NAME_SIZE_MAX) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list  not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }

        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->channelId == channelId && sessionNode->channelType == (ChannelType)channelType) {
                (void)memcpy_s(sessionName, len, serverNode->sessionName, len);
                (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
                return SOFTBUS_OK;
            }
        }
    }

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    TRANS_LOGE(TRANS_SDK, "not found session with channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientRawStreamEncryptDefOptGet(const char *sessionName, bool *isEncrypt)
{
    if (sessionName == NULL || isEncrypt == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_SDK, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (strcmp(serverNode->sessionName, sessionName) == 0) {
            *isEncrypt = serverNode->isSrvEncryptedRawStream;
            (void)SoftBusMutexUnlock(&g_clientSessionServerList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_clientSessionServerList->lock);
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGE(TRANS_SDK, "not found ClientSessionServer by sessionName=%{public}s", tmpName);
    AnonymizeFree(tmpName);
    return SOFTBUS_TRANS_SESSION_SERVER_NOT_FOUND;
}

int32_t ClientRawStreamEncryptOptGet(int32_t channelId, int32_t channelType, bool *isEncrypt)
{
    if (channelId < 0 || isEncrypt == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_SDK, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    SessionInfo *nextSessionNode = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }
        LIST_FOR_EACH_ENTRY_SAFE(sessionNode, nextSessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->channelId == channelId && sessionNode->channelType == (ChannelType)channelType) {
                *isEncrypt = sessionNode->isEncyptedRawStream;
                (void)SoftBusMutexUnlock(&g_clientSessionServerList->lock);
                return SOFTBUS_OK;
            }
        }
    }
    (void)SoftBusMutexUnlock(&g_clientSessionServerList->lock);
    TRANS_LOGE(TRANS_SDK, "not found session by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t SetSessionIsAsyncById(int32_t sessionId, bool isAsync)
{
    if (sessionId <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid sessionId");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }
        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->sessionId == sessionId) {
                sessionNode->isAsync = isAsync;
                (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
                return SOFTBUS_OK;
            }
        }
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t SetSessionInitInfoById(int32_t sessionId)
{
    if (sessionId <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid sessionId");
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }
        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->sessionId == sessionId) {
                sessionNode->enableStatus = ENABLE_STATUS_INIT;
                sessionNode->channelId = INVALID_CHANNEL_ID;
                sessionNode->channelType = CHANNEL_TYPE_BUTT;
                sessionNode->lifecycle.sessionState = SESSION_STATE_INIT;
                (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
                return SOFTBUS_OK;
            }
        }
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientTransSetChannelInfo(const char *sessionName, int32_t sessionId, int32_t channelId, int32_t channelType)
{
    if (sessionName == NULL || sessionId <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid session info");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_MSG, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if ((strcmp(serverNode->sessionName, sessionName) != 0) || IsListEmpty(&serverNode->sessionList)) {
            continue;
        }

        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->sessionId == sessionId) {
                sessionNode->channelId = channelId;
                sessionNode->channelType = (ChannelType)channelType;
                sessionNode->lifecycle.sessionState = SESSION_STATE_OPENED;
                (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
                return SOFTBUS_OK;
            }
        }
    }

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    TRANS_LOGE(TRANS_MSG, "not found session info with sessionId=%{public}d", sessionId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t GetSocketLifecycleAndSessionNameBySessionId(
    int32_t sessionId, char *sessionName, SocketLifecycleData *lifecycle)
{
    if (sessionId <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid param session id =%{public}d", sessionId);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    if (lifecycle == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param lifecycle is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_MSG, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "socket not found. socketFd=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }
    *lifecycle = sessionNode->lifecycle;
    if (sessionName != NULL && strcpy_s(sessionName, SESSION_NAME_SIZE_MAX, serverNode->sessionName) != EOK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        return SOFTBUS_STRCPY_ERR;
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

void AddSessionStateClosing(void)
{
    g_closingNum++;
}

void DelSessionStateClosing(void)
{
    if (g_closingNum > 0) {
        g_closingNum--;
    }
}

int32_t SetSessionStateBySessionId(int32_t sessionId, SessionState sessionState, int32_t optional)
{
    if (sessionId <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid session id =%{public}d", sessionId);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_MSG, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "socket not found. socketFd=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    TRANS_LOGI(TRANS_SDK, "socket state change:%{public}d -> %{public}d. socket=%{public}d",
        sessionNode->lifecycle.sessionState, sessionState, sessionId);
    sessionNode->lifecycle.sessionState = sessionState;
    if (sessionState == SESSION_STATE_CANCELLING) {
        TRANS_LOGW(TRANS_SDK, "set socket to cancelling, socket=%{public}d, errCode=%{public}d", sessionId, optional);
        sessionNode->lifecycle.bindErrCode = optional;
    }
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    return SOFTBUS_OK;
}

int32_t GetQosValue(const QosTV *qos, uint32_t qosCount, QosType type, int32_t *value, int32_t defVal)
{
    if (!IsValidQosInfo(qos, qosCount) || value == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (qos == NULL || qosCount == 0) {
        TRANS_LOGW(TRANS_SDK, "no qos info, use defVal");
        *value = defVal;
        return SOFTBUS_OK;
    }

    for (uint32_t i = 0; i < qosCount; i++) {
        if (qos[i].qos != type) {
            continue;
        }
        *value = qos[i].value;
        return SOFTBUS_OK;
    }
    *value = defVal;
    return SOFTBUS_OK;
}

int32_t ClientWaitSyncBind(int32_t socket)
{
    if (socket <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid param session id =%{public}d", socket);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_MSG, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "socket not found. socket=%{public}d", socket);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    if (sessionNode->lifecycle.sessionState == SESSION_STATE_CANCELLING) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGW(TRANS_SDK, "session is cancelling socket=%{public}d", socket);
        return sessionNode->lifecycle.bindErrCode;
    }

    int32_t ret = SoftBusCondWait(&(sessionNode->lifecycle.callbackCond), &(g_clientSessionServerList->lock), NULL);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "cond wait failed, socket=%{public}d", socket);
        return ret;
    }

    if (sessionNode->enableStatus != ENABLE_STATUS_SUCCESS) {
        ret = sessionNode->lifecycle.bindErrCode;
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        // enableStatus=false and ret=SOFTBUS_OK, is an unexpected state
        if (ret == SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "invalid bindErrCode, socket=%{public}d", socket);
            return SOFTBUS_TRANS_SESSION_NO_ENABLE;
        }
        TRANS_LOGE(TRANS_SDK, "Bind fail, socket=%{public}d, ret=%{public}d", socket, ret);
        return ret;
    }

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    TRANS_LOGI(TRANS_SDK, "socket=%{public}d is enable", socket);
    return sessionNode->lifecycle.bindErrCode;
}

int32_t ClientSignalSyncBind(int32_t socket, int32_t errCode)
{
    if (socket <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid param session id =%{public}d", socket);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_MSG, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "socket not found. socket=%{public}d", socket);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    if (sessionNode->isAsync) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGW(TRANS_SDK, "socket is async, do not need signal. socket=%{public}d", socket);
        return SOFTBUS_OK;
    }

    sessionNode->lifecycle.bindErrCode = errCode;
    int32_t ret = SoftBusCondSignal(&(sessionNode->lifecycle.callbackCond));
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "cond single failed, socket=%{public}d", socket);
        return ret;
    }

    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
    TRANS_LOGI(TRANS_SDK, "socket=%{public}d signal success", socket);
    return SOFTBUS_OK;
}
static void FillDsfSocketParam(
    SessionParam *param, SessionAttribute *tmpAttr, ClientSessionServer *serverNode, SessionInfo *sessionNode)
{
    tmpAttr->fastTransData = NULL;
    tmpAttr->fastTransDataSize = 0;
    tmpAttr->dataType = sessionNode->info.flag;
    tmpAttr->attr.streamAttr.streamType = sessionNode->info.streamType;
    // 2 means has two linkType
    tmpAttr->linkTypeNum = 2;
    tmpAttr->linkType[0] = LINK_TYPE_WIFI_WLAN_5G;
    tmpAttr->linkType[1] = LINK_TYPE_WIFI_WLAN_2G;
    param->sessionName = serverNode->sessionName;
    param->peerSessionName = sessionNode->info.peerSessionName;
    param->peerDeviceId = sessionNode->info.peerDeviceId;
    param->groupId = "reserved";
    param->attr = tmpAttr;
    param->isQosLane = false;
    param->qosCount = 0;
    (void)memset_s(param->qos, sizeof(param->qos), 0, sizeof(param->qos));
    param->isAsync = false;
}

int32_t ClientDfsIpcOpenSession(int32_t sessionId, TransInfo *transInfo)
{
    if (sessionId < 0 || transInfo == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_SDK, "not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (SoftBusMutexLock(&(g_clientSessionServerList->lock)) != 0) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }
    int32_t ret = CheckBindSocketInfo(sessionNode);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
        TRANS_LOGE(TRANS_SDK, "check socekt info failed, ret=%{public}d", ret);
        return ret;
    }

    SessionAttribute tmpAttr;
    (void)memset_s(&tmpAttr, sizeof(SessionAttribute), 0, sizeof(SessionAttribute));
    SessionParam param;
    FillDsfSocketParam(&param, &tmpAttr, serverNode, sessionNode);
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));

    param.sessionId = sessionId;
    ret = SetSessionStateBySessionId(param.sessionId, SESSION_STATE_OPENING, 0);
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, TRANS_SDK, "set session state failed, maybe cancel, ret=%{public}d", ret);
    ret = ServerIpcOpenSession(&param, transInfo);
    if (ret != SOFTBUS_OK) {
        ClientConvertRetVal(sessionId, &ret);
        TRANS_LOGE(TRANS_SDK, "open session ipc err: ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}
