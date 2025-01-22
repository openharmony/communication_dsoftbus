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
#include <unistd.h>

#include "anonymizer.h"
#include "client_bus_center_manager.h"
#include "client_trans_channel_manager.h"
#include "client_trans_file_listener.h"
#include "client_trans_proxy_file_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_tcp_direct_manager.h"
#include "client_trans_udp_manager.h"
#include "session_ipc_adapter.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"
#include "softbus_utils.h"
#include "trans_log.h"
#include "trans_server_proxy.h"

#define CONVERSION_BASE 1000LL
#define CAST_SESSION "CastPlusSessionName"
static void ClientTransSessionTimerProc(void);
static void ClientTransAsyncSendBytesTimerProc(void);

static int32_t g_sessionIdNum = 0;
static int32_t g_sessionId = 1;
static int32_t g_closingIdNum = 0;
static SoftBusList *g_clientSessionServerList = NULL;

static int32_t LockClientSessionServerList()
{
    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }
    int32_t ret = SoftBusMutexLock(&(g_clientSessionServerList->lock));
    if (ret != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

static void UnlockClientSessionServerList()
{
    (void)SoftBusMutexUnlock(&(g_clientSessionServerList->lock));
}

int32_t CheckPermissionState(int32_t sessionId)
{
    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }
    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }
        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->sessionId == sessionId) {
                bool permissionState = serverNode->permissionState;
                UnlockClientSessionServerList();
                return permissionState ? SOFTBUS_OK : SOFTBUS_PERMISSION_DENIED;
            }
        }
    }
    UnlockClientSessionServerList();
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

void PermissionStateChange(const char *pkgName, int32_t state)
{
    if (LockClientSessionServerList() != SOFTBUS_OK) {
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
    UnlockClientSessionServerList();
}

int TransClientInit(void)
{
    g_clientSessionServerList = CreateSoftBusList();
    if (g_clientSessionServerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "entry list not init");
        return SOFTBUS_TRANS_SESSION_SERVER_NOINIT;
    }

    if (TransDataSeqInfoListInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "DataSeqInfo list not init");
        return SOFTBUS_TRANS_DATA_SEQ_INFO_NO_INIT;
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

    if (RegisterTimeoutCallback(
        SOFTBUS_TRANS_ASYNC_SENDBYTES_TIMER_FUN, ClientTransAsyncSendBytesTimerProc) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "init trans async sendbytes idle timer failed");
        return SOFTBUS_TRANS_DATA_SEQ_INFO_INIT_FAIL;
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

static void ShowAllSessionInfo(void)
{
    TRANS_LOGI(TRANS_SDK, "g_sessionIdNum=%{public}d, g_closingIdNum=%{public}d", g_sessionIdNum, g_closingIdNum);
    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    int count = 0;
    char *tmpName = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        Anonymize(serverNode->sessionName, &tmpName);
        TRANS_LOGI(TRANS_SDK, "client session server is exist. count=%{public}d, sessionName=%{public}s",
            count, AnonymizeWrapper(tmpName));
        AnonymizeFree(tmpName);
        count++;
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }
        int sessionCount = 0;
        char *tmpPeerSessionName = NULL;
        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            Anonymize(sessionNode->info.peerSessionName, &tmpPeerSessionName);
            TRANS_LOGI(TRANS_SDK,
                "client session info is exist. sessionCount=%{public}d, peerSessionName=%{public}s, "
                "channelId=%{public}d, channelType=%{public}d",
                sessionCount, AnonymizeWrapper(tmpPeerSessionName), sessionNode->channelId, sessionNode->channelType);
            AnonymizeFree(tmpPeerSessionName);
            sessionCount++;
        }
    }
}

// need get g_clientSessionServerList->lock before call this function
int32_t GenerateSessionId(void)
{
    if (g_sessionIdNum >= g_closingIdNum && g_sessionIdNum - g_closingIdNum >= MAX_SESSION_ID) {
        TRANS_LOGE(TRANS_SDK, "sessionid num cross the line error");
        return INVALID_SESSION_ID;
    }
    int32_t cnt = MAX_SESSION_ID + g_closingIdNum + 1;
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

// need get g_clientSessionServerList->lock before call this function
void DestroySessionId(void)
{
    if (g_sessionIdNum > 0) {
        g_sessionIdNum--;
    }

    if (g_closingIdNum > 0) {
        g_closingIdNum--;
    }
}

int32_t TryDeleteEmptySessionServer(const char *pkgName, const char *sessionName)
{
    if (pkgName == NULL || sessionName == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    ClientSessionServer *serverNodeNext = NULL;
    ListNode destroyList;
    ListInit(&destroyList);
    LIST_FOR_EACH_ENTRY_SAFE(
        serverNode, serverNodeNext, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (strcmp(serverNode->sessionName, sessionName) == 0 && IsListEmpty(&serverNode->sessionList) &&
            serverNode->sessionAddingCnt == 0) {
            ListDelete(&(serverNode->node));
            SoftBusFree(serverNode);
            g_clientSessionServerList->cnt--;
            UnlockClientSessionServerList();
            // calling the ipc interface by locking here may block other threads for a long time
            char *tmpName = NULL;
            Anonymize(sessionName, &tmpName);
            ret = ServerIpcRemoveSessionServer(pkgName, sessionName);
            if (ret != SOFTBUS_OK) {
                TRANS_LOGE(TRANS_SDK, "remove session server failed, ret=%{public}d", ret);
                AnonymizeFree(tmpName);
                return ret;
            }
            TRANS_LOGI(TRANS_SDK, "delete empty session server, sessionName=%{public}s", AnonymizeWrapper(tmpName));
            AnonymizeFree(tmpName);
            return SOFTBUS_OK;
        }
    }
    UnlockClientSessionServerList();
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

void TransClientDeinit(void)
{
    if (LockClientSessionServerList() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return;
    }
    (void)RegisterTimeoutCallback(SOFTBUS_TRANS_ASYNC_SENDBYTES_TIMER_FUN, NULL);
    ClientSessionServer *serverNode = NULL;
    ClientSessionServer *serverNodeNext = NULL;
    ListNode destroyList;
    ListInit(&destroyList);
    LIST_FOR_EACH_ENTRY_SAFE(serverNode, serverNodeNext, &(g_clientSessionServerList->list),
        ClientSessionServer, node) {
        DestroyClientSessionServer(serverNode, &destroyList);
    }
    UnlockClientSessionServerList();
    ClientDestroySession(&destroyList, SHUTDOWN_REASON_LOCAL);
    DestroyRelationChecker();

    DestroySoftBusList(g_clientSessionServerList);
    g_clientSessionServerList = NULL;
    TransDataSeqInfoListDeinit();
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

static bool SocketServerIsExistAndUpdate(const char *sessionName)
{
    /* need get lock before */
    ClientSessionServer *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_clientSessionServerList->list, ClientSessionServer, node) {
        if (strcmp(item->sessionName, sessionName) == 0) {
            /*
             * this field indicates that a process is using a SessionServer,
             * but the process has not yet added the session node to the sessionList.
             * Other processes cannot perceive this intermediate state, so this field is added to identify this state;
             * This field is cleared after adding the session node to the session list in the process
             */
            item->sessionAddingCnt++;
            return true;
        }
    }
    return false;
}

void SocketServerStateUpdate(const char *sessionName)
{
    if (sessionName == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return;
    }
    if (LockClientSessionServerList() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return;
    }
    ClientSessionServer *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_clientSessionServerList->list, ClientSessionServer, node) {
        if (strcmp(item->sessionName, sessionName) == 0) {
            if (item->sessionAddingCnt > 0) {
                item->sessionAddingCnt--;
            }
            UnlockClientSessionServerList();
            return;
        }
    }
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGE(TRANS_SDK, "not found session server by sessionName=%{public}s", AnonymizeWrapper(tmpName));
    AnonymizeFree(tmpName);
    UnlockClientSessionServerList();
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
            "client session server is exist. count=%{public}d, sessionName=%{public}s",
                count, AnonymizeWrapper(tmpName));
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

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }
    if (SessionServerIsExist(sessionName)) {
        UnlockClientSessionServerList();
        return SOFTBUS_SERVER_NAME_REPEATED;
    }

    if (g_clientSessionServerList->cnt >= MAX_SESSION_SERVER_NUMBER) {
        ShowClientSessionServer();
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "ClientAddSessionServer: client server num reach max");
        return SOFTBUS_INVALID_NUM;
    }

    ClientSessionServer *server = GetNewSessionServer(type, sessionName, pkgName, listener);
    if (server == NULL) {
        UnlockClientSessionServerList();
        return SOFTBUS_MEM_ERR;
    }
    server->permissionState = true;
    ListAdd(&g_clientSessionServerList->list, &server->node);
    g_clientSessionServerList->cnt++;

    UnlockClientSessionServerList();
    char *tmpName = NULL;
    char *tmpPkgName = NULL;
    Anonymize(pkgName, &tmpPkgName);
    Anonymize(sessionName, &tmpName);
    TRANS_LOGI(TRANS_SDK, "sessionName=%{public}s, pkgName=%{public}s",
        AnonymizeWrapper(tmpName), AnonymizeWrapper(tmpPkgName));
    AnonymizeFree(tmpName);
    AnonymizeFree(tmpPkgName);
    return SOFTBUS_OK;
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

static int32_t GetSessionByChannelId(int32_t channelId, int32_t channelType, ClientSessionServer **server,
    SessionInfo **session)
{
    /* need get lock before */
    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }
        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->channelId == channelId && (int32_t)sessionNode->channelType == channelType) {
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
        ShowAllSessionInfo();
        return SOFTBUS_TRANS_SESSION_CNT_EXCEEDS_LIMIT;
    }
    ClientSessionServer *serverNode = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (strcmp(serverNode->sessionName, sessionName) != 0) {
            continue;
        }
        ListAdd(&serverNode->sessionList, &session->node);
        char *anonyDeviceId = NULL;
        Anonymize(session->info.peerDeviceId, &anonyDeviceId);
        TRANS_LOGI(TRANS_SDK,
            "add, sessionId=%{public}d, channelId=%{public}d, channelType=%{public}d, routeType=%{public}d, "
            "peerDeviceId=%{public}s",
            session->sessionId, session->channelId, session->channelType, session->routeType,
            AnonymizeWrapper(anonyDeviceId));
        AnonymizeFree(anonyDeviceId);
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

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ret = AddSession(sessionName, session);
    if (ret != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "add session failed, ret=%{public}d", ret);
        return ret;
    }
    UnlockClientSessionServerList();
    return SOFTBUS_OK;
}

int32_t ClientAddSession(const SessionParam *param, int32_t *sessionId, SessionEnableStatus *isEnabled)
{
    if (!IsValidSessionParam(param) || (sessionId == NULL) || (isEnabled == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    SessionInfo *session = GetExistSession(param);
    if (session != NULL) {
        *sessionId = session->sessionId;
        *isEnabled = session->enableStatus;
        UnlockClientSessionServerList();
        return SOFTBUS_TRANS_SESSION_REPEATED;
    }

    session = CreateNewSession(param);
    if (session == NULL) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "create session failed");
        return SOFTBUS_TRANS_SESSION_CREATE_FAILED;
    }

    ret = AddSession(param->sessionName, session);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(session);
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "Add Session failed, ret=%{public}d", ret);
        return ret;
    }

    *sessionId = session->sessionId;
    UnlockClientSessionServerList();
    return SOFTBUS_OK;
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

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
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
    UnlockClientSessionServerList();
    (void)ClientDestroySession(&destroyList, SHUTDOWN_REASON_LOCAL);
    return SOFTBUS_OK;
}

int32_t ClientDeleteSession(int32_t sessionId)
{
    TRANS_LOGI(TRANS_SDK, "sessionId=%{public}d", sessionId);
    if (sessionId < 0) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
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
            if (!sessionNode->lifecycle.condIsWaiting) {
                (void)SoftBusCondDestroy(&(sessionNode->lifecycle.callbackCond));
            } else {
                (void)SoftBusCondSignal(&(sessionNode->lifecycle.callbackCond)); // destroy in CheckSessionEnableStatus
                TRANS_LOGI(TRANS_SDK, "sessionId=%{public}d condition is waiting", sessionId);
            }
            SoftBusFree(sessionNode);
            UnlockClientSessionServerList();
            return SOFTBUS_OK;
        }
    }

    UnlockClientSessionServerList();
    TRANS_LOGE(TRANS_SDK, "not found session by sessionId=%{public}d", sessionId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientGetSessionDataById(int32_t sessionId, char *data, uint16_t len, SessionKey key)
{
    if ((sessionId < 0) || (data == NULL) || (len == 0)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
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
            UnlockClientSessionServerList();
            return SOFTBUS_MEM_ERR;
    }

    UnlockClientSessionServerList();
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

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    ret = GetSessionById(sessionId, &serverNode, &sessionNode);
    if (ret != SOFTBUS_OK) {
        UnlockClientSessionServerList();
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
        case KEY_ACTION_ID:
            *data = (int32_t)sessionNode->actionId;
            break;
        default:
            UnlockClientSessionServerList();
            return SOFTBUS_NOT_FIND;
    }

    UnlockClientSessionServerList();
    return SOFTBUS_OK;
}

int32_t ClientGetChannelBySessionId(
    int32_t sessionId, int32_t *channelId, int32_t *type, SessionEnableStatus *enableStatus)
{
    if (sessionId < 0) {
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }
    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
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
    UnlockClientSessionServerList();
    return SOFTBUS_OK;
}

int32_t ClientSetStatusClosingBySocket(int32_t socket, bool isClosing)
{
    if (socket < 0) {
        TRANS_LOGE(TRANS_INIT, "invalid socket=%{public}d", socket);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "socket not found. socket=%{public}d", socket);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    sessionNode->isClosing = isClosing;
    UnlockClientSessionServerList();
    return SOFTBUS_OK;
}

int32_t ClientSetEnableStatusBySocket(int32_t socket, SessionEnableStatus enableStatus)
{
    if (socket < 0) {
        TRANS_LOGE(TRANS_INIT, "invalid socket=%{public}d", socket);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "socket not found. socket=%{public}d", socket);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    sessionNode->enableStatus = enableStatus;
    UnlockClientSessionServerList();
    return SOFTBUS_OK;
}

int32_t ClientGetChannelBusinessTypeBySessionId(int32_t sessionId, int32_t *businessType)
{
    if ((sessionId < 0) || (businessType == NULL)) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    *businessType = sessionNode->businessType;

    UnlockClientSessionServerList();
    return SOFTBUS_OK;
}

int32_t GetSupportTlvAndNeedAckById(int32_t channelId, int32_t channelType, bool *supportTlv, bool *needAck)
{
    if (channelId <= 0 || (supportTlv == NULL && needAck == NULL)) { // supportTlv and needAck is an optional param
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionByChannelId(channelId, channelType, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "channel not found. channelId=%{public}d", channelId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }
    if (supportTlv != NULL) {
        *supportTlv = sessionNode->isSupportTlv;
    }
    if (needAck != NULL) {
        *needAck = sessionNode->needAck;
    }
    UnlockClientSessionServerList();
    TRANS_LOGD(TRANS_SDK, "get support tlv or needAck success by channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}

int32_t ClientSetChannelBySessionId(int32_t sessionId, TransInfo *transInfo)
{
    if ((sessionId < 0) || (transInfo->channelId < 0)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }
    sessionNode->channelId = transInfo->channelId;
    sessionNode->channelType = (ChannelType)transInfo->channelType;
    TRANS_LOGI(TRANS_SDK, "Client set channel by sessionId success, sessionId=%{public}d, channelId=%{public}d, "
        "channelType=%{public}d", sessionId, sessionNode->channelId, sessionNode->channelType);

    UnlockClientSessionServerList();
    return SOFTBUS_OK;
}

int32_t GetEncryptByChannelId(int32_t channelId, int32_t channelType, int32_t *data)
{
    if ((channelId < 0) || (data == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }

        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->channelId == channelId && (int32_t)sessionNode->channelType == channelType) {
                *data = (int32_t)sessionNode->isEncrypt;
                UnlockClientSessionServerList();
                return SOFTBUS_OK;
            }
        }
    }

    UnlockClientSessionServerList();
    TRANS_LOGE(TRANS_SDK, "not found session by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientGetSessionStateByChannelId(int32_t channelId, int32_t channelType, SessionState *sessionState)
{
    if ((channelId < 0) || (sessionState == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param, channelId=%{public}d, channelType=%{public}d", channelId, channelType);
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }

        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->channelId == channelId && sessionNode->channelType == (ChannelType)channelType) {
                *sessionState = sessionNode->lifecycle.sessionState;
                UnlockClientSessionServerList();
                return SOFTBUS_OK;
            }
        }
    }

    UnlockClientSessionServerList();
    TRANS_LOGE(TRANS_SDK, "not found session by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientGetSessionIdByChannelId(int32_t channelId, int32_t channelType, int32_t *sessionId, bool isClosing)
{
    if ((channelId < 0) || (sessionId == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }

        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            bool flag = (isClosing ? sessionNode->isClosing : true);
            if (sessionNode->channelId == channelId && sessionNode->channelType == (ChannelType)channelType && flag) {
                *sessionId = sessionNode->sessionId;
                UnlockClientSessionServerList();
                return SOFTBUS_OK;
            }
        }
    }

    UnlockClientSessionServerList();
    TRANS_LOGE(TRANS_SDK, "not found session by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientGetSessionIsAsyncBySessionId(int32_t sessionId, bool *isAsync)
{
    if ((sessionId < 0) || (isAsync == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
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
                UnlockClientSessionServerList();
                return SOFTBUS_OK;
            }
        }
    }

    UnlockClientSessionServerList();
    TRANS_LOGE(TRANS_SDK, "not found session with sessionId=%{public}d", sessionId);
    return SOFTBUS_NOT_FIND;
}

int32_t ClientGetRouteTypeByChannelId(int32_t channelId, int32_t channelType, int32_t *routeType)
{
    if ((channelId < 0) || (routeType == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }

        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->channelId == channelId && sessionNode->channelType == (ChannelType)channelType) {
                *routeType = sessionNode->routeType;
                UnlockClientSessionServerList();
                return SOFTBUS_OK;
            }
        }
    }

    UnlockClientSessionServerList();
    TRANS_LOGE(TRANS_SDK, "not found session by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientGetDataConfigByChannelId(int32_t channelId, int32_t channelType, uint32_t *dataConfig)
{
    if ((channelId < 0) || (dataConfig == NULL)) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }

        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->channelId == channelId && sessionNode->channelType == (ChannelType)channelType) {
                *dataConfig = sessionNode->dataConfig;
                UnlockClientSessionServerList();
                return SOFTBUS_OK;
            }
        }
    }

    UnlockClientSessionServerList();
    TRANS_LOGE(TRANS_SDK, "not found session by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

// Only need to operate on the action guidance ishare auth channel
static void ClientSetAuthSessionTimer(const ClientSessionServer *serverNode, SessionInfo *sessionNode)
{
    if (strcmp(serverNode->sessionName, ISHARE_AUTH_SESSION) == 0 && sessionNode->channelType == CHANNEL_TYPE_AUTH &&
        sessionNode->actionId != 0) {
        sessionNode->lifecycle.maxWaitTime = ISHARE_AUTH_SESSION_MAX_IDLE_TIME;
        sessionNode->lifecycle.waitTime = 0;
        TRANS_LOGI(TRANS_SDK, "set auth sessionId=%{public}d waitTime success.", sessionNode->sessionId);
    }
}

int32_t ClientEnableSessionByChannelId(const ChannelInfo *channel, int32_t *sessionId)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        (channel != NULL && sessionId != NULL), SOFTBUS_INVALID_PARAM, TRANS_SDK, "Invalid param");

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

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
                sessionNode->osType = channel->osType;
                *sessionId = sessionNode->sessionId;
                sessionNode->isSupportTlv = channel->isSupportTlv;
                if (channel->channelType == CHANNEL_TYPE_AUTH || !sessionNode->isEncrypt) {
                    ClientSetAuthSessionTimer(serverNode, sessionNode);
                    if (memcpy_s(sessionNode->info.peerDeviceId, DEVICE_ID_SIZE_MAX,
                        channel->peerDeviceId, DEVICE_ID_SIZE_MAX) != EOK) {
                        UnlockClientSessionServerList();
                        return SOFTBUS_MEM_ERR;
                    }
                }
                UnlockClientSessionServerList();
                return SOFTBUS_OK;
            }
        }
    }

    UnlockClientSessionServerList();
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

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    ret = memcpy_s(callback, sizeof(ISessionListener), &serverNode->listener.session, sizeof(ISessionListener));
    UnlockClientSessionServerList();
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

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (strcmp(serverNode->sessionName, sessionName) != 0) {
            continue;
        }

        ret = memcpy_s(callback, sizeof(ISessionListener), &serverNode->listener.session, sizeof(ISessionListener));
        UnlockClientSessionServerList();
        if (ret != EOK) {
            return SOFTBUS_MEM_ERR;
        }
        return SOFTBUS_OK;
    }

    UnlockClientSessionServerList();
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGE(TRANS_SDK, "not found session by sessionName=%{public}s", AnonymizeWrapper(tmpName));
    AnonymizeFree(tmpName);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientGetSessionSide(int32_t sessionId)
{
    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    int32_t side = -1;
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
            side = sessionNode->isServer ? IS_SERVER : IS_CLIENT;
            UnlockClientSessionServerList();
            return side;
        }
    }
    UnlockClientSessionServerList();
    return side;
}

static void ClientTransLnnOfflineProc(NodeBasicInfo *info)
{
    TRANS_LOGD(TRANS_SDK, "device offline callback enter.");
    if (info == NULL) {
        return;
    }
    if (LockClientSessionServerList() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return;
    }

    ClientSessionServer *serverNode = NULL;
    ListNode destroyList;
    ListInit(&destroyList);
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        DestroyClientSessionByNetworkId(serverNode, info->networkId, ROUTE_TYPE_ALL, &destroyList);
    }
    UnlockClientSessionServerList();
    (void)ClientDestroySession(&destroyList, SHUTDOWN_REASON_LNN_OFFLINE);
    return;
}

static INodeStateCb g_transLnnCb = {
    .events = EVENT_NODE_STATE_OFFLINE,
    .onNodeOffline = ClientTransLnnOfflineProc,
};

void ClientTransRegLnnOffline(void)
{
    int32_t ret;
    ret = RegNodeDeviceStateCbInner("trans", &g_transLnnCb);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "reg lnn offline fail");
    }
}

void ClientTransOnUserSwitch(void)
{
    if (LockClientSessionServerList() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return;
    }
    TRANS_LOGD(TRANS_SDK, "recv user switch event, clear all socket");
    ClientSessionServer *serverNode = NULL;
    ListNode destroyList;
    ListInit(&destroyList);
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        DestroyAllClientSession(serverNode, &destroyList);
    }
    UnlockClientSessionServerList();
    (void)ClientDestroySession(&destroyList, SHUTDOWN_REASON_USER_SWICTH);
}

void ClientTransOnLinkDown(const char *networkId, int32_t routeType)
{
    if (networkId == NULL) {
        return;
    }
    uint64_t tokenId = 0;
    int32_t ret = SoftBusGetSelfTokenId(&tokenId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get selfTokenId failed");
        return;
    }
    if (LockClientSessionServerList() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return;
    }
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    TRANS_LOGD(TRANS_SDK, "routeType=%{public}d, networkId=%{public}s", routeType, AnonymizeWrapper(anonyNetworkId));
    AnonymizeFree(anonyNetworkId);

    ClientSessionServer *serverNode = NULL;
    ListNode destroyList;
    ListInit(&destroyList);
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (strcmp(CAST_SESSION, serverNode->sessionName) == 0 && SoftBusCheckIsSystemService(tokenId)) {
            TRANS_LOGD(TRANS_SDK, "cast plus sessionname is different");
            continue;
        }
        DestroyClientSessionByNetworkId(serverNode, networkId, routeType, &destroyList);
    }
    UnlockClientSessionServerList();
    (void)ClientDestroySession(&destroyList, SHUTDOWN_REASON_LINK_DOWN);
}

int32_t ClientGetFileConfigInfoById(int32_t sessionId, int32_t *fileEncrypt, int32_t *algorithm, int32_t *crc)
{
    if (sessionId < 0 || fileEncrypt == NULL || algorithm == NULL || crc == NULL) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }
    *fileEncrypt = sessionNode->fileEncrypt;
    *algorithm = sessionNode->algorithm;
    *crc = sessionNode->crc;
    UnlockClientSessionServerList();
    return SOFTBUS_OK;
}

void ClientCleanAllSessionWhenServerDeath(ListNode *sessionServerInfoList)
{
    if (sessionServerInfoList == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param.");
        return;
    }

    if (LockClientSessionServerList() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return;
    }
    uint32_t destroyCnt = 0;
    ListNode destroyList;
    ListInit(&destroyList);
    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    SessionInfo *nextSessionNode = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        serverNode->sessionAddingCnt = 0;
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
    UnlockClientSessionServerList();
    (void)ClientDestroySession(&destroyList, SHUTDOWN_REASON_SERVICE_DIED);
    TRANS_LOGI(TRANS_SDK, "client destroy session cnt=%{public}d.", destroyCnt);
}

int32_t ClientAddSocketServer(SoftBusSecType type, const char *pkgName, const char *sessionName)
{
    if (pkgName == NULL || sessionName == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }
    if (SocketServerIsExistAndUpdate(sessionName)) {
        UnlockClientSessionServerList();
        return SOFTBUS_SERVER_NAME_REPEATED;
    }

    if (g_clientSessionServerList->cnt >= MAX_SESSION_SERVER_NUMBER) {
        ShowClientSessionServer();
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "ClientAddSocketServer: client server num reach max");
        return SOFTBUS_INVALID_NUM;
    }

    ClientSessionServer *server = GetNewSocketServer(type, sessionName, pkgName);
    if (server == NULL) {
        UnlockClientSessionServerList();
        return SOFTBUS_MEM_ERR;
    }
    server->permissionState = true;
    ListAdd(&g_clientSessionServerList->list, &server->node);
    g_clientSessionServerList->cnt++;

    UnlockClientSessionServerList();
    char *anonymizePkgName = NULL;
    char *tmpName = NULL;
    Anonymize(pkgName, &anonymizePkgName);
    Anonymize(sessionName, &tmpName);
    TRANS_LOGE(TRANS_SDK, "sessionName=%{public}s, pkgName=%{public}s",
        AnonymizeWrapper(tmpName), AnonymizeWrapper(anonymizePkgName));
    AnonymizeFree(anonymizePkgName);
    AnonymizeFree(tmpName);
    return SOFTBUS_OK;
}

int32_t DeleteSocketSession(int32_t sessionId, char *pkgName, char *sessionName)
{
    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    if (strcpy_s(pkgName, PKG_NAME_SIZE_MAX, serverNode->pkgName) != EOK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "strcpy pkgName failed");
        return SOFTBUS_STRCPY_ERR;
    }

    if (strcpy_s(sessionName, SESSION_NAME_SIZE_MAX, serverNode->sessionName) != EOK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "strcpy sessionName failed");
        return SOFTBUS_STRCPY_ERR;
    }
    ListDelete(&(sessionNode->node));
    TRANS_LOGI(TRANS_SDK, "delete session, sessionId=%{public}d", sessionId);
    DestroySessionId();
    if (!sessionNode->lifecycle.condIsWaiting) {
        (void)SoftBusCondDestroy(&(sessionNode->lifecycle.callbackCond));
    } else {
        (void)SoftBusCondSignal(&(sessionNode->lifecycle.callbackCond)); // destroy in CheckSessionEnableStatus
        TRANS_LOGI(TRANS_SDK, "sessionId=%{public}d condition is waiting", sessionId);
    }
    SoftBusFree(sessionNode);
    UnlockClientSessionServerList();
    return SOFTBUS_OK;
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

int32_t ClientAddSocketSession(
    const SessionParam *param, bool isEncyptedRawStream, int32_t *sessionId, SessionEnableStatus *isEnabled)
{
    if (param == NULL || param->sessionName == NULL || param->groupId == NULL || param->attr == NULL ||
        sessionId == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    SessionInfo *session = GetSocketExistSession(param, isEncyptedRawStream);
    if (session != NULL) {
        if (session->lifecycle.bindErrCode != SOFTBUS_TRANS_STOP_BIND_BY_CANCEL) {
            *sessionId = session->sessionId;
            *isEnabled = session->enableStatus;
            UnlockClientSessionServerList();
            return SOFTBUS_TRANS_SESSION_REPEATED;
        }
        TRANS_LOGI(TRANS_SDK, "socket=%{public}d is shutdown", session->sessionId);
    }

    session = CreateNewSocketSession(param);
    if (session == NULL) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "create session failed");
        return SOFTBUS_TRANS_SESSION_CREATE_FAILED;
    }
    session->isEncyptedRawStream = isEncyptedRawStream;
    ret = AddSession(param->sessionName, session);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(session);
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "Add Session failed, ret=%{public}d", ret);
        return ret;
    }

    *sessionId = session->sessionId;
    UnlockClientSessionServerList();
    return SOFTBUS_OK;
}

int32_t ClientSetListenerBySessionId(int32_t sessionId, const ISocketListener *listener, bool isServer)
{
    if ((sessionId < 0) || listener == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    if (sessionNode->role != SESSION_ROLE_INIT) {
        TRANS_LOGE(TRANS_SDK, "socket in use, currentRole=%{public}d", sessionNode->role);
        UnlockClientSessionServerList();
        return SOFTBUS_TRANS_SOCKET_IN_USE;
    }
    ISocketListener *socketListener = isServer ? &(serverNode->listener.socketServer) :
        &(serverNode->listener.socketClient);
    ret = memcpy_s(socketListener, sizeof(ISocketListener), listener, sizeof(ISocketListener));
    if (ret != EOK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "memcpy_s socketListener failed, ret=%{public}d", ret);
        return SOFTBUS_MEM_ERR;
    }
    serverNode->listener.isSocketListener = true;
    if (socketListener->OnFile == NULL) {
        UnlockClientSessionServerList();
        return SOFTBUS_OK;
    }
    ret = TransSetSocketFileListener(serverNode->sessionName, socketListener->OnFile, isServer);
    if (ret != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "register socket file listener failed");
        return ret;
    }
    UnlockClientSessionServerList();
    return SOFTBUS_OK;
}

int32_t ClientIpcOpenSession(int32_t sessionId, const QosTV *qos, uint32_t qosCount, TransInfo *transInfo, bool isAsync)
{
    if (sessionId < 0 || transInfo == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }
    ret = CheckBindSocketInfo(sessionNode);
    if (ret != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "check socekt info failed, ret=%{public}d", ret);
        return ret;
    }

    SessionAttribute tmpAttr;
    (void)memset_s(&tmpAttr, sizeof(SessionAttribute), 0, sizeof(SessionAttribute));
    SessionParam param;
    FillSessionParam(&param, &tmpAttr, serverNode, sessionNode);
    UnlockClientSessionServerList();

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

int32_t ClientSetActionIdBySessionId(int32_t sessionId, uint32_t actionId)
{
    if ((sessionId < 0) || actionId == 0) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    ret = GetSessionById(sessionId, &serverNode, &sessionNode);
    if (ret != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "not found");
        return ret;
    }

    if (sessionNode->role != SESSION_ROLE_INIT) {
        TRANS_LOGE(TRANS_SDK, "socket in use, currentRole=%{public}d", sessionNode->role);
        UnlockClientSessionServerList();
        return SOFTBUS_TRANS_SOCKET_IN_USE;
    }

    sessionNode->actionId = actionId;
    UnlockClientSessionServerList();
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

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "socket not found. socket=%{public}d", socket);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }
    if (action == TIMER_ACTION_START) {
        TRANS_LOGI(TRANS_SDK,
            "socket=%{public}d, inputMaxWaitTime=%{public}u, maxWaitTime=%{public}u, enableStatus=%{public}d",
            socket, maxWaitTime, sessionNode->lifecycle.maxWaitTime, sessionNode->enableStatus);
        bool binding = (sessionNode->lifecycle.maxWaitTime != 0);
        bool bindSuccess =
            (sessionNode->lifecycle.maxWaitTime == 0 && sessionNode->enableStatus == ENABLE_STATUS_SUCCESS);
        if (binding) {
            UnlockClientSessionServerList();
            TRANS_LOGE(TRANS_SDK, "socket=%{public}d The socket is binding", socket);
            return SOFTBUS_TRANS_SOCKET_IN_USE;
        }
        if (bindSuccess) {
            UnlockClientSessionServerList();
            TRANS_LOGW(TRANS_SDK, "socket=%{public}d The socket was bound successfully", socket);
            return SOFTBUS_ALREADY_TRIGGERED;
        }
    }

    sessionNode->lifecycle.maxWaitTime = (action == TIMER_ACTION_START) ? maxWaitTime : 0;
    sessionNode->lifecycle.waitTime = 0;
    UnlockClientSessionServerList();
    return SOFTBUS_OK;
}

int32_t ClientSetSocketState(int32_t socket, uint32_t maxIdleTimeout, SessionRole role)
{
    if (socket < 0) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
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
    UnlockClientSessionServerList();
    return SOFTBUS_OK;
}

int32_t ClientDfsIpcOpenSession(int32_t sessionId, TransInfo *transInfo)
{
    if (sessionId < 0 || transInfo == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }
    ret = CheckBindSocketInfo(sessionNode);
    if (ret != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "check socekt info failed, ret=%{public}d", ret);
        return ret;
    }

    SessionAttribute tmpAttr;
    (void)memset_s(&tmpAttr, sizeof(SessionAttribute), 0, sizeof(SessionAttribute));
    SessionParam param;
    FillDfsSocketParam(&param, &tmpAttr, serverNode, sessionNode);
    UnlockClientSessionServerList();

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

int32_t ClientGetSessionCallbackAdapterByName(const char *sessionName, SessionListenerAdapter *callbackAdapter)
{
    if (sessionName == NULL || callbackAdapter == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (strcmp(serverNode->sessionName, sessionName) != 0) {
            continue;
        }

        ret = memcpy_s(callbackAdapter, sizeof(SessionListenerAdapter),
            &serverNode->listener, sizeof(SessionListenerAdapter));
        UnlockClientSessionServerList();
        if (ret != EOK) {
            char *tmpName = NULL;
            Anonymize(sessionName, &tmpName);
            TRANS_LOGE(TRANS_SDK,
                "memcpy SessionListenerAdapter failed, sessionName=%{public}s, ret=%{public}d",
                AnonymizeWrapper(tmpName), ret);
            AnonymizeFree(tmpName);
            return SOFTBUS_MEM_ERR;
        }
        return SOFTBUS_OK;
    }

    UnlockClientSessionServerList();
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGE(TRANS_SDK, "SessionCallbackAdapter not found, sessionName=%{public}s", AnonymizeWrapper(tmpName));
    AnonymizeFree(tmpName);
    return SOFTBUS_NOT_FIND;
}

int32_t ClientGetSessionCallbackAdapterById(int32_t sessionId, SessionListenerAdapter *callbackAdapter, bool *isServer)
{
    if (sessionId < 0 || callbackAdapter == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    ret = memcpy_s(callbackAdapter, sizeof(SessionListenerAdapter), &serverNode->listener,
        sizeof(SessionListenerAdapter));
    *isServer = sessionNode->isServer;
    UnlockClientSessionServerList();
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

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "socket not found. socketFd=%{public}d", socket);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    peerSocketInfo->name = sessionNode->info.peerSessionName;
    peerSocketInfo->networkId = sessionNode->info.peerDeviceId;
    peerSocketInfo->pkgName = serverNode->pkgName;
    peerSocketInfo->dataType = (TransDataType)sessionNode->info.flag;
    UnlockClientSessionServerList();
    return SOFTBUS_OK;
}

bool IsSessionExceedLimit(void)
{
    if (LockClientSessionServerList() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return true;
    }
    if (g_sessionIdNum >= MAX_SESSION_ID) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "sessionId num exceed limit.");
        return true;
    }
    UnlockClientSessionServerList();
    return false;
}

static void ClientTransSessionTimerProc(void)
{
    if (LockClientSessionServerList() != SOFTBUS_OK) {
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
            ClientCheckWaitTimeOut(serverNode, sessionNode, waitOutSocket, MAX_SESSION_ID, &waitOutNum);
            ClientUpdateIdleTimeout(serverNode, sessionNode, &destroyList);
        }
    }
    UnlockClientSessionServerList();
    (void)ClientCleanUpIdleTimeoutSocket(&destroyList);
    (void)ClientCleanUpWaitTimeoutSocket(waitOutSocket, waitOutNum);
}

static void ClientTransAsyncSendBytesTimerProc(void)
{
    return TransAsyncSendBytesTimeoutProc();
}

int32_t ClientResetIdleTimeoutById(int32_t sessionId)
{
    if (sessionId <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid sessionId");
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
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
                UnlockClientSessionServerList();
                TRANS_LOGD(TRANS_SDK, "reset timeout of sessionId=%{public}d", sessionId);
                return SOFTBUS_OK;
            }
        }
    }
    UnlockClientSessionServerList();
    TRANS_LOGE(TRANS_SDK, "not found session by sessionId=%{public}d", sessionId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientGetSessionNameByChannelId(int32_t channelId, int32_t channelType, char *sessionName, int32_t len)
{
    if (channelId < 0 || sessionName == NULL || len <= 0 || len > SESSION_NAME_SIZE_MAX) {
        TRANS_LOGW(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;

    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList)) {
            continue;
        }

        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->channelId == channelId && sessionNode->channelType == (ChannelType)channelType) {
                (void)memcpy_s(sessionName, len, serverNode->sessionName, len);
                UnlockClientSessionServerList();
                return SOFTBUS_OK;
            }
        }
    }

    UnlockClientSessionServerList();
    TRANS_LOGE(TRANS_SDK, "not found session with channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientRawStreamEncryptDefOptGet(const char *sessionName, bool *isEncrypt)
{
    if (sessionName == NULL || isEncrypt == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (strcmp(serverNode->sessionName, sessionName) == 0) {
            *isEncrypt = serverNode->isSrvEncryptedRawStream;
            UnlockClientSessionServerList();
            return SOFTBUS_OK;
        }
    }
    UnlockClientSessionServerList();
    char *tmpName = NULL;
    Anonymize(sessionName, &tmpName);
    TRANS_LOGE(TRANS_SDK, "not found ClientSessionServer by sessionName=%{public}s", AnonymizeWrapper(tmpName));
    AnonymizeFree(tmpName);
    return SOFTBUS_TRANS_SESSION_SERVER_NOT_FOUND;
}

int32_t ClientRawStreamEncryptOptGet(int32_t channelId, int32_t channelType, bool *isEncrypt)
{
    if (channelId < 0 || isEncrypt == NULL) {
        TRANS_LOGE(TRANS_SDK, "Invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
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
                UnlockClientSessionServerList();
                return SOFTBUS_OK;
            }
        }
    }
    UnlockClientSessionServerList();
    TRANS_LOGE(TRANS_SDK, "not found session by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t SetSessionIsAsyncById(int32_t sessionId, bool isAsync)
{
    if (sessionId <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid sessionId");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
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
                UnlockClientSessionServerList();
                return SOFTBUS_OK;
            }
        }
    }
    UnlockClientSessionServerList();
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t SetSessionInitInfoById(int32_t sessionId)
{
    if (sessionId <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid sessionId");
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
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
                UnlockClientSessionServerList();
                return SOFTBUS_OK;
            }
        }
    }
    UnlockClientSessionServerList();
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientTransSetChannelInfo(const char *sessionName, int32_t sessionId, int32_t channelId, int32_t channelType)
{
    if (sessionName == NULL || sessionId <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid session info");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }
    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "socket not found. socketFd=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }
    if (sessionNode->lifecycle.sessionState == SESSION_STATE_CANCELLING) {
        TRANS_LOGW(TRANS_SDK, "this socket already in cancelling state. socketFd=%{public}d", sessionId);
        UnlockClientSessionServerList();
        return sessionNode->lifecycle.bindErrCode;
    }
    sessionNode->channelId = channelId;
    sessionNode->channelType = (ChannelType)channelType;
    sessionNode->lifecycle.sessionState = SESSION_STATE_OPENED;
    UnlockClientSessionServerList();
    return SOFTBUS_OK;
}

int32_t GetSocketLifecycleAndSessionNameBySessionId(
    int32_t sessionId, char *sessionName, SocketLifecycleData *lifecycle)
{
    if (sessionId <= 0 || lifecycle == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param, sessionId =%{public}d", sessionId);
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "socket not found. socketFd=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }
    *lifecycle = sessionNode->lifecycle;
    if (sessionName != NULL && strcpy_s(sessionName, SESSION_NAME_SIZE_MAX, serverNode->sessionName) != EOK) {
        UnlockClientSessionServerList();
        return SOFTBUS_STRCPY_ERR;
    }
    UnlockClientSessionServerList();
    return SOFTBUS_OK;
}

void AddSessionStateClosing(void)
{
    if (LockClientSessionServerList() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return;
    }
    g_closingIdNum++;
    UnlockClientSessionServerList();
}

void DelSessionStateClosing(void)
{
    if (LockClientSessionServerList() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return;
    }
    if (g_closingIdNum > 0) {
        g_closingIdNum--;
    }
    UnlockClientSessionServerList();
}

int32_t SetSessionStateBySessionId(int32_t sessionId, SessionState sessionState, int32_t optional)
{
    if (sessionId <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid sessionId =%{public}d", sessionId);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
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
    UnlockClientSessionServerList();
    return SOFTBUS_OK;
}

static int32_t CheckSessionEnableStatus(int32_t socket, SoftBusCond *callbackCond)
{
    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed socket=%{public}d", socket);
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        (void)SoftBusCondDestroy(callbackCond);
        TRANS_LOGE(TRANS_SDK, "socket=%{public}d not found, destroy condition", socket);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }
    sessionNode->lifecycle.condIsWaiting = false;
    ret = sessionNode->lifecycle.bindErrCode;
    if (sessionNode->enableStatus != ENABLE_STATUS_SUCCESS) {
        UnlockClientSessionServerList();
        // enableStatus=false and ret=SOFTBUS_OK, is an unexpected state
        if (ret == SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "invalid bindErrCode, socket=%{public}d, ret=%{public}d", socket, ret);
            return SOFTBUS_TRANS_SESSION_NO_ENABLE;
        }
        TRANS_LOGE(TRANS_SDK, "Bind fail, socket=%{public}d, ret=%{public}d", socket, ret);
        return ret;
    }
    UnlockClientSessionServerList();
    TRANS_LOGI(TRANS_SDK, "socket=%{public}d is enable, ret=%{public}d", socket, ret);
    return ret;
}

int32_t ClientWaitSyncBind(int32_t socket)
{
#define EXTRA_WAIT_TIME 5 // 5s, ensure that the timeout here occurs after ClientCheckWaitTimeOut
    if (socket <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid param sessionId =%{public}d", socket);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "socket not found. socket=%{public}d", socket);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    if (sessionNode->lifecycle.sessionState == SESSION_STATE_CANCELLING) {
        UnlockClientSessionServerList();
        TRANS_LOGW(TRANS_SDK, "session is cancelling socket=%{public}d", socket);
        return sessionNode->lifecycle.bindErrCode;
    }
    SoftBusCond *callbackCond = &(sessionNode->lifecycle.callbackCond);
    sessionNode->lifecycle.condIsWaiting = true;
    SoftBusSysTime *timePtr = NULL;
    SoftBusSysTime absTime = { 0 };
    if (sessionNode->lifecycle.maxWaitTime != 0) {
        ret = SoftBusGetTime(&absTime);
        if (ret == SOFTBUS_OK) {
            absTime.sec += (int64_t)((sessionNode->lifecycle.maxWaitTime / CONVERSION_BASE) + EXTRA_WAIT_TIME);
            timePtr = &absTime;
        }
    }
    ret = SoftBusCondWait(callbackCond, &(g_clientSessionServerList->lock), timePtr);
    if (ret != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "cond wait failed, socket=%{public}d", socket);
        return ret;
    }
    UnlockClientSessionServerList();
    return CheckSessionEnableStatus(socket, callbackCond);
}

static void TransWaitForBindReturn(int32_t socket)
{
#define RETRY_GET_BIND_RESULT_TIMES 10
#define RETRY_WAIT_TIME             500

    SocketLifecycleData lifecycle;
    (void)memset_s(&lifecycle, sizeof(SocketLifecycleData), 0, sizeof(SocketLifecycleData));
    int32_t ret;

    for (int32_t retryTimes = 0; retryTimes < RETRY_GET_BIND_RESULT_TIMES; ++retryTimes) {
        ret = GetSocketLifecycleAndSessionNameBySessionId(socket, NULL, &lifecycle);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "Get session lifecycle failed, ret=%{public}d", ret);
            return;
        }

        if (lifecycle.maxWaitTime == 0) {
            return;
        }
        TRANS_LOGW(TRANS_SDK, "wait for bind return, socket=%{public}d, retryTimes=%{public}d", socket, retryTimes);
        usleep(RETRY_WAIT_TIME);
    }
}

int32_t ClientSignalSyncBind(int32_t socket, int32_t errCode)
{
    if (socket <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid param sessionId =%{public}d", socket);
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "socket not found. socket=%{public}d", socket);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    if (sessionNode->isAsync) {
        UnlockClientSessionServerList();
        TRANS_LOGW(TRANS_SDK, "socket is async, do not need signal. socket=%{public}d", socket);
        return SOFTBUS_OK;
    }

    sessionNode->lifecycle.bindErrCode = errCode;
    ret = SoftBusCondSignal(&(sessionNode->lifecycle.callbackCond));
    if (ret != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "cond single failed, socket=%{public}d", socket);
        return ret;
    }

    UnlockClientSessionServerList();
    TRANS_LOGI(TRANS_SDK, "socket=%{public}d signal success", socket);
    TransWaitForBindReturn(socket);
    return SOFTBUS_OK;
}

static int32_t ClientUpdateAuthSessionTimer(SessionInfo *sessionNode, int32_t sessionId)
{
    // Only need to operate on the action guidance channel
    if (sessionNode->actionId == 0) {
        return SOFTBUS_OK;
    }
    if (sessionNode->lifecycle.maxWaitTime == 0) {
        TRANS_LOGE(TRANS_SDK, "sessionId=%{public}d is not need update.", sessionId);
        return SOFTBUS_NOT_NEED_UPDATE;
    }
    sessionNode->lifecycle.maxWaitTime = 0;
    return SOFTBUS_OK;
}

int32_t ClientCancelAuthSessionTimer(int32_t sessionId)
{
    if (sessionId <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid sessionId");
        return SOFTBUS_TRANS_INVALID_SESSION_ID;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        if (IsListEmpty(&serverNode->sessionList) || strcmp(serverNode->sessionName, ISHARE_AUTH_SESSION) != 0) {
            continue;
        }
        LIST_FOR_EACH_ENTRY(sessionNode, &(serverNode->sessionList), SessionInfo, node) {
            if (sessionNode->sessionId != sessionId ||
                (sessionNode->channelType != CHANNEL_TYPE_PROXY && sessionNode->channelType != CHANNEL_TYPE_AUTH)) {
                continue;
            }
            ret = ClientUpdateAuthSessionTimer(sessionNode, sessionId);
            UnlockClientSessionServerList();
            return ret;
        }
    }
    UnlockClientSessionServerList();
    TRANS_LOGE(TRANS_SDK, "not found ishare auth session by sessionId=%{public}d", sessionId);
    return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
}

int32_t ClientGetChannelOsTypeBySessionId(int32_t sessionId, int32_t *osType)
{
    if ((sessionId < 0) || (osType == NULL)) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(sessionId, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", sessionId);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    *osType = sessionNode->osType;

    UnlockClientSessionServerList();
    return SOFTBUS_OK;
}

void ClientTransOnPrivilegeClose(const char *peerNetworkId)
{
    if (LockClientSessionServerList() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return;
    }
    TRANS_LOGD(TRANS_SDK, "recv privilege close event, clear all socket");
    ClientSessionServer *serverNode = NULL;
    ListNode destroyList;
    ListInit(&destroyList);
    LIST_FOR_EACH_ENTRY(serverNode, &(g_clientSessionServerList->list), ClientSessionServer, node) {
        PrivilegeDestroyAllClientSession(serverNode, &destroyList, peerNetworkId);
    }
    UnlockClientSessionServerList();
    (void)ClientDestroySession(&destroyList, SHUTDOWN_REASON_PRIVILEGE_SHUTDOWN);
}

int32_t ClientCacheQosEvent(int32_t socket, QoSEvent event, const QosTV *qos, uint32_t count)
{
    if (socket <= 0 || qos == NULL || count == 0) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", socket);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }
    if (sessionNode->lifecycle.sessionState == SESSION_STATE_CALLBACK_FINISHED) {
        UnlockClientSessionServerList();
        return SOFTBUS_TRANS_NO_NEED_CACHE_QOS_EVENT;
    }
    for (uint32_t i = 0; i < count; i++) {
        sessionNode->cachedQosEvent.qos[i].qos = qos[i].qos;
        sessionNode->cachedQosEvent.qos[i].value = qos[i].value;
    }
    sessionNode->cachedQosEvent.count = count;
    sessionNode->cachedQosEvent.event = event;
    UnlockClientSessionServerList();
    TRANS_LOGI(TRANS_SDK, "cache qos event success, socket=%{public}d", socket);
    return SOFTBUS_OK;
}

int32_t ClientGetCachedQosEventBySocket(int32_t socket, CachedQosEvent *cachedQosEvent)
{
    if (socket <= 0 || cachedQosEvent == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }
    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "session not found. sessionId=%{public}d", socket);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }
    ret = memcpy_s(cachedQosEvent, sizeof(CachedQosEvent), &sessionNode->cachedQosEvent, sizeof(CachedQosEvent));
    if (ret != EOK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "copy cachedQosEvent failed, ret=%{public}d", ret);
        return SOFTBUS_MEM_ERR;
    }
    (void)memset_s(&sessionNode->cachedQosEvent, sizeof(CachedQosEvent), 0, sizeof(CachedQosEvent));
    UnlockClientSessionServerList();
    TRANS_LOGI(TRANS_SDK, "get cached qos event success, socket=%{public}d", socket);
    return SOFTBUS_OK;
}

int32_t GetMaxIdleTimeBySocket(int32_t socket, uint32_t *optValue)
{
    if (socket <= 0 || optValue == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "socket not found. socketFd=%{public}d", socket);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    if (sessionNode->role == SESSION_ROLE_CLIENT) {
        *optValue = sessionNode->maxIdleTime;
    } else {
        ret = SOFTBUS_NOT_IMPLEMENT;
    }
    UnlockClientSessionServerList();
    return ret;
}

int32_t SetMaxIdleTimeBySocket(int32_t socket, uint32_t maxIdleTime)
{
    if (socket <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "socket not found. socketFd=%{public}d", socket);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    if (sessionNode->role == SESSION_ROLE_CLIENT) {
        sessionNode->maxIdleTime = maxIdleTime;
    } else {
        ret = SOFTBUS_NOT_IMPLEMENT;
    }
    UnlockClientSessionServerList();
    return ret;
}

int32_t TransGetSupportTlvBySocket(int32_t socket, bool *supportTlv, int32_t *optValueSize)
{
    if (socket <= 0 || supportTlv == NULL || optValueSize == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "socket not found. socketFd=%{public}d", socket);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }
    *supportTlv = sessionNode->isSupportTlv;
    *optValueSize = sizeof(bool);
    UnlockClientSessionServerList();
    return SOFTBUS_OK;
}

int32_t TransSetNeedAckBySocket(int32_t socket, bool needAck)
{
    if (socket <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = LockClientSessionServerList();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return ret;
    }

    ClientSessionServer *serverNode = NULL;
    SessionInfo *sessionNode = NULL;
    if (GetSessionById(socket, &serverNode, &sessionNode) != SOFTBUS_OK) {
        UnlockClientSessionServerList();
        TRANS_LOGE(TRANS_SDK, "socket not found. socketFd=%{public}d", socket);
        return SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND;
    }

    if (!sessionNode->isSupportTlv) {
        TRANS_LOGI(TRANS_SDK, "cannot support set needAck");
        return SOFTBUS_TRANS_NOT_SUPPORT_TLV_HEAD;
    }
    sessionNode->needAck = needAck;
    UnlockClientSessionServerList();
    return SOFTBUS_OK;
}