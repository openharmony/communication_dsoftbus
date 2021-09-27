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

#include "softbus_base_listener.h"

#include <arpa/inet.h>
#include <errno.h>
#include <securec.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common_list.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_tcp_socket.h"
#include "softbus_thread_pool.h"
#include "softbus_utils.h"

#define MAX_LISTEN_EVENTS 1024
#define TIMEOUT           10000
#define DEFAULT_BACKLOG   4
#define FDARR_START_SIZE  16
#define FDARR_EXPAND_BASE 2

#define CLIENT_THREADNUM  1
#define CLIENT_QUEUE_NUM  10

#define SERVER_THREADNUM  1
#define SERVER_QUEUE_NUM  10

typedef enum {
    LISTENER_IDLE,
    LISTENER_PREPARED,
    LISTENER_RUNNING,
    LISTENER_ERROR,
} ListenerStatus;

typedef struct {
    ListNode node;
    int32_t fd;
} FdNode;

typedef struct {
    ListNode node;
    int32_t listenFd;
    char ip[IP_LEN];
    int32_t listenPort;
    int32_t fdCount;
    ModeType modeType;
    ListenerStatus status;
} SoftbusBaseListenerInfo;

typedef struct {
    ListenerModule module;
    SoftbusBaseListener *listener;
    SoftbusBaseListenerInfo *info;
    pthread_mutex_t lock;
} SoftbusListenerNode;

static SoftbusListenerNode g_listenerList[UNUSE_BUTT];
static ThreadPool *g_clientPool = NULL;
static ThreadPool *g_serverPool = NULL;
static fd_set g_readSet;
static fd_set g_writeSet;
static fd_set g_exceptSet;
static int32_t g_maxFd;
static pthread_mutex_t g_fdSetLock = PTHREAD_MUTEX_INITIALIZER;
static bool g_fdSetInit = false;

static int32_t FdCopy(fd_set *dest, const fd_set *src)
{
    return memcpy_s((void *)dest, sizeof(fd_set), (void *)src, sizeof(fd_set));
}

static int32_t MaxFd(int32_t fd1, int32_t fd2)
{
    return (fd1 > fd2) ? fd1 : fd2;
}

static void UpdateMaxFd(void)
{
    int32_t tmpMax = -1;

    for (int i = 0; i < UNUSE_BUTT; i++) {
        if (g_listenerList[i].info == NULL || g_listenerList[i].info->status != LISTENER_RUNNING) {
            continue;
        }

        if (pthread_mutex_lock(&g_listenerList[i].lock) != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
            continue;
        }

        SoftbusBaseListenerInfo *listenerInfo = g_listenerList[i].info;
        if (listenerInfo == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "listenerInfo is NULL");
            pthread_mutex_unlock(&g_listenerList[i].lock);
            continue;
        }

        tmpMax = MaxFd(listenerInfo->listenFd, tmpMax);
        FdNode *item = NULL;
        FdNode *nextItem = NULL;
        LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &listenerInfo->node, FdNode, node) {
            tmpMax = MaxFd(item->fd, tmpMax);
        }
        pthread_mutex_unlock(&g_listenerList[i].lock);
    }

    if (pthread_mutex_lock(&g_fdSetLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    g_maxFd = tmpMax;
    pthread_mutex_unlock(&g_fdSetLock);
}

static int32_t CheckModule(ListenerModule module)
{
    if (module >= UNUSE_BUTT || module < PROXY) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Invalid listener module.");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static int32_t CheckTrigger(TriggerType triggerType)
{
    if (triggerType < READ_TRIGGER || triggerType > RW_TRIGGER) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Invalid listener trigger type.");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static void ClearListenerFdList(ListNode *cfdList)
{
    FdNode *item = NULL;

    if (pthread_mutex_lock(&g_fdSetLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    while (!IsListEmpty(cfdList)) {
        item = LIST_ENTRY(cfdList->next, FdNode, node);
        ListDelete(&item->node);
        FD_CLR(item->fd, &g_readSet);
        FD_CLR(item->fd, &g_writeSet);
        FD_CLR(item->fd, &g_exceptSet);
        SoftBusFree(item);
    }
    pthread_mutex_unlock(&g_fdSetLock);
}

static int32_t InitListenFd(ListenerModule module, const char *ip, int32_t port)
{
    if (CheckModule(module) != SOFTBUS_OK || ip == NULL || port < 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    SoftbusBaseListenerInfo *listenerInfo = g_listenerList[module].info;
    if (listenerInfo == NULL) {
        return SOFTBUS_ERR;
    }
    int32_t rc = OpenTcpServerSocket(ip, port);
    if (rc < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "OpenTcpServer failed, rc=%d errno=%d", rc, errno);
        return SOFTBUS_TCP_SOCKET_ERR;
    }
    listenerInfo->listenFd = rc;
    rc = listen(listenerInfo->listenFd, DEFAULT_BACKLOG);
    if (rc != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "listen failed, rc=%d errno=%d", rc, errno);
        ResetBaseListener(module);
        return SOFTBUS_TCP_SOCKET_ERR;
    }
    listenerInfo->fdCount = 1;
    listenerInfo->listenPort = GetTcpSockPort(listenerInfo->listenFd);
    if (memcpy_s(listenerInfo->ip, IP_LEN, ip, IP_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Copy ip failed");
        ResetBaseListener(module);
        return SOFTBUS_MEM_ERR;
    }
    if (listenerInfo->listenPort < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetSockPort failed, listenPort_=%d", listenerInfo->listenPort);
        ResetBaseListener(module);
        return SOFTBUS_ERR;
    }

    if (pthread_mutex_lock(&g_fdSetLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        ResetBaseListener(module);
        return SOFTBUS_ERR;
    }
    FD_SET(listenerInfo->listenFd, &g_readSet);
    g_maxFd = MaxFd(listenerInfo->listenFd, g_maxFd);
    pthread_mutex_unlock(&g_fdSetLock);

    return SOFTBUS_OK;
}

void ResetBaseListener(ListenerModule module)
{
    if (CheckModule(module) != SOFTBUS_OK) {
        return;
    }
    if (pthread_mutex_lock(&g_listenerList[module].lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    SoftbusBaseListenerInfo *listenerInfo = g_listenerList[module].info;
    if (listenerInfo == NULL) {
        pthread_mutex_unlock(&g_listenerList[module].lock);
        return;
    }
    if (listenerInfo->listenFd >= 0) {
        TcpShutDown(listenerInfo->listenFd);
    }
    listenerInfo->listenFd = -1;
    listenerInfo->listenPort = -1;
    listenerInfo->status = LISTENER_IDLE;
    listenerInfo->modeType = UNSET_MODE;
    listenerInfo->fdCount = 0;
    ClearListenerFdList(&listenerInfo->node);
    pthread_mutex_unlock(&g_listenerList[module].lock);
    UpdateMaxFd();
}

void ResetBaseListenerSet(ListenerModule module)
{
    if (CheckModule(module) != SOFTBUS_OK) {
        return;
    }
    if (pthread_mutex_lock(&g_listenerList[module].lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    SoftbusBaseListenerInfo *listenerInfo = g_listenerList[module].info;
    if (listenerInfo == NULL) {
        pthread_mutex_unlock(&g_listenerList[module].lock);
        return;
    }
    ClearListenerFdList(&listenerInfo->node);
    listenerInfo->fdCount = 0;
    pthread_mutex_unlock(&g_listenerList[module].lock);
    UpdateMaxFd();
}

static int32_t OnEvent(ListenerModule module, int32_t fd, uint32_t events)
{
    if (CheckModule(module) != SOFTBUS_OK) {
        return SOFTBUS_INVALID_PARAM;
    }
    SoftbusBaseListenerInfo *listenerInfo = g_listenerList[module].info;
    SoftbusBaseListener *listener = g_listenerList[module].listener;
    if (listenerInfo == NULL || listener == NULL) {
        return SOFTBUS_ERR;
    }
    if (fd == listenerInfo->listenFd) {
        struct sockaddr_in addr;
        if (memset_s(&addr, sizeof(addr), 0, sizeof(addr)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "memset failed");
            return SOFTBUS_ERR;
        }
        socklen_t addrLen = sizeof(addr);
        int32_t cfd = TEMP_FAILURE_RETRY(accept(fd, (struct sockaddr *)&addr, &addrLen));
        if (cfd < 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "accept failed, cfd=%d, errno=%d", cfd, errno);
            return SOFTBUS_TCP_SOCKET_ERR;
        }
        char ip[IP_LEN] = {0};
        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
        if (listener->onConnectEvent != NULL) {
            listener->onConnectEvent(events, cfd, ip);
        } else {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Please set onConnectEvent callback");
            close(cfd);
        }
    } else {
        if (listener->onDataEvent != NULL) {
            listener->onDataEvent(events, fd);
        } else {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Please set onDataEvent callback");
        }
    }
    return SOFTBUS_OK;
}

static int CreateFdArr(int32_t **fdArr, int32_t *fdArrLen, const ListNode *list)
{
    if (list == NULL || list->next == list) {
        *fdArrLen = 0;
        return SOFTBUS_OK;
    }

    int32_t fdArrSize = FDARR_START_SIZE;
    int32_t *tmpFdArr = NULL;

    tmpFdArr = (int32_t *)SoftBusCalloc(sizeof(int32_t) * fdArrSize);
    if (tmpFdArr == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusCalloc failed, out of memory");
        return SOFTBUS_MALLOC_ERR;
    }
    *fdArrLen = 0;

    FdNode *item = NULL;
    LIST_FOR_EACH_ENTRY(item, list, FdNode, node) {
        if (*fdArrLen == fdArrSize) {
            int32_t *tmp = NULL;

            tmp = (int32_t *)SoftBusCalloc(sizeof(int32_t) * fdArrSize * FDARR_EXPAND_BASE);
            if (tmp == NULL) {
                SoftBusFree(tmpFdArr);
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "SoftBusCalloc failed, out of memory");
                return SOFTBUS_MALLOC_ERR;
            }
            for (int i = 0; i < *fdArrLen; i++) {
                tmp[i] = tmpFdArr[i];
            }
            SoftBusFree(tmpFdArr);
            tmpFdArr = tmp;
            fdArrSize *= FDARR_EXPAND_BASE;
        }
        tmpFdArr[*fdArrLen] = item->fd;
        *fdArrLen = *fdArrLen + 1;
    }
    *fdArr = tmpFdArr;
    return SOFTBUS_OK;
}

static void ProcessData(const fd_set *readSet, const fd_set *writeSet, const fd_set *exceptSet)
{
    for (int i = 0; i < UNUSE_BUTT; i++) {
        SoftbusBaseListenerInfo *listenerInfo = g_listenerList[i].info;
        if (listenerInfo == NULL || listenerInfo->status != LISTENER_RUNNING) {
            continue;
        }
        if (pthread_mutex_lock(&g_listenerList[i].lock) != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
            continue;
        }
        int32_t listenFd = listenerInfo->listenFd;
        int32_t *fdArr = NULL;
        int32_t fdArrLen = 0;

        if (CreateFdArr(&fdArr, &fdArrLen, &listenerInfo->node) != SOFTBUS_OK) {
            pthread_mutex_unlock(&g_listenerList[i].lock);
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "CreateFdArr failed, module:%d", i);
            continue;
        }
        pthread_mutex_unlock(&g_listenerList[i].lock);

        if ((listenFd > 0) && FD_ISSET(listenFd, readSet)) {
            OnEvent(i, listenFd, SOFTBUS_SOCKET_IN);
        }
        for (int j = 0; j < fdArrLen; j++) {
            if (FD_ISSET(fdArr[j], readSet)) {
                OnEvent(i, fdArr[j], SOFTBUS_SOCKET_IN);
            }
            if (FD_ISSET(fdArr[j], writeSet)) {
                OnEvent(i, fdArr[j], SOFTBUS_SOCKET_OUT);
            }
            if (FD_ISSET(fdArr[j], exceptSet)) {
                OnEvent(i, fdArr[j], SOFTBUS_SOCKET_EXCEPTION);
            }
        }
        SoftBusFree(fdArr);
    }
}

static int32_t SetSelect(fd_set *readSet, fd_set *writeSet, fd_set *exceptSet)
{
    if (pthread_mutex_lock(&g_fdSetLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_ERR;
    }
    if (FdCopy(readSet, &g_readSet) != EOK) {
        goto EXIT;
    }
    if (FdCopy(writeSet, &g_writeSet) != EOK) {
        goto EXIT;
    }
    if (FdCopy(exceptSet, &g_exceptSet) != EOK) {
        goto EXIT;
    }
    pthread_mutex_unlock(&g_fdSetLock);

    return SOFTBUS_OK;
EXIT:
    pthread_mutex_unlock(&g_fdSetLock);
    FD_ZERO(readSet);
    FD_ZERO(writeSet);
    FD_ZERO(exceptSet);
    return SOFTBUS_MEM_ERR;
}

static int32_t SelectThread(void)
{
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = TIMEOUT;

    fd_set readSet;
    fd_set writeSet;
    fd_set exceptSet;
    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    FD_ZERO(&exceptSet);
    if (SetSelect(&readSet, &writeSet, &exceptSet) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "select failed with invalid listener");
        return SOFTBUS_ERR;
    }
    int32_t maxFd = g_maxFd;
    if (maxFd < 0) {
        select(0, NULL, NULL, NULL, &tv);
        return SOFTBUS_OK;
    }

    int32_t nEvents = select(maxFd + 1, &readSet, &writeSet, &exceptSet, &tv);
    if (nEvents < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "select failed, errno=%d", errno);
        return SOFTBUS_TCP_SOCKET_ERR;
    } else if (nEvents == 0) {
        return SOFTBUS_OK;
    } else {
        ProcessData(&readSet, &writeSet, &exceptSet);
        return SOFTBUS_OK;
    }
}

static int32_t StartThread(ListenerModule module, ModeType modeType)
{
    SoftbusBaseListenerInfo *listenerInfo = g_listenerList[module].info;
    if (listenerInfo == NULL) {
        return SOFTBUS_ERR;
    }
    listenerInfo->modeType = modeType;
    listenerInfo->status = LISTENER_RUNNING;
    if (modeType == SERVER_MODE) {
        return ThreadPoolAddJob(g_serverPool, (int(*)(void *))SelectThread,
            NULL, PERSISTENT, (uintptr_t)0);
    } else if (modeType == CLIENT_MODE) {
        return ThreadPoolAddJob(g_clientPool, (int(*)(void *))SelectThread,
            NULL, PERSISTENT, (uintptr_t)0);
    } else {
        return SOFTBUS_INVALID_PARAM;
    }
}

static int32_t PrepareBaseListener(ListenerModule module, ModeType modeType)
{
    if (CheckModule(module) != SOFTBUS_OK) {
        return SOFTBUS_INVALID_PARAM;
    }
    SoftbusBaseListenerInfo *listenerInfo = g_listenerList[module].info;
    if (listenerInfo == NULL) {
        return SOFTBUS_ERR;
    }

    if (modeType == SERVER_MODE) {
        if (g_serverPool == NULL) {
            g_serverPool = ThreadPoolInit(SERVER_THREADNUM, SERVER_QUEUE_NUM);
            if (g_serverPool == NULL) {
                return SOFTBUS_MALLOC_ERR;
            }
        }
    } else {
        if (g_clientPool == NULL) {
            g_clientPool = ThreadPoolInit(CLIENT_THREADNUM, CLIENT_QUEUE_NUM);
            if (g_clientPool == NULL) {
                return SOFTBUS_MALLOC_ERR;
            }
        }
    }
    int ret = StartThread(module, modeType);
    if (ret != SOFTBUS_OK && ret != SOFTBUS_ALREADY_EXISTED) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "StartThread failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static SoftbusBaseListenerInfo *CreateNewListenerInfo(void)
{
    SoftbusBaseListenerInfo *listenerInfo = (SoftbusBaseListenerInfo *)SoftBusCalloc(sizeof(SoftbusBaseListenerInfo));
    if (listenerInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Malloc error");
        return NULL;
    }
    listenerInfo->modeType = UNSET_MODE;
    listenerInfo->fdCount = 0;
    listenerInfo->listenFd = -1;
    listenerInfo->listenPort = -1;
    listenerInfo->status = LISTENER_IDLE;
    ListInit(&listenerInfo->node);

    if (pthread_mutex_lock(&g_fdSetLock) != 0) {
        SoftBusFree(listenerInfo);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock g_fdSetLock failed");
        return NULL;
    }
    if (g_fdSetInit == false) {
        FD_ZERO(&g_readSet);
        FD_ZERO(&g_writeSet);
        FD_ZERO(&g_exceptSet);
        g_fdSetInit = true;
    }
    pthread_mutex_unlock(&g_fdSetLock);

    return listenerInfo;
}

int32_t StartBaseClient(ListenerModule module)
{
    if (CheckModule(module) != SOFTBUS_OK) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret;

    g_listenerList[module].module = module;
    if (g_listenerList[module].listener == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BaseListener not set, start failed.");
        return SOFTBUS_ERR;
    }
    if (g_listenerList[module].info == NULL) {
        g_listenerList[module].info = CreateNewListenerInfo();
        if (g_listenerList[module].info == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "malloc listenerInfo err");
            return SOFTBUS_MALLOC_ERR;
        }
        pthread_mutexattr_t mutexAttr;
        pthread_mutexattr_init(&mutexAttr);
        pthread_mutexattr_settype(&mutexAttr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&g_listenerList[module].lock, &mutexAttr);
    }
    if (g_listenerList[module].info->status != LISTENER_IDLE) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "listener is not in idle status.");
        return SOFTBUS_ERR;
    }
    g_listenerList[module].info->status = LISTENER_PREPARED;
    ret = PrepareBaseListener(module, CLIENT_MODE);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "StartBaseClient %s",
        (ret == SOFTBUS_OK) ? "SUCCESS" : "FAILED");

    return ret;
}

int32_t StartBaseListener(ListenerModule module, const char *ip, int32_t port, ModeType modeType)
{
    if (CheckModule(module) != SOFTBUS_OK || port < 0 || ip == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret;

    g_listenerList[module].module = module;
    if (g_listenerList[module].listener == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BaseListener not set, start failed.");
        return SOFTBUS_ERR;
    }
    if (g_listenerList[module].info == NULL) {
        g_listenerList[module].info = CreateNewListenerInfo();
        if (g_listenerList[module].info == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "malloc listenerInfo err");
            return SOFTBUS_MALLOC_ERR;
        }
        pthread_mutexattr_t mutexAttr;
        pthread_mutexattr_init(&mutexAttr);
        pthread_mutexattr_settype(&mutexAttr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&g_listenerList[module].lock, &mutexAttr);
    }
    if (g_listenerList[module].info->status != LISTENER_IDLE) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "listener is not in idle status.");
        return SOFTBUS_ERR;
    }
    ret = InitListenFd(module, ip, port);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "InitListenFd failed");
        return ret;
    }
    g_listenerList[module].info->status = LISTENER_PREPARED;
    ret = PrepareBaseListener(module, modeType);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "StartBaseListener success");

    return g_listenerList[module].info->listenPort;
}

int32_t GetSoftbusBaseListener(ListenerModule module, SoftbusBaseListener *listener)
{
    if (CheckModule(module) != SOFTBUS_OK || listener == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_listenerList[module].lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (g_listenerList[module].listener != NULL) {
        if (memcpy_s(listener, sizeof(SoftbusBaseListener), g_listenerList[module].listener,
            sizeof(SoftbusBaseListener)) != EOK) {
            pthread_mutex_unlock(&g_listenerList[module].lock);
            return SOFTBUS_MEM_ERR;
        }
    } else {
        SoftBusFree(listener);
    }
    pthread_mutex_unlock(&g_listenerList[module].lock);
    return SOFTBUS_OK;
}

int32_t SetSoftbusBaseListener(ListenerModule module, const SoftbusBaseListener *listener)
{
    if (CheckModule(module) != SOFTBUS_OK || listener == NULL ||
        listener->onConnectEvent == NULL || listener->onDataEvent == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_listenerList[module].lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (g_listenerList[module].listener == NULL) {
        g_listenerList[module].listener = (SoftbusBaseListener *)SoftBusCalloc(sizeof(SoftbusBaseListener));
        if (g_listenerList[module].listener == NULL) {
            pthread_mutex_unlock(&g_listenerList[module].lock);
            return SOFTBUS_MALLOC_ERR;
        }
    }
    if (memcpy_s(g_listenerList[module].listener, sizeof(SoftbusBaseListener),
        listener, sizeof(SoftbusBaseListener)) != EOK) {
        pthread_mutex_unlock(&g_listenerList[module].lock);
        return SOFTBUS_MEM_ERR;
    }
    pthread_mutex_unlock(&g_listenerList[module].lock);
    return SOFTBUS_OK;
}

int32_t StopBaseListener(ListenerModule module)
{
    if (CheckModule(module) != SOFTBUS_OK) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_listenerList[module].lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SoftbusBaseListenerInfo *listenerInfo = g_listenerList[module].info;
    if (listenerInfo == NULL) {
        pthread_mutex_unlock(&g_listenerList[module].lock);
        return SOFTBUS_ERR;
    }
    if (listenerInfo->status != LISTENER_RUNNING) {
        listenerInfo->status = LISTENER_IDLE;
        pthread_mutex_unlock(&g_listenerList[module].lock);
        return SOFTBUS_OK;
    }
    listenerInfo->status = LISTENER_IDLE;
    if (listenerInfo->listenFd > 0) {
        TcpShutDown(listenerInfo->listenFd);
    }
    listenerInfo->listenFd = -1;
    pthread_mutex_unlock(&g_listenerList[module].lock);

    UpdateMaxFd();
    return SOFTBUS_OK;
}

void DestroyBaseListener(ListenerModule module)
{
    if (CheckModule(module) != SOFTBUS_OK) {
        return;
    }
    ResetBaseListener(module);
    if (pthread_mutex_lock(&g_listenerList[module].lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return;
    }
    if (g_listenerList[module].info != NULL) {
        SoftBusFree(g_listenerList[module].info);
        g_listenerList[module].info = NULL;
    }
    if (g_listenerList[module].listener != NULL) {
        SoftBusFree(g_listenerList[module].listener);
        g_listenerList[module].listener = NULL;
    }
    pthread_mutex_unlock(&g_listenerList[module].lock);
}

static int32_t AddTriggerToSet(int32_t fd, TriggerType triggerType)
{
    int32_t ret = SOFTBUS_OK;
    if (pthread_mutex_lock(&g_fdSetLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_ERR;
    }
    switch (triggerType) {
        case READ_TRIGGER:
            FD_SET(fd, &g_readSet);
            break;
        case WRITE_TRIGGER:
            FD_SET(fd, &g_writeSet);
            break;
        case EXCEPT_TRIGGER:
            FD_SET(fd, &g_exceptSet);
            break;
        case RW_TRIGGER:
            FD_SET(fd, &g_readSet);
            FD_SET(fd, &g_writeSet);
            break;
        default:
            ret = SOFTBUS_INVALID_PARAM;
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Invalid trigger type");
            break;
    }
    pthread_mutex_unlock(&g_fdSetLock);

    return ret;
}

static int32_t DelTriggerFromSet(int32_t fd, TriggerType triggerType)
{
    int32_t ret = SOFTBUS_OK;
    if (pthread_mutex_lock(&g_fdSetLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_ERR;
    }
    switch (triggerType) {
        case READ_TRIGGER:
            FD_CLR(fd, &g_readSet);
            break;
        case WRITE_TRIGGER:
            FD_CLR(fd, &g_writeSet);
            break;
        case EXCEPT_TRIGGER:
            FD_CLR(fd, &g_exceptSet);
            break;
        case RW_TRIGGER:
            FD_CLR(fd, &g_readSet);
            FD_CLR(fd, &g_writeSet);
            break;
        default:
            ret = SOFTBUS_INVALID_PARAM;
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Invalid trigger type");
            break;
    }
    pthread_mutex_unlock(&g_fdSetLock);

    return ret;
}

static bool CheckFdIsExist(SoftbusBaseListenerInfo *info, int32_t fd)
{
    FdNode *item = NULL;
    FdNode *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &info->node, FdNode, node) {
        if (item->fd == fd) {
            return true;
        }
    }
    return false;
}

static int32_t AddNewFdNode(SoftbusBaseListenerInfo *info, int32_t fd)
{
    FdNode *newNode = (FdNode *)SoftBusCalloc(sizeof(FdNode));
    if (newNode == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    newNode->fd = fd;
    ListInit(&newNode->node);
    ListNodeInsert(&info->node, &newNode->node);
    info->fdCount++;
    return SOFTBUS_OK;
}

static void DelFdNode(SoftbusBaseListenerInfo *info, int32_t fd)
{
    FdNode *item = NULL;
    FdNode *nextItem = NULL;

    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &info->node, FdNode, node) {
        if (item->fd == fd) {
            ListDelete(&item->node);
            SoftBusFree(item);
            info->fdCount--;
            return;
        }
    }
}

int32_t AddTrigger(ListenerModule module, int32_t fd, TriggerType triggerType)
{
    if (CheckModule(module) != SOFTBUS_OK || fd < 0 || CheckTrigger(triggerType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Invalid AddTrigger Param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&g_listenerList[module].lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SoftbusBaseListenerInfo *info = g_listenerList[module].info;
    if (info == NULL || info->fdCount > MAX_LISTEN_EVENTS) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Cannot AddTrigger any more");
        pthread_mutex_unlock(&g_listenerList[module].lock);
        return SOFTBUS_ERR;
    }

    if (AddTriggerToSet(fd, triggerType) != SOFTBUS_OK) {
        pthread_mutex_unlock(&g_listenerList[module].lock);
        return SOFTBUS_ERR;
    }

    if (CheckFdIsExist(info, fd)) {
        pthread_mutex_unlock(&g_listenerList[module].lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "fd exist");
        return SOFTBUS_OK;
    }

    if (AddNewFdNode(info, fd) != SOFTBUS_OK) {
        (void)DelTriggerFromSet(fd, triggerType);
        pthread_mutex_unlock(&g_listenerList[module].lock);
        return SOFTBUS_ERR;
    }
    pthread_mutex_unlock(&g_listenerList[module].lock);

    if (pthread_mutex_lock(&g_fdSetLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_OK;
    }
    g_maxFd = MaxFd(fd, g_maxFd);
    pthread_mutex_unlock(&g_fdSetLock);

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "AddTrigger fd:%d success, current fdcount:%d, module:%d, triggerType:%d",
        fd, info->fdCount, module, triggerType);
    return SOFTBUS_OK;
}

int32_t DelTrigger(ListenerModule module, int32_t fd, TriggerType triggerType)
{
    if (CheckModule(module) != SOFTBUS_OK || fd < 0 || CheckTrigger(triggerType)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Invalid AddTrigger Param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_listenerList[module].lock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SoftbusBaseListenerInfo *info = g_listenerList[module].info;
    if (info == NULL) {
        pthread_mutex_unlock(&g_listenerList[module].lock);
        return SOFTBUS_ERR;
    }

    if (DelTriggerFromSet(fd, triggerType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
            "del trigger fail: fd = %d, trigger = %d", fd, triggerType);
    }

    if (FD_ISSET(fd, &g_writeSet) || FD_ISSET(fd, &g_readSet) || FD_ISSET(fd, &g_exceptSet)) {
        pthread_mutex_unlock(&g_listenerList[module].lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
            "DelTrigger [fd:%d] success, current fdcount:%d, triggerType:%d",
            fd, info->fdCount, triggerType);
        return SOFTBUS_OK;
    }

    DelFdNode(info, fd);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "DelTrigger and node [fd:%d] success, current fdcount:%d, triggerType:%d",
        fd, info->fdCount, triggerType);
    pthread_mutex_unlock(&g_listenerList[module].lock);
    UpdateMaxFd();

    return SOFTBUS_OK;
}
