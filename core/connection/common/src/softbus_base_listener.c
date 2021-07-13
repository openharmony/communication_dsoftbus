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
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"
#include "softbus_tcp_socket.h"
#include "softbus_thread_pool.h"
#include "softbus_utils.h"

#define MAX_LISTEN_EVENTS 1024
#define TIMEOUT 500
#define DEFAULT_BACKLOG 4

#define CLIENT_THREADNUM 1
#define CLIENT_QUEUE_NUM 10

#define SERVER_THREADNUM 1
#define SERVER_QUEUE_NUM 10

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
    fd_set readSet;
    fd_set writeSet;
    fd_set exceptSet;
    struct timeval tv;
    int32_t listenFd;
    char ip[IP_LEN];
    int32_t listenPort;
    int32_t fdCount;
    int32_t maxFd;
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

static int32_t InitListenFd(ListenerModule module, const char *ip, int32_t port);
static int32_t OnEvent(ListenerModule module, int32_t fd, uint32_t events);
static void ProcessData(ListenerModule module, fd_set *readSet,
    fd_set *writeSet, fd_set *exceptSet);
static int32_t PrepareBaseListener(ListenerModule module, ModeType modeType);
static int32_t CheckModule(ListenerModule module);

static int32_t FdCopy(const fd_set *dest, const fd_set *src)
{
    return memcpy_s((void *)dest, sizeof(fd_set), (void *)src, sizeof(fd_set));
}

static int32_t MaxFd(int32_t fd1, int32_t fd2)
{
    return (fd1 > fd2) ? fd1 : fd2;
}

static int32_t CheckModule(ListenerModule module)
{
    if (module >= UNUSE_BUTT || module < PROXY) {
        LOG_ERR("Invalid listener module.");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static int32_t CheckTrigger(TriggerType triggerType)
{
    if (triggerType < READ_TRIGGER || triggerType > RW_TRIGGER) {
        LOG_ERR("Invalid listener trigger type.");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static void ClearListenerFdList(const ListNode *cfdList)
{
    FdNode *item = NULL;
    while (!IsListEmpty(cfdList)) {
        item = LIST_ENTRY(cfdList->next, FdNode, node);
        ListDelete(&item->node);
        SoftBusFree(item);
    }
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
        LOG_ERR("OpenTcpServer failed, rc=%d errno=%d", rc, errno);
        return SOFTBUS_TCP_SOCKET_ERR;
    }
    listenerInfo->listenFd = rc;
    rc = listen(listenerInfo->listenFd, DEFAULT_BACKLOG);
    if (rc != 0) {
        LOG_ERR("listen failed, rc=%d errno=%d", rc, errno);
        ResetBaseListener(module);
        return SOFTBUS_TCP_SOCKET_ERR;
    }
    listenerInfo->fdCount = 1;
    listenerInfo->listenPort = GetTcpSockPort(listenerInfo->listenFd);
    if (memcpy_s(listenerInfo->ip, IP_LEN, ip, IP_LEN) != EOK) {
        LOG_ERR("Copy ip failed");
        ResetBaseListener(module);
        return SOFTBUS_MEM_ERR;
    }
    if (listenerInfo->listenPort < 0) {
        LOG_ERR("GetSockPort failed, listenPort_=%d", listenerInfo->listenPort);
        ResetBaseListener(module);
        return SOFTBUS_ERR;
    }
    FD_SET(listenerInfo->listenFd, &listenerInfo->readSet);
    listenerInfo->maxFd = MaxFd(listenerInfo->listenFd, listenerInfo->maxFd);
    return SOFTBUS_OK;
}

void ResetBaseListener(ListenerModule module)
{
    if (CheckModule(module) != SOFTBUS_OK) {
        return;
    }
    if (pthread_mutex_lock(&g_listenerList[module].lock) != 0) {
        LOG_ERR("lock failed");
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
    FD_ZERO(&listenerInfo->readSet);
    FD_ZERO(&listenerInfo->writeSet);
    FD_ZERO(&listenerInfo->exceptSet);
    listenerInfo->status = LISTENER_IDLE;
    listenerInfo->modeType = UNSET_MODE;
    listenerInfo->fdCount = 0;
    listenerInfo->maxFd = 0;
    ClearListenerFdList(&listenerInfo->node);
    pthread_mutex_unlock(&g_listenerList[module].lock);
}

void ResetBaseListenerSet(ListenerModule module)
{
    if (CheckModule(module) != SOFTBUS_OK) {
        return;
    }
    if (pthread_mutex_lock(&g_listenerList[module].lock) != 0) {
        LOG_ERR("lock failed");
        return;
    }
    SoftbusBaseListenerInfo *listenerInfo = g_listenerList[module].info;
    if (listenerInfo == NULL) {
        pthread_mutex_unlock(&g_listenerList[module].lock);
        return;
    }
    FD_ZERO(&listenerInfo->readSet);
    FD_ZERO(&listenerInfo->writeSet);
    FD_ZERO(&listenerInfo->exceptSet);
    ClearListenerFdList(&listenerInfo->node);
    listenerInfo->fdCount = 0;
    pthread_mutex_unlock(&g_listenerList[module].lock);
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
            LOG_ERR("memset failed");
            return SOFTBUS_ERR;
        }
        socklen_t addrLen = sizeof(addr);
        int32_t cfd = TEMP_FAILURE_RETRY(accept(fd, (struct sockaddr *)&addr, &addrLen));
        if (cfd < 0) {
            LOG_ERR("accept failed, cfd=%d, errno=%d", cfd, errno);
            return SOFTBUS_TCP_SOCKET_ERR;
        }
        char ip[IP_LEN] = {0};
        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
        if (listener->onConnectEvent != NULL) {
            listener->onConnectEvent(events, cfd, ip);
        } else {
            LOG_ERR("Please set onConnectEvent callback");
        }
    } else {
        if (listener->onDataEvent != NULL) {
            listener->onDataEvent(events, fd);
        } else {
            LOG_ERR("Please set onDataEvent callback");
        }
    }
    return SOFTBUS_OK;
}

static void ProcessData(ListenerModule module, fd_set *readSet,
    fd_set *writeSet, fd_set *exceptSet)
{
    if (CheckModule(module) != SOFTBUS_OK) {
        return;
    }
    SoftbusBaseListenerInfo *listenerInfo = g_listenerList[module].info;
    if (listenerInfo == NULL) {
        return;
    }
    FdNode *item = NULL;
    if ((listenerInfo->listenFd > 0) && FD_ISSET(listenerInfo->listenFd, readSet)) {
        OnEvent(module, listenerInfo->listenFd, SOFTBUS_SOCKET_IN);
        return;
    }
    LIST_FOR_EACH_ENTRY(item, &listenerInfo->node, FdNode, node) {
        if (FD_ISSET(item->fd, readSet)) {
            OnEvent(module, item->fd, SOFTBUS_SOCKET_IN);
            return;
        }
    }
    LIST_FOR_EACH_ENTRY(item, &listenerInfo->node, FdNode, node) {
        if (FD_ISSET(item->fd, writeSet)) {
            OnEvent(module, item->fd, SOFTBUS_SOCKET_OUT);
            return;
        }
    }
    LIST_FOR_EACH_ENTRY(item, &listenerInfo->node, FdNode, node) {
        if (FD_ISSET(item->fd, exceptSet)) {
            OnEvent(module, item->fd, SOFTBUS_SOCKET_EXCEPTION);
            return;
        }
    }
}

static int32_t SetSelect(ListenerModule module, fd_set *readSet, fd_set *writeSet, fd_set *exceptSet)
{
    if (CheckModule(module) != SOFTBUS_OK) {
        return SOFTBUS_INVALID_PARAM;
    }
    SoftbusBaseListenerInfo *listenerInfo = g_listenerList[module].info;
    if (listenerInfo == NULL) {
        return SOFTBUS_ERR;
    }
    FdNode *item = NULL;
    listenerInfo->maxFd = listenerInfo->listenFd;
    FD_ZERO(readSet);
    FD_ZERO(writeSet);
    FD_ZERO(exceptSet);
    if (listenerInfo->listenFd > 0) {
        FD_SET(listenerInfo->listenFd, readSet);
    }
    LIST_FOR_EACH_ENTRY(item, &listenerInfo->node, FdNode, node) {
        listenerInfo->maxFd = MaxFd(item->fd, listenerInfo->maxFd);
    }
    if (FdCopy(readSet, &listenerInfo->readSet) != EOK) {
        goto EXIT;
    }
    if (FdCopy(writeSet, &listenerInfo->writeSet) != EOK) {
        goto EXIT;
    }
    if (FdCopy(exceptSet, &listenerInfo->exceptSet) != EOK) {
        goto EXIT;
    }
    return SOFTBUS_OK;

EXIT:
    FD_ZERO(readSet);
    FD_ZERO(writeSet);
    FD_ZERO(exceptSet);
    return SOFTBUS_MEM_ERR;
}

static int32_t SelectThread(const SoftbusListenerNode *node)
{
    if (node == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    ListenerModule module = node->module;
    if (CheckModule(node->module) != SOFTBUS_OK) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_listenerList[module].lock) != 0) {
        LOG_ERR("lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SoftbusBaseListenerInfo *listenerInfo = g_listenerList[module].info;
    if (listenerInfo == NULL || listenerInfo->status != LISTENER_RUNNING) {
        pthread_mutex_unlock(&g_listenerList[module].lock);
        return SOFTBUS_ERR;
    }
    fd_set readSet;
    fd_set writeSet;
    fd_set exceptSet;
    if (SetSelect(module, &readSet, &writeSet, &exceptSet) != SOFTBUS_OK) {
        LOG_ERR("select failed with invalid listener");
        pthread_mutex_unlock(&g_listenerList[module].lock);
        return SOFTBUS_ERR;
    }
    int32_t nEvents = select(listenerInfo->maxFd + 1, &readSet, &writeSet,
        &exceptSet, &listenerInfo->tv);
    if (nEvents < 0) {
        LOG_ERR("select failed, errno=%d", errno);
        pthread_mutex_unlock(&g_listenerList[module].lock);
        return SOFTBUS_TCP_SOCKET_ERR;
    } else if (nEvents == 0) {
        pthread_mutex_unlock(&g_listenerList[module].lock);
        return SOFTBUS_OK;
    } else {
        ProcessData(module, &readSet, &writeSet, &exceptSet);
        pthread_mutex_unlock(&g_listenerList[module].lock);
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
            &g_listenerList[module], PERSISTENT, (uintptr_t)module);
    } else if (modeType == CLIENT_MODE) {
        return ThreadPoolAddJob(g_clientPool, (int(*)(void *))SelectThread,
            &g_listenerList[module], PERSISTENT, (uintptr_t)module);
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
    if (StartThread(module, modeType) != SOFTBUS_OK) {
        LOG_ERR("StartThread failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static SoftbusBaseListenerInfo *CreateNewListenerInfo(void)
{
    SoftbusBaseListenerInfo *listenerInfo = (SoftbusBaseListenerInfo *)SoftBusCalloc(sizeof(SoftbusBaseListenerInfo));
    if (listenerInfo == NULL) {
        LOG_ERR("Malloc error");
        return NULL;
    }
    listenerInfo->tv.tv_sec = 0;
    listenerInfo->tv.tv_usec = TIMEOUT;
    listenerInfo->maxFd = 0;
    listenerInfo->modeType = UNSET_MODE;
    listenerInfo->fdCount = 0;
    listenerInfo->listenFd = -1;
    listenerInfo->listenPort = -1;
    listenerInfo->status = LISTENER_IDLE;
    ListInit(&listenerInfo->node);
    FD_ZERO(&listenerInfo->readSet);
    FD_ZERO(&listenerInfo->writeSet);
    FD_ZERO(&listenerInfo->exceptSet);
    return listenerInfo;
}

int32_t StartBaseClient(ListenerModule module)
{
    if (CheckModule(module) != SOFTBUS_OK) {
        return SOFTBUS_INVALID_PARAM;
    }
    g_listenerList[module].module = module;
    if (g_listenerList[module].listener == NULL) {
        LOG_ERR("BaseListener not set, start failed.");
        return SOFTBUS_ERR;
    }
    if (g_listenerList[module].info == NULL) {
        g_listenerList[module].info = CreateNewListenerInfo();
        if (g_listenerList[module].info == NULL) {
            LOG_ERR("malloc listenerInfo err");
            return SOFTBUS_MALLOC_ERR;
        }
        pthread_mutexattr_t mutexAttr;
        pthread_mutexattr_init(&mutexAttr);
        pthread_mutexattr_settype(&mutexAttr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&g_listenerList[module].lock, &mutexAttr);
    }
    if (g_listenerList[module].info->status != LISTENER_IDLE) {
        LOG_ERR("listener is not in idle status.");
        return SOFTBUS_ERR;
    }
    g_listenerList[module].info->status = LISTENER_PREPARED;
    return PrepareBaseListener(module, CLIENT_MODE);
}

int32_t StartBaseListener(ListenerModule module, const char *ip, int32_t port, ModeType modeType)
{
    if (CheckModule(module) != SOFTBUS_OK || port < 0 || ip == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret;
    g_listenerList[module].module = module;
    if (g_listenerList[module].listener == NULL) {
        LOG_ERR("BaseListener not set, start failed.");
        return SOFTBUS_ERR;
    }
    if (g_listenerList[module].info == NULL) {
        g_listenerList[module].info = CreateNewListenerInfo();
        if (g_listenerList[module].info == NULL) {
            LOG_ERR("malloc listenerInfo err");
            return SOFTBUS_MALLOC_ERR;
        }
        pthread_mutexattr_t mutexAttr;
        pthread_mutexattr_init(&mutexAttr);
        pthread_mutexattr_settype(&mutexAttr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&g_listenerList[module].lock, &mutexAttr);
    }
    if (g_listenerList[module].info->status != LISTENER_IDLE) {
        LOG_ERR("listener is not in idle status.");
        return SOFTBUS_ERR;
    }
    ret = InitListenFd(module, ip, port);
    if (ret != SOFTBUS_OK) {
        LOG_ERR("InitListenFd failed");
        return ret;
    }
    g_listenerList[module].info->status = LISTENER_PREPARED;
    ret = PrepareBaseListener(module, modeType);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return g_listenerList[module].info->listenPort;
}

int32_t GetSoftbusBaseListener(ListenerModule module, SoftbusBaseListener *listener)
{
    if (CheckModule(module) != SOFTBUS_OK || listener == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_listenerList[module].lock) != 0) {
        LOG_ERR("lock failed");
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
        LOG_ERR("lock failed");
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
        LOG_ERR("lock failed");
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
    pthread_mutex_unlock(&g_listenerList[module].lock);

    if (listenerInfo->modeType == SERVER_MODE) {
        return ThreadPoolRemoveJob(g_serverPool, (uintptr_t)module);
    } else if (listenerInfo->modeType == CLIENT_MODE) {
        return ThreadPoolRemoveJob(g_clientPool, (uintptr_t)module);
    } else {
        LOG_ERR("No such thread pool type.");
        return SOFTBUS_INVALID_PARAM;
    }
}

void DestroyBaseListener(ListenerModule module)
{
    if (CheckModule(module) != SOFTBUS_OK) {
        return;
    }
    ResetBaseListener(module);
    if (pthread_mutex_lock(&g_listenerList[module].lock) != 0) {
        LOG_ERR("lock failed");
        return;
    }
    SoftBusFree(g_listenerList[module].info);
    SoftBusFree(g_listenerList[module].listener);
    g_listenerList[module].info = NULL;
    g_listenerList[module].listener = NULL;
    pthread_mutex_unlock(&g_listenerList[module].lock);
}

static void OnAddTrigger(fd_set *set, int32_t fd)
{
    FD_SET(fd, set);
}

static void OnDelTrigger(fd_set *set, int32_t fd)
{
    FD_CLR(fd, set);
}

static int32_t AddTriggerToSet(SoftbusBaseListenerInfo *info, int32_t fd, TriggerType triggerType)
{
    int32_t ret = SOFTBUS_OK;
    switch (triggerType) {
        case READ_TRIGGER:
            OnAddTrigger(&info->readSet, fd);
            break;
        case WRITE_TRIGGER:
            OnAddTrigger(&info->writeSet, fd);
            break;
        case EXCEPT_TRIGGER:
            OnAddTrigger(&info->exceptSet, fd);
            break;
        case RW_TRIGGER:
            OnAddTrigger(&info->readSet, fd);
            OnAddTrigger(&info->writeSet, fd);
            break;
        default:
            ret = SOFTBUS_INVALID_PARAM;
            LOG_ERR("Invalid trigger type");
            break;
    }

    return ret;
}

static int32_t DelTriggerFromSet(SoftbusBaseListenerInfo *info, int32_t fd, TriggerType triggerType)
{
    int32_t ret = SOFTBUS_OK;
    switch (triggerType) {
        case READ_TRIGGER:
            OnDelTrigger(&info->readSet, fd);
            break;
        case WRITE_TRIGGER:
            OnDelTrigger(&info->writeSet, fd);
            break;
        case EXCEPT_TRIGGER:
            OnDelTrigger(&info->exceptSet, fd);
            break;
        case RW_TRIGGER:
            OnDelTrigger(&info->readSet, fd);
            OnDelTrigger(&info->writeSet, fd);
            break;
        default:
            ret = SOFTBUS_INVALID_PARAM;
            LOG_ERR("Invalid trigger type");
            break;
    }

    return ret;
}

static bool CheckFdIsExist(SoftbusBaseListenerInfo *info, int32_t fd)
{
    FdNode *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &info->node, FdNode, node) {
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
    LIST_FOR_EACH_ENTRY(item, &info->node, FdNode, node) {
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
        LOG_ERR("Invalid AddTrigger Param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&g_listenerList[module].lock) != 0) {
        LOG_ERR("lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SoftbusBaseListenerInfo *info = g_listenerList[module].info;
    if (info == NULL || info->fdCount > MAX_LISTEN_EVENTS) {
        LOG_ERR("Cannot AddTrigger any more");
        pthread_mutex_unlock(&g_listenerList[module].lock);
        return SOFTBUS_ERR;
    }

    if (AddTriggerToSet(info, fd, triggerType) != SOFTBUS_OK) {
        pthread_mutex_unlock(&g_listenerList[module].lock);
        return SOFTBUS_ERR;
    }

    if (CheckFdIsExist(info, fd)) {
        pthread_mutex_unlock(&g_listenerList[module].lock);
        return SOFTBUS_OK;
    }

    if (AddNewFdNode(info, fd) != SOFTBUS_OK) {
        (void)DelTriggerFromSet(info, fd, triggerType);
        pthread_mutex_unlock(&g_listenerList[module].lock);
        return SOFTBUS_ERR;
    }

    pthread_mutex_unlock(&g_listenerList[module].lock);
    LOG_INFO("AddTrigger fd:%d success, current fdcount:%d", fd, info->fdCount);
    return SOFTBUS_OK;
}

int32_t DelTrigger(ListenerModule module, int32_t fd, TriggerType triggerType)
{
    if (CheckModule(module) != SOFTBUS_OK || fd < 0 || CheckTrigger(triggerType)) {
        LOG_ERR("Invalid AddTrigger Param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_listenerList[module].lock) != 0) {
        LOG_ERR("lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    SoftbusBaseListenerInfo *info = g_listenerList[module].info;
    if (info == NULL) {
        pthread_mutex_unlock(&g_listenerList[module].lock);
        return SOFTBUS_ERR;
    }

    if (DelTriggerFromSet(info, fd, triggerType) != SOFTBUS_OK) {
        LOG_ERR("del trigger fail: fd = %d, trigger = %d", fd, triggerType);
    }

    if (!FD_ISSET(fd, &info->writeSet) && !FD_ISSET(fd, &info->readSet) && !FD_ISSET(fd, &info->exceptSet)) {
        DelFdNode(info, fd);
    }

    pthread_mutex_unlock(&g_listenerList[module].lock);
    LOG_INFO("DelTrigger fd:%d success, current fdcount:%d", fd, info->fdCount);
    return SOFTBUS_OK;
}