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

#include <securec.h>
#include <unistd.h>

#include "common_list.h"
#include "softbus_adapter_errcode.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_log.h"
#include "softbus_socket.h"
#include "softbus_thread_pool.h"
#include "softbus_utils.h"

#define MAX_LISTEN_EVENTS 1024
#define TIMEOUT           10000
#define DEFAULT_BACKLOG   4
#define FDARR_START_SIZE  16
#define FDARR_EXPAND_BASE 2

#define THREADPOOL_THREADNUM 1
#define THREADPOOL_QUEUE_NUM 10

typedef struct {
    ListNode node;
    int32_t fd;
} FdNode;

enum BaseListenerStatus {
    LISTENER_IDLE = 0,
    LISTENER_RUNNING,
    LISTENER_CLOSEING,
};

typedef struct {
    ListNode node;
    LocalListenerInfo listenerInfo;
    int32_t listenFd;
    int32_t listenPort;
    int32_t fdCount;
    ModeType modeType;
    enum BaseListenerStatus status;
} SoftbusBaseListenerInfo;

typedef struct {
    ListenerModule module;
    SoftbusBaseListener *listener;
    const SocketInterface *socketIf;
    SoftbusBaseListenerInfo info;
    uint32_t ref;
    SoftBusMutex lock;
} SoftbusListenerNode;

static SoftbusListenerNode *g_listenerList[UNUSE_BUTT] = {0};
static SoftBusMutex g_listenerListLock;


static SoftBusMutex g_threadLock;
static int32_t g_threadRefCount = 0;

static ThreadPool *g_threadPool = NULL;
static SoftBusFdSet g_readSet;
static SoftBusFdSet g_writeSet;
static SoftBusFdSet g_exceptSet;
static int32_t g_maxFd;
static SoftBusMutex g_fdSetLock;

static void ReleaseListenerSockets(SoftbusListenerNode* node);
static void UpdateMaxFd(void);
static void ClearListenerFdList(const ListNode *cfdList);
static void InitListenerInfo(SoftbusBaseListenerInfo *listenerInfo);
static int32_t ShutdownBaseListener(SoftbusListenerNode *node);
static int32_t StopListenerThread(SoftbusListenerNode *node);

static SoftbusListenerNode *RequestListenerNode(ListenerModule module)
{
    if (module >= UNUSE_BUTT) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:Invalid listener module.", __func__);
        return NULL;
    }
    int32_t ret = SoftBusMutexLock(&g_listenerListLock);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s: lock g_listenerListLock failed!.", __func__);
        return NULL;
    }

    SoftbusListenerNode *node = g_listenerList[module];
    do {
        if (node == NULL) {
            break;
        }
        if (node->info.status == LISTENER_CLOSEING) {
            node = NULL;
            break;
        }
        ret = SoftBusMutexLock(&node->lock);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s: lock node failed!.", __func__);
            node = NULL;
            break;
        }
        node->ref++;
        SoftBusMutexUnlock(&node->lock);
    } while (false);

    (void)SoftBusMutexUnlock(&g_listenerListLock);
    return node;
}

static void ReleaseListenerSockets(SoftbusListenerNode *node)
{
    if (SoftBusMutexLock(&node->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        return;
    }
    if (node->info.listenFd >= 0) {
        ConnShutdownSocket(node->info.listenFd);
    }
    node->info.listenFd = -1;
    node->info.listenPort = -1;
    node->info.modeType = UNSET_MODE;
    node->info.fdCount = 0;
    ClearListenerFdList(&(node->info.node));
    SoftBusMutexUnlock(&node->lock);
    UpdateMaxFd();
}

// Node: get g_listenerListLock first
static int32_t ReleaseListenerRef(ListenerModule module)
{
    SoftbusListenerNode *node = g_listenerList[module];
    if (node == NULL) {
        return SOFTBUS_NOT_FIND;
    }
    int32_t ret = SoftBusMutexLock(&node->lock);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        return ret;
    }
    node->ref--;

    if (node->ref == 0) {
        g_listenerList[module] = NULL;

        if (node->listener != NULL) {
            SoftBusFree(node->listener);
            node->listener = NULL;
        }
        ReleaseListenerSockets(node);
        (void)StopListenerThread(node);
        (void)SoftBusMutexUnlock(&node->lock);
        (void)SoftBusMutexDestroy(&node->lock);
        SoftBusFree(node);
    } else {
        (void)SoftBusMutexUnlock(&node->lock);
    }

    return SOFTBUS_OK;
}

static void ReleaseListenerNode(SoftbusListenerNode *node)
{
    if (node == NULL || node->module >= UNUSE_BUTT) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Invalid listener module.");
        return;
    }
    int32_t ret = SoftBusMutexLock(&g_listenerListLock);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s: lock g_listenerListLock failed!.", __func__);
        return;
    }

    ret = ReleaseListenerRef(node->module);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s: release node failed!.", __func__);
    }
    (void)SoftBusMutexUnlock(&g_listenerListLock);
}

// Node: get g_listenerListLock first
static int32_t CreateSpecifiedListenerModule(ListenerModule module)
{
    SoftbusListenerNode *node = (SoftbusListenerNode *)SoftBusCalloc(sizeof(SoftbusListenerNode));
    if (node == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:oom!", __func__);
        return SOFTBUS_MALLOC_ERR;
    }

    // init lock
    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    if (SoftBusMutexInit(&node->lock, &mutexAttr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:init lock failed!", __func__);
        SoftBusFree(node);
        return SOFTBUS_LOCK_ERR;
    }
    InitListenerInfo(&node->info);

    node->module = module;
    node->ref = 1;

    g_listenerList[module] = node;
    return SOFTBUS_OK;
}

static int32_t CreateStaticModules(void)
{
    for (uint32_t i = 0; i < LISTENER_MODULE_DYNAMIC_START; i++) {
        int32_t ret = CreateSpecifiedListenerModule((ListenerModule)i);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s: create module %" PRIu32 " failed!ret=" PRId32,
                __func__, i, ret);
            return ret;
        }
    }
    return SOFTBUS_OK;
}

uint32_t CreateListenerModule(void)
{
    uint32_t moduleId = UNUSE_BUTT;
    int32_t ret = SoftBusMutexLock(&g_listenerListLock);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s: lock g_listenerListLock failed!.", __func__);
        return moduleId;
    }

    for (uint32_t i = LISTENER_MODULE_DYNAMIC_START; i <= LISTENER_MODULE_DYNAMIC_END; i++) {
        if (g_listenerList[i] != NULL) {
            continue;
        }
        ret = CreateSpecifiedListenerModule((ListenerModule)i);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s: create module %" PRIu32 " failed!ret=" PRId32,
                __func__, i, ret);
            break;
        }
        moduleId = i;
        break;
    }

    (void)SoftBusMutexUnlock(&g_listenerListLock);
    return moduleId;
}

int32_t InitBaseListener(void)
{
    int32_t ret = SoftBusMutexInit(&g_fdSetLock, NULL);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "g_fdSetLock init failed.ret=%" PRId32, ret);
        return ret;
    }

    ret = SoftBusMutexInit(&g_listenerListLock, NULL);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "g_listenerListLock init failed.ret=%" PRId32, ret);
        (void)SoftBusMutexDestroy(&g_fdSetLock);
        return ret;
    }

    ret = SoftBusMutexInit(&g_threadLock, NULL);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "g_threadLock init failed.ret=%" PRId32, ret);
        (void)SoftBusMutexDestroy(&g_listenerListLock);
        (void)SoftBusMutexDestroy(&g_fdSetLock);
        return ret;
    }

    g_threadPool = ThreadPoolInit(THREADPOOL_THREADNUM, THREADPOOL_QUEUE_NUM);
    if (g_threadPool == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Init thread pool failed.");
        (void)SoftBusMutexDestroy(&g_fdSetLock);
        (void)SoftBusMutexDestroy(&g_listenerListLock);
        return SOFTBUS_MALLOC_ERR;
    }

    (void)memset_s(g_listenerList, sizeof(g_listenerList), 0, sizeof(g_listenerList));

    SoftBusSocketFdZero(&g_readSet);
    SoftBusSocketFdZero(&g_writeSet);
    SoftBusSocketFdZero(&g_exceptSet);

    ret = CreateStaticModules();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Create static listener module failed! ret=%" PRId32, ret);
        (void)ThreadPoolDestroy(g_threadPool);
        (void)SoftBusMutexDestroy(&g_fdSetLock);
        (void)SoftBusMutexDestroy(&g_listenerListLock);
        return ret;
    }
    return SOFTBUS_OK;
}

void DeinitBaseListener(void)
{
    int32_t ret = SoftBusMutexLock(&g_listenerListLock);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:get lock failed!ret=%" PRId32, __func__, ret);
        return;
    }

    for (uint32_t i = 0; i < UNUSE_BUTT; i++) {
        (void)ShutdownBaseListener(g_listenerList[i]);
        (void)ReleaseListenerRef((ListenerModule)i);
        g_listenerList[i] = NULL;
    }

    if (g_threadPool != NULL) {
        ret = ThreadPoolDestroy(g_threadPool);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Destroy thread pool failed.ret=%" PRId32, ret);
        }
    }

    (void)SoftBusMutexUnlock(&g_listenerListLock);
    (void)SoftBusMutexDestroy(&g_listenerListLock);
    (void)SoftBusMutexDestroy(&g_fdSetLock);
    (void)SoftBusMutexDestroy(&g_threadLock);
}

static int32_t FdCopy(const SoftBusFdSet *dest, const SoftBusFdSet *src)
{
    return memcpy_s((void *)dest, sizeof(SoftBusFdSet), (void *)src, sizeof(SoftBusFdSet));
}

static int32_t MaxFd(int32_t fd1, int32_t fd2)
{
    return (fd1 > fd2) ? fd1 : fd2;
}

static void UpdateMaxFd(void)
{
    int32_t tmpMax = -1;
    int32_t ret = SoftBusMutexLock(&g_listenerListLock);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s: lock g_listenerListLock failed!.", __func__);
        return;
    }

    for (int i = 0; i < UNUSE_BUTT; i++) {
        if (g_listenerList[i] == NULL) {
            continue;
        }
        if (SoftBusMutexLock(&g_listenerList[i]->lock) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
            continue;
        }

        if (g_listenerList[i]->info.status == LISTENER_RUNNING) {
            tmpMax = MaxFd(g_listenerList[i]->info.listenFd, tmpMax);
            FdNode *item = NULL;
            FdNode *nextItem = NULL;
            LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &g_listenerList[i]->info.node, FdNode, node)
            {
                tmpMax = MaxFd(item->fd, tmpMax);
            }
        }
        (void)SoftBusMutexUnlock(&g_listenerList[i]->lock);
    }
    (void)SoftBusMutexUnlock(&g_listenerListLock);

    if (SoftBusMutexLock(&g_fdSetLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        return;
    }
    g_maxFd = tmpMax;
    SoftBusMutexUnlock(&g_fdSetLock);
}

static int32_t CheckTrigger(TriggerType triggerType)
{
    if (triggerType < READ_TRIGGER || triggerType > RW_TRIGGER) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Invalid listener trigger type.");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

static void ClearListenerFdList(const ListNode *cfdList)
{
    FdNode *item = NULL;

    if (SoftBusMutexLock(&g_fdSetLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        return;
    }
    while (!IsListEmpty(cfdList)) {
        item = LIST_ENTRY(cfdList->next, FdNode, node);
        ListDelete(&item->node);
        SoftBusSocketFdClr(item->fd, &g_readSet);
        SoftBusSocketFdClr(item->fd, &g_writeSet);
        SoftBusSocketFdClr(item->fd, &g_exceptSet);
        SoftBusFree(item);
    }
    SoftBusMutexUnlock(&g_fdSetLock);
}

static int32_t InitListenFd(SoftbusListenerNode* node, const LocalListenerInfo *info)
{
    if (node == NULL || info == NULL || info->socketOption.port < 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (node->socketIf == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "no protocol inited!");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret = SOFTBUS_OK;
    do {
        int32_t rc = node->socketIf->OpenServerSocket(info);
        if (rc < 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "OpenTcpServer failed, rc=%d", rc);
            return SOFTBUS_TCP_SOCKET_ERR;
        }
        node->info.listenFd = rc;
        rc = SoftBusSocketListen(node->info.listenFd, DEFAULT_BACKLOG);
        if (rc != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "listen failed, rc=%d", rc);
            ReleaseListenerSockets(node);
            ret = SOFTBUS_TCP_SOCKET_ERR;
            break;
        }
        node->info.fdCount = 1;
        node->info.listenPort = node->socketIf->GetSockPort(node->info.listenFd);
        if (node->info.listenPort < 0) {
            SoftBusLog(
                SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "GetSockPort failed, listenPort_=%d", node->info.listenPort);
            ReleaseListenerSockets(node);
            ret = SOFTBUS_ERR;
            break;
        }
        if (memcpy_s(&node->info.listenerInfo, sizeof(node->info.listenerInfo), info, sizeof(*info)) != EOK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Copy server option failed!");
            ReleaseListenerSockets(node);
            ret = SOFTBUS_MEM_ERR;
            break;
        }
    } while (false);

    if (node->info.listenFd > 0) {
        if (SoftBusMutexLock(&g_fdSetLock) != 0) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
            ReleaseListenerSockets(node);
            return SOFTBUS_ERR;
        }
        SoftBusSocketFdSet(node->info.listenFd, &g_readSet);
        g_maxFd = MaxFd(node->info.listenFd, g_maxFd);
        SoftBusMutexUnlock(&g_fdSetLock);
    }
    return ret;
}

static int32_t OnEvent(SoftbusListenerNode *node, int32_t fd, uint32_t events)
{
    if (SoftBusMutexLock(&node->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "event lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (node->listener == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "info or listener is null");
        SoftBusMutexUnlock(&node->lock);
        return SOFTBUS_ERR;
    }
    int32_t listenFd = node->info.listenFd;
    SoftbusBaseListener listener = {0};
    listener.onConnectEvent = node->listener->onConnectEvent;
    listener.onDataEvent = node->listener->onDataEvent;
    const SocketInterface *socketIf = node->socketIf;
    ListenerModule module = node->module;
    ConnectType connectType = node->info.listenerInfo.type;
    SoftBusMutexUnlock(&node->lock);

    if (fd == listenFd) {
        while (true) {
            if (socketIf == NULL || socketIf->AcceptClient == NULL) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "accept func not found! module=%d", module);
                break;
            }
            int32_t cfd;
            ConnectOption clientAddr = {
                .type = connectType,
                .socketOption = {.addr = {0}, .port = 0, .protocol = 0, .moduleId = module}
            };
            int32_t ret = SOFTBUS_TEMP_FAILURE_RETRY(socketIf->AcceptClient(fd, &clientAddr, &cfd));
            if (ret != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "accept failed, cfd=%d, module=%d, fd=%d", cfd,
                    module, fd);
                break;
            }
            if (listener.onConnectEvent != NULL) {
                listener.onConnectEvent(module, events, cfd, &clientAddr);
            } else {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Please set onConnectEvent callback");
                SoftBusSocketClose(cfd);
            }
        }
    } else {
        if (listener.onDataEvent != NULL) {
            listener.onDataEvent(module, events, fd);
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
    LIST_FOR_EACH_ENTRY(item, list, FdNode, node)
    {
        if (*fdArrLen == fdArrSize) {
            int32_t *tmp = NULL;

            tmp = (int32_t *)SoftBusCalloc((int32_t)sizeof(int32_t) * fdArrSize * FDARR_EXPAND_BASE);
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

static void ProcessNodeData(
    SoftbusListenerNode *node, SoftBusFdSet *readSet, SoftBusFdSet *writeSet, SoftBusFdSet *exceptSet)
{
    if (SoftBusMutexLock(&node->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        return;
    }

    if (node->info.status != LISTENER_RUNNING) {
        SoftBusLog(
            SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "module %d is not running!status = %d", node->module, node->info.status);
        SoftBusMutexUnlock(&node->lock);
        return;
    }
    int32_t listenFd = node->info.listenFd;
    int32_t *fdArr = NULL;
    int32_t fdArrLen = 0;

    if (CreateFdArr(&fdArr, &fdArrLen, &node->info.node) != SOFTBUS_OK) {
        SoftBusMutexUnlock(&node->lock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "CreateFdArr failed, module:%d", node->module);
        return;
    }
    SoftBusMutexUnlock(&node->lock);

    if ((listenFd > 0) && SoftBusSocketFdIsset(listenFd, readSet)) {
        OnEvent(node, listenFd, SOFTBUS_SOCKET_IN);
    }
    for (int j = 0; j < fdArrLen; j++) {
        if (SoftBusSocketFdIsset(fdArr[j], readSet)) {
            OnEvent(node, fdArr[j], SOFTBUS_SOCKET_IN);
        }
        if (SoftBusSocketFdIsset(fdArr[j], writeSet)) {
            OnEvent(node, fdArr[j], SOFTBUS_SOCKET_OUT);
        }
        if (SoftBusSocketFdIsset(fdArr[j], exceptSet)) {
            OnEvent(node, fdArr[j], SOFTBUS_SOCKET_EXCEPTION);
        }
    }
    SoftBusFree(fdArr);
}

static void ProcessData(SoftBusFdSet *readSet, SoftBusFdSet *writeSet, SoftBusFdSet *exceptSet)
{
    for (int i = 0; i < UNUSE_BUTT; i++) {
        SoftbusListenerNode *node = RequestListenerNode((ListenerModule)i);
        if (node == NULL) {
            continue;
        }
        ProcessNodeData(node, readSet, writeSet, exceptSet);
        ReleaseListenerNode(node);
    }
}

static int32_t SetSelect(SoftBusFdSet *readSet, SoftBusFdSet *writeSet, SoftBusFdSet *exceptSet)
{
    if (SoftBusMutexLock(&g_fdSetLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
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
    SoftBusMutexUnlock(&g_fdSetLock);

    return SOFTBUS_OK;
EXIT:
    SoftBusMutexUnlock(&g_fdSetLock);
    SoftBusSocketFdZero(readSet);
    SoftBusSocketFdZero(writeSet);
    SoftBusSocketFdZero(exceptSet);
    return SOFTBUS_MEM_ERR;
}

static int32_t SelectThread(void *data)
{
    (void)data;
    SoftBusSockTimeOut tv = {0};
    tv.sec = 0;
    tv.usec = TIMEOUT;
    int32_t timeOut = 0;
    if (SoftbusGetConfig(SOFTBUS_INT_SUPPORT_SELECT_INTERVAL, (unsigned char *)&timeOut, sizeof(timeOut)) ==
        SOFTBUS_OK) {
        tv.usec = (long)timeOut;
    }
    SoftBusFdSet readSet;
    SoftBusFdSet writeSet;
    SoftBusFdSet exceptSet;
    SoftBusSocketFdZero(&readSet);
    SoftBusSocketFdZero(&writeSet);
    SoftBusSocketFdZero(&exceptSet);
    if (SetSelect(&readSet, &writeSet, &exceptSet) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "select failed with invalid listener");
        return SOFTBUS_ERR;
    }
    int32_t maxFd = g_maxFd;
    if (maxFd < 0) {
        SoftBusSocketSelect(0, NULL, NULL, NULL, &tv);
        return SOFTBUS_OK;
    }

    int32_t nEvents = SoftBusSocketSelect(maxFd + 1, &readSet, &writeSet, &exceptSet, &tv);
    if (nEvents < 0) {
        return SOFTBUS_TCP_SOCKET_ERR;
    } else if (nEvents == 0) {
        return SOFTBUS_OK;
    } else {
        ProcessData(&readSet, &writeSet, &exceptSet);
        return SOFTBUS_OK;
    }
}

static int32_t StopListenerThread(SoftbusListenerNode *node)
{
    int32_t ret = SoftBusMutexLock(&node->lock);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed!ret=%" PRId32, __func__, ret);
        return ret;
    }

    do {
        if (node->info.status != LISTENER_RUNNING) {
            SoftBusLog(
                SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "%s:node not running.status=%d", __func__, node->info.status);
            break;
        }

        ret = SoftBusMutexLock(&g_threadLock);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock g_threadLock failed!ret=%" PRId32, __func__, ret);
            break;
        }

        --g_threadRefCount;

        if (g_threadRefCount <= 0) {
            ret = ThreadPoolRemoveJob(g_threadPool, (uintptr_t)0);
            if (ret != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:remove job failed!ret=%" PRId32, __func__, ret);
                (void)SoftBusMutexUnlock(&g_threadLock);
                break;
            }
        }

        (void)SoftBusMutexUnlock(&g_threadLock);

        node->info.status = LISTENER_IDLE;
        node->info.modeType = UNSET_MODE;
    } while (false);
    (void)SoftBusMutexUnlock(&node->lock);
    return ret;
}

static int32_t StartListenerThread(SoftbusListenerNode *node, ModeType modeType)
{
    int32_t ret = SoftBusMutexLock(&node->lock);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed!ret=%" PRId32, __func__, ret);
        return ret;
    }

    do {
        if (node->info.status != LISTENER_IDLE) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:bad status(%d)", __func__, node->info.status);
            ret = SOFTBUS_ERR;
            break;
        }

        ret = SoftBusMutexLock(&g_threadLock);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock g_threadLock failed!ret=%" PRId32, __func__, ret);
            break;
        }

        if (g_threadRefCount > 0) {
            g_threadRefCount++;
            (void)SoftBusMutexUnlock(&g_threadLock);
            break;
        }

        ret = ThreadPoolAddJob(g_threadPool, (int32_t(*)(void *))SelectThread, NULL, PERSISTENT, (uintptr_t)0);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:start thread failed!ret=%" PRId32, __func__, ret);
            (void)SoftBusMutexUnlock(&g_threadLock);
            break;
        }

        g_threadRefCount++;
        (void)SoftBusMutexUnlock(&g_threadLock);
    } while (false);

    if (ret == SOFTBUS_OK) {
        node->info.modeType = modeType;
        node->info.status = LISTENER_RUNNING;
    }

    (void)SoftBusMutexUnlock(&node->lock);
    return ret;
}

static int32_t ShutdownBaseListener(SoftbusListenerNode *node)
{
    if (node == NULL) {
        return SOFTBUS_NOT_FIND;
    }

    int32_t ret = SoftBusMutexLock(&node->lock);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        return ret;
    }

    ret = StopListenerThread(node);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s: stop listener failed!ret=%" PRId32, __func__, ret);
    }
    node->info.status = LISTENER_CLOSEING;
    SoftBusMutexUnlock(&node->lock);
    return SOFTBUS_OK;
}

static void InitListenerInfo(SoftbusBaseListenerInfo *listenerInfo)
{
    listenerInfo->modeType = UNSET_MODE;
    listenerInfo->fdCount = 0;
    listenerInfo->listenFd = -1;
    listenerInfo->listenPort = -1;
    listenerInfo->status = LISTENER_IDLE;
    ListInit(&listenerInfo->node);
}


static int32_t AddTriggerToSet(int32_t fd, TriggerType triggerType)
{
    int32_t ret = SOFTBUS_OK;
    if (SoftBusMutexLock(&g_fdSetLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        return SOFTBUS_ERR;
    }
    switch (triggerType) {
        case READ_TRIGGER:
            SoftBusSocketFdSet(fd, &g_readSet);
            break;
        case WRITE_TRIGGER:
            SoftBusSocketFdSet(fd, &g_writeSet);
            break;
        case EXCEPT_TRIGGER:
            SoftBusSocketFdSet(fd, &g_exceptSet);
            break;
        case RW_TRIGGER:
            SoftBusSocketFdSet(fd, &g_readSet);
            SoftBusSocketFdSet(fd, &g_writeSet);
            break;
        default:
            ret = SOFTBUS_INVALID_PARAM;
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Invalid trigger type");
            break;
    }
    SoftBusMutexUnlock(&g_fdSetLock);

    return ret;
}

static int32_t DelTriggerFromSet(int32_t fd, TriggerType triggerType)
{
    int32_t ret = SOFTBUS_OK;
    if (SoftBusMutexLock(&g_fdSetLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        return SOFTBUS_ERR;
    }
    switch (triggerType) {
        case READ_TRIGGER:
            SoftBusSocketFdClr(fd, &g_readSet);
            break;
        case WRITE_TRIGGER:
            SoftBusSocketFdClr(fd, &g_writeSet);
            break;
        case EXCEPT_TRIGGER:
            SoftBusSocketFdClr(fd, &g_exceptSet);
            break;
        case RW_TRIGGER:
            SoftBusSocketFdClr(fd, &g_readSet);
            SoftBusSocketFdClr(fd, &g_writeSet);
            break;
        default:
            ret = SOFTBUS_INVALID_PARAM;
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Invalid trigger type");
            break;
    }
    SoftBusMutexUnlock(&g_fdSetLock);

    return ret;
}

int32_t StartBaseClient(ListenerModule module)
{
    SoftbusListenerNode *node = RequestListenerNode(module);
    if (node == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret;

    do {
        if (node->listener == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BaseListener not set, start failed.");
            ret = SOFTBUS_ERR;
            break;
        }
        if (node->info.status != LISTENER_IDLE) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "listener is not in idle status.");
            ret = SOFTBUS_ERR;
            break;
        }
        ret = StartListenerThread(node, CLIENT_MODE);
        SoftBusLog(
            SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "StartBaseClient %s", (ret == SOFTBUS_OK) ? "SUCCESS" : "FAILED");
    } while (false);

    ReleaseListenerNode(node);

    return ret;
}

int32_t StartBaseListener(const LocalListenerInfo *info)
{
    if (info == NULL || (info->type != CONNECT_TCP && info->type != CONNECT_P2P) || info->socketOption.port < 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s: bad input", __func__);
        return SOFTBUS_INVALID_PARAM;
    }
    ListenerModule module = info->socketOption.moduleId;
    SoftbusListenerNode *node = RequestListenerNode(module);
    if (node == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s: no listner with module %" PRIu32, __func__, module);
        return SOFTBUS_NOT_FIND;
    }
    int32_t ret;
    do {
        if (node->listener == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "BaseListener not set, start failed.");
            ret = SOFTBUS_ERR;
            break;
        }
        if (node->info.status != LISTENER_IDLE) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:listener is not in idle status.status=%d", __func__,
                node->info.status);
            ret = SOFTBUS_ERR;
            break;
        }
        node->socketIf = GetSocketInterface(info->socketOption.protocol);
        if (node->socketIf == NULL) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:no such protocol.protocol=%d", __func__,
                info->socketOption.protocol);
            ret = SOFTBUS_ERR;
            break;
        }
        ret = InitListenFd(node, info);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:InitListenFd failed!ret=%" PRId32, __func__, ret);
            break;
        }
        ret = StartListenerThread(node, SERVER_MODE);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(
                SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:Start listener thread failed!ret=%" PRId32, __func__, ret);
            ReleaseListenerSockets(node);
            break;
        }
    } while (false);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "StartBaseListener success, fd = %d, module = %d",
        node->info.listenPort, module);
    int32_t port = node->info.listenPort;
    ReleaseListenerNode(node);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    return port;
}

int32_t GetSoftbusBaseListener(ListenerModule module, SoftbusBaseListener *listener)
{
    if (listener == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    SoftbusListenerNode *node = RequestListenerNode(module);
    if (node == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s: no listner with module %" PRIu32, __func__, module);
        return SOFTBUS_NOT_FIND;
    }

    if (SoftBusMutexLock(&node->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        ReleaseListenerNode(node);
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = SOFTBUS_OK;
    do {
        if (node->listener == NULL) {
            ret = SOFTBUS_NOT_FIND;
            break;
        }
        if (memcpy_s(listener, sizeof(SoftbusBaseListener), node->listener, sizeof(SoftbusBaseListener)) != EOK) {
            ret = SOFTBUS_MEM_ERR;
            break;
        }
    } while (false);
    (void)SoftBusMutexUnlock(&node->lock);
    (void)ReleaseListenerNode(node);
    return ret;
}

int32_t SetSoftbusBaseListener(ListenerModule module, const SoftbusBaseListener *listener)
{
    if (listener == NULL || listener->onConnectEvent == NULL || listener->onDataEvent == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    SoftbusListenerNode *node = RequestListenerNode(module);
    if (node == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s: no listner with module %" PRIu32, __func__, module);
        return SOFTBUS_NOT_FIND;
    }

    if (SoftBusMutexLock(&node->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "set listener lock failed");
        (void)ReleaseListenerNode(node);
        return SOFTBUS_LOCK_ERR;
    }

    int32_t ret = SOFTBUS_OK;
    do {
        if (node->listener == NULL) {
            node->listener = (SoftbusBaseListener *)SoftBusCalloc(sizeof(SoftbusBaseListener));
            if (node->listener == NULL) {
                ret = SOFTBUS_MALLOC_ERR;
                break;
            }
        }
        if (memcpy_s(node->listener, sizeof(SoftbusBaseListener), listener, sizeof(SoftbusBaseListener)) != EOK) {
            ret = SOFTBUS_MEM_ERR;
            break;
        }
    } while (false);
    (void)SoftBusMutexUnlock(&node->lock);
    (void)ReleaseListenerNode(node);
    return ret;
}

int32_t StopBaseListener(ListenerModule module)
{
    SoftbusListenerNode *node = RequestListenerNode(module);
    if (node == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s: no listner with module %" PRIu32, __func__, module);
        return SOFTBUS_NOT_FIND;
    }
    if (SoftBusMutexLock(&node->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        ReleaseListenerNode(node);
        return SOFTBUS_LOCK_ERR;
    }
    
    int32_t listenFd = node->info.listenFd;
    node->info.listenFd = -1;
    int32_t ret = StopListenerThread(node);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "stop listen thread failed!ret = %" PRId32 ", module = %d.",
            ret, module);
    }
    SoftBusMutexUnlock(&node->lock);
    ReleaseListenerNode(node);

    if (listenFd > 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "del listen fd from readSet, fd = %d, module = %d.",
            listenFd, module);
        DelTriggerFromSet(listenFd, READ_TRIGGER);
        ConnShutdownSocket(listenFd);
        UpdateMaxFd();
    }
    return ret;
}

static int32_t WaitBaseListenerDestroy(ListenerModule module, int32_t waitTimeOut)
{
    const int32_t waitInterval = 100;
    while (waitTimeOut > 0) {
        int32_t ret = SoftBusMutexLock(&g_listenerListLock);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
            return SOFTBUS_LOCK_ERR;
        }

        if (g_listenerList[module] != NULL) {
            SoftBusMutexUnlock(&g_listenerListLock);
            SoftBusSleepMs(waitInterval);
            waitTimeOut -= waitInterval;
            continue;
        }
        (void)SoftBusMutexUnlock(&g_listenerListLock);
        return SOFTBUS_OK;
    }
    return SOFTBUS_TIMOUT;
}

void DestroyBaseListener(ListenerModule module)
{
    if (module >= UNUSE_BUTT) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Invalid listener module.");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "%s:Destory listener module %" PRIu32, __func__, module);
    int32_t ret = SoftBusMutexLock(&g_listenerListLock);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:get lock failed!ret=%" PRId32, __func__, ret);
        return;
    }

    ret = ShutdownBaseListener(g_listenerList[module]);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_listenerListLock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:shutdown listener failed!ret=%" PRId32, __func__, ret);
        g_listenerList[module] = NULL;
        return;
    }

    ret = ReleaseListenerRef(module);
    if (ret != SOFTBUS_OK) {
        (void)SoftBusMutexUnlock(&g_listenerListLock);
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:release listener failed!ret=%" PRId32, __func__, ret);
        g_listenerList[module] = NULL;
        return;
    }
    (void)SoftBusMutexUnlock(&g_listenerListLock);
#define LISTENER_MODULE_DESTROY_TIMEOUT (30 * 1000)
    ret = WaitBaseListenerDestroy(module, LISTENER_MODULE_DESTROY_TIMEOUT);
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "%s:Destory listener module %" PRIu32 " finished. ret=%" PRId32,
        __func__, module, ret);
}

static bool CheckFdIsExist(const SoftbusBaseListenerInfo *info, int32_t fd)
{
    FdNode *item = NULL;
    FdNode *nextItem = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &info->node, FdNode, node)
    {
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

    LIST_FOR_EACH_ENTRY_SAFE(item, nextItem, &info->node, FdNode, node)
    {
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
    if (fd < 0 || CheckTrigger(triggerType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Invalid AddTrigger Param");
        return SOFTBUS_INVALID_PARAM;
    }

    SoftbusListenerNode *node = RequestListenerNode(module);
    if (node == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s: no listner with module %" PRIu32, __func__, module);
        return SOFTBUS_NOT_FIND;
    }

    if (SoftBusMutexLock(&node->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        ReleaseListenerNode(node);
        return SOFTBUS_LOCK_ERR;
    }
    int32_t ret = SOFTBUS_OK;

    do {
        if (node->info.fdCount > MAX_LISTEN_EVENTS) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Cannot AddTrigger any more");
            break;
        }

        ret = AddTriggerToSet(fd, triggerType);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR,
                "AddTrigger failed!ret=%" PRId32 " Module=%" PRIu32 "TriggerType=%d", ret, module, triggerType);
            break;
        }

        if (CheckFdIsExist(&node->info, fd)) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "fd exist");
            break;
        }

        if (AddNewFdNode(&node->info, fd) != SOFTBUS_OK) {
            (void)DelTriggerFromSet(fd, triggerType);
            break;
        }
    } while (false);

    SoftBusMutexUnlock(&node->lock);
    ReleaseListenerNode(node);

    if (SoftBusMutexLock(&g_fdSetLock) != 0) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        return SOFTBUS_OK;
    }
    g_maxFd = MaxFd(fd, g_maxFd);
    SoftBusMutexUnlock(&g_fdSetLock);

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO,
        "AddTrigger fd:%d success, current fdcount:%d, module:%d, triggerType:%d", fd, node->info.fdCount, module,
        triggerType);
    return SOFTBUS_OK;
}

int32_t DelTrigger(ListenerModule module, int32_t fd, TriggerType triggerType)
{
    if (fd < 0 || CheckTrigger(triggerType)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "Invalid AddTrigger Param");
        return SOFTBUS_INVALID_PARAM;
    }

    SoftbusListenerNode *node = RequestListenerNode(module);
    if (node == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s: no listner with module %" PRIu32, __func__, module);
        return SOFTBUS_NOT_FIND;
    }

    if (SoftBusMutexLock(&node->lock) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "%s:lock failed", __func__);
        ReleaseListenerNode(node);
        return SOFTBUS_LOCK_ERR;
    }

    do {
        if (DelTriggerFromSet(fd, triggerType) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "del trigger fail: fd = %d, trigger = %d", fd, triggerType);
        }

        if (SoftBusSocketFdIsset(fd, &g_writeSet) || SoftBusSocketFdIsset(fd, &g_readSet) ||
            SoftBusSocketFdIsset(fd, &g_exceptSet)) {
            break;
        }

        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "%s:[fd:%d] removed from all fdSet. del fdnode", __func__, fd);
        DelFdNode(&node->info, fd);
    } while (false);

    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "%s:[fd:%d] success, current fdcount:%d, module:%d, triggerType:%d",
        __func__, fd, node->info.fdCount, module, triggerType);

    SoftBusMutexUnlock(&node->lock);
    ReleaseListenerNode(node);
    UpdateMaxFd();

    return SOFTBUS_OK;
}
