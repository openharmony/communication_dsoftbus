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
#include <fcntl.h>
#include <unistd.h>

#include "common_list.h"
#include "conn_log.h"
#include "softbus_adapter_errcode.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_conn_common.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"
#include "softbus_socket.h"
#include "softbus_utils.h"

#define MAX_LISTEN_EVENTS 1024
#define DEFAULT_BACKLOG   4
#define FDARR_EXPAND_BASE 2
#define SELECT_UNEXPECT_FAIL_RETRY_WAIT_MILLIS (3 * 1000)

enum BaseListenerStatus {
    LISTENER_IDLE = 0,
    LISTENER_RUNNING,
};

typedef struct {
    ListNode node;
    int32_t fd;
    uint32_t triggerSet;
} FdNode;

typedef struct {
    ListNode waitEventFds;
    uint32_t waitEventFdsLen;

    ModeType modeType;
    LocalListenerInfo listenerInfo;
    int32_t listenFd;
    int32_t listenPort;

    enum BaseListenerStatus status;
} SoftbusBaseListenerInfo;

typedef struct {
    ListenerModule module;
    SoftBusMutex lock;
    SoftbusBaseListener listener;
    const SocketInterface *socketIf;
    SoftbusBaseListenerInfo info;
    int32_t objectRc;
} SoftbusListenerNode;

typedef struct {
    uint32_t traceId;
    // pipe fds, to wakeup select thread in time
    int32_t ctrlRfd;
    int32_t ctrlWfd;

    SoftBusMutex lock;
    int32_t referenceCount;
} SelectThreadState;

static int32_t ShutdownBaseListener(SoftbusListenerNode *node);
static int32_t StartSelectThread(void);
static int32_t StopSelectThread(void);
static void WakeupSelectThread(void);
static SoftbusListenerNode *CreateSpecifiedListenerModule(ListenerModule module);

static SoftBusMutex g_listenerListLock = { 0 };
static SoftbusListenerNode *g_listenerList[UNUSE_BUTT] = { 0 };
static SoftBusMutex g_selectThreadStateLock = { 0 };
static SelectThreadState *g_selectThreadState = NULL;

static SoftbusListenerNode *GetListenerNodeCommon(ListenerModule module, bool create)
{
    int32_t status = SoftBusMutexLock(&g_listenerListLock);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        status == SOFTBUS_OK, NULL, CONN_COMMON, "lock listener lists failed, module=%{public}d, error=%{public}d",
        module, status);
    SoftbusListenerNode *node = g_listenerList[module];
    do {
        if (node == NULL) {
            if (create) {
                node = CreateSpecifiedListenerModule(module);
            }
            if (node == NULL) {
                break;
            }
            g_listenerList[module] = node;
        }
        status = SoftBusMutexLock(&node->lock);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "lock listener failed, module=%{public}d, error=%{public}d", module, status);
            node = NULL;
            break;
        }
        node->objectRc += 1;
        SoftBusMutexUnlock(&node->lock);
    } while (false);
    (void)SoftBusMutexUnlock(&g_listenerListLock);
    return node;
}

static SoftbusListenerNode *GetListenerNode(ListenerModule module)
{
    return GetListenerNodeCommon(module, false);
}

static SoftbusListenerNode *GetOrCreateListenerNode(ListenerModule module)
{
    return GetListenerNodeCommon(module, true);
}

static void RemoveListenerNode(SoftbusListenerNode *node)
{
    int32_t status = SoftBusMutexLock(&g_listenerListLock);
    CONN_CHECK_AND_RETURN_LOGE(
        status == SOFTBUS_OK, CONN_COMMON, "lock listener lists failed, module=%{public}d, error=%{public}d",
        node->module, status);
    do {
        if (g_listenerList[node->module] != node) {
            CONN_LOGW(CONN_COMMON, "listener node is not in listener list, just skip, module=%{public}d",
                node->module);
            break;
        }
        status = SoftBusMutexLock(&node->lock);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "lock listener node failed, module=%{public}d", node->module);
            break;
        }
        // decrease root object reference
        node->objectRc -= 1;
        g_listenerList[node->module] = NULL;
        (void)SoftBusMutexUnlock(&node->lock);
    } while (false);
    (void)SoftBusMutexUnlock(&g_listenerListLock);
}

static void ReturnListenerNode(SoftbusListenerNode **nodePtr)
{
    SoftbusListenerNode *node = *nodePtr;
    do {
        int32_t status = SoftBusMutexLock(&node->lock);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "lock listener node failed, module=%{public}d", node->module);
            break;
        }
        node->objectRc -= 1;
        int32_t objectRc = node->objectRc;
        (void)SoftBusMutexUnlock(&node->lock);

        if (objectRc > 0) {
            break;
        }
        CONN_LOGI(CONN_COMMON, "object reference count <= 0, free listener node, module=%{public}d, "
                               "objectReference=%{public}d", node->module, objectRc);
        (void)ShutdownBaseListener(node);
        SoftBusFree(node);
    } while (false);

    *nodePtr = NULL;
}

static SoftbusListenerNode *CreateSpecifiedListenerModule(ListenerModule module)
{
    SoftbusListenerNode *node = (SoftbusListenerNode *)SoftBusCalloc(sizeof(SoftbusListenerNode));
    CONN_CHECK_AND_RETURN_RET_LOGE(
        node != NULL, NULL, CONN_COMMON, "calloc listener node object failed, module=%{public}d", module);

    node->module = module;
    // NOT apply recursive lock on purpose, problem will be exposes quickly if exist
    int32_t status = SoftBusMutexInit(&node->lock, NULL);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "init lock failed, module=%{public}d, error=%{public}d", module, status);
        SoftBusFree(node);
        return NULL;
    }
    ListInit(&node->info.waitEventFds);
    node->info.waitEventFdsLen = 0;
    node->info.modeType = UNSET_MODE;
    node->info.listenFd = -1;
    node->info.listenPort = -1;
    // set root object reference count 1
    node->objectRc = 1;
    return node;
}

int32_t InitBaseListener(void)
{
    // stop select thread need re-enter lock
    SoftBusMutexAttr attr = {
        .type = SOFTBUS_MUTEX_RECURSIVE,
    };
    int32_t status = SoftBusMutexInit(&g_selectThreadStateLock, &attr);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "init select thread lock failed, error=%{public}d", status);
        return SOFTBUS_LOCK_ERR;
    }
    // NOT apply recursive lock on purpose, problem will be exposes quickly if exist
    status = SoftBusMutexInit(&g_listenerListLock, NULL);
    if (status != SOFTBUS_OK) {
        SoftBusMutexDestroy(&g_selectThreadStateLock);
        CONN_LOGE(CONN_INIT, "init listener list lock failed, error=%{public}d", status);
        return SOFTBUS_LOCK_ERR;
    }

    status = SoftBusMutexLock(&g_listenerListLock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "lock listener list failed, error=%{public}d", status);
        SoftBusMutexDestroy(&g_selectThreadStateLock);
        SoftBusMutexDestroy(&g_listenerListLock);
        return SOFTBUS_LOCK_ERR;
    }
    (void)memset_s(g_listenerList, sizeof(g_listenerList), 0, sizeof(g_listenerList));
    (void)SoftBusMutexUnlock(&g_listenerListLock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "create static module listener failed, error=%{public}d", status);
        SoftBusMutexDestroy(&g_selectThreadStateLock);
        SoftBusMutexDestroy(&g_listenerListLock);
        return status;
    }

    return SOFTBUS_OK;
}

void DeinitBaseListener(void)
{
    for (ListenerModule module = 0; module < UNUSE_BUTT; module++) {
        SoftbusListenerNode *node = GetListenerNode(module);
        if (node == NULL) {
            continue;
        }
        RemoveListenerNode(node);
        ReturnListenerNode(&node);
    }
}

uint32_t CreateListenerModule(void)
{
    int32_t status = SoftBusMutexLock(&g_listenerListLock);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        status == SOFTBUS_OK, UNUSE_BUTT, CONN_COMMON, "lock listener list failed, error=%{public}d", status);

    ListenerModule module = LISTENER_MODULE_DYNAMIC_START;
    for (; module <= LISTENER_MODULE_DYNAMIC_END; module++) {
        if (g_listenerList[module] != NULL) {
            continue;
        }
        SoftbusListenerNode *node = CreateSpecifiedListenerModule(module);
        if (node == NULL) {
            CONN_LOGE(CONN_COMMON, "create specified listener module failed, module=%{public}d", module);
            module = UNUSE_BUTT;
        } else {
            CONN_LOGI(CONN_COMMON, "create listener module success, module=%{public}d", module);
            g_listenerList[module] = node;
        }
        break;
    }
    (void)SoftBusMutexUnlock(&g_listenerListLock);
    return module;
}

void DestroyBaseListener(ListenerModule module)
{
    CONN_CHECK_AND_RETURN_LOGW(module >= LISTENER_MODULE_DYNAMIC_START && module <= LISTENER_MODULE_DYNAMIC_END,
        CONN_COMMON, "only dynamic module support destroy, module=%{public}d", module);

    CONN_LOGI(CONN_COMMON, "receive request, module=%{public}d", module);
    SoftbusListenerNode *node = GetListenerNode(module);
    if (node == NULL) {
        CONN_LOGW(CONN_COMMON, "listener not exist, module=%{public}d", module);
        return;
    }
    RemoveListenerNode(node);
    ReturnListenerNode(&node);
}

int32_t StartBaseClient(ListenerModule module, const SoftbusBaseListener *listener)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(module >= 0 && module < UNUSE_BUTT, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "invalid module, module=%{public}d", module);
    CONN_CHECK_AND_RETURN_RET_LOGW(listener != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "listener is null, module=%{public}d", module);
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onConnectEvent != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "listener onConnectEvent is null, module=%{public}d", module);
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onDataEvent != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "listener onDataEvent is null, module=%{public}d", module);

    CONN_LOGI(CONN_COMMON, "receive request, module=%{public}d", module);

    SoftbusListenerNode *node = GetOrCreateListenerNode(module);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        node != NULL, SOFTBUS_NOT_FIND, CONN_COMMON, "get listener node failed, module=%{public}d", module);

    int32_t status = SoftBusMutexLock(&node->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "lock listener node failed, module=%{public}d, error=%{public}d", module, status);
        ReturnListenerNode(&node);
        return SOFTBUS_LOCK_ERR;
    }
    do {
        if (node->info.status != LISTENER_IDLE) {
            CONN_LOGE(CONN_COMMON, "listener is not idle status, module=%{public}d, status=%{public}d",
                module, node->info.status);
            status = SOFTBUS_ERR;
            break;
        }
        node->listener.onConnectEvent = listener->onConnectEvent;
        node->listener.onDataEvent = listener->onDataEvent;
        status = StartSelectThread();
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "start select thread failed, module=%{public}d, "
                "status=%{public}d", module, status);
            break;
        }
        node->info.status = LISTENER_RUNNING;
        CONN_LOGI(CONN_COMMON, "start base client listener success, module=%{public}d", module);
    } while (false);
    (void)SoftBusMutexUnlock(&node->lock);
    ReturnListenerNode(&node);
    return status;
}

static int32_t StartServerListenUnsafe(SoftbusListenerNode *node, const LocalListenerInfo *info)
{
    ListenerModule module = node->module;
    ProtocolType protocol = info->socketOption.protocol;
    const SocketInterface *socketIf = GetSocketInterface(protocol);
    if (socketIf == NULL) {
        CONN_LOGE(CONN_COMMON, "not find protocal implement, module=%{public}d, protocal=%{public}d", module, protocol);
        return SOFTBUS_NOT_FIND;
    }
    node->socketIf = socketIf;

    int32_t listenFd = -1;
    int32_t listenPort = -1;
    int32_t status = SOFTBUS_OK;
    do {
        listenFd = socketIf->OpenServerSocket(info);
        if (listenFd < 0) {
            CONN_LOGE(CONN_COMMON, "create server socket failed: module=%{public}d, listenFd=%{public}d",
                module, listenFd);
            status = SOFTBUS_TCP_SOCKET_ERR;
            break;
        }
        status = SoftBusSocketListen(listenFd, DEFAULT_BACKLOG);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "listen server socket failed: module=%{public}d, error=%{public}d", module, status);
            break;
        }
        listenPort = socketIf->GetSockPort(listenFd);
        if (listenPort < 0) {
            CONN_LOGE(CONN_COMMON, "get listen server port failed: module=%{public}d, listenFd=%{public}d, "
                                   "error=%{public}d", module, listenFd, status);
            status = SOFTBUS_TCP_SOCKET_ERR;
            break;
        }
        if (memcpy_s(&node->info.listenerInfo, sizeof(LocalListenerInfo), info, sizeof(LocalListenerInfo)) != EOK) {
            CONN_LOGE(CONN_COMMON, "memcpy_s local listener info object failed: module=%{public}d", module);
            status = SOFTBUS_MEM_ERR;
            break;
        }
        node->info.modeType = SERVER_MODE;
        node->info.listenFd = listenFd;
        node->info.listenPort = listenPort;
    } while (false);
    if (status != SOFTBUS_OK && listenFd > 0) {
        ConnShutdownSocket(listenFd);
    }
    return status == SOFTBUS_OK ? listenPort : status;
}

static void CleanupServerListenInfoUnsafe(SoftbusListenerNode *node)
{
    memset_s(&node->info.listenerInfo, sizeof(SoftbusBaseListenerInfo), 0, sizeof(SoftbusBaseListenerInfo));
    if (node->info.listenFd > 0) {
        ConnShutdownSocket(node->info.listenFd);
    }
    node->info.listenFd = -1;
    node->info.listenPort = -1;
}

int32_t StartBaseListener(const LocalListenerInfo *info, const SoftbusBaseListener *listener)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(info != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "info is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(info->type == CONNECT_TCP || info->type == CONNECT_P2P, SOFTBUS_INVALID_PARAM,
        CONN_COMMON, "only CONNECT_TCP and CONNECT_P2P is permitted, "
                     "CONNECT_TCP=%{public}d, CONNECT_P2P=%{public}d, type=%{public}d",
        CONNECT_TCP, CONNECT_P2P, info->type);
    CONN_CHECK_AND_RETURN_RET_LOGW(info->socketOption.port >= 0, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "port is invalid, port=%{public}d", info->socketOption.port);
    CONN_CHECK_AND_RETURN_RET_LOGW(info->socketOption.moduleId >= 0 && info->socketOption.moduleId < UNUSE_BUTT,
        SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid module, module=%{public}d", info->socketOption.moduleId);
    CONN_CHECK_AND_RETURN_RET_LOGW(listener != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "listener is null, module=%{public}d", info->socketOption.moduleId);
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onConnectEvent != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "listener onConnectEvent is null, module=%{public}d", info->socketOption.moduleId);
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onDataEvent != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "listener onDataEvent is null, module=%{public}d", info->socketOption.moduleId);

    ListenerModule module = info->socketOption.moduleId;
    CONN_LOGI(CONN_COMMON, "receive request, module=%{public}d", module);
    SoftbusListenerNode *node = GetOrCreateListenerNode(module);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        node != NULL, SOFTBUS_NOT_FIND, CONN_COMMON, "get listener node failed, module=%{public}d", module);
    int32_t status = SoftBusMutexLock(&node->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "lock listener node failed, module=%{public}d, error=%{public}d", module, status);
        ReturnListenerNode(&node);
        return SOFTBUS_LOCK_ERR;
    }

    int32_t listenPort = -1;
    do {
        if (node->info.status != LISTENER_IDLE) {
            CONN_LOGE(CONN_COMMON, "listener is not idle status, module=%{public}d, status=%{public}d",
                module, node->info.status);
            status = SOFTBUS_ERR;
            break;
        }

        node->listener.onConnectEvent = listener->onConnectEvent;
        node->listener.onDataEvent = listener->onDataEvent;
        if (memcpy_s(&node->info.listenerInfo, sizeof(LocalListenerInfo), info, sizeof(LocalListenerInfo)) != EOK) {
            CONN_LOGE(CONN_COMMON, "memcpy_s listener info failed, module=%{public}d", node->module);
            status = SOFTBUS_LOCK_ERR;
            break;
        }
        listenPort = StartServerListenUnsafe(node, info);
        if (listenPort <= 0) {
            CONN_LOGE(CONN_COMMON, "start server failed, module=%{public}d, listenPort=%{public}d",
                module, listenPort);
            status = SOFTBUS_ERR;
            break;
        }

        status = StartSelectThread();
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "start listener thread failed, module=%{public}d, status=%{public}d",
                module, status);
            CleanupServerListenInfoUnsafe(node);
            break;
        }
        node->info.status = LISTENER_RUNNING;
        CONN_LOGI(CONN_COMMON, "start base listener success, module=%{public}d, listenFd=%{public}d, "
                               "listenPort=%{public}d", module, node->info.listenFd, listenPort);
    } while (false);
    (void)SoftBusMutexUnlock(&node->lock);
    ReturnListenerNode(&node);
    return status == SOFTBUS_OK ? listenPort : status;
}

int32_t StopBaseListener(ListenerModule module)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(
        module >= 0 && module < UNUSE_BUTT, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "invalid module, module=%{public}d", module);

    CONN_LOGI(CONN_COMMON, "receive request, module=%{public}d", module);
    SoftbusListenerNode *node = GetListenerNode(module);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        node != NULL, SOFTBUS_NOT_FIND, CONN_COMMON, "listener node not exist, module=%{public}d", module);

    int32_t status = ShutdownBaseListener(node);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "stop listen thread failed, module=%{public}d, error=%{public}d", module, status);
    }
    ReturnListenerNode(&node);
    return status;
}

static int32_t ShutdownBaseListener(SoftbusListenerNode *node)
{
    int32_t status = SoftBusMutexLock(&node->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_COMMON,
        "lock listener node failed, module=%{public}d, error=%{public}d", node->module, status);

    do {
        if (node->info.status != LISTENER_RUNNING) {
            CONN_LOGW(CONN_COMMON, "listener is not running, just skip, module=%{public}d, error=%{public}d",
                node->module, node->info.status);
            break;
        }
        status = StopSelectThread();
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "stop select thread failed, module=%{public}d, error=%{public}d",
                node->module, status);
            break;
        }
        node->info.status = LISTENER_IDLE;

        FdNode *it = NULL;
        FdNode *next = NULL;
        LIST_FOR_EACH_ENTRY_SAFE(it, next, &node->info.waitEventFds, FdNode, node) {
            CONN_LOGE(CONN_COMMON, "listener node there is fd not close, module=%{public}d, fd=%{public}d, "
                                   "triggerSet=%{public}u", node->module, it->fd, it->triggerSet);
            // not close fd, repeat close will crash process
            ListDelete(&it->node);
            SoftBusFree(it);
        }
        node->info.waitEventFdsLen = 0;

        int32_t listenFd = node->info.listenFd;
        int32_t listenPort = node->info.listenPort;
        if (node->info.modeType == SERVER_MODE && listenFd > 0) {
            CONN_LOGE(CONN_COMMON, "close server, module=%{public}d, listenFd=%{public}d, port=%{public}d",
                node->module, listenFd, listenPort);
            ConnCloseSocket(listenFd);
        }
        node->info.modeType = UNSET_MODE;
        node->info.listenFd = -1;
        node->info.listenPort = -1;
        (void)memset_s(&node->info.listenerInfo, sizeof(LocalListenerInfo), 0, sizeof(LocalListenerInfo));
    } while (false);

    SoftBusMutexUnlock(&node->lock);
    return status;
}

static bool IsValidTriggerType(TriggerType trigger)
{
    switch (trigger) {
        case READ_TRIGGER:
        case WRITE_TRIGGER:
        case EXCEPT_TRIGGER:
        case RW_TRIGGER:
            return true;
        default:
            return false;
    }
}

int32_t AddTrigger(ListenerModule module, int32_t fd, TriggerType trigger)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(module >= 0 && module < UNUSE_BUTT, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "invalid module, module=%{public}d", module);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        fd > 0, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid fd, module=%{public}d, fd=%{public}d", module, fd);
    CONN_CHECK_AND_RETURN_RET_LOGW(IsValidTriggerType(trigger), SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "invalid trigger, module=%{public}d, fd=%{public}d, trigger=%{public}d", module, fd, trigger);

    CONN_LOGI(CONN_COMMON,
        "receive request, module=%{public}d, fd=%{public}d, trigger=%{public}d", module, fd, trigger);
    SoftbusListenerNode *node = GetListenerNode(module);
    CONN_CHECK_AND_RETURN_RET_LOGW(node != NULL, SOFTBUS_NOT_FIND, CONN_COMMON,
        "listener node not exist, module=%{public}d, fd=%{public}d, trigger=%{public}d", module, fd, trigger);

    int32_t status = SoftBusMutexLock(&node->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "lock listener node failed, module=%{public}d, fd=%{public}d, trigger=%{public}d, "
                               "error=%{public}d", module, fd, trigger, status);
        ReturnListenerNode(&node);
        return SOFTBUS_LOCK_ERR;
    }

    bool wakeup = false;
    do {
        if (node->info.status != LISTENER_RUNNING) {
            CONN_LOGE(CONN_COMMON, "module is not running, module=%{public}d, fd=%{public}d, trigger=%{public}d",
                module, fd, trigger);
            status = SOFTBUS_ERR;
            break;
        }

        if (node->info.waitEventFdsLen > MAX_LISTEN_EVENTS) {
            CONN_LOGE(CONN_COMMON,
                "can not trigger more, fd exceed more than MAX_LISTEN_EVENTS, MAX_LISTEN_EVENTS=%{public}d, "
                "module=%{public}d, fd=%{public}d, trigger=%{public}d, waitEventFdsLen=%{public}d",
                MAX_LISTEN_EVENTS, module, fd, trigger, node->info.waitEventFdsLen);
            status = SOFTBUS_ERR;
            break;
        }

        FdNode *target = NULL;
        FdNode *it = NULL;
        LIST_FOR_EACH_ENTRY(it, &node->info.waitEventFds, FdNode, node) {
            if (fd == it->fd) {
                target = it;
                break;
            }
        }

        if (target != NULL) {
            if ((it->triggerSet & trigger) == trigger) {
                CONN_LOGW(CONN_COMMON, "repeat add trigger, just skip, module=%{public}d, fd=%{public}d, "
                                       "trigger=%{public}d, triggerSet=%{public}u",
                    module, fd, trigger, it->triggerSet);
                break;
            }
            it->triggerSet |= trigger;
            CONN_LOGI(CONN_COMMON, "add trigger success, module=%{public}d, fd=%{public}d, newAddTrigger=%{public}d, "
                                   "triggerSet=%{public}u", module, fd, trigger, it->triggerSet);
            wakeup = true;
            break;
        }

        FdNode *fdNode = (FdNode *)SoftBusCalloc(sizeof(FdNode));
        if (fdNode == NULL) {
            CONN_LOGE(CONN_COMMON, "calloc fd node object failed, module=%{public}d, fd=%{public}d, trigger=%{public}d",
                module, fd, trigger);
            status = SOFTBUS_MALLOC_ERR;
            break;
        }
        ListInit(&fdNode->node);
        fdNode->fd = fd;
        fdNode->triggerSet = trigger;
        ListAdd(&node->info.waitEventFds, &fdNode->node);
        node->info.waitEventFdsLen += 1;
        wakeup = true;
        CONN_LOGI(CONN_COMMON, "add trigger success, module=%{public}d, fd=%{public}d, trigger=%{public}d",
            module, fd, trigger);
    } while (false);

    (void)SoftBusMutexUnlock(&node->lock);
    ReturnListenerNode(&node);

    if (status == SOFTBUS_OK && wakeup) {
        WakeupSelectThread();
    }
    return status;
}

int32_t DelTrigger(ListenerModule module, int32_t fd, TriggerType trigger)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(module >= 0 && module < UNUSE_BUTT, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "invalid module, module=%{public}d", module);
    CONN_CHECK_AND_RETURN_RET_LOGW(fd > 0, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "invalid fd, module=%{public}d, fd=%{public}d", module, fd);
    CONN_CHECK_AND_RETURN_RET_LOGW(IsValidTriggerType(trigger), SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "invalid trigger, module=%{public}d, fd=%{public}d, trigger=%{public}d", module, fd, trigger);

    CONN_LOGI(CONN_COMMON,
        "receive request, module=%{public}d, fd=%{public}d, trigger=%{public}d", module, fd, trigger);
    SoftbusListenerNode *node = GetListenerNode(module);
    CONN_CHECK_AND_RETURN_RET_LOGW(node != NULL, SOFTBUS_NOT_FIND, CONN_COMMON,
        "listener node not exist, module=%{public}d, fd=%{public}d, trigger=%{public}d", module, fd, trigger);

    int32_t status = SoftBusMutexLock(&node->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "lock listener node failed, module=%{public}d, fd=%{public}d, trigger=%{public}d, "
                               "error=%{public}d", module, fd, trigger, status);
        ReturnListenerNode(&node);
        return SOFTBUS_LOCK_ERR;
    }

    bool wakeup = false;
    do {
        FdNode *target = NULL;
        FdNode *it = NULL;
        LIST_FOR_EACH_ENTRY(it, &node->info.waitEventFds, FdNode, node) {
            if (fd == it->fd) {
                target = it;
                break;
            }
        }

        if (target == NULL) {
            CONN_LOGW(CONN_COMMON, "fd node not exist, module=%{public}d, fd=%{public}d, trigger=%{public}d",
                module, fd, trigger);
            // consider delete trigger success,
            status = SOFTBUS_OK;
            break;
        }

        if ((target->triggerSet & trigger) == 0) {
            CONN_LOGW(CONN_COMMON,
                "without add trigger before, repeat delete trigger or mismatch module. "
                "module=%{public}d, fd=%{public}d, wantDeleteTrigger=%{public}d, triggerSet=%{public}u",
                module, fd, trigger, it->triggerSet);
            // consider delete trigger success,
            status = SOFTBUS_OK;
            break;
        }

        target->triggerSet &= ~trigger;
        wakeup = true;
        if (target->triggerSet != 0) {
            CONN_LOGI(CONN_COMMON, "delete trigger success, module=%{public}d, fd=%{public}d, trigger=%{public}d, "
                                   "triggerSet=%{public}u", module, fd, trigger, target->triggerSet);
            status = SOFTBUS_OK;
            break;
        }
        CONN_LOGI(
            CONN_COMMON,
            "delete trigger success, free fd node now, module=%{public}d, fd=%{public}d, trigger=%{public}d",
            module, fd, trigger);
        ListDelete(&target->node);
        SoftBusFree(target);
        node->info.waitEventFdsLen -= 1;
    } while (false);

    SoftBusMutexUnlock(&node->lock);
    ReturnListenerNode(&node);

    if (status == SOFTBUS_OK && wakeup) {
        WakeupSelectThread();
    }
    return status;
}

static void CleanupSelectThreadState(SelectThreadState **statePtr)
{
    SelectThreadState *state = *statePtr;
    if (state->ctrlRfd != 0) {
        ConnCloseSocket(state->ctrlRfd);
    }
    if (state->ctrlWfd != 0) {
        ConnCloseSocket(state->ctrlWfd);
    }

    CONN_LOGI(CONN_COMMON, "cleanup select thread state, traceId=%{public}d, ctrlRfd=%{public}d, ctrlWfd=%{public}d",
        state->traceId, state->ctrlRfd, state->ctrlWfd);
    (void)SoftBusMutexDestroy(&state->lock);
    SoftBusFree(state);
    *statePtr = NULL;
}

static void ProcessCtrlFdEvent(int32_t fd, int32_t wakeupTrace)
{
#ifndef __LITEOS__
    while (true) {
        int32_t ctrlTraceId = 0;
        ssize_t len = read(fd, &ctrlTraceId, sizeof(ctrlTraceId));
        if (len < 0) {
            int32_t status = errno;
            if (status == EINTR) {
                continue;
            } else if (status == EAGAIN) {
                break;
            } else {
                CONN_LOGE(
                    CONN_COMMON, "wakeupTrace=%{public}d, fd=%{public}d, readLen=%{public}zd, error=%{public}d",
                    wakeupTrace, fd, len, status);
                break;
            }
        }
        CONN_LOGI(CONN_COMMON, "wakeup ctrl message received, wakeupTrace=%{public}d, fd=%{public}d, "
                               "ctrlTraceId=%{public}d, readLength=%{public}zd", wakeupTrace, fd, ctrlTraceId, len);
    }
#endif
}

static void DispatchFdEvent(
    int32_t fd, ListenerModule module, enum SocketEvent event, const SoftbusBaseListener *listener, int32_t wakeupTrace)
{
    if (listener->onDataEvent != NULL) {
        listener->onDataEvent(module, event, fd);
    } else {
        CONN_LOGE(CONN_COMMON,
            "new event coming, but event listener not registered, to avoid repeat wakeup "
            "select(LEVEL MODE), close it, wakeupTrace=%{public}d, module=%{public}d, fd=%{public}d, event=%{public}d",
            wakeupTrace, module, fd, event);
        ConnCloseSocket(fd);
    }
}

static int32_t ProcessSpecifiedServerAcceptEvent(ListenerModule module, int32_t listenFd, ConnectType connectType,
    const SocketInterface *socketIf, const SoftbusBaseListener *listener, int32_t wakeupTrace)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(socketIf != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "socket interface implement is null, wakeupTrace=%{public}d, module=%{public}d", wakeupTrace, module);
    CONN_CHECK_AND_RETURN_RET_LOGW(socketIf->AcceptClient != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "socket interface implement not support AcceptClient method, wakeupTrace=%{public}d, module=%{public}d",
        wakeupTrace, module);

    int32_t status = SOFTBUS_OK;
    while (true) {
        int32_t clientFd = -1;
        ConnectOption clientAddr = {
            .type = connectType,
            .socketOption = {
                .addr = { 0 },
                .port = 0,
                .moduleId = module,
                .protocol = 0,
                .keepAlive = 0,
            },
        };
        status = SOFTBUS_TEMP_FAILURE_RETRY(socketIf->AcceptClient(listenFd, &clientAddr, &clientFd));
        if (status != SOFTBUS_OK) {
            break;
        }

        char animizedIp[IP_LEN] = { 0 };
        ConvertAnonymizeIpAddress(animizedIp, IP_LEN, clientAddr.socketOption.addr, IP_LEN);
        if (listener->onConnectEvent != NULL) {
            CONN_LOGI(CONN_COMMON,
                "trigger ACCEPT event, wakeupTrace=%{public}d, module=%{public}d, listenFd=%{public}d, "
                "clientIp=%{public}s, clientFd=%{public}d", wakeupTrace, module, listenFd, animizedIp, clientFd);
            listener->onConnectEvent(module, clientFd, &clientAddr);
        } else {
            CONN_LOGE(CONN_COMMON,
                "trigger ACCEPT event, but event listener not registered, wakeupTrace=%{public}d, module=%{public}d, "
                "listenFd=%{public}d, clientIp=%{public}s, clientFd=%{public}d",
                wakeupTrace, module, listenFd, animizedIp, clientFd);
            ConnCloseSocket(clientFd);
        }
    }
    return status;
}

static int32_t CopyWaitEventFdsUnsafe(const SoftbusListenerNode *node, FdNode **outArray, uint32_t *outArrayLen)
{
    if (node->info.waitEventFdsLen == 0) {
        *outArray = NULL;
        outArrayLen = 0;
        return SOFTBUS_OK;
    }

    uint32_t fdArrayLen = node->info.waitEventFdsLen;
    FdNode *fdArray = (FdNode *)SoftBusCalloc(fdArrayLen * sizeof(FdNode));
    CONN_CHECK_AND_RETURN_RET_LOGE(fdArray != NULL, SOFTBUS_MALLOC_ERR, CONN_COMMON,
        "calloc fd node array object failed, module=%{public}d, eventLen=%{public}u", node->module, fdArrayLen);

    uint32_t i = 0;
    FdNode *item = NULL;
    bool expand = false;
    LIST_FOR_EACH_ENTRY(item, &node->info.waitEventFds, FdNode, node) {
        if (i >= fdArrayLen) {
            uint32_t tmpLen = fdArrayLen * FDARR_EXPAND_BASE;
            FdNode *tmp = (FdNode *)SoftBusCalloc(tmpLen * sizeof(FdNode));
            if (tmp == NULL) {
                CONN_LOGE(CONN_COMMON, "expand calloc fd node array object failed, module=%{public}d, "
                                       "eventLen=%{public}u", node->module, tmpLen);
                SoftBusFree(fdArray);
                return SOFTBUS_MALLOC_ERR;
            }
            for (uint32_t j = 0; j < fdArrayLen; j++) {
                tmp[j].fd = fdArray[j].fd;
                tmp[j].triggerSet = fdArray[j].triggerSet;
            }
            SoftBusFree(fdArray);
            fdArray = tmp;
            fdArrayLen = tmpLen;
            expand = true;
        }
        fdArray[i].fd = item->fd;
        fdArray[i].triggerSet = item->triggerSet;
        i++;
    }

    // diagnose by the way
    if (expand) {
        CONN_LOGE(CONN_COMMON,
            "listener node 'waitEventFdsLen' field is unexpected, actual wait event fd size larger than it, "
            "module=%{public}d, waitEventFdsLen=%{public}u, actualWaitEventFdsLen=%{public}u",
            node->module, node->info.waitEventFdsLen, i);
    } else if (i != fdArrayLen) {
        CONN_LOGE(CONN_COMMON,
            "listener node 'waitEventFdsLen' field is unexpected, actual wait event fd size lower than it, "
            "module=%{public}d, waitEventFdsLen=%{public}u, actualWaitEventFdsLen=%{public}u",
            node->module, node->info.waitEventFdsLen, i);
    }

    *outArrayLen = i;
    *outArray = fdArray;
    return SOFTBUS_OK;
}

static void CloseInvalidListenForcely(SoftbusListenerNode *node, int32_t listenFd, const char *anomizedIp,
    int32_t reason)
{
    CONN_CHECK_AND_RETURN_LOGE(
        SoftBusMutexLock(&node->lock) == SOFTBUS_OK, CONN_COMMON, "lock listener node failed, module=%{public}d",
        node->module);
    do {
        if (node->info.status != LISTENER_RUNNING || node->info.modeType != SERVER_MODE ||
            node->info.listenFd != listenFd) {
            break;
        }
        CONN_LOGW(CONN_COMMON, "forcely close to prevent repeat wakeup select, module=%{public}d, "
            "listenFd=%{public}d, port=%{public}d, ip=%{public}s, error=%{public}d",
            node->module, node->info.listenFd, node->info.listenPort, anomizedIp, reason);
        ConnCloseSocket(node->info.listenFd);
        node->info.listenFd = -1;
        node->info.listenPort = -1;
    } while (false);
    SoftBusMutexUnlock(&node->lock);
}

static void ProcessSpecifiedListenerNodeEvent(SoftbusListenerNode *node, SoftBusFdSet *readSet, SoftBusFdSet *writeSet,
    SoftBusFdSet *exceptSet, int32_t wakeupTrace)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&node->lock) == SOFTBUS_OK, CONN_COMMON,
        "lock listener node failed, wakeupTrace=%{public}d, module=%{public}d", wakeupTrace, node->module);
    if (node->info.status != LISTENER_RUNNING) {
        SoftBusMutexUnlock(&node->lock);
        return;
    }

    int32_t listenFd = -1;
    int32_t listenPort = -1;
    char animizedIp[IP_LEN] = { 0 };
    if (node->info.modeType == SERVER_MODE && node->info.listenFd > 0) {
        listenFd = node->info.listenFd;
        listenPort = node->info.listenPort;
        ConvertAnonymizeIpAddress(animizedIp, IP_LEN, node->info.listenerInfo.socketOption.addr, IP_LEN);
    }
    const SocketInterface *socketIf = node->socketIf;
    SoftbusBaseListener listener = node->listener;
    ConnectType connectType = node->info.listenerInfo.type;

    FdNode *fdArray = NULL;
    uint32_t fdArrayLen = 0;
    int32_t status = CopyWaitEventFdsUnsafe(node, &fdArray, &fdArrayLen);
    SoftBusMutexUnlock(&node->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON,
            "copy wait event fds failed, wakeupTrace=%{public}d, module=%{public}d, error=%{public}d",
            wakeupTrace, node->module, status);
        return;
    }

    if (listenFd > 0 && SoftBusSocketFdIsset(listenFd, readSet)) {
        status =
            ProcessSpecifiedServerAcceptEvent(node->module, listenFd, connectType, socketIf, &listener, wakeupTrace);
        switch (status) {
            case SOFTBUS_OK:
            case SOFTBUS_ADAPTER_SOCKET_EAGAIN:
                break;
            case SOFTBUS_ADAPTER_SOCKET_EINVAL:
            case SOFTBUS_ADAPTER_SOCKET_EBADF:
                CloseInvalidListenForcely(node, listenFd, animizedIp, status);
                break;
            default:
                CONN_LOGD(CONN_COMMON,
                    "accept client failed, wakeupTrace=%{public}d, module=%{public}d, listenFd=%{public}d, "
                    "port=%{public}d, ip=%{public}s, error=%{public}d",
                    wakeupTrace, node->module, listenFd, listenPort, animizedIp, status);
                break;
        }
    }

    if (fdArrayLen == 0) {
        return;
    }

    for (uint32_t i = 0; i < fdArrayLen; i++) {
        if ((fdArray[i].triggerSet & READ_TRIGGER) != 0 && SoftBusSocketFdIsset(fdArray[i].fd, readSet)) {
            CONN_LOGD(CONN_COMMON, "trigger IN event, wakeupTrace=%{public}d, module=%{public}d, fd=%{public}d, "
                                   "triggerSet=%{public}u",
                wakeupTrace, node->module, fdArray[i].fd, fdArray[i].triggerSet);
            DispatchFdEvent(fdArray[i].fd, node->module, SOFTBUS_SOCKET_IN, &listener, wakeupTrace);
        }
        if ((fdArray[i].triggerSet & WRITE_TRIGGER) != 0 && SoftBusSocketFdIsset(fdArray[i].fd, writeSet)) {
            CONN_LOGD(CONN_COMMON, "trigger OUT event, wakeupTrace=%{public}d, module=%{public}d, fd=%{public}d, "
                                   "triggerSet=%{public}u",
                wakeupTrace, node->module, fdArray[i].fd, fdArray[i].triggerSet);
            DispatchFdEvent(fdArray[i].fd, node->module, SOFTBUS_SOCKET_OUT, &listener, wakeupTrace);
        }
        if ((fdArray[i].triggerSet & EXCEPT_TRIGGER) != 0 && SoftBusSocketFdIsset(fdArray[i].fd, exceptSet)) {
            CONN_LOGW(CONN_COMMON,
                "trigger EXCEPTION(out-of-band data) event, wakeupTrace=%{public}d, module=%{public}d, fd=%{public}d, "
                "triggerSet=%{public}u", wakeupTrace, node->module, fdArray[i].fd, fdArray[i].triggerSet);
            DispatchFdEvent(fdArray[i].fd, node->module, SOFTBUS_SOCKET_EXCEPTION, &listener, wakeupTrace);
        }
        // RW_TRIGGER is already triggered in READ_TRIGGER and WRITE_TRIGGER, just skip it
    }
    SoftBusFree(fdArray);
}

static void ProcessEvent(SoftBusFdSet *readSet, SoftBusFdSet *writeSet, SoftBusFdSet *exceptSet,
    const SelectThreadState *selectState, int32_t wakeupTrace)
{
    for (ListenerModule module = 0; module < UNUSE_BUTT; module++) {
        SoftbusListenerNode *node = GetListenerNode(module);
        if (node == NULL) {
            continue;
        }
        ProcessSpecifiedListenerNodeEvent(node, readSet, writeSet, exceptSet, wakeupTrace);
        ReturnListenerNode(&node);
    }

    if (SoftBusSocketFdIsset(selectState->ctrlRfd, readSet)) {
        ProcessCtrlFdEvent(selectState->ctrlRfd, wakeupTrace);
    }
}

static int32_t CollectSpecifiedModuleListenerEvents(
    SoftbusListenerNode *node, SoftBusFdSet *readSet, SoftBusFdSet *writeSet, SoftBusFdSet *exceptSet)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&node->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_COMMON,
        "lock listener node failed, module=%{public}d", node->module);

    if (node->info.status != LISTENER_RUNNING) {
        (void)SoftBusMutexUnlock(&node->lock);
        return 0;
    }

    int32_t maxFd = 0;
    if (node->info.modeType == SERVER_MODE && node->info.listenFd > 0) {
        SoftBusSocketFdSet(node->info.listenFd, readSet);
        maxFd = node->info.listenFd;
    }

    FdNode *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &node->info.waitEventFds, FdNode, node) {
        if ((it->triggerSet & READ_TRIGGER) != 0) {
            SoftBusSocketFdSet(it->fd, readSet);
        }
        if ((it->triggerSet & WRITE_TRIGGER) != 0) {
            SoftBusSocketFdSet(it->fd, writeSet);
        }
        if ((it->triggerSet & EXCEPT_TRIGGER) != 0) {
            SoftBusSocketFdSet(it->fd, exceptSet);
        }
        // RW_TRIGGER is already collected in READ_TRIGGER and WRITE_TRIGGER, just skip it
        maxFd = it->fd > maxFd ? it->fd : maxFd;
    }
    (void)SoftBusMutexUnlock(&node->lock);
    return maxFd;
}

static int32_t CollectWaitEventFdSet(SoftBusFdSet *readSet, SoftBusFdSet *writeSet, SoftBusFdSet *exceptSet)
{
    int32_t maxFd = 0;
    int32_t statusOrFd = 0;
    int32_t status = SOFTBUS_OK;
    do {
        for (ListenerModule module = 0; module < UNUSE_BUTT; module++) {
            SoftbusListenerNode *node = GetListenerNode(module);
            if (node == NULL) {
                continue;
            }
            statusOrFd = CollectSpecifiedModuleListenerEvents(node, readSet, writeSet, exceptSet);
            ReturnListenerNode(&node);
            if (statusOrFd < 0) {
                status = statusOrFd;
                CONN_LOGE(CONN_COMMON, "collect wait event fd set failed: module=%{public}d, error=%{public}d",
                    module, status);
                break;
            }
            maxFd = statusOrFd > maxFd ? statusOrFd : maxFd;
        }
    } while (false);

    if (status != SOFTBUS_OK) {
        SoftBusSocketFdZero(readSet);
        SoftBusSocketFdZero(writeSet);
        SoftBusSocketFdZero(exceptSet);
        return status;
    }

    return maxFd;
}

static void *SelectTask(void *arg)
{
    static int32_t wakeupTraceIdGenerator = 0;

    SelectThreadState *selectState = (SelectThreadState *)arg;
    CONN_LOGI(CONN_COMMON, "select task start, selectTrace=%{public}d, ctrlRfd=%{public}d, ctrlWfd=%{public}d",
        selectState->traceId, selectState->ctrlRfd, selectState->ctrlWfd);
    while (true) {
        int status = SoftBusMutexLock(&selectState->lock);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "lock select thread state self failed, retry after some times. "
                                   "waitDelay=%{public}dms, selectTrace=%{public}d, error=%{public}d",
                SELECT_UNEXPECT_FAIL_RETRY_WAIT_MILLIS, selectState->traceId, status);
            SoftBusSleepMs(SELECT_UNEXPECT_FAIL_RETRY_WAIT_MILLIS);
            continue;
        }
        int32_t referenceCount = selectState->referenceCount;
        (void)SoftBusMutexUnlock(&selectState->lock);

        if (referenceCount <= 0) {
            CONN_LOGW(CONN_COMMON, "select task, select task is not reference by others any more, exit... "
                                   "selectTrace=%{public}d", selectState->traceId);
            break;
        }

        SoftBusFdSet readSet;
        SoftBusFdSet writeSet;
        SoftBusFdSet exceptSet;
        SoftBusSocketFdZero(&readSet);
        SoftBusSocketFdZero(&writeSet);
        SoftBusSocketFdZero(&exceptSet);
        int32_t maxFdOrStatus = CollectWaitEventFdSet(&readSet, &writeSet, &exceptSet);
        if (maxFdOrStatus < 0) {
            CONN_LOGE(CONN_COMMON, "collect wait event fd set failed, retry after some times. "
                                   "waitDelay=%{public}dms, selectTrace=%{public}d, error=%{public}d",
                SELECT_UNEXPECT_FAIL_RETRY_WAIT_MILLIS, selectState->traceId, maxFdOrStatus);
            SoftBusSocketFdZero(&readSet);
            SoftBusSocketFdZero(&writeSet);
            SoftBusSocketFdZero(&exceptSet);
            SoftBusSleepMs(SELECT_UNEXPECT_FAIL_RETRY_WAIT_MILLIS);
            continue;
        }
        SoftBusSocketFdSet(selectState->ctrlRfd, &readSet);
        int32_t maxFd = maxFdOrStatus > selectState->ctrlRfd ? maxFdOrStatus : selectState->ctrlRfd;
        int32_t nEvents = SoftBusSocketSelect(maxFd + 1, &readSet, &writeSet, &exceptSet, NULL);
        int32_t wakeupTraceId = ++wakeupTraceIdGenerator;
        if (nEvents <= 0) {
            CONN_LOGE(CONN_COMMON, "unexpect wakeup, retry after some times. "
                                   "waitDelay=%{public}dms, wakeupTraceId=%{public}d, events=%{public}d",
                SELECT_UNEXPECT_FAIL_RETRY_WAIT_MILLIS, wakeupTraceId, nEvents);
            SoftBusSleepMs(SELECT_UNEXPECT_FAIL_RETRY_WAIT_MILLIS);
            continue;
        }
        CONN_LOGI(CONN_COMMON, "select task, wakeup from select, selectTrace=%{public}d, wakeupTraceId=%{public}d, "
                               "events=%{public}d", selectState->traceId, wakeupTraceId, nEvents);
        ProcessEvent(&readSet, &writeSet, &exceptSet, selectState, wakeupTraceId);
    }
    CleanupSelectThreadState(&selectState);
    return NULL;
}

static int32_t StartSelectThread(void)
{
    static int32_t selectThreadTraceIdGenerator = 1;

    int32_t status = SoftBusMutexLock(&g_selectThreadStateLock);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        status == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_COMMON, "lock global select thread state failed");

    do {
        if (g_selectThreadState != NULL) {
            status = SoftBusMutexLock(&g_selectThreadState->lock);
            if (status != SOFTBUS_OK) {
                CONN_LOGE(CONN_COMMON, "lock select thread state self failed, error=%{public}d", status);
                status = SOFTBUS_LOCK_ERR;
                break;
            }
            int32_t referenceCount = ++g_selectThreadState->referenceCount;
            (void)SoftBusMutexUnlock(&g_selectThreadState->lock);
            WakeupSelectThread();

            CONN_LOGW(CONN_COMMON,
                "select thread is already start, selectTrace=%{public}d, ctrlRfd=%{public}d, ctrlWfd=%{public}d, "
                "referenceCount=%{public}d",
                g_selectThreadState->traceId, g_selectThreadState->ctrlRfd, g_selectThreadState->ctrlWfd,
                referenceCount);
            break;
        }

        SelectThreadState *state = SoftBusCalloc(sizeof(SelectThreadState));
        if (state == NULL) {
            status = SOFTBUS_ERR;
            break;
        }
        state->traceId = ++selectThreadTraceIdGenerator;
        int32_t fds[2] = { 0 };
        int32_t rc = 0;
#ifndef __LITEOS__
        rc = pipe2(fds, O_CLOEXEC | O_NONBLOCK);
#endif
        if (rc != 0) {
            CONN_LOGE(CONN_COMMON, "create ctrl pipe failed, error=%{public}s", strerror(errno));
            SoftBusFree(state);
            status = SOFTBUS_ERR;
            break;
        }
        state->ctrlRfd = fds[0];
        state->ctrlWfd = fds[1];

        status = SoftBusMutexInit(&state->lock, NULL);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "start select task async failed, error=%{public}d", status);
            CleanupSelectThreadState(&state);
            break;
        }
        state->referenceCount = 1;
        status = ConnStartActionAsync(state, SelectTask, "OS_selectTsk");
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "init lock failed, error=%{public}d", status);
            CleanupSelectThreadState(&state);
            break;
        }
        CONN_LOGI(CONN_COMMON,
            "start select thread success, traceId=%{public}d, ctrlRfd=%{public}d, ctrlWfd=%{public}d",
            state->traceId, state->ctrlRfd, state->ctrlWfd);
        g_selectThreadState = state;
    } while (false);
    (void)SoftBusMutexUnlock(&g_selectThreadStateLock);
    return status;
}

static int32_t StopSelectThread(void)
{
    int32_t status = SoftBusMutexLock(&g_selectThreadStateLock);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        status == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_COMMON, "lock global select thread state failed");
    do {
        if (g_selectThreadState == NULL) {
            CONN_LOGW(CONN_COMMON, "select thread is already stop or never start");
            break;
        }

        status = SoftBusMutexLock(&g_selectThreadState->lock);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "lock select thread state self");
            break;
        }
        g_selectThreadState->referenceCount -= 1;
        int32_t referenceCount = g_selectThreadState->referenceCount;
        (void)SoftBusMutexUnlock(&g_selectThreadState->lock);
        if (referenceCount <= 0) {
            CONN_LOGI(CONN_COMMON, "select thread is not used by other module any more, notify "
                "exit, thread reference count=%{public}d", referenceCount);
            WakeupSelectThread();
            g_selectThreadState = NULL;
        }
    } while (false);
    (void)SoftBusMutexUnlock(&g_selectThreadStateLock);
    return status;
}

static void WakeupSelectThread(void)
{
#ifndef __LITEOS__
    static int32_t selectWakeupTraceIdGenerator = 0;

    int32_t status = SoftBusMutexLock(&g_selectThreadStateLock);
    CONN_CHECK_AND_RETURN_LOGE(
        status == SOFTBUS_OK, CONN_COMMON, "lock global select thread state failed, error=%{public}d", status);
    do {
        if (g_selectThreadState == NULL) {
            CONN_LOGW(CONN_COMMON, "select thread is not running, just skip");
            break;
        }
        int32_t ctrlTraceId = selectWakeupTraceIdGenerator++;
        ssize_t len = write(g_selectThreadState->ctrlWfd, &ctrlTraceId, sizeof(ctrlTraceId));
        CONN_LOGI(CONN_COMMON, "wakeup ctrl message sent, writeLength=%{public}zd, ctrlTraceId=%{public}d",
            len, ctrlTraceId);
    } while (false);
    SoftBusMutexUnlock(&g_selectThreadStateLock);
#endif
}