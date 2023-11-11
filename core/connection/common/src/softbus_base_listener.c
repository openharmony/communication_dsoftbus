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

static SoftBusMutex g_listenerListLock = { 0 };
static SoftbusListenerNode *g_listenerList[UNUSE_BUTT] = { 0 };
static SoftBusMutex g_selectThreadStateLock = { 0 };
static SelectThreadState *g_selectThreadState = NULL;

static SoftbusListenerNode *GetListenerNode(ListenerModule module)
{
    int32_t status = SoftBusMutexLock(&g_listenerListLock);
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, NULL, CONN_COMMON,
        "ATTENTION UNEXPECTED ERROR! request listener node failed: try to lock listener lists failed, module=%d, "
        "error=%d", module, status);
    SoftbusListenerNode *node = g_listenerList[module];
    do {
        if (node == NULL) {
            break;
        }
        status = SoftBusMutexLock(&node->lock);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "ATTENTION UNEXPECTED ERROR! request listener node failed: try to lock "
                "listener failed, module=%d, error=%d", module, status);
            node = NULL;
            break;
        }
        node->objectRc += 1;
        SoftBusMutexUnlock(&node->lock);
    } while (false);
    (void)SoftBusMutexUnlock(&g_listenerListLock);
    return node;
}

static void RemoveListenerNode(SoftbusListenerNode *node)
{
    int32_t status = SoftBusMutexLock(&g_listenerListLock);
    CONN_CHECK_AND_RETURN_LOGE(status == SOFTBUS_OK, CONN_COMMON,
        "ATTENTION UNEXPECTED ERROR! remove listener node failed: try to lock listener lists failed, module=%d, "
        "error=%d", node->module, status);
    do {
        if (g_listenerList[node->module] != node) {
            CONN_LOGW(CONN_COMMON, "ATTENTION! remove listener node warning: listener node is not in "
                "listener list, repeat remove? just skip, module=%d", node->module);
            break;
        }
        status = SoftBusMutexLock(&node->lock);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "ATTENTION UNEXPECT ERROR! remove listener node failed: "
                "try to lock listener node failed, module=%d", node->module);
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
            CONN_LOGE(CONN_COMMON, "ATTENTION UNEXPECT ERROR! return listener node failed: "
                "try to lock listener node failed, module=%d", node->module);
            break;
        }
        node->objectRc -= 1;
        int32_t objectRc = node->objectRc;
        (void)SoftBusMutexUnlock(&node->lock);

        if (objectRc > 0) {
            break;
        }
        CONN_LOGI(CONN_COMMON,
            "release listener node, object reference count <= 0, free listener node, module=%d, object reference=%d",
            node->module, objectRc);
        (void)ShutdownBaseListener(node);
        SoftBusFree(node);
    } while (false);

    *nodePtr = NULL;
}

static SoftbusListenerNode *CreateSpecifiedListenerModule(ListenerModule module)
{
    SoftbusListenerNode *node = (SoftbusListenerNode *)SoftBusCalloc(sizeof(SoftbusListenerNode));
    CONN_CHECK_AND_RETURN_RET_LOGE(node != NULL, NULL, CONN_COMMON,
        "ATTENTION UNEXPECTED ERROR! create specified listener module failed: calloc listener node object failed, "
        "module=%d",
        module);

    node->module = module;
    // NOT apply recursive lock on purpose, problem will be exposes quickly if exist
    int32_t status = SoftBusMutexInit(&node->lock, NULL);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON,
            "ATTENTION UNEXPECTED ERROR! create specified listener module failed: init lock failed, module=%d, "
            "error=%d",
            module, status);
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

static int32_t CreateStaticModulesUnsafe(void)
{
    ListenerModule module = 0;
    for (; module < LISTENER_MODULE_DYNAMIC_START; module++) {
        SoftbusListenerNode *node = CreateSpecifiedListenerModule(module);
        if (node == NULL) {
            CONN_LOGW(CONN_COMMON, "create static module failed: create module listener node failed, module=%d",
                module);
            goto CLEANUP;
        }
        CONN_LOGI(CONN_COMMON, "create static module, create module listener node success, module=%d", module);
        g_listenerList[module] = node;
    }
    return SOFTBUS_OK;
CLEANUP:
    for (ListenerModule i = module - 1; i >= 0; i--) {
        SoftbusListenerNode *node = g_listenerList[i];
        g_listenerList[i] = NULL;
        // cleanup
        ReturnListenerNode(&node);
        CONN_LOGI(CONN_COMMON, "create static module failed: clean up listener node done, module=%d", module);
    }
    return SOFTBUS_ERR;
}

int32_t InitBaseListener(void)
{
    // stop select thread need re-enter lock
    SoftBusMutexAttr attr = {
        .type = SOFTBUS_MUTEX_RECURSIVE,
    };
    int32_t status = SoftBusMutexInit(&g_selectThreadStateLock, &attr);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT,
            "ATTENTION UNEXPECTED ERROR! init base listener failed: init select thread lock failed, error=%d",
            status);
        return SOFTBUS_LOCK_ERR;
    }
    // NOT apply recursive lock on purpose, problem will be exposes quickly if exist
    status = SoftBusMutexInit(&g_listenerListLock, NULL);
    if (status != SOFTBUS_OK) {
        SoftBusMutexDestroy(&g_selectThreadStateLock);
        CONN_LOGE(CONN_INIT,
            "ATTENTION UNEXPECTED ERROR! init base listener failed: init listener list lock failed, error=%d",
            status);
        return SOFTBUS_LOCK_ERR;
    }

    status = SoftBusMutexLock(&g_listenerListLock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT,
            "ATTENTION UNEXPECTED ERROR! init base listener failed: try to lock listener list failed, error=%d",
            status);
        SoftBusMutexDestroy(&g_selectThreadStateLock);
        SoftBusMutexDestroy(&g_listenerListLock);
        return SOFTBUS_LOCK_ERR;
    }
    (void)memset_s(g_listenerList, sizeof(g_listenerList), 0, sizeof(g_listenerList));
    status = CreateStaticModulesUnsafe();
    (void)SoftBusMutexUnlock(&g_listenerListLock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "init base listener failed: create static module listener failed, error=%d",
            status);
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
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, UNUSE_BUTT, CONN_COMMON,
        "ATTENTION UNEXPECTED ERROR! create listener module failed: try to lock listener list failed, error=%d",
        status);

    ListenerModule module = LISTENER_MODULE_DYNAMIC_START;
    for (; module <= LISTENER_MODULE_DYNAMIC_END; module++) {
        if (g_listenerList[module] != NULL) {
            continue;
        }
        SoftbusListenerNode *node = CreateSpecifiedListenerModule(module);
        if (node == NULL) {
            CONN_LOGE(CONN_COMMON, "create listener module failed, create specified listener module failed, module=%d",
                module);
            module = UNUSE_BUTT;
        } else {
            CONN_LOGI(CONN_COMMON, "create listener module success, module=%d", module);
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
        CONN_COMMON, "destroy base listener failed: only dynamic module support destroy, module=%d", module);

    CONN_LOGI(CONN_COMMON, "receive destroy base listener request, module=%d", module);
    SoftbusListenerNode *node = GetListenerNode(module);
    if (node == NULL) {
        CONN_LOGW(CONN_COMMON, "destroy base listener warning, listener not exist, module=%d", module);
        return;
    }
    RemoveListenerNode(node);
    ReturnListenerNode(&node);
}

int32_t StartBaseClient(ListenerModule module, const SoftbusBaseListener *listener)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(module >= 0 && module < UNUSE_BUTT, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "start base client listener failed: invalid module, module=%d", module);
    CONN_CHECK_AND_RETURN_RET_LOGW(listener != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "start base client listener failed: listener is null, module=%d", module);
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onConnectEvent != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "start base client listener failed: listener onConnectEvent is null, module=%d", module);
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onDataEvent != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "start base client listener failed: listener onDataEvent is null, module=%d", module);

    CONN_LOGI(CONN_COMMON, "receive start base client listener request, module=%d", module);

    SoftbusListenerNode *node = GetListenerNode(module);
    CONN_CHECK_AND_RETURN_RET_LOGW(node != NULL, SOFTBUS_NOT_FIND, CONN_COMMON,
        "start base client listener failed: get listener node failed, dynamic module forgot register "
                     "first? or static module start before base listener init? module=%d",
        module);

    int32_t status = SoftBusMutexLock(&node->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "ATTENTION UNEXPECTED ERROR! start base client listener failed: try to lock "
                           "listener node failed, module=%d, error=%d",
            module, status);
        ReturnListenerNode(&node);
        return SOFTBUS_LOCK_ERR;
    }
    do {
        if (node->info.status != LISTENER_IDLE) {
            CONN_LOGE(CONN_COMMON, "start base client listener failed: listener is not idle status, module=%d, "
                "status=%d", module, node->info.status);
            status = SOFTBUS_ERR;
            break;
        }
        node->listener.onConnectEvent = listener->onConnectEvent;
        node->listener.onDataEvent = listener->onDataEvent;
        status = StartSelectThread();
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "start base client listener failed: start select thread failed, module=%d, "
                "status=%d", module, status);
            break;
        }
        node->info.status = LISTENER_RUNNING;
        CONN_LOGI(CONN_COMMON, "start base client listener success, module=%d", module);
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
        CONN_LOGE(CONN_COMMON,
            "not find protocal implement, protocal implement should register first, module=%d, protocal=%d",
            module, protocol);
        return SOFTBUS_NOT_FIND;
    }
    node->socketIf = socketIf;

    int32_t listenFd = -1;
    int32_t listenPort = -1;
    int32_t status = SOFTBUS_OK;
    do {
        listenFd = socketIf->OpenServerSocket(info);
        if (listenFd < 0) {
            CONN_LOGE(CONN_COMMON, "create server socket failed: module=%d, invalid listen fd=%d", module,
                listenFd);
            status = SOFTBUS_TCP_SOCKET_ERR;
            break;
        }
        status = SoftBusSocketListen(listenFd, DEFAULT_BACKLOG);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "listen server socket failed: module=%d, error=%d", module, status);
            break;
        }
        listenPort = socketIf->GetSockPort(listenFd);
        if (listenPort < 0) {
            CONN_LOGE(CONN_COMMON, "get listen server port failed: module=%d, listen fd=%d, error=%d",
                module, listenFd, status);
            status = SOFTBUS_TCP_SOCKET_ERR;
            break;
        }
        if (memcpy_s(&node->info.listenerInfo, sizeof(LocalListenerInfo), info, sizeof(LocalListenerInfo)) != EOK) {
            CONN_LOGE(CONN_COMMON, "memcpy_s local listener info object failed: module=%d", module);
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
    CONN_CHECK_AND_RETURN_RET_LOGW(info != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "start base listener failed: info is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(info->type == CONNECT_TCP || info->type == CONNECT_P2P, SOFTBUS_INVALID_PARAM,
        CONN_COMMON, "start base listener failed: only CONNECT_TCP(%d) and CONNECT_P2P(%d) is permitted, type=%d",
        CONNECT_TCP, CONNECT_P2P, info->type);
    CONN_CHECK_AND_RETURN_RET_LOGW(info->socketOption.port >= 0, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "start base listener failed: port is invalid, port=%d", info->socketOption.port);
    CONN_CHECK_AND_RETURN_RET_LOGW(info->socketOption.moduleId >= 0 && info->socketOption.moduleId < UNUSE_BUTT,
        SOFTBUS_INVALID_PARAM, CONN_COMMON, "start base client listener failed: invalid module, module=%d",
        info->socketOption.moduleId);
    CONN_CHECK_AND_RETURN_RET_LOGW(listener != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "start base listener failed: listener is null, module=%d", info->socketOption.moduleId);
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onConnectEvent != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "start base listener failed: listener is null, module=%d", info->socketOption.moduleId);
    CONN_CHECK_AND_RETURN_RET_LOGW(listener->onDataEvent != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "start base listener failed: listener is null, module=%d", info->socketOption.moduleId);

    ListenerModule module = info->socketOption.moduleId;
    CONN_LOGI(CONN_COMMON, "receive start base listener request, module=%d", module);
    SoftbusListenerNode *node = GetListenerNode(module);
    CONN_CHECK_AND_RETURN_RET_LOGW(node != NULL, SOFTBUS_NOT_FIND, CONN_COMMON,
        "start base listener failed: get listener node failed, dynamic module should register first, module=%d",
        module);
    int32_t status = SoftBusMutexLock(&node->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "ATTENTION UNEXPECTED ERROR! start base listener failed: try to lock listener node "
            "failed, module=%d, error=%d", module, status);
        ReturnListenerNode(&node);
        return SOFTBUS_LOCK_ERR;
    }

    int32_t listenPort = -1;
    do {
        if (node->info.status != LISTENER_IDLE) {
            CONN_LOGE(CONN_COMMON, "start base listener failed: listener is not idle status, module=%d, status=%d",
                module, node->info.status);
            status = SOFTBUS_ERR;
            break;
        }

        node->listener.onConnectEvent = listener->onConnectEvent;
        node->listener.onDataEvent = listener->onDataEvent;
        if (memcpy_s(&node->info.listenerInfo, sizeof(LocalListenerInfo), info, sizeof(LocalListenerInfo)) != EOK) {
            CONN_LOGE(CONN_COMMON, "start base listener failed: memcpy_s listener info failed, module=%d",
                node->module);
            status = SOFTBUS_LOCK_ERR;
            break;
        }
        listenPort = StartServerListenUnsafe(node, info);
        if (listenPort <= 0) {
            CONN_LOGE(CONN_COMMON, "start base listener failed: start server failed, module=%d, invalid listen "
                "port=%d", module, listenPort);
            status = SOFTBUS_ERR;
            break;
        }

        status = StartSelectThread();
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "start base listener failed: start listener thread failed, module=%d, status=%d",
                module, status);
            CleanupServerListenInfoUnsafe(node);
            break;
        }
        node->info.status = LISTENER_RUNNING;
        CONN_LOGI(CONN_COMMON, "start base listener success, module=%d, listen fd=%d, listen port=%d", module,
            node->info.listenFd, listenPort);
    } while (false);
    (void)SoftBusMutexUnlock(&node->lock);
    ReturnListenerNode(&node);
    return status == SOFTBUS_OK ? listenPort : status;
}

int32_t StopBaseListener(ListenerModule module)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(module >= 0 && module < UNUSE_BUTT, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "stop base listener failed: invalid module, module=%d", module);

    CONN_LOGI(CONN_COMMON, "receive stop base listener request, module=%d", module);
    SoftbusListenerNode *node = GetListenerNode(module);
    CONN_CHECK_AND_RETURN_RET_LOGW(node != NULL, SOFTBUS_NOT_FIND, CONN_COMMON,
        "stop base listener failed: listener node not exist, module=%d", module);

    int32_t status = ShutdownBaseListener(node);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "stop base listener failed: stop listen thread failed, module=%d, error=%d",
            module, status);
    }
    ReturnListenerNode(&node);
    return status;
}

static int32_t ShutdownBaseListener(SoftbusListenerNode *node)
{
    int32_t status = SoftBusMutexLock(&node->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_COMMON,
        "ATTENTION UNEXPECTED ERROR! shutdown base listener failed: try to lock listener node failed, "
                     "module=%d, error=%d",
        node->module, status);

    do {
        if (node->info.status != LISTENER_RUNNING) {
            CONN_LOGW(CONN_COMMON,
                "shutdown base listener warning, listener is not running, just skip, module=%d, error=%d",
                node->module, node->info.status);
            break;
        }
        status = StopSelectThread();
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "shutdown base listener failed: stop select thread failed, module=%d, error=%d",
                node->module, status);
            break;
        }
        node->info.status = LISTENER_IDLE;

        FdNode *it = NULL;
        FdNode *next = NULL;
        LIST_FOR_EACH_ENTRY_SAFE(it, next, &node->info.waitEventFds, FdNode, node) {
            CONN_LOGE(CONN_COMMON,
                "ATTENTION, shutdown base listener warning: listener node there is fd not close, module=%d, fd=%d, "
                "trigger set=%u",
                node->module, it->fd, it->triggerSet);
            // not close fd, repeat close will crash process
            ListDelete(&it->node);
            SoftBusFree(it);
        }
        node->info.waitEventFdsLen = 0;

        int32_t listenFd = node->info.listenFd;
        int32_t listenPort = node->info.listenPort;
        if (node->info.modeType == SERVER_MODE && listenFd > 0) {
            CONN_LOGE(CONN_COMMON, "shutdown base listener, close server, module=%d, listen fd=%d, port=%d",
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
        "add trigger failed: invalid module, module=%d", module);
    CONN_CHECK_AND_RETURN_RET_LOGW(fd > 0, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "add trigger failed: invalid fd, module=%d, fd=%d", module, fd);
    CONN_CHECK_AND_RETURN_RET_LOGW(IsValidTriggerType(trigger), SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "add trigger failed: invalid trigger, module=%d, fd=%d, trigger=%d", module, fd, trigger);

    CONN_LOGI(CONN_COMMON, "receive add trigger request, module=%d, fd=%d, trigger=%d", module, fd, trigger);
    SoftbusListenerNode *node = GetListenerNode(module);
    CONN_CHECK_AND_RETURN_RET_LOGW(node != NULL, SOFTBUS_NOT_FIND, CONN_COMMON,
        "add trigger failed: listener node not exist, module=%d, fd=%d, trigger=%d", module, fd, trigger);

    int32_t status = SoftBusMutexLock(&node->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "ATTENTION UNEXPECTED ERROR! add trigger failed: try to lock listener node failed, "
                           "module=%d, fd=%d, trigger=%d, error=%d",
            module, fd, trigger, status);
        ReturnListenerNode(&node);
        return SOFTBUS_LOCK_ERR;
    }

    bool wakeup = false;
    do {
        if (node->info.status != LISTENER_RUNNING) {
            CONN_LOGE(CONN_COMMON, "add trigger failed: module is not running, call 'StartBaseListener' or "
                               "'StartBaseClient' first, module=%d, fd=%d, trigger=%d",
                module, fd, trigger);
            status = SOFTBUS_ERR;
            break;
        }

        if (node->info.waitEventFdsLen > MAX_LISTEN_EVENTS) {
            CONN_LOGE(CONN_COMMON, "add trigger failed: can not trigger more, fd exceed more than %d, module=%d, "
                "fd=%d, trigger=%d, wait event fds len=%d",
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
                CONN_LOGW(CONN_COMMON,
                    "repeat add trigger, just skip, module=%d, fd=%d, want add trigger=%d, exist trigger set=%u",
                    module, fd, trigger, it->triggerSet);
                break;
            }
            it->triggerSet |= trigger;
            CONN_LOGI(CONN_COMMON, "add trigger success, module=%d, fd=%d, new add trigger=%d, all trigger set=%u",
                module, fd, trigger, it->triggerSet);
            wakeup = true;
            break;
        }

        FdNode *fdNode = (FdNode *)SoftBusCalloc(sizeof(FdNode));
        if (fdNode == NULL) {
            CONN_LOGE(CONN_COMMON, "ATTENTION UNEXPECTED ERROR! add trigger failed: calloc fd node object failed, "
                               "module=%d, fd=%d, trigger=%d",
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
        CONN_LOGI(CONN_COMMON, "add trigger success, module=%d, fd=%d, trigger=%d", module, fd, trigger);
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
        "delete trigger failed: invalid module, module=%d", module);
    CONN_CHECK_AND_RETURN_RET_LOGW(fd > 0, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "delete trigger failed: invalid fd, module=%d, fd=%d", module, fd);
    CONN_CHECK_AND_RETURN_RET_LOGW(IsValidTriggerType(trigger), SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "delete trigger failed: invalid trigger, module=%d, fd=%d, trigger=%d", module, fd, trigger);

    CONN_LOGI(CONN_COMMON, "receive delete trigger request, module=%d, fd=%d, trigger=%d", module, fd, trigger);
    SoftbusListenerNode *node = GetListenerNode(module);
    CONN_CHECK_AND_RETURN_RET_LOGW(node != NULL, SOFTBUS_NOT_FIND, CONN_COMMON,
        "delete trigger failed: listener node not exist, module=%d, fd=%d, trigger=%d",
        module, fd, trigger);

    int32_t status = SoftBusMutexLock(&node->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "ATTENTION UNEXPECTED ERROR! delete trigger failed: try to lock listener node failed, "
                           "module=%d, fd=%d, trigger=%d, error=%d",
            module, fd, trigger, status);
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
            CONN_LOGW(CONN_COMMON,
                "delete trigger warning, fd node not exist, call delete trigger without add trigger before or mismatch "
                "module. You are warned, fix it quickly! module=%d, fd=%d, trigger=%d",
                module, fd, trigger);
            // consider delete trigger success,
            status = SOFTBUS_OK;
            break;
        }

        if ((target->triggerSet & trigger) == 0) {
            CONN_LOGW(CONN_COMMON,
                "delete trigger warning, without add trigger before, repeat delete trigger or mismatch module. You are "
                "warned, fix it quickly! module=%d, fd=%d,  want delete trigger=%d, exist trigger set=%u",
                module, fd, trigger, it->triggerSet);
            // consider delete trigger success,
            status = SOFTBUS_OK;
            break;
        }

        target->triggerSet &= ~trigger;
        wakeup = true;
        if (target->triggerSet != 0) {
            CONN_LOGI(CONN_COMMON, "delete trigger success, module=%d, fd=%d, trigger=%d, exist trigger set=%u",
                module, fd, trigger, target->triggerSet);
            status = SOFTBUS_OK;
            break;
        }
        CONN_LOGI(CONN_COMMON,
            "delete trigger success, there is not exist any trigger, free fd node now, module=%d, fd=%d, trigger=%d",
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

    CONN_LOGI(CONN_COMMON, "cleanup select thread state, traceId=%d, ctrl read fd=%d, ctrl write fd=%d",
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
                CONN_LOGE(CONN_COMMON,
                    "process ctrl fd event failed: wakeup trace=%d, fd=%d, invalid read len=%d, error=%d",
                    wakeupTrace, fd, len, status);
                break;
            }
        }
        CONN_LOGI(CONN_COMMON, "process ctrl fd event, wakeup ctrl message received, wakeup trace=%d, fd=%d, "
                           "ctrl trace=%d, read length=%d",
            wakeupTrace, fd, ctrlTraceId, len);
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
            "process fd event, new event coming, but event listener not registered, to avoid repeat wakeup "
            "select(LEVEL MODE), close it, wakeup trace=%d, module=%d, fd=%d, event=%d",
            wakeupTrace, module, fd, event);
        ConnCloseSocket(fd);
    }
}

static int32_t ProcessSpecifiedServerAcceptEvent(ListenerModule module, int32_t listenFd, ConnectType connectType,
    const SocketInterface *socketIf, const SoftbusBaseListener *listener, int32_t wakeupTrace)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(socketIf != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "process spectified listener node event failed: socket interface implement is null, wakeup trace=%d module=%d",
        wakeupTrace, module);
    CONN_CHECK_AND_RETURN_RET_LOGW(socketIf->AcceptClient != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "process spectified listener node event failed: socket interface implement not support "
                     "AcceptClient method, wakeup trace=%d, module=%d",
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
            CONN_LOGI(CONN_COMMON, "process spectified listener node event trace, trigger ACCEPT event, wakeup "
                "trace=%d, module=%d, listen fd=%d, client ip=%s, client fd=%d",
                wakeupTrace, module, listenFd, animizedIp, clientFd);
            listener->onConnectEvent(module, clientFd, &clientAddr);
        } else {
            CONN_LOGE(CONN_COMMON, "process spectified listener node event trace, trigger ACCEPT event, but event "
                "listener not registered, wakeup trace=%d, module=%d, listen fd=%d, client ip=%s, client fd=%d",
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
        "ATTENTION UNEXPECTED ERROR! copy wait event fds failed: calloc fd node array object failed, module=%d, "
        "wait event len=%u", node->module, fdArrayLen);

    uint32_t i = 0;
    FdNode *item = NULL;
    bool expand = false;
    LIST_FOR_EACH_ENTRY(item, &node->info.waitEventFds, FdNode, node) {
        if (i >= fdArrayLen) {
            uint32_t tmpLen = fdArrayLen * FDARR_EXPAND_BASE;
            FdNode *tmp = (FdNode *)SoftBusCalloc(tmpLen * sizeof(FdNode));
            if (tmp == NULL) {
                CONN_LOGE(CONN_COMMON,
                    "copy wait event fds failed: expand calloc fd node array object failed, module=%d, wait event "
                    "len=%u",
                    node->module, tmpLen);
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
            "ATTENTION! copy wait event fds warining, listener node 'waitEventFdsLen' field is unexpected, actual "
            "wait event fd size larget than it, forgot maintain while update fd? fix it quickly. module=%d, "
            "wait event fds len=%u, actual wait event fds len=%u",
            node->module, node->info.waitEventFdsLen, i);
    } else if (i != fdArrayLen) {
        CONN_LOGE(CONN_COMMON,
            "ATTENTION! copy wait event fds warining, listener node 'waitEventFdsLen' field is unexpected, actual "
            "wait event fd size lower than it, forgot maintain while update fd? fix it quickly. module=%d, "
            "wait event fds len=%u, actual wait event fds len=%u",
            node->module, node->info.waitEventFdsLen, i);
    }

    *outArrayLen = i;
    *outArray = fdArray;
    return SOFTBUS_OK;
}

static void CloseInvalidListenForcely(SoftbusListenerNode *node, int32_t listenFd, const char *anomizedIp,
    int32_t reason)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&node->lock) == SOFTBUS_OK, CONN_COMMON,
        "ATTENTION UNEXPECTED ERROR! close invalid listen forcely failed: try to lock listener node failed, module=%d",
        node->module);
    do {
        if (node->info.status != LISTENER_RUNNING || node->info.modeType != SERVER_MODE ||
            node->info.listenFd != listenFd) {
            break;
        }
        CONN_LOGW(CONN_COMMON, "ATTENTION, forcely close to prevent repeat wakeup select, module=%d, invalid listen "
            "fd=%d port=%d, ip=%s, error=%d", node->module, node->info.listenFd, node->info.listenPort, anomizedIp,
            reason);
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
        "ATTENTION UNEXPECTED ERROR! try to lock listener node failed, wakeup trace=%d, module=%d",
        wakeupTrace, node->module);
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
            "process spectified listener node event failed: copy wait event fds failed, wakeup trace=%d, module=%d, "
            "error=%d",
            wakeupTrace, node->module, status);
        return;
    }

    // TODO: process listen fd exception, rebuild listen socket
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
                    "process spectified listener node event failed: accept client failed, wakeup trace=%d, "
                    "module=%d, listen fd=%d, port=%d, ip=%s, error=%d",
                    wakeupTrace, node->module, listenFd, listenPort, animizedIp, status);
                break;
        }
    }

    if (fdArrayLen == 0) {
        return;
    }

    for (uint32_t i = 0; i < fdArrayLen; i++) {
        if ((fdArray[i].triggerSet & READ_TRIGGER) != 0 && SoftBusSocketFdIsset(fdArray[i].fd, readSet)) {
            CONN_LOGD(CONN_COMMON,
                "process spectified listener node event trace, trigger IN event, wakeup trace=%d, module=%d, fd=%d, "
                "trigger set=%u",
                wakeupTrace, node->module, fdArray[i].fd, fdArray[i].triggerSet);
            DispatchFdEvent(fdArray[i].fd, node->module, SOFTBUS_SOCKET_IN, &listener, wakeupTrace);
        }
        if ((fdArray[i].triggerSet & WRITE_TRIGGER) != 0 && SoftBusSocketFdIsset(fdArray[i].fd, writeSet)) {
            CONN_LOGD(CONN_COMMON,
                "process spectified listener node event trace, trigger OUT event, wakeup trace=%d, module=%d, fd=%d, "
                "trigger set=%u",
                wakeupTrace, node->module, fdArray[i].fd, fdArray[i].triggerSet);
            DispatchFdEvent(fdArray[i].fd, node->module, SOFTBUS_SOCKET_OUT, &listener, wakeupTrace);
        }
        if ((fdArray[i].triggerSet & EXCEPT_TRIGGER) != 0 && SoftBusSocketFdIsset(fdArray[i].fd, exceptSet)) {
            CONN_LOGW(CONN_COMMON,
                "process spectified listener node event trace, trigger EXCEPTION(out-of-band data) event, wakeup "
                "trace=%d, module=%d, fd=%d, trigger set=%u",
                wakeupTrace, node->module, fdArray[i].fd, fdArray[i].triggerSet);
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
        "ATTENTION UNEXPECTED ERROR! collect wait event fd set failed: try to lock listener node failed, module=%d",
        node->module);

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
                CONN_LOGE(CONN_COMMON, "collect wait event fd set failed: module=%d, error=%d", module, status);
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
#define SELECT_UNEXPECT_FAIL_RETRY_WAIT_MILLIS (3 * 1000)
    static int32_t wakeupTraceIdGenerator = 0;

    SelectThreadState *selectState = (SelectThreadState *)arg;
    CONN_LOGI(CONN_COMMON, "select task start, select trace=%d, ctrl read fd=%d, ctrl write fd=%d",
        selectState->traceId, selectState->ctrlRfd, selectState->ctrlWfd);
    while (true) {
        int status = SoftBusMutexLock(&selectState->lock);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON,
                "ATTENTION UNEXPECTED ERROR! try to lock select thread state self failed, retry after %d ms, "
                "select trace=%d, error=%d",
                SELECT_UNEXPECT_FAIL_RETRY_WAIT_MILLIS, selectState->traceId, status);
            SoftBusSleepMs(SELECT_UNEXPECT_FAIL_RETRY_WAIT_MILLIS);
            continue;
        }
        int32_t referenceCount = selectState->referenceCount;
        (void)SoftBusMutexUnlock(&selectState->lock);

        if (referenceCount <= 0) {
            CONN_LOGW(CONN_COMMON, "select task, select task is not reference by others any more, select trace=%d, "
                "exit...", selectState->traceId);
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
            CONN_LOGE(CONN_COMMON,
                "select task failed: collect wait event fd set failed, retry after %d ms, select trace=%d, error=%d",
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
            CONN_LOGE(CONN_COMMON,
                "ATTENTION, select task failed: unexpect wakeup, retry after %d ms, wakeup trace id=%d, events=%d",
                SELECT_UNEXPECT_FAIL_RETRY_WAIT_MILLIS, wakeupTraceId, nEvents);
            SoftBusSleepMs(SELECT_UNEXPECT_FAIL_RETRY_WAIT_MILLIS);
            continue;
        }
        CONN_LOGI(CONN_COMMON, "select task, wakeup from select, select trace=%d, wakeup trace=%d, events=%d",
            selectState->traceId, wakeupTraceId, nEvents);
        ProcessEvent(&readSet, &writeSet, &exceptSet, selectState, wakeupTraceId);
    }
    CleanupSelectThreadState(&selectState);
    return NULL;
}

static int32_t StartSelectThread(void)
{
    static int32_t selectThreadTraceIdGenerator = 1;

    int32_t status = SoftBusMutexLock(&g_selectThreadStateLock);
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_COMMON,
        "ATTENTION UNEXPECTED ERROR! start select thread failed: try to lock global select thread state failed");

    do {
        if (g_selectThreadState != NULL) {
            status = SoftBusMutexLock(&g_selectThreadState->lock);
            if (status != SOFTBUS_OK) {
                CONN_LOGE(CONN_COMMON, "ATTENTION UNEXPECTED ERROR! start select thread failed: try to lock select "
                    "thread state self failed, error=%d",
                    status);
                status = SOFTBUS_LOCK_ERR;
                break;
            }
            int32_t referenceCount = ++g_selectThreadState->referenceCount;
            (void)SoftBusMutexUnlock(&g_selectThreadState->lock);
            WakeupSelectThread();

            CONN_LOGW(CONN_COMMON,
                "start select thread, select thread is already start, select trace=%d, ctrl read fd=%d, ctrl write "
                "fd=%d, reference count=%d",
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
            CONN_LOGE(CONN_COMMON, "start select thread failed: create ctrl pipe failed, error=%s", strerror(errno));
            SoftBusFree(state);
            status = SOFTBUS_ERR;
            break;
        }
        state->ctrlRfd = fds[0];
        state->ctrlWfd = fds[1];

        status = SoftBusMutexInit(&state->lock, NULL);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "start select thread failed: start select task async failed, error=%d", status);
            CleanupSelectThreadState(&state);
            break;
        }
        state->referenceCount = 1;
        status = ConnStartActionAsync(state, SelectTask);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "start select thread failed: init lock failed, error=%d", status);
            CleanupSelectThreadState(&state);
            break;
        }
        CONN_LOGI(CONN_COMMON, "start select thread success, trace id=%d, ctrl read fd=%d, ctrl write fd=%d",
            state->traceId, state->ctrlRfd, state->ctrlWfd);
        g_selectThreadState = state;
    } while (false);
    (void)SoftBusMutexUnlock(&g_selectThreadStateLock);
    return status;
}

static int32_t StopSelectThread(void)
{
    int32_t status = SoftBusMutexLock(&g_selectThreadStateLock);
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_COMMON,
        "ATTENTION UNEXPECTED ERROR! stop select thread failed: try to lock global select thread state "
                     "failed");
    do {
        if (g_selectThreadState == NULL) {
            CONN_LOGW(CONN_COMMON, "stop select thread, select thread is already stop or never start");
            break;
        }

        status = SoftBusMutexLock(&g_selectThreadState->lock);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "ATTENTION UNEXPECTED ERROR! stop select thread, try to lock select thread state "
                "self");
            break;
        }
        g_selectThreadState->referenceCount -= 1;
        int32_t referenceCount = g_selectThreadState->referenceCount;
        (void)SoftBusMutexUnlock(&g_selectThreadState->lock);
        if (referenceCount <= 0) {
            CONN_LOGI(CONN_COMMON, "stop select thread, select thread is not used by other module any more, notify "
                "exit, thread reference count=%d", referenceCount);
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
    CONN_CHECK_AND_RETURN_LOGE(status == SOFTBUS_OK, CONN_COMMON,
        "ATTENTION UNEXPECTED ERROR! wakeup select thread failed: try to lock global select thread state "
                     "failed, error=%d",
        status);
    do {
        if (g_selectThreadState == NULL) {
            CONN_LOGW(CONN_COMMON, "wakeup select thread warning: select thread is not running, just skip");
            break;
        }
        int32_t ctrlTraceId = selectWakeupTraceIdGenerator++;
        ssize_t len = write(g_selectThreadState->ctrlWfd, &ctrlTraceId, sizeof(ctrlTraceId));
        CONN_LOGI(CONN_COMMON, "wakeup select thread, wakeup ctrl message sent, write length=%d, ctrl trace=%d", len,
            ctrlTraceId);
    } while (false);
    SoftBusMutexUnlock(&g_selectThreadStateLock);
#endif
}