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

#include <fcntl.h>
#include <securec.h>
#include <stdatomic.h>
#include <unistd.h>

#include "common_list.h"
#include "conn_event.h"
#include "conn_log.h"
#include "softbus_adapter_errcode.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_conn_common.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_feature_config.h"
#include "softbus_socket.h"
#include "softbus_utils.h"
#include "softbus_watch_event_interface.h"

#define DEFAULT_BACKLOG   4
#define FDARR_EXPAND_BASE 2
#define WATCH_UNEXPECT_FAIL_RETRY_WAIT_MILLIS (3 * 1000)
#define WATCH_ABNORMAL_EVENT_RETRY_WAIT_MILLIS (3 * 10) /* wait retry time for an abnotmal event by watch*/
#define SOFTBUS_LISTENER_WATCH_TIMEOUT_MSEC (6 * 60 * 60 * 1000)

enum BaseListenerStatus {
    LISTENER_IDLE = 0,
    LISTENER_RUNNING,
};

typedef struct {
    ListNode waitEventFds;
    uint32_t waitEventFdsLen;

    ModeType modeType;
    int32_t listenFd;
    int32_t listenPort;

    enum BaseListenerStatus status;
    LocalListenerInfo listenerInfo;
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
    int32_t referenceCount;
    SoftBusMutex lock;
} WatchThreadState;

static int32_t ShutdownBaseListener(SoftbusListenerNode *node);
static int32_t StartWatchThread(void);
static int32_t StopWatchThread(void);
static SoftbusListenerNode *CreateSpecifiedListenerModule(ListenerModule module);

static SoftBusMutex g_listenerListLock = { 0 };
static SoftbusListenerNode *g_listenerList[UNUSE_BUTT] = { 0 };
static SoftBusMutex g_watchThreadStateLock = { 0 };
static WatchThreadState *g_watchThreadState = NULL;
static EventWatcher *g_eventWatcher = NULL;
static _Atomic bool g_initBaseListener = false;

static SoftbusListenerNode *GetListenerNodeCommon(ListenerModule module, bool create)
{
    int32_t status = SoftBusMutexLock(&g_listenerListLock);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        status == SOFTBUS_OK, NULL, CONN_COMMON, "lock failed, module=%{public}d, error=%{public}d",
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
        SoftBusMutexDestroy(&node->lock);
        SoftBusFree(node);
    } while (false);

    *nodePtr = NULL;
}

static SoftbusListenerNode *CreateSpecifiedListenerModule(ListenerModule module)
{
    SoftbusListenerNode *node = (SoftbusListenerNode *)SoftBusCalloc(sizeof(SoftbusListenerNode));
    CONN_CHECK_AND_RETURN_RET_LOGE(
        node != NULL, NULL, CONN_COMMON, "calloc failed, module=%{public}d", module);

    node->module = module;
    // NOT apply recursive lock on purpose, problem will be exposes quickly if exist
    int32_t status = SoftBusMutexInit(&node->lock, NULL);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "init lock failed, module=%{public}d, error=%{public}d", module, status);
        SoftBusFree(node);
        return NULL;
    }
    node->listener.onConnectEvent = NULL;
    node->listener.onDataEvent = NULL;

    node->socketIf = NULL;

    ListInit(&node->info.waitEventFds);
    node->info.waitEventFdsLen = 0;
    node->info.modeType = UNSET_MODE;
    (void)memset_s(&node->info.listenerInfo, sizeof(LocalListenerInfo), 0, sizeof(LocalListenerInfo));
    node->info.listenFd = -1;
    node->info.listenPort = -1;
    // set root object reference count 1
    node->objectRc = 1;
    return node;
}

static int32_t AddFdNode(ListNode *fdList, int32_t fd, uint32_t event)
{
    struct FdNode *fdNode = (struct FdNode *)SoftBusCalloc(sizeof(struct FdNode));
    CONN_CHECK_AND_RETURN_RET_LOGE(fdNode != NULL, SOFTBUS_MALLOC_ERR, CONN_COMMON, "calloc fdNode failed");
    ListInit(&fdNode->node);
    fdNode->fd = fd;
    fdNode->triggerSet = event;
    ListAdd(fdList, &fdNode->node);
    return SOFTBUS_OK;
}

static int32_t CollectModuleFdEvent(SoftbusListenerNode *node, ListNode *list)
{
    int32_t ret = SoftBusMutexLock(&node->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_COMMON,
        "lock failed, module=%{public}d, error=%{public}d", node->module, ret);

    if (node->info.status != LISTENER_RUNNING) {
        (void)SoftBusMutexUnlock(&node->lock);
        return 0;
    }

    ret = SOFTBUS_OK;
    if (node->info.modeType == SERVER_MODE && node->info.listenFd > 0) {
        ret = AddFdNode(list, node->info.listenFd, READ_TRIGGER);
        if (ret != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "add fd node failed, fd=%{public}d, status=%{public}d", node->info.listenFd, ret);
            (void)SoftBusMutexUnlock(&node->lock);
            return ret;
        }
    }

    struct FdNode *it = NULL;
    LIST_FOR_EACH_ENTRY(it, &node->info.waitEventFds, struct FdNode, node) {
        ret = AddFdNode(list, it->fd, it->triggerSet);
        if (ret != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "add fd node failed, fd=%{public}d, status=%{public}d", it->fd, ret);
            (void)SoftBusMutexUnlock(&node->lock);
            return ret;
        }
    }
    (void)SoftBusMutexUnlock(&node->lock);
    return ret;
}

static int32_t OnGetAllFdEvent(ListNode *list)
{
    int32_t status = SOFTBUS_OK;
    for (ListenerModule module = 0; module < UNUSE_BUTT; module++) {
        SoftbusListenerNode *node = GetListenerNode(module);
        if (node == NULL) {
            continue;
        }
        status = CollectModuleFdEvent(node, list);
        ReturnListenerNode(&node);
        if (status != SOFTBUS_OK) {
            ReleaseFdNode(list);
            CONN_LOGE(CONN_COMMON, "collect wait event fd set failed: module=%{public}d, error=%{public}d",
                module, status);
            break;
        }
    }
    return status;
}

static int32_t InitBaseListenerLock(void)
{
    // stop watch thread need re-enter lock
    SoftBusMutexAttr attr = {
        .type = SOFTBUS_MUTEX_RECURSIVE,
    };
    int32_t status = SoftBusMutexInit(&g_watchThreadStateLock, &attr);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "init watch thread lock failed, error=%{public}d", status);
        return SOFTBUS_LOCK_ERR;
    }
    // NOT apply recursive lock on purpose, problem will be exposes quickly if exist
    status = SoftBusMutexInit(&g_listenerListLock, NULL);
    if (status != SOFTBUS_OK) {
        SoftBusMutexDestroy(&g_watchThreadStateLock);
        CONN_LOGE(CONN_INIT, "init listener list lock failed, error=%{public}d", status);
        return SOFTBUS_LOCK_ERR;
    }
    return SOFTBUS_OK;
}

int32_t InitBaseListener(void)
{
    if (atomic_load_explicit(&g_initBaseListener, memory_order_acquire)) {
        return SOFTBUS_OK;
    }
    // flag : if the client and server are in the same process, this function can be executed only once.
    static bool flag = false;
    if (flag) {
        return SOFTBUS_OK;
    }
    flag = true;

    CONN_CHECK_AND_RETURN_RET_LOGE(InitBaseListenerLock() == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_COMMON,
        "init lock failed");
    int32_t status = SoftBusMutexLock(&g_listenerListLock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "lock listener list failed, error=%{public}d", status);
        SoftBusMutexDestroy(&g_watchThreadStateLock);
        SoftBusMutexDestroy(&g_listenerListLock);
        return SOFTBUS_LOCK_ERR;
    }
    (void)memset_s(g_listenerList, sizeof(g_listenerList), 0, sizeof(g_listenerList));
    (void)SoftBusMutexUnlock(&g_listenerListLock);
    g_eventWatcher = RegisterEventWatcher(OnGetAllFdEvent);
    if (g_eventWatcher == NULL) {
        CONN_LOGE(CONN_INIT, "register event watcher failed");
        SoftBusMutexDestroy(&g_watchThreadStateLock);
        SoftBusMutexDestroy(&g_listenerListLock);
        return SOFTBUS_MEM_ERR;
    }
    atomic_store_explicit(&g_initBaseListener, true, memory_order_release);
    return SOFTBUS_OK;
}

void DeinitBaseListener(void)
{
    if (!atomic_load_explicit(&g_initBaseListener, memory_order_acquire)) {
        return;
    }

    for (ListenerModule module = 0; module < UNUSE_BUTT; module++) {
        SoftbusListenerNode *node = GetListenerNode(module);
        if (node == NULL) {
            continue;
        }
        RemoveListenerNode(node);
        ReturnListenerNode(&node);
    }
    
    CloseEventWatcher(g_eventWatcher);
    atomic_store_explicit(&g_initBaseListener, false, memory_order_release);
}

uint32_t CreateListenerModule(void)
{
    int32_t status = SoftBusMutexLock(&g_listenerListLock);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        status == SOFTBUS_OK, UNUSE_BUTT, CONN_COMMON, "lock failed, error=%{public}d", status);

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
            status = SOFTBUS_CONN_LISTENER_NOT_IDLE;
            break;
        }
        node->listener.onConnectEvent = listener->onConnectEvent;
        node->listener.onDataEvent = listener->onDataEvent;
        status = StartWatchThread();
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "start watch thread failed, module=%{public}d, "
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
            status = listenFd;
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

static void FillConnEventExtra(const LocalListenerInfo *info, ConnEventExtra *extra, int32_t err)
{
    if (info == NULL || extra == NULL) {
        return;
    }
    extra->errcode = err;
    extra->result = err == SOFTBUS_OK ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;
    extra->linkType = info->type;
    extra->moduleId = info->socketOption.moduleId;
    extra->proType = info->socketOption.protocol;
}

int32_t StartBaseListener(const LocalListenerInfo *info, const SoftbusBaseListener *listener)
{
    ConnEventExtra extra = {
        .result = 0
    };
    CONN_EVENT(EVENT_SCENE_START_BASE_LISTENER, EVENT_STAGE_TCP_COMMON_ONE, extra);
    CONN_CHECK_AND_RETURN_RET_LOGW(info != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "info is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(info->type == CONNECT_TCP || info->type == CONNECT_P2P || info->type == CONNECT_HML,
        SOFTBUS_INVALID_PARAM, CONN_COMMON, "only CONNECT_TCP, CONNECT_P2P and CONNECT_HML is permitted, "
        "CONNECT_TCP=%{public}d, CONNECT_P2P=%{public}d, CONNECT_HML=%{public}d, type=%{public}d",
        CONNECT_TCP, CONNECT_P2P, CONNECT_HML, info->type);
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
    SoftbusListenerNode *node = GetOrCreateListenerNode(module);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        node != NULL, SOFTBUS_NOT_FIND, CONN_COMMON, "get listener node failed, module=%{public}d", module);
    int32_t status = SoftBusMutexLock(&node->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "lock failed, module=%{public}d, error=%{public}d", module, status);
        ReturnListenerNode(&node);
        FillConnEventExtra(info, &extra, SOFTBUS_LOCK_ERR);
        CONN_EVENT(EVENT_SCENE_START_BASE_LISTENER, EVENT_STAGE_TCP_COMMON_ONE, extra);
        return SOFTBUS_LOCK_ERR;
    }

    int32_t listenPort = -1;
    do {
        if (node->info.status != LISTENER_IDLE) {
            CONN_LOGE(CONN_COMMON, "listener is not idle status, module=%{public}d, status=%{public}d",
                module, node->info.status);
            status = SOFTBUS_CONN_LISTENER_NOT_IDLE;
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
            status = listenPort;
            break;
        }

        status = StartWatchThread();
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "start listener thread failed, module=%{public}d, status=%{public}d",
                module, status);
            CleanupServerListenInfoUnsafe(node);
            break;
        }
        status = AddEvent(g_eventWatcher, node->info.listenFd, READ_TRIGGER);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "add fd trigger to watch failed, module=%{public}d", module);
            StopWatchThread();
            CleanupServerListenInfoUnsafe(node);
            break;
        }
        node->info.status = LISTENER_RUNNING;
        CONN_LOGI(CONN_COMMON, "start base listener success, module=%{public}d, listenFd=%{public}d, "
                               "listenPort=%{public}d", module, node->info.listenFd, listenPort);
    } while (false);
    (void)SoftBusMutexUnlock(&node->lock);
    ReturnListenerNode(&node);
    FillConnEventExtra(info, &extra, status);
    CONN_EVENT(EVENT_SCENE_START_BASE_LISTENER, EVENT_STAGE_TCP_COMMON_ONE, extra);
    return status == SOFTBUS_OK ? listenPort : status;
}

int32_t StopBaseListener(ListenerModule module)
{
    ConnEventExtra extra = {
        .moduleId = module,
        .result = 0
    };
    CONN_EVENT(EVENT_SCENE_STOP_BASE_LISTENER, EVENT_STAGE_TCP_COMMON_ONE, extra);
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
    extra.errcode = status;
    extra.result = status == SOFTBUS_OK ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;
    CONN_EVENT(EVENT_SCENE_STOP_BASE_LISTENER, EVENT_STAGE_TCP_COMMON_ONE, extra);
    return status;
}

static int32_t ShutdownBaseListener(SoftbusListenerNode *node)
{
    int32_t status = SoftBusMutexLock(&node->lock);
    CONN_CHECK_AND_RETURN_RET_LOGE(status == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_COMMON,
        "lock failed, module=%{public}d, error=%{public}d", node->module, status);

    do {
        if (node->info.status != LISTENER_RUNNING) {
            CONN_LOGW(CONN_COMMON, "listener is not running, just skip, module=%{public}d, error=%{public}d",
                node->module, node->info.status);
            break;
        }
        status = StopWatchThread();
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "stop watch thread failed, module=%{public}d, error=%{public}d",
                node->module, status);
            // fall-through
        }
        node->info.status = LISTENER_IDLE;

        struct FdNode *it = NULL;
        struct FdNode *next = NULL;
        LIST_FOR_EACH_ENTRY_SAFE(it, next, &node->info.waitEventFds, struct FdNode, node) {
            CONN_LOGE(CONN_COMMON, "listener node there is fd not close, module=%{public}d, fd=%{public}d, "
                                   "triggerSet=%{public}u", node->module, it->fd, it->triggerSet);
            // not close fd, repeat close will crash process
            (void)RemoveEvent(g_eventWatcher, it->fd);
            ListDelete(&it->node);
            SoftBusFree(it);
        }
        node->info.waitEventFdsLen = 0;

        int32_t listenFd = node->info.listenFd;
        int32_t listenPort = node->info.listenPort;
        if (node->info.modeType == SERVER_MODE && listenFd > 0) {
            CONN_LOGE(CONN_COMMON, "close server, module=%{public}d, listenFd=%{public}d, port=%{public}d",
                node->module, listenFd, listenPort);
            (void)RemoveEvent(g_eventWatcher, listenFd);
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

bool IsListenerNodeExist(ListenerModule module)
{
    SoftbusListenerNode *node = GetListenerNode(module);
    bool exist = false;
    if (node != NULL) {
        exist = true;
        ReturnListenerNode(&node);
    }
    return exist;
}

int32_t AddTrigger(ListenerModule module, int32_t fd, TriggerType trigger)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(module >= 0 && module < UNUSE_BUTT, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "invalid module, module=%{public}d", module);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        fd > 0, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid fd, module=%{public}d, fd=%{public}d", module, fd);
    CONN_CHECK_AND_RETURN_RET_LOGW(IsValidTriggerType(trigger), SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "invalid trigger, module=%{public}d, fd=%{public}d, trigger=%{public}d", module, fd, trigger);

    SoftbusListenerNode *node = GetListenerNode(module);
    CONN_CHECK_AND_RETURN_RET_LOGW(node != NULL, SOFTBUS_NOT_FIND, CONN_COMMON,
        "listener node not exist, module=%{public}d, fd=%{public}d, trigger=%{public}d", module, fd, trigger);

    int32_t status = SoftBusMutexLock(&node->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "lock failed, module=%{public}d, fd=%{public}d, trigger=%{public}d, "
                               "error=%{public}d", module, fd, trigger, status);
        ReturnListenerNode(&node);
        return SOFTBUS_LOCK_ERR;
    }

    do {
        if (node->info.status != LISTENER_RUNNING) {
            CONN_LOGE(CONN_COMMON, "module is not running, module=%{public}d, fd=%{public}d, trigger=%{public}d",
                module, fd, trigger);
            status = SOFTBUS_CONN_FAIL;
            break;
        }

        struct FdNode *target = NULL;
        struct FdNode *it = NULL;
        LIST_FOR_EACH_ENTRY(it, &node->info.waitEventFds, struct FdNode, node) {
            if (fd == it->fd) {
                target = it;
                break;
            }
        }

        if (target != NULL) {
            if ((target->triggerSet & trigger) == trigger) {
                CONN_LOGW(CONN_COMMON, "repeat add trigger, just skip, module=%{public}d, fd=%{public}d, "
                                       "trigger=%{public}d, triggerSet=%{public}u",
                    module, fd, trigger, target->triggerSet);
                break;
            }
            status = ModifyEvent(g_eventWatcher, fd, target->triggerSet | trigger);
            if (status == SOFTBUS_OK) {
                target->triggerSet |= trigger;
                CONN_LOGI(CONN_COMMON, "add trigger success, module=%{public}d, fd=%{public}d, "
                    "AddTrigger=%{public}d, triggerSet=%{public}u", module, fd, trigger, target->triggerSet);
            }
            break;
        }

        struct FdNode *fdNode = (struct FdNode *)SoftBusCalloc(sizeof(struct FdNode));
        if (fdNode == NULL) {
            CONN_LOGE(CONN_COMMON, "calloc failed, module=%{public}d, fd=%{public}d, trigger=%{public}d",
                module, fd, trigger);
            status = SOFTBUS_MALLOC_ERR;
            break;
        }
        status = AddEvent(g_eventWatcher, fd, trigger);
        if (status == SOFTBUS_OK) {
            ListInit(&fdNode->node);
            fdNode->fd = fd;
            fdNode->triggerSet = trigger;
            ListAdd(&node->info.waitEventFds, &fdNode->node);
            node->info.waitEventFdsLen += 1;
            CONN_LOGI(CONN_COMMON, "add trigger success, module=%{public}d, fd=%{public}d, trigger=%{public}d",
                module, fd, trigger);
            break;
        }
        SoftBusFree(fdNode);
    } while (false);

    (void)SoftBusMutexUnlock(&node->lock);
    ReturnListenerNode(&node);
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

    SoftbusListenerNode *node = GetListenerNode(module);
    CONN_CHECK_AND_RETURN_RET_LOGW(node != NULL, SOFTBUS_NOT_FIND, CONN_COMMON,
        "listener node not exist, module=%{public}d, fd=%{public}d, trigger=%{public}d", module, fd, trigger);

    int32_t status = SoftBusMutexLock(&node->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "lock failed, module=%{public}d, fd=%{public}d, trigger=%{public}d, "
                               "error=%{public}d", module, fd, trigger, status);
        ReturnListenerNode(&node);
        return SOFTBUS_LOCK_ERR;
    }

    do {
        struct FdNode *target = NULL;
        struct FdNode *it = NULL;
        LIST_FOR_EACH_ENTRY(it, &node->info.waitEventFds, struct FdNode, node) {
            if (fd == it->fd) {
                target = it;
                break;
            }
        }

        if (target == NULL) {
            CONN_LOGW(CONN_COMMON, "fd node not exist, module=%{public}d, fd=%{public}d, trigger=%{public}d",
                module, fd, trigger);
            // consider delete trigger success,
            status = SOFTBUS_NOT_FIND;
            break;
        }

        if ((target->triggerSet & trigger) == 0) {
            CONN_LOGW(CONN_COMMON,
                "without add trigger before, repeat delete trigger or mismatch module. "
                "module=%{public}d, fd=%{public}d, wantDeleteTrigger=%{public}d, triggerSet=%{public}u",
                module, fd, trigger, target->triggerSet);
            // consider delete trigger success,
            status = SOFTBUS_OK;
            break;
        }

        target->triggerSet &= ~trigger;
        if (target->triggerSet != 0) {
            (void)ModifyEvent(g_eventWatcher, fd, target->triggerSet);
            CONN_LOGI(CONN_COMMON, "delete trigger success, module=%{public}d, fd=%{public}d, trigger=%{public}d, "
                                   "triggerSet=%{public}u", module, fd, trigger, target->triggerSet);
            status = SOFTBUS_OK;
            break;
        }
        (void)RemoveEvent(g_eventWatcher, fd);
        CONN_LOGI(
            CONN_COMMON,
            "delete trigger success, module=%{public}d, fd=%{public}d, trigger=%{public}d",
            module, fd, trigger);
        ListDelete(&target->node);
        SoftBusFree(target);
        node->info.waitEventFdsLen -= 1;
    } while (false);

    SoftBusMutexUnlock(&node->lock);
    ReturnListenerNode(&node);
    return status;
}

static void CleanupWatchThreadState(WatchThreadState **statePtr)
{
    WatchThreadState *state = *statePtr;

    CONN_LOGI(CONN_COMMON, "cleanup watch thread state, traceId=%{public}d", state->traceId);
    (void)SoftBusMutexDestroy(&state->lock);
    SoftBusFree(state);
    *statePtr = NULL;
}

static void DispatchFdEvent(
    int32_t fd, ListenerModule module, enum SocketEvent event, const SoftbusBaseListener *listener, int32_t wakeupTrace)
{
    if (listener->onDataEvent != NULL) {
        listener->onDataEvent(module, event, fd);
        CONN_LOGI(CONN_COMMON,
            "wakeupTrace=%{public}d, module=%{public}d, fd=%{public}d, event=%{public}d",
            wakeupTrace, module, fd, event);
    } else {
        CONN_LOGE(CONN_COMMON,
            "listener not registered, to avoid repeat wakeup, close it,"
            "wakeupTrace=%{public}d, module=%{public}d, fd=%{public}d, event=%{public}d",
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
                "event listener not registered, wakeupTrace=%{public}d, module=%{public}d, "
                "listenFd=%{public}d, clientIp=%{public}s, clientFd=%{public}d",
                wakeupTrace, module, listenFd, animizedIp, clientFd);
            ConnCloseSocket(clientFd);
        }
    }
    return status;
}

static int32_t CopyWaitEventFdsUnsafe(const SoftbusListenerNode *node, struct FdNode **outArray, uint32_t *outArrayLen)
{
    if (node->info.waitEventFdsLen == 0) {
        *outArray = NULL;
        outArrayLen = 0;
        return SOFTBUS_OK;
    }

    uint32_t fdArrayLen = node->info.waitEventFdsLen;
    struct FdNode *fdArray = (struct FdNode *)SoftBusCalloc(fdArrayLen * sizeof(struct FdNode));
    CONN_CHECK_AND_RETURN_RET_LOGE(fdArray != NULL, SOFTBUS_MALLOC_ERR, CONN_COMMON,
        "calloc failed, module=%{public}d, eventLen=%{public}u", node->module, fdArrayLen);

    uint32_t i = 0;
    struct FdNode *item = NULL;
    bool expand = false;
    LIST_FOR_EACH_ENTRY(item, &node->info.waitEventFds, struct FdNode, node) {
        if (i >= fdArrayLen) {
            uint32_t tmpLen = fdArrayLen * FDARR_EXPAND_BASE;
            struct FdNode *tmp = (struct FdNode *)SoftBusCalloc(tmpLen * sizeof(struct FdNode));
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
        CONN_LOGE(CONN_COMMON, "listener node 'waitEventFdsLen' field is unexpected, "
            "actualWaitEventFdsLen=%{public}u > waitEventFdsLen=%{public}u, module=%{public}d",
            i, node->info.waitEventFdsLen, node->module);
    } else if (i != fdArrayLen) {
        CONN_LOGE(CONN_COMMON, "listener node 'waitEventFdsLen' field is unexpected, "
            "actualWaitEventFdsLen=%{public}u < waitEventFdsLen=%{public}u, module=%{public}d",
            i, node->info.waitEventFdsLen, node->module);
    }

    *outArrayLen = i;
    *outArray = fdArray;
    return SOFTBUS_OK;
}

static void CloseInvalidListenForcely(SoftbusListenerNode *node, int32_t listenFd, const char *anomizedIp,
    int32_t reason)
{
    int32_t ret = SoftBusMutexLock(&node->lock);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_COMMON, "lock failed, module=%{public}d, error=%{public}d",
        node->module, ret);
    do {
        if (node->info.status != LISTENER_RUNNING || node->info.modeType != SERVER_MODE ||
            node->info.listenFd != listenFd) {
            break;
        }
        CONN_LOGW(CONN_COMMON, "forcely close to prevent repeat wakeup watch, module=%{public}d, "
            "listenFd=%{public}d, port=%{public}d, ip=%{public}s, error=%{public}d",
            node->module, node->info.listenFd, node->info.listenPort, anomizedIp, reason);
        (void)RemoveEvent(g_eventWatcher, listenFd);
        ConnCloseSocket(node->info.listenFd);
        node->info.listenFd = -1;
        node->info.listenPort = -1;
    } while (false);
    SoftBusMutexUnlock(&node->lock);
}

static void ProcessServerAcceptEvent(
    SoftbusListenerNode *node, ListNode *fdNode, int32_t wakeupTrace, SoftbusBaseListener *listener)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&node->lock) == SOFTBUS_OK, CONN_COMMON,
        "lock failed, wakeupTrace=%{public}d, module=%{public}d", wakeupTrace, node->module);
    int32_t listenFd = -1;
    int32_t listenPort = -1;
    char animizedIp[IP_LEN] = { 0 };
    if (node->info.modeType == SERVER_MODE && node->info.listenFd > 0) {
        listenFd = node->info.listenFd;
        listenPort = node->info.listenPort;
        ConvertAnonymizeIpAddress(animizedIp, IP_LEN, node->info.listenerInfo.socketOption.addr, IP_LEN);
    }
    const SocketInterface *socketIf = node->socketIf;
    ConnectType connectType = node->info.listenerInfo.type;
    SoftBusMutexUnlock(&node->lock);

    if (listenFd > 0) {
        int32_t status = SOFTBUS_OK;
        struct FdNode *it = NULL;
        struct FdNode *next = NULL;
        LIST_FOR_EACH_ENTRY_SAFE(it, next, fdNode, struct FdNode, node) {
            if (it->fd == listenFd) {
                if ((it->triggerSet & READ_TRIGGER) != 0) {
                    status = ProcessSpecifiedServerAcceptEvent(
                        node->module, listenFd, connectType, socketIf, listener, wakeupTrace);
                }
            }
        }
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
}

static void ProcessFdEvent(SoftbusListenerNode *node, struct FdNode fdEvent,
    ListNode *fdNode, SoftbusBaseListener *listener, int32_t wakeupTrace)
{
    struct FdNode *it = NULL;
    struct FdNode *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(it, next, fdNode, struct FdNode, node) {
        if (it->fd == fdEvent.fd) {
            uint32_t triggerSet = fdEvent.triggerSet & it->triggerSet;
            if ((triggerSet & READ_TRIGGER) != 0) {
                CONN_LOGD(CONN_COMMON, "trigger IN event, wakeupTrace=%{public}d, "
                    "module=%{public}d, fd=%{public}d, triggerSet=%{public}u",
                    wakeupTrace, node->module, fdEvent.fd, fdEvent.triggerSet);
                DispatchFdEvent(fdEvent.fd, node->module, SOFTBUS_SOCKET_IN, listener, wakeupTrace);
            }
            if ((triggerSet & WRITE_TRIGGER) != 0) {
                CONN_LOGD(CONN_COMMON, "trigger OUT event, wakeupTrace=%{public}d, "
                    "module=%{public}d, fd=%{public}d, triggerSet=%{public}u",
                    wakeupTrace, node->module, fdEvent.fd, fdEvent.triggerSet);
                DispatchFdEvent(fdEvent.fd, node->module, SOFTBUS_SOCKET_OUT, listener, wakeupTrace);
            }
            if ((triggerSet & EXCEPT_TRIGGER) != 0) {
                CONN_LOGW(CONN_COMMON, "trigger EXCEPTION(out-of-band data) event, wakeupTrace=%{public}d, "
                    "module=%{public}d, fd=%{public}d, triggerSet=%{public}u",
                    wakeupTrace, node->module, fdEvent.fd, fdEvent.triggerSet);
                DispatchFdEvent(fdEvent.fd, node->module, SOFTBUS_SOCKET_EXCEPTION, listener, wakeupTrace);
            }
        }
    }
}

static void ProcessSpecifiedListenerNodeEvent(SoftbusListenerNode *node, ListNode *fdNode, int32_t wakeupTrace)
{
    CONN_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&node->lock) == SOFTBUS_OK, CONN_COMMON,
        "lock failed, wakeupTrace=%{public}d, module=%{public}d", wakeupTrace, node->module);
    if (node->info.status != LISTENER_RUNNING) {
        SoftBusMutexUnlock(&node->lock);
        return;
    }
    SoftbusBaseListener listener = node->listener;
    struct FdNode *fdArray = NULL;
    uint32_t fdArrayLen = 0;
    int32_t status = CopyWaitEventFdsUnsafe(node, &fdArray, &fdArrayLen);
    SoftBusMutexUnlock(&node->lock);
    if (status != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON,
            "copy wait event fds failed, wakeupTrace=%{public}d, module=%{public}d, error=%{public}d",
            wakeupTrace, node->module, status);
        return;
    }
    ProcessServerAcceptEvent(node, fdNode, wakeupTrace, &listener);

    for (uint32_t i = 0; i < fdArrayLen; i++) {
        ProcessFdEvent(node, fdArray[i], fdNode, &listener, wakeupTrace);
    }
    SoftBusFree(fdArray);
}

static void ProcessEvent(ListNode *fdNode, const WatchThreadState *watchState, int32_t wakeupTrace)
{
    for (ListenerModule module = 0; module < UNUSE_BUTT; module++) {
        SoftbusListenerNode *node = GetListenerNode(module);
        if (node == NULL) {
            continue;
        }
        ProcessSpecifiedListenerNodeEvent(node, fdNode, wakeupTrace);
        ReturnListenerNode(&node);
    }
}

static void *WatchTask(void *arg)
{
    static int32_t wakeupTraceIdGenerator = 0;

    CONN_CHECK_AND_RETURN_RET_LOGW(arg != NULL, NULL, CONN_COMMON, "invalid param");
    WatchThreadState *watchState = (WatchThreadState *)arg;
    while (true) {
        int32_t status = SoftBusMutexLock(&watchState->lock);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "lock failed, retry after some times. "
                                   "waitDelay=%{public}dms, watchTrace=%{public}d, error=%{public}d",
                WATCH_UNEXPECT_FAIL_RETRY_WAIT_MILLIS, watchState->traceId, status);
            SoftBusSleepMs(WATCH_UNEXPECT_FAIL_RETRY_WAIT_MILLIS);
            continue;
        }
        int32_t referenceCount = watchState->referenceCount;
        (void)SoftBusMutexUnlock(&watchState->lock);

        if (referenceCount <= 0) {
            CONN_LOGW(CONN_COMMON, "watch task, watch task is not reference by others any more, exit... "
                                   "watchTrace=%{public}d", watchState->traceId);
            break;
        }
        ListNode fdEvents;
        ListInit(&fdEvents);
        CONN_LOGI(CONN_COMMON, "WatchEvent is start, traceId=%{public}d", watchState->traceId);
        int32_t nEvents = WatchEvent(g_eventWatcher, SOFTBUS_LISTENER_WATCH_TIMEOUT_MSEC, &fdEvents);
        int32_t wakeupTraceId = ++wakeupTraceIdGenerator;
        if (nEvents == 0) {
            ReleaseFdNode(&fdEvents);
            continue;
        }
        if (nEvents < 0) {
            CONN_LOGE(CONN_COMMON, "unexpect wakeup, retry after some times. "
                                   "waitDelay=%{public}dms, wakeupTraceId=%{public}d, events=%{public}d",
                WATCH_ABNORMAL_EVENT_RETRY_WAIT_MILLIS, wakeupTraceId, nEvents);
            ReleaseFdNode(&fdEvents);
            SoftBusSleepMs(WATCH_ABNORMAL_EVENT_RETRY_WAIT_MILLIS);
            continue;
        }
        CONN_LOGI(CONN_COMMON, "watch task, wakeup from watch, watchTrace=%{public}d, wakeupTraceId=%{public}d, "
                               "events=%{public}d", watchState->traceId, wakeupTraceId, nEvents);
        ProcessEvent(&fdEvents, watchState, wakeupTraceId);
        ReleaseFdNode(&fdEvents);
    }
    CleanupWatchThreadState(&watchState);
    return NULL;
}

static int32_t StartWatchThread(void)
{
    static int32_t watchThreadTraceIdGenerator = 1;

    int32_t status = SoftBusMutexLock(&g_watchThreadStateLock);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        status == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_COMMON, "lock global watch thread state failed");

    do {
        if (g_watchThreadState != NULL) {
            status = SoftBusMutexLock(&g_watchThreadState->lock);
            if (status != SOFTBUS_OK) {
                CONN_LOGE(CONN_COMMON, "lock watch thread state self failed, error=%{public}d", status);
                status = SOFTBUS_LOCK_ERR;
                break;
            }
            int32_t referenceCount = ++g_watchThreadState->referenceCount;
            (void)SoftBusMutexUnlock(&g_watchThreadState->lock);

            CONN_LOGD(CONN_COMMON, "watch thread is already start, watchTrace=%{public}d, referenceCount=%{public}d",
                g_watchThreadState->traceId, referenceCount);
            break;
        }

        WatchThreadState *state = SoftBusCalloc(sizeof(WatchThreadState));
        if (state == NULL) {
            status = SOFTBUS_MALLOC_ERR;
            break;
        }
        state->traceId = ++watchThreadTraceIdGenerator;

        status = SoftBusMutexInit(&state->lock, NULL);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "start watch task async failed, error=%{public}d", status);
            CleanupWatchThreadState(&state);
            break;
        }
        state->referenceCount = 1;
        status = ConnStartActionAsync(state, WatchTask, "Watch_Tsk");
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "init lock failed, error=%{public}d", status);
            CleanupWatchThreadState(&state);
            break;
        }
        CONN_LOGI(CONN_COMMON, "start watch thread success, traceId=%{public}d", state->traceId);
        g_watchThreadState = state;
    } while (false);
    (void)SoftBusMutexUnlock(&g_watchThreadStateLock);
    return status;
}

static int32_t StopWatchThread(void)
{
    int32_t status = SoftBusMutexLock(&g_watchThreadStateLock);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        status == SOFTBUS_OK, SOFTBUS_LOCK_ERR, CONN_COMMON, "lock global watch thread state failed");
    do {
        if (g_watchThreadState == NULL) {
            CONN_LOGW(CONN_COMMON, "watch thread is already stop or never start");
            break;
        }

        status = SoftBusMutexLock(&g_watchThreadState->lock);
        if (status != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "lock watch thread state self");
            break;
        }
        g_watchThreadState->referenceCount -= 1;
        int32_t referenceCount = g_watchThreadState->referenceCount;
        (void)SoftBusMutexUnlock(&g_watchThreadState->lock);
        if (referenceCount <= 0) {
            CONN_LOGW(CONN_COMMON, "watch thread is not used by other module any more, notify "
                "exit, thread reference count=%{public}d", referenceCount);
            g_watchThreadState = NULL;
        }
    } while (false);
    (void)SoftBusMutexUnlock(&g_watchThreadStateLock);
    return status;
}
