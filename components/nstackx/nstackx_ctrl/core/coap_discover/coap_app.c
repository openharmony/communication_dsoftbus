/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "coap_app.h"

#include <errno.h>
#include <securec.h>
#include <string.h>
#include <inttypes.h>
#ifndef _WIN32
#include <netdb.h>
#include <pthread.h>
#include <unistd.h>
#endif

#include "coap_client.h"
#include "coap_discover.h"
#include "nstackx_util.h"
#include "nstackx_device.h"
#include "nstackx_epoll.h"
#include "nstackx_error.h"
#include "nstackx_dfinder_log.h"
#include "nstackx_event.h"
#include "nstackx_statistics.h"
#include "nstackx_device_local.h"

#define TAG "nStackXCoAP"

#define DEFAULT_COAP_TIMEOUT (COAP_RESOURCE_CHECK_TIME * COAP_TICKS_PER_SECOND)

static uint32_t GetTimeout(CoapCtxType *ctx, EpollDesc epollfd);

static List g_ctxList = { &g_ctxList, &g_ctxList };

List *GetCoapContextList(void)
{
    return &g_ctxList;
}

static void CoapContextInsert(CoapCtxType *ctx)
{
    ListInsertTail(&g_ctxList, &ctx->node);
}

static void CoapContextRemove(CoapCtxType *ctx)
{
    ListRemoveNode(&ctx->node);
}

CoapCtxType *CoapGetCoapCtxType(const coap_context_t *ctx)
{
    List *pos = NULL;
    LIST_FOR_EACH(pos, &g_ctxList) {
        CoapCtxType *coapCtx = (CoapCtxType *)pos;
        if (coapCtx->ctx == ctx) {
            return coapCtx;
        }
    }
    return NULL;
}

bool IsCoapContextReady(void)
{
    return !ListIsEmpty(&g_ctxList);
}

#ifdef _WIN32
#define SEC_TO_MILISEC 1000
#define MILISEC_TO_MICROSEC 1000
static pthread_t g_coapTid;

typedef struct {
    EpollTask taskList[3 * MAX_COAP_SOCKET_NUM];
    uint32_t eventList[3 * MAX_COAP_SOCKET_NUM];
    void *dataList[3 * MAX_COAP_SOCKET_NUM];
    uint32_t count;
    uint32_t timeout;
    EpollDesc epollFd;
} TaskListInfo;

typedef struct {
    uint8_t terminated;
    sem_t waitCondition;
    pthread_mutex_t waitLock;
    TaskListInfo taskListInfo;
} CoapThreadParam;

TaskListInfo g_taskListInfo = {0};
CoapThreadParam g_coapThreadParam = {0};
uint8_t g_coapThreadState = NSTACKX_FALSE;
#endif // _WIN32

typedef enum {
    SOCKET_READ_EVENT = 0,
    SOCKET_WRITE_EVENT,
    SOCKET_ERROR_EVENT,
    SOCKET_END_EVENT
} SocketEventType;
static uint64_t g_socketEventNum[SOCKET_END_EVENT];

static void CoAPEpollReadHandle(void *data)
{
    if (data == NULL) {
        return;
    }
    EpollTask *task = data;
    if (task->taskfd < 0) {
        return;
    }
    if (task->ptr == NULL) {
        return;
    }
    coap_socket_t *socket = task->ptr;

    if (socket->flags & COAP_SOCKET_WANT_READ) {
        socket->flags |= COAP_SOCKET_CAN_READ;
    }

    if (socket->flags & COAP_SOCKET_WANT_ACCEPT) {
        socket->flags |= COAP_SOCKET_CAN_ACCEPT;
    }
    g_socketEventNum[SOCKET_READ_EVENT]++;
}

static void CoAPEpollWriteHandle(void *data)
{
    if (data == NULL) {
        return;
    }
    EpollTask *task = data;
    if (task->taskfd < 0) {
        return;
    }
    if (task->ptr == NULL) {
        return;
    }
    coap_socket_t *socket = task->ptr;

    if (socket->flags & COAP_SOCKET_WANT_WRITE) {
        socket->flags |= COAP_SOCKET_CAN_WRITE;
    }

    if (socket->flags & COAP_SOCKET_WANT_CONNECT) {
        socket->flags |= COAP_SOCKET_CAN_CONNECT;
    }
    g_socketEventNum[SOCKET_WRITE_EVENT]++;
}

static void CoAPEpollErrorHandle(void *data)
{
    EpollTask *task = data;
    if (task == NULL || task->taskfd < 0) {
        return;
    }
    coap_socket_t *socket = task->ptr;
    if (socket == NULL) {
        return;
    }

    IncStatistics(STATS_SOCKET_ERROR);
    g_socketEventNum[SOCKET_ERROR_EVENT]++;

    List *pos = NULL;
    LIST_FOR_EACH(pos, &g_ctxList) {
        CoapCtxType *ctx = (CoapCtxType *)pos;
        if (IsCoapCtxEndpointSocket(ctx->ctx, socket->fd)) {
            DFINDER_LOGE(TAG, "coap epoll error occurred");
            ctx->socketErrFlag = NSTACKX_TRUE;
            return;
        }
    }

    DFINDER_LOGE(TAG, "coap session socket error occurred and close it");
    DeRegisterEpollTask(task);
    CloseDesc(socket->fd);
    socket->fd = -1;
    task->taskfd = -1;
}

static uint32_t RegisterCtxTask(EpollDesc epollfd)
{
    uint32_t minTimeout = DEFAULT_COAP_TIMEOUT;
    List *pos = NULL;
    LIST_FOR_EACH(pos, &g_ctxList) {
        CoapCtxType *ctx = (CoapCtxType *)pos;
        uint32_t currentTimeout = GetTimeout(ctx, epollfd);
        if (currentTimeout < minTimeout) {
            minTimeout = currentTimeout;
        }
    }

    return minTimeout;
}

#ifdef _WIN32
uint32_t RegisterCoAPEpollTask(EpollDesc epollfd)
{
    (void)memset_s(&g_taskListInfo, sizeof(g_taskListInfo), 0, sizeof(g_taskListInfo));
    uint32_t timeout = RegisterCtxTask(epollfd);
    g_taskListInfo.epollFd = epollfd;
    g_taskListInfo.timeout = timeout;
    // Lock to protect g_coapThreadParam
    if (PthreadMutexLock(&g_coapThreadParam.waitLock) != 0) {
        DFINDER_LOGE(TAG, "Failed to lock");
        return timeout;
    }
    (void)memcpy_s(&g_coapThreadParam.taskListInfo, sizeof(g_coapThreadParam.taskListInfo),
        &g_taskListInfo, sizeof(g_taskListInfo));
    SemPost(&g_coapThreadParam.waitCondition);
    if (PthreadMutexUnlock(&g_coapThreadParam.waitLock) != 0) {
        DFINDER_LOGE(TAG, "Failed to unlock");
    }

    return timeout;
}
#else
uint32_t RegisterCoAPEpollTask(EpollDesc epollfd)
{
    return RegisterCtxTask(epollfd);
}
#endif

static uint32_t GetTimeout(CoapCtxType *ctx, EpollDesc epollfd)
{
    uint32_t events, timeout, i;
    coap_tick_t now;
    coap_socket_t *sockets[MAX_COAP_SOCKET_NUM] = {0};

    coap_ticks(&now);
    timeout = coap_io_prepare_io(ctx->ctx, sockets, (uint32_t)(sizeof(sockets) / sizeof(sockets[0])),
        &ctx->socketNum, now);
    if (timeout == 0 || timeout > DEFAULT_COAP_TIMEOUT) {
        timeout = DEFAULT_COAP_TIMEOUT;
    }
    if (ctx->socketNum > MAX_COAP_SOCKET_NUM) {
        ctx->socketNum = MAX_COAP_SOCKET_NUM;
        DFINDER_LOGI(TAG, "socketNum exccedd MAX_COAP_SOCKET_NUM, and set it to MAX_COAP_SOCKET_NUM");
    }
    for (i = 0; i < ctx->socketNum; i++) {
        if (sockets[i]->fd < 0) {
            continue;
        }
        events = 0;
        if ((sockets[i]->flags & COAP_SOCKET_WANT_READ) || (sockets[i]->flags & COAP_SOCKET_WANT_ACCEPT)) {
            events = EPOLLIN;
        }
        if ((sockets[i]->flags & COAP_SOCKET_WANT_WRITE) || (sockets[i]->flags & COAP_SOCKET_WANT_CONNECT)) {
            events = events | EPOLLOUT;
        }
        if (sockets[i]->flags & COAP_SOCKET_WANT_CONNECT) {
            events = events | EPOLLHUP | EPOLLERR;
        }
        ctx->taskList[i].taskfd = sockets[i]->fd;
        ctx->taskList[i].epollfd = epollfd;
        ctx->taskList[i].readHandle = CoAPEpollReadHandle;
        ctx->taskList[i].writeHandle = CoAPEpollWriteHandle;
        ctx->taskList[i].errorHandle = CoAPEpollErrorHandle;
        ctx->taskList[i].ptr = sockets[i];
#ifdef _WIN32
        TaskListInfo *info = &g_taskListInfo;
        (void)memcpy_s(&info->taskList[info->count], sizeof(info->taskList[info->count]),
            &ctx->taskList[i], sizeof(ctx->taskList[i]));
        info->eventList[info->count] = events;
        info->dataList[info->count] = &ctx->taskList[i];
        info->count++;
#else
        (void)RegisterEpollTask(&ctx->taskList[i], events);
#endif /* #ifdef _WIN32 */
    }
    return timeout;
}

static void DeRegisteCoAPEpollTaskCtx(CoapCtxType *ctx)
{
    coap_tick_t now;
    uint32_t i;

    if (ctx->socketNum > MAX_COAP_SOCKET_NUM) {
        ctx->socketNum = MAX_COAP_SOCKET_NUM;
        DFINDER_LOGI(TAG, "socketNum exccedd MAX_COAP_SOCKET_NUM, and set it to MAX_COAP_SOCKET_NUM");
    }

    for (i = 0; i < ctx->socketNum; i++) {
        if (ctx->taskList[i].taskfd < 0) {
            continue;
        }
        (void)DeRegisterEpollTask(&ctx->taskList[i]);
    }
    ctx->socketNum = 0;

    coap_ticks(&now);
    coap_io_do_io(ctx->ctx, now);
}

static int DeRegisterCoAPEpollTaskCb(CoapCtxType *ctx)
{
    if (ctx->socketErrFlag) {
        DFINDER_LOGI(TAG, "error of ctx socket occurred and destroy g_ctx");
        ctx->socketErrFlag = NSTACKX_FALSE;
        NotifyDFinderMsgRecver(DFINDER_ON_INNER_ERROR);
        DestroyLocalIface(ctx->iface, NSTACKX_FALSE);
    } else {
        DeRegisteCoAPEpollTaskCtx(ctx);
    }
    if (ctx->freeCtxLater == NSTACKX_TRUE) {
        CoapContextRemove(ctx);
        coap_free_context(ctx->ctx);
        free(ctx);
    }
    return NSTACKX_EOK;
}

void DeRegisterCoAPEpollTask(void)
{
    List *pos = NULL;
    List *tmp = NULL;
    LIST_FOR_EACH_SAFE(pos, tmp, &g_ctxList) {
        (void)DeRegisterCoAPEpollTaskCb((CoapCtxType *)pos);
    }
}

#ifdef _WIN32
int32_t CoapSelectWait(TaskListInfo *taskListInfo)
{
    fd_set readSet, writeSet, errorSet;
    struct timeval tv;
    int maxFd = 0;

    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    FD_ZERO(&errorSet);
    for (int i = 0; i < taskListInfo->count; i++) {
        EpollTask *task = &taskListInfo->taskList[i];
        if (maxFd < task->taskfd) {
            maxFd = task->taskfd;
        }
        if (taskListInfo->eventList[i] & EPOLLIN) {
            FD_SET(task->taskfd, &readSet);
        }
        if (taskListInfo->eventList[i] & EPOLLOUT) {
            FD_SET(task->taskfd, &writeSet);
        }
        FD_SET(task->taskfd, &errorSet);
    }
    tv.tv_sec = taskListInfo->timeout / SEC_TO_MILISEC;
    tv.tv_usec = (taskListInfo->timeout % MILISEC_TO_MICROSEC) * MILISEC_TO_MICROSEC;
    int ret = select(maxFd + 1, &readSet, &writeSet, &errorSet, &tv);
    if (ret < 0) {
        int lastError = WSAGetLastError();
        if (lastError != WSAEINVAL) {
            IncStatistics(STATS_SOCKET_ERROR);
            DFINDER_LOGE(TAG, "select error ret lastError: %d", lastError);
            return NSTACKX_EFAILED;
        }
        return NSTACKX_EAGAIN;
    } else if (ret == 0) {
        return NSTACKX_EAGAIN;
    }
    for (uint32_t i = 0; i < taskListInfo->count; i++) {
        if (FD_ISSET(taskListInfo->taskList[i].taskfd, &readSet)) {
            PostEvent(GetMainLoopEvendChain(), taskListInfo->epollFd, CoAPEpollReadHandle,
                taskListInfo->dataList[i]);
        }
        if (FD_ISSET(taskListInfo->taskList[i].taskfd, &writeSet)) {
            PostEvent(GetMainLoopEvendChain(), taskListInfo->epollFd, CoAPEpollWriteHandle,
                taskListInfo->dataList[i]);
        }
        if (FD_ISSET(taskListInfo->taskList[i].taskfd, &errorSet)) {
            PostEvent(GetMainLoopEvendChain(), taskListInfo->epollFd, CoAPEpollErrorHandle,
                taskListInfo->dataList[i]);
        }
    }
    return NSTACKX_EOK;
}

static void *CoapIoMonitorLoop(void *arg)
{
    DFINDER_LOGI(TAG, "Enter CoapIoMonitorLoop");
    TaskListInfo taskListInfo;

    while (!g_coapThreadParam.terminated) {
        SemWait(&g_coapThreadParam.waitCondition);
        if (PthreadMutexLock(&g_coapThreadParam.waitLock) != 0) {
            DFINDER_LOGE(TAG, "Coap thread lock failed");
            break;
        }
        if (g_coapThreadParam.terminated) {
            DFINDER_LOGI(TAG, "Coap thread terminated");
            PthreadMutexUnlock(&g_coapThreadParam.waitLock);
            break;
        }

        if (g_coapThreadParam.taskListInfo.count == 0) {
            if (PthreadMutexUnlock(&g_coapThreadParam.waitLock) != 0) {
                break;
            }
            continue;
        }
        (void)memcpy_s(&taskListInfo, sizeof(taskListInfo), &g_coapThreadParam.taskListInfo,
            sizeof(g_coapThreadParam.taskListInfo));
        if (PthreadMutexUnlock(&g_coapThreadParam.waitLock) != 0) {
            DFINDER_LOGE(TAG, "Coap thread unlock failed");
            break;
        }
        if (CoapSelectWait(&taskListInfo) == NSTACKX_EFAILED) {
            IncStatistics(STATS_SOCKET_ERROR);
            DFINDER_LOGE(TAG, "Coap select failure");
            break;
        }
    }
    DFINDER_LOGI(TAG, "Exit CoapIoMonitorLoop");
    return NULL;
}

int32_t CoapThreadInit(void)
{
    if (SemInit(&g_coapThreadParam.waitCondition, 0, 0) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Failed to init sem condition");
        return NSTACKX_EFAILED;
    }

    if (PthreadMutexInit(&g_coapThreadParam.waitLock, NULL) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "Faile to init lock");
        SemDestroy(&g_coapThreadParam.waitCondition);
        return NSTACKX_EFAILED;
    }

    int32_t ret = PthreadCreate(&g_coapTid, NULL, CoapIoMonitorLoop, NULL);
    if (ret != 0) {
        SemDestroy(&g_coapThreadParam.waitCondition);
        PthreadMutexDestroy(&g_coapThreadParam.waitLock);
        (void)memset_s(&g_coapThreadParam, sizeof(g_coapThreadParam), 0, sizeof(g_coapThreadParam));
        DFINDER_LOGE(TAG, "thread create failed");
        return NSTACKX_EFAILED;
    }
    DFINDER_LOGI(TAG, "Init CoAP thread done!");
    return NSTACKX_EOK;
}

void CoapThreadDestroy(void)
{
    PthreadMutexLock(&g_coapThreadParam.waitLock);
    g_coapThreadParam.terminated = NSTACKX_TRUE;
    SemPost(&g_coapThreadParam.waitCondition);
    PthreadMutexUnlock(&g_coapThreadParam.waitLock);
    // May got block for 2 seconds.
    PthreadJoin(g_coapTid, NULL);
    SemDestroy(&g_coapThreadParam.waitCondition);
    PthreadMutexDestroy(&g_coapThreadParam.waitLock);
    (void)memset_s(&g_coapThreadParam, sizeof(g_coapThreadParam), 0, sizeof(g_coapThreadParam));
}
#endif

void CoapServerDestroy(CoapCtxType *ctx, bool moduleDeinit)
{
    DFINDER_LOGD(TAG, "coap server destroy, module deinit: %d", moduleDeinit);

    for (uint32_t i = 0; i < ctx->socketNum && i < MAX_COAP_SOCKET_NUM; ++i) {
        if (ctx->taskList[i].taskfd < 0) {
            continue;
        }
        (void)DeRegisterEpollTask(&ctx->taskList[i]);
    }

    if (moduleDeinit) {
        CoapContextRemove(ctx);
        coap_free_context(ctx->ctx);
        free(ctx);
    } else {
        // release the context after EpollLoop has processed this round of tasks
        ctx->freeCtxLater = NSTACKX_TRUE;
    }
}

CoapCtxType *CoapServerInit(const struct in_addr *ip, void *iface)
{
    DFINDER_LOGI(TAG, "CoapServerInit");
    CoapCtxType *ctx = calloc(1, sizeof(CoapCtxType));
    if (ctx == NULL) {
        DFINDER_LOGE(TAG, "alloc failed");
        return NULL;
    }

    coap_startup();

    char addrStr[NI_MAXHOST] = COAP_SRV_DEFAULT_ADDR;
    char portStr[NI_MAXSERV] = COAP_SRV_DEFAULT_PORT;

    ctx->ctx = CoapGetContext(addrStr, portStr, NSTACKX_TRUE, ip);
    if (ctx->ctx == NULL) {
        DFINDER_LOGE(TAG, "coap init get context failed");
        free(ctx);
        return NULL;
    }

    if (CoapInitResources(ctx->ctx) != NSTACKX_EOK) {
        DFINDER_LOGE(TAG, "init resource failed");
        coap_free_context(ctx->ctx);
        free(ctx);
        return NULL;
    }

    coap_register_response_handler(ctx->ctx, CoapMessageHandler);
    ctx->iface = iface;
    CoapContextInsert(ctx);

    return ctx;
}

void ResetCoapSocketTaskCount(uint8_t isBusy)
{
    List *pos = NULL;
    LIST_FOR_EACH(pos, &g_ctxList) {
        CoapCtxType *ctx = (CoapCtxType *)pos;
        uint64_t totalTaskCount = 0;
        uint32_t i;
        for (i = 0; i < ctx->socketNum && i < MAX_COAP_SOCKET_NUM; i++) {
            if (totalTaskCount < UINT64_MAX && ctx->taskList[i].count <= UINT64_MAX - totalTaskCount) {
                totalTaskCount += ctx->taskList[i].count;
            }
            ctx->taskList[i].count = 0;
        }

        if (isBusy) {
            DFINDER_LOGI(TAG, "in this busy interval, socket task count of iface %s is: %" PRIu64,
                GetLocalIfaceName(ctx->iface), totalTaskCount);
        }
    }

    if (isBusy) {
        DFINDER_LOGI(TAG, "in this busy interval, socket event count: read %" PRIu64
            ", write %" PRIu64 ", error %" PRIu64,
            g_socketEventNum[SOCKET_READ_EVENT], g_socketEventNum[SOCKET_WRITE_EVENT],
            g_socketEventNum[SOCKET_ERROR_EVENT]);
    }

    (void)memset_s(g_socketEventNum, sizeof(g_socketEventNum), 0, sizeof(g_socketEventNum));
}
