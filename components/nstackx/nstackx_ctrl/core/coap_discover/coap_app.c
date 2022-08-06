/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#define TAG "nStackXCoAP"

#define DEFAULT_COAP_TIMEOUT (COAP_RESOURCE_CHECK_TIME * COAP_TICKS_PER_SECOND)

#ifdef DFINDER_SUPPORT_MULTI_NIF
static CoapCtxType g_coapCtxArr[NSTACKX_MAX_LISTENED_NIF_NUM] = {
    {NULL, {0}, 0, NSTACKX_FALSE},
    {NULL, {0}, 0, NSTACKX_FALSE}
};
#else
static coap_context_t *g_ctx = NULL;
static EpollTask g_taskList[MAX_COAP_SOCKET_NUM] = {0};
static uint32_t g_socketNum = 0;
static uint8_t g_ctxSocketErrFlag = NSTACKX_FALSE;

static coap_context_t *g_p2pCtx = NULL;
static EpollTask g_p2pTaskList[MAX_COAP_SOCKET_NUM] = {0};
static uint32_t g_p2pSocketNum = 0;
static uint8_t g_p2pCtxSocketErrFlag = NSTACKX_FALSE;

static coap_context_t *g_usbCtx = NULL;
static EpollTask g_usbTaskList[MAX_COAP_SOCKET_NUM] = {0};
static uint32_t g_usbSocketNum = 0;
static uint8_t g_usbCtxSocketErrFlag = NSTACKX_FALSE;
#endif

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

#ifdef DFINDER_SUPPORT_MULTI_NIF
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
    EpollTask *currEpollTask = NULL;

    for (uint32_t i = 0; i < NSTACKX_MAX_LISTENED_NIF_NUM && g_coapCtxArr[i].ctx != NULL; ++i) {
        for (uint32_t j = 0; j < MAX_COAP_SOCKET_NUM; ++j) {
            currEpollTask = &(g_coapCtxArr[i].taskList[j]);
            if (currEpollTask->taskfd != task->taskfd) {
                continue;
            }
            if (IsCoapCtxEndpointSocket(g_coapCtxArr[i].ctx, socket->fd)) {
                DFINDER_LOGE(TAG, "coap epoll error occured, with context idx-%u", i);
                g_coapCtxArr[i].ctxSocketErrFlag = NSTACKX_TRUE;
                return;
            }
        }
    }
    DFINDER_LOGE(TAG, "coap session socket error occurred and close it");
    DeRegisterEpollTask(task);
    CloseDesc(socket->fd);
    socket->fd = -1;
    task->taskfd = -1;
}
#else
static void CoAPEpollErrorHandle(void *data)
{
    if (data == NULL) {
        return;
    }
    EpollTask *task = data;
    if (task->taskfd < 0) {
        return;
    }
    coap_socket_t *socket = task->ptr;
    IncStatistics(STATS_SOCKET_ERROR);
    g_socketEventNum[SOCKET_ERROR_EVENT]++;
    if (socket == NULL) {
        return;
    }
    if (IsCoapCtxEndpointSocket(g_ctx, socket->fd)) {
        DFINDER_LOGE(TAG, "error of g_ctx's socket occurred ");
        g_ctxSocketErrFlag = NSTACKX_TRUE;
        return;
    }

    if (IsCoapCtxEndpointSocket(g_p2pCtx, socket->fd)) {
        DFINDER_LOGE(TAG, "error of g_p2pCtx's socket occurred ");
        g_p2pCtxSocketErrFlag = NSTACKX_TRUE;
        return;
    }

    if (IsCoapCtxEndpointSocket(g_usbCtx, socket->fd)) {
        DFINDER_LOGE(TAG, "error of g_usbCtx's socket occurred ");
        g_usbCtxSocketErrFlag = NSTACKX_TRUE;
        return;
    }

    DFINDER_LOGE(TAG, "coap session socket error occurred and close it");
    DeRegisterEpollTask(task);
    CloseDesc(socket->fd);
    socket->fd = -1;
    task->taskfd = -1;
}
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */

#ifdef DFINDER_SUPPORT_MULTI_NIF
uint32_t RegisterCoAPEpollTask(EpollDesc epollfd)
{
    uint32_t currentTimeout;
    uint32_t minTimeout = DEFAULT_COAP_TIMEOUT;
    uint8_t allCtxEmpty = 1;
    for (uint32_t i = 0; i < NSTACKX_MAX_LISTENED_NIF_NUM; ++i) {
        if (g_coapCtxArr[i].ctx != NULL) {
            allCtxEmpty = 0;
            break;
        }
    }
    if (allCtxEmpty) {
        return DEFAULT_COAP_TIMEOUT;
    }

    for (uint32_t j = 0; j < NSTACKX_MAX_LISTENED_NIF_NUM && g_coapCtxArr[j].ctx != NULL; ++j) {
        currentTimeout = GetTimeout(g_coapCtxArr[j].ctx, &(g_coapCtxArr[j].socketNum), g_coapCtxArr[j].taskList,
            epollfd);
        if (currentTimeout < minTimeout) {
            minTimeout = currentTimeout;
        }
    }
    return minTimeout;
}
#else
uint32_t RegisterCoAPEpollTask(EpollDesc epollfd)
{
    uint32_t timeoutWlan, timeoutP2p, timeoutUsb, minTimeout;
    uint32_t timeout;

    if ((g_ctx == NULL) && (g_p2pCtx == NULL) && (g_usbCtx == NULL)) {
        return DEFAULT_COAP_TIMEOUT;
    }
#ifdef _WIN32
    (void)memset_s(&g_taskListInfo, sizeof(g_taskListInfo), 0, sizeof(g_taskListInfo));
    timeoutWlan = GetTimeout(g_ctx, &g_socketNum, g_taskList, epollfd, &g_taskListInfo);
    timeoutP2p = GetTimeout(g_p2pCtx, &g_p2pSocketNum, g_p2pTaskList, epollfd, &g_taskListInfo);
    timeoutUsb = GetTimeout(g_usbCtx, &g_usbSocketNum, g_usbTaskList, epollfd, &g_taskListInfo);
#else
    timeoutWlan = GetTimeout(g_ctx, &g_socketNum, g_taskList, epollfd);
    timeoutP2p = GetTimeout(g_p2pCtx, &g_p2pSocketNum, g_p2pTaskList, epollfd);
    timeoutUsb = GetTimeout(g_usbCtx, &g_usbSocketNum, g_usbTaskList, epollfd);
#endif
    if (timeoutWlan == DEFAULT_COAP_TIMEOUT &&
        timeoutP2p == DEFAULT_COAP_TIMEOUT &&
        timeoutUsb == DEFAULT_COAP_TIMEOUT) {
        timeout = DEFAULT_COAP_TIMEOUT;
    } else {
        minTimeout = (timeoutWlan < timeoutP2p) ? timeoutWlan : timeoutP2p;
        timeout = (minTimeout < timeoutUsb) ? minTimeout : timeoutUsb;
    }
#ifdef _WIN32
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
#else
    return timeout;
#endif
}
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */

#ifdef _WIN32
uint32_t GetTimeout(struct coap_context_t *ctx, uint32_t *socketNum, EpollTask *taskList, EpollDesc epollfd,
    TaskListInfo *info)
#else
uint32_t GetTimeout(struct coap_context_t *ctx, uint32_t *socketNum, EpollTask *taskList, EpollDesc epollfd)
#endif
{
    uint32_t events, timeout, i;
    coap_tick_t now;
    coap_socket_t *sockets[MAX_COAP_SOCKET_NUM] = {0};

    if (ctx == NULL || socketNum == NULL || taskList == NULL) {
        return DEFAULT_COAP_TIMEOUT;
    }
    coap_ticks(&now);
    timeout = coap_io_prepare_io(ctx, sockets, (uint32_t)(sizeof(sockets) / sizeof(sockets[0])), socketNum, now);
    if (timeout == 0 || timeout > DEFAULT_COAP_TIMEOUT) {
        timeout = DEFAULT_COAP_TIMEOUT;
    }
    if (*socketNum > MAX_COAP_SOCKET_NUM) {
        *socketNum = MAX_COAP_SOCKET_NUM;
        DFINDER_LOGI(TAG, "socketNum exccedd MAX_COAP_SOCKET_NUM, and set it to MAX_COAP_SOCKET_NUM");
    }
    for (i = 0; i < *socketNum; i++) {
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
        taskList[i].taskfd = sockets[i]->fd;
        taskList[i].epollfd = epollfd;
        taskList[i].readHandle = CoAPEpollReadHandle;
        taskList[i].writeHandle = CoAPEpollWriteHandle;
        taskList[i].errorHandle = CoAPEpollErrorHandle;
        taskList[i].ptr = sockets[i];
#ifdef _WIN32
        (void)memcpy_s(&info->taskList[info->count], sizeof(info->taskList[info->count]),
            &taskList[i], sizeof(taskList[i]));
        info->eventList[info->count] = events;
        info->dataList[info->count] = &taskList[i];
        info->count++;
#else
        RegisterEpollTask(&taskList[i], events);
#endif /* #ifdef _WIN32 */
    }
    return timeout;
}

#ifdef DFINDER_SUPPORT_MULTI_NIF
void DeRegisterCoAPEpollTask(void)
{
    for (uint32_t i = 0; i < NSTACKX_MAX_LISTENED_NIF_NUM && g_coapCtxArr[i].ctx != NULL; ++i) {
        if (g_coapCtxArr[i].ctxSocketErrFlag) {
            DFINDER_LOGI(TAG, "error occurred at idx-%u in global coap context array, now destroy this context", i);
            g_coapCtxArr[i].ctxSocketErrFlag = NSTACKX_FALSE;
            NotifyDFinderMsgRecver(DFINDER_ON_INNER_ERROR);
        } else {
            DeRegisteCoAPEpollTaskCtx(g_coapCtxArr[i].ctx, &(g_coapCtxArr[i].socketNum), g_coapCtxArr[i].taskList);
        }
    }
}
#else
void DeRegisterCoAPEpollTask(void)
{
    if (g_ctxSocketErrFlag) {
        DFINDER_LOGI(TAG, "error of g_ctx's socket occurred and destroy g_ctx");
        g_ctxSocketErrFlag = NSTACKX_FALSE;
        NotifyDFinderMsgRecver(DFINDER_ON_INNER_ERROR);
        CoapServerDestroy();
    } else {
        DeRegisteCoAPEpollTaskCtx(g_ctx, &g_socketNum, g_taskList);
    }
    if (g_p2pCtxSocketErrFlag) {
        DFINDER_LOGI(TAG, "error of g_p2pctx's socket occurred and destroy g_ctx");
        CoapP2pServerDestroy();
    } else {
        DeRegisteCoAPEpollTaskCtx(g_p2pCtx, &g_p2pSocketNum, g_p2pTaskList);
    }

    if (g_usbCtxSocketErrFlag) {
        DFINDER_LOGI(TAG, "error of g_usbCtx's socket occurred and destroy g_ctx");
        CoapUsbServerDestroy();
    } else {
        DeRegisteCoAPEpollTaskCtx(g_usbCtx, &g_usbSocketNum, g_usbTaskList);
    }
}
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */

void DeRegisteCoAPEpollTaskCtx(struct coap_context_t *ctx, uint32_t *socketNum, EpollTask *taskList)
{
    coap_tick_t now;
    uint32_t i;

    if (ctx == NULL || socketNum == NULL || taskList == NULL) {
        DFINDER_LOGE(TAG, "parameters null.");
        return;
    }

    if (*socketNum > MAX_COAP_SOCKET_NUM) {
        *socketNum = MAX_COAP_SOCKET_NUM;
        DFINDER_LOGI(TAG, "socketNum exccedd MAX_COAP_SOCKET_NUM, and set it to MAX_COAP_SOCKET_NUM");
    }

    for (i = 0; i < *socketNum; i++) {
        if (taskList[i].taskfd < 0) {
            continue;
        }
        DeRegisterEpollTask(&taskList[i]);
    }
    *socketNum = 0;

    coap_ticks(&now);
    coap_io_do_io(ctx, now);
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
            LOGE(TAG, "Coap thread lock failed");
            break;
        }
        if (g_coapThreadParam.terminated) {
            LOGI(TAG, "Coap thread terminated");
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

void CoapThreadDestory(void)
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

#ifdef DFINDER_SUPPORT_MULTI_NIF
static int32_t CoapServerInitWithIdxEx(const struct in_addr *ip, uint32_t idx, const char *networkName)
{
    DFINDER_LOGI(TAG, "CoapServerInitWithIdx, idx-%u", idx);

    char addrStr[NI_MAXHOST] = COAP_SRV_DEFAULT_ADDR;
    char portStr[NI_MAXSERV] = COAP_SRV_DEFAULT_PORT;

    if (!IsApConnectedWithIdx(idx)) {
        DFINDER_LOGD(TAG, "ap is not connected with nif-%u", idx);
        return NSTACKX_EOK;
    }

    if (g_coapCtxArr[idx].ctx != NULL) {
        DFINDER_LOGI(TAG, "coaps server need to change");
        CoapServerDestroyWithIdx(idx);
    }
    coap_startup();
    g_coapCtxArr[idx].ctx = CoapGetContext(addrStr, portStr, NSTACKX_TRUE, ip);
    if (g_coapCtxArr[idx].ctx == NULL) {
        DFINDER_LOGE(TAG, "coap init get context with idx-%u failed", idx);
        return NSTACKX_EFAILED;
    }
    CoapInitResourcesWithIdx(g_coapCtxArr[idx].ctx, idx, networkName);
    coap_register_response_handler(g_coapCtxArr[idx].ctx, CoapMessageHandler);

    return NSTACKX_EOK;
}

int32_t CoapServerInitWithIdx(const struct in_addr *ip, uint32_t idx, const char *networkName)
{
    int32_t ret = CoapServerInitWithIdxEx(ip, idx, networkName);
    if (ret != NSTACKX_EOK) {
        IncStatistics(STATS_CREATE_SERVER_FAILED);
    }
    return ret;
}
#else
static int32_t CoapServerInitEx(const struct in_addr *ip)
{
    DFINDER_LOGD(TAG, "CoapServerInit is called");

    char addrStr[NI_MAXHOST] = COAP_SRV_DEFAULT_ADDR;
    char portStr[NI_MAXSERV] = COAP_SRV_DEFAULT_PORT;

    if (!IsWifiApConnected()) {
        DFINDER_LOGD(TAG, "wifi not connected");
        return NSTACKX_EOK;
    }

    if (g_ctx != NULL) {
        DFINDER_LOGI(TAG, "coap server need to change");
        CoapServerDestroy();
    }

    coap_startup();
    g_ctx = CoapGetContext(addrStr, portStr, NSTACKX_TRUE, ip);
    if (g_ctx == NULL) {
        DFINDER_LOGE(TAG, "coap init get context failed");
        return NSTACKX_EFAILED;
    }

    CoapInitResources(g_ctx, SERVER_TYPE_WLANORETH);
    coap_register_response_handler(g_ctx, CoapMessageHandler);

    return NSTACKX_EOK;
}

int32_t CoapServerInit(const struct in_addr *ip)
{
    int32_t ret = CoapServerInitEx(ip);
    if (ret != NSTACKX_EOK) {
        IncStatistics(STATS_CREATE_SERVER_FAILED);
    }
    return ret;
}

static int32_t CoapP2pServerInitEx(const struct in_addr *ip)
{
    DFINDER_LOGD(TAG, "CoapP2pServerInit is called");

    char addrStr[NI_MAXHOST] = {0};
    char portStr[NI_MAXSERV] = COAP_SRV_DEFAULT_PORT;

    if (g_p2pCtx != NULL) {
        DFINDER_LOGI(TAG, "coap p2p server init has finished");
        return NSTACKX_EOK;
    }

    if (ip == NULL) {
        return NSTACKX_EFAILED;
    }

    if (inet_ntop(AF_INET, ip, addrStr, NI_MAXHOST) == NULL) {
        DFINDER_LOGE(TAG, "inet_ntop failed");
        return NSTACKX_EFAILED;
    }

    coap_startup();
    g_p2pCtx = CoapGetContext(addrStr, portStr, NSTACKX_TRUE, ip);
    if (g_p2pCtx == NULL) {
        DFINDER_LOGE(TAG, "coap p2p init get context failed");
        return NSTACKX_EFAILED;
    }

    /* if g_p2pCtx has been created, update the g_p2pIp */
    SetP2pIp(ip);
    CoapInitResources(g_p2pCtx, SERVER_TYPE_P2P);
    coap_register_response_handler(g_p2pCtx, CoapMessageHandler);
    return NSTACKX_EOK;
}

int32_t CoapP2pServerInit(const struct in_addr *ip)
{
    int32_t ret = CoapP2pServerInitEx(ip);
    if (ret != NSTACKX_EOK) {
        IncStatistics(STATS_CREATE_SERVER_FAILED);
    }
    return ret;
}

static int32_t CoapUsbServerInitEx(const struct in_addr *ip)
{
    DFINDER_LOGD(TAG, "CoapUsbServerInit is called");

    char addrStr[NI_MAXHOST] = {0};
    char portStr[NI_MAXSERV] = COAP_SRV_DEFAULT_PORT;

    if (g_usbCtx != NULL) {
        DFINDER_LOGI(TAG, "coap usb server init has finished");
        return NSTACKX_EOK;
    }

    if (ip == NULL) {
        return NSTACKX_EFAILED;
    }

    if (inet_ntop(AF_INET, ip, addrStr, NI_MAXHOST) == NULL) {
        DFINDER_LOGE(TAG, "inet_ntop failed");
        return NSTACKX_EFAILED;
    }

    coap_startup();
    g_usbCtx = CoapGetContext(addrStr, portStr, NSTACKX_TRUE, ip);
    if (g_usbCtx == NULL) {
        DFINDER_LOGE(TAG, "coap usb init get context failed");
        return NSTACKX_EFAILED;
    }
    SetUsbIp(ip);

    CoapInitResources(g_usbCtx, SERVER_TYPE_USB);
    coap_register_response_handler(g_usbCtx, CoapMessageHandler);

    return NSTACKX_EOK;
}

int32_t CoapUsbServerInit(const struct in_addr *ip)
{
    int32_t ret = CoapUsbServerInitEx(ip);
    if (ret != NSTACKX_EOK) {
        IncStatistics(STATS_CREATE_SERVER_FAILED);
    }
    return ret;
}
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */

#ifdef DFINDER_SUPPORT_MULTI_NIF
void CoapServerDestroyWithIdx(uint32_t ctxIdx)
{
    DFINDER_LOGD(TAG, "coap server destroy with index-%u", ctxIdx);

    uint32_t i;
    g_coapCtxArr[ctxIdx].ctxSocketErrFlag = NSTACKX_FALSE;
    if (g_coapCtxArr[ctxIdx].ctx == NULL) {
        DFINDER_LOGD(TAG, "coap server destroy with idx-%u, ctx is null", ctxIdx);
        return;
    }
    for (i = 0; i < g_coapCtxArr[ctxIdx].socketNum && i < MAX_COAP_SOCKET_NUM; ++i) {
        if (g_coapCtxArr[ctxIdx].taskList[i].taskfd < 0) {
            continue;
        }
        DeRegisterEpollTask(&(g_coapCtxArr[ctxIdx].taskList[i]));
    }
    g_coapCtxArr[ctxIdx].socketNum = 0;
    coap_free_context(g_coapCtxArr[ctxIdx].ctx);
    g_coapCtxArr[ctxIdx].ctx = NULL;
    CoapDestroyCtxWithIdx(ctxIdx);
}
#else
void CoapServerDestroy(void)
{
    DFINDER_LOGD(TAG, "CoapServerDestroy is called");

    uint32_t i;
    g_ctxSocketErrFlag = NSTACKX_FALSE;
    if (g_ctx == NULL) {
        return;
    }
    for (i = 0; i < g_socketNum && i < MAX_COAP_SOCKET_NUM; i++) {
        if (g_taskList[i].taskfd < 0) {
            continue;
        }
        DeRegisterEpollTask(&g_taskList[i]);
    }
    g_socketNum = 0;

    coap_free_context(g_ctx);
    g_ctx = NULL;
    CoapDestroyCtx(SERVER_TYPE_WLANORETH);
}

void CoapP2pServerDestroy(void)
{
    DFINDER_LOGD(TAG, "CoapP2pServerDestroy is called");

    uint32_t i;
    g_p2pCtxSocketErrFlag = NSTACKX_FALSE;
    if (g_p2pCtx == NULL) {
        return;
    }

    if (g_p2pSocketNum > MAX_COAP_SOCKET_NUM) {
        g_p2pSocketNum = MAX_COAP_SOCKET_NUM;
        DFINDER_LOGI(TAG, "socketNum exccedd MAX_COAP_SOCKET_NUM, and set it to MAX_COAP_SOCKET_NUM");
    }

    for (i = 0; i < g_p2pSocketNum; i++) {
        if (g_p2pTaskList[i].taskfd < 0) {
            continue;
        }
        DeRegisterEpollTask(&g_p2pTaskList[i]);
    }
    g_p2pSocketNum = 0;

    coap_free_context(g_p2pCtx);
    g_p2pCtx = NULL;
    CoapDestroyCtx(SERVER_TYPE_P2P);
}

void CoapUsbServerDestroy(void)
{
    DFINDER_LOGD(TAG, "CoapUsbServerDestroy is called");

    uint32_t i;
    g_usbCtxSocketErrFlag = NSTACKX_FALSE;
    if (g_usbCtx == NULL) {
        return;
    }

    if (g_usbSocketNum > MAX_COAP_SOCKET_NUM) {
        g_usbSocketNum = MAX_COAP_SOCKET_NUM;
        DFINDER_LOGI(TAG, "socketNum exccedd MAX_COAP_SOCKET_NUM, and set it to MAX_COAP_SOCKET_NUM");
    }

    for (i = 0; i < g_usbSocketNum; i++) {
        if (g_usbTaskList[i].taskfd < 0) {
            continue;
        }
        DeRegisterEpollTask(&g_usbTaskList[i]);
    }
    g_usbSocketNum = 0;

    coap_free_context(g_usbCtx);
    g_usbCtx = NULL;
    CoapDestroyCtx(SERVER_TYPE_USB);
}
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */

#ifdef DFINDER_SUPPORT_MULTI_NIF
void ResetCoapSocketTaskCount(uint8_t isBusy)
{
    uint64_t totalTaskCountArr[NSTACKX_MAX_LISTENED_NIF_NUM] = {0};

    for (uint32_t i = 0; i < NSTACKX_MAX_LISTENED_NIF_NUM && g_coapCtxArr[i].ctx != NULL; ++i) {
        for (uint32_t j = 0; j < g_coapCtxArr[i].socketNum && j < MAX_COAP_SOCKET_NUM; ++j) {
            if (totalTaskCountArr[i] < UINT64_MAX &&
                g_coapCtxArr[i].taskList[j].count <= UINT64_MAX - totalTaskCountArr[i]) {
                totalTaskCountArr[i] += g_coapCtxArr[i].taskList[j].count;
            }
            g_coapCtxArr[i].taskList[j].count = 0;
        }
    }
    if (isBusy) {
        for (uint32_t i = 0; i < NSTACKX_MAX_LISTENED_NIF_NUM; ++i) {
            DFINDER_LOGI(TAG, "in this busy interval, socket task count with coap context[%u] is: %llu",
                i, totalTaskCountArr[i]);
        }
        DFINDER_LOGI(TAG, "in this busy interval, socket event count: read %llu, write %llu, error %llu",
            g_socketEventNum[SOCKET_READ_EVENT], g_socketEventNum[SOCKET_WRITE_EVENT],
            g_socketEventNum[SOCKET_ERROR_EVENT]);
    }
    (void)memset_s(g_socketEventNum, sizeof(g_socketEventNum), 0, sizeof(g_socketEventNum));
}
#else
void ResetCoapSocketTaskCount(uint8_t isBusy)
{
    uint64_t totalTaskCount = 0;
    uint64_t totalP2pTaskCount = 0;
    uint64_t totalUsbTaskCount = 0;
    for (uint32_t i = 0; i < g_socketNum && i < MAX_COAP_SOCKET_NUM; i++) {
        if (totalTaskCount < UINT64_MAX && g_taskList[i].count <= UINT64_MAX - totalTaskCount) {
            totalTaskCount += g_taskList[i].count;
        }
        g_taskList[i].count = 0;
    }
    for (uint32_t i = 0; i < g_p2pSocketNum && i < MAX_COAP_SOCKET_NUM; i++) {
        if (totalP2pTaskCount < UINT64_MAX && g_p2pTaskList[i].count <= UINT64_MAX - totalP2pTaskCount) {
            totalP2pTaskCount += g_p2pTaskList[i].count;
        }
        g_p2pTaskList[i].count = 0;
    }
    for (uint32_t i = 0; i < g_usbSocketNum && i < MAX_COAP_SOCKET_NUM; i++) {
        if (totalUsbTaskCount < UINT64_MAX && g_usbTaskList[i].count <= UINT64_MAX - totalUsbTaskCount) {
            totalUsbTaskCount += g_usbTaskList[i].count;
        }
        g_usbTaskList[i].count = 0;
    }
    if (isBusy) {
        DFINDER_LOGI(TAG, "in this busy interval, socket task count: wifi %llu, p2p %llu, usb %llu",
                     totalTaskCount, totalP2pTaskCount, totalUsbTaskCount);
        DFINDER_LOGI(TAG, "in this busy interval, socket event count: read %llu, write %llu, error %llu",
                     g_socketEventNum[SOCKET_READ_EVENT], g_socketEventNum[SOCKET_WRITE_EVENT],
                     g_socketEventNum[SOCKET_ERROR_EVENT]);
    }
    (void)memset_s(g_socketEventNum, sizeof(g_socketEventNum), 0, sizeof(g_socketEventNum));
}
#endif /* END OF DFINDER_SUPPORT_MULTI_NIF */
