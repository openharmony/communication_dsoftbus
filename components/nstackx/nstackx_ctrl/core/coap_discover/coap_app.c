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
#include <net.h>
#include <netdb.h>
#include <pthread.h>
#include <securec.h>
#include <string.h>
#include <unistd.h>

#include "coap.h"
#include "coap_client.h"
#include "coap_discover.h"
#include "nstackx_util.h"
#include "nstackx_device.h"
#include "nstackx_epoll.h"
#include "nstackx_error.h"
#include "nstackx_log.h"

#define TAG "nStackXCoAP"

#define DEFAULT_COAP_TIMEOUT (COAP_RESOURCE_CHECK_TIME * COAP_TICKS_PER_SECOND)
#define MAX_COAP_SOCKET_NUM 64

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
    EpollTask *task = (EpollTask*)data;
    if (task->taskfd < 0) {
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
    if (data == NULL) {
        return;
    }
    EpollTask *task = data;
    if (task->taskfd < 0) {
        return;
    }
    coap_socket_t *socket = task->ptr;
    g_socketEventNum[SOCKET_ERROR_EVENT]++;
    if (IsCoapCtxEndpointSocket(g_ctx, socket->fd)) {
        LOGE(TAG, "error of g_ctx's socket occurred");
        g_ctxSocketErrFlag = NSTACKX_TRUE;
        return;
    }

    if (IsCoapCtxEndpointSocket(g_p2pCtx, socket->fd)) {
        LOGE(TAG, "error of g_p2pCtx's socket occurred");
        g_p2pCtxSocketErrFlag = NSTACKX_TRUE;
        return;
    }

    if (IsCoapCtxEndpointSocket(g_usbCtx, socket->fd)) {
        LOGE(TAG, "error of g_usbCtx's socket occurred");
        g_usbCtxSocketErrFlag = NSTACKX_TRUE;
        return;
    }

    LOGE(TAG, "coap session socket error occurred and close it");
    DeRegisterEpollTask(task);
    CloseDesc(socket->fd);
    socket->fd = -1;
    task->taskfd = -1;
}

uint32_t RegisterCoAPEpollTask(EpollDesc epollfd)
{
    uint32_t timeoutWlan, timeoutP2p, timeoutUsb, minTimeout;

    if ((g_ctx == NULL) && (g_p2pCtx == NULL) && (g_usbCtx == NULL)) {
        return DEFAULT_COAP_TIMEOUT;
    }

    timeoutWlan = GetTimeout(g_ctx, &g_socketNum, g_taskList, epollfd);
    timeoutP2p = GetTimeout(g_p2pCtx, &g_p2pSocketNum, g_p2pTaskList, epollfd);
    timeoutUsb = GetTimeout(g_usbCtx, &g_usbSocketNum, g_usbTaskList, epollfd);
    if (timeoutWlan == DEFAULT_COAP_TIMEOUT &&
        timeoutP2p == DEFAULT_COAP_TIMEOUT &&
        timeoutUsb == DEFAULT_COAP_TIMEOUT) {
        return DEFAULT_COAP_TIMEOUT;
    } else {
        minTimeout = (timeoutWlan < timeoutP2p) ? timeoutWlan : timeoutP2p;
        return (minTimeout < timeoutUsb) ? minTimeout : timeoutUsb;
    }
}

uint32_t GetTimeout(struct coap_context_t *ctx, uint32_t *socketNum, EpollTask *taskList, EpollDesc epollfd)
{
    uint32_t events;
    coap_tick_t now;
    uint32_t i;
    uint32_t timeout;
    coap_socket_t *sockets[MAX_COAP_SOCKET_NUM] = {0};

    if (ctx == NULL) {
        return DEFAULT_COAP_TIMEOUT;
    }

    coap_ticks(&now);
    timeout = coap_write(ctx, sockets,
        (uint32_t)(sizeof(sockets) / sizeof(sockets[0])), socketNum, now);
    if (timeout == 0 || timeout > DEFAULT_COAP_TIMEOUT) {
        timeout = DEFAULT_COAP_TIMEOUT;
    }
    if (*socketNum > MAX_COAP_SOCKET_NUM) {
        *socketNum = MAX_COAP_SOCKET_NUM;
        LOGI(TAG, "socketNum exccedd MAX_COAP_SOCKET_NUM, and set it to MAX_COAP_SOCKET_NUM");
    }
    for (i = 0; i < *socketNum; i++) {
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
        if (taskList[i].taskfd < 0) {
            continue;
        }
        RegisterEpollTask(&taskList[i], events);
    }

    return timeout;
}

void DeRegisterCoAPEpollTask(void)
{
    if (g_ctxSocketErrFlag) {
        LOGI(TAG, "error of g_ctx's socket occurred and destroy g_ctx");
        g_ctxSocketErrFlag = NSTACKX_FALSE;
        NotifyDFinderMsgRecver(DFINDER_ON_INNER_ERROR);
    } else {
        DeRegisteCoAPEpollTaskCtx(g_ctx, &g_socketNum, g_taskList);
    }
    if (g_p2pCtxSocketErrFlag) {
        LOGI(TAG, "error of g_p2pctx's socket occurred and destroy g_ctx");
        CoapP2pServerDestroy();
    } else {
        DeRegisteCoAPEpollTaskCtx(g_p2pCtx, &g_p2pSocketNum, g_p2pTaskList);
    }

    if (g_usbCtxSocketErrFlag) {
        LOGI(TAG, "error of g_usbCtx's socket occurred and destroy g_ctx");
        CoapUsbServerDestroy();
    } else {
        DeRegisteCoAPEpollTaskCtx(g_usbCtx, &g_usbSocketNum, g_usbTaskList);
    }
}

void DeRegisteCoAPEpollTaskCtx(struct coap_context_t *ctx, uint32_t *socketNum, EpollTask *taskList)
{
    coap_tick_t now;
    uint32_t i;

    if (ctx == NULL) {
        return;
    }

    if (*socketNum > MAX_COAP_SOCKET_NUM) {
        *socketNum = MAX_COAP_SOCKET_NUM;
        LOGI(TAG, "socketNum exccedd MAX_COAP_SOCKET_NUM, and set it to MAX_COAP_SOCKET_NUM");
    }

    for (i = 0; i < *socketNum; i++) {
        if (taskList[i].taskfd < 0) {
            continue;
        }
        DeRegisterEpollTask(&taskList[i]);
    }
    *socketNum = 0;

    coap_ticks(&now);
    coap_read(ctx, now);
}

int32_t CoapServerInit(const struct in_addr *ip)
{
    LOGD(TAG, "CoapServerInit is called");

    char addrStr[NI_MAXHOST] = COAP_SRV_DEFAULT_ADDR;
    char portStr[NI_MAXSERV] = COAP_SRV_DEFAULT_PORT;

    if (!IsWifiApConnected()) {
        LOGD(TAG, "wifi not connected");
        return NSTACKX_EOK;
    }

    if (g_ctx != NULL) {
        LOGI(TAG, "coap server need to change");
        CoapServerDestroy();
    }

    coap_startup();
    g_ctx = CoapGetContext(addrStr, portStr, NSTACKX_TRUE, ip);
    if (g_ctx == NULL) {
        LOGE(TAG, "coap init get context failed");
        return NSTACKX_EFAILED;
    }

    CoapInitResources(g_ctx, SERVER_TYPE_WLANORETH);
    coap_register_response_handler(g_ctx, CoapMessageHandler);

    return NSTACKX_EOK;
}

int32_t CoapP2pServerInit(const struct in_addr *ip)
{
    LOGD(TAG, "CoapP2pServerInit is called");

    char addrStr[NI_MAXHOST] = {0};
    char portStr[NI_MAXSERV] = COAP_SRV_DEFAULT_PORT;

    if (g_p2pCtx != NULL) {
        LOGI(TAG, "coap p2p server init has finished");
        return NSTACKX_EOK;
    }

    if (ip == NULL) {
        return NSTACKX_EFAILED;
    }

    if (inet_ntop(AF_INET, ip, addrStr, NI_MAXHOST) == NULL) {
        LOGE(TAG, "inet_ntop failed");
        return NSTACKX_EFAILED;
    }

    coap_startup();
    g_p2pCtx = CoapGetContext(addrStr, portStr, NSTACKX_TRUE, ip);
    if (g_p2pCtx == NULL) {
        LOGE(TAG, "coap p2p init get context failed");
        return NSTACKX_EFAILED;
    }

    /* if g_p2pCtx has been created, update the g_p2pIp */
    SetP2pIp(ip);
    CoapInitResources(g_p2pCtx, SERVER_TYPE_P2P);
    coap_register_response_handler(g_p2pCtx, CoapMessageHandler);
    return NSTACKX_EOK;
}

int32_t CoapUsbServerInit(const struct in_addr *ip)
{
    LOGD(TAG, "CoapUsbServerInit is called");

    char addrStr[NI_MAXHOST] = {0};
    char portStr[NI_MAXSERV] = COAP_SRV_DEFAULT_PORT;

    if (g_usbCtx != NULL) {
        LOGI(TAG, "coap usb server init has finished");
        return NSTACKX_EOK;
    }

    if (ip == NULL) {
        return NSTACKX_EFAILED;
    }

    if (inet_ntop(AF_INET, ip, addrStr, NI_MAXHOST) == NULL) {
        LOGE(TAG, "inet_ntop failed");
        return NSTACKX_EFAILED;
    }

    coap_startup();
    g_usbCtx = CoapGetContext(addrStr, portStr, NSTACKX_TRUE, ip);
    if (g_usbCtx == NULL) {
        LOGE(TAG, "coap usb init get context failed");
        return NSTACKX_EFAILED;
    }
    SetUsbIp(ip);

    CoapInitResources(g_usbCtx, SERVER_TYPE_USB);
    coap_register_response_handler(g_usbCtx, CoapMessageHandler);

    return NSTACKX_EOK;
}

void CoapServerDestroy(void)
{
    LOGD(TAG, "CoapServerDestroy is called");

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
    LOGD(TAG, "CoapP2pServerDestroy is called");

    uint32_t i;
    g_p2pCtxSocketErrFlag = NSTACKX_FALSE;
    if (g_p2pCtx == NULL) {
        return;
    }

    if (g_p2pSocketNum > MAX_COAP_SOCKET_NUM) {
        g_p2pSocketNum = MAX_COAP_SOCKET_NUM;
        LOGI(TAG, "socketNum exccedd MAX_COAP_SOCKET_NUM, and set it to MAX_COAP_SOCKET_NUM");
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
    LOGD(TAG, "CoapUsbServerDestroy is called");

    uint32_t i;
    g_usbCtxSocketErrFlag = NSTACKX_FALSE;
    if (g_usbCtx == NULL) {
        return;
    }

    if (g_usbSocketNum > MAX_COAP_SOCKET_NUM) {
        g_usbSocketNum = MAX_COAP_SOCKET_NUM;
        LOGI(TAG, "socketNum exccedd MAX_COAP_SOCKET_NUM, and set it to MAX_COAP_SOCKET_NUM");
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
        LOGI(TAG, "in this busy interval, socket task count: wifi %llu, p2p %llu, usb %llu,"
            "read %llu, write %llu, error %llu",
            totalTaskCount, totalP2pTaskCount, totalUsbTaskCount,
            g_socketEventNum[SOCKET_READ_EVENT],
            g_socketEventNum[SOCKET_WRITE_EVENT], g_socketEventNum[SOCKET_ERROR_EVENT]);
    }
    (void)memset_s(g_socketEventNum, sizeof(g_socketEventNum), 0, sizeof(g_socketEventNum));
}
