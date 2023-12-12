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
#include <netdb.h>
#include <securec.h>
#include <string.h>
#include <unistd.h>

#include "cJSON.h"
#include "coap_adapter.h"
#include "coap_discover.h"
#include "json_payload.h"
#include "lwip/sockets.h"
#include "nstackx_device.h"
#include "nstackx_epoll.h"
#include "nstackx_error.h"
#include "nstackx_dfinder_log.h"
#include "sys_util.h"
#include "nstackx_statistics.h"
#include "nstackx_device_local.h"

#define TAG "nStackXCoAP"

typedef struct {
    int32_t cliendFd;
    struct sockaddr_in dstAddr;
} SocketInfo;

typedef struct CoapRequest {
    const char *remoteUrl;
    char *data;
    size_t dataLength;
    const char *remoteIp;
} CoapRequest;

static EpollTask g_task;
static uint8_t g_ctxSocketErrFlag = NSTACKX_FALSE;
static uint64_t g_socketEventNum[SOCKET_END_EVENT];

static CoapCtxType g_coapCtx;

bool IsCoapContextReady(void)
{
    return g_coapCtx.inited;
}

const char *CoapGetLocalIfaceName(void)
{
    if (g_coapCtx.inited) {
        return GetLocalIfaceName(g_coapCtx.iface);
    }

    return NULL;
}

CoapCtxType *CoapGetCoapCtxType(void)
{
    if (g_coapCtx.inited) {
        return &g_coapCtx;
    }

    return NULL;
}

static bool IsLoopBackPacket(struct sockaddr_in *remoteAddr)
{
    if (!g_coapCtx.inited) {
        return false;
    }
    struct in_addr *localAddr = GetLocalIfaceIp(g_coapCtx.iface);
    if (remoteAddr->sin_addr.s_addr != localAddr->s_addr) {
        return false;
    }
    return true;
}

static void HandleReadEvent(int32_t fd)
{
    uint8_t *recvBuffer = calloc(1, COAP_MAX_PDU_SIZE + 1);
    if (recvBuffer == NULL) {
        return;
    }
    struct sockaddr_in remoteAddr = {0};
    socklen_t len = sizeof(struct sockaddr_in);
    ssize_t nRead = recvfrom(fd, recvBuffer, COAP_MAX_PDU_SIZE, 0, (struct sockaddr *)&remoteAddr, &len);
    if ((nRead == 0) || (nRead < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
        IncStatistics(STATS_SOCKET_ERROR);
        free(recvBuffer);
        DFINDER_LOGE(TAG, "receive from remote packet failed");
        return;
    }

    if (IsLoopBackPacket(&remoteAddr)) {
        IncStatistics(STATS_DROP_LOOPBACK_PKT);
        free(recvBuffer);
        return;
    }

    CoapPacket decodePacket;
    (void)memset_s(&decodePacket, sizeof(CoapPacket), 0, sizeof(CoapPacket));
    decodePacket.protocol = COAP_UDP;
    CoapSoftBusDecode(&decodePacket, recvBuffer, nRead);
    HndPostServiceDiscover(&decodePacket);
    free(recvBuffer);
}

static int32_t CoapCreateUdpClientEx(const struct sockaddr_in *sockAddr, uint8_t isBroadCast)
{
    (void)sockAddr;
    int32_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        DFINDER_LOGE(TAG, "create socket failed, errno = %d", fd);
        return NSTACKX_EFAILED;
    }

    int32_t optVal = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optVal, sizeof(optVal)) != 0) {
        DFINDER_LOGE(TAG, "set sock opt failed, errno = %d", errno);
        goto CLOSE_FD;
    }

    struct sockaddr_in localAddr;
    (void)memset_s(&localAddr, sizeof(localAddr), 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = GetLocalIfaceIp(g_coapCtx.iface)->s_addr;
    localAddr.sin_port = htons(COAP_SRV_DEFAULT_PORT);

    if (bind(fd, (struct sockaddr *)&localAddr, sizeof(struct sockaddr_in)) == -1) {
        DFINDER_LOGE(TAG, "bind local addr failed, errno = %d", errno);
        goto CLOSE_FD;
    }

    if (isBroadCast && setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &optVal, sizeof(optVal)) != 0) {
        DFINDER_LOGE(TAG, "set sock opt broadcast failed, errno = %d", errno);
        goto CLOSE_FD;
    }

    return fd;
CLOSE_FD:
    lwip_close(fd);
    return NSTACKX_EFAILED;
}

static int32_t CoapCreateUdpClient(const struct sockaddr_in *sockAddr, uint8_t isBroadCast)
{
    int32_t ret = CoapCreateUdpClientEx(sockAddr, isBroadCast);
    if (ret == NSTACKX_EFAILED) {
        IncStatistics(STATS_CREATE_CLIENT_FAILED);
    }
    return ret;
}

static int32_t CoapSocketSend(const SocketInfo *socket, const uint8_t *buffer, size_t length)
{
    if (buffer == NULL || socket == NULL) {
        return NSTACKX_EFAILED;
    }

    socklen_t dstAddrLen = sizeof(struct sockaddr_in);
    int32_t ret = sendto(socket->cliendFd, buffer, length, 0, (struct sockaddr *)&socket->dstAddr, dstAddrLen);
    if (ret != length) {
        IncStatistics(STATS_SOCKET_ERROR);
        DFINDER_LOGE(TAG, "sendto failed, ret = %d, errno = %d", ret, errno);
    }
    return ret;
}

static int32_t CoapSendMsg(const CoapRequest *coapRequest, uint8_t isBroadcast)
{
    if (coapRequest == NULL || coapRequest->remoteIp == NULL) {
        return NSTACKX_EFAILED;
    }

    struct sockaddr_in sockAddr = {0};
    sockAddr.sin_addr.s_addr = inet_addr(coapRequest->remoteIp);
    sockAddr.sin_port = htons(COAP_SRV_DEFAULT_PORT);
    sockAddr.sin_family = AF_INET;

    int32_t fd = CoapCreateUdpClient(&sockAddr, isBroadcast);
    if (fd < 0) {
        DFINDER_LOGE(TAG, "Create coap udp client failed");
        return NSTACKX_EFAILED;
    }

    SocketInfo socket = {0};
    socket.cliendFd = fd;
    socket.dstAddr = sockAddr;
    if (CoapSocketSend(&socket, (uint8_t *)coapRequest->data, coapRequest->dataLength) == -1) {
        DFINDER_LOGE(TAG, "Coap socket send response message failed");
        lwip_close(fd);
        return NSTACKX_EFAILED;
    }
    lwip_close(fd);
    return NSTACKX_EOK;
}

static int32_t CoapSendMessageEx(const CoapBuildParam *param, uint8_t isBroadcast, uint8_t businessType, bool isAckMsg)
{
    if (param == NULL) {
        DFINDER_LOGE(TAG, "coap build param is null");
        return NSTACKX_EFAILED;
    }

    int32_t ret;
    char *payload = NULL;
    CoapRequest coapRequest = {0};
    coapRequest.remoteIp = param->remoteIp;
    CoapReadWriteBuffer sndPktBuff = {0};
    sndPktBuff.readWriteBuf = (char *)calloc(COAP_MAX_PDU_SIZE, sizeof(char));
    if (sndPktBuff.readWriteBuf == NULL) {
        DFINDER_LOGE(TAG, "mem calloc failed, size = %u", COAP_MAX_PDU_SIZE * sizeof(char));
        return NSTACKX_EFAILED;
    }
    sndPktBuff.size = COAP_MAX_PDU_SIZE;
    sndPktBuff.len = 0;
    if (!isAckMsg) {
        payload = PrepareServiceDiscover(GetLocalIfaceIpStr(g_coapCtx.iface), isBroadcast, businessType);
        if (payload == NULL) {
            free(sndPktBuff.readWriteBuf);
            DFINDER_LOGE(TAG, "prepare payload data failed");
            return NSTACKX_EFAILED;
        }
    }

    ret = BuildCoapPkt(param, payload, &sndPktBuff, isAckMsg);
    if (payload != NULL) {
        cJSON_free(payload);
        payload = NULL;
    }
    if (ret != DISCOVERY_ERR_SUCCESS) {
        free(sndPktBuff.readWriteBuf);
        sndPktBuff.readWriteBuf = NULL;
        DFINDER_LOGE(TAG, "build coap packet failed, ret = %d", ret);
        return ret;
    }
    coapRequest.data = sndPktBuff.readWriteBuf;
    coapRequest.dataLength = sndPktBuff.len;
    ret = CoapSendMsg(&coapRequest, isBroadcast);
    free(sndPktBuff.readWriteBuf);
    sndPktBuff.readWriteBuf = NULL;
    return ret;
}

int32_t CoapSendMessage(const CoapBuildParam *param, uint8_t isBroadcast, uint8_t businessType, bool isAckMsg)
{
    if (!g_coapCtx.inited) {
        DFINDER_LOGE(TAG, "coap context not inited");
        return NSTACKX_EFAILED;
    }

    int32_t ret = CoapSendMessageEx(param, isBroadcast, businessType, isAckMsg);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        IncStatistics(STATS_SEND_MSG_FAILED);
    }
    return ret;
}

static void DeRegisteCoAPEpollTaskCtx(void)
{
    DeRegisterEpollTask(&g_task);
    CloseDesc(g_task.taskfd);
    g_task.taskfd = -1;
}

static void DeRegisterCoAPEpollTask(void)
{
    if (g_ctxSocketErrFlag) {
        DFINDER_LOGI(TAG, "error of g_ctx's socket occurred and destroy g_ctx");
        g_ctxSocketErrFlag = NSTACKX_FALSE;
        NotifyDFinderMsgRecver(DFINDER_ON_INNER_ERROR);
    } else {
        DeRegisteCoAPEpollTaskCtx();
    }
}

static void CoAPEpollReadHandle(void *data)
{
    if (data == NULL) {
        return;
    }
    EpollTask *task = (EpollTask*)data;
    if (task->taskfd < 0) {
        return;
    }
    g_socketEventNum[SOCKET_READ_EVENT]++;
    HandleReadEvent(task->taskfd);
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
    IncStatistics(STATS_SOCKET_ERROR);
    g_socketEventNum[SOCKET_ERROR_EVENT]++;
    g_ctxSocketErrFlag = NSTACKX_TRUE;
    DFINDER_LOGE(TAG, "coap socket error occurred and close it");
    DeRegisterCoAPEpollTask();
    CloseDesc(task->taskfd);
    task->taskfd = -1;
}

static int32_t CoapCreateUdpServer(const char *ipAddr, int32_t port)
{
    struct sockaddr_in localAddr;
    socklen_t len = sizeof(localAddr);
    int32_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }

    int32_t optVal = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optVal, sizeof(optVal)) != 0) {
        DFINDER_LOGE(TAG, "set sock opt failed, errno = %d", errno);
        lwip_close(fd);
        return -1;
    }

    (void)memset_s(&localAddr, sizeof(localAddr), 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(port);
    localAddr.sin_addr.s_addr = inet_addr(ipAddr);

    if (bind(fd, (struct sockaddr *)&localAddr, len) == -1) {
        lwip_close(fd);
        return -1;
    }

    if (getsockname(fd, (struct sockaddr *)&localAddr, &len) == -1) {
        lwip_close(fd);
        return -1;
    }
    return fd;
}

CoapCtxType *CoapServerInit(const struct in_addr *ip, void *iface)
{
    if (g_coapCtx.inited) {
        return &g_coapCtx;
    }

    EpollDesc epollFd = GetMainLoopEpollFd();
    if (!IsEpollDescValid(epollFd)) {
        DFINDER_LOGE(TAG, "epoll is invalid!");
        return NULL;
    }

    int32_t listenFd = CoapCreateUdpServer(COAP_SRV_DEFAULT_ADDR, COAP_SRV_DEFAULT_PORT);
    if (listenFd < 0) {
        DFINDER_LOGE(TAG, "get context failed");
        return NULL;
    }

    uint32_t events = EPOLLIN | EPOLLERR;
    g_coapCtx.task.taskfd = listenFd;
    g_coapCtx.task.epollfd = epollFd;
    g_coapCtx.task.readHandle = CoAPEpollReadHandle;
    g_coapCtx.task.writeHandle = NULL;
    g_coapCtx.task.errorHandle = CoAPEpollErrorHandle;
    RegisterEpollTask(&g_coapCtx.task, events);

    g_coapCtx.iface = iface;
    g_coapCtx.inited = NSTACKX_TRUE;
    return &g_coapCtx;
}

void CoapServerDestroy(CoapCtxType *ctx, bool moduleDeinit)
{
    if (ctx != &g_coapCtx || !g_coapCtx.inited || !moduleDeinit) {
        DFINDER_LOGE(TAG, "do not destroy, inited: %hhd, module deinit: %hhd", g_coapCtx.inited, moduleDeinit);
        return;
    }

    if (g_coapCtx.socketErrFlag) {
        DFINDER_LOGI(TAG, "socket error occurred and destroy context");
        NotifyDFinderMsgRecver(DFINDER_ON_INNER_ERROR);
    } else {
        DeRegisterEpollTask(&g_coapCtx.task);
        CloseDesc(g_coapCtx.task.taskfd);
    }

    (void)memset_s(&g_coapCtx, sizeof(g_coapCtx), 0, sizeof(g_coapCtx));
    g_coapCtx.task.taskfd = -1;
}

void ResetCoapSocketTaskCount(uint8_t isBusy)
{
    if (isBusy) {
        DFINDER_LOGI(TAG, "in this busy interval, socket task count: wifi %llu,"
            "read %llu, write %llu, error %llu", g_task.count,
            g_socketEventNum[SOCKET_READ_EVENT],
            g_socketEventNum[SOCKET_WRITE_EVENT], g_socketEventNum[SOCKET_ERROR_EVENT]);
    }
    g_task.count = 0;
    (void)memset_s(g_socketEventNum, sizeof(g_socketEventNum), 0, sizeof(g_socketEventNum));
}
