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
#include <netdb.h>
#include <securec.h>
#include <string.h>
#include <unistd.h>

#include "cJSON.h"
#include "coap_adapter.h"
#include "coap_discover.h"
#include "json_payload.h"
#include "nstackx_device.h"
#include "nstackx_epoll.h"
#include "nstackx_error.h"
#include "nstackx_log.h"
#include "sys_util.h"

#define TAG "nStackXCoAP"

typedef enum {
    SOCKET_READ_EVENT = 0,
    SOCKET_WRITE_EVENT,
    SOCKET_ERROR_EVENT,
    SOCKET_END_EVENT
} SocketEventType;

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

static int32_t g_coapListenFd = -1;
static EpollTask g_task;
static uint8_t g_ctxSocketErrFlag = NSTACKX_FALSE;
static uint64_t g_socketEventNum[SOCKET_END_EVENT];

static bool IsLoopBackPacket(struct sockaddr_in *remoteAddr)
{
    struct in_addr localAddr = {0};
    char ipString[NSTACKX_MAX_IP_STRING_LEN] = {0};
    if (GetLocalIpString(ipString, sizeof(ipString)) != NSTACKX_EOK) {
        LOGE(TAG, "get local ip string failed");
        return false;
    }
    if (inet_pton(AF_INET, ipString, &localAddr) != 1) {
        LOGE(TAG, "inet_pton failed, errno = %d", errno);
        return false;
    }
    if (remoteAddr->sin_addr.s_addr == localAddr.s_addr) {
        LOGE(TAG, "drop loopback packet");
        return true;
    }
    return false;
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
        free(recvBuffer);
        LOGE(TAG, "receive from remote packet failed");
        return;
    }

    if (IsLoopBackPacket(&remoteAddr)) {
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

static int32_t CoapCreateUdpClient(const struct sockaddr_in *sockAddr, uint8_t isBroadCast)
{
    (void)sockAddr;
    int32_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOGE(TAG, "create socket failed, errno = %d", fd);
        return NSTACKX_EFAILED;
    }

    int32_t optVal = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optVal, sizeof(optVal)) != 0) {
        LOGE(TAG, "set sock opt failed, errno = %d", errno);
        goto CLOSE_FD;
    }

    char ipString[NSTACKX_MAX_IP_STRING_LEN] = {0};
    if (GetLocalIpString(ipString, sizeof(ipString)) != NSTACKX_EOK) {
        LOGE(TAG, "get local ip string failed");
        goto CLOSE_FD;
    }

    struct sockaddr_in localAddr;
    (void)memset_s(&localAddr, sizeof(localAddr), 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = inet_addr(ipString);
    localAddr.sin_port = htons(COAP_SRV_DEFAULT_PORT);

    if (bind(fd, (struct sockaddr *)&localAddr, sizeof(struct sockaddr_in)) == -1) {
        LOGE(TAG, "bind local addr failed, errno = %d", errno);
        goto CLOSE_FD;
    }

    if (isBroadCast && setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &optVal, sizeof(optVal)) != 0) {
        LOGE(TAG, "set sock opt broadcast failed, errno = %d", errno);
        goto CLOSE_FD;
    }

    return fd;
CLOSE_FD:
    close(fd);
    return NSTACKX_EFAILED;
}

static int32_t CoapSocketSend(const SocketInfo *socket, const uint8_t *buffer, size_t length)
{
    if (buffer == NULL || socket == NULL) {
        return NSTACKX_EFAILED;
    }

    socklen_t dstAddrLen = sizeof(struct sockaddr_in);
    int32_t ret = sendto(socket->cliendFd, buffer, length, 0, (struct sockaddr *)&socket->dstAddr, dstAddrLen);
    if (ret != (int32_t)length) {
        LOGE(TAG, "sendto failed, ret = %d, errno = %d", ret, errno);
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
    if (fd == NSTACKX_EFAILED) {
        return NSTACKX_EFAILED;
    }

    SocketInfo socket = {0};
    socket.cliendFd = fd;
    socket.dstAddr = sockAddr;
    if (CoapSocketSend(&socket, (uint8_t *)coapRequest->data, coapRequest->dataLength) == -1) {
        LOGE(TAG, "Coap socket send response message failed");
        close(fd);
        return NSTACKX_EFAILED;
    }
    close(fd);
    return NSTACKX_EOK;
}

int32_t CoapSendMessage(const CoapBuildParam *param, uint8_t isBroadcast, bool isAckMsg)
{
    if (param == NULL) {
        LOGE(TAG, "coap build param is null");
        return NSTACKX_EFAILED;
    }

    int32_t ret;
    char *payload = NULL;
    CoapRequest coapRequest = {0};
    coapRequest.remoteIp = param->remoteIp;
    CoapReadWriteBuffer sndPktBuff = {0};
    sndPktBuff.readWriteBuf = calloc(1, COAP_MAX_PDU_SIZE);
    if (sndPktBuff.readWriteBuf == NULL) {
        return NSTACKX_EFAILED;
    }
    sndPktBuff.size = COAP_MAX_PDU_SIZE;
    sndPktBuff.len = 0;
    if (!isAckMsg) {
        payload = PrepareServiceDiscover(isBroadcast);
        if (payload == NULL) {
            free(sndPktBuff.readWriteBuf);
            LOGE(TAG, "prepare payload data failed");
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
        LOGE(TAG, "build coap packet failed, ret = %d", ret);
        return ret;
    }
    coapRequest.data = sndPktBuff.readWriteBuf;
    coapRequest.dataLength = sndPktBuff.len;
    ret = CoapSendMsg(&coapRequest, isBroadcast);
    free(sndPktBuff.readWriteBuf);
    sndPktBuff.readWriteBuf = NULL;
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
        LOGI(TAG, "error of g_ctx's socket occurred and destroy g_ctx");
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
    g_socketEventNum[SOCKET_ERROR_EVENT]++;
    g_ctxSocketErrFlag = NSTACKX_TRUE;
    LOGE(TAG, "coap socket error occurred and close it");
    DeRegisterCoAPEpollTask();
    CloseDesc(task->taskfd);
    task->taskfd = -1;
}

static uint32_t RegisterCoAPEpollTask(EpollDesc epollfd)
{
    if (g_coapListenFd == -1) {
        LOGI(TAG, "g_coapListenFd hasn't initialized.");
        return NSTACKX_FALSE;
    }

    uint32_t events = EPOLLIN | EPOLLERR;
    g_task.taskfd = g_coapListenFd;
    g_task.epollfd = epollfd;
    g_task.readHandle = CoAPEpollReadHandle;
    g_task.writeHandle = NULL;
    g_task.errorHandle = CoAPEpollErrorHandle;
    if (g_task.taskfd < 0) {
        LOGE(TAG, "g_coapListenFd isn't correct.");
        return NSTACKX_FALSE;
    }
    RegisterEpollTask(&g_task, events);
    return NSTACKX_EOK;
}

static int32_t CoapCreateUdpServer(const char *ipAddr, int32_t port)
{
    struct sockaddr_in localAddr;
    socklen_t len = sizeof(localAddr);
    int32_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return NSTACKX_FALSE;
    }

    int32_t optVal = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optVal, sizeof(optVal)) != 0) {
        LOGE(TAG, "set sock opt failed, errno = %d", errno);
        close(fd);
        return NSTACKX_FALSE;
    }

    (void)memset_s(&localAddr, sizeof(localAddr), 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(port);
    localAddr.sin_addr.s_addr = inet_addr(ipAddr);

    if (bind(fd, (struct sockaddr *)&localAddr, len) == -1) {
        close(fd);
        return NSTACKX_FALSE;
    }

    if (getsockname(fd, (struct sockaddr *)&localAddr, &len) == -1) {
        close(fd);
        return NSTACKX_FALSE;
    }
    return fd;
}

static int32_t CoapGetContext(const char *node, int32_t port, uint8_t needBind, const struct in_addr *ip)
{
    (void)ip;
    (void)needBind;
    int32_t coapListenFd = CoapCreateUdpServer(node, port);
    if (coapListenFd <= 0) {
        LOGE(TAG, "create coap listen fd failed");
        return NSTACKX_FALSE;
    }

    return coapListenFd;
}

int32_t CoapServerInit(const struct in_addr *ip)
{
    LOGD(TAG, "CoapServerInit is called");
    EpollDesc epollFd;
    int32_t ret;

    if (!IsWifiApConnected()) {
        LOGD(TAG, "wifi not connected");
        return NSTACKX_EOK;
    }

    if (g_coapListenFd != -1) {
        LOGI(TAG, "coap server has initialized.");
        return NSTACKX_EOK;
    }

    g_coapListenFd = CoapGetContext(COAP_SRV_DEFAULT_ADDR, COAP_SRV_DEFAULT_PORT, NSTACKX_TRUE, ip);
    if (g_coapListenFd == -1) {
        LOGE(TAG, "coap init get listen fd failed");
        return NSTACKX_EFAILED;
    }

    epollFd = GetMainLoopEpollFd();
    if (!IsEpollDescValid(epollFd)) {
        LOGE(TAG, "epoll is invalid!");
        return NSTACKX_EFAILED;
    }

    ret = RegisterCoAPEpollTask(epollFd);
    if (ret != NSTACKX_EOK) {
        LOGE(TAG, "register coap epoll task failed!");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

void CoapServerDestroy(void)
{
    LOGD(TAG, "CoapServerDestroy is called");

    if (g_coapListenFd == -1) {
        return;
    }
    DeRegisterCoAPEpollTask();
    g_ctxSocketErrFlag = NSTACKX_FALSE;
    g_coapListenFd = -1;
}

void ResetCoapSocketTaskCount(uint8_t isBusy)
{
    if (isBusy) {
        LOGI(TAG, "in this busy interval, socket task count: wifi %llu,"
            "read %llu, write %llu, error %llu", g_task.count,
            g_socketEventNum[SOCKET_READ_EVENT],
            g_socketEventNum[SOCKET_WRITE_EVENT], g_socketEventNum[SOCKET_ERROR_EVENT]);
    }
    g_task.count = 0;
    (void)memset_s(g_socketEventNum, sizeof(g_socketEventNum), 0, sizeof(g_socketEventNum));
}
