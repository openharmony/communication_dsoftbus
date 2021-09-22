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
#include "nstackx_util.h"

#define TAG "nStackXCoAP"

typedef enum {
    SOCKET_READ_EVENT = 0,
    SOCKET_WRITE_EVENT,
    SOCKET_ERROR_EVENT,
    SOCKET_END_EVENT
} SocketEventType;

typedef struct {
    int cliendFd;
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

static int32_t CoapSocketRecv(int socketFd, uint8_t *buffer, size_t length)
{
    if (buffer == NULL || socketFd < 0) {
        return NSTACKX_EFAILED;
    }

    struct sockaddr_in addr;
    socklen_t len = sizeof(struct sockaddr_in);
    (void)memset_s(&addr, sizeof(addr), 0, sizeof(addr));
    int ret = recvfrom(socketFd, buffer, length, 0, (struct sockaddr *)&addr, &len);
    return ret;
}

static void HandleReadEvent(int32_t fd)
{
    int32_t socketFd = fd;
    uint8_t *recvBuffer = calloc(1, COAP_MAX_PDU_SIZE + 1);
    if (recvBuffer == NULL) {
        return;
    }
    ssize_t nRead;
    nRead = CoapSocketRecv(socketFd, recvBuffer, COAP_MAX_PDU_SIZE);
    if ((nRead == 0) || (nRead < 0 && errno != EAGAIN &&
        errno != EWOULDBLOCK && errno != EINTR)) {
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

static int CoapCreateUdpClient(const struct sockaddr_in *sockAddr)
{
    if (sockAddr == NULL) {
        return NSTACKX_EFAILED;
    }

    struct sockaddr_in tmpAddr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return NSTACKX_EFAILED;
    }

    int ret = connect(sockfd, (struct sockaddr *)sockAddr, sizeof(struct sockaddr));
    if (ret != 0) {
        close(sockfd);
        return NSTACKX_EFAILED;
    }

    socklen_t srcAddrLen = sizeof(struct sockaddr_in);
    (void)memset_s(&tmpAddr, sizeof(tmpAddr), 0, sizeof(tmpAddr));
    ret = getsockname(sockfd, (struct sockaddr *)&tmpAddr, &srcAddrLen);
    if (ret != 0) {
        close(sockfd);
        return NSTACKX_EFAILED;
    }

    return sockfd;
}

static int CoapSocketSend(const SocketInfo *socket, const uint8_t *buffer, size_t length)
{
    if (buffer == NULL || socket == NULL) {
        return NSTACKX_EFAILED;
    }

    socklen_t dstAddrLen = sizeof(struct sockaddr_in);
    int ret = sendto(socket->cliendFd, buffer, length, 0, (struct sockaddr *)&socket->dstAddr, dstAddrLen);
    return ret;
}

static int CoapSendRequest(const CoapRequest *coapRequest)
{
    if (coapRequest == NULL || coapRequest->remoteUrl == NULL) {
        return NSTACKX_EFAILED;
    }

    struct sockaddr_in sockAddr = {0};
    if (coapRequest->remoteIp == NULL) {
        return NSTACKX_EFAILED;
    }

    sockAddr.sin_addr.s_addr = inet_addr(coapRequest->remoteIp);
    sockAddr.sin_port = htons(COAP_SRV_DEFAULT_PORT);
    sockAddr.sin_family = AF_INET;

    int udpClientFd = CoapCreateUdpClient(&sockAddr);
    if (udpClientFd == NSTACKX_EFAILED) {
        return NSTACKX_EFAILED;
    }
    SocketInfo socket = {0};
    socket.cliendFd = udpClientFd;
    socket.dstAddr = sockAddr;
    if (CoapSocketSend(&socket, (uint8_t *)coapRequest->data, coapRequest->dataLength) == -1) {
        LOGE(TAG, "Coap socket send response message failed");
        close(udpClientFd);
        return NSTACKX_EFAILED;
    }
    close(udpClientFd);
    return NSTACKX_EOK;
}

int CoapResponseService(const CoapPacket *pkt, const char *remoteUrl, const char *remoteIp)
{
    int ret;
    CoapRequest coapRequest;
    (void)memset_s(&coapRequest, sizeof(coapRequest), 0, sizeof(coapRequest));
    coapRequest.remoteUrl = remoteUrl;
    coapRequest.remoteIp = remoteIp;
    char *payload = PrepareServiceDiscover(NSTACKX_FALSE);
    if (payload == NULL) {
        return NSTACKX_EFAILED;
    }

    CoapReadWriteBuffer sndPktBuff = {0};
    sndPktBuff.readWriteBuf = calloc(1, COAP_MAX_PDU_SIZE);
    if (sndPktBuff.readWriteBuf == NULL) {
        cJSON_free(payload);
        return NSTACKX_EFAILED;
    }
    sndPktBuff.size = COAP_MAX_PDU_SIZE;
    sndPktBuff.len = 0;

    ret = BuildSendPkt(pkt, remoteIp, payload, &sndPktBuff);
    cJSON_free(payload);
    if (ret != DISCOVERY_ERR_SUCCESS) {
        free(sndPktBuff.readWriteBuf);
        sndPktBuff.readWriteBuf = NULL;
        return ret;
    }
    coapRequest.data = sndPktBuff.readWriteBuf;
    coapRequest.dataLength = sndPktBuff.len;
    ret = CoapSendRequest(&coapRequest);
    free(sndPktBuff.readWriteBuf);
    sndPktBuff.readWriteBuf = NULL;

    return ret;
}

static void DeRegisteCoAPEpollTaskCtx(void)
{
    DeRegisterEpollTask(&g_task);
    CloseDesc(g_task.taskfd);
    g_task.taskfd = -1;
    g_coapListenFd = -1;
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
}

static uint32_t RegisterCoAPEpollTask(EpollDesc epollfd)
{
    if (g_coapListenFd == -1) {
        LOGI(TAG, "g_coapListenFd hasn't initialized.");
        return NSTACKX_FALSE;
    }


    uint32_t events = 0;
    events = EPOLLIN | EPOLLERR;
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
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return NSTACKX_FALSE;
    }

    (void)memset_s(&localAddr, sizeof(localAddr), 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(port);
    localAddr.sin_addr.s_addr = inet_addr(ipAddr);

    if (bind(sockfd, (struct sockaddr *)&localAddr, len) == -1) {
        close(sockfd);
        return NSTACKX_FALSE;
    }

    if (getsockname(sockfd, (struct sockaddr *)&localAddr, &len) == -1) {
        close(sockfd);
        return NSTACKX_FALSE;
    }
    return sockfd;
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
