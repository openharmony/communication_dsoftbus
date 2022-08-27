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

#include "nstackx_socket.h"
#include "nstackx_log.h"
#include "nstackx_error.h"
#include "nstackx_util.h"
#include "nstackx_dev.h"
#include "locale.h"
#include "securec.h"

#define NSTACKX_MAX_LISTEN_NUMBER 3
#define NSTACKX_TCP_SOCKET_BUFFER_SIZE (1 * 1024 * 1024)

#define TAG "nStackXSocket"

void CloseSocket(Socket *socket)
{
    if (socket == NULL) {
        return;
    }
    CloseSocketInner(socket->sockfd);
    socket->sockfd = INVALID_SOCKET;
    free(socket);
}

static void GetTcpSocketBufSize(SocketDesc fd)
{
    int32_t ret;
    int32_t bufSize;
    socklen_t optLen = sizeof(bufSize);

    ret = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufSize, &optLen);
    if (ret < 0) {
        LOGE(TAG, "getsockopt SO_SNDBUF failed");
        return;
    }
    LOGD(TAG, "SO_SNDBUF = %d", bufSize);

    ret = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufSize, &optLen);
    if (ret < 0) {
        LOGE(TAG, "getsockopt SO_RCVBUF failed");
        return;
    }
    LOGD(TAG, "SO_RCVBUF = %d", bufSize);
}

static int32_t SetTcpSocketBufSize(SocketDesc fd, int32_t bufSize)
{
    int32_t ret;
    socklen_t optLen = sizeof(bufSize);

    if (bufSize < 0) {
        return NSTACKX_EFAILED;
    }

    GetTcpSocketBufSize(fd);
    ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufSize, optLen);
    if (ret < 0) {
        LOGE(TAG, "setsockopt SO_SNDBUF failed");
        return NSTACKX_EFAILED;
    }
    LOGD(TAG, "setsockopt SO_SNDBUF = %d", bufSize);

    ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufSize, optLen);
    if (ret < 0) {
        LOGE(TAG, "setsockopt SO_RCVBUF failed");
        return NSTACKX_EFAILED;
    }
    LOGD(TAG, "setsockopt SO_RCVBUF = %d", bufSize);
    GetTcpSocketBufSize(fd);
    return NSTACKX_EOK;
}

static int32_t ConnectTcpServerWithTargetDev(Socket *clientSocket, const struct sockaddr_in *sockAddr,
                                             const char *localInterface)
{
    socklen_t addrLen = sizeof(struct sockaddr_in);

    clientSocket->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket->sockfd == INVALID_SOCKET) {
        LOGE(TAG, "socket create failed, error :%d", GetErrno());
        return NSTACKX_EFAILED;
    }
    if (SetTcpSocketBufSize(clientSocket->sockfd, NSTACKX_TCP_SOCKET_BUFFER_SIZE) != NSTACKX_EOK) {
        LOGE(TAG, "set socket buf failed");
    }
    if (SetSocketNonBlock(clientSocket->sockfd) != NSTACKX_EOK) {
        LOGE(TAG, "set socket nonblock failed");
    }
    if (localInterface == NULL) {
        BindToDevInTheSameLan(clientSocket->sockfd, sockAddr);
    } else {
        LOGI(TAG, "bind to target interface %s", localInterface);
        if (BindToTargetDev(clientSocket->sockfd, localInterface) != NSTACKX_EOK) {
            LOGE(TAG, "can't bind to target interface %s", localInterface);
        } else {
            LOGI(TAG, "bind to target interface %s successfully", localInterface);
        }
    }
    int32_t ret = connect(clientSocket->sockfd, (struct sockaddr *)sockAddr, addrLen);
    if (ret != 0) {
        if (!SocketOpInProgress()) {
            LOGE(TAG, "connect error, %d", GetErrno());
            goto FAIL_SOCKET;
        }
    }
    LOGI(TAG, "connect success");

    clientSocket->dstAddr = *sockAddr;
    return NSTACKX_EOK;

FAIL_SOCKET:
    CloseSocketInner(clientSocket->sockfd);
    clientSocket->sockfd = INVALID_SOCKET;
    return NSTACKX_EFAILED;
}

static int32_t ConnectUdpServerWithTargetDev(Socket *clientSocket, const struct sockaddr_in *sockAddr,
                                             const char *localInterface)
{
    int32_t ret = 0;
    struct sockaddr_in tmpAddr;
    socklen_t srcAddrLen = sizeof(struct sockaddr_in);
    clientSocket->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (clientSocket->sockfd == INVALID_SOCKET) {
        LOGE(TAG, "socket create failed, error :%d", GetErrno());
        return NSTACKX_EFAILED;
    }
    if (SetSocketNonBlock(clientSocket->sockfd) != NSTACKX_EOK) {
        LOGE(TAG, "set socket nonblock failed");
        goto FAIL_SOCKET;
    }

    if (localInterface == NULL) {
        BindToDevInTheSameLan(clientSocket->sockfd, sockAddr);
    } else {
        if (BindToTargetDev(clientSocket->sockfd, localInterface) != NSTACKX_EOK) {
            LOGE(TAG, "can't bind to target interface %s", localInterface);
        } else {
            LOGI(TAG, "bind to target interface %s successfully", localInterface);
        }
    }
    ret = connect(clientSocket->sockfd, (struct sockaddr *)sockAddr, sizeof(struct sockaddr));
    if (ret != 0) {
        LOGE(TAG, "connect to udp server failed %d", GetErrno());
        goto FAIL_SOCKET;
    }

    (void)memset_s(&tmpAddr, sizeof(tmpAddr), 0, sizeof(tmpAddr));
    ret = getsockname(clientSocket->sockfd, (struct sockaddr *)&tmpAddr, &srcAddrLen);
    if (ret != 0) {
        LOGE(TAG, "getsockname failed %d", GetErrno());
        goto FAIL_SOCKET;
    }
    clientSocket->dstAddr = *sockAddr;
    clientSocket->srcAddr = tmpAddr;
    return NSTACKX_EOK;
FAIL_SOCKET:
    CloseSocketInner(clientSocket->sockfd);
    clientSocket->sockfd = INVALID_SOCKET;
    return NSTACKX_EFAILED;
}

static int32_t CreateTcpServer(Socket *serverSocket, const struct sockaddr_in *sockAddr)
{
    int32_t reuse = 1;
    struct sockaddr_in localAddr;
    socklen_t len = sizeof(localAddr);

    serverSocket->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket->sockfd == INVALID_SOCKET) {
        LOGE(TAG, "create socket failed, error :%d", GetErrno());
        return NSTACKX_EFAILED;
    }
    if (SetSocketNonBlock(serverSocket->sockfd) != NSTACKX_EOK) {
        LOGE(TAG, "set socket nonblock failed");
        goto FAIL_SOCKET;
    }

    if (setsockopt(serverSocket->sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0) {
        LOGE(TAG, "Failed to set server socket! error :%d", GetErrno());
        goto FAIL_SOCKET;
    }

    (void)memset_s(&localAddr, sizeof(localAddr), 0, sizeof(localAddr));
    /* Bind to ANY source ip address and random port number */
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = sockAddr->sin_port;
    if (sockAddr->sin_addr.s_addr != 0) {
        localAddr.sin_addr.s_addr = sockAddr->sin_addr.s_addr;
    } else {
        localAddr.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(serverSocket->sockfd, (struct sockaddr *)&localAddr, len) != 0) {
        LOGE(TAG, "Failed to bind socket error :%d", GetErrno());
        goto FAIL_SOCKET;
    }

    if (sockAddr->sin_addr.s_addr != 0 &&
        BindToDevice(serverSocket->sockfd, sockAddr) != NSTACKX_EOK) {
        LOGE(TAG, "Failed to bind socket to device");
    }

    if (getsockname(serverSocket->sockfd, (struct sockaddr *)&(serverSocket->srcAddr), &len) != 0) {
        LOGE(TAG, "Failed to get socket name! error :%d", GetErrno());
        goto FAIL_SOCKET;
    }

    if (listen(serverSocket->sockfd, NSTACKX_MAX_LISTEN_NUMBER) != 0) {
        LOGE(TAG, "Failed to listen TCP port! error :%d", GetErrno());
        goto FAIL_SOCKET;
    }

    /* Note: Here we rely on that an accepted socket will inherit SO_SNDBUF and SO_RCVBUF
        options from the listening socket. */
    if (SetTcpSocketBufSize(serverSocket->sockfd, NSTACKX_TCP_SOCKET_BUFFER_SIZE) != NSTACKX_EOK) {
        LOGE(TAG, "Failed to set socket buff size:%u", NSTACKX_TCP_SOCKET_BUFFER_SIZE);
    }

    return NSTACKX_EOK;
FAIL_SOCKET:
    CloseSocketInner(serverSocket->sockfd);
    serverSocket->sockfd = INVALID_SOCKET;
    return NSTACKX_EFAILED;
}

static int32_t CreateUdpServer(Socket *serverSocket, const struct sockaddr_in *sockAddr)
{
    if (sockAddr == NULL) {
        LOGE(TAG, "sockAddr is null");
        return NSTACKX_EFAILED;
    }
    struct sockaddr_in localAddr;
    socklen_t len = sizeof(localAddr);
    serverSocket->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (serverSocket->sockfd == INVALID_SOCKET) {
        LOGE(TAG, "create socket failed, error :%d", GetErrno());
        return NSTACKX_EFAILED;
    }

    if (SetSocketNonBlock(serverSocket->sockfd) != NSTACKX_EOK) {
        LOGE(TAG, "set socket nonblock failed");
        goto FAIL_SOCKET;
    }

    (void)memset_s(&localAddr, sizeof(localAddr), 0, sizeof(localAddr));
    /* Bind to ANY source ip address and random port number */
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = sockAddr->sin_port;
    if (sockAddr->sin_addr.s_addr != 0) {
        localAddr.sin_addr.s_addr = sockAddr->sin_addr.s_addr;
    } else {
        localAddr.sin_addr.s_addr = INADDR_ANY;
    }
    if (bind(serverSocket->sockfd, (struct sockaddr *)&localAddr, len) != 0) {
        LOGE(TAG, "Failed to bind socket, error :%d", GetErrno());
        goto FAIL_SOCKET;
    }

    if (sockAddr->sin_addr.s_addr != 0 &&
        BindToDevice(serverSocket->sockfd, sockAddr) != NSTACKX_EOK) {
        LOGE(TAG, "Failed to bind socket to device");
    }

    if (getsockname(serverSocket->sockfd, (struct sockaddr *)(&serverSocket->srcAddr), &len) != 0) {
        LOGE(TAG, "Failed to get socket name! error :%d", GetErrno());
        goto FAIL_SOCKET;
    }

    return NSTACKX_EOK;
FAIL_SOCKET:
    CloseSocketInner(serverSocket->sockfd);
    serverSocket->sockfd = INVALID_SOCKET;
    return NSTACKX_EFAILED;
}

Socket *ClientSocketWithTargetDev(SocketProtocol protocol, const struct sockaddr_in *sockAddr,
                                  const char *localInterface)
{
    int32_t ret;
    if (sockAddr == NULL) {
        return NULL;
    }
    Socket *socket = calloc(1, sizeof(Socket));
    if (socket == NULL) {
        LOGE(TAG, "malloc Socket failed\n");
        return NULL;
    }

    switch (protocol) {
        case NSTACKX_PROTOCOL_TCP:
            socket->protocol = NSTACKX_PROTOCOL_TCP;
            ret = ConnectTcpServerWithTargetDev(socket, sockAddr, localInterface);
            break;
        case NSTACKX_PROTOCOL_UDP:
            socket->protocol = NSTACKX_PROTOCOL_UDP;
            ret = ConnectUdpServerWithTargetDev(socket, sockAddr, localInterface);
            break;
        case NSTACKX_PROTOCOL_D2D:
            LOGE(TAG, "d2d not support");
            ret = NSTACKX_EFAILED;
            break;
        default:
            LOGE(TAG, "protocol not support");
            ret = NSTACKX_EFAILED;
            break;
    }

    if (ret != NSTACKX_EOK) {
        LOGE(TAG, "Create client socket failed! %d", ret);
        free(socket);
        return NULL;
    }
    socket->isServer = NSTACKX_FALSE;
    return socket;
}

Socket *ClientSocket(SocketProtocol protocol, const struct sockaddr_in *sockAddr)
{
    return ClientSocketWithTargetDev(protocol, sockAddr, NULL);
}

Socket *ServerSocket(SocketProtocol protocol, const struct sockaddr_in *sockAddr)
{
    int32_t ret;
    if (sockAddr == NULL) {
        return NULL;
    }
    Socket *socket = calloc(1, sizeof(Socket));
    if (socket == NULL) {
        LOGE(TAG, "malloc Socket failed\n");
        return NULL;
    }

    switch (protocol) {
        case NSTACKX_PROTOCOL_TCP:
            socket->protocol = NSTACKX_PROTOCOL_TCP;
            ret = CreateTcpServer(socket, sockAddr);
            break;
        case NSTACKX_PROTOCOL_UDP:
            socket->protocol = NSTACKX_PROTOCOL_UDP;
            ret = CreateUdpServer(socket, sockAddr);
            break;
        case NSTACKX_PROTOCOL_D2D:
            socket->protocol = NSTACKX_PROTOCOL_D2D;
            ret = NSTACKX_EFAILED;
            LOGE(TAG, "d2d not support");
            break;
        default:
            LOGE(TAG, "protocol not support");
            ret = NSTACKX_EFAILED;
            break;
    }

    if (ret != NSTACKX_EOK) {
        LOGE(TAG, "Create server socket failed! %d", ret);
        free(socket);
        return NULL;
    }
    socket->isServer = NSTACKX_TRUE;
    return socket;
}

static int32_t CheckAcceptSocketValid(const Socket *serverSocket)
{
    if (serverSocket == NULL || serverSocket->isServer == NSTACKX_FALSE ||
        serverSocket->protocol != NSTACKX_PROTOCOL_TCP) {
        LOGE(TAG, "invalue Socket for accept");
        return NSTACKX_EINVAL;
    }
    return NSTACKX_EOK;
}

static int32_t SetAcceptSocket(SocketDesc acceptFd)
{
    struct sockaddr_in localAddr;
    socklen_t localAddrLen = sizeof(localAddr);
    (void)memset_s(&localAddr, localAddrLen, 0, localAddrLen);
    if (getsockname(acceptFd, (struct sockaddr *)&localAddr, &localAddrLen) != 0) {
        LOGE(TAG, "get socket name fail %d", GetErrno());
        return NSTACKX_EFAILED;
    }
    /* It will always failed on devices without system authority, such as third-party devices. */
    if (BindToDevice(acceptFd, &localAddr) != NSTACKX_EOK) {
        LOGW(TAG, "Accept client bind to device failed");
    }

    if (SetSocketNonBlock(acceptFd) != NSTACKX_EOK) {
        LOGE(TAG, "set socket nonblock failed");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

Socket *AcceptSocket(Socket *serverSocket)
{
    struct sockaddr_in clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
    (void)memset_s(&clientAddr, addrLen, 0, addrLen);

    if (CheckAcceptSocketValid(serverSocket) != NSTACKX_EOK) {
        LOGE(TAG, "invalue Socket for accept \n");
        return NULL;
    }

    Socket *clientSocket = calloc(1, sizeof(Socket));
    if (clientSocket == NULL) {
        LOGE(TAG, "client socket malloc failed\n");
        return NULL;
    }
    clientSocket->protocol = NSTACKX_PROTOCOL_TCP;
    clientSocket->isServer = NSTACKX_FALSE;
    clientSocket->sockfd = accept(serverSocket->sockfd, (struct sockaddr *)&clientAddr, &addrLen);
    if (clientSocket->sockfd == INVALID_SOCKET) {
        LOGE(TAG, "accept return error: %d", GetErrno());
        goto L_SOCKET_FAIL;
    }

    if (SetAcceptSocket(clientSocket->sockfd) != NSTACKX_EOK) {
        LOGE(TAG, "set accept socket failed");
        goto L_SOCKET_FAIL;
    }

    clientSocket->dstAddr = clientAddr;

    return clientSocket;
L_SOCKET_FAIL:
    if (clientSocket->sockfd != INVALID_SOCKET) {
        CloseSocketInner(clientSocket->sockfd);
        clientSocket->sockfd = INVALID_SOCKET;
    }
    free(clientSocket);
    return NULL;
}

int32_t CheckSocketError(void)
{
    int32_t ret;
    if (SocketOpWouldBlock()) {
        ret = NSTACKX_EAGAIN;
    } else {
        LOGE(TAG, "sendto/recvfrom error: %d", GetErrno());
        ret = NSTACKX_EFAILED;
    }
    return ret;
}

static int32_t SocketSendUdp(const Socket *socket, const uint8_t *buffer, size_t length)
{
    socklen_t dstAddrLen = sizeof(struct sockaddr_in);

    int32_t ret = (int32_t)sendto(socket->sockfd, buffer, length, 0, (struct sockaddr *)&socket->dstAddr, dstAddrLen);
    if (ret <= 0) {
        ret = CheckSocketError();
    }
    return ret;
}

int32_t SocketSend(const Socket *socket, const uint8_t *buffer, size_t length)
{
    int32_t ret = NSTACKX_EFAILED;

    if (socket == NULL || buffer == NULL) {
        LOGE(TAG, "invalue socket input");
        return ret;
    }

    if (socket->protocol == NSTACKX_PROTOCOL_TCP) {
        ret = (int32_t)send(socket->sockfd, buffer, length, 0);
    } else if (socket->protocol == NSTACKX_PROTOCOL_UDP) {
        ret = SocketSendUdp(socket, buffer, length);
    } else {
        LOGE(TAG, "protocol not support %d", socket->protocol);
    }

    return ret;
}

static int32_t SocketRecvTcp(const Socket *socket, uint8_t *buffer, size_t length, struct sockaddr_in *srcAddr,
                             const socklen_t *addrLen)
{
    int32_t ret = (int32_t)recv(socket->sockfd, buffer, length, 0);
    if (srcAddr != NULL && *addrLen >= (socklen_t)sizeof(struct sockaddr_in)) {
        *srcAddr = socket->dstAddr;
    }
    return ret;
}

static int32_t SocketRecvUdp(const Socket *socket, uint8_t *buffer, size_t length, struct sockaddr_in *srcAddr,
                             const socklen_t *addrLen)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(struct sockaddr_in);
    (void)memset_s(&addr, sizeof(addr), 0, sizeof(addr));
    int32_t ret = (int32_t)recvfrom(socket->sockfd, buffer, length, 0, (struct sockaddr *)&addr, &len);
    if (ret < 0) {
        ret = CheckSocketError();
    } else if (ret == 0 || addr.sin_port == 0 || addr.sin_family != AF_INET) {
        ret = NSTACKX_EAGAIN;
    } else {
        if (srcAddr != NULL && *addrLen >= (socklen_t)sizeof(struct sockaddr_in)) {
            *srcAddr = addr;
        }
    }
    return ret;
}

int32_t SocketRecv(Socket *socket, uint8_t *buffer, size_t length, struct sockaddr_in *srcAddr,
                   const socklen_t *addrLen)
{
    int32_t ret = NSTACKX_EFAILED;

    if (socket == NULL) {
        LOGE(TAG, "invalue socket input");
        return ret;
    }

    if (socket->protocol == NSTACKX_PROTOCOL_TCP) {
        ret = SocketRecvTcp(socket, buffer, length, srcAddr, addrLen);
    } else if (socket->protocol == NSTACKX_PROTOCOL_UDP) {
        ret = SocketRecvUdp(socket, buffer, length, srcAddr, addrLen);
    } else {
        LOGE(TAG, "protocol not support %d", socket->protocol);
    }

    return ret;
}
