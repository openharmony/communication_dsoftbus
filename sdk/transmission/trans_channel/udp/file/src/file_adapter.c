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

#include "file_adapter.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <securec.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_tcp_socket.h"

static int SetReuseAddr(int fd, int on)
{
    int rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    if (rc != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set SO_REUSEADDR : %s.", strerror(errno));
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int SetReusePort(int fd, int on)
{
    int rc = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
    if (rc != 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "set SO_REUSEPORT : %s.", strerror(errno));
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int OpenTcpServer(const char *ip, int port)
{
    struct sockaddr_in addr;
    (void)memset_s(&addr, sizeof(addr), 0, sizeof(addr));
    errno = 0;
    int rc = inet_pton(AF_INET, ip, &addr.sin_addr);
    if (rc <= 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "rc=%d:%s", rc, strerror(errno));
        return SOFTBUS_ERR;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    errno = 0;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "%s", strerror(errno));
        return SOFTBUS_ERR;
    }
    (void)SetReuseAddr(fd, 1);
    (void)SetReusePort(fd, 1);
    errno = 0;
    rc = TEMP_FAILURE_RETRY(bind(fd, (struct sockaddr *)&addr, sizeof(addr)));
    if (rc < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "rc=%d:%s", rc, strerror(errno));
        TcpShutDown(fd);
        return SOFTBUS_ERR;
    }
    return fd;
}

int32_t StartNStackXDFileServer(const char *myIP, const uint8_t *key,
    uint32_t keyLen, DFileMsgReceiver msgReceiver, int32_t *filePort)
{
    if (myIP == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int fd = OpenTcpServer(myIP, 0);
    if (fd < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "failed to start tcp server for getting port");
        return SOFTBUS_ERR;
    }
    int port = GetTcpSockPort(fd);
    if (port < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "failed to get port from tcp socket");
        TcpShutDown(fd);
        return SOFTBUS_ERR;
    }
    *filePort = port;
    struct sockaddr_in localAddr;
    (void)memset_s(&localAddr, sizeof(localAddr), 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = port;
    localAddr.sin_addr.s_addr = ntohl(inet_addr(myIP));
    socklen_t addrLen = sizeof(struct sockaddr_in);

    int sessionId = NSTACKX_DFileServer(&localAddr, addrLen, key, keyLen, msgReceiver);
    TcpShutDown(fd);
    if (sessionId < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "failed to start dfile server.");
        return SOFTBUS_ERR;
    }
    return sessionId;
}

int32_t StartNStackXDFileClient(const char *peerIp, int32_t peerPort, const uint8_t *key,
    uint32_t keyLen, DFileMsgReceiver msgReceiver)
{
    if (peerIp == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    struct sockaddr_in localAddr;
    (void)memset_s(&localAddr, sizeof(localAddr), 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = peerPort;
    localAddr.sin_addr.s_addr = ntohl(inet_addr(peerIp));
    socklen_t addrLen = sizeof(struct sockaddr_in);

    int32_t sessionId = NSTACKX_DFileClient(&localAddr, addrLen, key, keyLen, msgReceiver);
    if (sessionId < 0) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "failed to start dfile client");
        return SOFTBUS_ERR;
    }
    return sessionId;
}