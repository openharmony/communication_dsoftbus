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

#include <securec.h>
#include <unistd.h>

#include "softbus_adapter_errcode.h"
#include "softbus_adapter_socket.h"
#include "softbus_errcode.h"
#include "softbus_socket.h"
#include "trans_log.h"

static int SetReuseAddr(int fd, int on)
{
    int rc = SoftBusSocketSetOpt(fd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEADDR, &on, sizeof(on));
    if (rc != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "set SO_REUSEADDR error. fd=%{public}d", fd);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int SetReusePort(int fd, int on)
{
    int rc = SoftBusSocketSetOpt(fd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_REUSEPORT, &on, sizeof(on));
    if (rc != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "set SO_REUSEPORT error. fd=%{public}d", fd);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int OpenTcpServer(const char *ip, int port)
{
    SoftBusSockAddrIn addr;
    (void)memset_s(&addr, sizeof(addr), 0, sizeof(addr));
    int rc = SoftBusInetPtoN(SOFTBUS_AF_INET, ip, &addr.sinAddr);
    if (rc != SOFTBUS_ADAPTER_OK) {
        TRANS_LOGE(TRANS_FILE, "rc=%{public}d", rc);
        return SOFTBUS_ERR;
    }
    addr.sinFamily = SOFTBUS_AF_INET;
    addr.sinPort = SoftBusHtoNs(port);
    int fd;
    int ret = SoftBusSocketCreate(SOFTBUS_AF_INET, SOFTBUS_SOCK_STREAM | SOFTBUS_SOCK_NONBLOCK |
        SOFTBUS_SOCK_CLOEXEC, 0, &fd);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_FILE, "OpenTcpServer Create error, ret=%{public}d.", ret);
        return SOFTBUS_ERR;
    }

    (void)SetReuseAddr(fd, 1);
    (void)SetReusePort(fd, 1);
    rc = SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketBind(fd, (SoftBusSockAddr *)&addr, sizeof(addr)));
    if (rc != SOFTBUS_ADAPTER_OK) {
        TRANS_LOGE(TRANS_FILE, "OpenTcpServer Bind error, rc=%{public}d.", rc);
        ConnShutdownSocket(fd);
        return SOFTBUS_ERR;
    }
    return fd;
}

int32_t StartNStackXDFileServer(const char *myIp, const uint8_t *key,
    uint32_t keyLen, DFileMsgReceiver msgReceiver, int32_t *filePort)
{
    if (myIp == NULL || filePort == NULL) {
        TRANS_LOGW(TRANS_FILE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int fd = OpenTcpServer(myIp, 0);
    if (fd < 0) {
        TRANS_LOGE(TRANS_FILE, "failed to start tcp server for getting port");
        return SOFTBUS_ERR;
    }
    const SocketInterface *ip = GetSocketInterface(LNN_PROTOCOL_IP);
    if (ip == NULL) {
        TRANS_LOGE(TRANS_FILE, "no ip supportted");
        ConnShutdownSocket(fd);
        return SOFTBUS_NOT_FIND;
    }
    int port = ip->GetSockPort(fd);
    if (port < 0) {
        TRANS_LOGE(TRANS_FILE, "failed to get port from tcp socket");
        ConnShutdownSocket(fd);
        return SOFTBUS_ERR;
    }
    *filePort = port;
    struct sockaddr_in localAddr;
    (void)memset_s(&localAddr, sizeof(localAddr), 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = (uint16_t)port;
    localAddr.sin_addr.s_addr = SoftBusNtoHl(SoftBusInetAddr(myIp));
    socklen_t addrLen = sizeof(struct sockaddr_in);

    int sessionId = NSTACKX_DFileServer(&localAddr, addrLen, key, keyLen, msgReceiver);
    ConnShutdownSocket(fd);
    if (sessionId < 0) {
        TRANS_LOGE(TRANS_FILE, "failed to start dfile server.");
        return SOFTBUS_ERR;
    }
    return sessionId;
}

int32_t StartNStackXDFileClient(const char *peerIp, int32_t peerPort, const uint8_t *key,
    uint32_t keyLen, DFileMsgReceiver msgReceiver)
{
    if (peerIp == NULL) {
        TRANS_LOGW(TRANS_FILE, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    struct sockaddr_in localAddr;
    (void)memset_s(&localAddr, sizeof(localAddr), 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = (uint16_t)peerPort;
    localAddr.sin_addr.s_addr = SoftBusNtoHl(SoftBusInetAddr(peerIp));
    socklen_t addrLen = sizeof(struct sockaddr_in);

    int32_t sessionId = NSTACKX_DFileClient(&localAddr, addrLen, key, keyLen, msgReceiver);
    if (sessionId < 0) {
        TRANS_LOGE(TRANS_FILE, "failed to start dfile client");
        return SOFTBUS_ERR;
    }
    return sessionId;
}
