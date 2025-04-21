/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "softbus_usb_tcp_socket.h"

#include <securec.h>
#include "conn_log.h"
#include "softbus_adapter_errcode.h"
#include "softbus_conn_common.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"
#include "softbus_tcp_socket.h"
 
#define M_BYTES                     0x100000
#define SEND_BUF_SIZE               (4 * M_BYTES) // 4M
#define RECV_BUF_SIZE               (6 * M_BYTES) // 6M
#define USER_TIMEOUT_MS             (15 * 1000)   // 15s
#define SOFTBUS_TCP_USER_TIME USER_TIMEOUT_MS
#define SOFTBUS_CONN_TCP_USER_TIME  (35 * 1000)   // 35s

static int32_t OpenUsbServerSocket(const LocalListenerInfo *option)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(option != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid param, null option");
    CONN_CHECK_AND_RETURN_RET_LOGW(option->type == CONNECT_TCP, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "invalid param, unsupport type=%{public}d", option->type);
    CONN_CHECK_AND_RETURN_RET_LOGW(option->socketOption.port >= 0, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "invalid param, invalid port=%{public}d", option->socketOption.port);

    int fd;
    int32_t domain = GetDomainByAddr(option->socketOption.addr);
    int ret = SoftBusSocketCreate(
        domain, SOFTBUS_SOCK_STREAM | SOFTBUS_SOCK_CLOEXEC | SOFTBUS_SOCK_NONBLOCK, 0, (int32_t *)&fd);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "Create socket failed! ret=%{public}d", ret);
        return SOFTBUS_TCP_SOCKET_ERR;
    }

    SetServerOption(fd);
    ret = BindLocalIP(domain, fd, option->socketOption.addr, (uint16_t)option->socketOption.port);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "BindLocalIP ret=%{public}d", ret);
        ConnShutdownSocket(fd);
        return SOFTBUS_SOCKET_BIND_ERR;
    }

    BindToInterface(option->socketOption.addr, domain, fd, (char *)(option->socketOption.ifName), IF_NAME_SIZE);
    CONN_LOGI(CONN_COMMON, "server listen tcp socket, fd=%{public}d", fd);
    return fd;
}

static int32_t OpenUsbClientSocket(const ConnectOption *option, const char *myIp, bool isNonBlock)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(option != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid param, null option");
    CONN_CHECK_AND_RETURN_RET_LOGW(option->type == CONNECT_TCP, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "invalid param, unsupport type=%{public}d", option->type);
    CONN_CHECK_AND_RETURN_RET_LOGW(option->socketOption.port > 0, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "invalid param, invalid port=%{public}d", option->socketOption.port);
    CONN_CHECK_AND_RETURN_RET_LOGW(option->socketOption.addr[0] != '\0', SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "invalid param, invalid addr");

    char animizedIp[IP_LEN] = { 0 };
    ConvertAnonymizeIpAddress(animizedIp, IP_LEN, option->socketOption.addr, IP_LEN);

    int32_t fd = -1;
    int32_t domain = GetDomainByAddr(option->socketOption.addr);
    int32_t ret = SoftBusSocketCreate(domain, SOFTBUS_SOCK_STREAM, 0, &fd);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "create socket failed, serverIp=%{public}s, serverPort=%{public}d, error=%{public}d",
            animizedIp, option->socketOption.port, ret);
        return ret;
    }
    if (isNonBlock && ConnToggleNonBlockMode(fd, true) != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "set nonblock failed, serverIp=%{public}s, serverPort=%{public}d, fd=%{public}d",
            animizedIp, option->socketOption.port, fd);
        SoftBusSocketClose(fd);
        return SOFTBUS_TCPCONNECTION_SOCKET_ERR;
    }
    SetClientOption(fd);
    ret = BindTcpClientAddr(domain, fd, myIp);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "bind client address failed, serverIp=%{public}s, serverPort=%{public}d, "
            "error=%{public}d", animizedIp, option->socketOption.port, ret);
        ConnShutdownSocket(fd);
        return ret;
    }

    BindToInterface(myIp, domain, fd, (char *)(option->socketOption.ifName), IF_NAME_SIZE);
    ret = SocketConnect(fd, domain, option);
    if ((ret != SOFTBUS_ADAPTER_OK) && (ret != SOFTBUS_ADAPTER_SOCKET_EINPROGRESS) &&
        (ret != SOFTBUS_ADAPTER_SOCKET_EAGAIN)) {
        CONN_LOGE(CONN_COMMON, "client connect failed, serverIp=%{public}s, serverPort=%{public}d, fd=%{public}d, "
            "ret=%{public}d, errno=%{public}d(%{public}s)", animizedIp, option->socketOption.port, fd, ret,
            errno, strerror(errno));
        ConnShutdownSocket(fd);
        return ret;
    }
    CONN_LOGI(CONN_COMMON, "client open tcp socket, serverIp=%{public}s, serverPort=%{public}d, fd=%{public}d",
        animizedIp, option->socketOption.port, fd);
    return fd;
}

static int32_t AcceptUsbClient(int32_t fd, ConnectOption *clientAddr, int32_t *cfd)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(clientAddr != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "invalid param, clientAddr is null");
    SoftBusSockAddr addr;
    (void)memset_s(&addr, sizeof(addr), 0, sizeof(addr));
    int32_t ret = SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketAccept(fd, &addr, cfd));
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "accept failed, ret=%{public}" PRId32 ", cfd=%{public}d, fd=%{public}d", ret, *cfd, fd);
        return ret;
    }

    clientAddr->type = CONNECT_TCP;
    clientAddr->socketOption.port = GetTcpSockPort(*cfd);
    clientAddr->socketOption.protocol = LNN_PROTOCOL_USB;

    if (SoftBusInetNtoP(SOFTBUS_AF_INET6, &((SoftBusSockAddrIn6 *)&addr)->sin6Addr,
        clientAddr->socketOption.addr, sizeof(clientAddr->socketOption.addr)) == NULL) {
        CONN_LOGE(CONN_COMMON, "get addr failed");
        return SOFTBUS_TCPCONNECTION_SOCKET_ERR;
    }
    return SOFTBUS_OK;
}

const SocketInterface *GetUsbProtocol(void)
{
    static SocketInterface usbTcpSocketIntf = {
        .name = "USB_TCP",
        .type = LNN_PROTOCOL_USB,
        .GetSockPort = GetTcpSockPort,
        .OpenClientSocket = OpenUsbClientSocket,
        .OpenServerSocket = OpenUsbServerSocket,
        .AcceptClient = AcceptUsbClient,
    };
    return &usbTcpSocketIntf;
}