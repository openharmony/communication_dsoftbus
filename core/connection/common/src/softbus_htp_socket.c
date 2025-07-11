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

#include "softbus_htp_socket.h"

#include <ctype.h>
#include <securec.h>

#include "anonymizer.h"
#include "conn_log.h"
#include "softbus_conn_common.h"
#include "softbus_socket.h"
#include "softbus_tcp_socket.h"
#include "wifi_direct_defines_struct.h"

#define IPPROTO_HTP        201
#define HTP_ADDR_TYPE_MAC  0
#define HTP_ADDR_TYPE_IPV4 1
#define HTP_ADDR_TYPE_IPV6 2

static int32_t MacToHtpAddr(const char *mac, SoftBusSockAddrHtp *addr, uint16_t port)
{
    if (mac == NULL || addr == NULL) {
        CONN_LOGE(CONN_COMMON, "invalid param, mac or addr is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    if (sscanf_s(mac, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &addr->mac.addr[0], &addr->mac.addr[1],
        &addr->mac.addr[2], &addr->mac.addr[3], &addr->mac.addr[4], &addr->mac.addr[5]) != MAC_ADDR_ARRAY_SIZE) {
        return SOFTBUS_TRANS_SCAN_MAC_NUMBER_FAILED;
    }
    addr->sa_family = SOFTBUS_AF_INET;
    addr->type = HTP_ADDR_TYPE_MAC;
    addr->port = SoftBusHtoNs(port);
    return SOFTBUS_OK;
}

static int32_t HtpConnect(int32_t fd, const char *mac, uint16_t port)
{
    SoftBusSockAddrHtp htpAddr;
    int32_t ret = MacToHtpAddr(mac, &htpAddr, port);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "convert mac to htp address failed, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_TEMP_FAILURE_RETRY(
        SoftBusSocketConnect(fd, (SoftBusSockAddr *)&htpAddr, sizeof(SoftBusSockAddrHtp)));
}

static int32_t BindLocalMac(int32_t fd, const char *mac, uint16_t port)
{
    SoftBusSockAddrHtp htpAddr;
    int32_t ret = MacToHtpAddr(mac, &htpAddr, port);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "convert mac to htp address failed, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketBind(fd, (SoftBusSockAddr *)&htpAddr, sizeof(SoftBusSockAddrHtp)));
}

static int32_t GetHtpSockPort(int32_t fd)
{
    SoftBusSockAddr addr;
    int32_t rc = SoftBusSocketGetLocalName(fd, &addr);
    if (rc != SOFTBUS_ADAPTER_OK) {
        CONN_LOGE(CONN_COMMON, "get mintp sock port failed. rc=%{public}d, fd=%{public}d", rc, fd);
        return rc;
    }
    if (addr.saFamily == SOFTBUS_AF_INET6) {
        return SoftBusNtoHs(((SoftBusSockAddrIn6 *)&addr)->sin6Port);
    }
    return SoftBusNtoHs(((SoftBusSockAddrIn *)&addr)->sinPort);
}

static int32_t OpenHtpClientSocket(const ConnectOption *option, const char *myIp, bool isNonBlock)
{
    (void)myIp;
    CONN_CHECK_AND_RETURN_RET_LOGE(
        option != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid param, option is null.");
    CONN_CHECK_AND_RETURN_RET_LOGE(option->type == CONNECT_HML, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "invalid param, unsupported connect type, type=%{public}d.", option->type);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        option->socketOption.port > 0, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid param, port is invalid.");
    CONN_CHECK_AND_RETURN_RET_LOGE(
        option->socketOption.addr[0] != '\0', SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid param, addr is invalid.");

    char animizedMac[MAC_MAX_LEN] = { 0 };
    ConvertAnonymizeIpAddress(
        animizedMac, MAC_MAX_LEN, option->socketOption.remoteMac, strlen(option->socketOption.remoteMac));
    CONN_LOGI(CONN_COMMON, "open htp client socket, server mac=%{public}s, server port=%{public}d.",
        AnonymizeWrapper(animizedMac), option->socketOption.port);

    int32_t domain = GetDomainByAddr(option->socketOption.addr);
    int32_t fd = -1;
    int32_t ret = SoftBusSocketCreate(domain, SOFTBUS_SOCK_DGRAM, IPPROTO_HTP, &fd);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "create htp socket failed. serverMac=%{public}s, serverPort=%{public}d, ret=%{public}d",
            AnonymizeWrapper(animizedMac), option->socketOption.port, ret);
        return ret;
    }
    if (isNonBlock && ConnToggleNonBlockMode(fd, true) != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "set nonblock mode failed. serverMac=%{public}s, serverPort=%{public}d",
            AnonymizeWrapper(animizedMac), option->socketOption.port);
        ConnShutdownSocket(fd);
        return SOFTBUS_SOCKET_ERR;
    }
    SetClientOption(fd);
    ret = BindLocalMac(fd, option->socketOption.localMac, 0);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "bind client address failed. ret=%{public}d", ret);
        ConnShutdownSocket(fd);
        return ret;
    }

    ret = HtpConnect(fd, option->socketOption.remoteMac, option->socketOption.port);
    if ((ret != SOFTBUS_ADAPTER_OK) && (ret != SOFTBUS_ADAPTER_SOCKET_EINPROGRESS) &&
        (ret != SOFTBUS_ADAPTER_SOCKET_EAGAIN)) {
        CONN_LOGE(CONN_COMMON, "connect htp failed. serverMac=%{public}s, serverPort=%{public}d, ret=%{public}d",
            AnonymizeWrapper(animizedMac), option->socketOption.port, ret);
        ConnShutdownSocket(fd);
        return SOFTBUS_SOCKET_ERR;
    }
    CONN_LOGI(CONN_COMMON, "htp connect success, fd=%{public}d, serverMac=%{public}s, serverPort=%{public}d.", fd,
        AnonymizeWrapper(animizedMac), option->socketOption.port);
    return fd;
}

static int32_t OpenHtpServerSocket(const LocalListenerInfo *option)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(
        option != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid param, option is null.");
    CONN_CHECK_AND_RETURN_RET_LOGE(
        option->type == CONNECT_HML, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid connect type.");
    CONN_CHECK_AND_RETURN_RET_LOGE(option->socketOption.port >= 0, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid port.");

    char animizedMac[MAC_MAX_LEN] = { 0 };
    ConvertAnonymizeIpAddress(
        animizedMac, MAC_MAX_LEN, option->socketOption.remoteMac, strlen(option->socketOption.remoteMac));
    CONN_LOGI(CONN_COMMON, "open htp server socket, mac=%{public}s, port=%{public}d.", AnonymizeWrapper(animizedMac),
        option->socketOption.port);

    int32_t fd = -1;
    int32_t domain = GetDomainByAddr(option->socketOption.addr);
    int32_t ret = SoftBusSocketCreate(
        domain, SOFTBUS_SOCK_DGRAM | SOFTBUS_SOCK_CLOEXEC | SOFTBUS_SOCK_NONBLOCK, IPPROTO_HTP, &fd);
    if (ret != SOFTBUS_ADAPTER_OK) {
        CONN_LOGE(CONN_COMMON, "create htp socket failed. ret=%{public}d", ret);
        return ret;
    }
    SetServerOption(fd);
    ret = BindLocalMac(fd, option->socketOption.localMac, 0);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "bind client address failed. ret=%{public}d", ret);
        ConnShutdownSocket(fd);
        return ret;
    }
    CONN_LOGI(CONN_COMMON, "open htp server socket success, fd=%{public}d.", fd);
    return fd;
}

static int32_t AcceptHtpClient(int32_t fd, ConnectOption *clientAddr, int32_t *cfd)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(
        clientAddr != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid param, clientAddr is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(cfd != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid param, cfd is null");
    SoftBusSockAddr addr;
    (void)memset_s(&addr, sizeof(addr), 0, sizeof(addr));
    int32_t ret = SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketAccept(fd, &addr, cfd));
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "htp accept failed. ret=%{public}d", ret);
        return ret;
    }
    clientAddr->type = CONNECT_HML;
    clientAddr->socketOption.port = ((SoftBusSockAddrHtp *)&addr)->port;
    clientAddr->socketOption.protocol = LNN_PROTOCOL_HTP;
    unsigned char *mac_addr = ((SoftBusSockAddrHtp *)&addr)->mac.addr;
    ret = snprintf_s(clientAddr->socketOption.addr, sizeof(clientAddr->socketOption.addr), MAC_MAX_LEN,
        "%02X:%02X:%02X:%02X:%02X:%02X", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
    if (ret < 0 || ret >= MAC_MAX_LEN) {
        CONN_LOGE(CONN_COMMON, "snprintf_s failed. ret=%{public}d", ret);
        return SOFTBUS_STRCPY_ERR;
    }
    for (int32_t i = 0; i < strlen(clientAddr->socketOption.addr); i++) {
        if (isalpha(clientAddr->socketOption.addr[i])) {
            clientAddr->socketOption.addr[i] = tolower(clientAddr->socketOption.addr[i]);
        }
    }
    return SOFTBUS_OK;
}

const SocketInterface *GetHtpProtocol(void)
{
    static SocketInterface HtpSocketIntf = {
        .name = "HTP",
        .type = LNN_PROTOCOL_HTP,
        .GetSockPort = GetHtpSockPort,
        .OpenServerSocket = OpenHtpServerSocket,
        .OpenClientSocket = OpenHtpClientSocket,
        .AcceptClient = AcceptHtpClient,
    };
    return &HtpSocketIntf;
}