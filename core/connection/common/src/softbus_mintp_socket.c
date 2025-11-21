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

#include "softbus_mintp_socket.h"

#include "conn_log.h"
#include "softbus_adapter_errcode.h"
#include "softbus_conn_common.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"
#include "softbus_tcp_socket.h"
#include "softbus_utils.h"

#define IPPROTO_MINTP       200
#define SOL_MTP             300
#define MTP_ADDR_TYPE_MAC   0
#define MTP_ADDR_TYPE_IPV4  1
#define MTP_ADDR_TYPE_IPV6  2
#define MTP_SOCKET_MSG_SIZE 8000
#define MTP_TOS             1
#define MTP_KEEPIDLE        2
#define MTP_MAX_MSG_SIZE    3
#define MTP_TRANS_TYPE      10
#define MTP_TIME_SYNC       11
#define USER_TIMEOUT_MS     (15 * 1000) // 15s
#define MINTP_TRANS_TYPE    0
#define DETTP_TRANS_TYPE    1

struct MtpMacAddr {
    unsigned char addr[6];
    unsigned char pad[6]; // the inet framework need size of addr >= 16
};

struct MtpIpAddr {
    unsigned char addr;
    unsigned char pad[8]; // the inet framework need size of addr >= 16
};

struct MtpIp6Addr {
    unsigned int flowinfo;  // IPv6 flow information
    unsigned char addr[16]; // IPv6 address
    unsigned int scope;     // IPv6 address scope
};

struct SockAddrMtp {
    unsigned short saFamily;
    unsigned char port;
    unsigned char type;
    union {
        struct MtpMacAddr mac;
        struct MtpIpAddr ip;
        struct MtpIp6Addr ip6;
    };
};

int32_t SetMintpSocketMsgSize(int32_t fd)
{
    int32_t msgSize = MTP_SOCKET_MSG_SIZE;
    int32_t rc = SoftBusSocketSetOpt(fd, SOL_MTP, MTP_MAX_MSG_SIZE, &msgSize, sizeof(msgSize));
    if (rc != SOFTBUS_ADAPTER_OK) {
        CONN_LOGE(CONN_COMMON, "set MTP_MAX_MSG_SIZE fail. rc=%{public}d, errno=%{public}d", rc, errno);
        return rc;
    }
    return SOFTBUS_OK;
}

int32_t SetMintpSocketTos(int32_t fd, uint32_t tos)
{
    int32_t rc = SoftBusSocketSetOpt(fd, SOL_MTP, MTP_TOS, &tos, sizeof(tos));
    if (rc != SOFTBUS_ADAPTER_OK) {
        CONN_LOGE(CONN_COMMON, "set mintp tos fail. fd=%{public}d", fd);
        return rc;
    }
    return SOFTBUS_OK;
}

int32_t SetMintpSocketTransType(int32_t fd, uint32_t transType)
{
    int32_t rc = SoftBusSocketSetOpt(fd, SOL_MTP, MTP_TRANS_TYPE, &transType, sizeof(transType));
    if (rc != SOFTBUS_ADAPTER_OK) {
        CONN_LOGE(CONN_COMMON, "set mintp trans type fail. fd=%{public}d", fd);
        return rc;
    }
    return SOFTBUS_OK;
}

int32_t SetMintpSocketKeepAlive(int32_t fd, int32_t timeoutMs)
{
    if (timeoutMs <= 0) {
        CONN_LOGE(CONN_COMMON, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t rc = SoftBusSocketSetOpt(fd, SOL_MTP, MTP_KEEPIDLE, &timeoutMs, sizeof(timeoutMs));
    if (rc != SOFTBUS_ADAPTER_OK) {
        CONN_LOGE(CONN_COMMON, "set mintp keep idle fail. fd=%{public}d", fd);
        return rc;
    }
    return SOFTBUS_OK;
}

int32_t SetMintpSocketTimeSync(int32_t fd, MintpTimeSync *timeSync)
{
    if (timeSync == NULL) {
        CONN_LOGE(CONN_COMMON, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t rc = SoftBusSocketSetOpt(fd, SOL_MTP, MTP_TIME_SYNC, timeSync, sizeof(MintpTimeSync));
    if (rc != SOFTBUS_ADAPTER_OK) {
        CONN_LOGE(CONN_COMMON, "set mintp time sync fail. fd=%{public}d", fd);
        return rc;
    }
    return SOFTBUS_OK;
}

static void SetMintpOption(int32_t fd, uint32_t transType)
{
    SetMintpSocketKeepAlive(fd, USER_TIMEOUT_MS);
    SetMintpSocketMsgSize(fd);
    SetMintpSocketTransType(fd, transType);
}

static int32_t BindMintp(int32_t domain, int32_t fd, const char *localIp)
{
    bool isIpv4 = domain == SOFTBUS_AF_INET;
    struct SockAddrMtp tmpAddr;
    uint32_t addrLen;
    (void)memset_s(&tmpAddr, sizeof(tmpAddr), 0, sizeof(tmpAddr));
    tmpAddr.saFamily = domain;
    tmpAddr.port = 0;
    tmpAddr.type = isIpv4 ? MTP_ADDR_TYPE_IPV4 : MTP_ADDR_TYPE_IPV6;
    if (isIpv4) {
        int32_t rc = SoftBusInetPtoN(SOFTBUS_AF_INET, localIp, &tmpAddr.ip.addr);
        if (rc != SOFTBUS_ADAPTER_OK) {
            CONN_LOGE(CONN_COMMON, "ipv4 SoftBusInetPtoN fail. rc=%{public}d", rc);
            return SOFTBUS_SOCKET_ADDR_ERR;
        }
    } else {
        int32_t rc = SoftBusInetPtoN(SOFTBUS_AF_INET6, localIp, &tmpAddr.ip6.addr);
        if (rc != SOFTBUS_ADAPTER_OK) {
            CONN_LOGE(CONN_COMMON, "ipv6 SoftBusInetPtoN fail. rc=%{public}d", rc);
            return SOFTBUS_SOCKET_ADDR_ERR;
        }
    }
    addrLen = isIpv4 ? sizeof(SoftBusSockAddrIn) : sizeof(tmpAddr);
    int32_t ret = bind(fd, (struct sockaddr *)&tmpAddr, addrLen);
    if (ret != 0) {
        CONN_LOGE(CONN_COMMON, "bind mintp fail. ret=%{public}d, errno=%{public}d(%{public}s)", ret, errno,
            strerror(errno));
        return SOFTBUS_SOCKET_BIND_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t OpenMintpServerSocket(const LocalListenerInfo *option)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(
        option != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid param, option is null.");
    CONN_CHECK_AND_RETURN_RET_LOGE(
        option->type == CONNECT_HML, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid connect type.");
    CONN_CHECK_AND_RETURN_RET_LOGE(option->socketOption.port >= 0, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid port.");

    char animizedIp[IP_LEN] = { 0 };
    ConvertAnonymizeIpAddress(animizedIp, IP_LEN, option->socketOption.addr, strlen(option->socketOption.addr));
    CONN_LOGI(CONN_COMMON, "open mintp server socket, ip=%{public}s, port=%{public}d.", animizedIp,
        option->socketOption.port);

    int32_t fd = -1;
    int32_t domain = GetDomainByAddr(option->socketOption.addr);
    int32_t ret = SoftBusSocketCreate(domain, SOFTBUS_SOCK_DGRAM | SOFTBUS_SOCK_NONBLOCK, IPPROTO_MINTP, &fd);
    if (ret != SOFTBUS_ADAPTER_OK) {
        CONN_LOGE(CONN_COMMON, "create mintp socket fail. ret=%{public}d", ret);
        return ret;
    }
    ret = BindMintp(domain, fd, option->socketOption.addr);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "bind mintp fail. ret=%{public}d", ret);
        ConnShutdownSocket(fd);
        return ret;
    }
    uint32_t transType = option->socketOption.protocol == LNN_PROTOCOL_MINTP ? MINTP_TRANS_TYPE : DETTP_TRANS_TYPE;
    SetMintpOption(fd, transType);
    CONN_LOGI(CONN_COMMON, "open mintp server socket success, fd=%{public}d.", fd);
    return fd;
}

static int32_t MintpSocketConnect(int32_t fd, int32_t domain, const ConnectOption *option)
{
    struct SockAddrMtp tmpAddr;
    tmpAddr.saFamily = domain;
    tmpAddr.port = SoftBusHtoNs((uint16_t)(option->socketOption.port));
    tmpAddr.type = domain == SOFTBUS_AF_INET ? MTP_ADDR_TYPE_IPV4 : MTP_ADDR_TYPE_IPV6;
    if (domain == SOFTBUS_AF_INET) {
        int32_t rc = SoftBusInetPtoN(SOFTBUS_AF_INET, option->socketOption.addr, &tmpAddr.ip.addr);
        if (rc != SOFTBUS_ADAPTER_OK) {
            CONN_LOGE(CONN_COMMON, "ipv4 SoftBusInetPtoN fail. rc=%{public}d", rc);
            return rc;
        }
    } else {
        int32_t rc = SoftBusInetPtoN(SOFTBUS_AF_INET6, option->socketOption.addr, &tmpAddr.ip6.addr);
        if (rc != SOFTBUS_ADAPTER_OK) {
            CONN_LOGE(CONN_COMMON, "ipv6 SoftBusInetPtoN fail. rc=%{public}d", rc);
            return rc;
        }
    }
    int32_t addrLen = domain == SOFTBUS_AF_INET ? sizeof(SoftBusSockAddrIn) : sizeof(tmpAddr);
    return SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketConnect(fd, (SoftBusSockAddr *)&tmpAddr, addrLen));
}

static int32_t OpenMintpClientSocket(const ConnectOption *option, const char *myIp, bool isNonBlock)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(
        option != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid param, option is null.");
    CONN_CHECK_AND_RETURN_RET_LOGE(myIp != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid param, myIp is null.");
    CONN_CHECK_AND_RETURN_RET_LOGE(option->type == CONNECT_HML, SOFTBUS_INVALID_PARAM, CONN_COMMON,
        "invalid param, unsupported connect type, type=%{public}d.", option->type);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        option->socketOption.port > 0, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid param, port is invalid.");
    CONN_CHECK_AND_RETURN_RET_LOGE(
        option->socketOption.addr[0] != '\0', SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid param, addr is invalid.");

    char animizedIp[IP_LEN] = { 0 };
    ConvertAnonymizeIpAddress(animizedIp, IP_LEN, option->socketOption.addr, strlen(option->socketOption.addr));
    CONN_LOGI(CONN_COMMON, "open mintp client socket, server ip=%{public}s, server port=%{public}d.", animizedIp,
        option->socketOption.port);
    int32_t fd = -1;
    int32_t domain = GetDomainByAddr(option->socketOption.addr);
    int32_t ret = SoftBusSocketCreate(domain, SOFTBUS_SOCK_DGRAM, IPPROTO_MINTP, &fd);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "create mintp socket fail. serverIp=%{public}s, serverPort=%{public}d, ret=%{public}d",
            animizedIp, option->socketOption.port, ret);
        return ret;
    }
    if (isNonBlock && ConnToggleNonBlockMode(fd, true) != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "set nonblock mode fail. serverIp=%{public}s, serverPort=%{public}d", animizedIp,
            option->socketOption.port);
        ConnShutdownSocket(fd);
        return SOFTBUS_SOCKET_ERR;
    }
    ret = BindMintp(domain, fd, myIp);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "bind mintp fail. ret=%{public}d", ret);
        ConnShutdownSocket(fd);
        return ret;
    }
    uint32_t transType = option->socketOption.protocol == LNN_PROTOCOL_MINTP ? MINTP_TRANS_TYPE : DETTP_TRANS_TYPE;
    SetMintpOption(fd, transType);
    ret = MintpSocketConnect(fd, domain, option);
    if ((ret != SOFTBUS_ADAPTER_OK) && (ret != SOFTBUS_ADAPTER_SOCKET_EINPROGRESS) &&
        (ret != SOFTBUS_ADAPTER_SOCKET_EAGAIN)) {
        CONN_LOGE(CONN_COMMON, "connect mintp fail. serverIp=%{public}s, serverPort=%{public}d, ret=%{public}d",
            animizedIp, option->socketOption.port, ret);
        ConnShutdownSocket(fd);
        return SOFTBUS_SOCKET_ERR;
    }
    CONN_LOGI(CONN_COMMON, "mintp connect success, fd=%{public}d, serverIp=%{public}s, serverPort=%{public}d.", fd,
        animizedIp, option->socketOption.port);
    return fd;
}

int32_t GetMintpSockPort(int32_t fd)
{
    SoftBusSockAddr addr;
    int32_t rc = SoftBusSocketGetLocalName(fd, &addr);
    if (rc != SOFTBUS_ADAPTER_OK) {
        CONN_LOGE(CONN_COMMON, "get mintp sock port fail. rc=%{public}d, fd=%{public}d", rc, fd);
        return rc;
    }
    if (addr.saFamily == SOFTBUS_AF_INET6) {
        return SoftBusNtoHs(((SoftBusSockAddrIn6 *)&addr)->sin6Port);
    }
    return SoftBusNtoHs(((SoftBusSockAddrIn *)&addr)->sinPort);
}

static int32_t AcceptClientWithProtocol(int32_t fd, ConnectOption *clientAddr, int32_t *cfd, ProtocolType protocol)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(
        clientAddr != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid param, clientAddr is null");
    CONN_CHECK_AND_RETURN_RET_LOGW(cfd != NULL, SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid param, cfd is null");
    struct SockAddrMtp mtpClientAddr;
    socklen_t addrLen = sizeof(mtpClientAddr);
    (void)memset_s(&mtpClientAddr, addrLen, 0, addrLen);
    int32_t ret = SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketAccept(fd, (SoftBusSockAddr *)&mtpClientAddr, cfd));
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "accept mintp client fail. ret=%{public}d", ret);
        return ret;
    }
    clientAddr->type = CONNECT_HML;
    clientAddr->socketOption.port = GetMintpSockPort(*cfd);
    clientAddr->socketOption.protocol = protocol;
    char mtpMac[BT_MAC_LEN] = { 0 };
    ret = ConvertBtMacToStr(mtpMac, sizeof(mtpMac), mtpClientAddr.mac.addr, sizeof(mtpClientAddr.mac.addr));
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "convert mintp mac to string fail. ret=%{public}d", ret);
        return ret;
    }
    ret = strcpy_s(clientAddr->socketOption.addr, sizeof(clientAddr->socketOption.addr), mtpMac);
    if (ret != EOK) {
        CONN_LOGE(CONN_COMMON, "copy mintp mac to clientAddr fail. ret=%{public}d", ret);
        return SOFTBUS_ERR;
    }
    CONN_LOGI(CONN_COMMON, "accept mintp client success, cfd=%{public}d", *cfd);
    return SOFTBUS_OK;
}

static int32_t AcceptMintpClient(int32_t fd, ConnectOption *clientAddr, int32_t *cfd)
{
    return AcceptClientWithProtocol(fd, clientAddr, cfd, LNN_PROTOCOL_MINTP);
}

static int32_t AcceptDettpClient(int32_t fd, ConnectOption *clientAddr, int32_t *cfd)
{
    return AcceptClientWithProtocol(fd, clientAddr, cfd, LNN_PROTOCOL_DETTP);
}

const SocketInterface *GetMinTpProtocol(void)
{
    static SocketInterface mintpSocketIntf = {
        .name = "MINTP",
        .type = LNN_PROTOCOL_MINTP,
        .GetSockPort = GetMintpSockPort,
        .OpenServerSocket = OpenMintpServerSocket,
        .OpenClientSocket = OpenMintpClientSocket,
        .AcceptClient = AcceptMintpClient,
    };
    return &mintpSocketIntf;
}

const SocketInterface *GetDetTpProtocol(void)
{
    static SocketInterface mintpSocketIntf = {
        .name = "DETTP",
        .type = LNN_PROTOCOL_DETTP,
        .GetSockPort = GetMintpSockPort,
        .OpenServerSocket = OpenMintpServerSocket,
        .OpenClientSocket = OpenMintpClientSocket,
        .AcceptClient = AcceptDettpClient,
    };
    return &mintpSocketIntf;
}
