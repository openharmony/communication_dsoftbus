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

#include "softbus_socket.h"

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <securec.h>

#include "conn_log.h"
#include "softbus_adapter_socket.h"
#include "softbus_conn_common.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_tcp_socket.h"
#include "softbus_watch_event_interface.h"

#define HML_IPV4_ADDR_PREFIX "172.30."

#define MAX_SOCKET_TYPE 5
#define SEND_BUF_SIZE   0x200000 // 2M
#define RECV_BUF_SIZE   0x100000 // 1M
#define USER_TIMEOUT_US 5000000   // 5000000us

static const SocketInterface *g_socketInterfaces[MAX_SOCKET_TYPE] = { 0 };
static SoftBusMutex g_socketsMutex;

int32_t RegistSocketProtocol(const SocketInterface *interface)
{
    if (interface == NULL || interface->GetSockPort == NULL || interface->OpenClientSocket == NULL ||
        interface->OpenServerSocket == NULL || interface->AcceptClient == NULL) {
        CONN_LOGW(CONN_COMMON, "Bad socket interface!");
        return SOFTBUS_INVALID_PARAM;
    }
    int ret = SoftBusMutexLock(&g_socketsMutex);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "get lock failed! ret=%{public}" PRId32, ret);
        return ret;
    }

    ret = SOFTBUS_CONN_SOCKET_INTERNAL_ERR;
    for (uint8_t i = 0; i < MAX_SOCKET_TYPE; i++) {
        if (g_socketInterfaces[i] == NULL) {
            g_socketInterfaces[i] = interface;
            ret = SOFTBUS_OK;
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_socketsMutex);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "socket type list is full!");
    }
    return ret;
}

const SocketInterface *GetSocketInterface(ProtocolType protocolType)
{
    int ret = SoftBusMutexLock(&g_socketsMutex);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "get lock failed! ret=%{public}" PRId32, ret);
        return NULL;
    }
    const SocketInterface *result = NULL;
    for (uint8_t i = 0; i < MAX_SOCKET_TYPE; i++) {
        if (g_socketInterfaces[i] != NULL && g_socketInterfaces[i]->type == protocolType) {
            result = g_socketInterfaces[i];
            break;
        }
    }
    (void)SoftBusMutexUnlock(&g_socketsMutex);
    return result;
}

int32_t __attribute__((weak)) RegistNewIpSocket(void)
{
    CONN_LOGD(CONN_COMMON, "newip not deployed");
    return SOFTBUS_OK;
}

int32_t ConnInitSockets(void)
{
    int32_t ret = SoftBusMutexInit(&g_socketsMutex, NULL);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "init mutex failed! ret=%{public}" PRId32, ret);
        return ret;
    }

    (void)memset_s(g_socketInterfaces, sizeof(g_socketInterfaces), 0, sizeof(g_socketInterfaces));

    ret = RegistSocketProtocol(GetTcpProtocol());
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "regist tcp failed!! ret=%{public}" PRId32, ret);
        (void)SoftBusMutexDestroy(&g_socketsMutex);
        return ret;
    }
    CONN_LOGD(CONN_INIT, "tcp registed!");

    ret = RegistNewIpSocket();
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_INIT, "regist newip failed!! ret=%{public}" PRId32, ret);
        (void)SoftBusMutexDestroy(&g_socketsMutex);
        return ret;
    }

    return ret;
}

void ConnDeinitSockets(void)
{
    (void)memset_s(g_socketInterfaces, sizeof(g_socketInterfaces), 0, sizeof(g_socketInterfaces));
    (void)SoftBusMutexDestroy(&g_socketsMutex);
}

int32_t ConnOpenClientSocket(const ConnectOption *option, const char *bindAddr, bool isNonBlock)
{
    if (option == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    const SocketInterface *socketInterface = GetSocketInterface(option->socketOption.protocol);
    if (socketInterface == NULL) {
        CONN_LOGE(CONN_COMMON, "protocol not supported! protocol=%{public}d", option->socketOption.protocol);
        return SOFTBUS_CONN_SOCKET_GET_INTERFACE_ERR;
    }
    return socketInterface->OpenClientSocket(option, bindAddr, isNonBlock);
}

int32_t ConnToggleNonBlockMode(int32_t fd, bool isNonBlock)
{
    if (fd < 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        CONN_LOGE(CONN_COMMON, "fcntl get flag failed, fd=%{public}d, errno=%{public}d(%{public}s)",
            fd, errno, strerror(errno));
        return SOFTBUS_CONN_SOCKET_FCNTL_ERR;
    }
    if (isNonBlock && ((uint32_t)flags & O_NONBLOCK) == 0) {
        flags = (int32_t)((uint32_t)flags | O_NONBLOCK);
        CONN_LOGI(CONN_COMMON, "set to nonblock. fd=%{public}d", fd);
    } else if (!isNonBlock && ((uint32_t)flags & O_NONBLOCK) != 0) {
        flags = (int32_t)((uint32_t)flags & ~O_NONBLOCK);
        CONN_LOGI(CONN_COMMON, "set to block. fd=%{public}d", fd);
    } else {
        CONN_LOGI(CONN_COMMON, "nonblock state is already ok. fd=%{public}d", fd);
        return SOFTBUS_OK;
    }
    return fcntl(fd, F_SETFL, flags);
}

ssize_t ConnSendSocketData(int32_t fd, const char *buf, size_t len, int32_t timeout)
{
    if (fd < 0 || buf == NULL || len == 0) {
        CONN_LOGE(CONN_COMMON, "invalid params. fd=%{public}d", fd);
        return -1;
    }

    if (timeout == 0) {
        timeout = USER_TIMEOUT_US;
    }

    int err = WaitEvent(fd, SOFTBUS_SOCKET_OUT, USER_TIMEOUT_US);
    if (err <= 0) {
        CONN_LOGE(CONN_COMMON, "wait event error. err=%{public}d", err);
        return err;
    }
    ssize_t bytes = 0;
    while (1) {
        ssize_t rc = SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketSend(fd, &buf[bytes], len - bytes, 0));
        if (rc == SOFTBUS_ADAPTER_SOCKET_EAGAIN) {
            continue;
        } else if (rc <= 0) {
            if (bytes == 0) {
                bytes = -1;
            }
            CONN_LOGE(CONN_COMMON, "tcp send fail. rc=%{public}zd, errno=%{public}d(%{public}s)",
                rc, errno, strerror(errno));
            break;
        }
        bytes += rc;
        if (bytes == (ssize_t)(len)) {
            break;
        }

        err = WaitEvent(fd, SOFTBUS_SOCKET_OUT, timeout);
        if (err == 0) {
            continue;
        } else if (err < 0) {
            if (bytes == 0) {
                CONN_LOGE(CONN_COMMON, "send data wait event fail. err=%{public}d", err);
                bytes = err;
            }
            break;
        }
    }
    return bytes;
}

static ssize_t OnRecvData(int32_t fd, char *buf, size_t len, int timeout, int flags)
{
    if (fd < 0 || buf == NULL || len == 0) {
        CONN_LOGE(CONN_COMMON, "invalid params. fd=%{public}d, len=%{public}zu", fd, len);
        return -1;
    }

    if (timeout != 0) {
        int err = WaitEvent(fd, SOFTBUS_SOCKET_IN, timeout);
        if (err < 0) {
            CONN_LOGE(CONN_COMMON, "recv data wait event err=%{public}d", err);
            return err;
        }
    }

    ssize_t rc = SOFTBUS_TEMP_FAILURE_RETRY(SoftBusSocketRecv(fd, buf, len, flags));
    if (rc == SOFTBUS_ADAPTER_SOCKET_EAGAIN) {
        CONN_LOGW(CONN_COMMON, "recv data socket EAGAIN");
        rc = 0;
    } else if (rc == 0) {
        CONN_LOGE(CONN_COMMON, "recv data fail, peer close connection, fd=%{public}d", fd);
        rc = -1;
    } else if (rc < 0) {
        CONN_LOGE(CONN_COMMON, "recv data fail fd=%{public}d, errno=%{public}d(%{public}s), rc=%{public}zd",
            fd, errno, strerror(errno), rc);
        rc = -1;
    }
    return rc;
}

ssize_t ConnRecvSocketData(int32_t fd, char *buf, size_t len, int32_t timeout)
{
    return OnRecvData(fd, buf, len, timeout, 0);
}

void ConnCloseSocket(int32_t fd)
{
    if (fd >= 0) {
        CONN_LOGI(CONN_COMMON, "close fd=%{public}d", fd);
        SoftBusSocketClose(fd);
    }
}

void ConnShutdownSocket(int32_t fd)
{
    if (fd >= 0) {
        CONN_LOGI(CONN_COMMON, "shutdown fd=%{public}d", fd);
        SoftBusSocketShutDown(fd, SOFTBUS_SHUT_RDWR);
        SoftBusSocketClose(fd);
    }
}

int32_t ConnGetSocketError(int32_t fd)
{
    return SoftBusSocketGetError(fd);
}

int32_t ConnGetLocalSocketPort(int32_t fd)
{
    const SocketInterface *socketInterface = GetSocketInterface(LNN_PROTOCOL_IP);
    if (socketInterface == NULL) {
        CONN_LOGW(CONN_COMMON, "LNN_PROTOCOL_IP not supported!");
        return SOFTBUS_CONN_SOCKET_GET_INTERFACE_ERR;
    }
    return socketInterface->GetSockPort(fd);
}

int32_t ConnGetPeerSocketAddr(int32_t fd, SocketAddr *socketAddr)
{
    SoftBusSockAddr addr;
    if (socketAddr == NULL) {
        CONN_LOGW(CONN_COMMON, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int rc = SoftBusSocketGetPeerName(fd, &addr);
    if (rc != 0) {
        CONN_LOGE(CONN_COMMON, "GetPeerName fd=%{public}d, rc=%{public}d", fd, rc);
        return SOFTBUS_TCP_SOCKET_ERR;
    }
    if (addr.saFamily == SOFTBUS_AF_INET6) {
        rc = Ipv6AddrInToAddr((SoftBusSockAddrIn6 *)&addr, socketAddr->addr, sizeof(socketAddr->addr));
        socketAddr->port = SoftBusNtoHs(((SoftBusSockAddrIn6 *)&addr)->sin6Port);
        if (rc < 0) {
            CONN_LOGE(CONN_COMMON, "Ipv6AddrInToAddr fail. fd=%{public}d", fd);
            return SOFTBUS_SOCKET_ADDR_ERR;
        }
        return SOFTBUS_OK;
    }
    socketAddr->port = SoftBusNtoHs(((SoftBusSockAddrIn *)&addr)->sinPort);
    if (SoftBusInetNtoP(SOFTBUS_AF_INET, (void *)&((SoftBusSockAddrIn *)&addr)->sinAddr,
        socketAddr->addr, sizeof(socketAddr->addr)) == NULL) {
        CONN_LOGE(CONN_COMMON, "InetNtoP fail. fd=%{public}d", fd);
        return SOFTBUS_TCPCONNECTION_SOCKET_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ConnPreAssignPortBind(int32_t socketFd, int32_t domain)
{
    int ret = SOFTBUS_TCPCONNECTION_SOCKET_ERR;
    if (domain == SOFTBUS_AF_INET6) {
        SoftBusSockAddrIn6 addrIn6 = {0};
        ret = Ipv6AddrToAddrIn(&addrIn6, "::", 0);
        if (ret != SOFTBUS_ADAPTER_OK) {
            CONN_LOGE(CONN_COMMON, "convert address to net order failed");
            return SOFTBUS_TCPCONNECTION_SOCKET_ERR;
        }
        return SoftBusSocketBind(socketFd, (SoftBusSockAddr *)&addrIn6, sizeof(SoftBusSockAddrIn6));
    }
    SoftBusSockAddrIn addrIn = {0};
    ret = Ipv4AddrToAddrIn(&addrIn, "0.0.0.0", 0);
    if (ret != SOFTBUS_ADAPTER_OK) {
        CONN_LOGE(CONN_COMMON, "convert address to net order failed");
        return SOFTBUS_TCPCONNECTION_SOCKET_ERR;
    }
    return SoftBusSocketBind(socketFd, (SoftBusSockAddr *)&addrIn, sizeof(SoftBusSockAddrIn));
}

int32_t ConnPreAssignPort(int32_t domain)
{
    int socketFd = -1;
    int ret = SoftBusSocketCreate(domain, SOFTBUS_SOCK_STREAM, 0, &socketFd);
    if (ret < 0) {
        CONN_LOGE(CONN_COMMON, "create socket failed, ret=%{public}d", ret);
        return SOFTBUS_TCPCONNECTION_SOCKET_ERR;
    }
    int reuse = 1;
    ret = SoftBusSocketSetOpt(socketFd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "set reuse port option failed");
        SoftBusSocketClose(socketFd);
        return SOFTBUS_TCPCONNECTION_SOCKET_ERR;
    }
    ret = ConnPreAssignPortBind(socketFd, domain);
    if (ret != SOFTBUS_ADAPTER_OK) {
        SoftBusSocketClose(socketFd);
        CONN_LOGE(CONN_COMMON, "bind address failed");
        return SOFTBUS_TCPCONNECTION_SOCKET_ERR;
    }
    return socketFd;
}

int32_t GetDomainByAddr(const char *addr)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(addr != NULL,
        SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid param!");
    if (strchr(addr, ADDR_FEATURE_IPV6) != NULL) {
        return SOFTBUS_AF_INET6;
    }
    return SOFTBUS_AF_INET;
}

int32_t Ipv6AddrInToAddr(SoftBusSockAddrIn6 *addrIn6, char *addr, int32_t addrLen)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(addrIn6 != NULL && addr != NULL && addrLen > 0,
        SOFTBUS_INVALID_PARAM, CONN_COMMON, "invalid param!");
    char ip[IP_LEN] = {0};
    if (SoftBusInetNtoP(SOFTBUS_AF_INET6, &addrIn6->sin6Addr, ip, addrLen) == NULL) {
        CONN_LOGE(CONN_COMMON, "InetNtoP faild!");
        return SOFTBUS_SOCKET_ADDR_ERR;
    }
    char ifname[IF_NAME_SIZE] = { 0 };
    int32_t rc = SoftBusIndexToIfName(addrIn6->sin6ScopeId, ifname, IF_NAME_SIZE);
    if (rc < 0) {
        if (strcpy_s(addr, IP_LEN, ip) != SOFTBUS_OK) {
            CONN_LOGE(CONN_COMMON, "strcpy faild!");
            return SOFTBUS_STRCPY_ERR;
        }
        CONN_LOGW(CONN_COMMON, "no ifname or global addr");
        return SOFTBUS_OK;
    }
    rc = sprintf_s(addr, addrLen, "%s%s%s", ip, ADDR_SPLIT_IPV6, ifname);
    if (rc < 0) {
        COMM_LOGE(CONN_COMMON, "sprintf_s addr fail");
        return SOFTBUS_SOCKET_ADDR_ERR;
    }
    return SOFTBUS_OK;
}

int32_t Ipv6AddrToAddrIn(SoftBusSockAddrIn6 *addrIn6, const char *ip, uint16_t port)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(addrIn6 != NULL && ip != NULL, SOFTBUS_INVALID_PARAM,
        CONN_COMMON, "invalid param!");
    (void)memset_s(addrIn6, sizeof(*addrIn6), 0, sizeof(*addrIn6));
    addrIn6->sin6Family = SOFTBUS_AF_INET6;
    char *addr = NULL;
    char *ifName = NULL;
    char *nextToken = NULL;
    char tmpIp[IP_LEN] = { 0 };
    if (strcpy_s(tmpIp, sizeof(tmpIp), ip) != EOK) {
        CONN_LOGE(CONN_COMMON, "copy local id failed");
        return SOFTBUS_MEM_ERR;
    }
    addr = strtok_s(tmpIp, ADDR_SPLIT_IPV6, &nextToken);
    if (addr == NULL) {
        addr = "";
    }
    ifName = strtok_s(NULL, ADDR_SPLIT_IPV6, &nextToken);
    if (ifName != NULL) {
        addrIn6->sin6ScopeId = SoftBusIfNameToIndex(ifName);
        if (addrIn6->sin6ScopeId == 0) {
            CONN_LOGE(CONN_WIFI_DIRECT, "nameToIndex failed, errno=%{public}d(%{public}s)", errno, strerror(errno));
            return SOFTBUS_SOCKET_ADDR_ERR;
        }
    }
    int32_t rc = SoftBusInetPtoN(SOFTBUS_AF_INET6, addr, &addrIn6->sin6Addr);
    if (rc != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "ipv6 SoftBusInetPtoN rc=%{public}d", rc);
        return SOFTBUS_SOCKET_ADDR_ERR;
    }
    addrIn6->sin6Port = SoftBusHtoNs(port);
    return SOFTBUS_OK;
}

int32_t Ipv4AddrToAddrIn(SoftBusSockAddrIn *addrIn, const char *ip, uint16_t port)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(addrIn != NULL && ip != NULL, SOFTBUS_INVALID_PARAM,
        CONN_COMMON, "invalid param!");
    (void)memset_s(addrIn, sizeof(*addrIn), 0, sizeof(*addrIn));
    addrIn->sinFamily = SOFTBUS_AF_INET;
    int32_t rc = SoftBusInetPtoN(SOFTBUS_AF_INET, ip, &addrIn->sinAddr);
    if (rc != SOFTBUS_OK) {
        CONN_LOGE(CONN_COMMON, "ipv4 SoftBusInetPtoN rc=%{public}d", rc);
        return SOFTBUS_SOCKET_ADDR_ERR;
    }
    addrIn->sinPort = SoftBusHtoNs(port);
    return SOFTBUS_OK;
}

bool IsHmlIpAddr(const char *ip)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(ip != NULL, false, CONN_COMMON, "invalid param!");
    if (GetDomainByAddr(ip) == SOFTBUS_AF_INET6) {
        return true;
    }

    return strncmp(ip, HML_IPV4_ADDR_PREFIX, strlen(HML_IPV4_ADDR_PREFIX)) == 0;
}

static int32_t GetIfNameByIp(const char *myIp, int32_t domain, char *ifName, int32_t ifNameMaxLen)
{
    if (myIp == NULL || ifName == NULL || strcmp(myIp, BIND_ADDR_ALL) == 0) {
        COMM_LOGE(CONN_COMMON, "Invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    struct ifaddrs *ifa = NULL;
    struct ifaddrs *ifList = NULL;
    struct in_addr inAddr = { 0 };
    char animizedIp[IP_LEN] = { 0 };
    ConvertAnonymizeIpAddress(animizedIp, IP_LEN, myIp, IP_LEN);

    int32_t ret = getifaddrs(&ifList);
    if (ret != 0) {
        COMM_LOGE(CONN_COMMON, "ip=%{public}s getifaddrs ifList failed, ret=%{public}d, errno=%{public}d(%{public}s)",
            animizedIp, ret, errno, strerror(errno));
        return SOFTBUS_SOCKET_ADDR_ERR;
    }
    if (inet_aton(myIp, &inAddr) == 0) {
        COMM_LOGE(CONN_COMMON, "inet_aton ip=%{public}s failed.", animizedIp);
        freeifaddrs(ifList);
        return SOFTBUS_TCP_SOCKET_ERR;
    }
    for (ifa = ifList; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }
        (void)memset_s(ifName, ifNameMaxLen, 0, ifNameMaxLen);
        if (memcmp(&inAddr, &(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr), sizeof(struct in_addr)) == 0) {
            if (memcpy_s(ifName, ifNameMaxLen - 1, ifa->ifa_name, strlen(ifa->ifa_name)) != EOK) {
                COMM_LOGE(CONN_COMMON, "fail to memcpy_s ifName by ip=%{public}s", animizedIp);
                freeifaddrs(ifList);
                return SOFTBUS_MEM_ERR;
            }
            freeifaddrs(ifList);
            return SOFTBUS_OK;
        }
    }
    COMM_LOGW(CONN_COMMON, "not found ifName by ip=%{public}s", animizedIp);
    freeifaddrs(ifList);
    return SOFTBUS_CONN_NOT_FOUND_FAILED;
}

// prevent the scenario of using VPN to produce virtual network cards.
void BindToInterface(const char *myIp, int32_t domain, int fd, char *ifName, int32_t ifNameMaxLen)
{
    // The IPv6 socket has already been bound to the network card, there is no need to bind it again.
    CONN_CHECK_AND_RETURN_LOGW(domain != SOFTBUS_AF_INET6, CONN_COMMON, "Ipv6 addr no need to get ifName.");

    int32_t ret = GetIfNameByIp(myIp, domain, ifName, ifNameMaxLen);
    CONN_CHECK_AND_RETURN_LOGW(ret == SOFTBUS_OK, CONN_COMMON, "cannot bind to interface.");

    ret = SoftBusSocketSetOpt(fd, SOFTBUS_SOL_SOCKET, SOFTBUS_SO_BINDTODEVICE, ifName, strlen(ifName));
    if (ret < 0) {
        COMM_LOGE(
            CONN_COMMON, "socketSetOpt fail, fd=%{public}d, ifName=%{public}s, errno=%{public}d", fd, ifName, ret);
        return;
    }
    return;
}
