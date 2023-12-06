/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "sysio.h"
#include "sockets.h"
#include "socket_common.h"
#include "spunge_mem.h"
#include "opt.h"
#include "res.h"
#include "spunge.h"

#ifdef __cplusplus
extern "C" {
#endif
static int SysioSendUdp(
    void *arg,
    FILLP_CONST char *buf,
    FILLP_SIZE_T size,
    FILLP_SOCKADDR *dest,
    FILLP_UINT16 destAddrLen);

static struct SpungePcb*SysioGetPcbFromRemoteaddrUdp(
    struct sockaddr *addr,
    FILLP_CONST struct SockOsSocket *osSock,
    FILLP_CONST struct Hlist *list);

static int SysioDoSocketUdp(void *argSock);
static void *SysioRecvUdp(void *arg, FILLP_CONST void *buf, void *databuf);
static void *SysioCreateSocketUdp(
    FILLP_INT domain,
    FILLP_INT type,
    FILLP_INT protocol);
static int SysioDestroySocketUdp(void *arg);
static int SysioBindUdp(void *argSock, void *argPcb, FILLP_SOCKADDR *addr, FILLP_UINT16 len);
static int SysioCanSockReadUdp(void *arg);
static int SysioSelectUdp(void *arg, FILLP_INT timeoutUs);
static void *SysioFetchPacketUdp(void *sock, void *buf, void *count);
static int SysioConnectUdp(void *argSock, void *argPcb);
static void SysioRemovePcbUdp(void *argSock, void *argPcb);
static void SysioAddPcbUdp(void *argSock, void *argPcb);
static void SysioFreeSocketUdp(void *argSock, void *argOsSock);
static int SysioSendPacketUdp(
    int msgType,
    void *argSock,
    void *argPcb,
    void *argBuf);
static int SysioHandlePacketUdp(
    int msgType,
    void *argSock,
    void *argPcb,
    void *argBuf);

static int SysioListenUdp(void *argSock);

static int SysioGetSocknameUdp(void *argSock, void *name, void *nameLen);

static int SysioGetOsSocketUdp(void *argSock)
{
    SysIoUdpSock *udpSock = (SysIoUdpSock *)argSock;
    return udpSock->udpSock;
}

static void SysioConnectedUdp(void *argSock, void *argOsSock);
static int SysioGetsockoptUdp(
    void *arg,
    FILLP_INT level,
    FILLP_INT optName,
    void *optVal,
    FILLP_INT *optLen);
static int SysioSetsockoptUdp(
    void *arg,
    FILLP_INT level,
    FILLP_INT optName,
    FILLP_CONST void *optVal,
    socklen_t optLen);

SysioUdpT g_udpIo = {
    {
        SysioDoSocketUdp,
        SysioSendUdp,
        SysioRecvUdp,
        SysioFetchPacketUdp,
        SysioSelectUdp,
        SysioCreateSocketUdp,
        SysioDestroySocketUdp,
        SysioListenUdp,
        SysioBindUdp,
        SysioConnectUdp,
        SysioCanSockReadUdp,
        SysioHandlePacketUdp,
        SysioSendPacketUdp,
        SysioRemovePcbUdp,
        SysioFreeSocketUdp,
        SysioGetSocknameUdp,
        SysioAddPcbUdp,
        SysioGetOsSocketUdp,
        SysioConnectedUdp,
        SysioGetsockoptUdp,
        SysioSetsockoptUdp
    },
    0,
    0,
    0,
    {
        {
            0, 0, 0,
        },
        0,
#ifdef FILLP_64BIT_ALIGN
        {
            0
        }
#endif
    }
};

static int SysioDoSocketUdp(void *argSock)
{
    FILLP_UNUSED_PARA(argSock);
    return ERR_OK;
}

static int SysioListenUdp(void *argSock)
{
    struct FtSocket *sock = (struct FtSocket *)argSock;
    HlistAddTail(&g_udpIo.listenPcbList, &sock->listenNode);
    return ERR_OK;
}

static int SysioSendUdp(
    void *arg,
    FILLP_CONST char *buf,
    FILLP_SIZE_T size,
    FILLP_SOCKADDR *dest,
    FILLP_UINT16 destAddrLen)
{
    int ret;

#if defined(FILLP_LINUX) && !defined(FILLP_MAC)
    FILLP_INT flg = MSG_NOSIGNAL;
#else
    FILLP_INT flg = 0;
#endif

    SysIoUdpSock *udpSock = (SysIoUdpSock *)arg;

    if (udpSock->connected) {
        ret = (int)FILLP_SEND(udpSock->udpSock, buf, (FILLP_INT)size, flg);
    } else {
        ret = (int)FILLP_SENDTO(udpSock->udpSock, buf, size, flg, dest, destAddrLen);
    }

    return ret;
}

static int SysioGetsockoptUdp(
    void *arg,
    FILLP_INT level,
    FILLP_INT optName,
    void *optVal,
    FILLP_INT *optLen)
{
    SysIoUdpSock *udpSock = (SysIoUdpSock *)arg;

    return FILLP_GETSOCKOPT(udpSock->udpSock, level, optName, optVal, optLen);
}

static int SysioSetsockoptUdp(
    void *arg,
    FILLP_INT level,
    FILLP_INT optName,
    FILLP_CONST void *optVal,
    socklen_t optLen)
{
    SysIoUdpSock *udpSock = (SysIoUdpSock *)arg;

    return FILLP_SETSOCKOPT(udpSock->udpSock, level, optName, optVal, optLen);
}

static void *SysioRecvUdp(void *arg, FILLP_CONST void *buf, void *databuf)
{
    FILLP_UNUSED_PARA(arg);
    FILLP_UNUSED_PARA(buf);
    FILLP_UNUSED_PARA(databuf);
    return FILLP_NULL_PTR;
}

static int SysioSelectUdp(void *arg, FILLP_INT timeoutUs)
{
    (void)FILLP_FD_COPY_FD_SET(g_udpIo.readableSet, g_udpIo.readSet);

    FILLP_UNUSED_PARA(arg);
    FILLP_UNUSED_PARA(timeoutUs);
    return ERR_OK;
}

static void SysioFreeSocketUdp(void *argSock, void *argOsSock)
{
    struct FtSocket *sock = (struct FtSocket *)argSock;
    if (sock->isListenSock) {
        struct HlistNode *node = HLIST_FIRST(&g_udpIo.listenPcbList);
        while (node != FILLP_NULL_PTR) {
            if (node == &sock->listenNode) {
                HlistDelete(&g_udpIo.listenPcbList, node);
                break;
            }
            node = node->next;
        }
    }

    FILLP_UNUSED_PARA(argOsSock);

    return;
}

static void *SysioFetchPacketUdp(void *sock, void *buf, void *count)
{
    struct SockOsSocket *osSock = (struct SockOsSocket *)sock;
    SysIoUdpSock *sysioUdpSock = (SysIoUdpSock *)osSock->ioSock;
    struct NetBuf *netbuf = (struct NetBuf *)buf;
    FILLP_SIZE_T addLen = sizeof(struct sockaddr_in6);
    FILLP_UINT32 hashIndex;
    FILLP_LLONG recvTime = 0;

    struct SpungePcb *spcb = FILLP_NULL_PTR;
    struct Hlist *list = FILLP_NULL_PTR;

    FILLP_UNUSED_PARA(count);
    FILLP_UNUSED_PARA(recvTime);
    netbuf->len = (int)FILLP_RECVFROM(sysioUdpSock->udpSock, netbuf->p,
        (size_t)FILLP_MAX_PKT_SIZE, 0, &netbuf->addr, (FILLP_SIZE_T *)&addLen);
    if (netbuf->len <= FILLP_HLEN) {
        return FILLP_NULL_PTR; /* No data received */
    }

    netbuf->len -= FILLP_HLEN;

    hashIndex = UtilsAddrHashKey((struct sockaddr_in *)&netbuf->addr);
    list = &(sysioUdpSock->pcbHash[hashIndex & (UDP_HASH_TABLE_SIZE - 1)].list);
    spcb = SysioGetPcbFromRemoteaddrUdp((struct sockaddr *)&netbuf->addr, osSock, list);
    return spcb;
}

static int SysioSetSocketOpt(SysIoUdpSock *udpSock)
{
    if (SysArchSetSockBlocking(udpSock->udpSock, FILLP_FALSE)) {
        SET_ERRNO(FT_OS_GET_ERRNO);
        FILLP_LOGERR("set sock nonblocking fail errno=%d", FT_OS_GET_ERRNO);
        return -1;
    }

    if (SysArchSetSockRcvbuf(udpSock->udpSock, g_appResource.common.recvBufSize)) {
        SET_ERRNO(FT_OS_GET_ERRNO);
        FILLP_LOGERR("Fail to set sock recvBuf errno=%d", FT_OS_GET_ERRNO);
        return -1;
    }
#ifndef NSTACKX_WITH_LITEOS
    if (SysArchSetSockSndbuf(udpSock->udpSock, g_appResource.common.udpSendBufSize)) {
        SET_ERRNO(FT_OS_GET_ERRNO);
        FILLP_LOGERR("Fail to set sock sndBuf errno=%d", FT_OS_GET_ERRNO);
        return -1;
    }
#endif
    return 0;
}

static inline void SysioMaxUdpSockSet(int fd)
{
    if (fd > g_udpIo.maxUdpSock) {
        g_udpIo.maxUdpSock = fd;
    }
}

static void *SysioCreateSocketUdp(FILLP_INT domain, FILLP_INT type, FILLP_INT protocol)
{
    int i;
    size_t sockSize = sizeof(SysIoUdpSock);

    SysIoUdpSock *udpSock = (SysIoUdpSock *)SpungeAlloc(1, sockSize, SPUNGE_ALLOC_TYPE_CALLOC);
    if (udpSock == FILLP_NULL_PTR) {
        goto FAIL;
    }

    udpSock->sysIoSock.ops = &g_udpIo.ops;
    udpSock->connected = FILLP_FALSE;

    FILLP_UNUSED_PARA(type);
    FILLP_UNUSED_PARA(protocol);

    udpSock->udpSock = FILLP_SOCKET(domain, (FILLP_INT)SOCK_DGRAM, 0);
    udpSock->addrType = domain;
    if (udpSock->udpSock == -1) {
        SET_ERRNO(FT_OS_GET_ERRNO);
        FILLP_LOGERR("Can't create udp socket errno=%d", FT_OS_GET_ERRNO);
        goto FAIL;
    }
    FILLP_LOGINF("alloc udp socket %d", udpSock->udpSock);
    if (SysioSetSocketOpt(udpSock) != 0) {
        goto FAIL;
    }
    SysioMaxUdpSockSet(udpSock->udpSock);
    FILLP_FD_SET((FILLP_UINT)udpSock->udpSock, g_udpIo.readSet);

    udpSock->pcbHash = (struct SpungePcbhashbucket *)SpungeAlloc(UDP_HASH_TABLE_SIZE,
        sizeof(struct SpungePcbhashbucket), SPUNGE_ALLOC_TYPE_CALLOC);
    if (udpSock->pcbHash == FILLP_NULL_PTR) {
        FILLP_FD_CLR((FILLP_UINT32)udpSock->udpSock, g_udpIo.readSet);
        FILLP_LOGERR("Failed to allocate memory for pcb hash bucket");
        goto FAIL;
    }
    for (i = 0; i < UDP_HASH_TABLE_SIZE; i++) {
        HLIST_INIT(&udpSock->pcbHash[i].list);
    }

    return (void *)udpSock;
FAIL:
    if (udpSock != FILLP_NULL_PTR) {
        if (udpSock->udpSock >= 0) {
            (void)FILLP_CLOSE(udpSock->udpSock);
            udpSock->udpSock = -1;
        }
        SpungeFree(udpSock, SPUNGE_ALLOC_TYPE_CALLOC);
        udpSock = FILLP_NULL_PTR;
    }

    return (void *)udpSock;
}

static int SysioDestroySocketUdp(void *arg)
{
    SysIoUdpSock *udpSock = (SysIoUdpSock *)arg;
    if (udpSock->udpSock >= 0) {
        if (g_udpIo.readSet != FILLP_NULL_PTR) {
            if (FILLP_FD_ISSET(udpSock->udpSock, g_udpIo.readSet)) {
                FILLP_FD_CLR((FILLP_UINT32)udpSock->udpSock, g_udpIo.readSet);
            }
        }
        (void)FILLP_CLOSE(udpSock->udpSock);
        FILLP_LOGINF("close udp socket %d", udpSock->udpSock);
        udpSock->udpSock = -1;
    }

    udpSock->connected = FILLP_FALSE;
    if (udpSock->pcbHash != FILLP_NULL_PTR) {
        SpungeFree(udpSock->pcbHash, SPUNGE_ALLOC_TYPE_CALLOC);
        udpSock->pcbHash = FILLP_NULL_PTR;
    }
    SpungeFree(udpSock, SPUNGE_ALLOC_TYPE_CALLOC);
    return ERR_OK;
}

static int SysioBindUdp(void *argSock, void *argPcb, FILLP_SOCKADDR *addr, FILLP_UINT16 len)
{
    SysIoUdpSock *udpSock = (SysIoUdpSock *)argSock;

    int err = FILLP_BIND(udpSock->udpSock, addr, (FILLP_INT32)len);
    if (err != ERR_OK) {
        FILLP_LOGERR("Bind error");
        return err;
    }

    FILLP_UNUSED_PARA(argPcb);

    return err;
}

static int SysioConnectUdp(void *argSock, void *argPcb)
{
    SysIoUdpSock *udpSock = (SysIoUdpSock *)argSock;
    struct SpungePcb *pcb = (struct SpungePcb *)argPcb;

    FILLP_UINT32 addrHashKey = UtilsAddrHashKey((struct sockaddr_in *)&pcb->remoteAddr);
    HlistAddTail(&udpSock->pcbHash[addrHashKey & (UDP_HASH_TABLE_SIZE - 1)].list, &pcb->hashNode);

    return ERR_OK;
}

static void SysioRemovePcbUdp(void *argSock, void *argPcb)
{
    SysIoUdpSock *udpSock = (SysIoUdpSock *)argSock;
    struct SpungePcb *pcb = (struct SpungePcb*)argPcb;
    if (udpSock->pcbHash == FILLP_NULL_PTR) {
        return;
    }
    FILLP_UINT32 addrHashKey = UtilsAddrHashKey((struct sockaddr_in *)&pcb->remoteAddr);
    struct Hlist *pcbHashList = &(udpSock->pcbHash[addrHashKey & (UDP_HASH_TABLE_SIZE - 1)].list);
    struct HlistNode *node = FILLP_NULL_PTR;
    /* Ipv6 is not supported for raw socket so check is not added */
    if ((pcbHashList != FILLP_NULL_PTR) && !HLIST_EMPTY(pcbHashList)) {
        node = HLIST_FIRST(pcbHashList);
        while (node != FILLP_NULL_PTR) {
            if (node == &pcb->hashNode) {
                break;
            }
            node = node->next;
        }
    }

    if (node != FILLP_NULL_PTR) {
        HlistDelete(pcbHashList, node);
    }
}

static void SysioAddPcbUdp(void *argSock, void *argPcb)
{
    FILLP_UNUSED_PARA(argSock);
    FILLP_UNUSED_PARA(argPcb);
}


static int SysioCanSockReadUdp(void *arg)
{
    SysIoUdpSock *udpSock = (SysIoUdpSock *)arg;
    return FILLP_FD_ISSET(udpSock->udpSock, g_udpIo.readableSet);
}

static int SysioHandlePacketUdp(
    int msgType,
    void *argSock,
    void *argPcb,
    void *argBuf)
{
    SysIoUdpSock *udpSock = (SysIoUdpSock *)argSock;
    struct SpungePcb *pcb = (struct SpungePcb *)argPcb;

    switch (msgType) {
        case FILLP_PKT_TYPE_CONN_CONFIRM: {
            FILLP_UINT32 addrHashKey = UtilsAddrHashKey((struct sockaddr_in *)&pcb->remoteAddr);
            HlistAddTail(&udpSock->pcbHash[addrHashKey & (UDP_HASH_TABLE_SIZE - 1)].list, &pcb->hashNode);
            break;
        }
        default:
            FILLP_LOGERR("Unsupported message type");
            return ERR_PARAM;
    }

    FILLP_UNUSED_PARA(argBuf);

    return ERR_OK;
}

static int SysioGetSocknameUdp(void *argSock, void *name, void *nameLen)
{
    SysIoUdpSock *udpSock = (SysIoUdpSock *)argSock;
    return FILLP_GETSOCKNAME(udpSock->udpSock, name, nameLen);
}

static int SysioSendPacketUdp(
    int msgType,
    void *argSock,
    void *argPcb,
    void *argBuf)
{
    struct SpungePcb *pcb = (struct SpungePcb*)argPcb;
    struct FtNetconn *conn = (struct FtNetconn *)pcb->conn;

    FILLP_UNUSED_PARA(argSock);

    switch (msgType) {
        case FILLP_PKT_TYPE_DATA: {
            struct NetBuf *sendBuf = (struct NetBuf *)argBuf;
            return pcb->fpcb.sendFunc(conn, sendBuf->p, sendBuf->len + FILLP_HLEN, pcb);
        }

        case FILLP_PKT_TYPE_CONN_REQ: {
            return FillpSendConnReq(&pcb->fpcb);
        }

        default:
            FILLP_LOGERR("Unsupported message type");
            return ERR_PARAM;
    }
}

static struct SpungePcb *SysioGetListenSocketByOssock(
    FILLP_CONST struct SockOsSocket *osSock)
{
    struct HlistNode *node = FILLP_NULL_PTR;
    struct FtSocket *sock = FILLP_NULL_PTR;
    FILLP_INT instIndex = SPUNGE_GET_CUR_INSTANCE()->instIndex;

    if ((instIndex < 0) || (instIndex >= MAX_SPUNGEINSTANCE_NUM)) {
        return FILLP_NULL_PTR;
    }

    node = HLIST_FIRST(&g_udpIo.listenPcbList);
    while (node != FILLP_NULL_PTR) {
        sock = SockEntryListenSocket(node);
        if (osSock == sock->netconn->osSocket[instIndex]) {
            return sock->netconn->pcb;
        }
        node = node->next;
    }

    return FILLP_NULL_PTR;
}

static struct SpungePcb *SysioGetPcbFromRemoteaddrUdp(
    struct sockaddr *addr,
    FILLP_CONST struct SockOsSocket *osSock,
    FILLP_CONST struct Hlist *list)
{
    struct HlistNode *node = FILLP_NULL_PTR;
    struct SpungePcb *spcb = FILLP_NULL_PTR;

    if (list != FILLP_NULL_PTR) {
        node = HLIST_FIRST(list);
        while (node != FILLP_NULL_PTR) {
            spcb = SpungePcbHashNodeEntry(node);
            if (UtilsAddrMatch((struct sockaddr_in *)addr, (struct sockaddr_in *)&spcb->remoteAddr)) {
                return spcb;
            }
            spcb = FILLP_NULL_PTR;
            node = node->next;
        }
    }

    /* Now trying to find listen socket */
    return SysioGetListenSocketByOssock(osSock);
}

static void SysioConnectedUdp(void *argSock, void *argOsSock)
{
    SysIoUdpSock *udpSock = (SysIoUdpSock *)argOsSock;
    struct FtSocket *sock = (struct FtSocket *)argSock;

    if (FILLP_CONNECT(udpSock->udpSock, (struct sockaddr *)&sock->netconn->pcb->remoteAddr,
        (FILLP_INT32)UtilsAddrValidLength((struct sockaddr_in *)&sock->netconn->pcb->remoteAddr)) == 0) {
        FILLP_LOGDBG("UDP Connect success!!!!");
        udpSock->connected = FILLP_TRUE;
    } else {
        FILLP_LOGERR("UDP Connect Failure !!!!");
    }
}

#ifdef __cplusplus
}
#endif
