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

#include "pcb.h"
#ifdef FILLP_SUPPORT_GSO
#include "check_gso_support.h"
#endif
#ifdef FILLP_LINUX
#include <netinet/udp.h>
#endif
#include "res.h"
#include "fillp_algorithm.h"
#include "spunge.h"
#include "fillp_mgt_msg_log.h"

#ifdef __cplusplus
extern "C" {
#endif

static FILLP_INT SpungePcbRecv(void *argConn, void **buf, FILLP_INT count)
{
    struct FtNetconn *conn = (struct FtNetconn *)argConn;
    struct FtSocket *sock = (struct FtSocket *)conn->sock;
    FillpErrorType err = FillpQueuePush(conn->pcb->fpcb.recv.recvBox, buf, FILLP_TRUE, (FILLP_UINT)count);
    if (err) {
        FILLP_LOGERR("SpungePcbRecv: FillpQueuePush failed. sockId =%d", sock->index);

        return err;
    }

#ifdef SOCK_RECV_SEM
    {
        FILLP_INT tmp = count;

        while (tmp--) {
            (void)SYS_ARCH_SEM_POST(&SOCK_GET_RECVSEM(sock));
        }
    }
#endif /* SOCK_RECV_SEM */

    SpungeEpollEventCallback(sock, SPUNGE_EPOLLIN, count);

    return ERR_OK;
}

static FILLP_INT SpungePcbSend(void *arg, FILLP_CONST char *buf,
    FILLP_INT size, void *ppcb)
{
    struct FtNetconn *conn = (struct FtNetconn *)arg;
    struct SpungePcb *pcb = (struct SpungePcb *)ppcb;
    struct SockOsSocket *osSock = NETCONN_GET_OSSOCK(conn, SPUNGE_GET_CUR_INSTANCE()->instIndex);

    if (!OS_SOCK_OPS_FUNC_VALID(osSock, send)) {
        return -1;
    }

    FILLP_PKT_SIMPLE_LOG(((struct FtSocket *)conn->sock)->index,
        (FILLP_CONST struct FillpPktHead *)buf, FILLP_DIRECTION_TX);

    if (size != (FILLP_INT) osSock->ioSock->ops->send(osSock->ioSock,
                                                      buf,
                                                      (FILLP_SIZE_T)((FILLP_UINT)size),
                                                      (struct sockaddr *)&pcb->remoteAddr,
                                                      pcb->addrLen)) {
        return -1;
    } else {
        return size;
    }
}

#ifdef FILLP_SUPPORT_GSO
#ifndef UDP_MAX_SEG
#define UDP_MAX_SEG 44
#endif
void SendUdpSegmentCmsg(struct cmsghdr *cm)
{
    FILLP_UINT16 *valp = FILLP_NULL_PTR;
    cm->cmsg_level = SOL_UDP;
    cm->cmsg_type = UDP_SEGMENT;
    cm->cmsg_len = CMSG_LEN(sizeof(FILLP_UINT16));
    valp = (FILLP_UINT16 *)(void *)CMSG_DATA(cm);
    *valp = CFG_MSS;
}

static FILLP_INT SpungePcbSendmsgInner(struct FtNetconn *conn, struct SpungePcb *spcb,
    SysIoUdpSock *udpSock, FILLP_INT size)
{
    struct msghdr mh;
    FILLP_CHAR control[CMSG_SPACE(sizeof(FILLP_UINT16))] = {0};
    int ret;

    if (conn->iovCount == 0) {
        return 0;
    }

    mh.msg_name = (struct sockaddr *)&spcb->remoteAddr;
    mh.msg_namelen = spcb->addrLen;
    mh.msg_iov = conn->sendIov;
    mh.msg_iovlen = conn->iovCount;
    mh.msg_flags = 0;
    if (conn->iovCount == 1) {
        mh.msg_control = FILLP_NULL_PTR;
        mh.msg_controllen = 0;
    } else {
        mh.msg_control = control;
        mh.msg_controllen = sizeof(control);
        SendUdpSegmentCmsg(CMSG_FIRSTHDR(&mh));
    }
    if (sendmsg(udpSock->udpSock, &mh, 0) < 0) {
        ret = -1;
    } else {
        ret = size;
    }
    FILLP_LOGDTL("gso send %zu", conn->iovCount);

    if (ret == -1 && errno == EIO) {
        FILLP_INT sentFail = 0;
        for (size_t i = 0; i < conn->iovCount; i++) {
            /* EIO may be caused by netdevices not support checksum offload, so kernel gso return EIO.
             * As kernel udp gso suggested, fallback to send.
             */
            ret = spcb->fpcb.sendFunc(conn, conn->sendIov[i].iov_base, conn->sendIov[i].iov_len, spcb);
            if (ret <= 0) {
                sentFail = 1;
                break;
            }
        }

        if (sentFail == 0) {
            ret = size;
        } else {
            ret = -1;
        }
        FILLP_LOGERR("fallback to send, ret %d", ret);
        spcb->fpcb.sendmsgEio = FILLP_TRUE;
    }
    conn->iovCount = 0;
    return ret;
}

FILLP_INT SpungePcbSendmsg(void *arg, FILLP_CONST char *buf, FILLP_INT size, void *pcb)
{
    struct FtNetconn *conn = FILLP_NULL_PTR;
    struct SockOsSocket *osSock = FILLP_NULL_PTR;
    struct FillpPcb *fpcb = (struct FillpPcb *)pcb;
    struct SpungePcb *spcb = (struct SpungePcb *)fpcb->spcb;
    FILLP_UINT16 cfgMss = CFG_MSS;
    FILLP_INT ret;
    SysIoUdpSock *udpSock = FILLP_NULL_PTR;
    FILLP_BOOL send = FILLP_FALSE;

    if (buf == FILLP_NULL_PTR) {
        conn = (struct FtNetconn *)spcb->conn;
    } else {
        conn = (struct FtNetconn *)arg;
    }
    osSock = NETCONN_GET_OSSOCK(conn, SPUNGE_GET_CUR_INSTANCE()->instIndex);
    if (osSock == FILLP_NULL_PTR) {
        return -1;
    }

    udpSock = (SysIoUdpSock *)osSock->ioSock;

    if (buf == FILLP_NULL_PTR) {
        ret = SpungePcbSendmsgInner(conn, spcb, udpSock, size);
        return ret;
    }

    if (size < cfgMss) {
        send = FILLP_TRUE;
    }

    conn->sendIov[conn->iovCount].iov_len = (size_t)(FILLP_UINT)size;
    conn->sendIov[conn->iovCount].iov_base = (void *)buf;
    conn->iovCount++;

    if ((conn->iovCount < UDP_MAX_SEG) && (fpcb->isLast == FILLP_FALSE) && send == FILLP_FALSE) {
        return size;
    }
    ret = SpungePcbSendmsgInner(conn, spcb, udpSock, size);
    return ret;
}
#endif
void SpcbAddPcbToSpinst(struct SpungeInstance *inst, struct SpungePcb *pcb)
{
    SpinstAddToPcbList(inst, &pcb->udpNode);
}

void SpcbDeleteFromSpinst(struct SpungeInstance *inst, struct SpungePcb *pcb)
{
    SpinstDeleteFromPcbList(inst, &pcb->udpNode);
}

struct SpungePcb *SpungePcbNew(void *argConn, struct SpungeInstance *inst)
{
    struct SpungePcb *pcb = (struct SpungePcb *)SpungeAlloc(1, sizeof(struct SpungePcb), SPUNGE_ALLOC_TYPE_CALLOC);
    if (pcb == FILLP_NULL_PTR) {
        FILLP_LOGERR("Failed allocate memory for spunge_pcb");
        return FILLP_NULL_PTR;
    }

    pcb->conn = argConn;
    pcb->fpcb.spcb = (void *)pcb;
    pcb->fpcb.resInited = 0;

    pcb->fpcb.mpRecvSize = 0;
    pcb->fpcb.mpSendSize = 0;
    pcb->fpcb.clientCookiePreserveTime = 0;
    pcb->fpcb.pcbInst = inst;
    pcb->fpcb.localUniqueId = 0;
    pcb->fpcb.peerUniqueId = 0;
    pcb->fpcb.send.pktStartNum = FILLP_CRYPTO_RAND();
    pcb->fpcb.send.seqStartNum = FILLP_CRYPTO_RAND();

    pcb->rateControl.recv.curMaxRateLimitation = 0;
    pcb->rateControl.recv.weight = 0;

    pcb->rateControl.send.curMaxRateLimitation = 0;
    pcb->rateControl.send.weight = 0;

    pcb->fpcb.pktSize = (FILLP_MAX_PKT_SIZE - FILLP_HLEN);
    pcb->fpcb.recvFunc = SpungePcbRecv;
    pcb->fpcb.sendFunc = SpungePcbSend;
#ifdef FILLP_SUPPORT_GSO
    pcb->fpcb.sendmsgFunc = SpungePcbSendmsg;
    (void)memset_s(pcb->devName, IFNAMESIZE, 0, IFNAMESIZE);
    pcb->fpcb.sendmsgEio = FILLP_FALSE;
#endif
    pcb->fpcb.isFinAckReceived = FILLP_FALSE;
    SpcbAddPcbToSpinst(inst, pcb);
    return pcb;
}

void SpungePcbSetSendCacheSize(struct SpungePcb *pcb, FILLP_UINT32 cacheSize)
{
    pcb->fpcb.mpSendSize = cacheSize;
}

void SpungePcbSetRecvCacheSize(struct SpungePcb *pcb, FILLP_UINT32 cacheSize)
{
    pcb->fpcb.mpRecvSize = cacheSize;
}

void SpungePcbSetPktSize(struct SpungePcb *pcb, FILLP_UINT32 pktSize)
{
    pcb->fpcb.pktSize = pktSize;
}

void SpungePcbSetOppositeRate(struct SpungePcb *pcb, FILLP_UINT32 rate)
{
    pcb->fpcb.recv.oppositeSetRate = rate;
}

void SpungePcbSetSlowStart(struct SpungePcb *pcb, FILLP_BOOL slowStart)
{
    pcb->fpcb.send.slowStart = slowStart;
}

void SpungePcbSetPackInterval(struct SpungePcb *pcb, FILLP_UINT32 interval)
{
    pcb->fpcb.statistics.pack.packInterval = interval;
    pcb->fpcb.packTimerNode.interval = interval;
    pcb->fpcb.FcTimerNode.interval = interval;
}

void SpungePcbSetAddrType(struct SpungePcb *pcb, FILLP_UINT16 addrType)
{
    pcb->addrType = addrType;
}

void SpungePcbSetLocalPort(struct SpungePcb *pcb, FILLP_INT port)
{
    pcb->localPort = port;
}

void SpungePcbSetDirectlySend(struct SpungePcb *pcb, FILLP_INT directlySend)
{
    pcb->fpcb.send.directlySend = directlySend;
}

void SpungePcbRemove(struct SpungePcb *pcb)
{
    struct FtNetconn *conn = FILLP_NULL_PTR;
    struct SockOsSocket *osSock = FILLP_NULL_PTR;
    if (pcb == FILLP_NULL_PTR) {
        FILLP_LOGERR("SpungePcbRemove: Invalid parameters passed");
        return;
    }

    conn = (struct FtNetconn *)pcb->conn;
    SpcbDeleteFromSpinst(pcb->fpcb.pcbInst, pcb);
    FillpRemovePcb(&pcb->fpcb);
    if (conn != FILLP_NULL_PTR) {
        osSock = NETCONN_GET_OSSOCK(conn, SPUNGE_GET_CUR_INSTANCE()->instIndex);
        if (OS_SOCK_OPS_FUNC_VALID(osSock, removePcb)) {
            // If alloc sock fails, the free code will go to here, sock->netconn->osSocket will be null
            osSock->ioSock->ops->removePcb(osSock->ioSock, conn->pcb);
        }
    }

    SpungeFree(pcb, SPUNGE_ALLOC_TYPE_CALLOC);
}

#ifdef __cplusplus
}
#endif
