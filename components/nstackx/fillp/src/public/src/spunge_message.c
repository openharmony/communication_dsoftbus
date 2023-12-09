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

#include "spunge_stack.h"
#include "spunge_app.h"
#include "res.h"
#include "socket_common.h"
#include "fillp_dfx.h"
#include "spunge_message.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

FillpErrorType SpungePostMsg(struct SpungeInstance *inst, void *value, FILLP_INT type, FILLP_BOOL block)
{
    struct SpungeMsg *msg = FILLP_NULL_PTR;
    FillpErrorType err;

    if ((inst == FILLP_NULL_PTR) || (value == FILLP_NULL_PTR) || (inst->msgPool == FILLP_NULL_PTR)) {
        FILLP_LOGERR("invalid input params");
        return ERR_PARAM;
    }

    err = DympAlloc(inst->msgPool, (void **)&msg, FILLP_FALSE);
    if ((err != ERR_OK) || (msg == FILLP_NULL_PTR)) {
        FILLP_LOGERR("failed to allocate the msgpool\n");
        return err;
    }

    (void)SYS_ARCH_ATOMIC_INC(&inst->msgUsingCount, 1);
    msg->msgType = type;
    msg->value = value;
    msg->block = block;

    err = FillpQueuePush(inst->msgBox, (void *)&msg, FILLP_FALSE, 1);
    if (err != ERR_OK) {
        FILLP_LOGERR("Failed to push the message in msgBox queue , MessageType = %d", type);
        DympFree(msg);
        (void)SYS_ARCH_ATOMIC_DEC(&inst->msgUsingCount, 1);
        return err;
    }

    if (msg->block) {
        if (SYS_ARCH_SEM_WAIT(&msg->syncSem)) {
            FILLP_LOGWAR("sem wait failed");
            (void)SYS_ARCH_ATOMIC_DEC(&inst->msgUsingCount, 1);
            DympFree(msg);
            return ERR_COMM;
        }
        DympFree(msg);
    }
    (void)SYS_ARCH_ATOMIC_DEC(&inst->msgUsingCount, 1);

    return ERR_OK;
}

static void SpungeHandleMsgAllocSock(void *value, struct SpungeInstance *inst)
{
    if (value == FILLP_NULL_PTR) {
        FILLP_LOGERR("Invalid socket");
        return;
    }

    struct SpungeSocketMsg *msg = (struct SpungeSocketMsg *)value;
    struct FtSocket *sock = (struct FtSocket *)msg->sock;
    FILLP_LOGINF("fillp_sock_id:%d", sock->index);
    struct FtNetconn *conn = FillpNetconnAlloc(sock->sockAddrType, inst);
    if (conn == FILLP_NULL_PTR) {
        FILLP_LOGERR("Error to alloc netconn");
        sock->allocState = SOCK_ALLOC_STATE_ERR;
        SET_ERRNO(FILLP_ENOMEM);
        sock->coreErrType[MSG_TYPE_ALLOC_SOCK] = FILLP_EMFILE;
        return;
    }

    NetconnSetRecvCacheSize(conn, sock->resConf.common.recvCache);
    NetconnSetSendCacheSize(conn, sock->resConf.common.sendCache);
    FillpInitNewconnBySock(conn, sock);

    FILLP_LOGINF("conn:recvSize:%u,sendSize:%u,pktSize:%u,opersite:%u,slowStart:%u,addrType:%u",
        sock->resConf.common.sendCache, sock->resConf.common.recvCache, sock->resConf.flowControl.pktSize,
        sock->resConf.flowControl.oppositeSetRate, sock->resConf.flowControl.slowStart, sock->sockAddrType);

    NetconnSetSock(sock, conn);

    struct SockOsSocket *osSock = SpungeAllocSystemSocket(msg->domain, msg->type, msg->protocol);
    if (osSock == FILLP_NULL_PTR) {
        FILLP_LOGERR("sock alloc sys sock failed. socketId=%d", sock->index);
        sock->allocState = SOCK_ALLOC_STATE_ERR;
        FILLP_INT errorNum = FtGetErrno();
        if (errorNum == ERR_OK) {
            SET_ERRNO(FILLP_EMFILE);
            errorNum = FILLP_EMFILE;
        }
        sock->coreErrType[MSG_TYPE_ALLOC_SOCK] = errorNum;
        FillpNetconnDestroy(conn);
        return;
    }

    SockSetOsSocket(sock, osSock);
    sock->coreErrType[MSG_TYPE_ALLOC_SOCK] = ERR_OK;
    sock->netconn->lastErr = ERR_OK;
}

static void SpungeHandleMsgFreeSockEagain(void *value, struct SpungeInstance *inst)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    FILLP_UNUSED_PARA(inst);

    if (value == FILLP_NULL_PTR) {
        FILLP_LOGERR("SpungeHandleMsgFreeSockEagain failed : invalid socket \r\n");
        return;
    }

    sock = (struct FtSocket *)value;
    FILLP_LOGDBG("MSG_TYPE_FREE_SOCK_EAGIN, sock = %d, allocState = %d\n", sock->index, sock->allocState);
    if ((sock->allocState == SOCK_ALLOC_STATE_EPOLL) || (sock->allocState == SOCK_ALLOC_STATE_EPOLL_TO_CLOSE)) {
        SpungEpollClose(sock);
        return;
    }

    SpungeFreeSock(sock);
}

static FILLP_INT SpungeListenMsgCheckState(void *value, struct SpungeInstance *inst,
    struct FtSocket **pSock, struct SockOsSocket **pOsSock)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    struct SockOsSocket *osSock = FILLP_NULL_PTR;
    struct FtNetconn *netconn = FILLP_NULL_PTR;
    int netState;

    if ((value == FILLP_NULL_PTR) || (inst == FILLP_NULL_PTR)) {
        FILLP_LOGERR("invalid param");
        return -1;
    }

    sock = (struct FtSocket *)value;
    FILLP_LOGINF("MSG_TYPE_DO_LISTEN fillp_sock_id:%d,inst:%d", sock->index, inst->instIndex);

    netconn = sock->netconn;
    netState = NETCONN_GET_STATE(netconn);
    if (netState != CONN_STATE_IDLE) {
        FILLP_LOGERR("netconn state error state:%d", netState);
        SET_ERRNO(FILLP_ENOTCONN);
        sock->coreErrType[MSG_TYPE_DO_LISTEN] = ERR_WRONGSTATE;
        return -1;
    }

    FillpNetconnSetState(netconn, CONN_STATE_LISTENING);

    /* For server socket, should listen on every instance */
    osSock = NETCONN_GET_OSSOCK(sock->netconn, inst->instIndex);
    if (osSock == FILLP_NULL_PTR) {
        FILLP_LOGERR("Can't find osSocket, socketId=%d", sock->index);
        sock->allocState = SOCK_ALLOC_STATE_ERR;
        SET_ERRNO(FILLP_ENOMEM);
        sock->coreErrType[MSG_TYPE_DO_LISTEN] = ERR_NO_SOCK;
        return -1;
    }

    sock->coreErrType[MSG_TYPE_DO_LISTEN] = ERR_OK;
    FILLP_SOCK_SET_ERR(sock, ERR_OK);

    *pSock = sock;
    *pOsSock = osSock;

    return FILLP_OK;
}

static void SpungeHandleMsgListen(void *value, struct SpungeInstance *inst)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    struct SockOsSocket *osSock = FILLP_NULL_PTR;
    FILLP_INT err;

    if (SpungeListenMsgCheckState(value, inst, &sock, &osSock) != FILLP_OK) {
        return;
    }

    err = SYS_ARCH_SEM_INIT(&sock->acceptSem, 0);
    if (err != ERR_OK) {
        FILLP_LOGERR("Init accept semaphore error");
        SET_ERRNO(FILLP_EFAULT);
        sock->coreErrType[MSG_TYPE_DO_LISTEN] = ERR_FAILURE;
        return;
    }

    sock->acceptBox =
        FillpQueueCreate("acceptBox", (FILLP_SIZE_T)(unsigned int)sock->listenBacklog, SPUNGE_ALLOC_TYPE_MALLOC);

    if (sock->acceptBox == FILLP_NULL_PTR) {
        FILLP_LOGERR("accept box Queue create failed sock=%d", sock->index);

        SET_ERRNO(FILLP_ENOMEM);
        sock->coreErrType[MSG_TYPE_DO_LISTEN] = ERR_NOBUFS;

        (void)SYS_ARCH_SEM_DESTROY(&sock->acceptSem);
        return;
    }

    FillpQueueSetConsSafe(sock->acceptBox, FILLP_TRUE);
    FillpQueueSetProdSafe(sock->acceptBox, FILLP_TRUE);

    // Listen socket should not report error and out event at  the first time it added to epoll
    sock->errEvent = 0;
    (void)SYS_ARCH_ATOMIC_SET(&sock->sendEvent, 0);
    if (!OS_SOCK_OPS_FUNC_VALID(osSock, listen) || osSock->ioSock->ops->listen(sock) != ERR_OK) {
        sock->coreErrType[MSG_TYPE_DO_LISTEN] = ERR_FAILURE;
        FillpQueueDestroy(sock->acceptBox);
        sock->acceptBox = FILLP_NULL;
        return;
    }
    sock->isListenSock = FILLP_TRUE;
}

static FILLP_INT SpungeConnMsgCheckSockState(struct FtSocket *sock, FILLP_INT connState)
{
    if (connState == CONN_STATE_CONNECTED) {
        SET_ERRNO(FILLP_EISCONN);
        sock->coreErrType[MSG_TYPE_DO_CONNECT] = FILLP_ERR_ISCONN;
        FILLP_LOGERR("Netconn is already connected, fillp_sock_id:%d,state:%d", sock->index, connState);
        return -1;
    }

    if (connState != CONN_STATE_IDLE) {
        if (connState == CONN_STATE_CONNECTING) {
            SET_ERRNO(FILLP_EALREADY);
            sock->coreErrType[MSG_TYPE_DO_CONNECT] = FILLP_ERR_EALREADY;
        } else {
            SET_ERRNO(FILLP_EBADF);
            sock->coreErrType[MSG_TYPE_DO_CONNECT] = ERR_PARAM;
        }

        FILLP_LOGERR("Netconn state is not idle, fillp_sock_id:%d,state:%d", sock->index, connState);
        return -1;
    }
    return ERR_OK;
}

static FILLP_INT SpungeConnMsgGetSock(void *value, struct FtSocket **pSock, struct SockOsSocket **pOsSock)
{
    FillpErrorType err;
    int connState;
    struct SpungeConnectMsg *connMsg = (struct SpungeConnectMsg *)value;
    struct FtSocket *sock = (struct FtSocket *)connMsg->sock;
    struct SockOsSocket *osSock = FILLP_NULL_PTR;

    *pSock = sock;
    if (sock->netconn == FILLP_NULL_PTR) {
        FILLP_LOGERR("sock->netconn is NULL, fillp_sock_id:%d", sock->index);
        SET_ERRNO(FILLP_EPIPE);
        sock->coreErrType[MSG_TYPE_DO_CONNECT] = ERR_PARAM;
        return -1;
    }

    err = memcpy_s(&sock->netconn->pcb->remoteAddr, sizeof(sock->netconn->pcb->remoteAddr), connMsg->addr,
        connMsg->addrLen);
    if (err != EOK) {
        FILLP_LOGERR("SpungeHandleMsgConnect memcpy_s failed: %d fillp_sock_id:%d", err, sock->index);
        sock->coreErrType[MSG_TYPE_DO_CONNECT] = ERR_PARAM;
        return -1;
    }
    sock->netconn->pcb->addrLen = (FILLP_UINT16)connMsg->addrLen;

    osSock = NETCONN_GET_OSSOCK(sock->netconn, sock->inst->instIndex);
    if (osSock == FILLP_NULL_PTR) {
        FILLP_LOGERR("Can't get osSocket, fillp_sock_id:%d", sock->index);
        sock->coreErrType[MSG_TYPE_DO_CONNECT] = ERR_PARAM;
        return -1;
    }

    connState = NETCONN_GET_STATE(sock->netconn);
    if (SpungeConnMsgCheckSockState(sock, connState) != ERR_OK) {
        return -1;
    }

    *pOsSock = osSock;

    return FILLP_OK;
}

static void SpungeStartConnRetryTimer(struct FillpPcb *fpcb, FILLP_CONST struct FtSocket *sock)
{
    FILLP_TIMING_WHEEL_INIT_NODE(&fpcb->connRetryTimeoutTimerNode);
    fpcb->connRetryTimeoutTimerNode.cbNode.cb = SpungeSendConnectMsg;
    fpcb->connRetryTimeoutTimerNode.cbNode.arg = (void *)sock->netconn;
    fpcb->connRetryTimeoutTimerNode.interval = (FILLP_UINT32)FILLP_UTILS_MS2US(sock->resConf.common.connRetryTimeout);

    FillpEnableConnRetryCheckTimer(fpcb);
}

static void SpungeHandleMsgConnect(void *value, struct SpungeInstance *inst)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    struct SockOsSocket *osSock = FILLP_NULL_PTR;

    if (value == FILLP_NULL_PTR) {
        FILLP_LOGERR("Failed : invalid value");
        return;
    }

    FILLP_UNUSED_PARA(inst);

    if (SpungeConnMsgGetSock(value, &sock, &osSock) != FILLP_OK) {
        goto FAIL;
    }

    if (!OS_SOCK_OPS_FUNC_VALID(osSock, connect) ||
        osSock->ioSock->ops->connect(osSock->ioSock, sock->netconn->pcb) != ERR_OK) {
        FILLP_LOGERR("sysio connect fail");
        SET_ERRNO(FILLP_EINVAL);
        sock->coreErrType[MSG_TYPE_DO_CONNECT] = ERR_PARAM;
        goto FAIL;
    }

    NetconnSetConnectTimeout(sock->netconn, FILLP_UTILS_MS2US((FILLP_LLONG)sock->resConf.common.connectTimeout));
    NetconnSetDirectlySend(sock->netconn, sock->directlySend);

    SpungeStartConnRetryTimer(&sock->netconn->pcb->fpcb, sock);

    FillpNetconnSetState(sock->netconn, CONN_STATE_CONNECTING);

    if (!OS_SOCK_OPS_FUNC_VALID(osSock, sendPacket) ||
        (osSock->ioSock->ops->sendPacket(FILLP_PKT_TYPE_CONN_REQ, (void *)osSock->ioSock,
        (void *)sock->netconn->pcb, FILLP_NULL_PTR) == -1)) {
        FillpDisableConnRetryCheckTimer(&sock->netconn->pcb->fpcb);
        SET_ERRNO(FILLP_ECONNREFUSED);
        sock->coreErrType[MSG_TYPE_DO_CONNECT] = ERR_CONNREFUSED;
        goto FAIL;
    }

    if (!SOCK_IS_NONBLOCKING(sock)) {
        sock->coreErrType[MSG_TYPE_DO_CONNECT] = ERR_OK;
    } else {
        sock->coreErrType[MSG_TYPE_DO_CONNECT] = ERR_NONBLOCK_UNDERCONNECT;
    }

    if (SOCK_IS_NONBLOCKING(sock)) {
        (void)SYS_ARCH_SEM_POST(&sock->connBlockSem);
    }
    /* IMP: linux do not give HUP while connecting, so do not add any error event.
        Also in linux till connect success and connect fail (during connection establishment) there is
        no event reproted for the socket
    */
    sock->errEvent = 0;
    (void)SYS_ARCH_ATOMIC_SET(&sock->sendEvent, 0);

    return;

FAIL:
    (void)SYS_ARCH_SEM_POST(&sock->connBlockSem);
}

static FILLP_INT SpungeBindMsgCheckState(struct FtSocket *sock, struct SockOsSocket **pOsSock,
    struct FtNetconn **pConn, struct SpungePcb **pPcb)
{
    struct SockOsSocket *osSock = FILLP_NULL_PTR;
    struct FtNetconn *conn = FILLP_NULL_PTR;
    struct SpungePcb *pcb = FILLP_NULL_PTR;
    FILLP_INT connState;

    conn = sock->netconn;
    if (conn == FILLP_NULL_PTR) {
        FILLP_LOGERR("conn is NULL fillp_sock_id:%d", sock->index);
        sock->coreErrType[MSG_TYPE_DO_BIND] = FILLP_ERR_CONN;
        SET_ERRNO(FILLP_EBADF);
        return -1;
    }

    pcb = conn->pcb;
    if (pcb == FILLP_NULL_PTR) {
        sock->coreErrType[MSG_TYPE_DO_BIND] = FILLP_ERR_CONN;
        FILLP_LOGERR("PCB is null fillp_sock_id:%d", sock->index);
        SET_ERRNO(FILLP_EBADF);
        return -1;
    }

    connState = NETCONN_GET_STATE(sock->netconn);
    if (connState != CONN_STATE_IDLE) {
        sock->coreErrType[MSG_TYPE_DO_BIND] = FILLP_ERR_CONN;
        FILLP_LOGERR("Connect state is not idle fillp_sock_id:%d", sock->index);
        SET_ERRNO(FILLP_EBADF);
        return -1;
    }

    osSock = NETCONN_GET_OSSOCK(sock->netconn, sock->inst->instIndex);

    if (sock->isSockBind) {
        sock->coreErrType[MSG_TYPE_DO_BIND] = ERR_NO_REBIND;
        FILLP_LOGERR("Socket already do bind before fillp_sock_id:%d", sock->index);
        SET_ERRNO(FILLP_EADDRINUSE);
        return -1;
    }

    *pOsSock = osSock;
    *pConn = conn;
    *pPcb = pcb;

    return FILLP_OK;
}

static void SpungeHandleMsgBind(void *value, struct SpungeInstance *inst)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    struct SockOsSocket *osSock = FILLP_NULL_PTR;
    struct FtNetconn *conn = FILLP_NULL_PTR;
    struct SpungePcb *pcb = FILLP_NULL_PTR;

    FillpErrorType err;
    FILLP_UINT32 addrLen;
    struct SpungeBindMsg *bindMsg = FILLP_NULL_PTR;
    struct sockaddr_in *localAddr = FILLP_NULL_PTR;
    FILLP_INT sysErrno;

    FILLP_UNUSED_PARA(inst);

    bindMsg = (struct SpungeBindMsg *)value;
    sock = (struct FtSocket *)bindMsg->sock;
    localAddr = bindMsg->addr;
    addrLen = bindMsg->addrLen;

    if (SpungeBindMsgCheckState(sock, &osSock, &conn, &pcb) != FILLP_OK) {
        return;
    }

    err = memcpy_s(&pcb->localAddr, sizeof(pcb->localAddr), localAddr, addrLen);
    if (err != ERR_OK) {
        FILLP_LOGERR("memcpy_s failed with errcode %d", err);
        SET_ERRNO(FILLP_EINVAL);
        sock->coreErrType[MSG_TYPE_DO_BIND] = ERR_NOBUFS;
        return;
    }
    NetconnSetLocalPort(conn, ((struct sockaddr_in *)(&pcb->localAddr))->sin_port);

    if (!OS_SOCK_OPS_FUNC_VALID(osSock, bind)) {
        FILLP_LOGERR("os sock ops bind is null");
        SET_ERRNO(FILLP_EOPNOTSUPP);
        sock->coreErrType[MSG_TYPE_DO_BIND] = ERR_COMM;
        return;
    }

    err = osSock->ioSock->ops->bind((void *)osSock->ioSock, (void *)conn->pcb, (struct sockaddr *)&pcb->localAddr,
        (FILLP_UINT16)addrLen);
    if (err != ERR_OK) {
        sysErrno = FT_OS_GET_ERRNO;
        FILLP_LOGERR("system bind fail sock=%d,err=%d, sysErrno=%d", sock->index, err, sysErrno);

        if (sysErrno == FILLP_EADDRINUSE) {
            sock->coreErrType[MSG_TYPE_DO_BIND] = ERR_NO_REBIND;
        } else {
            sock->coreErrType[MSG_TYPE_DO_BIND] = ERR_SOCK_BIND;
        }
        SET_ERRNO(sysErrno);
        return;
    }

    sock->coreErrType[MSG_TYPE_DO_BIND] = ERR_OK;
    sock->isSockBind = FILLP_TRUE;
}

static void SpungeHandleMsgConnAccepted(void *value, struct SpungeInstance *inst)
{
    struct FtSocket *listenSock = FILLP_NULL_PTR;
    struct FtSocket *sock = FILLP_NULL_PTR;
    struct SpungeAcceptMsg *acceptMsg = FILLP_NULL_PTR;
    struct FtNetconn *netconn = FILLP_NULL_PTR;

    if (value == FILLP_NULL_PTR) {
        FILLP_LOGERR("Value is NULL");
        return;
    }

    acceptMsg = (struct SpungeAcceptMsg *)value;
    listenSock = (struct FtSocket *)acceptMsg->listenSock;
    netconn = (struct FtNetconn *)acceptMsg->netconn;

    sock = SpungeAllocSock(SOCK_ALLOC_STATE_COMM);
    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("Can't alloc socket!!!");
        SET_ERRNO(FILLP_ENOMEM);
        listenSock->coreErrType[MSG_TYPE_NETCONN_ACCPETED] = ERR_NORES;
        return;
    }

    sock->dataOptionFlag = 0;
    (void)SockUpdatePktDataOpt(sock, listenSock->dataOptionFlag, 0);
    sock->fillpLinger = listenSock->fillpLinger;

    /* Copy the traace handle from server listen socket to newly accepting socket */
    sock->traceFlag = listenSock->traceFlag;

    sock->traceHandle = listenSock->traceHandle;
    sock->sockAddrType = listenSock->sockAddrType;

    NetconnSetSock(sock, netconn);

    listenSock->listenBacklog++;

    sock->sockAddrType = netconn->pcb->addrType;
    FillpSendConnConfirmAck(&netconn->pcb->fpcb);

    sock->resConf.flowControl.pktSize = (FILLP_UINT16)netconn->pcb->fpcb.pktSize;
    /* Check the connection max rate, it should not be configured to more
        than the core max rate */
    sock->resConf.flowControl.maxRate = UTILS_MIN(sock->resConf.flowControl.maxRate, g_resource.flowControl.maxRate);
    sock->resConf.flowControl.maxRecvRate = UTILS_MIN(sock->resConf.flowControl.maxRecvRate,
                                                      g_resource.flowControl.maxRecvRate);

    FILLP_LOGINF("fillp_sock_id:%d "
        "Accepted connection established time = %lld, local seq num = %u, "
        "local pkt num = %u, peer seq num = %u peer pkt num = %u, maxRate= %u maxRecvRate= %u",
        sock->index, SYS_ARCH_GET_CUR_TIME_LONGLONG(), netconn->pcb->fpcb.send.seqNum, netconn->pcb->fpcb.send.pktNum,
        netconn->pcb->fpcb.recv.seqNum, netconn->pcb->fpcb.recv.pktNum, sock->resConf.flowControl.maxRate,
        sock->resConf.flowControl.maxRecvRate);

    FillpNetconnSetState(netconn, CONN_STATE_CONNECTED);

    sock->coreErrType[MSG_TYPE_NETCONN_ACCPETED] = ERR_OK;
    FillpNetconnSetSafeErr(netconn, ERR_OK);

    /* We just reset the err event because if already connected */
    sock->errEvent = 0;
    (void)SYS_ARCH_ATOMIC_SET(&sock->sendEvent, 1);

    (void)SYS_ARCH_ATOMIC_SET(&sock->sendEventCount, (FILLP_INT)netconn->pcb->fpcb.send.curItemCount);

    /* Implementing Fair Bandwidth sharing among sockets */
    inst->rateControl.connectionNum++;
}

static void SpungeHandleMsgDoShutdown(void *value, struct SpungeInstance *inst)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    struct FtNetconn *conn = FILLP_NULL_PTR;
    FILLP_UINT8 connState;
    FILLP_INT writeShut = FILLP_FALSE;
    FILLP_INT readShut = FILLP_FALSE;
    FILLP_INT howValue;
    int evt;
    struct SpungeShutdownMsg *shutdownMsg = FILLP_NULL_PTR;

    if (value == FILLP_NULL_PTR) {
        FILLP_LOGERR("NULL value");
        return;
    }

    FILLP_UNUSED_PARA(inst);

    shutdownMsg = (struct SpungeShutdownMsg *)value;
    howValue = shutdownMsg->how;

    sock = (struct FtSocket *)shutdownMsg->sock;
    conn = sock->netconn;
    connState = NETCONN_GET_STATE(conn);
    if (!((connState == CONN_STATE_CONNECTED) || (connState == CONN_STATE_CLOSING))) {
        goto FINISH;
    }

    if (((howValue == SPUNGE_SHUT_RD) || (howValue == SPUNGE_SHUT_RDWR)) && !conn->shutdownRdSet) {
        readShut = FILLP_TRUE;
    }

    if (((howValue == SPUNGE_SHUT_WR) || (howValue == SPUNGE_SHUT_RDWR)) && !conn->shutdownWrSet) {
        writeShut = FILLP_TRUE;
    }

    if ((writeShut == FILLP_FALSE) && (readShut == FILLP_FALSE)) {
        FILLP_LOGERR("Already shutdown before fillp_sock_id:%d,how:%d", sock->index, shutdownMsg->how);
        goto FINISH;
    }

    FillpDfxSockLinkAndQosNotify(sock, FILLP_DFX_LINK_CLOSE);
    SpungeShutdownSock(sock, howValue);

    if (readShut && writeShut) {
        evt = (FILLP_INT)SPUNGE_EPOLLIN | (FILLP_INT)SPUNGE_EPOLLOUT | (FILLP_INT)SPUNGE_EPOLLRDHUP |
            (FILLP_INT)SPUNGE_EPOLLHUP;
    } else if (readShut) {
        evt = (FILLP_INT)SPUNGE_EPOLLIN | (FILLP_INT)SPUNGE_EPOLLOUT | (FILLP_INT)SPUNGE_EPOLLRDHUP;
    } else { // just writeShut
        evt = (FILLP_INT)SPUNGE_EPOLLOUT;
    }
    SpungeEpollEventCallback(sock, evt, 1);

    if (writeShut) { // Need to check the status
        FillpEnableFinCheckTimer(&conn->pcb->fpcb);
    }

FINISH:
    sock->coreErrType[MSG_TYPE_DO_SHUTDOWN] = ERR_OK;
}

static void SpungeCloseMsgFreeSrc(struct FtNetconn *conn, struct FtSocket *sock)
{
    /* To check if this netconn can release resource or not */
    switch (NETCONN_GET_STATE(conn)) {
        case CONN_STATE_IDLE:
        case CONN_STATE_CLOSED:
        case CONN_STATE_LISTENING:
            /* Release resource */
            SpungeFreeSock(sock);
            break;
        case CONN_STATE_CONNECTING:
            FillpDisableConnRetryCheckTimer(&conn->pcb->fpcb);
            SET_ERRNO(FILLP_ETIMEDOUT);
            sock->coreErrType[MSG_TYPE_DO_CONNECT] = ERR_CONN_TIMEOUT;
            if (SOCK_IS_NONBLOCKING(sock)) {
                FILLP_SOCK_SET_ERR(sock, FILLP_ECONNREFUSED);
                FillpNetconnSetSafeErr(conn, ERR_CONNREFUSED);
            } else {
                FillpNetconnSetSafeErr(conn, ERR_CONN_TIMEOUT);
            }
            SpungeConnConnectFail(sock);
            SpungeFreeSock(sock);
            break;
        /* once in closing state, this means socket is waiting to close(processing fin)and finCheckTimer is working */
        case CONN_STATE_CLOSING:
            break;
        case CONN_STATE_CONNECTED:
            FillpEnableFinCheckTimer(&conn->pcb->fpcb);
            break;
        default:
            break;
    }
}

static void SpungeHandleMsgClose(void *value, struct SpungeInstance *inst)
{
    struct FtNetconn *conn = FILLP_NULL_PTR;
    struct FtSocket *sock = (struct FtSocket *)value;

    FILLP_UNUSED_PARA(inst);

    /* If it already did close before */
    if ((sock->allocState != SOCK_ALLOC_STATE_COMM) && (sock->allocState != SOCK_ALLOC_STATE_EPOLL)) {
        FILLP_LOGINF("Can't close fillp_sock_id:%d,allocState:%d", sock->index, sock->allocState);
        SET_ERRNO(FILLP_EINVAL);
        sock->coreErrType[MSG_TYPE_DO_CLOSE] = ERR_UNDERCLOSURE;
        return;
    }

    if ((sock->allocState == SOCK_ALLOC_STATE_EPOLL) || (sock->allocState == SOCK_ALLOC_STATE_EPOLL_TO_CLOSE)) {
        SpungEpollClose(sock);
        sock->coreErrType[MSG_TYPE_DO_CLOSE] = ERR_OK;
        return;
    }

    /* Application has called FtClose, so remove all epoll events */
    {
        struct HlistNode *node = FILLP_NULL_PTR;
        struct EpItem *epi = FILLP_NULL_PTR;

        if (SYS_ARCH_SEM_WAIT(&(sock->epollTaskListLock))) {
            FILLP_LOGERR("Error to wait epollTaskListLock");
            SET_ERRNO(FILLP_EBUSY);
            sock->coreErrType[MSG_TYPE_DO_CLOSE] = ERR_COMM;
            return;
        }
        node = HLIST_FIRST(&sock->epTaskList);
        while (node != FILLP_NULL_PTR) {
            epi = EpitemEntrySockWaitNode(node);
            epi->event.events = 0;
            node = node->next;
        }

        (void)SYS_ARCH_SEM_POST(&(sock->epollTaskListLock));
    }

    conn = sock->netconn;
    conn->closeSet = 1;
    sock->allocState = SOCK_ALLOC_STATE_WAIT_TO_CLOSE;

    FillpDfxSockLinkAndQosNotify(sock, FILLP_DFX_LINK_CLOSE);
    SpungeShutdownSock(sock, SPUNGE_SHUT_RDWR);

    SpungeCloseMsgFreeSrc(conn, sock);

    sock->coreErrType[MSG_TYPE_DO_CLOSE] = ERR_OK;
}

static void SpungeHandleMsgSetSendBuf(void *value, struct SpungeInstance *inst)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    struct SockOsSocket *osSock = FILLP_NULL_PTR;
    int sysosSocket;
    FILLP_INT ret;
    FILLP_UNUSED_PARA(inst);

    if (value == FILLP_NULL_PTR) {
        FILLP_LOGERR("SpungeHandleMsgSetSendBuf value is NULL");
        return;
    }

    sock = (struct FtSocket *)value;
    osSock = NETCONN_GET_OSSOCK(sock->netconn, sock->inst->instIndex);
    if (!OS_SOCK_OPS_FUNC_VALID(osSock, getOsSocket)) {
        sock->coreErrType[MSG_TYPE_SET_SEND_BUF] = ERR_PARAM;
        FILLP_LOGERR("fillp_sock_id:%d Failed to set the send Buffer size for system socket : not allocated",
            sock->index);
        return;
    }

    sysosSocket = osSock->ioSock->ops->getOsSocket(osSock->ioSock);
    ret = SysArchSetSockSndbuf(sysosSocket, sock->resConf.common.udpSendBufSize);
    if (ret != ERR_OK) {
        sock->coreErrType[MSG_TYPE_SET_SEND_BUF] = ERR_FAILURE;
        FILLP_LOGERR("fillp_sock_id:%d Failed to set the send Buffer size for syssocketId = %d",
            sock->index, sysosSocket);
        return;
    }

    sock->coreErrType[MSG_TYPE_SET_SEND_BUF] = ERR_OK;
}

static void SpungeHandleMsgSetRecvBuf(void *value, struct SpungeInstance *inst)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    struct SockOsSocket *osSock = FILLP_NULL_PTR;
    FILLP_INT ret;
    int sysosSocket;
    FILLP_UNUSED_PARA(inst);

    if (value == FILLP_NULL_PTR) {
        FILLP_LOGERR("SpungeHandleMsgSetRecvBuf value is NULL");
        return;
    }

    sock = (struct FtSocket *)value;

    osSock = NETCONN_GET_OSSOCK(sock->netconn, sock->inst->instIndex);
    if (!OS_SOCK_OPS_FUNC_VALID(osSock, getOsSocket)) {
        sock->coreErrType[MSG_TYPE_SET_RECV_BUF] = ERR_PARAM;
        FILLP_LOGERR("fillp_sock_id:%d Failed to set the receive Buffer size for system socket : not allocated",
            sock->index);
        return;
    }

    sysosSocket = osSock->ioSock->ops->getOsSocket(osSock->ioSock);
    ret = SysArchSetSockRcvbuf(sysosSocket, sock->resConf.common.recvBufSize);
    if (ret != ERR_OK) {
        sock->coreErrType[MSG_TYPE_SET_RECV_BUF] = ERR_FAILURE;
        FILLP_LOGERR("fillp_sock_id:%d Failed to set the receive Buffer size for syssocketId = %d",
            sock->index, sysosSocket);
        return;
    }

    sock->coreErrType[MSG_TYPE_SET_RECV_BUF] = ERR_OK;
}

static void SpungeHandleMsgSetNackDelay(void *value, struct SpungeInstance *inst)
{
    struct NackDelayCfg *cfg = FILLP_NULL_PTR;
    struct HlistNode *pcbNode = FILLP_NULL_PTR;
    struct SpungePcb *pcb = FILLP_NULL_PTR;

    if (value == FILLP_NULL_PTR) {
        FILLP_LOGERR("SpungeHandleMsgSetRecvBuf value is NULL");
        return;
    }

    FILLP_UNUSED_PARA(inst);

    cfg = (struct NackDelayCfg *)value;

    if (cfg->nackCfgVal) {
        pcbNode = HLIST_FIRST(&SPUNGE_GET_CUR_INSTANCE()->pcbList.list);
        while (pcbNode != FILLP_NULL_PTR) {
            pcb = SpungePcbListNodeEntry(pcbNode);
            pcbNode = pcbNode->next;
            pcb->fpcb.delayNackTimerNode.interval = (FILLP_UINT32)cfg->nackDelayTimeout;
            if ((((struct FtNetconn *)pcb->conn)->state == CONN_STATE_CONNECTED) ||
                ((struct FtNetconn *)pcb->conn)->state == CONN_STATE_CLOSING) {
                FillpEnableDelayNackTimer(&pcb->fpcb);
            } else {
                /* update socket config */
                ((struct FtSocket *)(((struct FtNetconn *)pcb->conn)->sock))->resConf.common.nackDelayTimeout =
                    (FILLP_UINT32)cfg->nackDelayTimeout;
            }
        }
    }

    SpungeFree(cfg, SPUNGE_ALLOC_TYPE_MALLOC);
}

static void SpungeHandleMsgGetEvtInfo(void *value, struct SpungeInstance *inst)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    FtEventCbkInfo *info = FILLP_NULL_PTR;
    struct SpungeEvtInfoMsg *msg = FILLP_NULL_PTR;

    if (value == FILLP_NULL_PTR) {
        FILLP_LOGERR("value is NULL");
        return;
    }

    FILLP_UNUSED_PARA(inst);
    msg = (struct SpungeEvtInfoMsg *)value;
    sock = (struct FtSocket *)msg->sock;
    info = msg->info;

    FILLP_UNUSED_PARA(info);
    sock->coreErrType[MSG_TYPE_GET_EVENT_INFO] = ERR_PARAM;
}

static void SpungeHandleMsgSetKeepAlive(void *value, struct SpungeInstance *inst)
{
    struct FtSocket *sock = FILLP_NULL_PTR;

    if (value == FILLP_NULL_PTR) {
        FILLP_LOGERR("value is NULL");
        return;
    }

    FILLP_UNUSED_PARA(inst);
    sock = (struct FtSocket *)value;
    if (sock->netconn != FILLP_NULL_PTR && sock->netconn->pcb != FILLP_NULL_PTR &&
        sock->netconn->state == CONN_STATE_CONNECTED) {
        struct FillpPcb *pcb = &sock->netconn->pcb->fpcb;
        FillpDisableKeepAliveTimer(pcb);
        pcb->keepAliveTimerNode.interval = FILLP_UTILS_MS2US(sock->resConf.common.keepAliveTime);
        FillpEnableKeepAliveTimer(pcb);
        FILLP_LOGINF("set the keepalive interval to %u ms", sock->resConf.common.keepAliveTime);
    }

    sock->coreErrType[MSG_TYPE_SET_KEEP_ALIVE] = ERR_OK;
}

static void SpungeHandleMsgSetHiEventCb(void *value, struct SpungeInstance *inst)
{
    struct SpungeHiEventCbMsg *msg = (struct SpungeHiEventCbMsg *)value;
    if (value == FILLP_NULL_PTR) {
        FILLP_LOGERR("value is NULL");
        return;
    }
    FILLP_UNUSED_PARA(inst);
    FillpDfxDoEvtCbSet(msg->softObj, msg->cb);
}

/*
Description: Message handler
Value Range: None
Access: Message handler to handle different types of messages like alloc socket, free socket, etc.,
Remarks:
*/
spungeMsgHandler g_msgHandler[MSG_TYPE_END] = {
    SpungeHandleMsgAllocSock,               /* MSG_TYPE_ALLOC_SOCK  */
    SpungeHandleMsgFreeSockEagain,          /* MSG_TYPE_FREE_SOCK_EAGAIN */
    SpungeHandleMsgListen,                  /* MSG_TYPE_DO_LISTEN */
    SpungeHandleMsgConnect,                 /* MSG_TYPE_DO_CONNECT */
    SpungeHandleMsgBind,                    /* MSG_TYPE_DO_BIND */
    SpungeHandleMsgConnAccepted,            /* MSG_TYPE_NETCONN_ACCPETED */
    SpungeHandleMsgClose,                   /* MSG_TYPE_DO_CLOSE */
    SpungeHandleMsgDoShutdown,              /* MSG_TYPE_DO_SHUTDOWN */
    SpungeHandleMsgSetSendBuf,              /* MSG_TYPE_SET_SEND_BUF */
    SpungeHandleMsgSetRecvBuf,              /* MSG_TYPE_SET_RECV_BUF */
    SpungeHandleMsgSetNackDelay,            /* MSG_TYPE_SET_NACK_DELAY */
    SpungeHandleMsgGetEvtInfo,              /* MSG_TYPE_GET_EVENT_INFO */
    SpungeHandleMsgSetKeepAlive,            /* MSG_TYPE_SET_KEEP_ALIVE */
    SpungeHandleMsgSetHiEventCb,            /* MSG_TYPE_SET_HIEVENT_CB */
};

static FILLP_INT SpungeMsgCreatePoolCb(DympItemType *item)
{
    FILLP_INT ret;
    struct SpungeMsg *msg = (struct SpungeMsg *)DYMP_ITEM_DATA(item);
    ret = SYS_ARCH_SEM_INIT(&msg->syncSem, 0);
    if (ret != FILLP_OK) {
        FILLP_LOGERR("SpungeMsgCreatePoolCb:SYS_ARCH_SEM_INIT fails ALARM !! \r\n");
    }

    return ret;
}

static void SpungeMsgDestroyPoolCb(DympItemType *item)
{
    FILLP_INT ret;
    struct SpungeMsg *msg = (struct SpungeMsg *)DYMP_ITEM_DATA(item);
    ret = SYS_ARCH_SEM_DESTROY(&msg->syncSem);
    if (ret != FILLP_OK) {
        FILLP_LOGERR("sys arch sem destroy failed ALARM !!\n");
    }
}

void *SpungeMsgCreatePool(int initSize, int maxSize)
{
    DympoolItemOperaCbSt itemOperaCb = {SpungeMsgCreatePoolCb, SpungeMsgDestroyPoolCb};
    return DympCreatePool(initSize, maxSize, sizeof(struct SpungeMsg), FILLP_TRUE,
                          &itemOperaCb);
}

void SpungeMsgPoolDestroy(DympoolType *msgPool)
{
    DympDestroyPool(msgPool);
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
