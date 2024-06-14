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

#include "epoll_app.h"
#include "spunge_app.h"
#include "res.h"
#include "fillp_flow_control.h"
#include "spunge_message.h"
#include "socket_common.h"
#include "fillp_common.h"
#include "spunge_stack.h"

#ifdef __cplusplus
extern "C" {
#endif

struct SockOsSocket *SpungeAllocSystemSocket(FILLP_INT domain, FILLP_INT type, FILLP_INT protocol)
{
    struct SpungeInstance *curInst = SPUNGE_GET_CUR_INSTANCE();
    struct SockOsSocket *osSock;

    osSock = (struct SockOsSocket *)SpungeAlloc(1, sizeof(struct SockOsSocket), SPUNGE_ALLOC_TYPE_CALLOC);
    if (osSock == FILLP_NULL_PTR) {
        FILLP_LOGERR("Failed to allocate memory for os socket \r\n");
        return FILLP_NULL_PTR;
    }

    osSock->reference = 0;
    osSock->addrType = domain;

    osSock->ioSock = SysIoSocketFactory(domain, type, protocol);
    if (osSock->ioSock == FILLP_NULL_PTR) {
        FILLP_LOGERR("Alloc osSock fail");
        SpungeFree(osSock, SPUNGE_ALLOC_TYPE_CALLOC);
        osSock = FILLP_NULL_PTR;
        return osSock;
    }

    HLIST_INIT_NODE(&osSock->osListNode);
    HlistAddTail(&curInst->osSockist, &osSock->osListNode);

    return osSock;
}

static void SpungeEpollFreeResource(struct FtSocket *sock)
{
    FILLP_UINT32 i;

    HLIST_INIT(&sock->epTaskList);

    if (sock->eventEpoll != FILLP_NULL_PTR) {
        (void)SYS_ARCH_SEM_DESTROY(&sock->eventEpoll->waitSem);

        (void)SYS_ARCH_SEM_DESTROY(&sock->eventEpoll->appCoreSem);

        (void)SYS_ARCH_SEM_DESTROY(&sock->eventEpoll->appSem);
    }

    /* Scan the epoll instance list to which this FtSocket is associated with */
    for (i = 0; i < FILLP_NUM_OF_EPOLL_INSTANCE_SUPPORTED; i++) {
        /* Delete happens from higher array index to lower array index. So until
           the 0th index is cleared, continue to remove epoll instance
        */
        if (sock->associatedEpollInstanceArr[0] != FILLP_INVALID_INT) {
            struct FtSocket *epollSock = FILLP_NULL_PTR;
            FILLP_INT assIdex = sock->associatedEpollInstanceArr[0];

            if ((assIdex < 0) || (assIdex >= SYS_ARCH_ATOMIC_READ(&g_spunge->sockTable->used))) {
                /* Socket index is not in range, skip and continue */
                continue;
            }

            epollSock = g_spunge->sockTable->sockPool[assIdex];

            if (epollSock->allocState == SOCK_ALLOC_STATE_FREE) {
                SpungeDelEpInstFromFtSocket(sock, assIdex);

                /* Socket state is in free state, skip and continue */
                continue;
            }

            (void)SpungeEpollFindRemove(sock->associatedEpollInstanceArr[0], sock->index);
        }
    }

    sock->associatedEpollInstanceIdx = 0;

    (void)SYS_ARCH_ATOMIC_SET(&sock->rcvEvent, 0);
    (void)SYS_ARCH_ATOMIC_SET(&sock->sendEvent, 0);
    (void)SYS_ARCH_ATOMIC_SET(&sock->sendEventCount, 0);
    sock->errEvent = 0;
}

void SpungeFreeAcceptBox(struct FtSocket *sock)
{
    FILLP_INT i;
    struct FtNetconn *conn = FILLP_NULL_PTR;
    int count;

    for (i = 0; i < SPUNGE_SOCKET_BOX_SIZE; i++) {
        count = FillpQueuePop(sock->acceptBox, (void *)&conn, 1);
        if (count > 0) {
            FillpNetconnDestroy(conn);
        } else {
            break;
        }
    }

    FillpQueueDestroy(sock->acceptBox);
    sock->acceptBox = FILLP_NULL_PTR;
    return;
}

void SpungeIncFreeCntPostEagain(struct FtSocket *sock)
{
    FillpErrorType ret;
    sock->freeTimeCount++;
    FILLP_LOGDBG("fillp_sock_id:%d,sock->freeTimeCount:%d, errno:%d",
        sock->index, sock->freeTimeCount, FT_OS_GET_ERRNO);

    ret = SpungePostMsg(SPUNGE_GET_CUR_INSTANCE(), (void *)sock, MSG_TYPE_FREE_SOCK_EAGAIN, FILLP_FALSE);
    if (ret != ERR_OK) {
        FILLP_LOGERR("FAILED TO POST -- MSG_TYPE_FREE_SOCK_EAGAIN--- to CORE."
            "Socket leak can happen : Sock ID: %d\r\n", sock->index);
    }
}

static void RecursiveRbTree(struct RbNode *node)
{
    struct RbNode *parent = node;
    struct EpItem *epi = FILLP_NULL_PTR;
    struct RbNode *right = FILLP_NULL_PTR;
    struct FtSocket *sock = FILLP_NULL_PTR;
    struct RbNode *left = FILLP_NULL_PTR;

    if (node == FILLP_NULL_PTR) {
        FILLP_LOGERR("RecursiveRbTree: Inavild parameters passed.");
        return;
    }

    left = (struct RbNode *)(parent->rbLeft);

    if (left != FILLP_NULL_PTR) {
        RecursiveRbTree(left);
    }

    right = (struct RbNode *)(parent->rbRight);
    epi = EpItemEntryRbNode(parent);
    if (epi == FILLP_NULL_PTR) {
        FILLP_LOGERR("RecursiveRbTree: EpItemEntryRbNode returns NULL. ");

        return;
    }

    sock = SockGetSocket(epi->fileDespcriptor);
    if (sock != FILLP_NULL_PTR) {
        (void)SYS_ARCH_ATOMIC_DEC(&sock->epollWaiting, 1);

        if (SYS_ARCH_SEM_WAIT(&sock->epollTaskListLock)) {
            FILLP_LOGERR("Error to wait epoll_task_list");
            return;
        }
        HlistDelNode(&epi->sockWaitNode);
        DympFree(epi);
        (void)SYS_ARCH_SEM_POST(&sock->epollTaskListLock);
    }

    if (right != FILLP_NULL_PTR) {
        RecursiveRbTree(right);
    }
}

/*
 * @Description : Closes the epoll socket and releases all associated resources.
 * @param : epoll ft sock index
 * @return : success: ERR_OK  fail: error code
 * @NOTE: caller must have acquired (wait) the close semaphore to protect from MT scenarios. this
 * function on completion will post the event back to semaphore once execution is completed.
 */
void SpungEpollClose(struct FtSocket *sock)
{
    struct EventPoll *ep = (sock->eventEpoll);
    struct RbRoot rtNoe;
    struct RbNode *parent = FILLP_NULL_PTR;
    SYS_ARCH_RW_SEM *sockConnSem = &sock->sockConnSem;

    if (ep == FILLP_NULL_PTR) {
        sock->allocState = SOCK_ALLOC_STATE_FREE;
        FILLP_LOGERR("eventEpoll is NULL. fillp_sock_id:%d", sock->index);
        return;
    }

    if (SYS_ARCH_RWSEM_TRYWRWAIT(sockConnSem) != ERR_OK) {
        int ret;
        sock->allocState = SOCK_ALLOC_STATE_EPOLL_TO_CLOSE;
        (void)SYS_ARCH_SEM_POST(&ep->waitSem);
        ret = SpungePostMsg(SPUNGE_GET_CUR_INSTANCE(), (void *)sock, MSG_TYPE_FREE_SOCK_EAGAIN, FILLP_FALSE);
        if (ret != ERR_OK) {
            FILLP_LOGERR("FAILED TO POST -- MSG_TYPE_FREE_SOCK_EAGAIN--- to CORE."
                "Socket leak can happen : Sock ID: %d", sock->index);
        }
        return;
    }

    rtNoe = ep->rbr;
    parent = rtNoe.rbNode;
    if (parent != FILLP_NULL_PTR) {
        RecursiveRbTree(parent);
    }

    SpungeEpollFreeResource(sock);

    DympFree(sock->eventEpoll);
    sock->eventEpoll = FILLP_NULL_PTR;

    sock->flags = 0;
    sock->traceFlag = 0;
    sock->allocState = SOCK_ALLOC_STATE_FREE;
    sock->freeTimeCount = FILLP_NULL_NUM;
    (void)SYS_ARCH_RWSEM_WRPOST(&sock->sockConnSem);

    (void)FillpQueuePush(g_spunge->sockTable->freeQueqe, (void *)&sock, FILLP_FALSE, 1);
}

static void SpungeCloseCBSocket(struct FtSocket *sock)
{
    if ((FILLP_SOCKETCLOSE_CBK != FILLP_NULL_PTR) && (sock->isListenSock == FILLP_FALSE) &&
        (sock->netconn != FILLP_NULL_PTR) && (sock->netconn->pcb != FILLP_NULL_PTR) &&
        (sock->netconn->state == CONN_STATE_CLOSED)) {
        SysIoUdpSock *udpSock = FILLP_NULL_PTR;
        struct SockOsSocket *osSock = NETCONN_GET_OSSOCK(sock->netconn, sock->inst->instIndex);
        if (osSock != FILLP_NULL_PTR) {
            udpSock = (SysIoUdpSock *)osSock->ioSock;
            FILLP_SOCKETCLOSE_CBK(udpSock->udpSock, (struct sockaddr *)&sock->netconn->pcb->localAddr,
                (struct sockaddr *)&sock->netconn->pcb->remoteAddr);
        }
    }
}

void SpungeFreeSock(struct FtSocket *sock)
{
    if ((sock == FILLP_NULL_PTR) || (sock->allocState == SOCK_ALLOC_STATE_FREE)) {
        return;
    }

    FILLP_LOGDTL("fillp_sock_id:%d", sock->index);
    FillpErrorType ret = SYS_ARCH_RWSEM_TRYWRWAIT(&sock->sockConnSem);
    if (ret != ERR_OK) {
        SpungeIncFreeCntPostEagain(sock);
        return;
    }

    if (sock->allocState != SOCK_ALLOC_STATE_EPOLL) {
        if ((sock->netconn != FILLP_NULL_PTR) && !SpungeConnCheckUnsendBoxEmpty(sock->netconn)) {
            FILLP_LOGDBG("Unsend Box still not empty, fillp_sock_id:%d", sock->index);
            SpungeIncFreeCntPostEagain(sock);
            (void)SYS_ARCH_RWSEM_WRPOST(&sock->sockConnSem);
            return;
        }
    }

    FILLP_LOGINF("spunge_free_start, fillp_sock_id:%d", sock->index);
    SpungeCloseCBSocket(sock);
    SpungeEpollFreeResource(sock);

    if (sock->netconn != FILLP_NULL_PTR) {
        struct SockOsSocket *osSock = NETCONN_GET_OSSOCK(sock->netconn, sock->inst->instIndex);
        if (OS_SOCK_OPS_FUNC_VALID(osSock, freeSock)) {
            osSock->ioSock->ops->freeSock((void *)sock, (void *)osSock);
        }
        FillpNetconnDestroy(sock->netconn);
        sock->netconn = FILLP_NULL_PTR;
    }

    if (sock->acceptBox != FILLP_NULL_PTR) {
        SpungeFreeAcceptBox(sock);
    }

    sock->flags = 0;
    sock->traceFlag = 0;
    if (sock->isListenSock == FILLP_TRUE) {
        (void)SYS_ARCH_SEM_DESTROY(&sock->acceptSem);
        sock->isListenSock = FILLP_FALSE;
    }

    sock->allocState = SOCK_ALLOC_STATE_FREE;
    sock->freeTimeCount = FILLP_NULL_NUM;

    (void)FillpQueuePush(g_spunge->sockTable->freeQueqe, (void *)&sock, FILLP_FALSE, 1);
    (void)SYS_ARCH_RWSEM_WRPOST(&sock->sockConnSem);
}

void SpungeShutdownSock(void *argSock, FILLP_INT how)
{
    struct FtSocket *sock = (struct FtSocket *)argSock;
    struct FtNetconn *netconn = sock->netconn;
    FILLP_INT connState;

    if (netconn == FILLP_NULL_PTR) {
        FILLP_LOGERR("sock->netconn is NULL");
        return;
    }

    connState = NETCONN_GET_STATE(netconn);
    FILLP_LOGINF("Shutdown,fillp_sock_id:%d,connState:%d", sock->index, connState);

    if (((how == SPUNGE_SHUT_RD) || (how == SPUNGE_SHUT_RDWR)) && !netconn->shutdownRdSet) {
        netconn->shutdownRdSet = 1;
#ifdef SOCK_RECV_SEM
        (void)SYS_ARCH_SEM_POST(&SOCK_GET_RECVSEM(sock));
#endif /* SOCK_RECV_SEM */

        if (sock->isListenSock == FILLP_TRUE) {
            (void)SYS_ARCH_SEM_POST(&sock->acceptSem);
        }
    }

    if (((how == SPUNGE_SHUT_WR) || (how == SPUNGE_SHUT_RDWR)) && !netconn->shutdownWrSet) {
        netconn->shutdownWrSet = 1;
        (void)SYS_ARCH_SEM_POST(&SOCK_GET_SENDSEM(sock));
    }
}

FILLP_BOOL SpungeConnCheckUnsendBoxEmpty(struct FtNetconn *conn)
{
    FILLP_ULLONG con;
    FILLP_ULLONG prod;
    void *data = FILLP_NULL_PTR;
    struct FillpPcbItem *item = FILLP_NULL_PTR;
    FillpQueue *unsendBox = FILLP_NULL_PTR;

    if ((conn == FILLP_NULL_PTR) || (conn->pcb == FILLP_NULL_PTR)) {
        FILLP_LOGERR("NULL Pointer");
        return FILLP_TRUE;
    }
    unsendBox = conn->pcb->fpcb.send.unsendBox;

    if (unsendBox == FILLP_NULL_PTR) {
        return FILLP_TRUE;
    }

    con = unsendBox->ring.cons.head + 1;
    prod = unsendBox->ring.prod.tail;

    while ((prod >= con) && ((FILLP_LLONG)(prod - con)) >= 0) {
        data = unsendBox->ring.ringCache[con % unsendBox->ring.size];
        con++;

        if (data == FILLP_NULL_PTR) {
            continue;
        }

        item = (struct FillpPcbItem *)data;
        if (item->netconn == (void *)conn) {
            FILLP_LOGDBG("Still has data in unsedn box");
            return FILLP_FALSE;
        }
    }

    return FILLP_TRUE;
}

static int SpungeDestroyNoWait(struct FillpPcb *pcb, struct FtSocket *sock, struct FtNetconn *conn)
{
#if FILLP_DEFAULT_DESTROY_STACK_WITHOUT_WAIT_SOCKET_CLOSE
    /* for miracast, ignore the unSend unAck and unRecv packets, skip the disconnection flow,
        because app will call FtClose once wifi disconnect, stack can't free socket until
        10s keep alive timeout. That would lead FtDestroy block a long time. */
    if (pcb->pcbInst->waitTobeCoreKilled == FILLP_TRUE) {
        FILLP_LOGERR("ignore unsend packet, skip dissconnetion flow and about to free socket %d", sock->index);
        SpungeConnClosed(conn);
        return 1;
    }
#endif
    return 0;
}

void SpungeCheckDisconn(void *argConn)
{
    struct FtNetconn *conn = (struct FtNetconn *)argConn;
    struct FtSocket *sock = (struct FtSocket *)conn->sock;
    struct FillpPcb *pcb = FILLP_NULL_PTR;
    FILLP_UINT8 connState;
    struct FillpSendPcb *sendPcb = FILLP_NULL_PTR;

    if (sock == FILLP_NULL_PTR || conn->pcb == FILLP_NULL_PTR) {
        FILLP_LOGERR("NULL pointer sock or conn->pcb");
        return;
    }

    pcb = &conn->pcb->fpcb;

    connState = NETCONN_GET_STATE(conn);
    FILLP_LOGDBG("fillp_sock_id:%d", sock->index);
    if (!(connState == CONN_STATE_CONNECTED || connState == CONN_STATE_CLOSING)) {
        FILLP_LOGERR("No need to check disconn message anymore,fillp_sock_id:%d,connState:%u",
            sock->index, connState);
        return;
    }

    if (connState == CONN_STATE_CONNECTED) {
        /* Check all unsend box */
        if (!SpungeConnCheckUnsendBoxEmpty(conn)) {
            goto TIMER_REPEAT;
        }

        if (SpungeDestroyNoWait(pcb, sock, conn) != 0) {
            return;
        }
        /* Check if all send data are sent out */
        sendPcb = &conn->pcb->fpcb.send;
        FillpAckSendPcb(&conn->pcb->fpcb, 0);

        if ((sock->lingering == FILLP_FALSE) && (sendPcb->unackList.count ||
            sendPcb->unrecvList.nodeNum || !HLIST_EMPTY(&sendPcb->unSendList) ||
            sendPcb->itemWaitTokenLists.nodeNum || sendPcb->redunList.nodeNum)) {
            FILLP_LOGDBG("Still has data to send");
            goto TIMER_REPEAT;
        }

        FILLP_LOGINF("Now all unSend data are checked.Going to send fin fillp_sock_id:%d", sock->index);
        conn->sendBufRunOut = FILLP_TRUE;
        /* Need to reconsider the disconn message send */
        FillpNetconnSetState(conn, CONN_STATE_CLOSING);
        pcb->finCheckTimer.interval =
            (FILLP_UINT32)FILLP_UTILS_MS2US((FILLP_LLONG)sock->resConf.common.disconnectRetryTimeout);
    } else if (SpungeDestroyNoWait(pcb, sock, conn) != 0) {
        return;
    }

    if (pcb->isFinAckReceived != FILLP_TRUE) {
        FillpSendFin(pcb);
    }

TIMER_REPEAT:
    FillpEnableFinCheckTimer(pcb);
}

void SpungeSendConnectMsg(void *argConn)
{
    struct FtNetconn *conn = (struct FtNetconn *)argConn;
    struct FtSocket *sock = (struct FtSocket *)conn->sock;
    struct SockOsSocket *osSock = FILLP_NULL_PTR;
    FILLP_UINT8 connState = NETCONN_GET_STATE(conn);
    if (connState != CONN_STATE_CONNECTING) {
        FILLP_LOGINF("socket state = %u is not in connecting state for the conn",
            connState);
        return;
    }

    if (NetconnIsConnectTimeout(conn)) {
        if (sock == FILLP_NULL_PTR) {
            FILLP_LOGWAR("connection state idle for the conn");

            /* No need to stop the conenct timer again, as it is already stopped upon earlier socket_clear */
            return;
        }

        FillpNetconnSetState(conn, CONN_STATE_IDLE);
        SET_ERRNO(FILLP_ETIMEDOUT);
        sock->coreErrType[MSG_TYPE_DO_CONNECT] = ERR_CONN_TIMEOUT;
        if (SOCK_IS_NONBLOCKING(sock)) {
            FILLP_SOCK_SET_ERR(sock, FILLP_ECONNREFUSED);
            FillpNetconnSetSafeErr(conn, ERR_CONNREFUSED);
        } else {
            FillpNetconnSetSafeErr(conn, ERR_CONN_TIMEOUT);
        }

        SpungeConnConnectFail(conn->sock);

        return;
    }

    FillpEnableConnRetryCheckTimer(&conn->pcb->fpcb);

    osSock = NETCONN_GET_OSSOCK(conn, SPUNGE_GET_CUR_INSTANCE()->instIndex);
    if (!OS_SOCK_OPS_FUNC_VALID(osSock, connected) || !OS_SOCK_OPS_FUNC_VALID(osSock, sendPacket)) {
        FILLP_LOGERR("osSock is NULL");
        return;
    }
    osSock->ioSock->ops->connected(sock, osSock->ioSock);
    if (osSock->ioSock->ops->sendPacket(
        FILLP_PKT_TYPE_CONN_REQ, (void *)osSock->ioSock, (void *)conn->pcb, FILLP_NULL_PTR) == -1) {
        FILLP_LOGINF("send conn req fail for sockId:%d", sock->index);
    }
}

void SpinstAddToPcbList(struct SpungeInstance *inst, struct HlistNode *node)
{
    HlistAddTail(&inst->pcbList.list, node);
}

void SpinstDeleteFromPcbList(struct SpungeInstance *inst, struct HlistNode *node)
{
    HlistDelete(&inst->pcbList.list, node);
}

FillpQueue *SpungeAllocUnsendBox(struct SpungeInstance *inst)
{
    return inst->unsendBox[0];
}

void SpungeFreeUnsendBox(struct FillpPcb *pcb)
{
    FILLP_UNUSED_PARA(pcb);
}

/* This function is called when the connection is sure closed
    For : 1) close() involked and rst send out
          2) recved rst from peer
          3) disconnect send out and disconn recved (local and peer send disconnect both)
          if close() involked, the recv box data will be dropped, or the recv() still returns positive if data remains,
          return 0 if all data taken
 */
void SpungeConnClosed(struct FtNetconn *conn)
{
    if (NETCONN_GET_STATE(conn) == CONN_STATE_CLOSED) {
        FILLP_LOGERR("Already closed");
        return;
    }

    if (conn->sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("conn socket is NULL");
        return;
    }

    if (conn->pcb == FILLP_NULL_PTR) {
        FILLP_LOGERR("conn pcb is NULL");
        return;
    }

    FILLP_LOGINF("fillp_sock_id:%d", ((struct FtSocket *)conn->sock)->index);

    FillpNetconnSetState(conn, CONN_STATE_CLOSED);
    FillpPcbRemoveTimers(&conn->pcb->fpcb);

    if (conn->closeSet) {
        /* Try to release the recv box data */
        if (SpungePostMsg(SPUNGE_GET_CUR_INSTANCE(), (void *)((struct FtSocket *)conn->sock),
            MSG_TYPE_FREE_SOCK_EAGAIN, FILLP_FALSE) != ERR_OK) {
            FILLP_LOGERR("FAILED TO POST -- MSG_TYPE_FREE_SOCK_EAGAIN--- to CORE"
                         " Sock ID: %d", ((struct FtSocket*)conn->sock)->index);
        }
    }
}

void SpungeConnConnectSuccess(void *argSock)
{
    struct FtSocket *sock = (struct FtSocket *)argSock;
    if (!SOCK_IS_NONBLOCKING(sock)) {
        (void)SYS_ARCH_SEM_POST(&sock->connBlockSem);
    }

    sock->errEvent = 0;
    SpungeEpollEventCallback(sock, SPUNGE_EPOLLOUT, 1);
}

void SpungeConnConnectFail(void *argSock)
{
    struct FtSocket *sock = (struct FtSocket *)argSock;
    if (!SOCK_IS_NONBLOCKING(sock)) {
        (void)SYS_ARCH_SEM_POST(&sock->connBlockSem);
    }
    sock->errEvent |= (FILLP_UINT32)SPUNGE_EPOLLHUP;
    SpungeEpollEventCallback(sock, (FILLP_INT)SPUNGE_EPOLLOUT | (FILLP_INT)SPUNGE_EPOLLHUP, 1);
}

#ifdef __cplusplus
}
#endif
