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

#include "sockets.h"
#include "spunge.h"
#include "socket_common.h"

#ifdef __cplusplus
extern "C" {
#endif

void EpollUpdateEpEvent(struct EpItem *epi)
{
    struct FtSocket *sock;

    sock = SockGetSocket(epi->fileDespcriptor);
    if (sock == FILLP_NULL_PTR) {
        return;
    }

    epi->revents = (epi->event.events & (FILLP_UINT32)sock->errEvent);
    if ((epi->event.events & SPUNGE_EPOLLIN) && ((SYS_ARCH_ATOMIC_READ(&sock->rcvEvent) > 0) || (sock->offset))) {
        epi->revents |= SPUNGE_EPOLLIN;
    } else {
        epi->revents &= (FILLP_UINT32)(~SPUNGE_EPOLLIN);
    }

    if ((epi->event.events & SPUNGE_EPOLLOUT) && (SYS_ARCH_ATOMIC_READ(&sock->sendEvent) > 0) &&
        (SYS_ARCH_ATOMIC_READ(&sock->sendEventCount) > 0)) {
        epi->revents |= SPUNGE_EPOLLOUT;
    } else {
        epi->revents &= (FILLP_UINT32)(~SPUNGE_EPOLLOUT);
    }
}

/**
 * Callback registered in the netconn layer for each socket-netconn.
 * Processes recvevent (data available) and wakes up tasks waiting for select.
 */
void EpollEventCallback(struct FtSocket *sock, FILLP_UINT32 upEvent)
{
    struct EpItem *sockEpItem = FILLP_NULL_PTR;
    struct HlistNode *epNode = FILLP_NULL_PTR;

    if (HLIST_EMPTY(&sock->epTaskList)) {
        return;
    }

    if (SYS_ARCH_SEM_WAIT(&sock->epollTaskListLock)) {
        FILLP_LOGERR("Error to do sem_wait");
        return;
    }
    epNode = HLIST_FIRST(&sock->epTaskList);
    while (epNode != FILLP_NULL_PTR) {
        sockEpItem = EpitemEntrySockWaitNode(epNode);
        epNode = epNode->next;

        if (!(sockEpItem->event.events & upEvent)) {
            continue;
        }

        sockEpItem->revents |= (sockEpItem->event.events & upEvent);

        if (SYS_ARCH_SEM_WAIT(&sockEpItem->ep->appCoreSem)) {
            FILLP_LOGERR("Error to wait appCoreSem");
            (void)SYS_ARCH_SEM_POST(&sock->epollTaskListLock);
            return;
        }
        EpSocketReady(sockEpItem->ep, sockEpItem);
        (void)SYS_ARCH_SEM_POST(&sockEpItem->ep->appCoreSem);
    }

    (void)SYS_ARCH_SEM_POST(&sock->epollTaskListLock);
}

struct GlobalAppResource g_appResource = {
    {
        FILLP_DEFAULT_APP_TX_BURST,                 /* udp.txBurst */
#ifdef FILLP_64BIT_ALIGN
        0                                           /* udp.reserve */
#endif
    },
    {
        FILLP_DEFAULT_APP_KEEP_ALIVE_TIME,             /* common.keepAliveTime */
        FILLP_DEFAULT_APP_MAX_SERVER_ALLOW_RECV_CACHE, /* common.maxServerAllowRecvCache */
        FILLP_DEFAULT_APP_MAX_SERVER_ALLOW_SEND_CACHE, /* common.maxServerAllowSendCache */
        FILLP_DEFAULT_UDP_SEND_BUFSIZE,                /* common.udpSendBufSize  */
        FILLP_DEFAULT_UDP_RECV_BUFSIZE,                /* common.recvBufSize */
        FILLP_DEFAULT_DISCONNECT_TIMER_INTERVAL,       /* common.disconnectRetrytimeout  */
        FILLP_DEFAULT_APP_SEND_CACHE,                  /* common.sendCache */
        FILLP_DEFAULT_APP_RECV_CACHE,                  /* common.recvCache */
        FILLP_DEFAULT_APP_CONNECT_TIMEOUT,             /* common.connectTimeout */
        0,                                             /* common.reserv */
        FILLP_DEFAULT_CONNECT_RETRY_TIMER_INTERVAL,    /* common.connRetryTimeout */
        FILLP_DELAY_NACK_ENABLE,                       /* common.enableNackDelay */
        FILLP_DEFAULT_ENLARGE_PACK_INTERVAL,           /* common.enlargePackIntervalFlag */
        FILLP_DEFAULT_DAT_OPT_TIMESTAMP_ENABLE,        /* common.enableDateOptTimestamp */
        {
            0,
            0,
            0
        },                                             /* common.pad[] */
        FILLP_DEFAULT_NACK_DELAY_TIME,                 /* common.nackDelayTimeout */
        FILLP_APP_FC_STASTICS_INTERVAL                 /* common.fcStasticsInterval */
    },
    {
        FILLP_DEFAULT_MAX_RATE,                        /* flowControl.maxRate */
        FILLP_DEFAULT_MAX_RECV_RATE,                   /* flowControl.maxRecvRate */
        FILLP_DEFAULT_APP_OPPOSITE_SET_RATE,           /* flowControl.oppositeSetRate */
        FILLP_DEFAULT_APP_PACK_INTERVAL,               /* flowControl.packInterval */
        FILLP_DEFAULT_APP_PKT_SIZE,                    /* flowControl.pktSize */
        FILLP_DEFAULT_APP_SLOW_START,                  /* flowControl.slowStart */
        FILLP_DEFAULT_CONST_RATE_ENABLE,               /* flowControl.constRateEnbale */
        {0}
    }
};

void InitGlobalAppResourceDefault(void)
{
    g_appResource.udp.txBurst = FILLP_DEFAULT_APP_TX_BURST;
    g_appResource.common.keepAliveTime = FILLP_DEFAULT_APP_KEEP_ALIVE_TIME;
    g_appResource.common.recvCache = FILLP_DEFAULT_APP_RECV_CACHE;
    g_appResource.common.maxServerAllowRecvCache = FILLP_DEFAULT_APP_MAX_SERVER_ALLOW_RECV_CACHE;
    g_appResource.common.maxServerAllowSendCache = FILLP_DEFAULT_APP_MAX_SERVER_ALLOW_SEND_CACHE;
    g_appResource.common.udpSendBufSize = FILLP_DEFAULT_UDP_SEND_BUFSIZE;
    g_appResource.common.sendCache = FILLP_DEFAULT_APP_SEND_CACHE;
    g_appResource.common.connectTimeout = FILLP_DEFAULT_APP_CONNECT_TIMEOUT;
    g_appResource.common.connRetryTimeout = FILLP_DEFAULT_CONNECT_RETRY_TIMER_INTERVAL;
    g_appResource.common.disconnectRetryTimeout = FILLP_DEFAULT_DISCONNECT_TIMER_INTERVAL;
    g_appResource.common.recvBufSize = FILLP_DEFAULT_UDP_RECV_BUFSIZE;
    g_appResource.common.enableNackDelay = FILLP_DELAY_NACK_ENABLE;

    g_appResource.common.nackDelayTimeout = FILLP_DEFAULT_NACK_DELAY_TIME;
    g_appResource.common.enlargePackIntervalFlag = FILLP_DEFAULT_ENLARGE_PACK_INTERVAL;
    g_appResource.common.enableDateOptTimestamp = FILLP_DEFAULT_DAT_OPT_TIMESTAMP_ENABLE;
    g_appResource.common.fcStasticsInterval = FILLP_APP_FC_STASTICS_INTERVAL;

    g_appResource.flowControl.constRateEnbale = FILLP_DEFAULT_CONST_RATE_ENABLE;
    g_appResource.flowControl.maxRate = FILLP_DEFAULT_MAX_RATE;
    g_appResource.flowControl.maxRecvRate = FILLP_DEFAULT_MAX_RECV_RATE;

    g_appResource.flowControl.oppositeSetRate = FILLP_DEFAULT_APP_OPPOSITE_SET_RATE;
    g_appResource.flowControl.pktSize = FILLP_DEFAULT_APP_PKT_SIZE;
    g_appResource.flowControl.packInterval = FILLP_DEFAULT_APP_PACK_INTERVAL;
    g_appResource.flowControl.slowStart = FILLP_DEFAULT_APP_SLOW_START;
}

/* Free socket */
/* This is for socket alloc/initial fail, it is only used before socket created and socket index returned to user */
void SockFreeSocket(struct FtSocket *sock)
{
    if (sock == FILLP_NULL_PTR) {
        return;
    }

    (void)FillpQueuePush(g_spunge->sockTable->freeQueqe, (void *)&sock, FILLP_FALSE, 1);
}

static int SpungeInitSocket(struct FtSocketTable *table, int tableIndex)
{
    struct FtSocket *sock;
    FillpErrorType ret;
    sock = table->sockPool[tableIndex];
    sock->index = tableIndex;
    sock->allocState = SOCK_ALLOC_STATE_FREE;
    sock->inst = SPUNGE_GET_CUR_INSTANCE();

    /* initialize all locks here */
    ret = SYS_ARCH_RWSEM_INIT(&sock->sockConnSem);
    if (ret != ERR_OK) { /* SFT */
        FILLP_LOGERR("sock_create_conn_sem returns null, ptr socket id:%d", sock->index);
        return ret;
    }

    ret = SYS_ARCH_SEM_INIT(&sock->connBlockSem, 0);
    if (ret != ERR_OK) { /* SFT */
        (void)SYS_ARCH_RWSEM_DESTROY(&sock->sockConnSem);
        return ret;
    }

    ret = SYS_ARCH_SEM_INIT(&sock->sockCloseProtect, 0);
    if (ret != ERR_OK) {
        (void)SYS_ARCH_RWSEM_DESTROY(&sock->sockConnSem);
        (void)SYS_ARCH_SEM_DESTROY(&sock->connBlockSem);
        return ret;
    }
    ret = SYS_ARCH_SEM_INIT(&sock->epollTaskListLock, 1);
    if (ret != FILLP_OK) {
        (void)SYS_ARCH_RWSEM_DESTROY(&sock->sockConnSem);
        (void)SYS_ARCH_SEM_DESTROY(&sock->connBlockSem);
        (void)SYS_ARCH_SEM_DESTROY(&sock->sockCloseProtect);
        return ret;
    }

    /* TAINTED_ANALYSIS TOOL: NULL_RETURNS */
    if (FillpQueuePush(table->freeQueqe, (void *)&sock, FILLP_TRUE, 1)) {
        FILLP_LOGERR("FillpQueuePush return error sock->index=%d", sock->index);
        (void)SYS_ARCH_RWSEM_DESTROY(&sock->sockConnSem);
        (void)SYS_ARCH_SEM_DESTROY(&sock->connBlockSem);
        (void)SYS_ARCH_SEM_DESTROY(&sock->sockCloseProtect);
        (void)SYS_ARCH_SEM_DESTROY(&sock->epollTaskListLock);
        return FILLP_FAILURE;
    }

    return ERR_OK;
}

static int SpungeAllocFtSock(struct FtSocketTable *table)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    int tableIndex;
    if (table == FILLP_NULL_PTR || table->sockPool == FILLP_NULL_PTR) {
        return FILLP_FAILURE;
    }

    sock = (struct FtSocket *)SpungeAlloc(1, sizeof(struct FtSocket), SPUNGE_ALLOC_TYPE_CALLOC);
    if (sock == FILLP_NULL_PTR) {
        return FILLP_FAILURE;
    }

    while (FILLP_TRUE) {
        tableIndex = SYS_ARCH_ATOMIC_READ(&table->used);
        if (tableIndex >= table->size) {
            SpungeFree(sock, SPUNGE_ALLOC_TYPE_CALLOC);
            return FILLP_FAILURE;
        }

        if (CAS((volatile FILLP_ULONG *)&table->sockPool[tableIndex], (volatile FILLP_ULONG)FILLP_NULL_PTR,
            (volatile FILLP_ULONG)sock) == 0) {
            FILLP_USLEEP(1);
        } else {
            break;
        }
    }

    if (SpungeInitSocket(table, tableIndex) != ERR_OK) {
        table->sockPool[tableIndex] = FILLP_NULL_PTR;
        SpungeFree(sock, SPUNGE_ALLOC_TYPE_CALLOC);
        return FILLP_FAILURE;
    }

    SYS_ARCH_ATOMIC_INC(&table->used, 1);
    return FILLP_OK;
}

struct FtSocket *SockAllocSocket(void)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    FILLP_INT ret;

    while (sock == FILLP_NULL_PTR) {
        ret = FillpQueuePop(g_spunge->sockTable->freeQueqe, (void *)&sock, 1);
        if (ret <= 0) {
            FILLP_LOGDBG("sockets not available from the sockTable->freeQueqe");

            if (SpungeAllocFtSock(g_spunge->sockTable) != FILLP_OK) {
                return FILLP_NULL_PTR;
            }
        }
    }

    return sock;
}

struct FtSocket *SockGetSocket(FILLP_INT sockIndex)
{
    struct FtSocket *sock = FILLP_NULL_PTR;

    if ((g_spunge == FILLP_NULL_PTR) || (!g_spunge->hasInited) || (g_spunge->sockTable == FILLP_NULL_PTR)) {
        FILLP_LOGERR("FILLP Not yet Initialized");

        return FILLP_NULL_PTR;
    }

    if ((sockIndex < 0) || (sockIndex >= SYS_ARCH_ATOMIC_READ(&g_spunge->sockTable->used))) {
        FILLP_LOGERR("index value not in the socket table size range. Index= %d", sockIndex);
        return FILLP_NULL_PTR;
    }

    sock = g_spunge->sockTable->sockPool[sockIndex];

    return sock;
}

struct FtSocket *SockApiGetAndCheck(int sockIdx)
{
    struct FtSocket *sock = SockGetSocket(sockIdx);
    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("Invalid fillp_sock_id:%d", sockIdx);
        SET_ERRNO(FILLP_EBADF);
        return FILLP_NULL_PTR;
    }

    if (SYS_ARCH_RWSEM_TRYRDWAIT(&sock->sockConnSem) != ERR_OK) {
        FILLP_LOGERR("sockConnSem rdwait fail fillp_sock_id:%d", sockIdx);
        SET_ERRNO(FILLP_EBUSY);
        return FILLP_NULL_PTR;
    }

    if (sock->allocState != SOCK_ALLOC_STATE_COMM) {
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        FILLP_LOGERR("sock allocState wrong fillp_sock_id:%d, state:%d", sockIdx, sock->allocState);
        SET_ERRNO(FILLP_ENOTSOCK);
        return FILLP_NULL_PTR;
    }

    return sock;
}

FILLP_BOOL SockCanSendData(FILLP_CONST struct FtSocket *sock)
{
    if ((sock->netconn == FILLP_NULL_PTR) || (sock->netconn->shutdownWrSet)) {
        return FILLP_FALSE;
    }

    int netConnState = NETCONN_GET_STATE(sock->netconn);
    if ((netConnState != CONN_STATE_CONNECTED) &&
        (netConnState != CONN_STATE_CLOSING)) {
        return FILLP_FALSE;
    }

    return FILLP_TRUE;
}

FILLP_BOOL SockCanRecvData(struct FtSocket *sock)
{
    if ((sock->netconn == FILLP_NULL_PTR) || sock->netconn->shutdownRdSet) {
        return FILLP_FALSE;
    }

    int netConnState = NETCONN_GET_STATE(sock->netconn);
    if ((netConnState != CONN_STATE_CONNECTED) &&
        (netConnState != CONN_STATE_CLOSING) &&
        (netConnState != CONN_STATE_CLOSED)) {
        return FILLP_FALSE;
    }

    return FILLP_TRUE;
}

FILLP_INT SockUpdatePktDataOpt(struct FtSocket *sock, FILLP_UINT16 addFlag, FILLP_UINT16 delFlag)
{
    FILLP_UINT16 dataOptLen = 0;
    FILLP_UINT16 dataOptFlag = (sock->dataOptionFlag | addFlag) & ~(delFlag);

    if (dataOptFlag == 0) {
        sock->dataOptionFlag = 0;
        sock->dataOptionSize = 0;
        return ERR_OK;
    }

    if (dataOptFlag & FILLP_OPT_FLAG_TIMESTAMP) {
        dataOptLen += (FILLP_UINT16)(FILLP_DATA_OPT_HLEN + FILLP_OPT_TIMESTAMP_LEN);
    }

    if ((sock->netconn != FILLP_NULL_PTR) && (sock->netconn->pcb != FILLP_NULL_PTR) &&
        ((FILLP_UINT32)((FILLP_UINT32)dataOptLen + FILLP_DATA_OFFSET_LEN) >= (FILLP_UINT32)SOCK_GET_PKTSIZE(sock))) {
        FILLP_LOGERR("option length error. sockIndex= %d, dataOptLen:%u greater than pktsize:%zu", sock->index,
            (FILLP_UINT32)dataOptLen + FILLP_DATA_OFFSET_LEN, SOCK_GET_PKTSIZE(sock));
        return FILLP_EINVAL;
    }

    sock->dataOptionFlag = dataOptFlag;
    sock->dataOptionSize = dataOptLen;
    FILLP_LOGINF("fillp_sock_id:%d, dataOptFlag:%x, dataOptionSize:%u", sock->index, dataOptFlag, dataOptLen);
    return ERR_OK;
}

#ifdef __cplusplus
}
#endif
