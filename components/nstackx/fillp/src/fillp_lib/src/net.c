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

#include "res.h"
#include "spunge.h"
#include "spunge_core.h"
#include "socket_common.h"
#include "fillp_flow_control.h"
#include "net.h"

#ifdef __cplusplus
extern "C" {
#endif

static void NetconnFreeOsSocket(struct SockOsSocket *osSock, struct SpungeInstance *curInst)
{
    if ((osSock == FILLP_NULL_PTR) || (curInst == FILLP_NULL_PTR)) {
        /* No need to prin the error log in this case, because the param 'ftSock->osSocket'
           can be set to NULL only in this function below, so printing log here is
           not useful
        */
        return;
    }

    osSock->reference--;
    if (osSock->reference <= 0) {
        if (OS_SOCK_OPS_FUNC_VALID(osSock, destroySysIoSocket)) {
            (void)osSock->ioSock->ops->destroySysIoSocket(osSock->ioSock);
        }
        HlistDelete(&curInst->osSockist, &osSock->osListNode);
        SpungeFree(osSock, SPUNGE_ALLOC_TYPE_CALLOC);
    }
}


void NetconnSetSock(struct FtSocket *sock, struct FtNetconn *conn)
{
    sock->netconn = conn;
    conn->sock = (void *)sock;
}

void NetconnSetSendCacheSize(struct FtNetconn *conn, FILLP_UINT32 cacheSize)
{
    SpungePcbSetSendCacheSize(conn->pcb, cacheSize);
}
void NetconnSetRecvCacheSize(struct FtNetconn *conn, FILLP_UINT32 cacheSize)
{
    SpungePcbSetRecvCacheSize(conn->pcb, cacheSize);
}
void NetconnSetPktSize(struct FtNetconn *conn, FILLP_UINT32 pktSize)
{
    SpungePcbSetPktSize(conn->pcb, pktSize);
}

void NetconnSetOpersiteRate(struct FtNetconn *conn, FILLP_UINT32 rate)
{
    SpungePcbSetOppositeRate(conn->pcb, rate);
}

void NetconnSetSlowStart(struct FtNetconn *conn, FILLP_BOOL slowStart)
{
    SpungePcbSetSlowStart(conn->pcb, slowStart);
}

void NetconnSetPackInterval(struct FtNetconn *conn, FILLP_UINT32 interval)
{
    SpungePcbSetPackInterval(conn->pcb, interval);
}

void NetconnSetLocalPort(struct FtNetconn *conn, FILLP_INT port)
{
    SpungePcbSetLocalPort(conn->pcb, port);
}

void NetconnSetAddrType(struct FtNetconn *conn, FILLP_UINT16 addrType)
{
    SpungePcbSetAddrType(conn->pcb, addrType);
}

void NetconnSetDirectlySend(struct FtNetconn *conn, FILLP_INT directlySend)
{
    SpungePcbSetDirectlySend(conn->pcb, directlySend);
}

void NetconnSetConnectTimeout(struct FtNetconn *conn, FILLP_LLONG timeoutUs)
{
    conn->connTimeout = SYS_ARCH_GET_CUR_TIME_LONGLONG() + timeoutUs;
}

FILLP_BOOL NetconnIsConnectTimeout(struct FtNetconn *conn)
{
    return conn->connTimeout <= SYS_ARCH_GET_CUR_TIME_LONGLONG();
}

struct FtNetconn *FillpNetconnAlloc(FILLP_UINT16 domain, struct SpungeInstance *inst)
{
    struct FtNetconn *conn = FILLP_NULL_PTR;
    FILLP_INT ret;

    FILLP_UNUSED_PARA(domain);

    ret = DympAlloc(g_spunge->netPool, (void **)&conn, FILLP_FALSE);
    if (conn == FILLP_NULL_PTR) {
        FILLP_LOGERR("Failed to allocate the netconn connection, Ret=%d", ret);
        return FILLP_NULL_PTR;
    }

    (void)memset_s(conn, sizeof(struct FtNetconn), 0, sizeof(struct FtNetconn));

    FillpNetconnSetState(conn, CONN_STATE_IDLE);

    conn->pcb = SpungePcbNew(conn, inst);
    if (conn->pcb == FILLP_NULL_PTR) {
        FILLP_LOGERR("alloc spunge_pcb fail");
        DympFree(conn);
        return FILLP_NULL_PTR;
    }

    conn->pcb->conn = conn;

    conn->clientFourHandshakeState = FILLP_CLIENT_FOUR_HANDSHAKE_STATE_INITIAL;

    conn->closeSet = 0;   /* Application calls close() function */
    conn->shutdownRdSet = 0; /* Application called shutdown(sock, RD) */
    conn->shutdownWrSet = 0;   /* Application called shutdown(sock, WR) */
    conn->peerRdSet = 0;       /* Peer notify that it won't read anything */
    conn->peerWrSet = 0;       /* Peer notify that it won't send anything */
    conn->sendBufRunOut = 0;    /* Send buffer has run out */
    conn->flagsReverse = 0;
    conn->calcRttDuringConnect = 0;
#ifdef FILLP_LINUX
    conn->iovCount = 0;
#endif
    return conn;
}

void FillpNetconnDestroy(struct FtNetconn *conn)
{
    int i;
    if (conn == FILLP_NULL_PTR) {
        FILLP_LOGERR("FillpNetconnDestroy: Invalid paramaters passed");
        return;
    }

    FillpDisableConnRetryCheckTimer(&conn->pcb->fpcb);

    conn->clientFourHandshakeState = FILLP_CLIENT_FOUR_HANDSHAKE_STATE_INITIAL;

    SpungePcbRemove(conn->pcb);
    conn->pcb = FILLP_NULL_PTR;

    for (i = 0; i < MAX_SPUNGEINSTANCE_NUM; i++) {
        if (conn->osSocket[i] != FILLP_NULL_PTR) {
            NetconnFreeOsSocket(conn->osSocket[i], SPUNGE_GET_CUR_INSTANCE());
            conn->osSocket[i] = FILLP_NULL_PTR;
        }
    }

    DympFree(conn);
}

static FILLP_BOOL FillpErrIsFatal(FILLP_INT err)
{
    FILLP_BOOL isFatal;
    switch (err) {
        case ERR_OK:
        case FILLP_ERR_ISCONN:
        case FILLP_ERR_EALREADY:
        case ERR_NOBUFS:
        case ERR_EINPROGRESS:
        case ERR_CONN_TIMEOUT:
        case ERR_NORES:
            isFatal = FILLP_FALSE;
            break;
        default:
            isFatal = FILLP_TRUE;
            break;
    }

    return isFatal;
}

FILLP_INT FillpErrToErrno(FILLP_INT err)
{
    switch (err) {
        case ERR_OK:
            return FILLP_OK;
        case FILLP_ERR_ISCONN:
            return FILLP_EISCONN;
        case FILLP_ERR_EALREADY:
            return FILLP_EALREADY;
        case ERR_NOBUFS:
            return FILLP_ENOBUFS;
        case ERR_EINPROGRESS:
            return FILLP_EINPROGRESS;
        case ERR_PARAM:
            return FILLP_EINVAL;
        case ERR_CONN_TIMEOUT:
            return FILLP_ETIMEDOUT;
        case ERR_WRONGSTATE:
            return FILLP_EINVAL;
        case ERR_NO_SOCK:
            return FILLP_ENOTSOCK;
        case ERR_FAILURE:
            return FILLP_EFAULT;
        case ERR_NORES:
            return FILLP_ENOMEM;
        case ERR_NO_SYS_SOCK:
            return FILLP_EFAULT;
        case ERR_NO_REBIND:
            return FILLP_EINVAL;
        case ERR_SOCK_BIND:
            return FILLP_EINVAL;
        case ERR_REMOTE_REJECT_OR_CLOSE:
            return FILLP_ECONNRESET;
        case ERR_CONNREFUSED:
            return FILLP_ECONNREFUSED;
        default:
            return FILLP_EFAULT;
    }
}

void FillpNetconnSetSafeErr(struct FtNetconn *conn, FILLP_INT err)
{
    if (!FillpErrIsFatal(conn->lastErr)) {
        conn->lastErr = err;
    }
}

void FillpNetconnSetState(struct FtNetconn *conn, FILLP_UINT8 state)
{
    conn->state = state;
    FILLP_LOGINF("Set conn state:%u", state);

    if (state == CONN_STATE_CONNECTED) {
        FillpEnablePackTimer(&conn->pcb->fpcb);
        FillpEnableFcTimer(&conn->pcb->fpcb);

        FillpEnableKeepAliveTimer(&conn->pcb->fpcb);
        conn->pcb->fpcb.statistics.keepAlive.lastRecvTime = conn->pcb->fpcb.pcbInst->curTime;

        if (g_resource.common.outOfOrderCacheEnable &&
            (g_appResource.common.enableNackDelay == FILLP_FALSE)) {
            conn->pcb->fpcb.dataBurstTimerNode.interval =
                (FILLP_UINT32)(g_resource.common.recvCachePktNumBufferTimeout * FILLP_ONE_SECOND);
            FillpEnableDataBurstTimer(&conn->pcb->fpcb);
        }

        SpungeTokenBucketAddFpcb(&conn->pcb->fpcb);
    }

    if (state == CONN_STATE_CLOSED) {
        if (conn->pcb != FILLP_NULL_PTR) {
            SpungeTokenBucketDelFpcb(&conn->pcb->fpcb);
        }
    }
}

#ifdef __cplusplus
}
#endif

