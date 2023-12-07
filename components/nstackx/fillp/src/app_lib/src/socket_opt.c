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

#include "socket_opt.h"
#include "sockets.h"
#include "socket_common.h"
#include "spunge.h"
#include "spunge_message.h"

#ifdef __cplusplus
extern "C" {
#endif

static FILLP_INT SockGetOptSendCache(struct FtSocket *sock, void *optVal, FILLP_INT *optLen)
{
    struct FillpCurrentSendCacheInf *currentSendCacheInfo = FILLP_NULL_PTR;
    struct FillpSendPcb *sendPcb = FILLP_NULL_PTR;
    if ((*optLen < (FILLP_INT)sizeof(struct FillpCurrentSendCacheInf)) || (sock->netconn == FILLP_NULL_PTR)) {
        SET_ERRNO(FILLP_EINVAL);
        return -1;
    }
    if ((sock->netconn == FILLP_NULL_PTR) || (sock->netconn->state != CONN_STATE_CONNECTED)) {
        FILLP_LOGERR("SockGetSockOpt: sock state must be connected Invalid sock = %d", sock->index);
        SET_ERRNO(FILLP_EBADF);
        return -1;
    }

    currentSendCacheInfo = (struct FillpCurrentSendCacheInf *)optVal;
    sendPcb = &(sock->netconn->pcb->fpcb.send);
    currentSendCacheInfo->currentSendCacheSize = sendPcb->curItemCount;
    currentSendCacheInfo->currentDataSizeInCache = (FILLP_UINT32)(sendPcb->unSendList.size +
        sendPcb->unackList.count + sendPcb->redunList.nodeNum + sendPcb->unrecvList.nodeNum +
        sendPcb->itemWaitTokenLists.nodeNum);

    return ERR_OK;
}

static FILLP_INT SockGetSockOptFillp(struct FtSocket *sock, FILLP_INT optName, void *optVal, FILLP_INT *optLen)
{
    FILLP_INT err;
    switch (optName) {
        case FILLP_PKT_DATA_OPTS_TIMESTAMP:
            if (*optLen < (FILLP_INT)sizeof(FILLP_INT)) {
                SET_ERRNO(FILLP_EINVAL);
                err = -1;
                break;
            }
            if (sock->dataOptionFlag & FILLP_OPT_FLAG_TIMESTAMP) {
                *(FILLP_INT *)optVal = 1;
                *optLen = (FILLP_INT)sizeof(FILLP_INT);
            } else {
                *(FILLP_INT *)optVal = 0;
                *optLen = (FILLP_INT)sizeof(FILLP_INT);
            }
            err = ERR_OK;
            break;
        case FILLP_SOCK_SEND_CACHE_INFO:
            err = SockGetOptSendCache(sock, optVal, optLen);
            break;
        case SO_LINGER:
            if (*optLen < (FILLP_INT)sizeof(struct linger)) {
                SET_ERRNO(FILLP_EINVAL);
                err = -1;
            } else {
                err = memcpy_s(optVal, (FILLP_UINT32)(*optLen), (void *)&sock->fillpLinger, sizeof(struct linger));
                if (err != EOK) {
                    FILLP_LOGERR("memcpy_s failed with errcode %d", err);
                    SET_ERRNO(FILLP_EINVAL);
                    err = -1;
                } else {
                    *optLen = (FILLP_INT)sizeof(struct linger);
                    err = ERR_OK;
                }
            }
            break;
        default:
            SET_ERRNO(FILLP_EINVAL);
            err = -1;
            break;
    }
    return err;
}

FILLP_INT SockGetSockOpt(
    FILLP_INT           sockIndex,
    FILLP_INT           level,
    FILLP_INT           optName,
    void               *optVal,
    FILLP_INT          *optLen)
{
    struct FtSocket *sock = SockApiGetAndCheck(sockIndex);
    struct SockOsSocket *osSock = FILLP_NULL_PTR;
    FillpErrorType err = ERR_OK;

    FILLP_LOGINF("SockGetSockOpt: sock = %d", sockIndex);

    if (sock == FILLP_NULL_PTR) {
        return -1;
    }

    if ((optLen == FILLP_NULL_PTR) || (optVal == FILLP_NULL_PTR)) {
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        SET_ERRNO(FILLP_EFAULT);
        FILLP_LOGERR("SockGetSockOpt: optLen or optVal NULL");
        return -1;
    }

    if ((optName == SO_ERROR) && (level == SOL_SOCKET)) {
        if (*optLen < (FILLP_INT)sizeof(int)) {
            (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
            SET_ERRNO(FILLP_EINVAL);
            return -1;
        }

        if (sock->err == FILLP_EINPROGRESS) {
            int errToErrno = FillpErrToErrno(sock->netconn->lastErr);
            FILLP_SOCK_SET_ERR(sock, errToErrno);
        }

        *(int *)optVal = sock->err;
        sock->err = ERR_OK;
    } else if (level == IPPROTO_FILLP) {
        err = SockGetSockOptFillp(sock, optName, optVal, optLen);
    } else {
        osSock = NETCONN_GET_OSSOCK(sock->netconn, sock->inst->instIndex);
        if (!OS_SOCK_OPS_FUNC_VALID(osSock, getsockopt)) {
            SET_ERRNO(FILLP_EINVAL);
            err = -1;
        } else {
            err = osSock->ioSock->ops->getsockopt(osSock->ioSock, level, optName, optVal, optLen);
        }
    }

    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    FILLP_LOGINF("SockGetSockOpt: return fillp_sock_id:%d, err:%d", sockIndex, err);

    if (err != ERR_OK) {
        err = -1;
    }

    return err;
}

static FILLP_INT SockSetOptTimestamp(struct FtSocket *sock, FILLP_CONST void *optVal, socklen_t optLen)
{
    FILLP_INT err;

    if (optLen < (FILLP_INT)sizeof(FILLP_INT)) {
        SET_ERRNO(FILLP_EINVAL);
        return ERR_PARAM;
    }

    if (*(FILLP_CONST FILLP_INT *)optVal) {
        err = SockUpdatePktDataOpt(sock, (FILLP_UINT16)FILLP_OPT_FLAG_TIMESTAMP, 0);
    } else {
        err = SockUpdatePktDataOpt(sock, 0, (FILLP_UINT16)FILLP_OPT_FLAG_TIMESTAMP);
    }
    if (err != ERR_OK) {
        SET_ERRNO(FILLP_EINVAL);
    }

    return err;
}

static FILLP_INT SockSetOptLinger(struct FtSocket *sock, FILLP_CONST void *optVal, socklen_t optLen)
{
    FILLP_INT err = ERR_PARAM;
    if (optLen < (FILLP_INT)sizeof(struct linger)) {
        SET_ERRNO(FILLP_EINVAL);
    } else {
        err = memcpy_s((void *)&sock->fillpLinger, sizeof(struct linger), optVal, (FILLP_UINT32)optLen);
        if (err != EOK) {
            FILLP_LOGERR("memcpy_s failed with errcode %d", err);
            SET_ERRNO(FILLP_EINVAL);
            err = ERR_PARAM;
        }
    }

    return err;
}

static FILLP_INT SockSetFcAlg(struct FtSocket *sock, FILLP_UINT32 alg)
{
    FILLP_UINT8 connState;

    if (sock->netconn == FILLP_NULL_PTR) {
        FILLP_LOGERR("netconn is NULL, fillp_sock_id:%d", sock->index);
        return FILLP_EINVAL;
    }

    connState = NETCONN_GET_STATE(sock->netconn);
    if (connState != CONN_STATE_IDLE) {
        FILLP_LOGERR("Netconn state is not idle fillp_sock_id:%d,state:%u", sock->index, connState);
        return FILLP_EINVAL;
    }

    if (sock->netconn->pcb == FILLP_NULL_PTR) {
        FILLP_LOGERR("pcb is NULL, fillp_sock_id:%d", sock->index);
        return FILLP_EINVAL;
    }

    if (alg != FILLP_ALG_ONE && alg != FILLP_ALG_TWO && alg != FILLP_ALG_THREE &&
        alg != FILLP_ALG_MSG && alg != FILLP_ALG_BASE) {
        FILLP_LOGERR("alg %u is not supported", alg);
        return FILLP_EINVAL;
    }

    if (alg != FILLP_ALG_BASE) {
        sock->netconn->pcb->fpcb.fcAlg = (FILLP_UINT8)FILLP_SUPPORT_ALG_N(alg);
    } else {
        sock->netconn->pcb->fpcb.fcAlg = FILLP_SUPPORT_ALG_BASE;
    }
    if (alg == FILLP_ALG_MSG) {
        sock->resConf.common.recvCache = FILLP_DEFAULT_MSG_RECV_CACHE;
        sock->resConf.common.sendCache = FILLP_DEFAULT_MSG_SEND_CACHE;
        NetconnSetRecvCacheSize(sock->netconn, sock->resConf.common.recvCache);
        NetconnSetSendCacheSize(sock->netconn, sock->resConf.common.sendCache);
    }
    return FILLP_OK;
}

static FILLP_INT SockSetOptFcAlg(struct FtSocket *sock, FILLP_CONST void *optVal, socklen_t optLen)
{
    FILLP_INT err = ERR_PARAM;

    if (optLen < (FILLP_INT)sizeof(FILLP_UINT32)) {
        SET_ERRNO(FILLP_EINVAL);
        return err;
    }

    if (SockSetFcAlg(sock, *(FILLP_UINT32 *)optVal) != ERR_OK) {
        SET_ERRNO(FILLP_EINVAL);
    } else {
        err = 0;
    }

    return err;
}

static FILLP_INT SockSetOptDirectlySend(struct FtSocket *sock, FILLP_CONST void *optVal, socklen_t optLen)
{
    if (optLen < (FILLP_INT)sizeof(FILLP_INT)) {
        SET_ERRNO(FILLP_EINVAL);
        return ERR_PARAM;
    }

    sock->directlySend = *(FILLP_INT *)optVal;
    FILLP_LOGBUTT("fillp sock id: %d, set directlySend to %d", sock->index, sock->directlySend);
    return ERR_OK;
}

static FILLP_INT SockSetSockOptFillp(struct FtSocket *sock,
    FILLP_INT optName, FILLP_CONST void *optVal, socklen_t optLen)
{
    FILLP_INT err = -1;
    switch (optName) {
        case FILLP_PKT_DATA_OPTS_TIMESTAMP:
            err = SockSetOptTimestamp(sock, optVal, optLen);
            break;
        case SO_LINGER:
            err = SockSetOptLinger(sock, optVal, optLen);
            break;
        case FILLP_SOCK_FC_ALG:
            err = SockSetOptFcAlg(sock, optVal, optLen);
            break;
        case FILLP_SOCK_DIRECTLY_SEND:
            err = SockSetOptDirectlySend(sock, optVal, optLen);
            break;
        default:
            SET_ERRNO(FILLP_EINVAL);
            break;
    }
    return err;
}

FILLP_INT SockSetSockOpt(
    FILLP_INT           sockIndex,
    FILLP_INT           level,
    FILLP_INT           optName,
    FILLP_CONST void   *optVal,
    socklen_t           optLen)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    struct SockOsSocket *osSock = FILLP_NULL_PTR;
    FillpErrorType err = -1;

    FILLP_LOGINF("SockSetSockOpt: sock = %d", sockIndex);

    if (optVal == FILLP_NULL_PTR) {
        SET_ERRNO(FILLP_EFAULT);
        return err;
    }

    if ((level == SOL_SOCKET) && ((optName == SO_SNDBUF) || (optName == SO_RCVBUF))) {
        FILLP_LOGERR("SockSetSockOpt: sock = %d invalid param optName=%d", sockIndex, optName);
        SET_ERRNO(FILLP_EOPNOTSUPP);
        return err;
    }

    sock = SockApiGetAndCheck(sockIndex);
    if (sock == FILLP_NULL_PTR) {
        return err;
    }

    if (level == IPPROTO_FILLP) {
        err = SockSetSockOptFillp(sock, optName, optVal, optLen);
    } else {
        osSock = NETCONN_GET_OSSOCK(sock->netconn, sock->inst->instIndex);
        if (OS_SOCK_OPS_FUNC_VALID(osSock, setsockopt)) {
            err = osSock->ioSock->ops->setsockopt(osSock->ioSock, level, optName, optVal, optLen);
        } else {
            SET_ERRNO(FILLP_EINVAL);
        }
    }

    if (err != ERR_OK) {
        err = -1;
    }

    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    FILLP_LOGINF("SockSetSockOpt: return fillp_sock_id:%d, err:%d", sockIndex, err);

    return err;
}

#ifdef __cplusplus
}
#endif
