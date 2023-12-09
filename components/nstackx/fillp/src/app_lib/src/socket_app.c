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

#include "socket_app.h"
#include "spunge_app.h"
#include "fillp_buf_item.h"
#include "spunge_message.h"

#ifdef __cplusplus
extern "C" {
#endif

static void SockSetError(struct FtSocket *sock, FillpErrorType err)
{
    switch (err) {
        case ERR_NONBLOCK_UNDERCONNECT:
            FILLP_SOCK_SET_ERR(sock, FILLP_EINPROGRESS);
            SET_ERRNO(FILLP_EINPROGRESS);
            break;

        case ERR_CONN_TIMEOUT:
            FILLP_SOCK_SET_ERR(sock, FILLP_ETIMEDOUT);
            SET_ERRNO(FILLP_ETIMEDOUT);
            break;

        case FILLP_ERR_ISCONN:
        case ERR_REMOTE_REJECT_OR_CLOSE:
            FILLP_SOCK_SET_ERR(sock, FILLP_EISCONN);
            SET_ERRNO(FILLP_EISCONN);
            break;

        case ERR_CONNREFUSED:
            FILLP_SOCK_SET_ERR(sock, FILLP_ECONNREFUSED);
            SET_ERRNO(FILLP_ECONNREFUSED);
            break;

        case FILLP_ERR_EALREADY:
            FILLP_SOCK_SET_ERR(sock, FILLP_EALREADY);
            SET_ERRNO(FILLP_EALREADY);
            break;

        case ERR_PARAM:
            FILLP_SOCK_SET_ERR(sock, FILLP_EINVAL);
            SET_ERRNO(FILLP_EINVAL);
            break;

        case ERR_WRONGSTATE:
            FILLP_SOCK_SET_ERR(sock, FILLP_ENOTCONN);
            SET_ERRNO(FILLP_ENOTCONN);
            break;

        case ERR_FAILURE:
            FILLP_SOCK_SET_ERR(sock, FILLP_EFAULT);
            SET_ERRNO(FILLP_EFAULT);
            break;

        case ERR_SYSTEM_MEMORY_FAILURE:
            FILLP_SOCK_SET_ERR(sock, FILLP_ENOMEM);
            SET_ERRNO(FILLP_ENOMEM);
            break;

        default:
            FILLP_SOCK_SET_ERR(sock, FILLP_ENOBUFS);
            SET_ERRNO(FILLP_ENOBUFS);
            break;
    }
}

static FILLP_INT SockCheckDomainTypeProto(FILLP_INT domain, FILLP_INT type, FILLP_INT protocol)
{
    if (((domain != PF_INET) && (domain != AF_INET) && (domain != AF_INET6) && (domain != PF_INET6)) ||
        (type != SOCK_STREAM)) {
        FILLP_LOGERR("SockCheckDomainTypeProto domain/type/protocol is not correct, "
                     "domain = %d, type = %d, protocol =%d", domain, type, protocol);
        if (type != SOCK_STREAM) {
            SET_ERRNO(FILLP_ESOCKTNOSUPPORT);
        } else {
            SET_ERRNO(FILLP_EAFNOSUPPORT);
        }

        return -1;
    }

    if (protocol != IPPROTO_FILLP) {
        FILLP_LOGERR("SockCheckDomainTypeProto domain/type/protocol is not correct, "
                     "domain = %d, type = %d, protocol =%d", domain, type, protocol);
        SET_ERRNO(FILLP_EPROTONOSUPPORT);
        return -1;
    }

    return ERR_OK;
}

FILLP_INT SockSocket(FILLP_INT domain, FILLP_INT type, FILLP_INT protocol)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    struct SpungeSocketMsg sockMsg;
    FillpErrorType err;
    FILLP_LOGINF("domain:%d,type:%d,protocol:%d", domain, type, protocol);
    if (SockCheckDomainTypeProto(domain, type, protocol) != ERR_OK) {
        return -1;
    }

    /* Connection resource not alloc here , but after do bind or connect action */
    sock = SpungeAllocSock(SOCK_ALLOC_STATE_COMM);
    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("SockSocket: failed to allocate socket");
        SET_ERRNO(FILLP_EMFILE);
        return -1;
    }

    sockMsg.domain = domain;
    sockMsg.protocol = protocol;
    sockMsg.type = type;
    sock->socketType = type;
    sock->socketProtocol = protocol;
    sockMsg.sock = (void *)sock;
    sock->sockAddrType = (FILLP_UINT16)domain;
    sock->traceFlag = g_spunge->traceFlag;
    sock->traceHandle = g_spunge->traceHandle;
    err = SpungePostMsg(sock->inst, &sockMsg, MSG_TYPE_ALLOC_SOCK, FILLP_TRUE);
    if (err != ERR_OK) {
        FILLP_LOGERR("SockSocket: failed to post msg to fillp sock->index = %d\r\n", sock->index);
        sock->allocState = SOCK_ALLOC_STATE_FREE;
        SockFreeSocket(sock);
        SET_ERRNO(FILLP_ENOBUFS);
        return -1;
    }

    if (sock->allocState != SOCK_ALLOC_STATE_COMM) {
        FILLP_LOGERR("socket state is invalid and no free sockets sock->index = %d\r\n", sock->index);
        sock->allocState = SOCK_ALLOC_STATE_FREE;
        SockFreeSocket(sock);
        SET_ERRNO(sock->coreErrType[MSG_TYPE_ALLOC_SOCK]);
        return -1;
    }

    /* When the socket is inited, then mark the errno for that socket as ERR_OK */
    FILLP_LOGINF("Sock alloced, fillp_sock_id:%d", sock->index);
    return sock->index;
}

FILLP_INT SockSend(FILLP_INT sockIndex, FILLP_CONST void *data, FILLP_SIZE_T size, FILLP_INT flags)
{
    return SockSendFrame(sockIndex, data, size, flags, FILLP_NULL_PTR);
}

#ifdef FILLP_LINUX
#define FRAME_CMSG_LEN CMSG_SPACE(sizeof(struct FrameInfo))
static void SockSendFrameInitCmsg(struct msghdr *m, FILLP_CONST struct FrameInfo *frame)
{
    struct cmsghdr *f = CMSG_FIRSTHDR(m);
    f->cmsg_level = IPPROTO_FILLP;
    f->cmsg_type = FILLP_CMSG_TYPE_FRAME;
    f->cmsg_len = CMSG_LEN(sizeof(struct FrameInfo));
    (void)memcpy_s((FILLP_UINT8 *)CMSG_DATA(f), sizeof(struct FrameInfo), frame, sizeof(struct FrameInfo));
}

static void SockSendSetFrameInfo(struct msghdr *m, FILLP_UINT8 *frameCmsg, size_t frameCmsgLen,
    FILLP_CONST struct FrameInfo *frame)
{
    if (frame != FILLP_NULL_PTR) {
        m->msg_control = (void *)frameCmsg;
        m->msg_controllen = frameCmsgLen;
        SockSendFrameInitCmsg(m, frame);
    } else {
        m->msg_control = FILLP_NULL_PTR;
        m->msg_controllen = 0;
    }
}

static FILLP_CONST struct FrameInfo *SockSendGetFrameInfo(struct msghdr *m)
{
    struct cmsghdr *cmsg = FILLP_NULL_PTR;

    if (m->msg_control == FILLP_NULL_PTR) {
        return FILLP_NULL_PTR;
    }

    for (cmsg = CMSG_FIRSTHDR(m); cmsg != FILLP_NULL_PTR; cmsg = CMSG_NXTHDR(m, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_FILLP &&
            cmsg->cmsg_type == FILLP_CMSG_TYPE_FRAME &&
            cmsg->cmsg_len == CMSG_LEN(sizeof(struct FrameInfo))) {
            return (FILLP_CONST struct FrameInfo *)CMSG_DATA(cmsg);
        }
    }

    return FILLP_NULL_PTR;
}
#else
static void SockSendSetFrameInfo(struct msghdr *m, FILLP_CONST struct FrameInfo *frame)
{
    m->msg_control = (void *)frame;
    m->msg_controllen = (frame == FILLP_NULL_PTR) ? 0 : sizeof(struct FrameInfo);
}

static FILLP_CONST struct FrameInfo *SockSendGetFrameInfo(struct msghdr *m)
{
    return (FILLP_CONST struct FrameInfo *)m->msg_control;
}
#endif

FILLP_INT SockSendFrame(FILLP_INT sockIndex, FILLP_CONST void *data, FILLP_SIZE_T size, FILLP_INT flags,
        FILLP_CONST struct FrameInfo *frame)
{
    struct iovec msgIov;
    struct msghdr msg;
#ifdef FILLP_LINUX
    FILLP_UINT8 frameCmsg[FRAME_CMSG_LEN] = {0};
#endif

    if ((data == FILLP_NULL_PTR) || (size == 0)) {
        FILLP_LOGERR("input data is pointer is null for sock id, fillp_sock_id: %d", sockIndex);
        SET_ERRNO(FILLP_EINVAL);
        return -1;
    }

    msgIov.iov_base = (void *)data;
    msgIov.iov_len = size;

    msg.msg_name = FILLP_NULL_PTR;
    msg.msg_namelen = 0;
    msg.msg_iov = &msgIov;
    msg.msg_iovlen = 1;
#ifdef FILLP_LINUX
    SockSendSetFrameInfo(&msg, frameCmsg, FRAME_CMSG_LEN, frame);
#else
    SockSendSetFrameInfo(&msg, frame);
#endif
    msg.msg_flags = 0;
    return SockSendmsg(sockIndex, &msg, flags);
}

static int SocketMsgGetLen(const struct msghdr *msg)
{
    size_t index;
    FILLP_ULLONG memSize = 0;
    struct iovec *iov = FILLP_NULL_PTR;

    if ((msg == FILLP_NULL_PTR) || (msg->msg_iov == FILLP_NULL_PTR)) {
        FILLP_LOGERR("input msg is null or iov is null");
        SET_ERRNO(FILLP_EFAULT);
        return -1;
    }
    iov = msg->msg_iov;

    for (index = 0; index < msg->msg_iovlen; index++) {
        if (iov[index].iov_base == FILLP_NULL_PTR) {
            FILLP_LOGERR("input iov_base is null ro iov_len is 0");
            SET_ERRNO(FILLP_EFAULT);
            return -1;
        }

        memSize = (FILLP_ULLONG)(memSize + (FILLP_ULLONG)(iov[index].iov_len));
        if ((memSize >= (FILLP_ULLONG)FILLP_MAX_INT_VALUE) || (iov[index].iov_len >= FILLP_MAX_INT_VALUE)) {
            FILLP_LOGERR("size value big, it need to be less than 2147483647(0x7FFFFFFF)");
            SET_ERRNO(FILLP_EINVAL);
            return -1;
        }
    }

    return (int)((FILLP_LLONG)memSize);
}

static struct FtSocket *SocketGetForDataTrans(FILLP_INT sockIndex, FILLP_INT flags)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    FillpTraceDescriptSt fillpTrcDesc;

    sock = SockApiGetAndCheck(sockIndex);
    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("sock is null");
        return FILLP_NULL_PTR;
    }

    if (sock->isListenSock == FILLP_TRUE) {
        (void)SOCK_CONN_UNLOCK_RD(sock);
        FILLP_LOGERR("netconn is null for sock id=%d", sockIndex);
        SET_ERRNO(FILLP_ENOTCONN);
        return FILLP_NULL_PTR;
    }

    if (sock->netconn == FILLP_NULL_PTR) {
        (void)SOCK_CONN_UNLOCK_RD(sock);
        FILLP_LOGERR("sock not connect");
        SET_ERRNO(FILLP_ENOTCONN);
        return FILLP_NULL_PTR;
    }

    (void)memset_s(&fillpTrcDesc, sizeof(fillpTrcDesc), 0, sizeof(fillpTrcDesc));
    fillpTrcDesc.traceDirection = FILLP_TRACE_DIRECT_SEND;
    FILLP_APP_LM_FILLPCMDTRACE_OUTPUT((FILLP_TRACE_DIRECT_USER, sock->traceHandle, 0, (FILLP_UINT32)sockIndex,
        (FILLP_UINT8 *)(void *)&fillpTrcDesc, "Entering Function : sock_send_rcv_param_validate socket:%d flags:%d",
        sockIndex, flags));

    return sock;
}

#ifdef SOCK_SEND_SEM
static struct FillpPcbItem *SockSendReqFpcbItemWithSem(struct FtSocket *sock, FILLP_INT flags)
{
    FILLP_INT err;
    struct FillpPcbItem *bufItem = FILLP_NULL_PTR;

    do {
        err = SOCK_TRYWAIT_SENDSEM(sock); // Try if can do send
        if (err != ERR_OK) {
            if (SOCK_IS_NONBLOCKING(sock) || ((FILLP_UINT32)flags & MSG_DONTWAIT)) {
                FILLP_LOGERR("send no buf error");
                SET_ERRNO(FILLP_ENOBUFS);
                break;
            }
            SOCK_SEND_CPU_PAUSE(); // To reduce cpu usage of send api
            err = SOCK_WAIT_SENDSEM(sock);
            if (err != ERR_OK) {
                FILLP_LOGERR("send busy error");
                SET_ERRNO(FILLP_EBUSY);
                break;
            }
        }

        if (!SockCanSendData(sock)) {
            (void)SOCK_POST_SENDSEM(sock); // Need to post here because may other thread is waiting
            FILLP_LOGERR("Fail to send msg, due to sock is not ready!!!! fillp_sock_id: %d", sock->index);
            SET_ERRNO(FILLP_ENOTCONN);
            break;
        }

        (void)FillpMallocBufItem(SOCK_GET_SENDPKTPOOL(sock), (void **)&bufItem, FILLP_FALSE);
    } while (bufItem == FILLP_NULL_PTR);

    return bufItem;
}

#else

static struct FillpPcbItem *SockSendReqFpcbItemWithoutSem(struct FtSocket *sock, FILLP_INT flags)
{
    struct FillpPcbItem *bufItem = FILLP_NULL_PTR;

    do {
        (void)FillpMallocBufItem(SOCK_GET_SENDPKTPOOL(sock), (void **)&bufItem, FILLP_FALSE);
        if (bufItem != FILLP_NULL_PTR) {
            break;
        }

        if (!SockCanSendData(sock)) {
            FILLP_LOGERR("Fail to send msg, due to sock is not ready!!!! fillp_sock_id:%d", sock->index);
            SET_ERRNO(FILLP_ENOBUFS);
            break;
        }

        if ((SOCK_IS_NONBLOCKING(sock) || ((FILLP_UINT)flags & MSG_DONTWAIT))) {
            FILLP_LOGERR("Fail to alloc buffer to send,that is not correct!!!! fillp_sock_id:%d", sock->index);
            SET_ERRNO(FILLP_ENOBUFS);
            break;
        }
        SOCK_SEND_CPU_PAUSE(); // To reduce cpu usage of send api
    } while (bufItem == FILLP_NULL_PTR);

    return bufItem;
}
#endif

static struct FillpPcbItem *SockSendReqFpcbItem(struct FtSocket *sock, FILLP_INT flags)
{
    struct FillpPcbItem *bufItem = FILLP_NULL_PTR;
#ifdef SOCK_SEND_SEM
    bufItem = SockSendReqFpcbItemWithSem(sock, flags);
#else /* SOCK_SEND_SEM */
    bufItem = SockSendReqFpcbItemWithoutSem(sock, flags);
#endif /* SOCK_SEND_SEM */
    if (bufItem != FILLP_NULL_PTR) {
        (void)SYS_ARCH_ATOMIC_DEC(&sock->sendEventCount, 1);
    }
    return bufItem;
}

static void SockSendmsgPushOrSendItem(FILLP_CONST struct FtSocket *sock,
    struct FillpPcbItem *itemList[], FILLP_UINT32 *itemCnt, struct FillpPcbItem *item)
{
    if (!FillpPcbGetDirectlySend(&sock->netconn->pcb->fpcb)) {
        (void)FillpQueuePush(SOCK_GET_SENDBOX(sock), (void *)&item, FILLP_FALSE, 1);
    } else {
        FILLP_UINT32 tmpItemCnt = *itemCnt;
        itemList[tmpItemCnt++] = item;
        if ((tmpItemCnt == UDP_MAX_SEG) ||
            (tmpItemCnt >= (FillpPcbGetSendCacheSize(&sock->netconn->pcb->fpcb) >> 1))) { /* > half of the cache */
            FillpPcbSend(&sock->netconn->pcb->fpcb, itemList, tmpItemCnt);
            tmpItemCnt = 0;
        }
        *itemCnt = tmpItemCnt;
    }
}

static void SockSendMsgSetItem(struct FillpPcbItem *item, FILLP_CONST struct FtSocket *sock,
    FILLP_LLONG appSendTime, FILLP_INT sendLen, FILLP_INT bufLen)
{
    FILLP_UINT16 pktDataOptLen = (sock->dataOptionFlag == 0) ? 0 :
        (FILLP_UINT16)(sock->dataOptionSize + FILLP_DATA_OFFSET_LEN);

    UTILS_FLAGS_RESET(item->flags);
    item->netconn = (void *)sock->netconn;
    item->fpcb = (void *)&sock->netconn->pcb->fpcb;
    item->dataOptFlag = sock->dataOptionFlag;
    item->dataOptLen = pktDataOptLen;
    item->appSendTimestamp = appSendTime;
    item->appSendSize = (FILLP_UINT32)(bufLen);
    item->dataLen = (FILLP_UINT16)0;
    if (sendLen == 0) {
        UTILS_FLAGS_SET(item->flags, FILLP_ITEM_FLAGS_FIRST_PKT);
    }
    if (bufLen >= MAX_APP_DATA_LENGTH_FOR_CAL_COST) {
        UTILS_FLAGS_SET(item->flags, FILLP_ITEM_FLAGS_APP_LARGE_DATA);
    }
    UTILS_FLAGS_SET(item->flags, FILLP_ITEM_FLAGS_REDUNDANT);
}

static void SockItemSetFrameInfo(struct FillpPcbItem *item, FILLP_CONST struct FtSocket *sock,
    FILLP_CONST struct FrameInfo *frame, struct FillpFrameItem *frameItem, FILLP_INT bufLen)
{
    FILLP_BOOL isFirstPkt = UTILS_FLAGS_CHECK(item->flags, FILLP_ITEM_FLAGS_FIRST_PKT);
    FillpFrameItemReference(item, frameItem);

    if (frameItem == FILLP_NULL_PTR) {
        return;
    }

    FillpFrameTxInitItem(&sock->netconn->pcb->fpcb.frameHandle, item, frame, (FILLP_UINT32)bufLen, isFirstPkt);
    item->dataOptLen = (FILLP_UINT16)FillpFrameGetPktDataOptLen(item->dataOptFlag, item->dataOptLen);
}

static void SockSendLastItem(FILLP_CONST struct FtSocket *sock, struct FillpPcbItem *item,
    struct FillpPcbItem *itemList[], FILLP_UINT32 itemCnt)
{
    if (item != FILLP_NULL_PTR) {
        UTILS_FLAGS_SET(item->flags, FILLP_ITEM_FLAGS_LAST_PKT);
        item->buf.len = (FILLP_INT)(item->dataOptLen + item->dataLen);
        SockSendmsgPushOrSendItem(sock, itemList, &itemCnt, item);
    }

    if (FillpPcbGetDirectlySend(&sock->netconn->pcb->fpcb) && itemCnt > 0) {
        FillpPcbSend(&sock->netconn->pcb->fpcb, itemList, itemCnt);
    }
}

static FILLP_INT SockSendmsgDataToBufCache(struct FtSocket *sock,
    struct msghdr *msg, FILLP_INT flags, FILLP_INT bufLen)
{
    FILLP_INT sendLen = 0;
    FILLP_UINT32 itemRemainLen = 0;
    FILLP_UINT32 iovRemainLen = 0;
    FILLP_UINT32 index = 0;
    FILLP_UINT32 copyLen;
    FILLP_UINT32 pktSize = (FILLP_UINT32)SOCK_GET_PKTSIZE(sock);
    char *iovIter = FILLP_NULL_PTR;
    char *itemIter = FILLP_NULL_PTR;
    struct FillpPcbItem *item = FILLP_NULL_PTR;
    struct FillpPcbItem *itemList[UDP_MAX_SEG] = {FILLP_NULL_PTR};
    FILLP_UINT32 itemCnt = 0;
    FILLP_LLONG appSendTime = SYS_ARCH_GET_CUR_TIME_LONGLONG();
    FILLP_CONST struct FrameInfo *frame = SockSendGetFrameInfo(msg);
    struct FillpFrameItem *frameItem = FillpFrameItemAlloc(frame);

    while (sendLen != bufLen) {
        SOCK_SENDMSG_DATA_MOD_IOV(iovRemainLen, iovIter, msg, index);

        if (itemRemainLen == 0) {
            if (item != FILLP_NULL_PTR) {
                item->buf.len = (FILLP_INT)(item->dataOptLen + item->dataLen);
                SockSendmsgPushOrSendItem(sock, itemList, &itemCnt, item);
            }
            item = SockSendReqFpcbItem(sock, flags);
            if (item == FILLP_NULL_PTR) {
                break;
            }

            SockSendMsgSetItem(item, sock, appSendTime, sendLen, bufLen);
            SockItemSetFrameInfo(item, sock, frame, frameItem, bufLen);
            itemIter = item->buf.p + FILLP_HLEN + item->dataOptLen;
            itemRemainLen = pktSize - item->dataOptLen;
        }

        if (item == FILLP_NULL_PTR || iovIter == FILLP_NULL_PTR || itemIter == FILLP_NULL_PTR) {
            FILLP_LOGERR("item or iovIter NULL");
            return -1;
        }
        copyLen = (itemRemainLen > iovRemainLen) ? iovRemainLen : itemRemainLen;
        if (memcpy_s(itemIter, itemRemainLen, iovIter, copyLen) != EOK) {
            FILLP_LOGERR("SockSendmsgDataToBufCache: memcpy failed");
            return -1;
        }

        SOCK_SENDMSG_DATA_MOD_LEN(iovIter, iovRemainLen, itemIter, itemRemainLen, sendLen, item->dataLen, copyLen);
    }

    SockSendLastItem(sock, item, itemList, itemCnt);
    SpungeEpollEventCallback(sock, SPUNGE_EPOLLOUT, 1);

    FillpFrameItemPut(frameItem);
    return sendLen;
}

FILLP_INT SockSendmsg(FILLP_INT sockIndex, struct msghdr *msg, FILLP_INT flags)
{
    FILLP_INT sendLen;
    struct FtSocket *sock = FILLP_NULL_PTR;

    sendLen = SocketMsgGetLen(msg);
    if (sendLen <= 0) {
        return sendLen;
    }

    sock = SocketGetForDataTrans(sockIndex, flags);
    if (sock == FILLP_NULL_PTR) {
        return -1;
    }

    if (SockCanSendData(sock) == FILLP_FALSE) {
        (void)SOCK_CONN_UNLOCK_RD(sock);
        FILLP_SOCK_SET_ERR(sock, FILLP_ENOTCONN);
        FILLP_LOGERR("send not conncet error");
        SET_ERRNO(FILLP_ENOTCONN);
        return -1;
    }

    sendLen = SockSendmsgDataToBufCache(sock, msg, flags, sendLen);
    (void)SOCK_CONN_UNLOCK_RD(sock);
    if (sendLen > 0) {
        FILLP_SOCK_SET_ERR(sock, ERR_OK);
        return sendLen;
    }

    if (SockCanSendData(sock)) {
        FILLP_SOCK_SET_ERR(sock, FILLP_EAGAIN);
        FILLP_LOGERR("send again error");
        SET_ERRNO(FILLP_EAGAIN);
    } else {
        FILLP_SOCK_SET_ERR(sock, FILLP_ECONNRESET);
        FILLP_LOGERR("send connect reset error");
        SET_ERRNO(FILLP_ECONNRESET);
    }
    return -1;
}

FILLP_INT SockRecv(FILLP_INT s, void *mem, FILLP_SIZE_T len, FILLP_INT flags)
{
    struct iovec msgIov;
    struct msghdr msg;

    if ((mem == FILLP_NULL_PTR) || (len == 0)) {
        FILLP_LOGERR("input data is pointer is null for sock id, fillp_sock_id:%d", s);
        SET_ERRNO(FILLP_EINVAL);
        return -1;
    }

    msgIov.iov_base = mem;
    msgIov.iov_len = len;

    msg.msg_name = FILLP_NULL_PTR;
    msg.msg_namelen = 0;
    msg.msg_iov = &msgIov;
    msg.msg_iovlen = 1;
    msg.msg_control = FILLP_NULL_PTR;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    return SockRecvmsg(s, &msg, flags);
}

#ifdef SOCK_RECV_SEM
static struct FillpPcbItem *SockRecvReqFpcbItemWithSem(struct FtSocket *sock, FILLP_INT flags)
{
    FILLP_INT err;
    struct FillpPcbItem *bufItem = FILLP_NULL_PTR;

    do {
        err = SOCK_TRYWAIT_RECVSEM(sock); // Try if can do recv
        if (err != ERR_OK) {
            if (SOCK_IS_NONBLOCKING(sock) || ((FILLP_UINT)flags & MSG_DONTWAIT)) {
                break;
            }
            SOCK_SEND_CPU_PAUSE(); // To reduce cpu usage of send api
            err = SOCK_WAIT_RECVSEM(sock);
            if (err != ERR_OK) {
                break;
            }
        }

        (void)FillpQueuePop(SOCK_GET_RECVBOX(sock), (void **)&bufItem, 1);
        if ((bufItem == FILLP_NULL_PTR) && (!SockCanRecvData(sock))) {
            (void)SOCK_POST_RECVSEM(sock); // Need to post here because may other thread is waiting
            FILLP_LOGERR("Fail to send msg, due to sock is not ready!!!! fillp_sock_id:%d", sock->index);
            break;
        }
    } while (bufItem == FILLP_NULL_PTR);

    return bufItem;
}

#else

static struct FillpPcbItem *SockRecvReqFpcbItemWithoutSem(struct FtSocket *sock, FILLP_INT flags)
{
    struct FillpPcbItem *bufItem = FILLP_NULL_PTR;

    do {
        (void)FillpQueuePop(SOCK_GET_RECVBOX(sock), (void **)&bufItem, 1);
        if (bufItem != FILLP_NULL_PTR) {
            break;
        }

        if (!SockCanRecvData(sock)) {
            FILLP_LOGERR("Fail to recv msg, due to sock is not ready!!!! fillp_sock_id:%d", sock->index);
            break;
        }

        if ((SOCK_IS_NONBLOCKING(sock) || ((FILLP_UINT32)flags & MSG_DONTWAIT))) {
            FILLP_LOGDBG("fillp_sock_id:%d, Fail to get data buffer to recv", sock->index);
            break;
        }
        SOCK_RECV_CPU_PAUSE(); // To reduce cpu usage of send api
    } while (bufItem == FILLP_NULL_PTR);

    return bufItem;
}
#endif

static struct FillpPcbItem *SockRecvReqFpcbItem(struct FtSocket *sock, FILLP_INT flags)
{
    struct FillpPcbItem *bufItem = FILLP_NULL_PTR;

    if (sock->recvPktBuf != FILLP_NULL_PTR) {
        bufItem = (struct FillpPcbItem *)sock->recvPktBuf;
        if (bufItem->dataLen == 0) {
            FillpFreeBufItem(sock->recvPktBuf);
            sock->recvPktBuf = FILLP_NULL;
            sock->offset = 0;
            SpungeEpollAppRecvOne(sock);
        } else {
            return bufItem;
        }
    }

#ifdef SOCK_RECV_SEM
    bufItem = SockRecvReqFpcbItemWithSem(sock, flags);
#else /* SOCK_RECV_SEM */
    bufItem = SockRecvReqFpcbItemWithoutSem(sock, flags);
#endif /* SOCK_RECV_SEM */
    if (bufItem != FILLP_NULL_PTR) {
        sock->recvPktBuf = (void *)bufItem;
        sock->offset = bufItem->dataOptLen;
    }

    return bufItem;
}

static FILLP_INT SockRecvmsgDataFromBufCache(struct FtSocket *sock,
    struct msghdr *msg, FILLP_INT flags, FILLP_INT bufLen)
{
    struct FillpPcbItem *item = FILLP_NULL_PTR;
    FILLP_INT rcvLen = 0;
    FILLP_INT ret;
    FILLP_UINT32 itemRemainLen = 0;
    FILLP_UINT32 iovRemainLen = 0;
    FILLP_UINT32 index = 0;
    FILLP_UINT32 copyLen;
    char *iovIter = FILLP_NULL_PTR;
    char *itemIter = FILLP_NULL_PTR;

    while (rcvLen != bufLen) {
        SOCK_SENDMSG_DATA_MOD_IOV(iovRemainLen, iovIter, msg, index);

        if (itemRemainLen == 0) {
            /* SOCK_DGRAM mode, at most 1 pkt will be returned */
            if ((sock->socketType == SOCK_DGRAM) && (item != FILLP_NULL_PTR)) {
                break;
            }
            if (rcvLen > 0) {
                flags = (FILLP_INT)((FILLP_UINT)flags | MSG_DONTWAIT);
            }
            item = SockRecvReqFpcbItem(sock, flags);
            if (item == FILLP_NULL_PTR) {
                break;
            }
            itemIter = item->buf.p + FILLP_HLEN + sock->offset;
            itemRemainLen = item->dataLen;
        }

        if (item == FILLP_NULL_PTR || iovIter == FILLP_NULL_PTR || itemIter == FILLP_NULL_PTR) {
            FILLP_LOGERR("item or iovIter NULL");
            return -1;
        }

        copyLen = (itemRemainLen > iovRemainLen) ? iovRemainLen : itemRemainLen;
        ret = memcpy_s(iovIter, iovRemainLen, itemIter, copyLen);
        if (ret != EOK) {
            FILLP_LOGERR("SockRecvmsgDataFromBufCache: memcpy fail, err code:%d", ret);
            return -1;
        }

        SOCK_SENDMSG_DATA_MOD_LEN(iovIter, iovRemainLen, itemIter, itemRemainLen, rcvLen, sock->offset, copyLen);
        item->dataLen -= (FILLP_UINT16)copyLen;
    }

    if ((item != FILLP_NULL_PTR) &&
        ((item->dataLen == 0) || ((iovRemainLen == 0) && (sock->socketType == SOCK_DGRAM)))) {
        FillpFreeBufItem(sock->recvPktBuf);
        sock->recvPktBuf = FILLP_NULL;
        sock->offset = 0;
        SpungeEpollAppRecvOne(sock);
    }

    return rcvLen;
}

FILLP_INT SockRecvmsg(FILLP_INT sockIndex, struct msghdr *msg, FILLP_INT flags)
{
    FILLP_INT recvLen;
    struct FtSocket *sock = FILLP_NULL_PTR;
    FILLP_INT ret;

    recvLen = SocketMsgGetLen(msg);
    if (recvLen <= 0) {
        FILLP_LOGERR("get msglen fail");
        return -1;
    }

    sock = SocketGetForDataTrans(sockIndex, flags);
    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("sock is null");
        return -1;
    }

    if ((sock->netconn->state != CONN_STATE_CONNECTED) && (sock->netconn->state != CONN_STATE_CLOSING) &&
        (sock->netconn->state != CONN_STATE_CLOSED)) {
        (void)SOCK_CONN_UNLOCK_RD(sock);
        FILLP_LOGERR("sock not connect");
        SET_ERRNO(FILLP_ENOTCONN);
        return -1;
    }

    if (msg->msg_name != FILLP_NULL_PTR) {
        ret = memcpy_s(msg->msg_name, msg->msg_namelen, &sock->netconn->pcb->remoteAddr, sock->netconn->pcb->addrLen);
        if (ret != EOK) {
            FILLP_LOGERR("SockRecvmsg: memcpy fail, err code:%d", ret);
            return -1;
        }
        msg->msg_namelen = sock->netconn->pcb->addrLen;
    }

    recvLen = SockRecvmsgDataFromBufCache(sock, msg, flags, recvLen);
    (void)SOCK_CONN_UNLOCK_RD(sock);
    if (recvLen > 0) {
        FILLP_SOCK_SET_ERR(sock, ERR_OK);
        return recvLen;
    }

    if (SockCanRecvData(sock)) {
        FILLP_SOCK_SET_ERR(sock, FILLP_EAGAIN);
        FILLP_LOGERR("recv again error");
        SET_ERRNO(FILLP_EAGAIN);
        return -1;
    }

    FILLP_SOCK_SET_ERR(sock, FILLP_ECONNRESET);
    FILLP_LOGERR("recv connect reset error");
    SET_ERRNO(FILLP_ECONNRESET);
    return 0;
}

FillpErrorType SockWritev(FILLP_INT sockIndex, const struct iovec *iov, FILLP_INT iovCount)
{
    struct msghdr msg;

    if (iov == FILLP_NULL_PTR) {
        FILLP_LOGERR("input iov is pointer is null for sock id fillp_sock_id:%d", sockIndex);
        SET_ERRNO(FILLP_EFAULT);
        return -1;
    }

    if (iovCount == 0) {
        return 0;
    }

    (void)memset_s(&msg, sizeof(struct msghdr), 0, sizeof(struct msghdr));
    msg.msg_iov = (struct iovec *)iov;
    msg.msg_iovlen = (size_t)(FILLP_UINT)iovCount;

    return SockSendmsg(sockIndex, &msg, 0);
}

FillpErrorType SockReadv(FILLP_INT sockIndex, const struct iovec *iov, FILLP_INT iovCount)
{
    struct msghdr msg;

    if (iov == FILLP_NULL_PTR) {
        FILLP_LOGERR("input iov is pointer is null for sock id fillp_sock_id:%d", sockIndex);
        SET_ERRNO(FILLP_EFAULT);
        return -1;
    }

    if (iovCount == 0) {
        return 0;
    }

    (void)memset_s(&msg, sizeof(struct msghdr), 0, sizeof(struct msghdr));
    msg.msg_iov = (struct iovec *)iov;
    msg.msg_iovlen = (size_t)(FILLP_UINT)iovCount;

    return SockRecvmsg(sockIndex, &msg, 0);
}

static struct FtSocket *SockApiGetAndCheckListenState(FILLP_INT sockIndex, FILLP_INT backLog, FillpErrorType *err)
{
    struct FtSocket *sock = FILLP_NULL_PTR;

    *err = -1;
    if (backLog < 0) {
        FILLP_LOGERR("Backlog is invalid fillp_sock_id:%d,backLog:%d", sockIndex, backLog);
        SET_ERRNO(FILLP_EINVAL);
        return FILLP_NULL_PTR;
    }

    /* errno is set inside the function upon failure */
    sock = SockApiGetAndCheck(sockIndex);
    if (sock == FILLP_NULL_PTR) {
        return FILLP_NULL_PTR;
    }

    if (sock->isSockBind == FILLP_FALSE) {
        FILLP_LOGERR("socket Id %d not bind ip", sockIndex);
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        SET_ERRNO(FILLP_EINVAL);
        return FILLP_NULL_PTR;
    }

    /* Call listen on the same socket fd twice: Kernel behavior: return success */
    if (sock->isListenSock == FILLP_TRUE) {
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        *err = 0;
        return FILLP_NULL_PTR;
    }

    if (sock->netconn == FILLP_NULL_PTR) {
        FILLP_LOGERR("sock->netconn is NULL, fillp_sock_id:%d", sockIndex);
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        SET_ERRNO(FILLP_ENOTCONN);
        return FILLP_NULL_PTR;
    }

    return sock;
}

FillpErrorType SockListen(FILLP_INT sockIndex, FILLP_INT backLog)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    FillpErrorType err;
    FillpTraceDescriptSt fillpTrcDesc = FILLP_TRACE_DESC_INIT(FILLP_TRACE_DIRECT_SEND);

    FILLP_LOGINF("SockListen, fillp_sock_id:%d, backLog:%d", sockIndex, backLog);

    sock = SockApiGetAndCheckListenState(sockIndex, backLog, &err);
    if (sock == FILLP_NULL_PTR) {
        return err;
    }

    FILLP_APP_LM_FILLPCMDTRACE_OUTPUT((FILLP_TRACE_DIRECT_USER, sock->traceHandle, 0, (FILLP_UINT32)sockIndex,
        (FILLP_UINT8 *)(void *)&fillpTrcDesc, "Entering Function : FtListen->SockListen socket:%d backlog:%d \r\n",
        sockIndex, backLog));

    if ((backLog == 0) || (backLog > (FILLP_INT)g_spunge->resConf.maxConnNum)) {
        FILLP_LOGWAR("input backLog is not equal to configured value"
            " so using the configured value backLog:%d, configValue:%u,fillp_sock_id:%d",
            backLog, g_spunge->resConf.maxConnNum, sock->index);

        backLog = (FILLP_INT)g_spunge->resConf.maxConnNum;
    }

    sock->listenBacklog = backLog;

    err = SpungePostMsg(sock->inst, sock, MSG_TYPE_DO_LISTEN, FILLP_TRUE);
    if (err != ERR_OK) {
        FILLP_LOGERR("failed to post msg to fillp sock->index = %d\r\n", sock->index);

        sock->listenBacklog = 0;
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        SET_ERRNO(FILLP_ENOBUFS);
        return -1;
    }

    err = sock->coreErrType[MSG_TYPE_DO_LISTEN];
    FillpNetconnSetSafeErr(sock->netconn, err);
    if (err != ERR_OK) {
        SockSetError(sock, err);
        err = -1;
    }

    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    return err;
}

static struct FtSocket *SockAcceptGetAndCheck(FILLP_INT sockFd)
{
    struct FtSocket *sock = SockApiGetAndCheck(sockFd);
    if (sock == FILLP_NULL_PTR) {
        return FILLP_NULL_PTR;
    }

    if (sock->netconn == FILLP_NULL_PTR) {
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);

        FILLP_LOGERR("network connection doesnot exist to accept : sockFd=%d", sockFd);
        SET_ERRNO(FILLP_ENOTCONN);
        return FILLP_NULL_PTR;
    }

    if (sock->isListenSock == FILLP_FALSE) {
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);

        FILLP_LOGERR("connection state is not in listening mode for sockFd=%d", sockFd);
        SET_ERRNO(FILLP_EINVAL);
        return FILLP_NULL_PTR;
    }

    if (sock->acceptBox == FILLP_NULL_PTR) {
        FILLP_LOGERR("accept box is NULL fillp_sock_id:%d", sockFd);
        SET_ERRNO(FILLP_EINVAL);
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        return FILLP_NULL_PTR;
    }

    return sock;
}

static void SockCopyAddr(struct sockaddr *addr, socklen_t *addrLen, struct FtNetconn *conn)
{
    FILLP_INT ret;

    if ((addr != FILLP_NULL_PTR) && (addrLen != FILLP_NULL_PTR)) {
        socklen_t localAddrLen = sizeof(struct sockaddr);
        if (((struct sockaddr_in *)((void *)&(conn->pcb->remoteAddr)))->sin_family == AF_INET6) {
            localAddrLen = sizeof(struct sockaddr_in6);
        }

        if (*addrLen >= localAddrLen) {
            *addrLen = localAddrLen;
        }

        if (*addrLen > 0) {
            ret = memcpy_s(addr, *addrLen, &conn->pcb->remoteAddr, *addrLen);
            if (ret != EOK) {
                FILLP_LOGERR("memcpy_s failed with errcode %d", ret);
                return;
            }
        }
    }
}

static struct FtNetconn *SockPopConn(struct FtSocket *sock, FILLP_INT sockFd)
{
    struct FtNetconn *conn = FILLP_NULL_PTR;
    FILLP_INT ret;

    /* Making the FtAccept call non blocking
       TCP accept():
       a) The accept() function shall extract the first connection on
       the queue of pending connections, create a new socket with the same socket
       type protocol and address family as the specified socket, and allocate a
       new file descriptor for that socket.

       b) If the listen queue is empty of connection requests and O_NONBLOCK is not
       set on the file descriptor for the socket, accept() shall block until a
       connection is present. If the listen() queue is empty of connection requests
       and O_NONBLOCK is set on the file descriptor for the socket, accept() shall
       fail and set errno to [EAGAIN] or [EWOULDBLOCK].

       c) The accept() function shall fail if:
       [EAGAIN] or [EWOULDBLOCK]
       O_NONBLOCK is set for the socket file descriptor and no connections are present to be accepted.
    */
    ret = FillpQueuePop(sock->acceptBox, (void *)&conn, 1);
    if (ret <= 0) {
        if ((SOCK_IS_NONBLOCKING(sock))) {
            (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);

            FILLP_LOGINF("SockAccept: connection request not received for listenID  = %d \r\n", sockFd);
            FILLP_SOCK_SET_ERR(sock, FILLP_EINPROGRESS);
            SET_ERRNO(FILLP_EAGAIN);
            /* Returns less than 0 value */
            return FILLP_NULL_PTR;
        } else {
            if (SYS_ARCH_SEM_WAIT(&sock->acceptSem)) {
                (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);

                FILLP_LOGERR("Error wait acceptSem, sockFd = %d \r\n", sockFd);
                FILLP_SOCK_SET_ERR(sock, FILLP_ENOMEM);
                SET_ERRNO(FILLP_ENOMEM);
                /* Returns less than 0 value */
                return FILLP_NULL_PTR;
            }

            ret = FillpQueuePop(sock->acceptBox, (void *)&conn, 1);
            if (ret <= 0) {
                (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);

                FILLP_LOGERR("SockAccept: pop error for sock Id = %d \r\n", sockFd);
                SET_ERRNO(FILLP_ENODATA);
                return FILLP_NULL_PTR;
            }
        }
    } else {
        if (!SOCK_IS_NONBLOCKING(sock) && (SYS_ARCH_SEM_WAIT(&sock->acceptSem))) {
            (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);

            FILLP_LOGERR("sem wait is failing when there is connection to be accepted, "
                         " Abnormal stack behavior, Server sockFd = %d \r\n", sockFd);
            FILLP_SOCK_SET_ERR(sock, FILLP_ENOMEM);
            SET_ERRNO(FILLP_ENOMEM);
            /* Returns less than 0 value */
            return FILLP_NULL_PTR;
        }
    }

    return conn;
}

FillpErrorType SockAccept(FILLP_INT sockFd, struct sockaddr *addr, socklen_t *addrLen)
{
    FillpErrorType err;
    struct FtSocket *sock = SockAcceptGetAndCheck(sockFd);
    struct FtNetconn *conn = FILLP_NULL_PTR;
    FillpTraceDescriptSt fillpTrcDesc;
    struct SpungeAcceptMsg acceptMsg;

    FILLP_LOGINF("sock_accpet:%d", sockFd);

    if (sock == FILLP_NULL_PTR) {
        return -1;
    }

    fillpTrcDesc.traceDirection = FILLP_TRACE_DIRECT_SEND;
    FILLP_APP_LM_FILLPCMDTRACE_OUTPUT((FILLP_TRACE_DIRECT_USER, sock->traceHandle, 0, (FILLP_UINT32)sockFd,
        (FILLP_UINT8 *)(void *)&fillpTrcDesc,
        "Entering Function : FtAccept->SockAccept socket:%d\r\n", sockFd));

    /* do SYS_ARCH_RWSEM_RDPOST in SockPopConn */
    conn = SockPopConn(sock, sockFd);
    if (conn == FILLP_NULL_PTR) {
        return -1;
    }

    SpungeEpollAppRecvOne(sock);

    acceptMsg.listenSock = (void *)sock;
    acceptMsg.netconn = conn;

    err = SpungePostMsg(sock->inst, (void *)&acceptMsg, MSG_TYPE_NETCONN_ACCPETED, FILLP_TRUE);
    if (err != ERR_OK) {
        FILLP_LOGERR("Failed to post msg to core, fillp_sock_id:%d", sock->index);
        SOCK_DESTROY_CONN(&sock->sockConnSem, conn, sock, FILLP_ENOBUFS);
        return -1;
    }

    if (sock->coreErrType[MSG_TYPE_NETCONN_ACCPETED] != ERR_OK) {
        FILLP_LOGERR("Failed in core to accept socket Id for listen fillp_sock_id:%d", sockFd);
        SOCK_DESTROY_CONN(&sock->sockConnSem, conn, sock, FILLP_ENOMEM);
        return -1;
    }

    SockCopyAddr(addr, addrLen, conn);

    FILLP_SOCK_SET_ERR(sock, ERR_OK);
    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);

    FILLP_LOGINF("sock_accpet return.listen fillp_sock_id:%d, accepted:%d", sockFd,
                 ((struct FtSocket *)conn->sock)->index);
    return ((struct FtSocket *)conn->sock)->index;
}

FillpErrorType SockClose(FILLP_INT sockIndex)
{
    struct FtSocket *sock = SockGetSocket(sockIndex);
    FILLP_INT err;
    FillpTraceDescriptSt fillpTrcDesc = FILLP_TRACE_DESC_INIT(FILLP_TRACE_DIRECT_SEND);

    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("Invalid fillp_sock_id:%d", sockIndex);
        SET_ERRNO(FILLP_EBADF);
        return -1;
    }

    FILLP_LOGINF("fillp_sock_id:%d, state:%d, linger:%d", sockIndex, sock->allocState, sock->fillpLinger.l_onoff);

    if (SOCK_CONN_TRY_RDLOCK(sock) != ERR_OK) {
        FILLP_LOGERR("Socket-%d is closing", sockIndex);
        SET_ERRNO(FILLP_EBUSY);
        return -1;
    }

    if ((sock->allocState != SOCK_ALLOC_STATE_COMM) && (sock->allocState != SOCK_ALLOC_STATE_EPOLL)) {
        (void)SOCK_CONN_UNLOCK_RD(sock);

        FILLP_LOGERR("socket state is incorrect for fillp_sock_id:%d,state=%d", sockIndex, sock->allocState);

        SET_ERRNO(FILLP_ENOTSOCK);
        return -1;
    }

    /* Just lock, no need to unlock, it is used for dumplicate close
       Dumplicate close may push two close message to fillp stack, if the first one has
       released the resource, then the second one will make bugs */
    if (SOCK_CONN_TRY_LOCK_CLOSE(sock) != ERR_OK) {
        FILLP_LOGERR("Try to lock close fail, maybe close already called before, fillp_sock_id:%d", sockIndex);
        SET_ERRNO(FILLP_EINVAL);
        (void)SOCK_CONN_UNLOCK_RD(sock);
        return -1;
    }

    FILLP_APP_LM_FILLPCMDTRACE_OUTPUT((FILLP_TRACE_DIRECT_USER, sock->traceHandle, 0, (FILLP_UINT32)sockIndex,
        (FILLP_UINT8 *)(void *)&fillpTrcDesc, "Entering Function : FtClose->SockClose Socket:%d \r\n", sockIndex));

    /* Before waiting for the core to complete the task, we must release the
           socket lock as core might require same.
    */
    (void)SOCK_CONN_UNLOCK_RD(sock);

    if (sock->fillpLinger.l_onoff) {
        sock->lingering = FILLP_TRUE;
    } else {
        sock->lingering = FILLP_FALSE;
    }

    err = SpungePostMsg(sock->inst, sock, MSG_TYPE_DO_CLOSE, FILLP_TRUE);
    if (err != ERR_OK) {
        FILLP_LOGERR("Failed to Close the Socket. SpungePostMsg returns failure. fillp_sock_id:%d \r\n", sockIndex);
        /* nothing can be done for post failure */
        (void)SOCK_CONN_UNLOCK_CLOSE(sock);
        SET_ERRNO(FILLP_ENOBUFS);
        return -1;
    }

    err = sock->coreErrType[MSG_TYPE_DO_CLOSE];

    FILLP_LOGINF("return fillp_sock_id:%d,err:%d,state:%d", sockIndex, err, sock->allocState);
    if (err != ERR_OK) {
        /* handle close can fail for semaphore wait epollTaskListLock,
           but application do not care about failure of FtClose, so this socket anyways hangs */
        err = -1;
    }

    return err;
}

static FILLP_INT SockCheckCanShutdown(struct FtSocket *sock, FILLP_INT sockIndex)
{
    if ((sock->netconn == FILLP_NULL_PTR) || (NETCONN_GET_STATE(sock->netconn) != CONN_STATE_CONNECTED)) {
        /* For listen socket shutdown always return success */
        if ((sock->netconn != FILLP_NULL_PTR) && (CONN_STATE_LISTENING == NETCONN_GET_STATE(sock->netconn))) {
            (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
            return FILLP_ERR_ISCONN;
        }

        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        FILLP_LOGERR("SockShutdown: netconn state is not CONNECTED for socket Id  = %d", sockIndex);
        SET_ERRNO(FILLP_ENOTCONN);
        return -1;
    }

    return ERR_OK;
}

FillpErrorType SockShutdown(FILLP_INT sockIndex, FILLP_INT how)
{
    struct FtSocket *sock = SockApiGetAndCheck(sockIndex);
    FillpTraceDescriptSt fillpTrcDesc = FILLP_TRACE_DESC_INIT(FILLP_TRACE_DIRECT_SEND);
    FILLP_INT err;
    struct SpungeShutdownMsg shutdownMsg;

    FILLP_LOGINF("fillp_sock_id:%d", sockIndex);

    if (sock == FILLP_NULL_PTR) {
        return -1;
    }

    FILLP_APP_LM_FILLPCMDTRACE_OUTPUT((FILLP_TRACE_DIRECT_USER, sock->traceHandle, 0, (FILLP_UINT32)sockIndex,
        (FILLP_UINT8 *)(void *)&fillpTrcDesc, "Entering Function : FtShutDown->SockShutdown Socket:%d \r\n",
        sockIndex));

    err = SockCheckCanShutdown(sock, sockIndex);
    if (err == FILLP_ERR_ISCONN) {
        return ERR_OK;
    } else if (err != ERR_OK) {
        return -1;
    }

    if ((how != SPUNGE_SHUT_RD) && (how != SPUNGE_SHUT_RDWR) && (how != SPUNGE_SHUT_WR)) {
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        SET_ERRNO(FILLP_EINVAL);
        FILLP_LOGERR("how value is not support, fillp_sock_id: %d, how: %d", sockIndex, how);
        return -1;
    }

    shutdownMsg.how = how;
    shutdownMsg.sock = sock;

    sock->lingering = FILLP_FALSE;
    err = SpungePostMsg(sock->inst, (void *)&shutdownMsg, MSG_TYPE_DO_SHUTDOWN, FILLP_TRUE);
    if (err != ERR_OK) {
        FILLP_LOGERR("Failed to Shutdown the Socket. SpungePostMsg returns failure. fillp_sock_id:%d \r\n", sockIndex);
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        SET_ERRNO(FILLP_ENOBUFS);
        return -1;
    }

    err = sock->coreErrType[MSG_TYPE_DO_SHUTDOWN];
    FillpNetconnSetSafeErr(sock->netconn, err);
    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);

    FILLP_LOGINF("shut down finished, fillp_sock_id:%d,err:%d", sockIndex, err);
    if (err != ERR_OK) {
        err = -1;
    }

    return err;
}

static FillpErrorType SockBindConnectValidateParams(struct FtSocket *sock,
    FILLP_CONST struct sockaddr *name,  FILLP_UINT32 nameLen)
{
    FillpTraceDescriptSt fillpTrcDesc = FILLP_TRACE_DESC_INIT(FILLP_TRACE_DIRECT_SEND);

    if (name  == FILLP_NULL_PTR) {
        FILLP_LOGERR("Input address is not correct, fillp_sock_id:%d", sock->index);
        SET_ERRNO(FILLP_EFAULT);
        return ERR_NULLPTR;
    }

    if (sock->sockAddrType != name->sa_family) {
        FILLP_LOGERR("addrType not match, fillp_sock_id:%d,sock->addrType:%u,name->addrType:%u", sock->index,
            sock->sockAddrType, name->sa_family);

        SET_ERRNO(FILLP_EAFNOSUPPORT);
        return ERR_SOCK_TYPE_ERR;
    }

    if (sock->sockAddrType == AF_INET) {
        struct sockaddr_in *ipv4Addr = (struct sockaddr_in *)name;
        if (nameLen < sizeof(struct sockaddr_in)) {
            FILLP_LOGERR("nameLen is too less for ipv4 addr, nameLen:%u", nameLen);
            SET_ERRNO(FILLP_EINVAL);
            return ERR_SOCK_TYPE_ERR;
        }

        if (ipv4Addr->sin_addr.s_addr == 0) {
            FILLP_LOGERR("IPV4 NULL IP is not allowed");
            SET_ERRNO(FILLP_EINVAL);
            return ERR_SOCK_TYPE_ERR;
        }
    } else {
        struct sockaddr_in6 *ipv6Addr = (struct sockaddr_in6 *)name;
        if (nameLen < sizeof(struct sockaddr_in6)) {
            FILLP_LOGERR("nameLen is too less for ipv6 addr, nameLen:%u", nameLen);
            SET_ERRNO(FILLP_EINVAL);
            return ERR_SOCK_TYPE_ERR;
        }

        if (IPV6_ADDR_IS_NULL(ipv6Addr)) {
            FILLP_LOGERR("IPV6 NULL IP is not allowed");
            SET_ERRNO(FILLP_EINVAL);
            return ERR_SOCK_TYPE_ERR;
        }
    }

    FILLP_APP_LM_FILLPCMDTRACE_OUTPUT((FILLP_TRACE_DIRECT_USER, sock->traceHandle, 0, (FILLP_UINT32)sock->index,
        (FILLP_UINT8 *)(void *)&fillpTrcDesc, "Entering Function : FtConnect / FtBind, socket:%d nameLen:%d",
        sock->index, nameLen));

    return ERR_OK;
}

FILLP_ULLONG SockGetRtt(FILLP_INT sockFd)
{
    FILLP_ULLONG rtt = 0;
    FILLP_UINT8 state;
    struct FtNetconn *conn = FILLP_NULL_PTR;

    /* errno is set inside the function upon failure */
    struct FtSocket *sock = SockApiGetAndCheck(sockFd);
    if (sock == FILLP_NULL_PTR) {
        return FILLP_NULL;
    }

    if (sock->netconn != FILLP_NULL_PTR) {
        conn = (struct FtNetconn *)sock->netconn;
        state = NETCONN_GET_STATE(conn);
        if (state == CONN_STATE_CONNECTED) {
            rtt = conn->calcRttDuringConnect;
        }
    }

    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);

    return rtt;
}

FillpErrorType SockConnect(FILLP_INT sockIndex, FILLP_CONST struct sockaddr *name, socklen_t nameLen)
{
    struct FtSocket *sock = SockApiGetAndCheck(sockIndex);
    struct SpungeConnectMsg connectMsg;
    FillpTraceDescriptSt fillpTrcDesc = FILLP_TRACE_DESC_INIT(FILLP_TRACE_DIRECT_SEND);
    FillpErrorType err;

    FILLP_LOGINF("fillp_sock_id:%d", sockIndex);

    /* errno is set inside the function upon failure */
    if (sock == FILLP_NULL_PTR) {
        return -1;
    }

    /* errno is set inside the function upon failure */
    err = SockBindConnectValidateParams(sock, name, nameLen);
    if (err != ERR_OK) {
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        return -1;
    }

    FILLP_APP_LM_FILLPCMDTRACE_OUTPUT((FILLP_TRACE_DIRECT_USER, sock->traceHandle, 0, (FILLP_UINT32)sockIndex,
        (FILLP_UINT8 *)(void *)&fillpTrcDesc,
        "Entering Function : FtConnect->SockConnect  socket:%d nameLen:%d", sockIndex, nameLen));

    connectMsg.addr = (struct sockaddr_in *)name;
    connectMsg.addrLen = nameLen;
    connectMsg.sock = (void *)sock;

    err = SpungePostMsg(sock->inst, &connectMsg, MSG_TYPE_DO_CONNECT, FILLP_TRUE);
    if (err != ERR_OK) {
        FILLP_LOGERR("Failed to send message in SockConnect for socketId = %d", sockIndex);
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        SET_ERRNO(FILLP_ENOBUFS);
        return -1;
    }

    if (!SOCK_IS_NONBLOCKING(sock)) {
        if (SYS_ARCH_SEM_WAIT(&sock->connBlockSem)) {
            FILLP_LOGERR("Error to wait connBlockSem");
            (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
            SET_ERRNO(FILLP_ENOBUFS);
            return -1;
        }
    }

    err = sock->coreErrType[MSG_TYPE_DO_CONNECT];
    if (err != ERR_OK) {
        if (err != ERR_NONBLOCK_UNDERCONNECT) {
            FillpNetconnSetSafeErr(sock->netconn, err);
        } else {
            FillpNetconnSetSafeErr(sock->netconn, sock->netconn->lastErr);
        }

        SockSetError(sock, err);
        err = -1;
    }

    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    return err;
}

FillpErrorType SockBind(FILLP_INT sockIndex, FILLP_CONST struct sockaddr *name, FILLP_UINT32 nameLen)
{
    struct FtSocket *sock = SockApiGetAndCheck(sockIndex);
    FILLP_INT err = ERR_OK;
    struct SpungeBindMsg bindMsg;

    /* errno is set inside this function upon failure */
    if (sock == FILLP_NULL_PTR) {
        return -1;
    }

    /* errno is set inside this function upon failure */
    err = SockBindConnectValidateParams(sock, name, nameLen);
    if (err != ERR_OK) {
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        return -1;
    }

    bindMsg.sock = (void *)sock;
    bindMsg.addr = (struct sockaddr_in *)name;
    bindMsg.addrLen = nameLen;

    FILLP_LOGINF("fillp_sock_id:%d,nameLen:%u,port:%u", sockIndex, nameLen, UTILS_GET_ADDRPORT(name));

    err = SpungePostMsg(sock->inst, &bindMsg, MSG_TYPE_DO_BIND, FILLP_TRUE);
    if (err != ERR_OK) {
        FILLP_LOGERR("Failed to post msg to fillp sock->index = %d", sock->index);
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        SET_ERRNO(FILLP_ENOBUFS);
        return -1;
    }

    err = sock->coreErrType[MSG_TYPE_DO_BIND];
    FillpNetconnSetSafeErr(sock->netconn, err);

    FILLP_LOGINF("fillp_sock_id:%d,ret:%d", sockIndex, err);

    if (err != ERR_OK) {
        if (err == ERR_NO_REBIND) {
            FILLP_SOCK_SET_ERR(sock, FILLP_EADDRINUSE);
            SET_ERRNO(FILLP_EADDRINUSE);
        } else {
            FILLP_SOCK_SET_ERR(sock, FILLP_EINVAL);
            SET_ERRNO(FILLP_EINVAL);
        }

        err = -1;
    } else {
        FILLP_SOCK_SET_ERR(sock, ERR_OK);
    }

    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);

    return err;
}

#ifdef FILLP_LINUX
FILLP_INT SockFcntl(FILLP_INT s, FILLP_INT cmd, FILLP_INT val)
{
    struct FtSocket *sock;
    FILLP_INT ret = -1;
    FillpTraceDescriptSt fillpTrcDesc;

    sock = SockApiGetAndCheck(s);
    if (sock == FILLP_NULL_PTR) {
        return -1;
    }

    fillpTrcDesc.traceDirection = FILLP_TRACE_DIRECT_SEND;
    FILLP_APP_LM_FILLPCMDTRACE_OUTPUT((FILLP_TRACE_DIRECT_USER, sock->traceHandle, 0, (FILLP_UINT32)s,
        (FILLP_UINT8 *)(void *)&fillpTrcDesc, "Entering Function : FtFcntl->SockFcntl socket:%d cmd:%d val:%d",
        s, cmd, val));

    switch (cmd) {
        case F_GETFL:
            ret = SOCK_IS_NONBLOCKING(sock) ? O_NONBLOCK : 0;
            break;

        case F_SETFL:
            if (((FILLP_UINT)val & ~(FILLP_UINT)O_NONBLOCK) == 0) {
                /* only O_NONBLOCK, all other bits are zero */
                SockSetNonblocking(sock, (FILLP_INT)((FILLP_UINT)val & (FILLP_UINT)O_NONBLOCK));
                ret = 0;
            }
            break;
        default:
            ret = -1;
            FILLP_LOGERR("sock_fnctl:invalid cmd %d, ft_sock_id %d \r\n", cmd, s);
            break;
    }

    if (ret < 0) {
        SET_ERRNO(FILLP_EINVAL);
    }

    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    return ret;
}
#endif

FILLP_INT SockIoctlsocket(FILLP_INT s, FILLP_SLONG cmd, FILLP_CONST FILLP_INT *val)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    FillpTraceDescriptSt fillpTrcDesc;

    if (val == FILLP_NULL_PTR) {
        FILLP_LOGERR("SockIoctlsocket : Invalid input parameter : val is null\r\n");
        SET_ERRNO(FILLP_EINVAL);
        return -1;
    }

    sock = SockApiGetAndCheck(s);
    if (sock == FILLP_NULL_PTR) {
        return -1;
    }

    fillpTrcDesc.traceDirection = FILLP_TRACE_DIRECT_SEND;
    FILLP_APP_LM_FILLPCMDTRACE_OUTPUT((FILLP_TRACE_DIRECT_USER, sock->traceHandle, 0, (FILLP_UINT32)s,
        (FILLP_UINT8 *)(void *)&fillpTrcDesc, "Entering Function : SockIoctlsocket s: %d cmd: %ld\r\n",
        s, cmd));

    switch (cmd) {
        case FILLP_FIONBIO:

            if ((*val != 0) && (*val != 1)) {
                FILLP_LOGERR("SockIoctlsocket:invalid val %d passed, Socket-%d \r\n", *val, s);
                (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
                SET_ERRNO(FILLP_EINVAL);
                return -1;
            }

            SockSetNonblocking(sock, *val);

            break;

        default:
            FILLP_LOGERR("SockIoctlsocket:invalid cmd %ld failed, Socket-%d \r\n", cmd, s);

            (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
            SET_ERRNO(FILLP_EINVAL);
            return -1;
    }

    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    return FILLP_OK;
}

static struct FtSocket *SockGetnameCheckParam(FILLP_INT sockIndex, FILLP_CONST struct sockaddr *name,
    FILLP_CONST socklen_t *nameLen)
{
    struct FtSocket *sock = FILLP_NULL_PTR;
    if (name == FILLP_NULL_PTR) {
        FILLP_LOGERR("fillp_sock_id:%d Input connect address is Invalid", sockIndex);
        SET_ERRNO(FILLP_EINVAL);
        return FILLP_NULL_PTR;
    }

    sock = SockApiGetAndCheck(sockIndex);
    if (sock == FILLP_NULL_PTR) {
        return FILLP_NULL_PTR;
    }

    /* non-negative number cannot be less than 0 */
    if ((nameLen == FILLP_NULL_PTR) || (*nameLen == 0) ||
        ((sock->sockAddrType == AF_INET) && (*nameLen < (socklen_t)sizeof(struct sockaddr_in))) ||
        ((sock->sockAddrType == AF_INET6) && (*nameLen < (socklen_t)sizeof(struct sockaddr_in6)))) {
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        FILLP_LOGERR("fillp_sock_id:%d Input connect address length is Invalid", sockIndex);
        SET_ERRNO(FILLP_EINVAL);
        return FILLP_NULL_PTR;
    }

    return sock;
}

FILLP_INT SockGetsockname(FILLP_INT sockIndex, struct sockaddr *name, socklen_t *nameLen)
{
    struct FtSocket *sock = SockGetnameCheckParam(sockIndex, name, nameLen);
    struct SockOsSocket *osSock = FILLP_NULL_PTR;
    FillpErrorType err = ERR_OK;
    size_t addrSize;

    FILLP_LOGINF("fillp_sock_id:%d", sockIndex);

    if (sock == FILLP_NULL_PTR) {
        return -1;
    }

    if (NETCONN_GET_STATE(sock->netconn) == CONN_STATE_CONNECTED) {
        if (sock->sockAddrType == AF_INET) {
            addrSize = sizeof(struct sockaddr_in);
            if (*nameLen > (socklen_t)addrSize) {
                *nameLen = (socklen_t)addrSize;
            }
            (void)memcpy_s(name, *nameLen, &(sock->netconn->pcb->localAddr), *nameLen);
        } else if (sock->sockAddrType == AF_INET6) {
            addrSize = sizeof(struct sockaddr_in6);
            if (*nameLen > (socklen_t)addrSize) {
                *nameLen = (socklen_t)addrSize;
            }
            (void)memcpy_s(name, *nameLen, &(sock->netconn->pcb->localAddr), *nameLen);
        }
    } else {
        osSock = NETCONN_GET_OSSOCK(sock->netconn, sock->inst->instIndex);
        if (!OS_SOCK_OPS_FUNC_VALID(osSock, getSockName)) {
            SET_ERRNO(FILLP_EINVAL);
            err = -1;
        } else {
            err = osSock->ioSock->ops->getSockName(osSock->ioSock, name, nameLen);
        }
    }

    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    FILLP_LOGINF("get sock name finished, fillp_sock_id:%d, err:%d", sockIndex, err);

    if (err != ERR_OK) {
        err = -1;
    }

    return err;
}

/* This interface do not check if socket is connected or not, just give whatever values
    are stored in cb, if application call before remote address is set,
    then it will cause */
FILLP_INT SockGetpeername(FILLP_INT sockIndex, struct sockaddr *name, socklen_t *nameLen)
{
    struct FtSocket *sock = SockGetnameCheckParam(sockIndex, name, nameLen);
    FillpErrorType err = ERR_OK;
    FILLP_UINT8 state;
    size_t addrSize;

    FILLP_LOGINF("SockGetpeername: fillp_sock_id:%d", sockIndex);

    if (sock == FILLP_NULL_PTR) {
        return -1;
    }

    state = NETCONN_GET_STATE(sock->netconn);
    if (state != CONN_STATE_CONNECTED) {
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        FILLP_LOGERR("SockGetpeername: netcon socket state is incorrect for sock=%d, state = %u\r\n", sockIndex, state);
        SET_ERRNO(FILLP_ENOTCONN);
        return -1;
    }

    if (sock->sockAddrType == AF_INET) {
        addrSize = sizeof(struct sockaddr_in);
        if (*nameLen > (socklen_t)addrSize) {
            *nameLen = (socklen_t)addrSize;
        }
        (void)memcpy_s(name, *nameLen, &(sock->netconn->pcb->remoteAddr), *nameLen);
    } else if (sock->sockAddrType == AF_INET6) {
        addrSize = sizeof(struct sockaddr_in6);
        if (*nameLen > (socklen_t)addrSize) {
            *nameLen = (socklen_t)addrSize;
        }
        (void)memcpy_s(name, *nameLen, &(sock->netconn->pcb->remoteAddr), *nameLen);
    }

    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    FILLP_LOGINF("SockGetpeername: return sock=%d, err:%d", sockIndex, err);

    return err;
}

FILLP_INT SockGetSockEvt(FILLP_INT s)
{
    FILLP_UINT ret = 0;
    struct FtSocket *sock = SockApiGetAndCheck(s);

    FILLP_LOGDBG("fillp_sock_id:%d", s);

    if (sock == FILLP_NULL_PTR) {
        return 0;
    }

    if (SYS_ARCH_ATOMIC_READ(&sock->rcvEvent)) {
        ret |= SPUNGE_EPOLLIN;
    }

    if ((SYS_ARCH_ATOMIC_READ(&sock->sendEvent)) && (SYS_ARCH_ATOMIC_READ(&sock->sendEventCount) > 0)) {
        ret |= SPUNGE_EPOLLOUT;
    }

    if (sock->errEvent) {
        ret |= sock->errEvent;
    }
    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    return (FILLP_INT)ret;
}

/* Set the blocking status of FtSocket

    The flag (which contains the socket options is in FtSocket and NOT in netconn CB)
    is in FtSocket structure, this is because: Application can set the socket to
    nonblock just after calling FtSocket (before ft_connet/FtAccept), but the
    netconn CB will be available only during FtConnect/FtAccept.
*/
void SockSetNonblocking(struct FtSocket *sock, FILLP_INT val)
{
    if ((val > 0) && SOCK_IS_BLOCKING(sock)) {
        sock->flags |= (FILLP_UINT16)SOCK_FLAG_NON_BLOCKING;
    } else if ((val == 0) && SOCK_IS_NONBLOCKING(sock)) {
        sock->flags &= (FILLP_UINT16)(~SOCK_FLAG_NON_BLOCKING);
    }
}

FILLP_INT SockEventInfoGet(int s, FtEventCbkInfo *info)
{
    FILLP_INT ret;
    struct FtSocket *sock = FILLP_NULL_PTR;
    struct SpungeEvtInfoMsg msg;

    if (info == FILLP_NULL_PTR) {
        SET_ERRNO(FILLP_EINVAL);
        return -1;
    }

    sock = SockApiGetAndCheck(s);
    if (sock == FILLP_NULL_PTR) {
        SET_ERRNO(FILLP_EINVAL);
        return -1;
    }

    msg.sock = (void *)sock;
    msg.info = info;
    ret = SpungePostMsg(sock->inst, &msg, MSG_TYPE_GET_EVENT_INFO, FILLP_TRUE);
    if (ret != ERR_OK) {
        SET_ERRNO(FILLP_EINVAL);
        FILLP_LOGERR("Failed to post msg to fillp sock->index = %d", sock->index);
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        return -1;
    }

    ret = sock->coreErrType[MSG_TYPE_GET_EVENT_INFO];
    if (ret != ERR_OK) {
        SET_ERRNO(FILLP_EINVAL);
        FILLP_LOGERR("fillp_sock_id:%d,ret:%d", sock->index, ret);
        (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
        return -1;
    }

    (void)SYS_ARCH_RWSEM_RDPOST(&sock->sockConnSem);
    return 0;
}

#ifdef __cplusplus
}
#endif
