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

#include "fillp_common.h"
#include "fillp_mgt_msg_log.h"
#include "fillp_dfx.h"

#ifdef __cplusplus
extern "C" {
#endif

struct FillpFinFlags {
    FILLP_BOOL wrSet;
    FILLP_BOOL rdSet;
    FILLP_BOOL ackSet;
    FILLP_BOOL verSet;
};

static FILLP_UCHAR g_rawMsg[FILLP_FRAME_MTU] = {0};

static void FillpConnReqInputTrace(FILLP_CONST struct FillpPcb *pcb, FILLP_CONST struct FtSocket *sock,
    struct FillpPktConnReq *req, FILLP_UINT16 flag)
{
    FillpTraceDescriptSt fillpTrcDesc;

    if (sock->traceFlag >= FILLP_TRACE_DIRECT_NETWORK) {
        struct FillpPktConnReq tmpConnReq;
        struct FillpPktHead *pktHdr = FILLP_NULL_PTR;
        (void)memset_s(&tmpConnReq, sizeof(struct FillpPktConnReq),
            0, sizeof(struct FillpPktConnReq));

        pktHdr = (struct FillpPktHead *)(void *)req->head;
        struct FillpPktHead *tmpHead1 = (struct FillpPktHead *)(void *)tmpConnReq.head;
        /* Recovert the header to NETWORK byte order to provide indication */
        tmpHead1->flag = FILLP_HTONS(flag);
        tmpHead1->dataLen = FILLP_HTONS(pktHdr->dataLen);
        tmpHead1->pktNum = FILLP_HTONL(pktHdr->pktNum);
        tmpHead1->seqNum = FILLP_HTONL(pktHdr->seqNum);

        /* Below field is already in NETWORK byte order */
        tmpConnReq.cookiePreserveTime = req->cookiePreserveTime;
        tmpConnReq.sendCache = req->sendCache;
        tmpConnReq.recvCache = req->recvCache;

        FILLP_LM_FILLPMSGTRACE_OUTPUT_WITHOUT_FT_TRACE_ENABLE_FLAG(FILLP_TRACE_DIRECT_NETWORK, sock->traceHandle,
            sizeof(struct FillpPktConnReq), FILLP_GET_SOCKET(pcb)->index, fillpTrcDesc,
            (FILLP_CHAR *)(&tmpConnReq));
    }
}

static FILLP_INT FillpConnReqStateCheck(struct FillpPcb *pcb, FILLP_CONST struct FtSocket *sock)
{
    FILLP_UINT8 connState = FILLP_GET_CONN_STATE(pcb);
    if (connState == CONN_STATE_CONNECTED) {
        if ((pcb->recv.seqNum == pcb->recv.seqStartNum) && (pcb->send.maxAckNumFromReceiver ==
            pcb->send.seqStartNum)) { /* Only if no data received or no data acked */
            FILLP_LOGINF("fillp_sock_id:%d Conn req in open state"
                         "as data not received, so sending conn resp,state = %u",
                         sock->index, connState);

            FillpSendConnConfirmAck(pcb);
        } else {
            FILLP_LOGINF("fillp_sock_id:%d Conn req in open state"
                         "so dropping the message, state = %u",
                         sock->index, connState);
        }

        return ERR_FAILURE;
    }

    if (connState != CONN_STATE_LISTENING) {
        FILLP_LOGINF("fillp_sock_id:%d Connection state in not correct, state = %u", sock->index, connState);
        return ERR_CONNREFUSED;
    }

    return ERR_OK;
}

void FillpConnReqInput(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p)
{
    struct FillpPktConnReq *req = FILLP_NULL_PTR;
    FillpCookieContent stateCookie;
    FILLP_UINT16 flag;
    struct FillpPktHead *tmpHead = FILLP_NULL_PTR;
    struct FtSocket *sock = FILLP_GET_SOCKET(pcb);
    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("sock is NULL");
        return;
    }

    /* We should check for minimum length because of optional parameter total length may be more, which can be added in
       future version of stack, current version just ignore optlen as none is defined */
    if (p->len < (FILLP_INT)(sizeof(struct FillpPktConnReq) - FILLP_HLEN)) {
        FILLP_LOGWAR("fillp_sock_id:%d, Invalid connection request, len = %d", FILLP_GET_SOCKET(pcb)->index, p->len);
        return;
    }

    FILLP_LOGINF("Get conn request, fillp_sock_id:%d, source port:%u, remote port:%u", sock->index,
        UTILS_GET_ADDRPORT(&((struct SpungePcb*)(pcb->spcb))->localAddr), UTILS_GET_ADDRPORT(&p->addr));

    req = (struct FillpPktConnReq *)(void *)p->p;
    tmpHead = (struct FillpPktHead *)(void *)req->head;
    flag = tmpHead->flag;

    FillpConnReqInputTrace(pcb, sock, req, flag);
    FILLP_CONN_REQ_LOG(sock->index, req, FILLP_DIRECTION_RX);
    if (FillpConnReqStateCheck(pcb, sock) != ERR_OK) {
        return;
    }

    req->cookiePreserveTime = FILLP_NTOHL(req->cookiePreserveTime);
    req->sendCache = FILLP_NTOHL(req->sendCache);
    req->recvCache = FILLP_NTOHL(req->recvCache);
    req->timestamp = FILLP_NTOHLL(req->timestamp);

    if ((req->recvCache == 0) || (req->sendCache == 0) || (req->timestamp == 0)) {
        FILLP_LOGINF("fillp_sock_id:%d recv cache or sendCache size or timestamp is not correct"
                     "recvCache=%u, sendCache=%u, timestamp=%llu",
                     sock->index, req->recvCache, req->sendCache, req->timestamp);
        return;
    }

    (void)memset_s(&stateCookie, sizeof(FillpCookieContent), 0, sizeof(FillpCookieContent));
    FillpGenerateCookie(pcb, req, &p->addr, ((struct sockaddr_in *)(&FILLP_GET_CONN(pcb)->pcb->localAddr))->sin_port,
        &stateCookie);

    FillpSendConnReqAck(pcb, &stateCookie, req->timestamp);
}

/* On success return number of bytes used to encode and on failure -ve values */
static FILLP_INT32 FillpEncodeExtPara(FILLP_UCHAR *buf, FILLP_INT32 bufLen, FILLP_UCHAR paraType, FILLP_UCHAR paraLen,
    FILLP_UCHAR *paraValue)
{
    FILLP_INT32 len;
    /* If paraLen is more than 1 then encode as name-length-value,
       If paraLen is 1 or 0 then encode as name-value.
       If MSB bit is set to 1 then it is encoded as name length value, otherwise it is encoded as
       name value */
    len = (paraLen <= 1) ? FILLP_ONE_EXT_PARA_LENGTH : (paraLen + FILLP_ONE_EXT_PARA_LENGTH);
    if (bufLen < len) {
        return ERR_FAILURE;
    }

    *buf = paraType;

    if (paraLen > 1) {
        *buf |= (FILLP_UCHAR)0x80;
    } else {
        buf++;
        *buf = *paraValue;
        return len;
    }

    buf++;
    *buf = paraLen;
    buf++;

    FillpErrorType err = memcpy_s(buf, (FILLP_UINT32)bufLen - FILLP_ONE_EXT_PARA_LENGTH, paraValue, paraLen);
    if (err != EOK) {
        FILLP_LOGERR("fillp_encode_ext_para memcpy_s failed:%d", err);
        return ERR_FAILURE;
    }
    return len;
}


/* On success returns buffer consumed, otherwise -ve value */
static FILLP_INT32 FillpDecodeExtParaNameLen(FILLP_CONST FILLP_UCHAR *buf, FILLP_INT bufLen, FILLP_UCHAR *paraType,
    FILLP_UCHAR *paraLen)
{
    FILLP_INT len;
    /* If paraLen is more then 1 then encode as name length value,
       If paraLen is 1 or 0 then encode as name value.
       If MSB bit is set to 1 then it is encoded as name length value, otherwise it is encoded as
       name value */
    if (bufLen < FILLP_ONE_EXT_PARA_LENGTH) {
        return ERR_FAILURE;
    }

    *paraType = *buf;

    if (*paraType & 0x80) {
        *paraLen = *(buf + 1);
        *paraType = (FILLP_UCHAR)((*paraType) & (FILLP_UCHAR)~(0x80));
        len = FILLP_ONE_EXT_PARA_LENGTH;
    } else {
        *paraLen = 1;
        len = 1;
    }

    if ((*paraLen == 0) || ((FILLP_INT)(len + (FILLP_INT)(*paraLen)) > bufLen)) {
        return ERR_FAILURE;
    }

    return len;
}

static void FillpDecodeRtt(struct FtNetconn *conn, FILLP_CONST FILLP_UCHAR *buf, FILLP_INT bufLen)
{
    FILLP_ULLONG rtt;
    if (bufLen != (FILLP_INT)sizeof(rtt)) {
        return;
    }

    FILLP_INT err = memcpy_s(&rtt, sizeof(rtt), buf, (FILLP_UINT32)bufLen);
    if (err != EOK) {
        FILLP_LOGERR("memcpy_s failed: %d", err);
        return;
    }

    conn->calcRttDuringConnect = FILLP_NTOHLL(rtt);
#ifdef FILLP_MGT_MSG_LOG
    conn->extParameterExisted[FILLP_PKT_EXT_CONNECT_CONFIRM_CARRY_RTT] = FILLP_TRUE;
#endif
}

static void FillpDecodePktSize(struct FtNetconn *conn, FILLP_CONST FILLP_UCHAR *buf, FILLP_INT bufLen)
{
    FILLP_UINT32 pktSize;
    if (bufLen != (FILLP_INT)sizeof(pktSize)) {
        return;
    }

    FILLP_INT err = memcpy_s(&pktSize, sizeof(pktSize), buf, (FILLP_UINT32)bufLen);
    if (err != EOK) {
        FILLP_LOGERR("memcpy_s failed: %d", err);
        return;
    }

    conn->peerPktSize = FILLP_NTOHL(pktSize);
#ifdef FILLP_MGT_MSG_LOG
    conn->extParameterExisted[FILLP_PKT_EXT_CONNECT_CONFIRM_CARRY_PKT_SIZE] = FILLP_TRUE;
#endif
}

static void FillpDecodeCharacters(struct FtNetconn *conn, FILLP_CONST FILLP_UCHAR *buf, FILLP_INT bufLen)
{
    FILLP_UINT32 characters;
    if (bufLen != (FILLP_INT)sizeof(characters)) {
        return;
    }

    FILLP_INT err = memcpy_s(&characters, sizeof(characters), buf, (FILLP_UINT32)bufLen);
    if (err != EOK) {
        FILLP_LOGERR("memcpy_s failed: %d", err);
        return;
    }

    conn->peerCharacters = FILLP_NTOHL(characters);
#ifdef FILLP_MGT_MSG_LOG
    conn->extParameterExisted[FILLP_PKT_EXT_CONNECT_CARRY_CHARACTER] = FILLP_TRUE;
#endif
}

static void FillpDecodeFcAlg(struct FtNetconn *conn, FILLP_CONST FILLP_UCHAR *buf, FILLP_INT bufLen)
{
    if (bufLen != (FILLP_INT)sizeof(conn->peerFcAlgs)) {
        return;
    }

    conn->peerFcAlgs = *(FILLP_UINT8 *)buf;
#ifdef FILLP_MGT_MSG_LOG
    conn->extParameterExisted[FILLP_PKT_EXT_CONNECT_CARRY_FC_ALG] = FILLP_TRUE;
#endif
}

typedef void (*FIllpExtParaDecoder)(struct FtNetconn *conn, FILLP_CONST FILLP_UCHAR *buf, FILLP_INT bufLen);
static FIllpExtParaDecoder g_extParaDecoder[FILLP_PKT_EXT_BUTT] = {
    FILLP_NULL_PTR, /* FILLP_PKT_EXT_START */
    FillpDecodeRtt, /* FILLP_PKT_EXT_CONNECT_CONFIRM_CARRY_RTT */
    FillpDecodePktSize, /* FILLP_PKT_EXT_CONNECT_CONFIRM_CARRY_PKT_SIZE */
    FillpDecodeCharacters, /* FILLP_PKT_EXT_CONNECT_CARRY_CHARACTER */
    FillpDecodeFcAlg, /* FILLP_PKT_EXT_CONNECT_CARRY_FC_ALG */
};

FILLP_INT32 FillpDecodeExtPara(FILLP_CONST FILLP_UCHAR *buf, FILLP_INT bufLen, struct FtNetconn *conn)
{
    FILLP_INT len = 0;
    FILLP_UCHAR paraType = 0;
    FILLP_UCHAR paraLen = 0;
    FILLP_INT ret;

    while (len < bufLen) {
        ret = FillpDecodeExtParaNameLen(buf + len, bufLen - len, &paraType, &paraLen);
        if (ret <= ERR_OK) {
            /* This can fail because of insufficient space so return */
            return ret;
        }

        len += ret;

        FILLP_LOGERR("paraType:%u ", paraType);

        if (bufLen - len >= paraLen &&
            paraType > FILLP_PKT_EXT_START && paraType < FILLP_PKT_EXT_BUTT &&
            g_extParaDecoder[paraType] != FILLP_NULL_PTR) {
            g_extParaDecoder[paraType](conn, buf + len, paraLen);
        }

        len += paraLen;
    }

    return ERR_OK;
}

static FILLP_INT32 FillpConnReqAckClientBuild(FILLP_CHAR *buf, FILLP_INT32 *len, FILLP_CONST struct NetBuf *p,
    struct FillpConnReqAckClient *reqAck)
{
    reqAck->tagCookie = *((FILLP_UINT16 *)buf);
    buf = buf + sizeof(FILLP_UINT16);
    *len += sizeof(FILLP_UINT16);
    reqAck->tagCookie = FILLP_NTOHS(reqAck->tagCookie);
    reqAck->cookieLength = *((FILLP_UINT16 *)buf);
    buf = buf + sizeof(FILLP_UINT16);
    *len += sizeof(FILLP_UINT16);
    reqAck->cookieLength = FILLP_NTOHS(reqAck->cookieLength);

    if ((p->len < (FILLP_INT)(reqAck->cookieLength + *len)) || (reqAck->cookieLength == 0)) {
        return FILLP_FAILURE;
    }

    reqAck->cookieContent = buf;

    buf = buf + reqAck->cookieLength;
    *len += reqAck->cookieLength;

    if (p->len < (*len + (FILLP_INT)sizeof(FILLP_ULLONG))) {
        return FILLP_FAILURE;
    }

    reqAck->timestamp = *((FILLP_ULLONG *)buf);
    reqAck->timestamp = FILLP_NTOHLL(reqAck->timestamp);

    buf = buf + sizeof(FILLP_ULLONG);
    *len += sizeof(FILLP_ULLONG);
    return FILLP_OK;
}

static FILLP_UINT8 FillpConsultFcAlg(FILLP_UINT8 presetFcAlg, FILLP_UINT8 peerFcAlgs)
{
    FILLP_UINT8 resultFcAlg;
    FILLP_UINT8 range = peerFcAlgs & (FILLP_UINT8)FILLP_SUPPORT_ALGS;
    if (presetFcAlg == FILLP_SUPPORT_ALG_BASE && g_resource.flowControl.fcAlg != FILLP_ALG_BASE) {
        presetFcAlg = (FILLP_UINT8)FILLP_SUPPORT_ALG_N(g_resource.flowControl.fcAlg);
    }
    if ((range & presetFcAlg) != 0) {
        range &= presetFcAlg;
    }
    resultFcAlg = FILLP_SUPPORT_ALG_HIGHEST;
    while (resultFcAlg > FILLP_SUPPORT_ALG_BASE) {
        if ((resultFcAlg & range) != 0) {
            break;
        }
        resultFcAlg >>= 1;
    }
    return resultFcAlg;
}

static FILLP_INT32 FillpDecodeConnReqAckClientPara(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p,
    struct FillpConnReqAckClient *reqAck)
{
    FILLP_INT32 len = 0;
    FILLP_CHAR *buf = p->p + FILLP_HLEN;
    struct FtNetconn *conn = FILLP_GET_CONN(pcb);

    if (p->len < (FILLP_INT)(sizeof(FILLP_UINT16) * 2)) {
        return FILLP_FAILURE;
    }

    if (FillpConnReqAckClientBuild(buf, &len, p, reqAck) != FILLP_OK) {
        return FILLP_FAILURE;
    }
    buf += len;

    conn->peerFcAlgs = 0;
    conn->peerCharacters = 0;
    if (FillpDecodeExtPara((FILLP_UCHAR *)buf, p->len - len, conn) != ERR_OK) {
        FILLP_LOGERR("FillpDecodeExtPara failed");
        return FILLP_FAILURE;
    }

    FILLP_CONN_REQ_ACK_RX_LOG(FILLP_GET_SOCKET(pcb)->index, (struct FillpPktHead *)p->p, reqAck,
        (FILLP_UCHAR *)buf, p->len - len);

    pcb->characters = conn->peerCharacters & (FILLP_UINT32)FILLP_DEFAULT_SUPPORT_CHARACTERS;
    pcb->fcAlg = FillpConsultFcAlg(pcb->fcAlg, conn->peerFcAlgs);

    return FILLP_SUCCESS;
}

static void FillpConnReqAckTrace(struct FtSocket *sock, struct FillpPktHead *pktHdr)
{
    FillpTraceDescriptSt fillpTrcDesc;
    if (sock->traceFlag < FILLP_TRACE_DIRECT_NETWORK) {
        return;
    }
    struct FillpPktConnReqAck tmpConnReqAck;
    struct FillpPktHead *tmpHead = (struct FillpPktHead *)(void *)tmpConnReqAck.head;

    (void)memset_s(&tmpConnReqAck, sizeof(struct FillpPktConnReqAck), 0,
        sizeof(struct FillpPktConnReqAck));

    /* Recovert the header to NETWORK byte order to provide indication */
    tmpHead->flag = FILLP_HTONS(pktHdr->flag);
    tmpHead->dataLen = FILLP_HTONS(pktHdr->dataLen);
    tmpHead->pktNum = FILLP_HTONL(pktHdr->pktNum);
    tmpHead->seqNum = FILLP_HTONL(pktHdr->seqNum);

    /* cookieContent information , including tag or length should not be given to
    user in indication. */
    FILLP_LM_FILLPMSGTRACE_OUTPUT_WITHOUT_FT_TRACE_ENABLE_FLAG(FILLP_TRACE_DIRECT_NETWORK, sock->traceHandle,
        sizeof(struct FillpPktConnReqAck), sock->index, fillpTrcDesc, (FILLP_CHAR *)(&tmpConnReqAck));
}

void FillpConnReqAckInput(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p)
{
    struct FillpConnReqAckClient reqAck = {0};
    struct FtSocket *sock = FILLP_GET_SOCKET(pcb);

    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("sock is null");
        return;
    }

    FILLP_LOGINF("req ack input, fillp_sock_id:%d, pcb, source port:%u, destport:%u", sock->index,
        UTILS_GET_ADDRPORT(&(FILLP_GET_CONN(pcb))->pcb->localAddr), UTILS_GET_ADDRPORT(&p->addr));


    if (FillpDecodeConnReqAckClientPara(pcb, p, &reqAck) != FILLP_SUCCESS) {
        FILLP_LOGINF("fillp_sock_id:%d Invalid connection request, len = %d", sock->index, p->len);
        return;
    }

    struct FillpPktHead *pktHdr = (struct FillpPktHead *)(void *)p->p;
    FillpConnReqAckTrace(sock, pktHdr);

    FILLP_UINT8 connState = FILLP_GET_CONN_STATE(pcb);
    if (connState != CONN_STATE_CONNECTING) {
        FILLP_LOGINF("fillp_sock_id=%d Connection state in not correct,state=%u", sock->index, connState);
        return;
    }

    pcb->peerUniqueId = pktHdr->seqNum;
    FILLP_LLONG curTime = SYS_ARCH_GET_CUR_TIME_LONGLONG();
    FILLP_LLONG rttTime = curTime - (FILLP_LLONG)reqAck.timestamp;
    if (rttTime <= 0) {
        FILLP_LOGWAR("System Time has changed;curTime:%lld,reqTime:%llu", curTime, reqAck.timestamp);
        return;
    }

    pcb->rtt = (FILLP_ULLONG)rttTime;


    if (FILLP_GET_CONN(pcb)->calcRttDuringConnect == 0) {
        FILLP_GET_CONN(pcb)->calcRttDuringConnect = pcb->rtt;
    }

    FILLP_GET_CONN(pcb)->clientFourHandshakeState = FILLP_CLIENT_FOUR_HANDSHAKE_STATE_REQACK_RCVED;

    {
        struct SpungePcb *spcb = (struct SpungePcb*)pcb->spcb;
        struct sockaddr *addr = (struct sockaddr *)(void *)&p->addr;


        if (addr->sa_family == AF_INET) {
            spcb->addrType = AF_INET;
            *((struct sockaddr_in *)&spcb->remoteAddr) = *(struct sockaddr_in *)addr;
            spcb->addrLen = sizeof(struct sockaddr);
        } else {
            spcb->addrType = AF_INET6;
            spcb->remoteAddr = p->addr;
            spcb->addrLen = sizeof(struct sockaddr_in6);
        }
    }

    FillpSendConnConfirm(pcb, &reqAck);
}

static FILLP_INT FillpInitNewPcbByNewConn(struct FtNetconn *newConn, FILLP_SIZE_T maxSendCache,
    FILLP_SIZE_T maxRecvCache)
{
    struct FtSocket *sock = (struct FtSocket *)newConn->sock;
    newConn->pcb->fpcb.pktSize = UTILS_MIN(sock->resConf.flowControl.pktSize, newConn->peerPktSize);
    if ((newConn->pcb->fpcb.pktSize > (FILLP_MAX_PKT_SIZE - FILLP_HLEN)) || (newConn->pcb->fpcb.pktSize == 0)) {
        newConn->pcb->fpcb.pktSize = (FILLP_MAX_PKT_SIZE - FILLP_HLEN);
    }

    newConn->pcb->fpcb.recv.pktRecvCache = (FILLP_UINT32)maxRecvCache * (FILLP_UINT32)newConn->pcb->fpcb.pktSize;
    newConn->pcb->fpcb.send.pktSendCache = (FILLP_UINT32)maxSendCache * (FILLP_UINT32)newConn->pcb->fpcb.pktSize;

    if (((newConn->pcb->fpcb.recv.pktRecvCache / newConn->pcb->fpcb.pktSize) != maxRecvCache) ||
        ((newConn->pcb->fpcb.send.pktSendCache / newConn->pcb->fpcb.pktSize) != maxSendCache)) {
        FILLP_LOGERR("fillp_sock_id:%d Invalid pkt cache size", sock->index);
        return -1;
    }

    if (newConn->calcRttDuringConnect) {
        struct FillpPcb *fpcb = &(newConn->pcb->fpcb);
        fpcb->rtt = newConn->calcRttDuringConnect;
    }

    newConn->pcb->fpcb.characters = newConn->peerCharacters & (FILLP_UINT32)FILLP_DEFAULT_SUPPORT_CHARACTERS;
    newConn->pcb->fpcb.fcAlg = newConn->peerFcAlgs & (FILLP_UINT8)FILLP_SUPPORT_ALGS;

    if (FillpInitPcb(&newConn->pcb->fpcb, (FILLP_INT)maxSendCache, (FILLP_INT)maxRecvCache) != ERR_OK) {
        FILLP_LOGERR("fillp_sock_id:%d Failed to init fillp pcb", sock->index);
        return -1;
    }
    return 0;
}

static void FillpInitNewPcbByConfirm(struct FtNetconn *newConn, FILLP_CONST struct FillpPktConnConfirm *confirm)
{
    newConn->pcb->fpcb.send.pktNum = confirm->cookieContent.localPacketSeqNumber;
    newConn->pcb->fpcb.send.seqNum = confirm->cookieContent.localMessageSeqNumber;
    newConn->pcb->fpcb.recv.lastPackPktNum = confirm->cookieContent.remotePacketSeqNumber;
    newConn->pcb->fpcb.recv.lastPackSeqNum = confirm->cookieContent.remoteMessageSeqNumber;
    newConn->pcb->fpcb.send.pktStartNum = confirm->cookieContent.localPacketSeqNumber;
    newConn->pcb->fpcb.send.seqStartNum = confirm->cookieContent.localMessageSeqNumber;
    newConn->pcb->fpcb.send.ackSeqNum = confirm->cookieContent.localMessageSeqNumber;
    newConn->pcb->fpcb.send.maxAckNumFromReceiver = confirm->cookieContent.localMessageSeqNumber;

    newConn->pcb->fpcb.recv.prePackPktNum = confirm->cookieContent.remotePacketSeqNumber;
    newConn->pcb->fpcb.recv.pktNum = confirm->cookieContent.remotePacketSeqNumber;
    newConn->pcb->fpcb.recv.seqNum = confirm->cookieContent.remoteMessageSeqNumber;
    newConn->pcb->fpcb.recv.pktStartNum = confirm->cookieContent.remotePacketSeqNumber;
    newConn->pcb->fpcb.recv.seqStartNum = confirm->cookieContent.remoteMessageSeqNumber;
    newConn->pcb->fpcb.recv.endSeqNum = confirm->cookieContent.remoteMessageSeqNumber;
    newConn->pcb->fpcb.statistics.pack.packPktNum = confirm->cookieContent.remotePacketSeqNumber;
    newConn->pcb->fpcb.statistics.appFcStastics.pktNum = confirm->cookieContent.remotePacketSeqNumber;

    newConn->pcb->fpcb.localUniqueId = confirm->cookieContent.localMessageSeqNumber;
    newConn->pcb->fpcb.peerUniqueId = confirm->cookieContent.remoteMessageSeqNumber;
}

void FillpInitNewconnBySock(struct FtNetconn *conn, FILLP_CONST struct FtSocket *sock)
{
    NetconnSetAddrType(conn, sock->sockAddrType);
    NetconnSetPktSize(conn, sock->resConf.flowControl.pktSize);
    NetconnSetOpersiteRate(conn, sock->resConf.flowControl.oppositeSetRate);
    NetconnSetSlowStart(conn, sock->resConf.flowControl.slowStart);
    NetconnSetPackInterval(conn, sock->resConf.flowControl.packInterval);
    FILLP_LOGDBG("Set pack interval:%u", sock->resConf.flowControl.packInterval);
    NetconnSetDirectlySend(conn, sock->directlySend);
}

static FILLP_INT FillpInitNewConnByConfirm(struct FillpPcb *pcb, struct FtNetconn *newConn,
    FILLP_CONST struct FillpPktConnConfirm *confirm, FILLP_CONST struct FtNetconn *conn, FILLP_CONST struct NetBuf *p)
{
    FILLP_SIZE_T maxSendCache;
    FILLP_SIZE_T maxRecvCache;
    struct sockaddr *addr = FILLP_NULL_PTR;
    FILLP_UINT16 addrLen = 0;
    struct SpungePcb *spcb = (struct SpungePcb*)pcb->spcb;
    struct sockaddr *localAddr = (struct sockaddr *)(void *)(&spcb->localAddr);
    struct FtSocket *sock = (struct FtSocket *)conn->sock;

    maxSendCache = sock->resConf.common.maxServerAllowSendCache;
    maxRecvCache = sock->resConf.common.maxServerAllowRecvCache;

    maxSendCache = UTILS_MIN(maxSendCache, confirm->cookieContent.remoteRecvCache);
    maxRecvCache = UTILS_MIN(maxRecvCache, confirm->cookieContent.remoteSendCache);

    NetconnSetRecvCacheSize(newConn, (FILLP_UINT32)maxRecvCache);
    NetconnSetSendCacheSize(newConn, (FILLP_UINT32)maxSendCache);
    FillpInitNewconnBySock(newConn, sock);
    NetconnSetLocalPort(newConn, conn->pcb->localPort); // The same with the server listen port

    /* Scenario: FtAccept() is not done. So NetconnSetSock() is not yet set in
         SpungeHandleMsgConnAccepted(), hence the variable ftSock is NULL
         and dumping in FillpDoInput.

         Temporarily the accepted->netconn sock reference is LISTEN socket.  It will reference
         to actual accepted sock in SpungeHandleMsgConnAccepted() when APP
         calls the FtAccept(). So if the keep alive timer expires before APP calls the FtAccept()
         then fc_cyle() will run and coredump can happen as the netconn->sock will be NULL

    */
    newConn->sock = sock; // It is very important to set this , because it is necessary to make netconn has a socket
    if (FillpInitNewPcbByNewConn(newConn, maxSendCache, maxRecvCache) != 0) {
        return -1;
    }

    FillpInitNewPcbByConfirm(newConn, confirm);
    FillpErrorType err = memcpy_s(&newConn->pcb->localAddr, sizeof(newConn->pcb->localAddr), localAddr,
        sizeof(spcb->localAddr));
    if (err != EOK) {
        FILLP_LOGERR("fillp_init_newConn_by_confirm memcpy_s local ip failed: %d", err);
        return err;
    }

    addr = (struct sockaddr *)(void *)&p->addr;
    NetconnSetAddrType(newConn, addr->sa_family);
    if (addr->sa_family == AF_INET) {
        addrLen = sizeof(struct sockaddr_in);
    } else {
        addrLen = sizeof(struct sockaddr_in6);
    }

    err = memcpy_s(&newConn->pcb->remoteAddr, sizeof(newConn->pcb->remoteAddr), addr, addrLen);
    if (err != EOK) {
        FILLP_LOGERR("fillp_init_newConn_by_confirm memcpy_s remote ip failed: %d", err);
        return err;
    }
    newConn->pcb->addrLen = addrLen;

    FillpNetconnSetState(newConn, CONN_STATE_CONNECTING);

    return ERR_OK;
}

static inline void FillpInitPeerOfNewconn(struct FtNetconn *newConn, FILLP_UINT32 peerPktSize)
{
    newConn->peerPktSize = peerPktSize;
    newConn->peerFcAlgs = 0;
    newConn->peerCharacters = 0;
}

static void FillpProcessConnConfirm(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p,
    FILLP_CONST struct FillpPktConnConfirm *confirm, FILLP_CONST struct FtNetconn *conn,
    struct SpungeInstance *inst)
{
    struct sockaddr *addr = (struct sockaddr *)(void *)&p->addr;
    struct FtSocket *sock = (struct FtSocket *)conn->sock;

    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("sock is null");
        return;
    }

    struct FtNetconn *newConn = FillpNetconnAlloc(addr->sa_family, inst);
    if (newConn == FILLP_NULL_PTR) {
        FILLP_LOGERR("fillp_sock_id:%d Failed in allocate new netconn connection", sock->index);
        return;
    }

    /* If client is old version then it will not have FILLP_PKT_EXT_CONNECT_CONFIRM_CARRY_PKT_SIZE
        parameter, so used current node pkt size */
    FillpInitPeerOfNewconn(newConn, sock->resConf.flowControl.pktSize);

    /* Decode connection confirm extension parameters */
    (void)FillpDecodeExtPara((FILLP_UCHAR *)(p->p) + sizeof(struct FillpPktConnConfirm),
        (FILLP_INT)(p->len - ((FILLP_INT)sizeof(struct FillpPktConnConfirm) - FILLP_HLEN)), newConn);

    if (FillpInitNewConnByConfirm(pcb, newConn, confirm, conn, p) != ERR_OK) {
        FillpNetconnDestroy(newConn);
        return;
    }

    struct SockOsSocket *osSock = NETCONN_GET_OSSOCK(conn, SPUNGE_GET_CUR_INSTANCE()->instIndex);
    if (!OS_SOCK_OPS_FUNC_VALID(osSock, handlePacket)) {
        FILLP_LOGERR("os sock ops handlePacket is null");
        FillpNetconnDestroy(newConn);
        return;
    }
    FillpErrorType err = osSock->ioSock->ops->handlePacket(FILLP_PKT_TYPE_CONN_CONFIRM, (void *)osSock->ioSock,
        (void *)newConn->pcb, (void *)p);

    /* Here we need to set newConn->osSock, or it will be null pointer, and when do accept, it will be rewrite */
    newConn->osSocket[SPUNGE_GET_CUR_INSTANCE()->instIndex] = osSock;
    osSock->reference++;
    if (err != ERR_OK) {
        FILLP_LOGERR("sysio connect fail");
        FillpNetconnDestroy(newConn);
        return;
    }

    if (FillpQueuePush(sock->acceptBox, (void *)&newConn, FILLP_TRUE, 1) != ERR_OK) {
        FILLP_LOGERR("push to accept box fail");
        FillpNetconnDestroy(newConn);
        return;
    }

    if (!(SOCK_IS_NONBLOCKING(sock))) {
        (void)SYS_ARCH_SEM_POST(&sock->acceptSem);
    }

    sock->listenBacklog--;

    FILLP_LOGINF("Push conn to accept box fillp_sock_id:%d,sock->listenBacklog:%d", sock->index, sock->listenBacklog);

    SpungeEpollEventCallback(sock, SPUNGE_EPOLLIN, 1);
}

static void FillpConnConfirmTrace(struct FtSocket *sock, struct FillpPktConnConfirm *confirm)
{
    FillpTraceDescriptSt fillpTrcDesc;
    if (sock->traceFlag < FILLP_TRACE_DIRECT_NETWORK) {
        return;
    }
    struct FillpPktConnConfirm tmpConnConfirm;
    struct FillpPktHead *pktHdr = FILLP_NULL_PTR;
    struct FillpPktHead *tempHdr = FILLP_NULL_PTR;

    (void)memset_s(&tmpConnConfirm, sizeof(struct FillpPktConnConfirm), 0,
        sizeof(struct FillpPktConnConfirm));

    pktHdr = (struct FillpPktHead *)confirm->head;
    tempHdr = (struct FillpPktHead *)tmpConnConfirm.head;
    /* Recovert the header to NETWORK byte order to provide indication */
    tempHdr->flag = FILLP_HTONS(pktHdr->flag);
    tempHdr->dataLen = FILLP_HTONS(pktHdr->dataLen);
    tempHdr->pktNum = FILLP_HTONL(pktHdr->pktNum);
    tempHdr->seqNum = FILLP_HTONL(pktHdr->seqNum);

    FILLP_LM_FILLPMSGTRACE_OUTPUT_WITHOUT_FT_TRACE_ENABLE_FLAG(FILLP_TRACE_DIRECT_NETWORK, sock->traceHandle,
        sizeof(struct FillpPktConnConfirm), sock->index, fillpTrcDesc, (FILLP_CHAR *)(&tmpConnConfirm));
}

static FILLP_BOOL FillpConfirmCheckState(FILLP_UINT8 connState, struct FtSocket *sock, struct FillpPcb *pcb)
{
    if (connState == CONN_STATE_CONNECTED) {
        if ((pcb->recv.seqNum == pcb->recv.seqStartNum) && (pcb->send.maxAckNumFromReceiver ==
            pcb->send.seqStartNum)) { /* Only if no data recved or no data acked */
            FILLP_LOGDBG("fillp_sock_id:%d Conn confirm in open state "
                         "as data not received, so sending conn confirm ack, state = %u",
                         sock->index, connState);

            FillpSendConnConfirmAck(pcb);
        } else {
            FILLP_LOGINF("fillp_sock_id:%d Conn confirm in open state "
                         "so dropping the message,state=%u",
                         sock->index, connState);
        }

        return FILLP_FALSE;
    }

    if (connState != CONN_STATE_LISTENING) {
        FILLP_LOGINF("fillp_sock_id:%d Connection state in not correct, state = %u", sock->index, connState);
        return FILLP_FALSE;
    }
    return FILLP_TRUE;
}

void FillpConnConfirmInput(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p, struct SpungeInstance *inst)
{
    struct FtNetconn *conn = FILLP_GET_CONN(pcb);
    struct FtSocket *sock = (struct FtSocket *)conn->sock;
    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("sock is null");
        return;
    }

    FILLP_LOGINF("conn confirm input, fillp_sock_id:%d, source port:%u, remote port:%u", sock->index,
        UTILS_GET_ADDRPORT(&conn->pcb->localAddr), UTILS_GET_ADDRPORT(&p->addr));

    if (p->len < (FILLP_INT)(sizeof(struct FillpPktConnConfirm) - FILLP_HLEN)) {
        FILLP_LOGINF("fillp_sock_id:%d Invalid connection confirm,len=%d", sock->index, p->len);
        return;
    }

    struct FillpPktConnConfirm *confirm = (struct FillpPktConnConfirm *)(void *)p->p;
    FillpConnConfirmTrace(sock, confirm);
    FILLP_CONN_CONFIRM_RX_LOG(sock->index, confirm, (FILLP_UCHAR *)p->p + sizeof(struct FillpPktConnConfirm),
        (FILLP_INT)(p->len - ((FILLP_INT)sizeof(struct FillpPktConnConfirm) - FILLP_HLEN)));

    FILLP_UINT8 connState = NETCONN_GET_STATE(conn);
    if (FillpConfirmCheckState(connState, sock, pcb) == FILLP_FALSE) {
        return;
    }

    /* Below two parameters are not used at the server side */
    confirm->cookieLength = FILLP_NTOHS(confirm->cookieLength);
    confirm->tagCookie = FILLP_NTOHS(confirm->tagCookie);

    if ((confirm->tagCookie != FILLP_COOKIE_TAG) || (confirm->cookieLength != sizeof(FillpCookieContent))) {
        FILLP_LOGINF("fillp_sock_id:%d, received cookie length = %u,"
                     "actual cookie size = %zu, discarding the packet",
                     sock->index, confirm->cookieLength, sizeof(FillpCookieContent));
        return;
    }

    FILLP_INT ret = FillpValidateCookie(pcb, ((struct sockaddr_in *)(&conn->pcb->localAddr))->sin_port, &p->addr,
        &confirm->cookieContent);
    if (ret != FILLP_SUCCESS) {
        FILLP_LOGINF("fillp_sock_id:%d cookieContent validation fails"
                     "state = %u, discarding the packet",
                     sock->index, connState);
        return;
    }

    if (sock->listenBacklog <= 0) {
        FILLP_UINT32 localUniqueIdBk = pcb->localUniqueId;
        FILLP_LOGINF("fillp_sock_id:%d listen backLog is not available, backLog = %d",
            sock->index, sock->listenBacklog);
        /*
            We are not using 3rd parmeter , so removed to fix leval 4
            warning(warning:formal parameter not used)
        */
        pcb->localUniqueId = confirm->cookieContent.localMessageSeqNumber;
        FillpSendRst(pcb, (struct sockaddr *)&p->addr);
        pcb->localUniqueId = localUniqueIdBk;
        return;
    }
    FillpProcessConnConfirm(pcb, p, confirm, conn, inst);
}

void FillpHandleConnConfirmAckInput(struct FtSocket *sock, struct FtNetconn *conn, struct FillpPcb *pcb,
    FILLP_CONST struct NetBuf *p)
{
    /* Check the connection max rate, it should not be configured to more
        than the core max rate */
    if (sock->resConf.flowControl.maxRate > g_resource.flowControl.maxRate) {
        sock->resConf.flowControl.maxRate = g_resource.flowControl.maxRate;
    }

    if (sock->resConf.flowControl.maxRecvRate > g_resource.flowControl.maxRecvRate) {
        sock->resConf.flowControl.maxRecvRate = g_resource.flowControl.maxRecvRate;
    }

    FILLP_LOGINF("FillpConnConfirmAckInput: fillp_sock_id:%d client connection "
                 "established, time = %lld, local seq num = %u, local pkt num = %u, peer seq num = %u, "
                 "peer pkt num = %u, maxRate:%u, maxRecvRate:%u",
                 sock->index, SYS_ARCH_GET_CUR_TIME_LONGLONG(), pcb->send.seqNum, pcb->send.pktNum, pcb->recv.seqNum,
                 pcb->recv.pktNum, sock->resConf.flowControl.maxRate, sock->resConf.flowControl.maxRecvRate);

    FillpNetconnSetState(conn, CONN_STATE_CONNECTED);
    FILLP_SOCK_SET_ERR(sock, ERR_OK);
    FillpNetconnSetSafeErr(sock->netconn, ERR_OK);
    SpungeConnConnectSuccess(conn->sock);
    sock->coreErrType[MSG_TYPE_DO_CONNECT] = ERR_OK;

    FILLP_UNUSED_PARA(p);

    pcb->connTimestamp = SYS_ARCH_GET_CUR_TIME_LONGLONG();
}

static FILLP_BOOL FillpCheckConfirmAckInfoIsValid(struct FillpPcb *pcb, struct FtSocket *sock,
    struct FillpPktConnConfirmAck *confirmAck)
{
    FILLP_UINT32 serverSendCache;
    FILLP_UINT32 serverRecvCache;

    if ((confirmAck->pktSize == 0) || (confirmAck->pktSize > (FILLP_MAX_PKT_SIZE - FILLP_HLEN))) {
        FILLP_LOGINF("fillp_sock_id:%d pktSize value is not correct, pktSize = %u "
                     "conn->pcb->sock->g_resource.flowControl.pktSize = %u",
                     sock->index, confirmAck->pktSize, sock->resConf.flowControl.pktSize);
        return FILLP_FALSE;
    }

    if (confirmAck->sendCache == 0) {
        FILLP_LOGINF("fillp_sock_id:%d sendCache value is not correct, sendCache = %u",
            sock->index, confirmAck->sendCache);
        return FILLP_FALSE;
    }

    if (confirmAck->recvCache == 0) {
        FILLP_LOGINF("fillp_sock_id:%d recvCache value is not correct, recvCache = %u",
            sock->index, confirmAck->recvCache);
        return FILLP_FALSE;
    }

    serverSendCache = confirmAck->sendCache;
    serverRecvCache = confirmAck->recvCache;

    if ((serverSendCache > pcb->mpRecvSize) || (serverRecvCache > pcb->mpSendSize)) {
        FILLP_LOGINF("FillpConnConfirmAckInput: fillp_sock_id:%d Connection response send cache or receive "
                     "cache is more than what client requested sendCache : %u receive_cache:%u \r\n",
                     sock->index, serverSendCache, serverRecvCache);
        return FILLP_FALSE;
    }

    /* FILLP_SIZE_T is added to remove the linux compile warning */
    pcb->pktSize = (FILLP_SIZE_T)confirmAck->pktSize;

    pcb->recv.pktRecvCache = (FILLP_UINT32)(serverSendCache * pcb->pktSize);
    pcb->send.pktSendCache = (FILLP_UINT32)(serverRecvCache * pcb->pktSize);

    if (((pcb->recv.pktRecvCache / pcb->pktSize) != serverSendCache) ||
        ((pcb->send.pktSendCache / pcb->pktSize) != serverRecvCache)) {
        FILLP_LOGINF("send/recvCache out of range pcb->send.pktSendCache:%u,recvCache:%u", pcb->send.pktSendCache,
            pcb->recv.pktRecvCache);
        return FILLP_FALSE;
    }
    return FILLP_TRUE;
}

void FillpConnConnectionEstFailure(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p)
{
    struct FtNetconn *conn = FILLP_GET_CONN(pcb);
    struct FtSocket *sock = FILLP_NULL_PTR;
    if (conn == FILLP_NULL_PTR) {
        FILLP_LOGERR("conn is NULL");
        return;
    }

    sock = (struct FtSocket *)conn->sock;
    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("sock is null");
        return;
    }

    FillpSendRst(pcb, (struct sockaddr *)&p->addr);

    FillpNetconnSetState(conn, CONN_STATE_IDLE);
    SET_ERRNO(FILLP_ENOMEM);
    sock->coreErrType[MSG_TYPE_DO_CONNECT] = ERR_SYSTEM_MEMORY_FAILURE;
    if (SOCK_IS_NONBLOCKING(sock)) {
        FILLP_SOCK_SET_ERR(sock, FILLP_ENOMEM);
        FillpNetconnSetSafeErr(conn, ERR_NORES);
    } else {
        FillpNetconnSetSafeErr(conn, ERR_NORES);
    }

    SpungeConnConnectFail(conn->sock);
}

static void FillpCheckandcopyConfirmAckAddr(struct FillpPcb *fpcb,
    FILLP_CONST struct FillpPktConnConfirmAck *confirmAck)
{
    struct SpungePcb *spcb = (struct SpungePcb*)fpcb->spcb;
    struct FtSocket *sock = FILLP_GET_SOCKET(fpcb);
    struct sockaddr_in6 matchAddr;
    FILLP_BOOL match;

    (void)memset_s(&matchAddr, sizeof(matchAddr), 0, sizeof(matchAddr));
    matchAddr.sin6_family = sock->sockAddrType;
    /* check whether confirmAck->remoteAddr is 0 or not */
    match = UtilsAddrMatch((FILLP_CONST struct sockaddr_in *)&matchAddr,
        (FILLP_CONST struct sockaddr_in *)&confirmAck->remoteAddr);
    if (match == FILLP_TRUE) {
        FILLP_LOGERR("fillp_sock_id:%d invalidity remoteAddr 0", sock->index);
        return;
    }

    if (sock->sockAddrType == AF_INET) {
        FILLP_CONST struct sockaddr_in *ipv4Addr = (FILLP_CONST struct sockaddr_in *)&confirmAck->remoteAddr;
        FILLP_CONST struct sockaddr_in *bind4Addr = (FILLP_CONST struct sockaddr_in *)&spcb->localAddr;

        /* socket bound, but remoteAddr is not equal to the bind addr */
        if ((sock->isSockBind == FILLP_TRUE) &&
            ((bind4Addr->sin_addr.s_addr != ipv4Addr->sin_addr.s_addr) || ((bind4Addr->sin_port != 0) &&
            (bind4Addr->sin_port != ipv4Addr->sin_port)))) { /* when call bind, sin_port can be set to 0 */
            FILLP_LOGERR("fillp_sock_id:%d invalidity remoteAddr != bind addr", sock->index);
            return;
        }
    } else if (sock->sockAddrType == AF_INET6) {
        FILLP_CONST struct sockaddr_in6 *ipv6Addr = (FILLP_CONST struct sockaddr_in6 *)&confirmAck->remoteAddr;
        FILLP_CONST struct sockaddr_in6 *bind6Addr = (FILLP_CONST struct sockaddr_in6 *)&spcb->localAddr;

        /* socket bound, but remoteAddr is not equal to the bind addr */
        if ((sock->isSockBind == FILLP_TRUE) &&
            (((FILLP_BOOL)UtilsIpv6AddrMatch(ipv6Addr, bind6Addr)) == FILLP_FALSE || ((bind6Addr->sin6_port != 0) &&
            (bind6Addr->sin6_port != ipv6Addr->sin6_port)))) { /* when call bind, sin6_port can be set to 0 */
            FILLP_LOGERR("fillp_sock_id:%d invalidity remoteAddr != bind addr", sock->index);
            return;
        }
    } else {
        FILLP_LOGERR("fillp_sock_id:%d invalidity sa_family", sock->index);
        return;
    }

    (void)memcpy_s(&spcb->localAddr, sizeof(struct sockaddr_in6), &confirmAck->remoteAddr,
        sizeof(struct sockaddr_in6));
}

static FILLP_BOOL FillpCheckConfirmAckPar(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p)
{
    if (pcb == FILLP_NULL_PTR) {
        FILLP_LOGWAR("fillp pcb pointer is NULL \r\n");
        return FILLP_FALSE;
    }
    if (p == FILLP_NULL_PTR) {
        FILLP_LOGWAR("net buf pointer is NULL \r\n");
        return FILLP_FALSE;
    }
    if (p->len < (FILLP_INT)(sizeof(struct FillpPktConnConfirmAck) - FILLP_HLEN)) {
        FILLP_LOGINF("Invalid confirm ack, len = %d", p->len);
        return FILLP_FALSE;
    }
    struct FtNetconn *conn = FILLP_GET_CONN(pcb);
    if (conn == FILLP_NULL_PTR) {
        FILLP_LOGERR("conn is NULL");
        return FILLP_FALSE;
    }
    struct FtSocket *sock = (struct FtSocket *)conn->sock;
    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("sock is null");
        return FILLP_FALSE;
    }
    FILLP_LOGINF("confirm ack input fillp_sock_id:%d, source port:%u, remote port:%u", sock->index,
        UTILS_GET_ADDRPORT(&conn->pcb->localAddr), UTILS_GET_ADDRPORT(&p->addr));
    return FILLP_TRUE;
}

static void FillpConnConfirmAckTrace(struct FtSocket *sock, struct FillpPktConnConfirmAck *confirmAck)
{
    FillpTraceDescriptSt fillpTrcDesc;
    if (sock->traceFlag < FILLP_TRACE_DIRECT_NETWORK) {
        return;
    }
    struct FillpPktConnConfirmAck tmpConnConfirmAck;
    (void)memset_s(&tmpConnConfirmAck, sizeof(struct FillpPktConnConfirmAck), 0,
        sizeof(struct FillpPktConnConfirmAck));

    struct FillpPktHead *pktHdr = (struct FillpPktHead *)confirmAck->head;
    struct FillpPktHead *tmpHeader = (struct FillpPktHead *)(void *)tmpConnConfirmAck.head;

    /* Recovert the header to NETWORK byte order to provide indication */
    tmpHeader->flag = FILLP_HTONS(pktHdr->flag);
    tmpHeader->dataLen = FILLP_HTONS(pktHdr->dataLen);
    tmpHeader->pktNum = FILLP_HTONL(pktHdr->pktNum);
    tmpHeader->seqNum = FILLP_HTONL(pktHdr->seqNum);

    /* Below field is already in NETWORK byte order */
    tmpConnConfirmAck.sendCache = confirmAck->sendCache;
    tmpConnConfirmAck.recvCache = confirmAck->recvCache;
    tmpConnConfirmAck.pktSize = confirmAck->pktSize;

    FILLP_LM_FILLPMSGTRACE_OUTPUT_WITHOUT_FT_TRACE_ENABLE_FLAG(FILLP_TRACE_DIRECT_NETWORK, sock->traceHandle,
        sizeof(struct FillpPktConnConfirmAck), sock->index, fillpTrcDesc,
        (FILLP_CHAR *)(&tmpConnConfirmAck));
}

static void FillpSaveConfirmActToPcb(struct FillpPktConnConfirmAck *confirmAck, struct FillpPcb *pcb)
{
    struct FillpPktHead *tmpHeader = (struct FillpPktHead *)(void *)confirmAck->head;
    pcb->peerUniqueId = tmpHeader->seqNum;
    pcb->recv.prePackPktNum = tmpHeader->pktNum;
    pcb->recv.pktNum = tmpHeader->pktNum;
    pcb->recv.seqNum = tmpHeader->seqNum;
    pcb->recv.pktStartNum = tmpHeader->pktNum;
    pcb->recv.seqStartNum = tmpHeader->seqNum;
    pcb->recv.endSeqNum = pcb->recv.seqStartNum;
    pcb->statistics.pack.packPktNum = pcb->recv.pktNum;
    pcb->statistics.appFcStastics.pktNum = pcb->recv.pktNum;
}

void FillpConnConfirmAckInput(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p)
{
    if (FillpCheckConfirmAckPar(pcb, p) == FILLP_FALSE) {
        return;
    }
    struct FtNetconn *conn = FILLP_GET_CONN(pcb);
    struct FillpPktConnConfirmAck *confirmAck = (struct FillpPktConnConfirmAck *)(void *)p->p;
    struct FtSocket *sock = (struct FtSocket *)conn->sock;
    FillpConnConfirmAckTrace(sock, confirmAck);
    FILLP_CONN_CONFIRM_ACK_LOG(sock->index, confirmAck, FILLP_DIRECTION_RX);
    FILLP_UINT8 connState = FILLP_GET_CONN_STATE(pcb);
    if (connState != CONN_STATE_CONNECTING) {
        FILLP_LOGINF("fillp_sock_id:%d Connection state response is not correct, state = %u", sock->index, connState);
        return;
    }
    confirmAck->sendCache = FILLP_NTOHL(confirmAck->sendCache);
    confirmAck->recvCache = FILLP_NTOHL(confirmAck->recvCache);
    confirmAck->pktSize = FILLP_NTOHL(confirmAck->pktSize);

    if (FillpCheckConfirmAckInfoIsValid(pcb, sock, confirmAck) == FILLP_FALSE) {
        return;
    }
    sock->resConf.flowControl.pktSize = (FILLP_UINT16)confirmAck->pktSize;
    FillpCheckandcopyConfirmAckAddr(pcb, confirmAck);
    if (FillpInitPcb(pcb, (FILLP_INT)(confirmAck->recvCache), (FILLP_INT)(confirmAck->sendCache)) != ERR_OK) {
        FILLP_LOGERR("fillp_sock_id:%d Failed to init the fillp PCB, releasing the connection", sock->index);
        FillpDisableConnRetryCheckTimer(&conn->pcb->fpcb);
        FillpConnConnectionEstFailure(pcb, p);
        return;
    }
    (void)SYS_ARCH_ATOMIC_SET(&sock->sendEventCount, (FILLP_INT)pcb->send.curItemCount);
    FillpDisableConnRetryCheckTimer(&conn->pcb->fpcb);
    FillpSaveConfirmActToPcb(confirmAck, pcb);
    struct SockOsSocket *osSock = NETCONN_GET_OSSOCK(sock->netconn, sock->inst->instIndex);
    if (!OS_SOCK_OPS_FUNC_VALID(osSock, connected)) {
        FILLP_LOGERR("osSock is null");
        FillpConnConnectionEstFailure(pcb, p);
        return;
    }
    osSock->ioSock->ops->connected(sock, osSock->ioSock);
    FillpHandleConnConfirmAckInput(sock, conn, pcb, p);
    conn->clientFourHandshakeState = FILLP_CLIENT_FOUR_HANDSHAKE_STATE_CONFIRMACK_RCVED;
    FILLP_LOGDBG("FillpConnConfirmAckInput: fillp_sock_id:%d, initial_send_rate = %u", FILLP_GET_SOCKET(pcb)->index,
        pcb->send.flowControl.sendRate);
}

static void ConnectingHandleFinInput(struct FillpPcb *pcb, struct FtSocket *sock,
    struct FtNetconn *conn, FILLP_CONST struct NetBuf *p, FILLP_CONST struct FillpFinFlags *flags)
{
    /* If this socket is not accepted then no event need to given to application as listen socket
        IN event is already gives and current socket is accepted by application. No need to change state also.
        This socket will be released after keep alive timeout after accept.
        We just drop FIN message wait for retranmission in connected state and then handle */
    if (sock->isListenSock) {
        return;
    }

    if (!flags->ackSet) { // Only non-ack needs to reply, or it may cause flooding
        FillpSendRst(pcb, (struct sockaddr *)&p->addr);
    }

    FillpDisableConnRetryCheckTimer(&conn->pcb->fpcb);

    if (flags->verSet) {
        sock->coreErrType[MSG_TYPE_DO_CONNECT] = ERR_REMOTE_REJECT_VERSION;
    } else {
        sock->coreErrType[MSG_TYPE_DO_CONNECT] = ERR_REMOTE_REJECT_OR_CLOSE;
    }

    FillpNetconnSetState(conn, CONN_STATE_IDLE);
    SpungeConnConnectFail(conn->sock);
}

static void FillpStateClosingHandleFinInput(struct FillpPcb *pcb, struct FtNetconn *conn,
    FILLP_BOOL isAck, FILLP_BOOL isWr, FILLP_BOOL *pcbFreed)
{
    if (isAck) {
        pcb->isFinAckReceived = FILLP_TRUE;
    }

    if (isWr || conn->peerWrSet || (isAck && conn->shutdownRdSet && conn->shutdownWrSet)) {
        // If not recved fin before, then there should be one IN event
        struct FtSocket *sock = (struct FtSocket *)conn->sock;
        FILLP_INT epEvt = (conn->peerWrSet ? 0 : (SPUNGE_EPOLLIN | SPUNGE_EPOLLRDHUP));
        conn->peerWrSet = FILLP_TRUE;
        SpungeShutdownSock(conn->sock, SPUNGE_SHUT_RDWR);

        epEvt = (FILLP_INT)((FILLP_UINT32)epEvt | (SPUNGE_EPOLLHUP | SPUNGE_EPOLLOUT));
        sock->errEvent |= SPUNGE_EPOLLHUP;
        SpungeEpollEventCallback(sock, epEvt, 1);

        *pcbFreed = FILLP_TRUE;
        SpungeConnClosed(conn);
    }
}

static void ConnectedHandleFinInput(struct FtSocket *sock, struct FtNetconn *conn, FILLP_BOOL isWr)
{
    if (isWr && !conn->peerWrSet) {
        conn->peerWrSet = FILLP_TRUE;
        SpungeShutdownSock(sock, SPUNGE_SHUT_RD);
        sock->errEvent |= SPUNGE_EPOLLRDHUP;
        SpungeEpollEventCallback(sock, ((FILLP_INT)SPUNGE_EPOLLIN | (FILLP_INT)SPUNGE_EPOLLRDHUP), 1);
    }
}

static void FillpFinInputTrace(FILLP_CONST struct FtSocket *sock, FILLP_CONST struct NetBuf *p)
{
    struct FillpPktFin *req = FILLP_NULL_PTR;
    struct FillpPktFin tmpFinPkt;
    struct FillpPktHead *pktHdr = FILLP_NULL_PTR;
    struct FillpPktHead *tmpHead = FILLP_NULL_PTR;
    FILLP_UINT16 flag;
    FillpTraceDescriptSt fillpTrcDesc;

    (void)memset_s(&tmpFinPkt, sizeof(struct FillpPktFin), 0, sizeof(struct FillpPktFin));
    if (sock->traceFlag >= FILLP_TRACE_DIRECT_NETWORK) {
        req = (struct FillpPktFin *)(void *)p->p;
        pktHdr = (struct FillpPktHead *)(void *)req->head;
        tmpHead = (struct FillpPktHead *)(void *)tmpFinPkt.head;
        flag = tmpHead->flag;
        /* Recovert the header to NETWORK byte order to provide indication */
        tmpHead->flag = FILLP_HTONS(flag);
        tmpHead->dataLen = FILLP_HTONS(pktHdr->dataLen);
        tmpHead->pktNum = FILLP_HTONL(pktHdr->pktNum);
        tmpHead->seqNum = FILLP_HTONL(pktHdr->seqNum);

        /* Below field is already in NETWORK byte order */
        tmpFinPkt.flag = req->flag;

        FILLP_LM_FILLPMSGTRACE_OUTPUT_WITHOUT_FT_TRACE_ENABLE_FLAG(FILLP_TRACE_DIRECT_NETWORK, sock->traceHandle,
            sizeof(struct FillpPktFin), sock->index, fillpTrcDesc, (FILLP_CHAR *)(&tmpFinPkt));
    }
}

static FILLP_INT FillpHandleFinFlagGet(FILLP_CONST struct NetBuf *p, struct FillpFinFlags *flags)
{
    struct FillpPktFin *fin = (struct FillpPktFin *)(void *)p->p;
    fin->flag = FILLP_HTONS(fin->flag);

    if (FILLP_PKT_DISCONN_MSG_FLAG_IS_ACK(fin->flag)) {
        flags->ackSet = FILLP_TRUE;
    }

    if (FILLP_PKT_DISCONN_MSG_FLAG_IS_RD(fin->flag)) {
        flags->rdSet = FILLP_TRUE;
    }

    if (FILLP_PKT_DISCONN_MSG_FLAG_IS_WR(fin->flag)) {
        flags->wrSet = FILLP_TRUE;
    }

    if (FILLP_PKT_DISCONN_MSG_FLAG_IS_VER(fin->flag)) {
        flags->verSet = FILLP_TRUE;
    }

    if (!flags->wrSet && !flags->ackSet) {
        FILLP_LOGWAR("Invalid fin flag!!!fin ack:%u,peer_rd:%u,peer_wr:%u,ver:%u",
            flags->ackSet, flags->rdSet, flags->wrSet, flags->verSet);
        return ERR_FAILURE;
    }

    FILLP_LOGINF("fin ack:%u,peer_rd:%u,peer_wr:%u,ver:%u", flags->ackSet, flags->rdSet, flags->wrSet, flags->verSet);
    return ERR_OK;
}

static void FillpHandleFinRst(struct FtNetconn *conn, struct FtSocket *sock)
{
    // If not recved fin before, then there should be one IN event
    FILLP_INT epEvt = conn->peerWrSet ? 0 : (SPUNGE_EPOLLIN | SPUNGE_EPOLLRDHUP);
    conn->peerRdSet = conn->peerWrSet = FILLP_TRUE;
    SpungeShutdownSock(conn->sock, SPUNGE_SHUT_RDWR);

    epEvt = (FILLP_INT)((FILLP_UINT32)epEvt | (SPUNGE_EPOLLHUP | SPUNGE_EPOLLOUT));
    sock->errEvent |= (FILLP_UINT32)SPUNGE_EPOLLHUP;
    SpungeEpollEventCallback(sock, epEvt, 1);

    SpungeConnClosed(conn);
}

static void FillpHandleFin(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p, FILLP_BOOL *pcbFreed)
{
    struct FtNetconn *conn = FILLP_NULL_PTR;
    struct FtSocket *sock = FILLP_NULL_PTR;
    struct FillpFinFlags flags = {0};
    int netconnState = 0;

    conn = FILLP_GET_CONN(pcb);
    netconnState = NETCONN_GET_STATE(conn);
    sock = (struct FtSocket *)conn->sock;


    if (FillpHandleFinFlagGet(p, &flags) != ERR_OK) {
        return;
    }

    /* Now we received disconn message
       1) if we has send disconn message before, this one may be the ack, then we need to cancel timer
       2) if wr set, means peer won't send data anymore
          then we need to set the read shutdown, when the application read all the data of stack, we will rise HUP event
          and recv() returns 0
       3) if rdwr set, means it is reset message, then need to set rdwr shutdown, application will get HUP event,  and
          send() return 0 and netconn state goto CLOSED
    */
    switch (netconnState) {
        /* If state is not connected or closing, it handle depends on different state */
        case CONN_STATE_LISTENING:
            if (!flags.ackSet) { // Only non-ack needs to reply, or it may cause flooding
                FillpSendRst(pcb, (struct sockaddr *)&p->addr);
            }
            return;

        case CONN_STATE_CONNECTING:
            ConnectingHandleFinInput(pcb, sock, conn, p, &flags);
            return;

        case CONN_STATE_CLOSED:
            /* If this is ack, means no need to response anymore, because that means peer already
                know you are shutdown */
            if (!flags.ackSet) {
                FillpSendFinAck(pcb, (struct sockaddr *)&p->addr);
            }
            break;

        case CONN_STATE_CLOSING:
        case CONN_STATE_CONNECTED:
            /* If this is ack, means no need to response anymore, because that means peer already
                know you are shutdown */
            if (!flags.ackSet) {
                FillpSendFinAck(pcb, (struct sockaddr *)&p->addr);
            }

            if (flags.rdSet) {
                conn->peerRdSet = FILLP_TRUE;
            }

            /* RST case */
            FillpDfxSockLinkAndQosNotify(sock, FILLP_DFX_LINK_FIN_INPUT);
            if (flags.wrSet && flags.rdSet) {
                FillpHandleFinRst(conn, sock);
                return;
            }

            if (netconnState == CONN_STATE_CLOSING) {
                FillpStateClosingHandleFinInput(pcb, conn, flags.ackSet, flags.wrSet, pcbFreed);
            } else if (netconnState == CONN_STATE_CONNECTED) {
                ConnectedHandleFinInput(sock, conn, flags.wrSet);
            }

            break;

        default:
            FILLP_LOGINF("State err, fillp_sock_id:%d, state:%d", sock->index, netconnState);
            break;
    }
}

void FillpFinInput(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p, FILLP_BOOL *pcbFreed)
{
    struct FillpPktHead *fillpHead = FILLP_NULL_PTR;
    struct FillpPktFin *fin = FILLP_NULL_PTR;
    struct FtNetconn *conn = FILLP_NULL_PTR;
    struct FtSocket *sock = FILLP_NULL_PTR;

    conn = FILLP_GET_CONN(pcb);
    sock = (struct FtSocket *)conn->sock;

    if (p->len < (FILLP_INT)(sizeof(struct FillpPktFin) - FILLP_HLEN)) {
        FILLP_LOGINF("Fin packet size invalid fillp_sock_id:%d,pkt_len:%d,expected length:%zu", sock->index, p->len,
            (sizeof(struct FillpPktFin) - FILLP_HLEN));
        return;
    }

    FILLP_CONN_FIN_LOG(sock->index, (struct FillpPktFin *)(void *)p->p, FILLP_DIRECTION_RX);

    if (sock->isListenSock) {
        return;
    }

    FillpFinInputTrace(sock, p);

    /* Header fields are already converted in FillpDoInput, and hence here
       should not be converted again
    */
    fin = (struct FillpPktFin *)(void *)p->p;
    fillpHead = (struct FillpPktHead *)fin->head;

    if (fillpHead->seqNum != pcb->peerUniqueId) {
        FILLP_LOGWAR("FillpFinInput: fillp_sock_id:%d Stale fin received peerUniqueId = %u,"
            "fin->head.seqNum %u\r\n", sock->index, pcb->peerUniqueId, fillpHead->seqNum);
        return;
    }

    FillpHandleFin(pcb, p, pcbFreed);
}

static void FillpSendConnReqBuild(struct FillpPcb *pcb, struct FillpPktConnReq *req, FILLP_LLONG curTime)
{
    struct FillpPktHead *pktHdr = FILLP_NULL_PTR;

    req->sendCache = FILLP_HTONL(pcb->mpSendSize);
    req->recvCache = FILLP_HTONL(pcb->mpRecvSize);

    req->cookiePreserveTime = FILLP_HTONL(pcb->clientCookiePreserveTime);
    req->timestamp = FILLP_HTONLL((FILLP_ULLONG)curTime);

    pktHdr = (struct FillpPktHead *)req->head;

    /* 0 converted to network order is also 0, hence explicit conversion not applied */
    pcb->send.pktNum = pcb->send.pktStartNum;
    pcb->send.ackSeqNum = pcb->send.seqStartNum;
    pcb->send.maxAckNumFromReceiver = pcb->send.ackSeqNum;
    pcb->send.seqNum = pcb->send.seqStartNum;

    pcb->localUniqueId = pcb->send.seqStartNum;

    pktHdr->pktNum = pcb->send.pktStartNum;
    pktHdr->seqNum = pcb->send.seqStartNum;

    pktHdr->flag = FILLP_NULL_NUM;
    FILLP_HEADER_SET_PKT_TYPE(pktHdr->flag, FILLP_PKT_TYPE_CONN_REQ);
    FILLP_HEADER_SET_PROTOCOL_VERSION(pktHdr->flag, FILLP_PROTOCOL_VERSION_NUMBER);
    pktHdr->flag = FILLP_HTONS(pktHdr->flag);

    pktHdr->dataLen = (sizeof(struct FillpPktConnReq) - FILLP_HLEN);
    pktHdr->dataLen = FILLP_HTONS(pktHdr->dataLen);

    pktHdr->pktNum = FILLP_HTONL(pktHdr->pktNum);
    pktHdr->seqNum = FILLP_HTONL(pktHdr->seqNum);

    FILLP_CONN_REQ_LOG(FILLP_GET_SOCKET(pcb)->index, req, FILLP_DIRECTION_RX);
}

FILLP_INT FillpSendConnReq(struct FillpPcb *pcb)
{
    struct FillpPktConnReq req;
    FILLP_LLONG curTime;
    struct FtNetconn *conn = FILLP_GET_CONN(pcb);
    struct FtSocket *sock = (struct FtSocket *)conn->sock;
    FillpTraceDescriptSt fillpTrcDesc;
    FILLP_INT ret;
    FILLP_INT osErrno;

    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("sock is NULL");
        return -1;
    }

    /* If already received the confirmAck then no need to send the conn_req again after timeout */
    if (conn->clientFourHandshakeState == FILLP_CLIENT_FOUR_HANDSHAKE_STATE_CONFIRMACK_RCVED) {
        FILLP_LOGINF("already received confirmAck");
        return ERR_NON_FATAL;
    }

    curTime = SYS_ARCH_GET_CUR_TIME_LONGLONG();
    FillpSendConnReqBuild(pcb, &req, curTime);
    FILLP_LOGINF("fillp_sock_id:%d,send req, "
        "sendCache:%u,recvCache:%u,timestamp:%lld,startSeqNum:%u,startPktNum:%u,source port:%u,dest port:%u",
        sock->index, pcb->mpSendSize, pcb->mpRecvSize, curTime, pcb->send.seqStartNum,
        pcb->send.pktStartNum, UTILS_GET_ADDRPORT(&conn->pcb->localAddr),
        UTILS_GET_ADDRPORT(&conn->pcb->remoteAddr));
    ret = pcb->sendFunc(conn, (char *)&req, sizeof(struct FillpPktConnReq), conn->pcb);
    if (ret <= 0) {
        osErrno = FT_OS_GET_ERRNO;
        pcb->statistics.debugPcb.connReqFailed++;

        if ((osErrno == FILLP_EWOULDBLOCK) || (osErrno == FILLP_EINPROGRESS)) {
            return ERR_NON_FATAL;
        }
        FILLP_LOGINF("send connreq fail");
        return ret;
    } else {
        fillpTrcDesc.traceDirection = FILLP_TRACE_DIRECT_SEND;

        FILLP_LM_FILLPMSGTRACE_OUTPUT(sock->traceFlag, FILLP_TRACE_DIRECT_NETWORK, sock->traceHandle,
            sizeof(struct FillpPktConnReq), sock->index, (FILLP_UINT8 *)(void *)&fillpTrcDesc,
            (FILLP_CHAR *)(&req));

        if ((conn->clientFourHandshakeState != FILLP_CLIENT_FOUR_HANDSHAKE_STATE_CONFIRMACK_RCVED) &&
            (conn->clientFourHandshakeState != FILLP_CLIENT_FOUR_HANDSHAKE_STATE_CONFIRM_SENT)) {
            conn->clientFourHandshakeState = FILLP_CLIENT_FOUR_HANDSHAKE_STATE_REQSENT;
        }

        pcb->statistics.debugPcb.connReqSend++;
    }

    return ret;
}

static FILLP_UINT16 FillpSendConnReqAckBuild(FILLP_CONST struct FillpPcb *pcb,
    FILLP_CONST FillpCookieContent *stateCookie, FILLP_ULLONG timestamp)
{
    FILLP_INT ret;
    FILLP_UINT32 localCharacters = (FILLP_UINT32)FILLP_DEFAULT_SUPPORT_CHARACTERS;
    FILLP_UINT8 localAlg = (FILLP_UINT8)FILLP_SUPPORT_ALGS;
    FILLP_UINT16 dataLen = 0;
    struct FillpPktConnReqAck *reqAck = FILLP_NULL_PTR;
    struct FillpPktHead *pktHdr = FILLP_NULL_PTR;
    reqAck = (struct FillpPktConnReqAck *)g_rawMsg;
    pktHdr = (struct FillpPktHead *)reqAck->head;

    /* 0 converted to network order is also 0, hence explicit conversion not applied */
    pktHdr->pktNum = 0;
    pktHdr->seqNum = FILLP_HTONL(stateCookie->localMessageSeqNumber);

    pktHdr->flag = FILLP_NULL_NUM;
    FILLP_HEADER_SET_PKT_TYPE(pktHdr->flag, FILLP_PKT_TYPE_CONN_REQ_ACK);
    FILLP_HEADER_SET_PROTOCOL_VERSION(pktHdr->flag, FILLP_PROTOCOL_VERSION_NUMBER);

    pktHdr->flag = FILLP_HTONS(pktHdr->flag);
    reqAck->timestamp = FILLP_HTONLL(timestamp);
    reqAck->tagCookie = FILLP_COOKIE_TAG;
    reqAck->tagCookie = FILLP_HTONS(reqAck->tagCookie);
    reqAck->cookieLength = sizeof(FillpCookieContent);

    ret = memcpy_s(&reqAck->cookieContent, sizeof(FillpCookieContent), stateCookie, reqAck->cookieLength);
    if (ret != EOK) {
        FILLP_LOGERR("fillp_send_conn_reqAck memcpy_s cookieContent failed: %d", ret);
        return 0;
    }

    reqAck->cookieLength = FILLP_HTONS(reqAck->cookieLength);
    dataLen = sizeof(struct FillpPktConnReqAck);
    ret = FillpEncodeExtPara(g_rawMsg + dataLen, (FILLP_INT32)(FILLP_FRAME_MTU - dataLen),
        FILLP_PKT_EXT_CONNECT_CARRY_FC_ALG, (FILLP_UCHAR)(sizeof(FILLP_UINT8)), (FILLP_UCHAR *)&localAlg);
    if (ret <= 0) {
        /* As encode of extension parameter has failed, still we can continue to send request, it does not impact base
         * functionality */
        FILLP_LOGWAR("encode extension parameter FILLP_PKT_EXT_CONNECT_CARRY_FC_ALG failed");
    } else {
        dataLen += (FILLP_UINT16)ret;
    }

    localCharacters = FILLP_HTONL(localCharacters);
    ret = FillpEncodeExtPara(g_rawMsg + dataLen, (FILLP_INT32)(FILLP_FRAME_MTU - dataLen),
        FILLP_PKT_EXT_CONNECT_CARRY_CHARACTER, (FILLP_UCHAR)(sizeof(FILLP_UINT32)), (FILLP_UCHAR *)&localCharacters);
    if (ret <= 0) {
        /* As encode of extension parameter has failed, still we can continue to send request, it does not impact base
         * functionality */
        FILLP_LOGWAR("encode extension parameter FILLP_PKT_EXT_CONNECT_CARRY_CHARACTER failed");
    } else {
        dataLen += (FILLP_UINT16)ret;
    }

    pktHdr->dataLen = FILLP_HTONS(dataLen - (FILLP_UINT16)FILLP_HLEN);

    FILLP_CONN_REQ_ACK_TX_LOG(FILLP_GET_SOCKET(pcb)->index, reqAck, g_rawMsg + sizeof(struct FillpPktConnReqAck),
        dataLen - sizeof(struct FillpPktConnReqAck));
    return dataLen;
}

void FillpSendConnReqAck(struct FillpPcb *pcb, FILLP_CONST FillpCookieContent *stateCookie,
    FILLP_ULLONG timestamp)
{
    struct FillpPktConnReqAck *reqAck = (struct FillpPktConnReqAck *)g_rawMsg;
    struct FtNetconn *conn = FILLP_NULL_PTR;
    struct FtSocket *sock = FILLP_NULL_PTR;
    FILLP_INT ret;
    FILLP_UINT16 dataLen;
    struct SpungePcb *tempPcb = FILLP_NULL_PTR;

    if (pcb == FILLP_NULL_PTR) {
        FILLP_LOGERR("FillpSendConnReq: PCB pointer is NULL");
        return;
    }

    tempPcb = &SPUNGE_GET_CUR_INSTANCE()->tempSpcb;
    (void)memset_s(tempPcb, sizeof(struct SpungePcb), 0, sizeof(struct SpungePcb));

    conn = FILLP_GET_CONN(pcb);
    sock = (struct FtSocket *)conn->sock;

    dataLen = FillpSendConnReqAckBuild(pcb, stateCookie, timestamp);
    if (dataLen == 0) {
        return;
    }

    if (AF_INET == stateCookie->addressType) {
        *((struct sockaddr_in *)&tempPcb->remoteAddr) = *((struct sockaddr_in *)&stateCookie->remoteSockIpv6Addr);
        tempPcb->addrType = AF_INET;
        tempPcb->addrLen = sizeof(struct sockaddr_in);
    } else {
        tempPcb->remoteAddr = *(struct sockaddr_in6 *)&stateCookie->remoteSockIpv6Addr;
        tempPcb->addrType = AF_INET6;
        tempPcb->addrLen = sizeof(struct sockaddr_in6);
    }

    ret = pcb->sendFunc(conn, (char *)g_rawMsg, (FILLP_INT)dataLen, tempPcb);
    if (ret <= 0) {
        pcb->statistics.debugPcb.connReqAckFailed++;
        FILLP_LOGINF("Send fail");
    } else {
        FillpTraceDescriptSt fillpTrcDesc = FILLP_TRACE_DESC_INIT(FILLP_TRACE_DIRECT_SEND);

        FILLP_LM_FILLPMSGTRACE_OUTPUT(sock->traceFlag, FILLP_TRACE_DIRECT_NETWORK, sock->traceHandle,
            sizeof(struct FillpPktConnReqAck), sock->index, (FILLP_UINT8 *)(void *)&fillpTrcDesc,
            (FILLP_CHAR *)reqAck);

        pcb->statistics.debugPcb.connReqAckSend++;
    }

    FILLP_LOGINF("send conn_reqAck fillp_sock_id:%d,destport:%u", sock->index,
        UTILS_GET_ADDRPORT(&tempPcb->remoteAddr));
}

static FILLP_INT32 ConnConfirmBuild(struct FillpPcb *pcb, FILLP_CONST struct FillpConnReqAckClient *reqAck,
    struct FillpPktHead *pktHdr)
{
    FILLP_INT32 encMsgLen = 0;
    FILLP_INT ret;
    /* 0 converted to network order is also 0, hence explicit conversion not applied */
    pktHdr->pktNum = 0;
    pktHdr->seqNum = 0;
    pktHdr->flag = 0;
    FILLP_HEADER_SET_PKT_TYPE(pktHdr->flag, FILLP_PKT_TYPE_CONN_CONFIRM);
    FILLP_HEADER_SET_PROTOCOL_VERSION(pktHdr->flag, (FILLP_UINT16)FILLP_PROTOCOL_VERSION_NUMBER);
    pktHdr->flag = FILLP_HTONS(pktHdr->flag);

    encMsgLen = FILLP_HLEN;
    *((FILLP_UINT16 *)(g_rawMsg + encMsgLen)) = FILLP_HTONS(reqAck->tagCookie);
    encMsgLen += sizeof(FILLP_UINT16);
    *((FILLP_UINT16 *)(g_rawMsg + encMsgLen)) = FILLP_HTONS(reqAck->cookieLength);
    encMsgLen += sizeof(FILLP_UINT16);
    if (reqAck->cookieLength != sizeof(FillpCookieContent) || reqAck->cookieContent == FILLP_NULL_PTR) {
        FILLP_LOGERR("fillp_send_conn_confirm reqAck->cookieLength is wrong:%u, expect : %zu",
            reqAck->cookieLength, sizeof(FillpCookieContent));
        return 0;
    }
    ret = memcpy_s(g_rawMsg + encMsgLen, (FILLP_UINT32)(FILLP_FRAME_MTU - encMsgLen),
        reqAck->cookieContent, reqAck->cookieLength);
    if (ret != EOK) {
        FILLP_LOGERR("fillp_send_conn_confirm memcpy_s cookieContent failed:%d", ret);
        return 0;
    }
    encMsgLen += reqAck->cookieLength;

    /* NOTE: This parameter needs to be encoded as old server will use struct FillpPktConnConfirm-> remoteAddr
        address. */
    {
        struct SpungePcb*spcb = (struct SpungePcb*)pcb->spcb;
        ret = memcpy_s(g_rawMsg + encMsgLen, (FILLP_UINT32)((FILLP_INT)sizeof(g_rawMsg) - encMsgLen),
            &spcb->remoteAddr, sizeof(spcb->remoteAddr));
        if (ret != EOK) {
            FILLP_LOGERR("fillp_send_conn_confirm memcpy_s remoteAddr failed:%d", ret);
            return 0;
        }
        encMsgLen += sizeof(spcb->remoteAddr);
    }
    return encMsgLen;
}

static FILLP_INT32 ConnConfirmEncodeExtPara(const struct FillpPcb *pcb, FILLP_INT32 encMsgLen)
{
    FILLP_INT ret;
    FILLP_ULLONG tempRtt;
    FILLP_UINT32 tempValue32;

    tempRtt = FILLP_HTONLL(pcb->rtt);
    ret = FillpEncodeExtPara(g_rawMsg + encMsgLen, (FILLP_INT32)(FILLP_FRAME_MTU - encMsgLen),
        FILLP_PKT_EXT_CONNECT_CONFIRM_CARRY_RTT, (FILLP_UCHAR)(sizeof(FILLP_ULLONG)), (FILLP_UCHAR *)&tempRtt);
    if (ret <= 0) {
        /* As encode of extension parameter has failed, still we can continue to send request, it does not impact base
         * functionality */
        FILLP_LOGWAR("encode extension parameter failed");
    } else {
        encMsgLen += ret;
    }

    tempValue32 = (FILLP_UINT32)pcb->pktSize;
    tempValue32 = FILLP_HTONL(tempValue32);
    ret = FillpEncodeExtPara(g_rawMsg + encMsgLen, (FILLP_INT32)(FILLP_FRAME_MTU - encMsgLen),
        FILLP_PKT_EXT_CONNECT_CONFIRM_CARRY_PKT_SIZE, (FILLP_UCHAR)(sizeof(FILLP_UINT32)),
        (FILLP_UCHAR *)&(tempValue32));
    if (ret <= 0) {
        /* As encode of extension parameter has failed, still we can continue to send request, it does not impact base
         * functionality */
        FILLP_LOGWAR("encode extension parameter FILLP_PKT_EXT_CONNECT_CONFIRM_CARRY_PKT_SIZE failed");
    } else {
        encMsgLen += ret;
    }

    FILLP_LOGERR("fcAlg %u", pcb->fcAlg);
    ret = FillpEncodeExtPara(g_rawMsg + encMsgLen, (FILLP_INT32)(FILLP_FRAME_MTU - encMsgLen),
        FILLP_PKT_EXT_CONNECT_CARRY_FC_ALG, (FILLP_UCHAR)(sizeof(FILLP_UINT8)), (FILLP_UCHAR *)&(pcb->fcAlg));
    if (ret <= 0) {
        /* As encode of extension parameter has failed, still we can continue to send request, it does not impact base
         * functionality */
        FILLP_LOGWAR("encode extension parameter FILLP_PKT_EXT_CONNECT_CARRY_FC_ALG failed");
    } else {
        encMsgLen += ret;
    }

    tempValue32 = FILLP_HTONL(pcb->characters);
    ret = FillpEncodeExtPara(g_rawMsg + encMsgLen, (FILLP_INT32)(FILLP_FRAME_MTU - encMsgLen),
        FILLP_PKT_EXT_CONNECT_CARRY_CHARACTER, (FILLP_UCHAR)(sizeof(FILLP_UINT32)), (FILLP_UCHAR *)&tempValue32);
    if (ret <= 0) {
        /* As encode of extension parameter has failed, still we can continue to send request, it does not impact base
         * functionality */
        FILLP_LOGWAR("encode extension parameter FILLP_PKT_EXT_CONNECT_CARRY_CHARACTER failed");
    } else {
        encMsgLen += ret;
    }
    return encMsgLen;
}

void FillpSendConnConfirm(struct FillpPcb *pcb, FILLP_CONST struct FillpConnReqAckClient *reqAck)
{
    FILLP_INT32 encMsgLen = 0;
    struct FillpPktHead *pktHdr = FILLP_NULL_PTR;
    struct FtNetconn *conn = FILLP_GET_CONN(pcb);
    FILLP_INT ret;
    struct FtSocket *ftSock = (struct FtSocket *)conn->sock;
    FillpTraceDescriptSt fillpTrcDesc = FILLP_TRACE_DESC_INIT(FILLP_TRACE_DIRECT_SEND);

    if (ftSock == FILLP_NULL_PTR) {
        return;
    }

    (void)memset_s(g_rawMsg, FILLP_FRAME_MTU, 0, FILLP_FRAME_MTU);
    pktHdr = (struct FillpPktHead *)(void *)g_rawMsg;
    encMsgLen = ConnConfirmBuild(pcb, reqAck, pktHdr);
    if (encMsgLen == 0) {
        return;
    }

    FILLP_INT extParaOffset = encMsgLen;
    encMsgLen = ConnConfirmEncodeExtPara(pcb, encMsgLen);
    /* To send the FILLP_CONNECT_CONFIRM_CARRY_RTT */
    pktHdr->dataLen = (FILLP_UINT16)(encMsgLen - FILLP_HLEN);
    pktHdr->dataLen = FILLP_HTONS(pktHdr->dataLen);

    FILLP_CONN_CONFIRM_TX_LOG(ftSock->index, g_rawMsg, encMsgLen, extParaOffset);

    ret = pcb->sendFunc(conn, (FILLP_CHAR *)g_rawMsg, encMsgLen, conn->pcb);
    if (ret <= 0) {
        pcb->statistics.debugPcb.connConfirmFailed++;
        FILLP_LOGINF("send fail fillp_sock_id:%d", ftSock->index);
    } else {
        FILLP_LM_FILLPMSGTRACE_OUTPUT(ftSock->traceFlag, FILLP_TRACE_DIRECT_NETWORK, ftSock->traceHandle,
            (FILLP_UINT32)encMsgLen, ftSock->index, (FILLP_UINT8 *)(void *)&fillpTrcDesc,
            (FILLP_CHAR *)g_rawMsg);

        pcb->statistics.debugPcb.connConfirmSend++;

        conn->clientFourHandshakeState = FILLP_CLIENT_FOUR_HANDSHAKE_STATE_CONFIRM_SENT;
    }

    FILLP_LOGINF("Send conn confirm fillp_sock_id:%d, source port:%u, dest port:%u", ftSock->index,
        UTILS_GET_ADDRPORT(&conn->pcb->localAddr), UTILS_GET_ADDRPORT(&conn->pcb->remoteAddr));
}


void FillpSendConnConfirmAck(struct FillpPcb *pcb)
{
    struct FillpPktConnConfirmAck confirmAck;
    struct FillpPktHead *pktHdr = FILLP_NULL_PTR;
    FILLP_INT ret;
    FillpTraceDescriptSt fillpTrcDesc;

    struct FtNetconn *conn = FILLP_GET_CONN(pcb);
    struct FtSocket *ftSock = (struct FtSocket *)conn->sock;

    if (ftSock == FILLP_NULL_PTR) {
        FILLP_LOGERR("ftSock is NULL");
        return;
    }

    FILLP_LOGINF("Send conn confirm ack fillp_sock_id:%d, source port:%u, remote port:%u", ftSock->index,
        UTILS_GET_ADDRPORT(&conn->pcb->localAddr), UTILS_GET_ADDRPORT(&conn->pcb->remoteAddr));

    confirmAck.sendCache = FILLP_HTONL(pcb->mpSendSize);
    confirmAck.recvCache = FILLP_HTONL(pcb->mpRecvSize);

    confirmAck.pktSize = FILLP_HTONL((FILLP_UINT32)pcb->pktSize);

    pktHdr = (struct FillpPktHead *)confirmAck.head;

    /* 0 converted to network order is also 0, hence explicit conversion not applied */
    pktHdr->pktNum = FILLP_HTONL(pcb->send.pktStartNum);
    pktHdr->seqNum = FILLP_HTONL(pcb->send.seqStartNum);

    pktHdr->flag = 0;
    FILLP_HEADER_SET_PKT_TYPE(pktHdr->flag, FILLP_PKT_TYPE_CONN_CONFIRM_ACK);
    FILLP_HEADER_SET_PROTOCOL_VERSION(pktHdr->flag, (FILLP_UINT16)FILLP_PROTOCOL_VERSION_NUMBER);
    pktHdr->flag = FILLP_HTONS(pktHdr->flag);

    pktHdr->dataLen = (sizeof(struct FillpPktConnConfirmAck) - FILLP_HLEN);
    pktHdr->dataLen = FILLP_HTONS(pktHdr->dataLen);
    (void)memcpy_s(&confirmAck.remoteAddr, sizeof(confirmAck.remoteAddr), &conn->pcb->remoteAddr,
        sizeof(conn->pcb->remoteAddr));

    FILLP_CONN_CONFIRM_ACK_LOG(ftSock->index, &confirmAck, FILLP_DIRECTION_TX);

    ret = pcb->sendFunc(FILLP_GET_CONN(pcb), (char *)&confirmAck, sizeof(struct FillpPktConnConfirmAck), conn->pcb);
    if (ret <= 0) {
        pcb->statistics.debugPcb.connConfirmAckFailed++;
        FILLP_LOGINF("send fail fillp_sock_id:%d", ftSock->index);
    } else {
        fillpTrcDesc.traceDirection = FILLP_TRACE_DIRECT_SEND;

        FILLP_LM_FILLPMSGTRACE_OUTPUT(ftSock->traceFlag, FILLP_TRACE_DIRECT_NETWORK, ftSock->traceHandle,
            sizeof(struct FillpPktConnConfirmAck), ftSock->index, (FILLP_UINT8 *)(void *)&fillpTrcDesc,
            (FILLP_CHAR *)(&confirmAck));

        pcb->statistics.debugPcb.connConfirmAckSend++;
        pcb->connTimestamp = SYS_ARCH_GET_CUR_TIME_LONGLONG();
    }
}

static void FillpSendFinBuild(FILLP_CONST struct FillpPcb *pcb, struct FillpPktFin *req,
    FILLP_CONST struct FillpFinFlags *flags)
{
    struct FillpPktHead *pktHdr = (struct FillpPktHead *)req->head;

    pktHdr->seqNum = FILLP_HTONL(pcb->localUniqueId);
    pktHdr->pktNum = FILLP_HTONL(pcb->send.pktNum);

    pktHdr->flag = FILLP_NULL_NUM;
    req->flag = FILLP_NULL_NUM;
    FILLP_HEADER_SET_PKT_TYPE(pktHdr->flag, FILLP_PKT_TYPE_FIN);
    FILLP_HEADER_SET_PROTOCOL_VERSION(pktHdr->flag, FILLP_PROTOCOL_VERSION_NUMBER);
    if (flags->wrSet) {
        FILLP_PKT_DISCONN_MSG_FLAG_SET_WR(req->flag);
    }
    if (flags->rdSet) {
        FILLP_PKT_DISCONN_MSG_FLAG_SET_RD(req->flag);
    }
    if (flags->ackSet) {
        FILLP_PKT_DISCONN_MSG_FLAG_SET_ACK(req->flag);
    }
    if (flags->verSet) {
        FILLP_PKT_DISCONN_MSG_FLAG_SET_VER(req->flag);
    }

    pktHdr->flag = FILLP_HTONS(pktHdr->flag);
    req->flag = FILLP_HTONS(req->flag);

    pktHdr->dataLen = (sizeof(struct FillpPktFin) - FILLP_HLEN);
    pktHdr->dataLen = FILLP_HTONS(pktHdr->dataLen);
}

static void FillpSendFinInnerImpl(struct FillpPcb *pcb, FILLP_CONST struct FillpFinFlags *flags,
    struct sockaddr *remoteAddr)
{
    struct FillpPktFin req;
    struct FtNetconn *conn = FILLP_GET_CONN(pcb);
    struct SpungePcb *remotePcb = FILLP_NULL_PTR;
    FILLP_INT ret;
    FillpTraceDescriptSt fillpTrcDesc;

    FILLP_LOGINF("wrSet:%u,rdSet:%u,ackSet:%u,verSet:%u", flags->wrSet, flags->rdSet, flags->ackSet, flags->verSet);

    if (conn == FILLP_NULL_PTR) {
        FILLP_LOGERR("conn is NULL");
        return;
    }

    FillpSendFinBuild(pcb, &req, flags);
    remotePcb = &SPUNGE_GET_CUR_INSTANCE()->tempSpcb;
    UtilsAddrCopy((struct sockaddr *)&remotePcb->remoteAddr, (struct sockaddr *)remoteAddr);

    if (((struct SpungePcb *)(pcb->spcb))->addrLen) {
        remotePcb->addrLen = ((struct SpungePcb *)(pcb->spcb))->addrLen;
        remotePcb->addrType = ((struct SpungePcb *)(pcb->spcb))->addrType;
    } else {
        if (remoteAddr->sa_family == AF_INET) {
            remotePcb->addrLen = sizeof(struct sockaddr_in);
            remotePcb->addrType = AF_INET;
        } else {
            remotePcb->addrLen = sizeof(struct sockaddr_in6);
            remotePcb->addrType = AF_INET6;
        }
    }

    FILLP_CONN_FIN_LOG(FILLP_GET_SOCKET(pcb)->index, &req, FILLP_DIRECTION_TX);

    ret = pcb->sendFunc(conn, (char *)&req, sizeof(struct FillpPktFin), remotePcb);
    if (ret <= 0) {
        pcb->statistics.debugPcb.disconnReqFailed++;
    } else {
        struct FtSocket *ftSock;

        ftSock = (struct FtSocket *)conn->sock;
        fillpTrcDesc.traceDirection = FILLP_TRACE_DIRECT_SEND;

        if (ftSock != FILLP_NULL_PTR) {
            FILLP_LM_FILLPMSGTRACE_OUTPUT(ftSock->traceFlag, FILLP_TRACE_DIRECT_NETWORK, ftSock->traceHandle,
                sizeof(struct FillpPktFin), ftSock->index, (FILLP_UINT8 *)(void *)&fillpTrcDesc, (FILLP_CHAR *)(&req));
        }

        pcb->statistics.debugPcb.disconnReqSend++;
    }
}

static void FillpSendFinInner(struct FillpPcb *pcb, FILLP_BOOL wrSet, FILLP_BOOL rdSet, FILLP_BOOL ackSet,
    struct sockaddr *remoteAddr)
{
    struct FillpFinFlags flags = {0};
    flags.wrSet = wrSet;
    flags.rdSet = rdSet;
    flags.ackSet = ackSet;
    flags.verSet = FILLP_FALSE;

    FillpSendFinInnerImpl(pcb, &flags, remoteAddr);
}

void FillpSendRstWithVersionImcompatible(struct FillpPcb *pcb, struct sockaddr *remoteAddr)
{
    struct FillpFinFlags flags = {0};
    flags.wrSet = FILLP_TRUE;
    flags.rdSet = FILLP_TRUE;
    flags.ackSet = FILLP_TRUE;
    flags.verSet = FILLP_TRUE;

    FillpSendFinInnerImpl(pcb, &flags, remoteAddr);
}

void FillpSendFin(struct FillpPcb *pcb)
{
    struct FtNetconn *conn = FILLP_GET_CONN(pcb);
    FILLP_BOOL wrSet = FILLP_FALSE;
    FILLP_BOOL rdSet = FILLP_FALSE;
    FILLP_BOOL ackSet = FILLP_FALSE;

    if (conn->shutdownWrSet && conn->sendBufRunOut) {
        wrSet = FILLP_TRUE;
    }
    if (conn->shutdownRdSet) {
        rdSet = FILLP_TRUE;
    }

    FillpSendFinInner(pcb, wrSet, rdSet, ackSet,
        (struct sockaddr *)(&((struct SpungePcb*)(pcb->spcb))->remoteAddr));
}

void FillpSendFinAck(struct FillpPcb *pcb, struct sockaddr *remoteAddr)
{
    FillpSendFinInner(pcb, FILLP_FALSE, FILLP_FALSE, FILLP_TRUE, remoteAddr);
}

void FillpSendRst(struct FillpPcb *pcb, struct sockaddr *remoteAddr)
{
    FillpSendFinInner(pcb, FILLP_TRUE, FILLP_TRUE, FILLP_TRUE, remoteAddr);
}


/* This function Generates the cookieContent for fillp on receiving Connection request from peer. */
void FillpGenerateCookie(IN FILLP_CONST struct FillpPcb *pcb, IN struct FillpPktConnReq *req,
    IN FILLP_CONST struct sockaddr_in6 *remoteAddr, IN FILLP_UINT16 serverPort, OUT FillpCookieContent *stateCookie)
{
    struct FillpPktHead *pktHdr = (struct FillpPktHead *)req->head;
    struct SpungePcb*spcb = (struct SpungePcb*)pcb->spcb;
    struct sockaddr *localAddr = (struct sockaddr *)(void *)(&spcb->localAddr);
    FillpHmacSha256 ctx;
    FillpCookieContentCalculate cookieCal;
    void *cookieDataPtr = FILLP_NULL_PTR;

    (void)memset_s(&cookieCal, sizeof(cookieCal), 0, sizeof(cookieCal));
    (void)memcpy_s(stateCookie->digest, FILLP_KEYSIZE, pcb->pcbInst->macInfo.currentMacKey, FILLP_KEYSIZE);
    FILLP_CONST struct sockaddr *addr = (struct sockaddr *)(void *)remoteAddr;
    FillpErrorType err = memcpy_s(&stateCookie->remoteSockIpv6Addr, sizeof(stateCookie->remoteSockIpv6Addr), remoteAddr,
        ((addr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)));
    if (err != EOK) {
        FILLP_LOGERR("fillp_generate_cookie memcpy_s remote %u failed:%d", addr->sa_family, err);
        return;
    }
    stateCookie->remoteRecvCache = req->recvCache;
    stateCookie->remoteSendCache = req->sendCache;
    FILLP_LLONG *cookieTime = (FILLP_LLONG *)(void *)(stateCookie->arr);
    *cookieTime = (FILLP_LLONG)SYS_ARCH_GET_CUR_TIME_LONGLONG();
    stateCookie->localMessageSeqNumber = FILLP_CRYPTO_RAND();
    stateCookie->localPacketSeqNumber = FILLP_CRYPTO_RAND();
    stateCookie->remoteMessageSeqNumber = pktHdr->seqNum;
    stateCookie->remotePacketSeqNumber = pktHdr->pktNum;
    stateCookie->addressType = addr->sa_family;
    stateCookie->srcPort = serverPort;
    if (req->cookiePreserveTime <= FILLP_MAX_COOKIE_LIFETIME) {
        stateCookie->lifeTime = FILLP_INITIAL_COOKIE_LIFETIME + req->cookiePreserveTime;
    } else {
        stateCookie->lifeTime = FILLP_INITIAL_COOKIE_LIFETIME;
    }
    if (memcpy_s(&cookieCal, sizeof(cookieCal), stateCookie, sizeof(FillpCookieContent)) != EOK) {
        return;
    }
    err = memcpy_s(&cookieCal.localSockIpv6Addr, sizeof(cookieCal.localSockIpv6Addr),
        &((struct SpungePcb*)(pcb->spcb))->localAddr,
        ((localAddr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)));
    if (err != EOK) {
        FILLP_LOGERR("fillp_generate_cookie memcpy_s local %u failed:%d", localAddr->sa_family, err);
        return;
    }
    FillpHmacSha256Init(&ctx, pcb->pcbInst->macInfo.currentMacKey, FILLP_KEYSIZE, pcb->pcbInst);
    cookieDataPtr = (void *)((uintptr_t)(&cookieCal) + FILLP_KEYSIZE);
    FillpHmacSha256Update(&ctx, cookieDataPtr, (sizeof(FillpCookieContentCalculate) - FILLP_KEYSIZE));
    FillpHmacSha256Final(&ctx, stateCookie->digest, FILLP_KEYSIZE);
}

static FILLP_INT  FillpValidateCookieHmac(FILLP_CONST struct FillpPcb *pcb, FILLP_CONST FillpCookieContent *stateCookie)
{
    FILLP_UINT32 count = 0;
    FILLP_UINT8 key[FILLP_KEYSIZE];
    FILLP_UINT8  outDigest[FILLP_KEYSIZE] = {0};
    FillpHmacSha256 ctx;
    FillpCookieContentCalculate cookieCal;
    struct SpungePcb *spcb = (struct SpungePcb*)pcb->spcb;
    struct sockaddr *localAddr = (struct sockaddr *)(void *)(&spcb->localAddr);
    void *cookieDataPtr = FILLP_NULL_PTR;
    FILLP_ULLONG *cookieTime = FILLP_NULL_PTR;

    (void)memset_s(&cookieCal, sizeof(cookieCal), 0, sizeof(cookieCal));
    FillpErrorType err = memcpy_s(&cookieCal, sizeof(cookieCal), stateCookie, sizeof(FillpCookieContent));
    if (err != EOK) {
        FILLP_LOGERR("fillp_validate_cookie memcpy_s cookieCal failed : %d", err);
        return err;
    }

    err = memcpy_s(&cookieCal.localSockIpv6Addr, sizeof(cookieCal.localSockIpv6Addr),
          &((struct SpungePcb*)(pcb->spcb))->localAddr,
          ((localAddr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)));
    if (err != EOK) {
        FILLP_LOGERR("fillp_validate_cookie memcpy_s %u failed : %d", localAddr->sa_family, err);
        return err;
    }

    cookieTime = (FILLP_ULLONG *)(void *)stateCookie->arr;
    if (pcb->pcbInst->macInfo.switchOverTime < *cookieTime) {
        for (count = 0; count < FILLP_KEYSIZE; count++) {
            key[count] = pcb->pcbInst->macInfo.currentMacKey[count];
        }
    } else {
        for (count = 0; count < FILLP_KEYSIZE; count++) {
            key[count] = pcb->pcbInst->macInfo.oldMacKey[count];
        }
    }

    FillpHmacSha256Init(&ctx, key, FILLP_KEYSIZE, pcb->pcbInst);
    cookieDataPtr = (void *)((uintptr_t)(&cookieCal) + FILLP_KEYSIZE);
    FillpHmacSha256Update(&ctx, cookieDataPtr,
        (sizeof(FillpCookieContentCalculate) - FILLP_KEYSIZE));
    FillpHmacSha256Final(&ctx, outDigest, FILLP_KEYSIZE);

    for (count = 0; count < FILLP_KEYSIZE; count++) {
        if (stateCookie->digest[count] != outDigest[count]) {
            FILLP_LOGINF("fillp_sock_id:%d HMAC-SHA2 digest mismatched. SaveDigest:%d  NewDigest:%d",
                FILLP_GET_SOCKET(pcb)->index, stateCookie->digest[count], outDigest[count]);
            return ERR_HMAC_SHA2_DIGEST_MISMATCH;
        }
    }

    return ERR_OK;
}

/* This function validates the cookieContent from peer. */
FILLP_INT FillpValidateCookie(IN FILLP_CONST struct FillpPcb *pcb, IN FILLP_UINT16 serverPort,
    IN FILLP_CONST struct sockaddr_in6 *clientAddr, IN FILLP_CONST FillpCookieContent *stateCookie)
{
    FILLP_LLONG timeDiffVal;
    FILLP_LLONG curTime;
    FILLP_INT ret;
    FILLP_ULLONG *cookieTime = FILLP_NULL_PTR;

    ret = FillpValidateCookieHmac(pcb, stateCookie);
    if (ret != ERR_OK) {
        return ret;
    }

    if (stateCookie->srcPort != serverPort) {
        FILLP_LOGINF("fillp_sock_id:%d FillP cookieContent Server Port mismatch. "
                     "cookieContent Generated server port:%u Msg Server Port:%u \r\n",
            FILLP_GET_SOCKET(pcb)->index, stateCookie->srcPort, serverPort);
        return ERR_COOKIE_PORT_MISMATCH;
    }

    /* no need to explicitly validate the server IP again here, since it is already
    validated in hash when receive the UDP packet
    Validate the source port and IP  of the client against the port and IP
    of the client stored in the cookie content, if mismatches, then discard the
    connection confirm message silently */
    if (UtilsAddrMatch((FILLP_CONST struct sockaddr_in *)&stateCookie->remoteSockIpv6Addr,
        (FILLP_CONST struct sockaddr_in *)clientAddr) == FILLP_FALSE) {
        FILLP_LOGINF("fillp_sock_id:%d Client address mismatch between cookie"
            " and message client",
            FILLP_GET_SOCKET(pcb)->index);
        return ERR_COOKIE_PORT_MISMATCH;
    }

    curTime = (FILLP_LLONG)SYS_ARCH_GET_CUR_TIME_LONGLONG();
    cookieTime = (FILLP_ULLONG *)(void *)stateCookie->arr;
    timeDiffVal = (FILLP_LLONG)((FILLP_ULLONG)curTime - (*cookieTime));

    if (timeDiffVal < 0) {
        FILLP_LOGERR("fillp_sock_id:%d FillP cookieContent is stale due to system time change."
            "CookieGenerated time:%llu Current time:%lld Life time of cookie:%u \r\n",
            FILLP_GET_SOCKET(pcb)->index, *cookieTime, curTime, stateCookie->lifeTime);
        return ERR_STALE_COOKIE_ERROR;
    }

    if (timeDiffVal > stateCookie->lifeTime) {
        FILLP_LOGINF("fillp_sock_id:%d FillP cookieContent is stale. CookieGenerated time:%llu"
            "Current time:%lld Life time of cookie:%u \r\n",
            FILLP_GET_SOCKET(pcb)->index, *cookieTime, curTime, stateCookie->lifeTime);
        return ERR_STALE_COOKIE_ERROR;
    }

    return FILLP_SUCCESS;
}

#ifdef __cplusplus
}
#endif
