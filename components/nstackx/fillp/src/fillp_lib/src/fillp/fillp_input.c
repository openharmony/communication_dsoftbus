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

#include "fillp_input.h"
#include "opt.h"
#include "fillp.h"
#include "fillp_flow_control.h"
#include "log.h"
#include "net.h"
#include "fillp_common.h"
#include "fillp_output.h"
#include "fillp_mgt_msg_log.h"
#include "fillp_dfx.h"

#ifdef __cplusplus
extern "C" {
#endif
#define FILLP_HLEN_U        12u
#define FILLP_INTERVAL_RATE 4
#define FILLP_FACTOR_PAR    15
#define FILLP_JITTER_PAR    16

static void FillpCalRecvJitter(struct FtSocket *sock, FILLP_LLONG arrival, FILLP_LLONG receiveTransmit)
{
    FILLP_LLONG transmit = arrival - receiveTransmit;
    FILLP_LLONG delta = transmit - sock->transmit;
    double factor;
    double factorJitter;

    /* init the sock->transmit by current transmit when recv the fist data packet */
    if ((sock->transmit == 0) && (sock->jitter == 0)) {
        sock->transmit = transmit;
        return;
    }

    sock->transmit = transmit;
    if (delta < 0) {
        delta = -delta;
    }
    FILLP_LOGDBG("last jitter:%lld d:%lld", sock->jitter, delta);
    factor = (((double)1 / FILLP_JITTER_PAR) * (double)delta);
    factorJitter = (((double)FILLP_FACTOR_PAR / FILLP_JITTER_PAR) * (double)(sock->jitter));
    sock->jitter = (FILLP_LLONG)(factor + factorJitter);
    FILLP_LOGDBG("current jitter:%lld", sock->jitter);
}

static void FillpChangePackInteval(struct FillpPcb *pcb)
{
    struct FtNetconn *conn = FILLP_GET_CONN(pcb);
    if (pcb->packState == FILLP_PACK_STATE_KEEP_ALIVE ||
        (((struct FtSocket *)conn->sock)->resConf.common.enlargePackIntervalFlag == FILLP_TRUE &&
        pcb->packTimerNode.interval != pcb->statistics.pack.packIntervalBackup)) {
        FILLP_LOGDBG("FillpDataInput, change pack timer to working state with a new time interval %u, old %u",
            pcb->statistics.pack.packIntervalBackup, pcb->statistics.pack.packInterval);
        pcb->statistics.pack.packInterval = pcb->statistics.pack.packIntervalBackup;
        FillpDisablePackTimer(pcb);
        pcb->packTimerNode.interval = pcb->statistics.pack.packInterval;
        FillpEnablePackTimer(pcb);
        pcb->packState = FILLP_PACK_STATE_NORMAL;
    }
}

static FILLP_INT FillpProcessDataOptions(FillpDataOption *dataOption, struct FillpPcb *pcb, struct FillpPcbItem *item)
{
    FILLP_INT err = ERR_OK;
    struct FtSocket *sock = FILLP_GET_SOCKET(pcb);
    switch (dataOption->type) {
        case FILLP_OPT_TIMESTAMP:
            if (dataOption->len == FILLP_OPT_TIMESTAMP_LEN) {
                FILLP_LLONG sendTimestamp = 0;
                FILLP_LLONG recvTimestamp = SYS_ARCH_GET_CUR_TIME_LONGLONG();
                err = memcpy_s(&sendTimestamp, sizeof(FILLP_LLONG), &(dataOption->value[0]), sizeof(FILLP_LLONG));
                if (err != EOK) {
                    FILLP_LOGERR("fillp_sock_id:%d, fillp_analysis_data_options memcpy_s failed : %d",
                        sock->index, err);
                    break;
                }
                sendTimestamp = (FILLP_LLONG)FILLP_NTOHLL((FILLP_ULLONG)sendTimestamp);
                FillpCalRecvJitter(sock, recvTimestamp, sendTimestamp);
            } else {
                FILLP_LOGWAR("fillp_sock_id:%d, TIMESTAMP option length illegal, optLen %u != %u.",
                    FILLP_GET_SOCKET(pcb)->index, dataOption->len, FILLP_OPT_TIMESTAMP_LEN);
                err = FILLP_EINVAL;
            }
            break;
        case FILLP_OPT_FRAME_INFO:
            err = FillpFrameParseOption(&pcb->frameHandle, item, &dataOption->value[0], dataOption->len);
            break;
        default:
            break; /* for downward compatibility, here should not think as an error when no option type to match */
    }
    return err;
}

static FILLP_INT FillpAnalysisDataOptions(struct FillpPcb *pcb, struct FillpPcbItem *item)
{
    FILLP_CHAR *datOptAddr = item->buf.p + FILLP_HLEN;
    FILLP_UINT16 datOptLen;
    FILLP_UINT16 curOptLen;
    FillpDataOption *dataOption = FILLP_NULL_PTR;
    FILLP_INT err = ERR_OK;

    if (item->buf.len < FILLP_DATA_OFFSET_LEN) {
        FILLP_LOGWAR("fillp_sock_id:%d, data option buffer len wrong, bufLen %d. \r\n", FILLP_GET_SOCKET(pcb)->index,
            item->buf.len);
        return FILLP_EINVAL;
    }

    datOptLen = *(FILLP_UINT16 *)datOptAddr;
    datOptLen = FILLP_NTOHS(datOptLen);
    item->dataOptLen = (FILLP_UINT16)(datOptLen + FILLP_DATA_OFFSET_LEN);
    *(FILLP_UINT16 *)datOptAddr = datOptLen;
    if (((FILLP_INT)datOptLen + FILLP_DATA_OFFSET_LEN) > item->buf.len) {
        FILLP_LOGWAR("fillp_sock_id:%d, data option total length illegal, optLen %u > bufLen %d. \r\n",
            FILLP_GET_SOCKET(pcb)->index, datOptLen, item->buf.len);
        return FILLP_EINVAL;
    }

    datOptAddr += (FILLP_UINT16)FILLP_DATA_OFFSET_LEN;
    while (datOptLen > 1) {
        dataOption = (FillpDataOption *)datOptAddr;
        curOptLen = (FILLP_UINT16)((FILLP_UINT16)dataOption->len + FILLP_DATA_OPT_HLEN);
        if (curOptLen > datOptLen) {
            FILLP_LOGWAR("fillp_sock_id:%d, current data option length illegal, optLen %u > remain optLen %u.",
                FILLP_GET_SOCKET(pcb)->index, dataOption->len, datOptLen);
            err = FILLP_EINVAL;
            break;
        }
        err = FillpProcessDataOptions(dataOption, pcb, item);
        if (err != ERR_OK) {
            break;
        }
        datOptAddr += curOptLen;
        datOptLen -= curOptLen;
    }

    return err;
}

static void FillpProcessItemData(struct FillpPcb *pcb, struct FillpPcbItem *item,
    FILLP_CONST struct FillpPktHead *pktHdr)
{
    if ((FILLP_INT)item->dataLen + (FILLP_INT)item->dataOptLen != item->buf.len) {
        FILLP_LOGWAR(" fillp_sock_id:%d packet length err, dataLen:%u, option eare size:%u, buflen:%d ",
            FILLP_GET_SOCKET(pcb)->index, item->dataLen, item->dataOptLen, item->buf.len);
        FillpFreeBufItem(item);
        return;
    }
    if (!FillpNumIsbigger(item->seqNum, pcb->recv.seqNum)) {
        FillpFcDataInput(pcb, pktHdr);
        FillpFreeBufItem(item);
        FillpFcRecvDropOne(pcb);
        return;
    }
    if (g_resource.common.outOfOrderCacheEnable && (g_appResource.common.enableNackDelay == FILLP_FALSE)) {
        if (SkipListInsert(&pcb->recv.recvBoxPlaceInOrder, (void *)item, &item->skipListNode, FILLP_TRUE)) {
            FILLP_LOGDTL("fillp_sock_id:%d Failed to insert node in recvBoxPlaceInOrder",
                FILLP_GET_SOCKET(pcb)->index);
            FillpFreeBufItem(item);
            return;
        }

        if (pcb->recv.recvBoxPlaceInOrder.nodeNum >= g_resource.common.recvCachePktNumBufferSize) {
            struct FillpPcbItem *itemPre = SkipListPopValue(&pcb->recv.recvBoxPlaceInOrder);
            if (itemPre == FILLP_NULL_PTR) {
                FILLP_LOGDTL("fillp_sock_id:%d FillpDataInput: pcb  is NULL!!!", FILLP_GET_SOCKET(pcb)->index);
                return;
            }
            FillpDataToStack(pcb, itemPre);
        }
    } else {
        FillpDataToStack(pcb, item);
    }
}

IGNORE_OVERFLOW static void FillpDataInput(struct FillpPcb *pcb, struct FillpPcbItem *item)
{
    FILLP_CONST struct FillpPktHead *pktHdr = (struct FillpPktHead *)(void *)item->buf.p;
    FILLP_UINT32 privRecvCacheSize = 0;

    FillpChangePackInteval(pcb);

    item->fpcb = pcb;
    item->pktNum = pktHdr->pktNum;
    item->seqNum = pktHdr->seqNum;
    item->dataLen = pktHdr->dataLen;

    if (FillpNumIsbigger(item->seqNum, (pcb->recv.seqNum + pcb->recv.pktRecvCache + privRecvCacheSize))) {
        FILLP_LOGWAR("fillp_sock_id:%d, seqnum received = %u from the peer is not in the send window range = %u",
            FILLP_GET_SOCKET(pcb)->index, item->seqNum,
            (pcb->recv.seqNum + pcb->recv.pktRecvCache + privRecvCacheSize));

        FillpFreeBufItem(item);
        return;
    }

    if (FILLP_PKT_GET_DAT_WITH_OPTION(pktHdr->flag)) {
        if (FillpAnalysisDataOptions(pcb, item) != ERR_OK) {
            FILLP_LOGWAR("fillp_sock_id:%d Failed to analysis data options.", FILLP_GET_SOCKET(pcb)->index);
            FillpFreeBufItem(item);
            return;
        }
    } else {
        item->dataOptLen = 0;
    }
    FillpProcessItemData(pcb, item, pktHdr);
}

static void ProcessPcbItem(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *buf, struct FillpPcbItem *pcbBuf)
{
    FILLP_CONST struct FillpPktHead *pktHdr = (struct FillpPktHead *)(void *)buf->p;
    if (pcbBuf != FILLP_NULL_PTR) {
        pcbBuf->rxTimeStamp = SYS_ARCH_GET_CUR_TIME_LONGLONG();
        pcbBuf->frame = FILLP_NULL_PTR;
        UTILS_FLAGS_RESET(pcbBuf->flags);
        /* We can't use mem copy here , which will rewrite the buf->p */
        pcbBuf->buf.addr = buf->addr;
        pcbBuf->buf.len = buf->len;
        FillpErrorType err = memcpy_s(pcbBuf->buf.p, (FILLP_UINT32)(pcb->pktSize + FILLP_HLEN), buf->p,
            (FILLP_UINT32)(buf->len + FILLP_HLEN));
        if (err != EOK) {
            FILLP_LOGERR("fillp_do_input_pkt_type memcpy_s failed: %d, fillp_sock_id:%d",
                err, FILLP_GET_SOCKET(pcb)->index);
            return;
        }
        FillpDataInput(pcb, pcbBuf);
        if (FILLP_PKT_GET_DAT_WITH_FIRST_FLAG(pktHdr->flag)) {
            FILLP_LOGINF("first flag: fillpSockId:%d, seqNum:%u, flag: 0x%4x",
                FILLP_GET_SOCKET(pcb)->index, pktHdr->seqNum, pktHdr->flag);
        }
        if (FILLP_PKT_GET_DAT_WITH_LAST_FLAG(pktHdr->flag)) {
            FILLP_LOGINF("last flag: fillpSockId:%d, seqNum:%u, flag: 0x%4x",
                FILLP_GET_SOCKET(pcb)->index, pktHdr->seqNum, pktHdr->flag);
        }
    } else {
        struct SkipListNode *node;
        node = SkipListGetPop(&pcb->recv.recvList);
        struct FillpPcbItem *item = FILLP_NULL_PTR;
        FILLP_UINT32 lostSeqNum = pcb->recv.seqNum;
        if (node != FILLP_NULL_PTR) {
            item = (struct FillpPcbItem *)node->item;
            lostSeqNum = (item->seqNum - item->dataLen);
        }
    }
}

static void FillpHdlDataInput(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *buf)
{
    FILLP_CONST struct FillpPktHead *pktHdr = (struct FillpPktHead *)(void *)buf->p;
    struct FillpPcbItem *pcbBuf = FILLP_NULL_PTR;
    int netconnState = NETCONN_GET_STATE(FILLP_GET_CONN(pcb));
    if ((netconnState != CONN_STATE_CLOSING) && (netconnState != CONN_STATE_CONNECTED)) {
        // Drop it silently
        FILLP_LOGDBG("not connected or connecting, drop it !!!!!");
        FillpDfxPktNotify(FILLP_GET_SOCKET(pcb)->index, FILLP_DFX_PKT_PARSE_FAIL, 1U);
        return;
    }

    (void)FillpMallocBufItem(pcb->recv.itemPool, (void **)&pcbBuf, FILLP_FALSE);
    if (pcbBuf == FILLP_NULL_PTR) {
        if (FillpAskMoreBufItem(pcb->recv.itemPool, FILLP_DYMM_INCREASE_STEP_RECV, FILLP_FALSE) > 0) {
            (void)FillpMallocBufItem(pcb->recv.itemPool, (void **)&pcbBuf, FILLP_FALSE);
            pcb->recv.curItemCount = (FILLP_UINT32)DYMP_GET_CUR_SIZE(pcb->recv.itemPool);
        }
    }

    if (pcbBuf == FILLP_NULL_PTR) {
        /* items inst recv cache are all using, try to replace the max seq item in recvList */
        struct FillpPcbItem *item = FILLP_NULL_PTR;
        struct SkipListNode *node = SkipListGetTail(&pcb->recv.recvList);
        if (node != FILLP_NULL_PTR) {
            item = (struct FillpPcbItem *)node->item;
        }
        if ((item != FILLP_NULL_PTR) && FillpNumIsbigger(item->seqNum, pktHdr->seqNum) &&
            FillpNumIsbigger(pktHdr->seqNum, pcb->recv.seqNum)) {
            item = (struct FillpPcbItem *)SkipListPopTail(&pcb->recv.recvList);
            FillpSendNack(pcb, (FILLP_UINT32)(item->pktNum - 1), (FILLP_UINT32)(item->pktNum + 1));
            pcbBuf = item;
            FILLP_LOGDTL("replace big seq item, fillp_sock_id:%d, seqNum:%u replace seqNum:%u",
                FILLP_GET_SOCKET(pcb)->index, pktHdr->seqNum, item->seqNum);
        }
    }
    ProcessPcbItem(pcb, buf, pcbBuf);
}

static int FillpCheckNackPacket(FILLP_CONST struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p)
{
    /* We should check for minimum length because of optional parameter total length may be more, which can be added in
       future version of stack, current version just ignore optlen as none is defined */
    if (p->len < (FILLP_INT)(sizeof(struct FillpPktNackWithRandnum) - FILLP_HLEN)) {
        FILLP_LOGWAR("fillp_sock_id:%d, Invalid nack request, len = %d", FILLP_GET_SOCKET(pcb)->index, p->len);
        return -1;
    }

    FILLP_UINT8 connState = FILLP_GET_CONN_STATE(pcb);
    if ((CONN_STATE_CLOSING != connState) && (CONN_STATE_CONNECTED != connState)) {
        FILLP_LOGINF("netconn state not correct for NACK, state:%u", connState);
        return -1;
    }
    return 0;
}

IGNORE_OVERFLOW static int FillpCheckNackSeq(FILLP_CONST struct FillpPcb *pcb,
    FILLP_CONST struct FillpPktHead *pktHdr, FILLP_CONST struct FillpSeqPktNum *seqPktNum)
{
    if (FillpNumIsbigger(pktHdr->seqNum, pcb->send.seqNum) ||
        FillpNumIsbigger(pcb->send.seqNum, (pktHdr->seqNum + pcb->send.pktSendCache))) {
        FILLP_LOGDTL("fillp_sock_id:%d Invalid NACK sequence number. seqNum = %u, pcb->send.seqNum = %u",
            FILLP_GET_SOCKET(pcb)->index, pktHdr->seqNum, pcb->send.seqNum);
        return -1;
    }

    /* use to ignore the redundant nack packet */
    if ((pcb->send.nackPktStartNum == seqPktNum->beginPktNum) &&
        (pcb->send.nackPktEndNum == seqPktNum->endPktNum)) {
        return -1;
    }
    return 0;
}

static void FillpNackInputTrace(FILLP_CONST struct FtSocket *sock, FILLP_CONST struct FillpPktNack *nack,
    FILLP_CONST struct FillpPktHead *pktHdr)
{
    struct FillpPktNack tmpNack;
    struct FillpPktHead *tmpHead = (struct FillpPktHead *)(void *)tmpNack.head;
    FillpTraceDescriptSt fillpTrcDesc;
    if ((sock != FILLP_NULL_PTR) && (sock->traceFlag >= FILLP_TRACE_DIRECT_NETWORK)) {
        /* Recovert the header to NETWORK byte order to provide indication */
        tmpHead->flag = FILLP_HTONS(pktHdr->flag);
        tmpHead->dataLen = FILLP_HTONS(pktHdr->dataLen);
        tmpHead->pktNum = FILLP_HTONL(pktHdr->pktNum);
        tmpHead->seqNum = FILLP_HTONL(pktHdr->seqNum);

        /* Below field is already in NETWORK byte order */
        tmpNack.lastPktNum = nack->lastPktNum;

        FILLP_LM_FILLPMSGTRACE_OUTPUT_WITHOUT_FT_TRACE_ENABLE_FLAG(FILLP_TRACE_DIRECT_NETWORK, sock->traceHandle,
            sizeof(struct FillpPktNack), sock->index, fillpTrcDesc, (FILLP_CHAR *)(&tmpNack));
    }
}

static FILLP_INT FillpGetSeqFromPktSeqHash(FILLP_UINT32 pktNum, FILLP_CONST struct FillpHashLlist *mapList,
    struct FillpPcbItem **outItem)
{
    FILLP_UINT32 hashIndex = (FILLP_UINT32)(pktNum & mapList->hashModSize);
    struct Hlist *list = &mapList->hashMap[hashIndex];
    struct HlistNode *pos = HLIST_FIRST(list);
    struct FillpPcbItem *item = FILLP_NULL_PTR;

    while (pos != FILLP_NULL_PTR) {
        item = FillpPcbPktSeqMapNodeEntry(pos);

        if (item->pktNum == pktNum) {
            *outItem = item;
            return FILLP_OK;
        } else if (FillpNumIsbigger(item->pktNum, pktNum)) {
            return FILLP_ERR_VAL;
        }
        pos = pos->next;
    }

    return FILLP_ERR_VAL;
}

static FILLP_UINT32 ProtectLongLoopRun(struct FillpPcb *pcb, FILLP_UINT32 identifyGap,
    struct FillpSeqPktNum *seqPktNum, FILLP_INT *isUsed)
{
    FILLP_UINT32 pktIndex;
    FILLP_UINT32 protectLoopCounter;
    FILLP_UINT32 startLoop = seqPktNum->beginPktNum + 1;
    FILLP_UINT32 lostPktGap = 0;
    struct FillpSendPcb *sendPcb = &pcb->send;
    for (pktIndex = startLoop, protectLoopCounter = 0;
        (FillpNumIsbigger(seqPktNum->endPktNum, pktIndex)) && (protectLoopCounter <= identifyGap);
        pktIndex++, protectLoopCounter++) {
        /* Check if pktNum still in unAck table */
        struct FillpPcbItem *unackItem = FILLP_NULL_PTR;
        if (FillpGetSeqFromPktSeqHash(pktIndex, &sendPcb->pktSeqMap, &unackItem)) {
            continue; /* Not Found, skip it */
        }

        if (unackItem->seqNum <= seqPktNum->beginSeqNum) {
            FILLP_LOGBUTT("FILLP_UINT32, unackItem->seqNum: %u, beginSeqNum: %u",
                unackItem->seqNum, seqPktNum->beginSeqNum);
            continue;
        }

        /* Query Success , delete pkt-seq map */
        HlistDelNode(&unackItem->pktSeqMapNode);
        HlistDelNode(&unackItem->node);
        lostPktGap++;
        if (pcb->send.unackList.count > 0) {
            pcb->send.unackList.count--;
        }

        pcb->send.inSendBytes -= (FILLP_ULLONG)unackItem->dataLen;
        unackItem->infCount--;
        if (identifyGap > FILLP_MAX_LOST_NUM_FOR_REDUN) {
            UTILS_FLAGS_CLEAN(unackItem->flags, FILLP_ITEM_FLAGS_REDUNDANT);
        }
        if (SkipListInsert(&pcb->send.unrecvList, unackItem, &unackItem->skipListNode, FILLP_TRUE)) {
            InsertUnrecvListFail(pcb, unackItem);
            /* Inserting ack item to SkipList failed, skip and continue */
            continue;
        }

        pcb->send.unrecvRedunListBytes += unackItem->dataLen;
        unackItem->sendCount++;
        unackItem->resendTrigger = (FILLP_UINT8)FILLP_ITEM_RESEND_TRIGGER_HNACK;
        pcb->statistics.appFcStastics.periodSendLostPkts++;
        if (isUsed != FILLP_NULL_PTR) {
            *isUsed = 1;
        }
    }
    return lostPktGap;
}

/**
 * Query SEQNUM in unackList, move item to unrecvList if query success.Then delete pkt-seq map relation
 */
static void FillpNackInput(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p)
{
    struct FtSocket *ftSock = (struct FtSocket *)FILLP_GET_CONN(pcb)->sock;
    FILLP_UINT32 identifyGap = 0;
    struct FillpSeqPktNum seqPktNum;

    if (FillpCheckNackPacket(pcb, p) != 0) {
        FillpDfxPktNotify(ftSock->index, FILLP_DFX_PKT_PARSE_FAIL, 1U);
        return;
    }

    struct FillpPktNackWithRandnum *nackReq = (struct FillpPktNackWithRandnum *)(void *)p->p;
    struct FillpPktNack *nack = &nackReq->nack;

    /* Header fields are already converted in FillpDoInput, and hence here
       should not be converted again
    */
    struct FillpPktHead *pktHdr = (struct FillpPktHead *)nack->head;
    seqPktNum.endPktNum = FILLP_NTOHL(nack->lastPktNum);
    seqPktNum.beginPktNum = pktHdr->pktNum;
    seqPktNum.beginSeqNum = pktHdr->seqNum;
    if (FillpCheckNackSeq(pcb, pktHdr, &seqPktNum) != 0) {
        return;
    }
    pcb->send.nackPktStartNum =  seqPktNum.beginPktNum;
    pcb->send.nackPktEndNum = seqPktNum.endPktNum;

    FILLP_LOGDBG("recv NACK sockId:%d,seqNum:%u,startPKTNum:%u,endPktNum:%u,gap:%u,unrecvList:%u,unackList:%u",
        FILLP_GET_SOCKET(pcb)->index, pktHdr->seqNum, pktHdr->pktNum, seqPktNum.endPktNum, seqPktNum.endPktNum -
        (seqPktNum.beginPktNum + 1), pcb->send.unrecvList.nodeNum, pcb->send.unackList.count);

    FillpNackInputTrace(ftSock, nack, pktHdr);
    FILLP_LOGDBG("recv NACK send seqnum = %u,send pkt = %u", pcb->send.seqNum, pcb->send.pktNum);
    FILLP_UINT32 startLoop = seqPktNum.beginPktNum + 1;
    if (FillpNumIsbigger(seqPktNum.endPktNum, startLoop)) {
        identifyGap = (seqPktNum.endPktNum - startLoop);
    } else {
        FILLP_LOGDTL("curPktNum(%u) is smaller than lastPktNum(%u)", seqPktNum.endPktNum, seqPktNum.beginPktNum);
        return;
    }

    if (identifyGap >= pcb->mpSendSize) {
        identifyGap = pcb->mpSendSize;
    }

    FILLP_UINT32 lostPktGap = ProtectLongLoopRun(pcb, identifyGap, &seqPktNum, FILLP_NULL);
    FILLP_UNUSED_PARA(lostPktGap);
    if (pcb->send.unrecvList.nodeNum) {
        FillpEnableSendTimer(pcb);
    }
    if (FillpNumIsbigger(seqPktNum.beginSeqNum, pcb->send.maxAckNumFromReceiver)) {
        pcb->send.maxAckNumFromReceiver = seqPktNum.beginSeqNum;
    }
    pcb->statistics.debugPcb.nackRcv++;
    FillpFcNackInput(pcb, nack);
}

static FILLP_BOOL FillpCheckPackInput(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p)
{
    FILLP_UINT8 connState = FILLP_GET_CONN_STATE(pcb);
    if ((connState != CONN_STATE_CLOSING) && (connState != CONN_STATE_CONNECTED)) {
        /* Changed the log level from WAR to INFO, because peer would have sent the outstanding
            packs at the time when local side connection is closed.
        */
        FILLP_LOGINF("netconn state not correct for PACK,state:%hhu", connState);
        return FILLP_FALSE;
    }
    /* We should check for minimum length because of optional parameter total length may be more, which can be added in
       future version of stack, current version just ignore optlen as none is defined */
    if (p->len < (FILLP_INT)(FILLP_PACK_MIN_LEN - FILLP_HLEN)) {
        FILLP_LOGWAR("fillp_sock_id:%d, Invalid pack request, len = %d", FILLP_GET_SOCKET(pcb)->index, p->len);
        return FILLP_FALSE;
    }
    return FILLP_TRUE;
}

static void FillpPackInputSendMsgTrace(FILLP_CONST struct FillpPcb *pcb, FILLP_CONST struct FillpPktHead *pktHdr,
    FILLP_CONST struct FillpPktPack *pack)
{
    struct FtSocket *ftSock;
    FillpTraceDescriptSt fillpTrcDesc;

    ftSock = FILLP_GET_SOCKET(pcb);
    if (ftSock == FILLP_NULL_PTR) {
        FILLP_LOGERR("sock is NULL");
        return;
    }

    if (ftSock->traceFlag >= FILLP_TRACE_DIRECT_NETWORK) {
        struct FillpPktPack tmpPack;
        struct FillpPktHead *tmpHead = (struct FillpPktHead *)(void *)tmpPack.head;
        FILLP_UINT16 traceMsgLen = sizeof(struct FillpPktPack);

        (void)memset_s(&tmpPack, sizeof(tmpPack), 0, sizeof(tmpPack));
        /* Recovert the header to NETWORK byte order to provide indication */
        tmpHead->flag = FILLP_HTONS(pktHdr->flag);
        tmpHead->dataLen = FILLP_HTONS(pktHdr->dataLen);
        tmpHead->pktNum = FILLP_HTONL(pktHdr->pktNum);
        tmpHead->seqNum = FILLP_HTONL(pktHdr->seqNum);

        /* Below field is already in NETWORK byte order */
        tmpPack.flag = pack->flag;
        tmpPack.pktLoss = pack->pktLoss;
        tmpPack.rate = pack->rate;
        tmpPack.oppositeSetRate = pack->oppositeSetRate;
        tmpPack.lostSeq = pack->lostSeq;
        tmpPack.bgnPktNum = pack->bgnPktNum;
        tmpPack.endPktNum = pack->endPktNum;
        tmpPack.optsOffset = pack->optsOffset;
        tmpPack.rcvListBytes = pack->rcvListBytes;

        if ((FILLP_NTOHS(pack->flag) & FILLP_PACK_FLAG_WITH_RTT) &&
            (!(pktHdr->dataLen < (FILLP_PACK_MIN_LEN - FILLP_HLEN))) && (!pcb->rtt)) {
            tmpPack.reserved.rtt = pack->reserved.rtt;
        } else {
            tmpPack.reserved.rtt = 0;
        }

        if (traceMsgLen > (pktHdr->dataLen + (FILLP_UINT16)FILLP_HLEN)) {
            traceMsgLen = pktHdr->dataLen + (FILLP_UINT16)FILLP_HLEN;
        }

        FILLP_LM_FILLPMSGTRACE_OUTPUT_WITHOUT_FT_TRACE_ENABLE_FLAG(FILLP_TRACE_DIRECT_NETWORK, ftSock->traceHandle,
            (FILLP_UINT32)traceMsgLen, FILLP_GET_SOCKET(pcb)->index, fillpTrcDesc, (FILLP_CHAR *)(&tmpPack));
    }
}

IGNORE_OVERFLOW static FILLP_BOOL FillpCheckPackNumber(struct FillpPcb *pcb,
    struct FillpPktPack *pack, FILLP_UINT32 ackSeqNum, FILLP_UINT32 lostSeqNum)
{
    struct FillpPktHead *pktHdr = (struct FillpPktHead *)pack->head;
    if (FillpNumIsbigger(ackSeqNum, pcb->send.seqNum) ||
        FillpNumIsbigger(pcb->send.seqNum, (ackSeqNum + pcb->send.pktSendCache))) {
        FILLP_LOGERR("fillp_sock_id:%d, error:ack seqnum:%u send seqnum:%u, ackSeqNum:%u unSendList:%u, unRecvList:%u,"
            "unAckList:%u, itemWaitTokenLists:%u, redunList:%u, curItemCount:%u, mpSendSize:%u",
            FILLP_GET_SOCKET(pcb)->index, ackSeqNum, pcb->send.seqNum, pcb->send.ackSeqNum,
            pcb->send.unSendList.size, pcb->send.unrecvList.nodeNum, pcb->send.unackList.count,
            pcb->send.itemWaitTokenLists.nodeNum, pcb->send.redunList.nodeNum, pcb->send.curItemCount,
            pcb->mpSendSize);
        return FILLP_FALSE;
    }

    if (FillpNumIsbigger(pktHdr->pktNum, pcb->send.pktNum)) {
        FILLP_LOGDBG("error: ack pktnum =%u sendpktnum = %u", pktHdr->pktNum, pcb->send.pktNum);
        return FILLP_FALSE;
    }

    if (FillpNumIsbigger(ackSeqNum, lostSeqNum)) {
        FILLP_LOGERR("error: ackSeqNum:%u, lost pktnum:%u", ackSeqNum, lostSeqNum);
        return FILLP_FALSE;
    }

    FILLP_LOGDBG("fillp_sock_id:%d loss:%u,rate:%u,seq:%u,pkt:%u,flag:%u,oppRate:%u,lostSeq:%u",
        FILLP_GET_SOCKET(pcb)->index, FILLP_NTOHS(pack->pktLoss),
        FILLP_NTOHL(pack->rate), pktHdr->seqNum, pktHdr->pktNum,
        FILLP_NTOHS(pack->flag), FILLP_NTOHL(pack->oppositeSetRate), lostSeqNum);

    return FILLP_TRUE;
}

static void FillpHandleAdhocpackFlag(struct FillpPcb *pcb, struct FillpPktPack *pack)
{
    if (pack->flag & FILLP_PACK_FLAG_REQURE_RTT) {
        struct FillpPktPack tmpPack;
        struct FtSocket *ftSock = FILLP_NULL_PTR;

        (void)memset_s(&tmpPack, sizeof(tmpPack), 0, sizeof(tmpPack));
        tmpPack.rate = pcb->statistics.pack.periodRecvRate;
        tmpPack.oppositeSetRate = 0;
        tmpPack.flag = FILLP_NULL_NUM;
        tmpPack.flag |= FILLP_PACK_FLAG_ADHOC;
        tmpPack.flag |= FILLP_PACK_FLAG_WITH_RTT;
        tmpPack.pktLoss = 0;
        tmpPack.reserved.rtt = FILLP_NTOHL(pack->reserved.rtt);
        tmpPack.lostSeq = pcb->recv.seqNum;

        ftSock = FILLP_GET_SOCKET(pcb);
        pcb->adhocPackReplied = FILLP_TRUE;
        FillpBuildAndSendPack(pcb, ftSock, &tmpPack, sizeof(struct FillpPktPack) - FILLP_HLEN);
    }

    if (pack->flag & FILLP_PACK_FLAG_WITH_RTT) {
        FILLP_LLONG curTime = SYS_ARCH_GET_CUR_TIME_LONGLONG();

        pack->reserved.rtt = FILLP_NTOHL(pack->reserved.rtt);
        /* rtt isn't much large, so only use the low 32bit is ok */
        pcb->statistics.appFcStastics.periodRtt =
            FILLP_UTILS_US2MS(((FILLP_UINT32)((FILLP_ULLONG)curTime & 0xFFFFFFFF) - pack->reserved.rtt));
        FILLP_LOGDBG("fillp_sock_id:%d, rtt = %u", FILLP_GET_SOCKET(pcb)->index,
            pcb->statistics.appFcStastics.periodRtt);
    }

    if (pcb->algFuncs.hdlPackFlag != FILLP_NULL_PTR) {
        pcb->algFuncs.hdlPackFlag(pcb, pack);
    }
}

static void FillpTryAckSendPcbByPackInfo(struct FillpPcb *pcb, FILLP_CONST struct FillpPktPack *pack,
    FILLP_UINT32 ackSeqNum, FILLP_UINT32 lostSeqNum)
{
    if (FillpNumIsbigger(ackSeqNum, pcb->send.ackSeqNum)) {
        if (FillpNumIsbigger(ackSeqNum, pcb->send.maxAckNumFromReceiver)) {
            pcb->send.maxAckNumFromReceiver = ackSeqNum;
            if (lostSeqNum != ackSeqNum) {
                FILLP_LOGDBG("fillp_sock_id:%d PACK: %u ~ %u, rate : %ukbps, Lost :%u unackcount:%u",
                    FILLP_GET_SOCKET(pcb)->index, ackSeqNum, lostSeqNum, pack->rate, pack->pktLoss,
                    FillpGetSendpcbUnackListPktNum(&(pcb->send)));
            }
        }
        FillpAckSendPcb(pcb, FILLP_MAXIMAL_ACK_NUM_LIMITATION);
    }
}

static void FillpHdlAdhocpack(struct FillpPcb *pcb, struct FillpPktPack *pack)
{
    struct FillpPktHead *pktHdr = (struct FillpPktHead *)pack->head;
    FillpHandleAdhocpackFlag(pcb, pack);
    FillpTryAckSendPcbByPackInfo(pcb, pack, pktHdr->seqNum, pack->lostSeq);
}

static void FillpChangePackInterval(struct FillpPcb *pcb, FILLP_CONST struct FtSocket *sock,
    FILLP_CONST struct FillpPktPack *pack)
{
    // It need to cancel if receiving any data from peer
    if (sock->resConf.common.enlargePackIntervalFlag && (pack->flag & FILLP_PACK_FLAG_NO_DATA_SEND)) {
        pcb->statistics.pack.packInterval = FILLP_NODATARECV_PACK_INTERVAL;
    } else {
        pcb->statistics.pack.packInterval = pcb->statistics.pack.packIntervalBackup;
    }
}

static FILLP_INT FillpHandlePackFlag(struct FillpPcb *pcb, struct FillpPktPack *pack)
{
    if ((pack->flag & FILLP_PACK_FLAG_WITH_RTT) && (!pcb->rtt)) {
        pack->reserved.rtt = FILLP_NTOHL(pack->reserved.rtt);
        pcb->rtt = pack->reserved.rtt;
        if (pcb->rtt > 0) {
            FillpAdjustFcParamsByRtt(pcb);
        }
    }

    if ((!pcb->statistics.pack.peerRtt) && (!(pack->flag & FILLP_PACK_FLAG_REQURE_RTT))) {
        pcb->statistics.pack.peerRtt = FILLP_TRUE;
    }

    struct FtSocket *sock = (struct FtSocket *)FILLP_GET_CONN(pcb)->sock;
    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("sock is null");
        return -1;
    }
    FillpChangePackInterval(pcb, sock, pack);

    pcb->packTimerNode.interval = pcb->statistics.pack.packInterval;

    if (pcb->algFuncs.hdlPackFlag != FILLP_NULL_PTR) {
        pcb->algFuncs.hdlPackFlag(pcb, pack);
    }

    return ERR_OK;
}

static void MoveUnackToUnrecvByPackInfo(struct FillpPcb *pcb, FILLP_UINT32 ackSeqNum, FILLP_UINT32 lostSeqNum)
{
    /* when FILLP_RETRANSMIT_CMP_TIME_EXT is 0, packet item resend is controlled by pack cnt with same
     * ackSeqNum */
    if (g_resource.retransmitCmpTime) {
        FillpMoveUnackToUnrecv(ackSeqNum, lostSeqNum, pcb, FILLP_TRUE);
        return;
    }

    if (ackSeqNum == pcb->send.lastPackAckSeq) {
        FILLP_UINT8 cmp_threshold = pcb->send.packMoveToUnrecvThreshold;
        pcb->send.packSameAckNum++;
        if (pcb->send.packSameAckNum >= cmp_threshold) {
            FillpMoveUnackToUnrecv(ackSeqNum, lostSeqNum, pcb, FILLP_TRUE);
            pcb->send.packSameAckNum = 0;
        }
    } else {
        pcb->send.lastPackAckSeq = ackSeqNum;
        pcb->send.packSameAckNum = 0;
    }
}

static void FillpPackInputLog(FILLP_CONST struct FillpPcb *pcb)
{
    FILLP_LOGDBG("fillp_sock_id:%d nackSend:%u,nackFailed:%u,nackRcv:%u,packSend:%u,packFailed:%u,packRcv:%u",
        FILLP_GET_SOCKET(pcb)->index, pcb->statistics.debugPcb.nackSend, pcb->statistics.debugPcb.nackFailed,
        pcb->statistics.debugPcb.nackRcv, pcb->statistics.debugPcb.packSend, pcb->statistics.debugPcb.packFailed,
        pcb->statistics.debugPcb.packRcv);

    FILLP_LOGDBG("fillp_sock_id:%d totalSend:%u,total_send_fail:%u,total_send_success:%u,"
        "totalSendBytes:%u totalRetryed:%u",
        FILLP_GET_SOCKET(pcb)->index, pcb->statistics.traffic.totalSend, pcb->statistics.traffic.totalSendFailed,
        pcb->statistics.traffic.totalSend - pcb->statistics.traffic.totalSendFailed,
        pcb->statistics.traffic.totalSendBytes, pcb->statistics.traffic.totalRetryed);

    FILLP_LOGDBG("fillp_sock_id:%d packIntervalSendPkt:%u,total_recv_bytes:%u,self_period_recv_rate:%u,"
        "last_Pack_input_time:%lld",
        FILLP_GET_SOCKET(pcb)->index, pcb->statistics.debugPcb.packIntervalSendPkt,
        pcb->statistics.traffic.totalRecved, pcb->statistics.pack.periodRecvRate,
        pcb->statistics.debugPcb.packRecvedTimeInterval);

    FILLP_LOGDBG("fillp_sock_id:%d After_Pack_input, unackList:%u,unrecvList:%u, itemWaitTokenLists:%u",
        FILLP_GET_SOCKET(pcb)->index, pcb->send.unackList.count, pcb->send.unrecvList.nodeNum,
        pcb->send.itemWaitTokenLists.nodeNum);
}


static void FillpPackInput(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *p)
{
    struct FillpPktPack *pack = FILLP_NULL_PTR;
    struct FillpPktHead *pktHdr = FILLP_NULL_PTR;
    FILLP_UINT32 ackSeqNum;
    FILLP_UINT32 lostSeqNum;

    if (FillpCheckPackInput(pcb, p) == FILLP_FALSE) {
        return;
    }

    /* Header fields are already converted in FillpDoInput, and hence here
       should not be converted again
    */
    pack = (struct FillpPktPack *)(void *)p->p;
    pktHdr = (struct FillpPktHead *)pack->head;
    pack->flag = FILLP_NTOHS(pack->flag);
    ackSeqNum = pktHdr->seqNum;
    pack->lostSeq = FILLP_NTOHL(pack->lostSeq);
    lostSeqNum = pack->lostSeq;
    if (FillpCheckPackNumber(pcb, pack, ackSeqNum, lostSeqNum) == FILLP_FALSE) {
        return;
    }

    /* send pack message maintenance info */
    FillpPackInputSendMsgTrace(pcb, pktHdr, pack);

    pack->pktLoss = FILLP_NTOHS(pack->pktLoss);
    pack->rate = FILLP_NTOHL(pack->rate);
    pack->oppositeSetRate = FILLP_NTOHL(pack->oppositeSetRate);

    if (pack->flag & FILLP_PACK_FLAG_ADHOC) {
        FILLP_LOGDBG("Adhoc Pack, ackSeqNum:%u, flag:%u", ackSeqNum, pack->flag);
        FillpHdlAdhocpack(pcb, pack);
        return;
    }

    if (FillpHandlePackFlag(pcb, pack) != ERR_OK) {
        return;
    }

    FillpTryAckSendPcbByPackInfo(pcb, pack, ackSeqNum, lostSeqNum);

    /* move item from unack list to unrecv list by the lostSeqNum */
    MoveUnackToUnrecvByPackInfo(pcb, ackSeqNum, lostSeqNum);
    pcb->statistics.debugPcb.packRcv++;

    FillpPackInputLog(pcb);
    FillpFcPackInput(pcb, pack);
}

static void FillpHdlConnect(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *buf, struct SpungeInstance *inst,
    FILLP_UINT16 flag)
{
    FILLP_BOOL validPkt = FILLP_TRUE;
    switch (flag) {
        case FILLP_PKT_TYPE_CONN_REQ:
#ifdef FILLP_SERVER_SUPPORT
            FillpConnReqInput(pcb, buf);
#else
            FILLP_LOGINF("FILLP_SERVER_SUPPORT is NOT enabled and received conn_req packet from peer "
                         "fillp_sock_id:%d", FILLP_GET_SOCKET(pcb)->index);
#endif
            break;
        case FILLP_PKT_TYPE_CONN_REQ_ACK:
            FillpConnReqAckInput(pcb, buf);
            break;
        case FILLP_PKT_TYPE_CONN_CONFIRM:
#ifdef FILLP_SERVER_SUPPORT
            FillpConnConfirmInput(pcb, buf, inst);
#else
            FILLP_LOGDBG("FILLP_SERVER_SUPPORT is NOT enabled and received conn_confirm packet from peer "
                         "fillp_sock_id:%d", FILLP_GET_SOCKET(pcb)->index);
#endif
            break;
        case FILLP_PKT_TYPE_CONN_CONFIRM_ACK:
            /*
                client sends connection request
                server directly sends CONFIRM ACK

                Our fillp server cannot do this. attacker does this .

                --- At client side, if we have not sent CONFIRM and get the CONFIRM ACK
                    then silently discard the message. We will not close the socket
                    here, socket close will happen when connectTimeout is expired.
            */
            if (FILLP_CLIENT_FOUR_HANDSHAKE_STATE_CONFIRM_SENT == FILLP_GET_CONN(pcb)->clientFourHandshakeState) {
                FillpConnConfirmAckInput(pcb, buf);
            }
            break;
        default:
            validPkt = FILLP_FALSE;
            break;
    }
    if (validPkt) {
        pcb->statistics.keepAlive.lastRecvTime = pcb->pcbInst->curTime;
    }
}

static void FillpDoInputPktType(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *buf, struct SpungeInstance *inst,
    FILLP_UINT16 flag)
{
    FILLP_BOOL validPkt = FILLP_TRUE;
    switch (flag) {
        case FILLP_PKT_TYPE_DATA:
            FillpHdlDataInput(pcb, buf);
            break;
        case FILLP_PKT_TYPE_NACK:
            FillpNackInput(pcb, buf);
            break;
        case FILLP_PKT_TYPE_PACK:
            FillpPackInput(pcb, buf);
            break;
        case FILLP_PKT_TYPE_FIN: {
            FILLP_BOOL pcbFreed = FILLP_FALSE;
            FillpFinInput(pcb, buf, &pcbFreed);
            /* If PCB is freed then no need to update stats */
            if (pcbFreed) {
                validPkt = FILLP_FALSE;
            }
            break;
        }
        default:
            FillpHdlConnect(pcb, buf, inst, flag);
            validPkt = FILLP_FALSE;
            break;
    }
    if (validPkt) {
        pcb->statistics.keepAlive.lastRecvTime = pcb->pcbInst->curTime;
    }
}

void FillpDoInput(struct FillpPcb *pcb, FILLP_CONST struct NetBuf *buf, struct SpungeInstance *inst)
{
    struct FillpPktHead *head = (struct FillpPktHead *)(void *)buf->p;
    FillpTraceDescriptSt fillpTrcDesc;
    struct FtSocket *ftSock = FILLP_GET_SOCKET(pcb);
    FILLP_UCHAR packetType;

    if (ftSock->traceFlag >= FILLP_TRACE_DIRECT_NETWORK) {
        /* Check for DATA message and all other fillp-control mesasge which has
           only header as the message and provide indication

           IMPORTANT: DATA message check SHOULD be the first check considering performance
           aspect, otherwise it results in multiple OR condition check
        */
        packetType = (FILLP_UCHAR)FILLP_PKT_GET_TYPE(FILLP_NTOHS(head->flag));
        if (packetType == FILLP_PKT_TYPE_DATA) {
            struct FillpPktHead tmpHead;

            tmpHead.dataLen = head->dataLen;
            tmpHead.flag = head->flag;
            tmpHead.pktNum = head->pktNum;
            tmpHead.seqNum = head->seqNum;

            FILLP_LM_FILLPMSGTRACE_OUTPUT_WITHOUT_FT_TRACE_ENABLE_FLAG(FILLP_TRACE_DIRECT_NETWORK,
                ftSock->traceHandle, FILLP_HLEN, ftSock->index, fillpTrcDesc, (FILLP_CHAR *)&tmpHead);
        }
    }

    /* convert pkt head structure from network to hex format */
    head->flag = FILLP_NTOHS(head->flag);
    head->dataLen = FILLP_NTOHS(head->dataLen);
    head->pktNum = FILLP_NTOHL(head->pktNum);
    head->seqNum = FILLP_NTOHL(head->seqNum);

    FILLP_PKT_SIMPLE_LOG(ftSock->index, head, FILLP_DIRECTION_RX);

    if (buf->len > (FILLP_INT)pcb->pktSize) {
        /* format specifier %zu is used for size_t variable */
        FILLP_LOGINF("FillpDoInput: recv buffer length incorrect, dataLen = %d is greater than pktSize = %zu,"
                     "flag:%u, pktNum:%u, seqNum:%u",
                     buf->len, pcb->pktSize, head->flag, head->pktNum, head->seqNum);
        FillpDfxPktNotify(ftSock->index, FILLP_DFX_PKT_PARSE_FAIL, 1U);
        return;
    }

    if ((FILLP_INT)head->dataLen > buf->len) {
        FILLP_LOGINF("FillpDoInput: fillp_sock_id:%d protocol head incorrect. "
                     "dataLen = %u greater than buflen = %d, flag:%u, pktNum:%u, seqNum:%u",
                     ftSock->index, head->dataLen, buf->len, head->flag, head->pktNum, head->seqNum);
        FillpDfxPktNotify(ftSock->index, FILLP_DFX_PKT_PARSE_FAIL, 1U);
        return;
    }
    FillpDoInputPktType(pcb, buf, inst, (FILLP_UINT16)FILLP_PKT_GET_TYPE(head->flag));
}

#ifdef __cplusplus
}
#endif
