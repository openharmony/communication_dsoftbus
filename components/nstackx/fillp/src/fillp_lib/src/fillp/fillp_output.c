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

#include "fillp_output.h"
#include "opt.h"
#include "skiplist.h"
#include "log.h"
#include "fillp_buf_item.h"
#include "fillp.h"
#include "spunge_core.h"
#include "fillp_common.h"
#include "check_gso_support.h"

#ifdef __cplusplus
extern "C" {
#endif

static void FillpMoveRedundantItemToUnrecvList(struct FillpPcb *pcb)
{
    struct FillpPcbItem *item;
    struct FillpSendPcb *sendPcb = &pcb->send;
    item = (struct FillpPcbItem *)SkipListPopValue(&sendPcb->redunList);
    while (item != FILLP_NULL_PTR) {
        if (SkipListInsert(&sendPcb->unrecvList, item, &item->skipListNode, FILLP_TRUE) != ERR_OK) {
            FILLP_LOGERR("fillp_sock_id:%d Can't move redundant item <%u,%u> to unrecvList",
                FILLP_GET_SOCKET(pcb)->index, item->seqNum, item->dataLen);
            sendPcb->unrecvRedunListBytes -= item->dataLen;
            FillpFreeBufItem(item);
            (void)SYS_ARCH_ATOMIC_INC(&(FILLP_GET_SOCKET(pcb)->sendEventCount), 1);
#ifdef SOCK_SEND_SEM
            (void)SYS_ARCH_SEM_POST(&pcb->send.send_sem);
#endif /* SOCK_SEND_SEM */
            break;
        }
        item = (struct FillpPcbItem *)SkipListPopValue(&sendPcb->redunList);
    }
}

IGNORE_OVERFLOW static struct FillpPcbItem *FillpGetSendItem(struct FillpSendPcb *sendPcb,
    struct FillpPcb *pcb)
{
    struct FillpPcbItem *item = (struct FillpPcbItem *)SkipListPopValue(&sendPcb->unrecvList);
    if (item != FILLP_NULL_PTR) {
        return item;
    }
    struct HlistNode *unsendNode = HLIST_FIRST(&sendPcb->unSendList);
    if (unsendNode == FILLP_NULL_PTR) {
        return FILLP_NULL_PTR;
    }
    item = FillpPcbUnsendNodeEntry(unsendNode);
    HlistDelete(&sendPcb->unSendList, unsendNode);
    sendPcb->seqNum = sendPcb->seqNum + (FILLP_UINT32)item->dataLen;
    item->seqNum = pcb->send.seqNum;
    item->sendCount = 0;
    item->infCount = 0;
    item->resendTrigger = 0;

    if (UTILS_FLAGS_CHECK(item->flags, FILLP_ITEM_FLAGS_FIRST_PKT_FOR_CAL_COST)) {
        FILLP_LOGINF("cost between thread: first seq:%u, last seq:%u, cost:%lld, size:%u",
            item->seqNum, (item->seqNum + item->appSendSize - item->dataLen),
            (SYS_ARCH_GET_CUR_TIME_LONGLONG() - (FILLP_LLONG)item->appSendTimestamp), item->appSendSize);
    } else if (UTILS_FLAGS_CHECK(item->flags, FILLP_ITEM_FLAGS_LAST_PKT_FOR_CAL_COST)) {
        FILLP_LOGINF("send expand: last seq:%u, cost:%lld, size:%u", item->seqNum,
            (SYS_ARCH_GET_CUR_TIME_LONGLONG() - (FILLP_LLONG)item->appSendTimestamp), item->appSendSize);
    }
    return item;
}

static FILLP_BOOL FillpIsAskMoreBuf(struct FillpSendPcb *sendPcb, struct FillpPcb *pcb)
{
    if (sendPcb->unackList.count < (FILLP_UINT32)DYMP_GET_CUR_SIZE(sendPcb->itemPool)) {
        return FILLP_FALSE;
    }
    int askMoreRet = FillpAskMoreBufItem(sendPcb->itemPool, FILLP_DYMM_INCREASE_STEP_SEND, FILLP_TRUE);
    if (askMoreRet <= 0) {
        return FILLP_FALSE;
    }
    
    struct FtSocket *sock = FILLP_GET_SOCKET(pcb);
#ifdef SOCK_SEND_SEM
    for (int inx = 0; inx < askMoreRet; inx++) {
        (void)SYS_ARCH_SEM_POST(&sendPcb->send_sem);
    }
#endif /* SOCK_SEND_SEM */
    (void)SYS_ARCH_ATOMIC_INC(&sock->sendEventCount, askMoreRet);
    sendPcb->curItemCount = (FILLP_UINT32)DYMP_GET_CUR_SIZE(sendPcb->itemPool);
    FILLP_LOGDBG("Ask more buffer for send success, fillp_sock_id:%d", sock->index);
    return FILLP_TRUE;
}

static void FillpDoneSendAllData(struct FillpSendPcb *sendPcb, struct FillpPcb *pcb,
    FILLP_UINT32 sentBytes, FILLP_UINT32 sendPktNum)
{
    /* Done sending all data */
    if (sendPcb->preItem != FILLP_NULL_PTR) {
        struct FillpPcbItem *item = (struct FillpPcbItem *)sendPcb->preItem;
        UTILS_FLAGS_SET(item->flags, FILLP_ITEM_FLAGS_APP_LIMITED);
        FILLP_LOGDBG("fillp_sock_id:%d, appLimited triggle, pktNum:%u, seqNum:%u, sc:%u, "
            "unSendList:%u, unackList:%u, unrecvList:%u, redunList:%u, itemWaitTokenLists:%u, "
            "curItemCount:%u",
            FILLP_GET_SOCKET(pcb)->index, item->pktNum, item->seqNum, item->sendCount,
            pcb->send.unSendList.size, pcb->send.unackList.count, pcb->send.unrecvList.nodeNum,
            pcb->send.redunList.nodeNum, pcb->send.itemWaitTokenLists.nodeNum,
            pcb->send.curItemCount);
    }
    sendPcb->appLimited = FILLP_TRUE;

    FILLP_LOGDBG("fillp_sock_id:%d NO_ENOUGH_DATA, expected_send:%u, actual_send:%u, set to appLimited",
        FILLP_GET_SOCKET(pcb)->index, sendPktNum, (sentBytes / (FILLP_UINT32)pcb->pktSize));
    sendPcb->flowControl.lastCycleNoEnoughData = FILLP_TRUE;
    sendPcb->flowControl.remainBytes = FILLP_NULL;
    sendPcb->flowControl.sendOneNoData = FILLP_TRUE;
#ifdef FILLP_SUPPORT_GSO
    if (g_gsoSupport == FILLP_TRUE && pcb->sendmsgEio == FILLP_FALSE) {
        pcb->sendmsgFunc(FILLP_NULL_PTR, FILLP_NULL_PTR, 0, pcb);
    }
#endif
}

static FILLP_UINT32 FillpBeforeSendItem(struct FillpPcbItem *item, struct FillpPcb *pcb,
    FILLP_UINT32 sentBytes, FILLP_UINT32 totalBytes)
{
    struct FillpSendPcb *sendPcb = &pcb->send;
    if (item->sendCount > 0) { /* resend item */
        sendPcb->unrecvRedunListBytes -= item->dataLen;
    }
    /*
    * 1) no matter the number of need_send_count, we just add one time for send_cycle
    * 2) we should always add one time to the send_cycle even if it send fail
    * for flowControl, we must care the real_send_bytes
    * so we should add all the packets be sent into the packIntervalSendPkt
    */
    sentBytes = (sentBytes + (FILLP_UINT32)item->dataLen);
    if (sendPcb->appLimited) {
        UTILS_FLAGS_SET(item->flags, FILLP_ITEM_FLAGS_APP_LIMITED);
    } else {
        UTILS_FLAGS_CLEAN(item->flags, FILLP_ITEM_FLAGS_APP_LIMITED);
    }
    sendPcb->appLimited = FILLP_FALSE;
    if ((sentBytes >= totalBytes) || (item->resendTrigger == FILLP_ITEM_RESEND_TRIGGER_HNACK) ||
        UTILS_FLAGS_CHECK(item->flags, FILLP_ITEM_FLAGS_LAST_PKT)) {
        pcb->isLast = FILLP_TRUE;
    } else {
        pcb->isLast = FILLP_FALSE;
    }
    return sentBytes;
}

FILLP_UINT32 FillpSendOne(struct FillpPcb *pcb, FILLP_UINT32 totalBytes, FILLP_UINT32 sendPktNum)
{
    FILLP_INT ret;
    struct FillpPcbItem *item = FILLP_NULL_PTR;
    struct FillpSendPcb *sendPcb = &pcb->send;
    FILLP_UINT32 sentBytes = FILLP_NULL;

    FillpMoveRedundantItemToUnrecvList(pcb);
    /* We don't ack all the data in unSendPCB when received ack, because that may costs big time
     * and make the send period not sending enough data out
     *
     * So here we ack the unackList every beginning of send
     *
     * Don't need to ack in when send buffer is less than FILLP_MAXIMAL_ACK_NUM_LIMITATION,
     * because the items could be fully acked in recv pack
     */
    if (pcb->mpSendSize > FILLP_MAXIMAL_ACK_NUM_LIMITATION) {
        FillpAckSendPcb(pcb, (FILLP_INT)UTILS_MAX(sendPktNum << 1, FILLP_SEND_ONE_ACK_NUM));
    }

    while (sentBytes <= totalBytes) {
        item = FillpGetSendItem(sendPcb, pcb);
        if (item == FILLP_NULL_PTR) {
            if (FillpIsAskMoreBuf(sendPcb, pcb) == FILLP_TRUE) {
                continue;
            }
            FillpDoneSendAllData(sendPcb, pcb, sentBytes, sendPktNum);
            return sentBytes;
        }
        sendPcb->flowControl.sendOneNoData = FILLP_FALSE;

        sentBytes = FillpBeforeSendItem(item, pcb, sentBytes, totalBytes);
        ret = SpungeItemRouteByToken(item, pcb);
        if (ret != ERR_OK) {
            break;
        }
    }
    return sentBytes;
}

static FILLP_UINT16 FillpBuildTimestamp(FILLP_CHAR *dataOptionPtr)
{
    FillpErrorType err;
    FillpDataOption *dataOption = FILLP_NULL_PTR;

    FILLP_LLONG curTime = SYS_ARCH_GET_CUR_TIME_LONGLONG();
    curTime = (FILLP_LLONG)FILLP_HTONLL((FILLP_ULLONG)curTime);
    dataOption = (FillpDataOption *)dataOptionPtr;
    dataOption->type = FILLP_OPT_TIMESTAMP;
    dataOption->len = FILLP_OPT_TIMESTAMP_LEN;
    err = memcpy_s(&(dataOption->value[0]), sizeof(FILLP_LLONG), &curTime, sizeof(FILLP_LLONG));
    if (err != EOK) {
        FILLP_LOGERR("fillp_build_pkt_data_options memcpy_s failed:%d", err);
    }

    return (FILLP_UINT16)(FILLP_DATA_OPT_HLEN + FILLP_OPT_TIMESTAMP_LEN);
}

static void FillpBuildPktDataOptions(FILLP_CONST struct FillpPcb *pcb,
    struct FillpPcbItem *item, FILLP_CHAR *dataOptionAddr)
{
    FILLP_UINT16 offset = 0;
    FILLP_CHAR *option = dataOptionAddr + FILLP_DATA_OFFSET_LEN;

    if (UTILS_FLAGS_CHECK(item->dataOptFlag, FILLP_OPT_FLAG_TIMESTAMP)) {
        offset += FillpBuildTimestamp(option);
    }

    if (UTILS_FLAGS_CHECK(item->dataOptFlag, FILLP_OPT_FLAG_FRAME_INFO)) {
        offset += FillpFrameBuildOption(item, (FILLP_UINT8 *)&option[offset]);
    }

    *(FILLP_UINT16 *)(dataOptionAddr) = FILLP_HTONS(offset);
    FILLP_UNUSED_PARA(pcb);
}

static void FillpBuildDataPkt(struct FillpPcb *pcb, struct FillpPcbItem *item)
{
    struct NetBuf *sendBuf;
    struct FillpPktHead *pktHdr;
    struct FillpSendPcb *sendPcb = &pcb->send;
    FILLP_UINT16 flag = 0;
    struct FtSocket *sock = FILLP_GET_SOCKET(pcb);
    FillpTraceDescriptSt fillpTrcDesc;

    sendBuf = &item->buf;
    pktHdr = (struct FillpPktHead *)(void *)sendBuf->p;

    item->pktNum = ++sendPcb->pktNum;

    FILLP_HEADER_SET_PKT_TYPE(flag, FILLP_PKT_TYPE_DATA);
    FILLP_HEADER_SET_PROTOCOL_VERSION(flag, FILLP_PROTOCOL_VERSION_NUMBER);
    if (item->dataOptFlag && item->dataOptLen) {
        FILLP_HEADER_SET_DAT_WITH_OPTION(flag);
        FillpBuildPktDataOptions(pcb, item, sendBuf->p + (FILLP_UINT16)FILLP_HLEN);
    }

    if (UTILS_FLAGS_CHECK(item->flags, FILLP_ITEM_FLAGS_LAST_PKT_FOR_CAL_COST)) {
        FILLP_HEADER_SET_DAT_WITH_LAST_FLAG(flag);
    } else if (UTILS_FLAGS_CHECK(item->flags, FILLP_ITEM_FLAGS_FIRST_PKT_FOR_CAL_COST)) {
        FILLP_HEADER_SET_DAT_WITH_FIRST_FLAG(flag);
    }
    pktHdr->flag = FILLP_HTONS(flag);

    pktHdr->pktNum = FILLP_HTONL(item->pktNum);
    pktHdr->seqNum = FILLP_HTONL(item->seqNum);
    pktHdr->dataLen = FILLP_HTONS(item->dataLen);

    /* Log the first data sending out of this connection */
    if (pcb->statistics.traffic.totalSend == 0) {
        FILLP_LOGINF("FirstData!!! fillp_sock_id:%d send seq num:%u, send pkt num:%u", sock->index, pcb->send.seqNum,
            pcb->send.pktNum);
    }

    FILLP_LM_TRACE_SEND_MSG(sock->traceFlag, FILLP_TRACE_DIRECT_NETWORK, sock->traceHandle, FILLP_HLEN, sock->index,
        fillpTrcDesc, (FILLP_CHAR *)pktHdr);
}

static void UpdateStatisticsWhenSendOne(struct FillpStatisticsPcb *stats, FILLP_UINT32 bufLen)
{
    stats->debugPcb.packIntervalSendBytes += bufLen;
    stats->debugPcb.packIntervalSendPkt++;
    stats->traffic.totalSend++;
    stats->traffic.totalSendBytes += bufLen;

    stats->appFcStastics.periodSendPkts++;
    stats->appFcStastics.periodSendBits += (FILLP_ULLONG)FILLP_FC_VAL_IN_BITS(((FILLP_ULLONG)bufLen));
}

static FillpErrorType FillpAddtoListBySeqNum(struct Hlist *list, struct FillpPcbItem *item)
{
    struct HlistNode *pos = FILLP_NULL_PTR;
    struct FillpPcbItem *posItem = FILLP_NULL_PTR;
    if (HLIST_EMPTY(list)) {
        HlistAddHead(list, &item->node);
        return ERR_OK;
    }

    pos = HLIST_TAIL(list);
    posItem = FILLP_NULL_PTR;

    while (pos != FILLP_NULL_PTR) {
        posItem = FillpPcbEntry(pos);
        if (posItem->seqNum == item->seqNum) {
            return ERR_COMM;
        } else if (FillpNumIsbigger(posItem->seqNum, item->seqNum)) {
            pos = (struct HlistNode *)(void *)pos->pprev;
            if (pos == &list->head) { // Back to the head, no more data
                pos = FILLP_NULL_PTR;
            }
        } else {
            break; /* Insert before pos */
        }
    }

    if (pos != FILLP_NULL_PTR) {
        HlistAddAfter(list, pos, &item->node);
    } else {
        /* Smaller than the first one */
        HlistAddHead(list, &item->node);
    }

    return ERR_OK;
}

static FillpErrorType FillpAddToUnackList(struct FillpPcb *pcb, struct FillpPcbItem *item)
{
    FILLP_UINT32 unackIndex = FILLP_UNACKLIST_HASHINDEX(item->seqNum, pcb);
    if (FillpAddtoListBySeqNum(&pcb->send.unackList.hashMap[unackIndex], item) != ERR_OK) {
        if (SkipListInsert(&pcb->send.unrecvList, item, &item->skipListNode, FILLP_TRUE) != ERR_OK) {
            FILLP_LOGERR("fillp_sock_id:%d Can't add send ones to SkipList", FILLP_GET_SOCKET(pcb)->index);
            return ERR_NOBUFS;
        }
        if (item->sendCount > 0) {
            pcb->send.unrecvRedunListBytes += item->dataLen;
        }
        FillpEnableSendTimer(pcb);
    } else {
        pcb->send.unackList.count++;
    }
    return ERR_OK;
}

static void FillpAddToPktSeqHash(FILLP_CONST struct FillpPcb *pcb, struct FillpPcbItem *item)
{
    struct Hlist *list = &pcb->send.pktSeqMap.hashMap[item->pktNum & pcb->send.pktSeqMap.hashModSize];
    HlistAddTail(list, &item->pktSeqMapNode);
}

static FILLP_INT FillpItemRetrans(struct FillpPcbItem *item, struct FillpPcb *fpcb, struct FillpSendPcb *sendPcb)
{
    /* First retransmit packet which sent but not received */
    if (item->sendCount > 0) {
        fpcb->statistics.traffic.totalRetryed++;
    }

    sendPcb->lastSendTs = fpcb->pcbInst->curTime;
    item->infCount++;
    sendPcb->inSendBytes += item->dataLen;

    if (FillpAddToUnackList(fpcb, item) != ERR_OK) {
        FILLP_LOGERR("FillpAddToUnackList error!seqNum:%u,insert to redunList", item->seqNum);
        /* fillp_add_to_unAckList will fail is seq number matches so calling SkipListInsert for unrecv list will again
        fail, so just free and continue, if lucky peer will receive this packet will be permantly lost, application need
        to recreate connection this failure should not happen until some bug in code */
        FillpFreeItemAndEvent(fpcb, item);
    } else {
        fpcb->send.preItem = (void *)item;
        FillpAddToPktSeqHash(fpcb, item);
    }
    return ERR_OK;
}

FILLP_INT FillpSendItem(struct FillpPcbItem *item, struct FillpPcb *fpcb)
{
    struct FtNetconn *conn = (struct FtNetconn *)FILLP_GET_CONN(fpcb);
    struct FillpStatisticsPcb *stats = &(fpcb->statistics);
    struct FillpSendPcb *sendPcb = &fpcb->send;
    FILLP_INT sentBytes;

    if (item->sendCount == 0) {
        item->firstSendTimestamp = fpcb->pcbInst->curTime;
        item->lastSendTimestamp = item->firstSendTimestamp;
    } else {
        item->lastSendTimestamp = fpcb->pcbInst->curTime;
        if (item->sendCount > stats->debugPcb.onePktMaxSendCount) {
            stats->debugPcb.onePktMaxSendCount = item->sendCount;
        }
    }

    FillpBuildDataPkt(fpcb, item);

    /*
     * for flowControl, we must care the real_send_bytes
     * so we should add all the packets be sent into the packIntervalSendPkt
     */
    UpdateStatisticsWhenSendOne(stats, (FILLP_UINT32)item->dataLen);

    /*
     * calculate loss rate by pktNum at recv endpoint,
     * so pktNum should be incresed when need_send_count more than 1
     */
#ifdef FILLP_SUPPORT_GSO
    if (g_gsoSupport == FILLP_FALSE || fpcb->sendmsgEio == FILLP_TRUE) {
#endif
        sentBytes = fpcb->sendFunc(conn, (void *)item->buf.p, (FILLP_INT)(item->buf.len + FILLP_HLEN), fpcb->spcb);
#ifdef FILLP_SUPPORT_GSO
    } else {
        sentBytes = fpcb->sendmsgFunc(conn, (void *)item->buf.p, (FILLP_INT)(item->buf.len + FILLP_HLEN), fpcb);
    }
#endif
    if (sentBytes <= 0) {
        stats->traffic.totalSendFailed++;
        /* Add to unrecvList */
        if (SkipListInsert(&sendPcb->unrecvList, (void *)item, &item->skipListNode, FILLP_TRUE) != ERR_OK) {
            InsertUnrecvListFail(fpcb, item);
        } else {
            if (item->sendCount > 0) {
                sendPcb->unrecvRedunListBytes += item->dataLen;
            }
        }
        /*
         * this is used to roll-back the pktNum which increased in func FillpBuildDataPkt,
         * if the increase role for sendPcb->pktNum or role to set item->pktNum is changed
         * this roll-back operation should be pay attention to
         */
        sendPcb->pktNum--;
        FillpEnableSendTimer(fpcb);
        return -1;
    }
    return FillpItemRetrans(item, fpcb, sendPcb);
}

void FillpSendAdhocpackToDetectRtt(struct FillpPcb *pcb)
{
    struct FillpPktPack pack;
    struct FtSocket *ftSock = FILLP_NULL_PTR;
    FILLP_LLONG curTime = SYS_ARCH_GET_CUR_TIME_LONGLONG();

    (void)memset_s(&pack, sizeof(pack), 0, sizeof(pack));
    pack.rate = pcb->statistics.pack.periodRecvRate;
    pack.oppositeSetRate = 0;
    pack.flag = FILLP_PACK_FLAG_ADHOC;
    pack.flag |= FILLP_PACK_FLAG_REQURE_RTT;
    pack.pktLoss = 0;
    pack.reserved.rtt =
        (FILLP_UINT32)((FILLP_ULLONG)curTime & 0xFFFFFFFF); /* rtt isn't much large, so only use the low 32bit is ok */
    pack.lostSeq = pcb->recv.seqNum;

    ftSock = FILLP_GET_SOCKET(pcb);
    FillpBuildAndSendPack(pcb, ftSock, &pack, sizeof(struct FillpPktPack) - FILLP_HLEN);
}

static void FillpSetSimplePack(FILLP_CONST struct FillpPcb *pcb, struct FillpPktPack *pack,
    FILLP_CONST struct FtSocket *ftSock)
{
    (void)memset_s(pack, sizeof(struct FillpPktPack), 0, sizeof(struct FillpPktPack));
    pack->rate = pcb->statistics.pack.periodRecvRate;
    pack->oppositeSetRate = 0;
    pack->flag = FILLP_NULL_NUM;
    pack->oppositeSetRate = pcb->recv.oppositeSetRate;
    if (pack->oppositeSetRate != 0) {
        pack->flag |= FILLP_PACK_FLAG_WITH_RATE_LIMIT;
    }

    if (ftSock->resConf.common.enlargePackIntervalFlag) {
        if (!(FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&pcb->sendTimerNode)) &&
            (!pcb->send.unackList.count)) {
            pack->flag |= FILLP_PACK_FLAG_NO_DATA_SEND;
        }
    }
    pack->pktLoss = pcb->statistics.pack.periodRecvPktLoss;

    pack->reserved.rtt = 0;
    if ((!pcb->statistics.pack.peerRtt) && pcb->rtt) {
        pack->flag |= FILLP_PACK_FLAG_WITH_RTT;
        pack->reserved.rtt = (FILLP_UINT32)pcb->rtt;
    }

    if (!pcb->rtt) {
        pack->flag |= FILLP_PACK_FLAG_REQURE_RTT;
    }
}

static FILLP_BOOL FillpSendPack(struct FillpPcb *pcb, struct FillpPktPack *pack)
{
    struct FillpPcbItem *item = FILLP_NULL_PTR;
    struct SkipListNode *node = FILLP_NULL_PTR;
    FILLP_UINT16 dataLen = 0;

    struct FtSocket *ftSock = FILLP_GET_SOCKET(pcb);
    if (ftSock == FILLP_NULL_PTR) {
        FILLP_LOGERR("sock is NULL");
        return FILLP_TRUE;
    }

    FillpSetSimplePack(pcb, pack, ftSock);
    node = SkipListGetPop(&pcb->recv.recvList);
    if (node != FILLP_NULL_PTR) {
        item = (struct FillpPcbItem *)node->item;
        pack->lostSeq = (item->seqNum - item->dataLen);
    } else {
        pack->lostSeq = pcb->recv.seqNum;
    }

    dataLen = sizeof(struct FillpPktPack) + dataLen - FILLP_HLEN;
    FillpBuildAndSendPack(pcb, ftSock, pack, dataLen);

    return FILLP_TRUE;
}

FILLP_BOOL FillpSendPackWithPcbBuffer(struct FillpPcb *pcb)
{
    FILLP_CHAR *buf = pcb->pcbInst->tmpBuf[0];
    struct FillpPktPack *pack = (struct FillpPktPack *)buf;

    return FillpSendPack(pcb, pack);
}

#ifdef __cplusplus
}
#endif
