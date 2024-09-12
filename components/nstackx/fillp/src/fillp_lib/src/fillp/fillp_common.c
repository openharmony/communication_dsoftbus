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
#include "res.h"
#include "opt.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FILLP_PACKET_INTER  2

void FillpFreeItemAndEvent(struct FillpPcb *pcb, struct FillpPcbItem *item)
{
    FillpFreeBufItem(item);
    (void)SYS_ARCH_ATOMIC_INC(&(FILLP_GET_SOCKET(pcb)->sendEventCount), 1);
#ifdef SOCK_SEND_SEM
    (void)SYS_ARCH_SEM_POST(&pcb->send.sendSem);
#endif /* SOCK_SEND_SEM */
}

void InsertUnrecvListFail(struct FillpPcb *pcb, struct FillpPcbItem *item)
{
    FILLP_LOGERR("fillp_sock_id:%d Can't add item <%u,%u> to unrecvList",
        FILLP_GET_SOCKET(pcb)->index, item->seqNum, item->dataLen);
    FillpFreeItemAndEvent(pcb, item);
}

static void FillpDelPktSeqHashItem(FILLP_UINT32 pktNum, FILLP_CONST struct FillpHashLlist *mapList)
{
    FILLP_UINT32 hashIndex = (FILLP_UINT32)(pktNum & mapList->hashModSize);
    struct Hlist *list = &mapList->hashMap[hashIndex];

    struct HlistNode *pos = HLIST_FIRST(list);
    struct FillpPcbItem *item = FILLP_NULL_PTR;

    while (pos != FILLP_NULL_PTR) {
        item = FillpPcbPktSeqMapNodeEntry(pos);

        if (item->pktNum == pktNum) {
            break;
        } else if (FillpNumIsbigger(item->pktNum, pktNum)) {
            return;
        }
        pos = pos->next;
    }

    if (pos != FILLP_NULL_PTR) {
        HlistDelete(list, pos);
    }
}

void FillpMoveUnackToUnrecv(FILLP_UINT32 ackSeq, FILLP_UINT32 lostSeq, struct FillpPcb *pcb,
    FILLP_BOOL isFromPack)
{
    FillpMoveUnackToUnrecvAll(ackSeq, lostSeq, pcb, isFromPack, FILLP_FALSE);
}

static FILLP_BOOL FillpMoveOneNode(struct Hlist *list, FILLP_UINT32 lostSeq, struct FillpPcb *pcb,
    FILLP_BOOL isFromPack, FILLP_BOOL onePktOnly)
{
    FILLP_BOOL pktFound = FILLP_FALSE;
    struct FillpHashLlist *unackList = &pcb->send.unackList;
    FILLP_LLONG cmpGap;
    if (g_resource.retransmitCmpTime) {
        cmpGap = (FILLP_LLONG)pcb->send.retramistRto;
    } else {
        cmpGap = 0;
    }
    while (HLIST_FIRST(list) != FILLP_NULL_PTR) {
        struct FillpPcbItem *item = FillpPcbEntry(HLIST_FIRST(list));
        if (FillpNumIsbigger(item->seqNum, lostSeq) == FILLP_TRUE) {
            break;
        }

        FILLP_LLONG gap = pcb->pcbInst->curTime - item->lastSendTimestamp;
        if (gap < cmpGap) {
            break;
        }

        HlistDelete(list, HLIST_FIRST(list));
        if (unackList->count > 0) {
            unackList->count--;
        }

        if (isFromPack) {
            pcb->send.inSendBytes -= (FILLP_ULLONG)item->dataLen;
            item->infCount--;
        }
        FillpDelPktSeqHashItem(item->pktNum, &pcb->send.pktSeqMap);
        if (SkipListInsert(&pcb->send.unrecvList, (void *)item, &item->skipListNode, FILLP_TRUE) !=
            ERR_OK) {
            InsertUnrecvListFail(pcb, item);
            FILLP_LOGERR("fillp_sock_id:%d Can't move to unrecvList from unackList !!!",
                FILLP_GET_SOCKET(pcb)->index);
            break;
        }

        pcb->send.unrecvRedunListBytes += item->dataLen;
        item->sendCount++;
        if (isFromPack) {
            item->resendTrigger = (FILLP_UINT8)FILLP_ITEM_RESEND_TRIGGER_PACK;
        } else { /* item resend triggered by tail protect */
            item->resendTrigger = (FILLP_UINT8)FILLP_ITEM_RESEND_TRIGGER_TP;
        }
        pcb->statistics.appFcStastics.periodSendLostPkts++;

        if (onePktOnly) {
            pktFound = FILLP_TRUE;
            break;
        }
    }
    return pktFound;
}

void FillpMoveUnackToUnrecvAll(FILLP_UINT32 ackSeq, FILLP_UINT32 lostSeq, struct FillpPcb *pcb,
    FILLP_BOOL isFromPack, FILLP_BOOL onePktOnly)
{
    struct FillpHashLlist *unackList = FILLP_NULL_PTR;
    FILLP_UINT32 i;
    FILLP_UINT32 ackSeqIndex;
    FILLP_UINT32 lostSeqIndex;
    FILLP_UINT32 loopCount;
    FILLP_UINT32 unackListSize;
    FILLP_UINT32 hashModSize;

    if (lostSeq == ackSeq) {
        return;
    }

    ackSeqIndex = FILLP_UNACKLIST_HASHINDEX(ackSeq, pcb);
    lostSeqIndex = FILLP_UNACKLIST_HASHINDEX(lostSeq, pcb);
    unackList = &pcb->send.unackList;
    loopCount = (FILLP_UINT32)((lostSeqIndex + unackList->size - ackSeqIndex) & unackList->hashModSize);
    unackListSize = unackList->size;
    hashModSize = unackList->hashModSize;

    if ((lostSeq - ackSeq) / FILLP_UNACK_HASH_MOD >= unackListSize) {
        loopCount = unackListSize;
    }

    for (i = 0; i <= loopCount; i++) {
        FILLP_UINT32 hashIndex = (FILLP_UINT32)((i + ackSeqIndex) & hashModSize);
        struct Hlist *list = &unackList->hashMap[hashIndex];

        FILLP_BOOL pktFound = FillpMoveOneNode(list, lostSeq, pcb, isFromPack, onePktOnly);
        if (pktFound == FILLP_TRUE) {
            break;
        }
    }

    if (pcb->send.unrecvList.nodeNum > 0) {
        FillpEnableSendTimer(pcb);
    }
}

static inline void LogForMsgRTT(const struct FillpPcbItem *item)
{
    if (UTILS_FLAGS_CHECK(item->flags, FILLP_ITEM_FLAGS_LAST_PKT_FOR_CAL_COST)) {
        FILLP_LOGINF("cost between send-recv: last seq:%u, cost:%lld, size:%u", item->seqNum,
            (SYS_ARCH_GET_CUR_TIME_LONGLONG() - (FILLP_LLONG)item->appSendTimestamp), item->appSendSize);
    }
}

static void FillpAckItemWaitTklist(struct FillpPcb *pcb, FILLP_UINT32 seqNum)
{
    struct SkipListNode *node = FILLP_NULL_PTR;
    struct FillpPcbItem *item = FILLP_NULL_PTR;

    if (!FillpNumIsbigger(seqNum, pcb->send.ackSeqNum)) {
        return;
    }

    node = SkipListGetPop(&pcb->send.itemWaitTokenLists);
    while (node != FILLP_NULL_PTR) {
        item = (struct FillpPcbItem *)node->item;
        if (FillpNumIsbigger(item->seqNum, seqNum)) {
            break;
        }

        pcb->send.inSendBytes -= (FILLP_ULLONG)((FILLP_ULLONG)item->dataLen * item->infCount);
        item->infCount = 0;
        (void)SkipListPopValue(&pcb->send.itemWaitTokenLists);
        pcb->pcbInst->stb.waitPktCount--;
        FillpFreeBufItem(item);
        (void)SYS_ARCH_ATOMIC_INC(&(FILLP_GET_SOCKET(pcb)->sendEventCount), 1);
#ifdef SOCK_SEND_SEM
        (void)SYS_ARCH_SEM_POST(&pcb->send.send_sem);
#endif /* SOCK_SEND_SEM */
        node = SkipListGetPop(&pcb->send.itemWaitTokenLists);
    }
}

static int FillpAckUnrecvList(struct FillpPcb *pcb, FILLP_UINT32 seqNum)
{
    struct SkipListNode *node = FILLP_NULL_PTR;
    struct FillpPcbItem *item = FILLP_NULL_PTR;
    struct FtNetconn *conn = FILLP_GET_CONN(pcb);
    struct FtSocket *sock = (struct FtSocket *)conn->sock;

    FILLP_INT count = 0;
    if (!FillpNumIsbigger(seqNum, pcb->send.ackSeqNum)) {
        return count;
    }

    node = SkipListGetPop(&pcb->send.unrecvList);
    while (node != FILLP_NULL_PTR) {
        item = (struct FillpPcbItem *)node->item;
        if (FillpNumIsbigger(item->seqNum, seqNum)) {
            break;
        }

        (void)SkipListPopValue(&pcb->send.unrecvList);

        pcb->send.unrecvRedunListBytes -= item->dataLen;
        pcb->send.inSendBytes -= (FILLP_ULLONG)((FILLP_ULLONG)item->dataLen * item->infCount);
        item->infCount = 0;
        FillpFreeBufItem(item);
        (void)SYS_ARCH_ATOMIC_INC(&sock->sendEventCount, 1);
#ifdef SOCK_SEND_SEM
        (void)SYS_ARCH_SEM_POST(&pcb->send.send_sem);
#endif /* SOCK_SEND_SEM */
        count++;
        node = SkipListGetPop(&pcb->send.unrecvList);
    }
    return count;
}

static void FillpAckRedunlist(struct FillpPcb *pcb, FILLP_UINT32 seqNum)
{
    struct SkipListNode *node = FILLP_NULL_PTR;
    struct FillpPcbItem *item = FILLP_NULL_PTR;

    if (!FillpNumIsbigger(seqNum, pcb->send.ackSeqNum)) {
        return;
    }

    node = SkipListGetPop(&pcb->send.redunList);
    while (node != FILLP_NULL_PTR) {
        item = (struct FillpPcbItem *)node->item;
        if (FillpNumIsbigger(item->seqNum, seqNum)) {
            break;
        }

        pcb->send.unrecvRedunListBytes -= item->dataLen;
        pcb->send.inSendBytes -= (FILLP_ULLONG)((FILLP_ULLONG)item->dataLen * item->infCount);
        item->infCount = 0;
        (void)SkipListPopValue(&pcb->send.redunList);
        FillpFreeBufItem(item);
        (void)SYS_ARCH_ATOMIC_INC(&(FILLP_GET_SOCKET(pcb)->sendEventCount), 1);
#ifdef SOCK_SEND_SEM
        (void)SYS_ARCH_SEM_POST(&pcb->send.send_sem);
#endif /* SOCK_SEND_SEM */
        node = SkipListGetPop(&pcb->send.redunList);
    }
}

static void FreeUnackList(struct FillpPcb *pcb, struct FillpPcbItem *item, struct Hlist *tempCtl)
{
    LogForMsgRTT(item);
    HlistDelNode(&item->pktSeqMapNode);
    HlistDelete(tempCtl, HLIST_FIRST(tempCtl));

    if (pcb->send.unackList.count > 0) {
        pcb->send.unackList.count--;
    }

    pcb->send.inSendBytes -= (FILLP_ULLONG)((FILLP_ULLONG)item->dataLen * item->infCount);
    item->infCount = 0;
    FillpFreeItemAndEvent(pcb, item);
}

IGNORE_OVERFLOW static void FillpAckUnackList(struct FillpPcb *pcb,
    FILLP_UINT32 curSeq, FILLP_INT cntLimit)
{
    FILLP_UINT32 i, loopCount;

    struct FtNetconn *conn = FILLP_GET_CONN(pcb);
    struct FtSocket *sock = (struct FtSocket *)conn->sock;

    if (!FillpNumIsbigger(curSeq, pcb->send.ackSeqNum)) {
        return;
    }

    FillpAckRedunlist(pcb, curSeq);
    FillpAckItemWaitTklist(pcb, curSeq);

    /* 1) First , we ack all unrecvList
       2) Then , we just try to ack limited unACK items
       3) If all items acked, then we can set the pcb->send.ackSeqNum = curSeq
    */
    FILLP_INT count = FillpAckUnrecvList(pcb, curSeq);
    if ((cntLimit > 0) && (count >= cntLimit)) {
        goto END;
    }

    struct FillpHashLlist *unackList = &(pcb->send.unackList);
    FILLP_UINT32 unackListSize = unackList->size;
    FILLP_UINT32 hashModSize = unackList->hashModSize;

    FILLP_UINT32 lastSeqIndex = (pcb->send.ackSeqNum / FILLP_UNACK_HASH_MOD) & hashModSize;
    FILLP_UINT32 curSeqIndex = (curSeq / FILLP_UNACK_HASH_MOD) & hashModSize;

    // Still need to check if should loop all list
    if (((curSeq / FILLP_UNACK_HASH_MOD) - (pcb->send.ackSeqNum / FILLP_UNACK_HASH_MOD)) >= unackListSize) {
        loopCount = unackListSize;
    } else {
        loopCount = UTILS_MIN((curSeqIndex + unackListSize - lastSeqIndex) & hashModSize, unackListSize);
    }

    for (i = 0; i <= loopCount; i++) {
        struct Hlist *list = pcb->send.unackList.hashMap;
        struct Hlist *tempCtl = &list[(i + lastSeqIndex) & hashModSize];

        while (HLIST_FIRST(tempCtl) != FILLP_NULL_PTR) {
            struct FillpPcbItem *item = FillpPcbEntry(HLIST_FIRST(tempCtl));
            if (FillpNumIsbigger(item->seqNum, curSeq) == FILLP_TRUE) {
                break;
            }
            FreeUnackList(pcb, item, tempCtl);
            count++;
            if ((cntLimit > 0) && (count >= cntLimit)) {
                goto END;
            }
        }
    }

END:
    if ((count == 0) || (!FillpNumIsbigger(pcb->send.pktSendCache, (curSeq - pcb->send.ackSeqNum)))) {
        pcb->send.ackSeqNum = curSeq;
    }
    SpungeEpollEventCallback(sock, SPUNGE_EPOLLOUT, count);
}

IGNORE_OVERFLOW void FillpAckSendPcb(struct FillpPcb *pcb, FILLP_INT cntLimit)
{
    FILLP_UINT32 pktSendCnt;
    /* ack the item in unackList */
    FillpAckUnackList(pcb, pcb->send.maxAckNumFromReceiver, cntLimit);
    pktSendCnt = pcb->send.unackList.count + pcb->send.unrecvList.nodeNum +
        pcb->send.itemWaitTokenLists.nodeNum + pcb->send.redunList.nodeNum;
    if (pktSendCnt == 0 && pcb->send.inSendBytes != 0) {
        FILLP_LOGERR("FillpAckSendPcb  fillp_sock_id:%d   inSendBytes %llu", FILLP_GET_SOCKET(pcb)->index,
            pcb->send.inSendBytes);
        pcb->send.inSendBytes = 0;
    }
}

#if FILLP_ADHOC_PACK_ENABLE
static void FillpSendAdhocpack(struct FillpPcb *pcb)
{
    struct FillpPktPack pack;
    struct FtSocket *ftSock;

    ftSock = FILLP_GET_SOCKET(pcb);
    (void)memset_s(&pack, sizeof(pack), 0, sizeof(pack));
    pack.rate = pcb->statistics.pack.periodRecvRate;
    pack.oppositeSetRate = 0;
    pack.flag = FILLP_PACK_FLAG_ADHOC;
    pack.pktLoss = 0;
    pack.reserved.rtt = 0;
    pack.lostSeq = pcb->recv.seqNum;

    FillpBuildAndSendPack(pcb, ftSock, &pack, sizeof(struct FillpPktPack) - FILLP_HLEN);
}
#endif

IGNORE_OVERFLOW void FillpUploadRecvBox(struct FillpPcb *pcb)
{
    struct FillpPcbItem *item = FILLP_NULL_PTR;
    struct SkipListNode *node = FILLP_NULL_PTR;
    struct SkipList *recvList = &pcb->recv.recvList;
    void *itemPool[FILLP_DEFAULT_RECVBOX_BRUST];
    FILLP_BOOL needLoopRun = FILLP_TRUE;

    do {
        FILLP_INT count = 0;

        node = SkipListGetPop(recvList);
        while ((node != FILLP_NULL_PTR) && (count < FILLP_DEFAULT_RECVBOX_BRUST)) {
            FILLP_UINT32 start_seq;
            item = (struct FillpPcbItem *)node->item;
            start_seq = item->seqNum - item->dataLen;

            /*
               1.startSeq = recv.seqNum : This pkt is we expected
               2.startSeq < recv.seqNum : This pkt has been recved
               3.startSeq > recv.seqNum : There is a gap between this pkt and last recved one
            */
            if (start_seq != pcb->recv.seqNum) {
                break;
            }

            FillpFrameRx(&pcb->frameHandle, item);

            itemPool[count++] = (void *)item;
            pcb->recv.seqNum = item->seqNum;
            pcb->recv.recvBytes -= item->dataLen;
            (void)SkipListPopValue(recvList);
            node = SkipListGetPop(recvList);
        }

        if (count == 0) {
            needLoopRun = FILLP_FALSE;
        }

        if (count > 0) {
            if (pcb->recvFunc(FILLP_GET_CONN(pcb), itemPool, count) != ERR_OK) {
                FILLP_LOGERR("upload data failed !!!!!!");
            }

#if FILLP_ADHOC_PACK_ENABLE
            /* if my receive buffer usage goes beyond 5% of the total available
            buffer occupation, send pack immediately and don't wait for the pack
            timeout to send it, since it will block the send buffer on sender
            side */
            if ((pcb->recv.pktNum - pcb->recv.lastPackPktNum) >= ADHOC_PACK_TRIGGLE_THRESHOLD) {
                FILLP_LOGDBG("fillp_sock_id:%d pktNum=%u lastPackPktNum=%u, diff=%u size=%u sending PACK",
                    FILLP_GET_SOCKET(pcb)->index, pcb->recv.pktNum, pcb->recv.lastPackPktNum,
                    (pcb->recv.pktNum - pcb->recv.lastPackPktNum), pcb->mpRecvSize);

                FillpSendAdhocpack(pcb);
            }
#endif
        }
    } while (needLoopRun);
}

static void FillpSendRepaetNack(struct FillpPcb *pcb, struct FillpPktNack *nack)
{
    FILLP_UINT16 i;
    struct FillpPktNackWithRandnum nackTest;
    FillpTraceDescriptSt fillpTrcDesc;
    struct FtSocket *ftSock = (struct FtSocket *)FILLP_GET_CONN(pcb)->sock;
    fillpTrcDesc.traceDirection = FILLP_TRACE_DIRECT_SEND;
    (void)memcpy_s(&(nackTest.nack), sizeof(struct FillpPktNack), nack, sizeof(struct FillpPktNack));
    for (i = 0; i < g_resource.flowControl.nackRepeatTimes; i++) {
        nackTest.randomNum = FILLP_HTONLL(pcb->send.nackRandomNum + FILLP_RAND());
        pcb->send.nackRandomNum++;
        FILLP_INT ret = pcb->sendFunc(FILLP_GET_CONN(pcb), (char *)&nackTest, sizeof(struct FillpPktNackWithRandnum),
            FILLP_GET_CONN(pcb)->pcb);
        if (ret <= 0) {
            pcb->statistics.debugPcb.nackFailed++;
        } else {
            /* provide trace without random number, receiver has no logic with this number as it is just added to
               deceive firewall dropping same packet in short duration */
            FILLP_LM_FILLPMSGTRACE_OUTPUT(ftSock->traceFlag, FILLP_TRACE_DIRECT_NETWORK, ftSock->traceHandle,
                (sizeof(struct FillpPktNackWithRandnum) - sizeof(FILLP_ULLONG)), FILLP_GET_SOCKET(pcb)->index,
                (FILLP_UINT8 *)(void *)&fillpTrcDesc, (FILLP_CHAR *)(&nackTest));

            pcb->statistics.debugPcb.nackSend++;
        }
    }
}

void FillpSendNack(struct FillpPcb *pcb, FILLP_UINT32 startPktNum, FILLP_UINT32 endPktNum)
{
    struct FillpPktHead *pktHead = FILLP_NULL_PTR;
    FILLP_UINT32 pktNum = endPktNum;
    FILLP_UINT32 lostPktNum = (endPktNum - startPktNum) - 1;
    struct FillpPktNack *nack = pcb->send.retryNackQueue[pcb->send.retryIndex];

    if (nack == FILLP_NULL_PTR) {
        nack = SpungeAlloc(1, sizeof(struct FillpPktNack), SPUNGE_ALLOC_TYPE_CALLOC);
        if (nack == FILLP_NULL_PTR) {
            FILLP_LOGERR("fail to allocate memory for retry nack queue");
            return;
        }
        pcb->send.retryNackQueue[pcb->send.retryIndex] = nack;
    }

    nack->lastPktNum = FILLP_HTONL(pktNum);
    pktHead = (struct FillpPktHead *)nack->head;
    pktHead->flag = 0;
    FILLP_HEADER_SET_PKT_TYPE(pktHead->flag, FILLP_PKT_TYPE_NACK);
    FILLP_HEADER_SET_PROTOCOL_VERSION(pktHead->flag, FILLP_PROTOCOL_VERSION_NUMBER);
    pktHead->flag = FILLP_HTONS(pktHead->flag);

    pktHead->dataLen = 0;
    pktHead->dataLen = (FILLP_UINT16)(pktHead->dataLen + sizeof(struct FillpPktNackWithRandnum) - FILLP_HLEN);
    pktHead->dataLen = FILLP_HTONS(pktHead->dataLen);

    pktHead->pktNum = FILLP_HTONL(startPktNum);
    pktHead->seqNum = FILLP_HTONL(pcb->recv.seqNum);

    FILLP_LOGDBG("fillp_sock_id:%d Send NACK: last : %u, this : %u,  seq: %u", FILLP_GET_SOCKET(pcb)->index, pktNum,
        (startPktNum - 1), pcb->recv.seqNum);

    FillpSendRepaetNack(pcb, nack);

    pcb->send.retryIndex++;
    if (pcb->send.retryIndex >= pcb->statistics.nack.historyNackQueueLen) {
        pcb->send.retryIndex = pcb->send.retryIndex % pcb->statistics.nack.historyNackQueueLen;
    }

    FillpFcRecvLost(pcb, lostPktNum);
}

static void FillpAddNodeAtDelayNackListTail(struct FillpPcb *pcb, FILLP_UINT32 startPktNum, FILLP_UINT32 endPktNum)
{
    struct FtSocket *sock = (struct FtSocket *)((struct FtNetconn *)((struct SpungePcb*)pcb->spcb)->conn)->sock;
    struct FillpNackNode *nackNode =
        (struct FillpNackNode *)SpungeAlloc(1, sizeof(struct FillpNackNode), SPUNGE_ALLOC_TYPE_CALLOC);
    if (nackNode == FILLP_NULL_PTR) {
        FILLP_LOGERR("Failed allocate memory for FillpNackNode\n");
        return;
    }
    nackNode->startPktNum = startPktNum;
    nackNode->endPktNum = endPktNum;
    nackNode->timestamp = pcb->pcbInst->curTime;
    HlistAddTail(&(pcb->recv.nackList), &(nackNode->hnode));
    /* Start the delay timer */
    pcb->delayNackTimerNode.interval = (FILLP_UINT32)sock->resConf.common.nackDelayTimeout;
    FillpEnableDelayNackTimer(pcb);
}

/* If the out-of-order packet received, then we need to update the list
 * Such as the old record is [2,8], some time later , 4 received, then the node should update to [2,4] and [4, 8]
 */
static void FillpCheckAndUpdateDelayNackList(struct FillpPcb *pcb, FILLP_UINT32 curRecvPktNum)
{
    struct HlistNode *node;
    struct Hlist *list;
    list = &(pcb->recv.nackList);
    node = HLIST_FIRST(list);

    while (node != FILLP_NULL_PTR) {
        struct FillpNackNode *nackNode = FillpNackNodeEntry(node);
        FILLP_UINT32 startPktNum = nackNode->startPktNum;
        FILLP_UINT32 endPktNum = nackNode->endPktNum;

        if (FillpNumIsbigger(curRecvPktNum, endPktNum)) {
            node = node->next;
            continue;
        } else if (!FillpNumIsbigger(curRecvPktNum, startPktNum)) {
            break;
        } else if (curRecvPktNum == endPktNum) {
            break;
        }

        struct FillpNackNode *newNackNode = FILLP_NULL_PTR;
        if (startPktNum == (FILLP_UINT32)(curRecvPktNum - 1)) {
            if (startPktNum == (FILLP_UINT32)(endPktNum - FILLP_PACKET_INTER)) {
                HlistDelete(list, node);
                SpungeFree(nackNode, SPUNGE_ALLOC_TYPE_CALLOC);
                nackNode = FILLP_NULL_PTR;
            } else {
                nackNode->startPktNum = curRecvPktNum;
            }
            break;
        }

        if (curRecvPktNum == (FILLP_UINT32)(endPktNum - 1)) {
            nackNode->endPktNum = curRecvPktNum;
            break;
        }

        if (pcb->recv.nackList.size >= pcb->mpRecvSize) {
            break;
        }

        newNackNode = (struct FillpNackNode *)SpungeAlloc(1, sizeof(struct FillpNackNode), SPUNGE_ALLOC_TYPE_CALLOC);
        if (newNackNode == FILLP_NULL_PTR) {
            FILLP_LOGERR("Failed allocate memory for FillpNackNode\n");
            return;
        }

        newNackNode->startPktNum = curRecvPktNum;
        newNackNode->endPktNum = nackNode->endPktNum;
        newNackNode->timestamp = nackNode->timestamp;

        nackNode->endPktNum = curRecvPktNum;

        HlistAddAfter(list, node, &(newNackNode->hnode));
        /* Delay NACK timer is already running, no need to start again here */
        break;
    }
}

static void FillBiggerItem(struct FillpPcb *pcb, struct FillpPcbItem *item)
{
    if ((pcb->recv.pktNum + 1) != item->pktNum) {
        if ((g_appResource.common.enableNackDelay) && (pcb->recv.nackList.size < pcb->mpRecvSize)) {
            /*
            1. check if overflow or excess
            2. check list if full
            3. try to add this to the list, just the tail
            4. else
            one tx_cycle       -------- one rx_cycle
            send 1,2,3,4,5,6   -------- first recv 1,2,5, nackNode:3,4
            then recv 3, update nackNode:4,4
            */
            FillpAddNodeAtDelayNackListTail(pcb, pcb->recv.pktNum, item->pktNum);
        } else if (g_appResource.common.enableNackDelay == FILLP_FALSE &&
            pcb->recv.seqNum != (item->seqNum - item->dataLen)) {
            FillpSendNack(pcb, pcb->recv.pktNum, item->pktNum);
            FILLP_LOGDBG("fillp_sock_id:%d seq %u, pktNum : %u, recv.pktNum = %u, deta=%u, dataLen :%u",
                FILLP_GET_SOCKET(pcb)->index, item->seqNum, item->pktNum, pcb->recv.pktNum,
                item->pktNum - pcb->recv.pktNum, item->dataLen);
        }
    }

    pcb->recv.pktNum = item->pktNum;
}

static inline void FillpRecvDropItem(struct FillpPcb *pcb, struct FillpPcbItem *item)
{
    FillpFreeBufItem(item);
    FillpFcRecvDropOne(pcb);
}

void FillpDataToStack(struct FillpPcb *pcb, struct FillpPcbItem *item)
{
    FILLP_LOGDBG("fillp_sock_id:%d seq %u, pktNum : %u", FILLP_GET_SOCKET(pcb)->index, item->seqNum, item->pktNum);

    FillpFcDataInput(pcb, (struct FillpPktHead *)(void *)item->buf.p);

    if (FillpNumIsbigger(item->pktNum, pcb->recv.pktNum)) {
        FillBiggerItem(pcb, item);
    } else {
        if (g_appResource.common.enableNackDelay) {
            /*
            pktNum less than lastRecvPktNum
            1. check this pktNum is legal
            2. less than the head of list, drop
            3. greater than head, less than tail of list, update this list

            the struct member of list node must contain:
            1. pktNum, current pktNum recv now
            2. lastPktNum, the pktNum last recv
            3. timestamp, the time recv, in the main thread check the time past whether more than timeout
            if more, send the fix list node
            */
            if (!FillpNumIsbigger(item->seqNum, pcb->recv.seqNum)) {
                FILLP_LOGDBG("fillp_sock_id:%d seq Recved before: start %u, end: %u, pktNum: %u",
                    FILLP_GET_SOCKET(pcb)->index, pcb->recv.seqNum, item->seqNum, item->pktNum);

                FillpRecvDropItem(pcb, item);

                return;
            } else if (pcb->recv.nackList.size) {
                FillpCheckAndUpdateDelayNackList(pcb, item->pktNum);
            }
        }

        FillpFcRecvOutOfOrder(pcb);
    }

    /* If this seqNum has been recved */
    if (!FillpNumIsbigger(item->seqNum, pcb->recv.seqNum)) {
        FILLP_LOGDBG("fillp_sock_id:%d seq Recved before: pcb->recv.seqNum %u, item->seqNum: %u, pktNum: %u",
            FILLP_GET_SOCKET(pcb)->index, pcb->recv.seqNum, item->seqNum, item->pktNum);

        FillpRecvDropItem(pcb, item);
        return;
    }

    if (SkipListInsert(&pcb->recv.recvList, (void *)item, &item->skipListNode, FILLP_TRUE)) {
        FillpRecvDropItem(pcb, item);

        FILLP_LOGDTL("fillp_sock_id:%d Insert to recvBox error: start %u, end: %u", FILLP_GET_SOCKET(pcb)->index,
            pcb->recv.seqNum, item->seqNum);
        return;
    }
    pcb->recv.recvBytes += item->dataLen;

    FillpUploadRecvBox(pcb);
}

void FillpAjustTlpParameterByRtt(struct FillpPcb *pcb, FILLP_LLONG rtt)
{
    if (rtt < FILLP_RTT_TIME_LEVEL1) {
#ifdef PDT_MIRACAST
        pcb->send.tailProtect.minJudgeThreshold = FILLP_ONE_THIRD_OF_RTT;
        pcb->send.tailProtect.maxJudgeThreshold = FILLP_ONE_THIRD_OF_RTT + 1;
#else
        if (rtt < FILLP_RTT_TIME_LEVEL1_HALF) {
            pcb->send.tailProtect.minJudgeThreshold = FILLP_ONE_THIRD_OF_RTT - 1;
            pcb->send.tailProtect.maxJudgeThreshold = FILLP_ONE_THIRD_OF_RTT;
        } else {
            pcb->send.tailProtect.minJudgeThreshold = FILLP_ONE_THIRD_OF_RTT;
            pcb->send.tailProtect.maxJudgeThreshold = FILLP_ONE_THIRD_OF_RTT + 1;
        }
#endif
    } else if (rtt < FILLP_RTT_TIME_LEVEL2) {
        pcb->send.tailProtect.minJudgeThreshold = FILLP_ONE_FOURTH_OF_RTT;
        pcb->send.tailProtect.maxJudgeThreshold = FILLP_ONE_FOURTH_OF_RTT + 1;
    } else {
        pcb->send.tailProtect.minJudgeThreshold = FILLP_ONE_FIFTH_OF_RTT;
        pcb->send.tailProtect.maxJudgeThreshold = FILLP_ONE_FIFTH_OF_RTT + 1;
    }

    pcb->send.tailProtect.judgeThreshold = pcb->send.tailProtect.minJudgeThreshold;
}

static void FillpCalPackInterval(struct FillpPcb *pcb)
{
    if (pcb->algFuncs.calPackInterval != FILLP_NULL_PTR) {
        pcb->algFuncs.calPackInterval(pcb);
    }
    pcb->packTimerNode.interval = pcb->statistics.pack.packInterval;
    pcb->send.retramistRto = pcb->rtt;

    pcb->statistics.pack.packIntervalBackup = pcb->statistics.pack.packInterval;
    pcb->statistics.debugPcb.curPackDeltaUs = pcb->statistics.pack.packIntervalBackup;

    /* Update the fc_pack_timer */
    FILLP_UINT32 packInterval = FillpGetSockPackInterval(pcb);
    if ((pcb->rtt / FILLP_FC_RTT_PACK_RATIO) < packInterval) {
        pcb->FcTimerNode.interval = packInterval;
    } else {
        pcb->FcTimerNode.interval = (FILLP_UINT32)(pcb->rtt / FILLP_FC_RTT_PACK_RATIO);
    }

    FILLP_LOGDTL("fillp_sock_id:%d, packInterval:%u, fcTime:%u, RTT:%llu, minPackInterval:%u, retransmitRTO:%llu",
        FILLP_GET_SOCKET(pcb)->index, pcb->packTimerNode.interval, pcb->FcTimerNode.interval, pcb->rtt,
        packInterval, pcb->send.retramistRto);
}

static void FillpCalNackDelayTimeByPackInterval(struct FillpPcb *pcb)
{
    struct FtNetconn *conn = FILLP_GET_CONN(pcb);
    struct FtSocket *sock = FILLP_NULL_PTR;
    if (conn == FILLP_NULL_PTR) {
        FILLP_LOGERR("netconn is NULl");
        return;
    }
    sock = (struct FtSocket *)conn->sock;
    if (sock == FILLP_NULL_PTR) {
        FILLP_LOGERR("sock is NULL");
        return;
    }

    /* nack_delay timeout depend on pack interval, there threshold is 5000us */
    if (pcb->statistics.pack.packInterval > 5000) {
        sock->resConf.common.nackDelayTimeout = pcb->statistics.pack.packInterval - FILLP_INTERVAL_THRESHOLD;
    }
    sock->resConf.common.nackDelayTimeout = UTILS_MAX(sock->resConf.common.nackDelayTimeout,
        FILLP_INTERVAL_DEFAULT);
}

void FillpAdjustFcParamsByRtt(struct FillpPcb *pcb)
{
    FillpCalPackInterval(pcb);
    FillpCalNackDelayTimeByPackInterval(pcb);

    FillpAjustTlpParameterByRtt(pcb, (FILLP_LLONG)pcb->rtt);
    pcb->statistics.appFcStastics.periodRtt = (FILLP_UINT32)FILLP_UTILS_US2MS(pcb->rtt);
}

void FillpBuildAndSendPack(struct FillpPcb *pcb, struct FtSocket *ftSock, struct FillpPktPack *pack,
    FILLP_UINT16 dataLen)
{
    FILLP_INT ret;
    FILLP_UINT tmpDataLen;
    FillpTraceDescriptSt fillpTrcDesc;
    struct FillpPktHead *pktHead = (struct FillpPktHead *)pack->head;
    pktHead->seqNum = pcb->recv.seqNum;
    pktHead->dataLen = dataLen;

    /* 0 converted to network order is also 0, hence explicit conversion not applied */
    if ((pack->flag & FILLP_PACK_FLAG_ADHOC) == 0) {
        pktHead->pktNum = pcb->recv.pktNum;
    }

    pktHead->flag = 0;
    FILLP_HEADER_SET_PKT_TYPE(pktHead->flag, FILLP_PKT_TYPE_PACK);
    FILLP_HEADER_SET_PROTOCOL_VERSION(pktHead->flag, FILLP_PROTOCOL_VERSION_NUMBER);
    pktHead->flag = FILLP_HTONS(pktHead->flag);
    tmpDataLen = pktHead->dataLen;
    pktHead->dataLen = FILLP_HTONS(pktHead->dataLen);
    pktHead->seqNum = FILLP_HTONL(pcb->recv.seqNum);
    pktHead->pktNum = FILLP_HTONL(pcb->recv.pktNum);
    pcb->recv.lastPackPktNum = pcb->recv.pktNum;
    pcb->recv.lastPackSeqNum = pcb->recv.seqNum;

    pack->flag = FILLP_HTONS(pack->flag);
    pack->pktLoss = FILLP_HTONS(pcb->statistics.pack.periodRecvPktLoss);
    pack->rate = FILLP_HTONL(pcb->statistics.pack.periodRecvRate);
    pack->oppositeSetRate = FILLP_HTONL(pack->oppositeSetRate);
    pack->lostSeq = FILLP_HTONL(pack->lostSeq);
    pack->reserved.rtt = FILLP_HTONL(pack->reserved.rtt);
    pack->bgnPktNum = FILLP_HTONL(pack->bgnPktNum);
    pack->endPktNum = FILLP_HTONL(pack->endPktNum);
    pack->optsOffset = FILLP_HTONS(pack->optsOffset);
    pack->rcvListBytes = FILLP_HTONL(pack->rcvListBytes);

    pcb->send.packRandomNum++;
    ret = pcb->sendFunc(FILLP_GET_CONN(pcb), (char *)pack, (FILLP_INT)(tmpDataLen + FILLP_HLEN),
        (struct SpungePcb *)pcb->spcb);
    if (ret <= 0) {
        pcb->statistics.debugPcb.packFailed++;
    } else {
        fillpTrcDesc.traceDirection = FILLP_TRACE_DIRECT_SEND;
        if (ftSock != FILLP_NULL_PTR) {
            FILLP_LM_FILLPMSGTRACE_OUTPUT(ftSock->traceFlag, FILLP_TRACE_DIRECT_NETWORK, ftSock->traceHandle,
                sizeof(struct FillpPktPack), FILLP_GET_SOCKET(pcb)->index,
                (FILLP_UINT8 *)(void *)&fillpTrcDesc, (FILLP_CHAR *)(pack));
        }
        pcb->statistics.debugPcb.packSend++;
    }
}

#ifdef __cplusplus
}
#endif
