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

#include "queue.h"
#include "fillp_flow_control.h"
#include "spunge_stack.h"
#include "spunge_core.h"
#include "fillp_buf_item.h"
#include "dympool.h"
#include "fillp_algorithm.h"
#include "fillp_output.h"
#include "res.h"
#include "fillp_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FILLP_PCB_GET_CONN(pcb) (struct FtNetconn *)((struct SpungePcb *)((pcb)->spcb))->conn
#define FILLP_UNRECV_THRESHOLD 2

IGNORE_OVERFLOW static inline FILLP_INT FillpSkiplistCmp(void *t1, void *t2)
{
    struct FillpPcbItem *value1 = (struct FillpPcbItem *)t1;
    struct FillpPcbItem *value2 = (struct FillpPcbItem *)t2;

    if (value1->seqNum == value2->seqNum) {
        return ERR_OK;
    }

    return ((FILLP_INT32)(value1->seqNum - value2->seqNum)) > 0;
}

IGNORE_OVERFLOW static inline FILLP_INT FillpSkiplistRecvcmp(void *t1, void *t2)
{
    struct FillpPcbItem *value1 = (struct FillpPcbItem *)t1;
    struct FillpPcbItem *value2 = (struct FillpPcbItem *)t2;

    if (value1->pktNum == value2->pktNum) {
        return ERR_OK;
    }

    return ((FILLP_INT32)(value1->seqNum - value2->seqNum)) > 0;
}

static FILLP_INT FillpInitSendpcbUnackList(struct FillpSendPcb *pcb)
{
    FILLP_UINT32 i;
    pcb->unackList.size = FILLP_UNACK_HASH_SIZE;
    pcb->unackList.hashModSize = pcb->unackList.size - 1;
    pcb->unackList.count = 0;
    pcb->unackList.hashMap =
        (struct Hlist *)SpungeAlloc(pcb->unackList.size, sizeof(struct Hlist), SPUNGE_ALLOC_TYPE_CALLOC);
    if (pcb->unackList.hashMap == FILLP_NULL_PTR) {
        FILLP_LOGERR("Failed to allocate memory for hash map");

        SkiplistDestroy(&pcb->unrecvList);
        return ERR_NOBUFS;
    }
    for (i = 0; i < pcb->unackList.size; i++) {
        HLIST_INIT(&pcb->unackList.hashMap[i]);
    }

    return ERR_OK;
}

static FILLP_INT FillpInitSendpcbPktSeqMap(struct FillpPcb *fpcb, struct FillpSendPcb *pcb)
{
    FILLP_UINT32 i;
    if (fpcb->mpSendSize > FILLP_MAX_PKTSEQ_HASH_SIZE) {
        pcb->pktSeqMap.size = FILLP_MAX_PKTSEQ_HASH_SIZE;
    } else {
        if ((fpcb->mpSendSize & (fpcb->mpSendSize - 1)) == 0) { /* already Power of 2  */
            pcb->pktSeqMap.size = fpcb->mpSendSize;
        } else { /* switch to power of 2  */
            for (pcb->pktSeqMap.size = 1; pcb->pktSeqMap.size <= fpcb->mpSendSize;) {
                pcb->pktSeqMap.size <<= 1;
            }
        }

        if (fpcb->mpSendSize > FILLP_MAX_PKTSEQ_HASH_SIZE) {
            pcb->pktSeqMap.size = FILLP_MAX_PKTSEQ_HASH_SIZE;
        }
    }

    pcb->pktSeqMap.hashModSize = pcb->pktSeqMap.size - 1;

    pcb->pktSeqMap.hashMap =
        (struct Hlist *)SpungeAlloc(pcb->pktSeqMap.size, sizeof(struct Hlist), SPUNGE_ALLOC_TYPE_CALLOC);
    if (pcb->pktSeqMap.hashMap == FILLP_NULL_PTR) {
        FILLP_LOGERR("Failed to allocate memory for hash map \r\n");

        SpungeFree(pcb->unackList.hashMap, SPUNGE_ALLOC_TYPE_CALLOC);
        pcb->unackList.hashMap = FILLP_NULL_PTR;
        SkiplistDestroy(&pcb->unrecvList);

        return ERR_NOBUFS;
    }

    for (i = 0; i < pcb->pktSeqMap.size; i++) {
        HLIST_INIT(&pcb->pktSeqMap.hashMap[i]);
    }

    return ERR_OK;
}

static void FillpFreeRecvItemPool(struct FillpRecvPcb *pcb)
{
    FillpDestroyBufItemPool(pcb->itemPool);
    pcb->itemPool = FILLP_NULL_PTR;
}

static void FillpFreeSendItemPool(struct FillpSendPcb *pcb)
{
    FillpDestroyBufItemPool(pcb->itemPool);
    pcb->itemPool = FILLP_NULL_PTR;
}

static FILLP_INT InitSendPcbSimplePar(struct FillpPcb *fpcb)
{
    struct FillpSendPcb *pcb = &fpcb->send;
    FILLP_INT ret;
    if (fpcb->mpSendSize == 0) {
        FILLP_LOGERR("FillpInitSendpcb:fpcb->mpSendSize is zero");
        return ERR_NOBUFS;
    }

    ret = SkiplistInit(&pcb->unrecvList, FillpSkiplistCmp);
    if (ret != ERR_OK) {
        FILLP_LOGERR("FillpInitSendpcb:SkiplistInit fails");
        return ERR_COMM;
    }

    ret = SkiplistInit(&pcb->itemWaitTokenLists, FillpSkiplistCmp);
    if (ret != ERR_OK) {
        FILLP_LOGERR("SkiplistInit redunList fails");
        SkiplistDestroy(&pcb->unrecvList);
        return ERR_COMM;
    }

    ret = SkiplistInit(&pcb->redunList, FillpSkiplistCmp);
    if (ret != ERR_OK) {
        FILLP_LOGERR("SkiplistInit redunList fails");
        SkiplistDestroy(&pcb->unrecvList);
        SkiplistDestroy(&pcb->itemWaitTokenLists);
        return ERR_COMM;
    }

    HLIST_INIT(&pcb->unSendList);
    pcb->unsendBox = FILLP_NULL_PTR;
    ret = FillpInitSendpcbUnackList(pcb);
    if (ret != ERR_OK) {
        SkiplistDestroy(&pcb->redunList);
        SkiplistDestroy(&pcb->itemWaitTokenLists);
        return ret;
    }

    ret = FillpInitSendpcbPktSeqMap(fpcb, pcb);
    if (ret != ERR_OK) {
        SkiplistDestroy(&pcb->redunList);
        SkiplistDestroy(&pcb->itemWaitTokenLists);
        return ret;
    }
    FILLP_LOGINF("send itemPool Size = %u", fpcb->mpSendSize);
    return ERR_OK;
}

static FILLP_INT InitSimplePcbPar(struct FillpSendPcb *pcb, struct FillpPcb *fpcb)
{
    FILLP_LOGINF("FillP init send PCB cache size:%u", fpcb->mpSendSize);
    pcb->newDataSendComplete = 0;
    pcb->nackRandomNum = FILLP_CRYPTO_RAND();
    pcb->packRandomNum = FILLP_CRYPTO_RAND();
    fpcb->statistics.nack.historyNackQueueLen = FILLP_DEFAULT_NACK_RETRY_LEN;
    pcb->retryNackQueue = SpungeAlloc(fpcb->statistics.nack.historyNackQueueLen, sizeof(struct FillpPktNack *),
        SPUNGE_ALLOC_TYPE_CALLOC);
    if (pcb->retryNackQueue == FILLP_NULL_PTR) {
        FILLP_LOGERR("fail to allocate memory for history nack queue");

        SpungeFree(pcb->unackList.hashMap, SPUNGE_ALLOC_TYPE_CALLOC);
        pcb->unackList.hashMap = FILLP_NULL_PTR;
        SpungeFree(pcb->pktSeqMap.hashMap, SPUNGE_ALLOC_TYPE_CALLOC);
        pcb->pktSeqMap.hashMap = FILLP_NULL_PTR;
        SkiplistDestroy(&pcb->unrecvList);
        SkiplistDestroy(&pcb->redunList);
        SkiplistDestroy(&pcb->itemWaitTokenLists);

        FillpFreeSendItemPool(pcb);

#ifdef SOCK_SEND_SEM
        (void)SYS_ARCH_SEM_DESTROY(&pcb->sendSem);
#endif
        return ERR_NORES;
    }
    pcb->retryIndex = 0;
    pcb->packMoveToUnrecvThreshold = FILLP_UNRECV_THRESHOLD;
    pcb->packSameAckNum = 0;
    pcb->lastPackAckSeq = 0;
    pcb->retramistRto = 0;
    pcb->preItem = FILLP_NULL_PTR;
    pcb->nackPktStartNum = pcb->pktStartNum;
    pcb->nackPktEndNum = pcb->pktStartNum;
    pcb->inSendBytes = 0;
    pcb->lastSendTs = fpcb->pcbInst->curTime;
    pcb->unrecvRedunListBytes = 0;

    return ERR_OK;
}

static FILLP_INT InitItemPool(struct FillpPcb *fpcb)
{
    struct FillpSendPcb *pcb = &fpcb->send;
    FILLP_INT ret;

    int initSize = (fpcb->fcAlg == FILLP_SUPPORT_ALG_MSG) ? FILLP_MSG_DYMM_INIT_SEND_SIZE : FILLP_DYMM_INIT_SEND_SIZE;
    pcb->itemPool = FillpCreateBufItemPool((int)fpcb->mpSendSize, initSize, (int)fpcb->pktSize);
    if (pcb->itemPool == FILLP_NULL_PTR) {
        FILLP_LOGERR("create itempool  fails");

        SpungeFree(pcb->unackList.hashMap, SPUNGE_ALLOC_TYPE_CALLOC);
        pcb->unackList.hashMap = FILLP_NULL_PTR;
        SpungeFree(pcb->pktSeqMap.hashMap, SPUNGE_ALLOC_TYPE_CALLOC);
        pcb->pktSeqMap.hashMap = FILLP_NULL_PTR;
        SkiplistDestroy(&pcb->unrecvList);
        SkiplistDestroy(&pcb->redunList);
        SkiplistDestroy(&pcb->itemWaitTokenLists);
        return ERR_NORES;
    }
    ret = ERR_OK;
    FillbufItemPoolSetConflictSafe(pcb->itemPool, FILLP_TRUE, FILLP_FALSE);

    pcb->unsendBox = SpungeAllocUnsendBox(fpcb->pcbInst);
    if (pcb->unsendBox == FILLP_NULL_PTR) {
        /* This function cannot fail, hence no free added here */
        FILLP_LOGERR("Can't get pcb unsendBox");
        return ERR_NORES;
    }
    return ret;
}

static FILLP_INT FillpInitSendpcb(struct FillpPcb *fpcb)
{
    struct FillpSendPcb *pcb = &fpcb->send;
    int initCacheSize;

    FILLP_INT ret = InitSendPcbSimplePar(fpcb);
    if (ret != ERR_OK) {
        return ret;
    }
    ret = InitItemPool(fpcb);
    if (ret != ERR_OK) {
        return ret;
    }

    initCacheSize = DYMP_GET_CUR_SIZE((DympoolType *)pcb->itemPool);
    pcb->curItemCount = (FILLP_UINT32)initCacheSize;

    FILLP_LOGINF("send init cache size:%d", initCacheSize);

#ifdef SOCK_SEND_SEM
    ret = SYS_ARCH_SEM_INIT(&pcb->sendSem, (FILLP_ULONG)initCacheSize);
    if (ret != FILLP_OK) {
        FILLP_LOGERR("FillpInitSendpcb:SYS_ARCH_SEM_INIT fails");

        SpungeFree(pcb->unackList.hashMap, SPUNGE_ALLOC_TYPE_CALLOC);
        pcb->unackList.hashMap = FILLP_NULL_PTR;
        SpungeFree(pcb->pktSeqMap.hashMap, SPUNGE_ALLOC_TYPE_CALLOC);
        pcb->pktSeqMap.hashMap = FILLP_NULL_PTR;
        SkiplistDestroy(&pcb->unrecvList);
        SkiplistDestroy(&pcb->redunList);
        SkiplistDestroy(&pcb->itemWaitTokenLists);

        FillpFreeSendItemPool(pcb);
        return ERR_NORES;
    }
#endif /* SOCK_SEND_SEM */

    return InitSimplePcbPar(pcb, fpcb);
}

static FillpQueue *FillpInitRecvPcbBox(struct FillpPcb *fpcb, struct FillpRecvPcb *pcb)
{
    FILLP_INT privRecvSize;

    privRecvSize = 0;
    pcb->privItemPool = FILLP_NULL_PTR;
    int initSize = (fpcb->fcAlg == FILLP_SUPPORT_ALG_MSG) ? FILLP_MSG_DYMM_INIT_RECV_SIZE : FILLP_DYMM_INIT_RECV_SIZE;
    pcb->itemPool = FillpCreateBufItemPool((int)fpcb->mpRecvSize, initSize, (int)fpcb->pktSize);
    if (pcb->itemPool == FILLP_NULL_PTR) {
        FILLP_LOGERR("FillpInitRecvpcb:FillpCreateBufItemPool fails \r\n");
        SkiplistDestroy(&pcb->recvBoxPlaceInOrder);
        return FILLP_NULL_PTR;
    }
    FillbufItemPoolSetConflictSafe(pcb->itemPool, FILLP_FALSE, FILLP_TRUE);
    FILLP_LOGINF("FillP init recv PCB cache size:%u", fpcb->mpRecvSize);
    pcb->curItemCount = (FILLP_UINT32)DYMP_GET_CUR_SIZE(pcb->itemPool);

    FillpQueue *recvBox = FillpQueueCreate("sock_recv_box", fpcb->mpRecvSize + (FILLP_UINT)privRecvSize,
        SPUNGE_ALLOC_TYPE_MALLOC);
    if (recvBox == FILLP_NULL_PTR) {
        SkiplistDestroy(&pcb->recvBoxPlaceInOrder);

        FillpFreeRecvItemPool(pcb);
    }
    return recvBox;
}

FILLP_INT FillpInitRecvpcb(struct FillpPcb *fpcb)
{
    struct FillpRecvPcb *pcb = &fpcb->recv;

    FILLP_INT ret = SYS_ARCH_SEM_INIT(&pcb->recvSem, 0);
    if (ret != FILLP_OK) {
        FILLP_LOGERR("SYS_ARCH_SEM_INIT fails");
        return ERR_NORES;
    }

    /*
    init NACK List
    notice, it not need free when pcb remove
    */
    HLIST_INIT(&(pcb->nackList));

    if (SkiplistInit(&pcb->recvList, FillpSkiplistCmp)) {
        FILLP_LOGERR("SkiplistInit failsn");
        (void)SYS_ARCH_SEM_DESTROY(&pcb->recvSem);
        return ERR_NORES;
    }

    if (SkiplistInit(&pcb->recvBoxPlaceInOrder, FillpSkiplistRecvcmp)) {
        FILLP_LOGERR("SkiplistInit fails for recvBoxPlaceInOrder");
        goto NORES;
    }

    pcb->recvBox = FillpInitRecvPcbBox(fpcb, pcb);
    if (pcb->recvBox == FILLP_NULL_PTR) {
        FILLP_LOGERR("Fail to create recv box");
        goto NORES;
    }

    FillpQueueSetConsSafe(pcb->recvBox, FILLP_FALSE);
    FillpQueueSetProdSafe(pcb->recvBox, FILLP_FALSE);

    pcb->isRecvingData = 0;
    pcb->recvBytes = 0;
    return ERR_OK;
NORES:
    SkiplistDestroy(&pcb->recvList);
    (void)SYS_ARCH_SEM_DESTROY(&pcb->recvSem);
    return ERR_NORES;
}

static void InitSimpleStatics(const struct FillpPcb *fpcb, struct FillpStatisticsPcb *pcb)
{
    pcb->traffic.totalRecved = 0;
    pcb->traffic.totalRecvedBytes = 0;
    pcb->traffic.totalDroped = 0;
    pcb->traffic.totalRetryed = 0;
    pcb->traffic.totalSendFailed = 0;
    pcb->traffic.totalOutOfOrder = 0;
    pcb->traffic.totalRecvLost = 0;
    pcb->traffic.totalSend = 0;
    pcb->traffic.totalSendBytes = 0;

    pcb->traffic.packSendBytes = 0;
    pcb->traffic.packExpSendBytes = 0;

    pcb->pack.periodDroped = 0;
    pcb->pack.periodRecvBits = 0;
    pcb->pack.peerRtt = FILLP_FALSE;
    pcb->pack.periodRecvedOnes = 0;

    pcb->pack.packIntervalBackup = pcb->pack.packInterval;
    pcb->pack.packLostSeq = 0;
    pcb->pack.packSendTime = fpcb->pcbInst->curTime;
    pcb->pack.packTimePassed = 0;
    pcb->pack.packPktNum = 0;
    pcb->pack.packRttDetectTime = fpcb->pcbInst->curTime;

    pcb->pack.periodRecvPktLoss = 0;
    pcb->pack.periodRecvRate = 0;
    pcb->pack.lastPackRecvRate = 0;
    pcb->pack.maxRecvRate = 0;

    pcb->nack.nackHistorySendQueueNum = 0;
    pcb->nack.currentHistoryNackNum = 0;
    pcb->nack.nackSendTime = fpcb->pcbInst->curTime;
}

static void FillpInitStastics(struct FillpPcb *fpcb)
{
    FILLP_INT i;
    struct FillpStatisticsPcb *pcb = &fpcb->statistics;
    InitSimpleStatics(fpcb, pcb);
    if (pcb->nack.nackInterval == 0) {
        pcb->nack.nackInterval = FILLP_MIN_NACK_INTERVAL;
    }

    /* nack_delay timeout depend on pack interval, there threshold is 5000us */
    pcb->nack.nackDelayTimeout = (pcb->pack.packInterval > FILLP_INTERVAL_THRESHOLD) ?
        (pcb->pack.packInterval - FILLP_INTERVAL_THRESHOLD) : FILLP_INTERVAL_DEFAULT;

    (void)memset_s(&pcb->debugPcb, sizeof(struct FillpStatatisticsDebugPcb), 0,
        sizeof(struct FillpStatatisticsDebugPcb));
    pcb->debugPcb.packRecvedTimeInterval = fpcb->pcbInst->curTime;
    pcb->debugPcb.curPackDeltaUs = pcb->pack.packIntervalBackup;

    for (i = 0; i < FILLP_NACK_HISTORY_NUM; i++) {
        pcb->nackHistory.nackHistoryArr[i].lostPktGap = 0;
        pcb->nackHistory.nackHistoryArr[i].timestamp = 0;
    }
    pcb->nackHistory.nackHistoryNum = 0;
    pcb->nackHistory.pktLoss = 0;
    for (i = 0; i < FILLP_NACK_HISTORY_ARR_NUM; i++) {
        pcb->nackHistory.historyAvgLostPktGap[i] = 0;
        pcb->nackHistory.historyMaxLostPktGap[i] = 0;
        pcb->nackHistory.historyMinLostPktGap[i] = 0;
    }

    pcb->appFcStastics.periodTimePassed = fpcb->pcbInst->curTime;
    pcb->appFcStastics.pktNum = 0;
    pcb->appFcStastics.periodRecvBits = 0;
    pcb->appFcStastics.periodRecvPkts = 0;
    pcb->appFcStastics.periodRecvPktLoss = 0;
    pcb->appFcStastics.periodRecvRate = 0;
    pcb->appFcStastics.periodRecvRateBps = 0;

    pcb->appFcStastics.periodRtt = (FILLP_UINT32)FILLP_UTILS_US2MS(fpcb->rtt);
    pcb->appFcStastics.periodRecvPktLossHighPrecision = 0;
    pcb->appFcStastics.periodSendLostPkts = 0;
    pcb->appFcStastics.periodSendPkts = 0;
    pcb->appFcStastics.periodSendPktLossHighPrecision = 0;
    pcb->appFcStastics.periodSendBits = 0;
    pcb->appFcStastics.periodSendRateBps = 0;
}

static void FillpPcbFreeRecvItemArray(struct FillpRecvPcb *pcb)
{
    struct FillpPcbItem *item = FILLP_NULL_PTR;
    int ret;
    FILLP_ULONG loopCount;
    FILLP_ULONG index;

    loopCount = (FILLP_ULONG)pcb->recvBoxPlaceInOrder.nodeNum;
    for (index = 0; index < loopCount; index++) {
        item = SkipListPopValue(&pcb->recvBoxPlaceInOrder);
        FillpFreeBufItem(item);
    }

    loopCount = (FILLP_ULONG)pcb->recvList.nodeNum;
    for (index = 0; index < loopCount; index++) {
        item = SkipListPopValue(&pcb->recvList);
        FillpFreeBufItem(item);
    }

    loopCount = FillpQueueValidOnes(pcb->recvBox);
    for (index = 0; index < loopCount; index++) {
        ret = FillpQueuePop(pcb->recvBox, (void **)&item, 1);
        if (ret == 1) {
            FillpFreeBufItem(item);
        }
    }

    FillpFreeRecvItemPool(pcb);
}

static void FillpPcbRemoveRecv(struct FillpPcb *fpcb)
{
    struct FillpRecvPcb *pcb = &fpcb->recv;
    struct Hlist *nackList = FILLP_NULL_PTR;
    struct HlistNode *node = FILLP_NULL_PTR;
    struct FillpNackNode *nackNode = FILLP_NULL_PTR;
    FillpPcbFreeRecvItemArray(pcb);

    SkiplistDestroy(&pcb->recvBoxPlaceInOrder);
    SkiplistDestroy(&pcb->recvList);
    pcb->itemPool = FILLP_NULL_PTR;
    FillpQueueDestroy(pcb->recvBox);
    pcb->recvBox = FILLP_NULL_PTR;

    nackList = &(pcb->nackList);
    if (nackList->size > 0) {
        node = HLIST_FIRST(nackList);
        while (node != FILLP_NULL_PTR) {
            nackNode = FillpNackNodeEntry(node);
            node = node->next;
            SpungeFree(nackNode, SPUNGE_ALLOC_TYPE_CALLOC);
            nackNode = FILLP_NULL_PTR;
        }
    }

    HLIST_INIT(&(pcb->nackList));

    (void)SYS_ARCH_SEM_DESTROY(&pcb->recvSem);
}

void FillpPcbSendFc(struct FillpPcb *fpcb)
{
    if (FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&fpcb->sendTimerNode)) {
        return;
    }

    struct FillpFlowControl *flowControl = &fpcb->send.flowControl;
    FILLP_LLONG detaTime = (FILLP_LLONG)(fpcb->pcbInst->curTime - flowControl->sendTime);
    FILLP_LLONG realDetaTime = (FILLP_LLONG)((FILLP_ULLONG)detaTime << FILLP_TIME_PRECISION);
    if (flowControl->sendTime == 0 || realDetaTime >= flowControl->sendInterval) {
        SpungeDoSendCycle((struct SpungePcb*)fpcb->spcb, fpcb->pcbInst, realDetaTime);
    } else {
        FillpEnableSendTimer(fpcb);
    }
}

void FillpPcbSend(struct FillpPcb *fpcb, struct FillpPcbItem *item[], FILLP_UINT32 itemCnt)
{
    FILLP_UINT32 i;

    if (SYS_ARCH_SEM_WAIT(&fpcb->pcbInst->threadSem)) {
        FILLP_LOGWAR("sem wait failed");
        return;
    }

    fpcb->pcbInst->curTime = SYS_ARCH_GET_CUR_TIME_LONGLONG();

    for (i = 0; i < itemCnt; i++) {
        HlistAddTail(&fpcb->send.unSendList, &item[i]->unsendNode);
        (void)FillpFrameAddItem(&fpcb->frameHandle, item[i]);
    }

    FillpPcbSendFc(fpcb);

    if (SYS_ARCH_SEM_POST(&fpcb->pcbInst->threadSem)) {
        FILLP_LOGWAR("sem post failed");
    }
}

static void FillpPcbFreeSendItemArray(struct FillpPcb *fpcb)
{
    struct FillpSendPcb *pcb = &fpcb->send;

    struct HlistNode *node = FILLP_NULL_PTR;
    struct FillpPcbItem *item = FILLP_NULL_PTR;
    FILLP_UINT32 loopCount;
    FILLP_UINT32 index;

    loopCount = pcb->itemWaitTokenLists.nodeNum;
    for (index = 0; index < loopCount; index++) {
        item = SkipListPopValue(&pcb->itemWaitTokenLists);
        FillpFreeBufItem(item);
    }

    node = HLIST_FIRST(&pcb->unSendList);
    while (node != FILLP_NULL_PTR) {
        item = FillpPcbUnsendNodeEntry(node);
        node = node->next;
        HlistDelete(&pcb->unSendList, &item->unsendNode);
        FillpFreeBufItem(item);
    }

    loopCount = pcb->unackList.size;
    for (index = 0; index < loopCount; index++) {
        struct Hlist *hashMap = &pcb->unackList.hashMap[index];
        node = HLIST_FIRST(hashMap);
        while (node != FILLP_NULL_PTR) {
            item = FillpPcbEntry(node);
            node = node->next;
            HlistDelete(hashMap, &item->node);
            FillpFreeBufItem(item);
        }
    }

    loopCount = pcb->unrecvList.nodeNum;
    for (index = 0; index < loopCount; index++) {
        item = SkipListPopValue(&pcb->unrecvList);
        FillpFreeBufItem(item);
    }

    loopCount = pcb->redunList.nodeNum;
    for (index = 0; index < loopCount; index++) {
        item = SkipListPopValue(&pcb->redunList);
        FillpFreeBufItem(item);
    }

    FillpFreeSendItemPool(pcb);
}

static void FillpPcbRemoveSend(struct FillpPcb *fpcb)
{
    struct FillpSendPcb *pcb = &fpcb->send;
    FillpPcbFreeSendItemArray(fpcb);

    SpungeFree(pcb->unackList.hashMap, SPUNGE_ALLOC_TYPE_CALLOC);
    pcb->unackList.hashMap = FILLP_NULL_PTR;
    SpungeFree(pcb->pktSeqMap.hashMap, SPUNGE_ALLOC_TYPE_CALLOC);
    pcb->pktSeqMap.hashMap = FILLP_NULL_PTR;
    SkiplistDestroy(&pcb->unrecvList);
    SkiplistDestroy(&pcb->redunList);
    SkiplistDestroy(&pcb->itemWaitTokenLists);
    pcb->itemPool = FILLP_NULL_PTR;
    SpungeFreeUnsendBox(fpcb);

    if (pcb->retryNackQueue != FILLP_NULL_PTR) {
        FILLP_UINT32 i;
        for (i = 0; i < fpcb->statistics.nack.historyNackQueueLen; i++) {
            if (pcb->retryNackQueue[i] != FILLP_NULL_PTR) {
                SpungeFree(pcb->retryNackQueue[i], SPUNGE_ALLOC_TYPE_CALLOC);
                pcb->retryNackQueue[i] = FILLP_NULL_PTR;
            }
        }
        SpungeFree(pcb->retryNackQueue, SPUNGE_ALLOC_TYPE_CALLOC);
        pcb->retryNackQueue = FILLP_NULL_PTR;
    }

    pcb->retryNackQueue = FILLP_NULL_PTR;
    pcb->retryIndex = 0;
#ifdef SOCK_SEND_SEM
    SYS_ARCH_SEM_DESTROY(&pcb->sendSem);
#endif /* SOCK_SEND_SEM */
}

void FillpPcbRemoveTimers(struct FillpPcb *fpcb)
{
    /* Remove if any send/pack timer is running on this socket */
    FillpDisableFinCheckTimer(fpcb);
    FillpDisableSendTimer(fpcb);
    FillpDisablePackTimer(fpcb);
    FillpDisableFcTimer(fpcb);
    FillpDisableKeepAliveTimer(fpcb);
    FillpDisableDelayNackTimer(fpcb);
    FillpDisableDataBurstTimer(fpcb);
}

static void FillpInitPcbTimeNode(struct FillpPcb *pcb)
{
    struct FtSocket *sock = FILLP_GET_SOCKET(pcb);

    FILLP_TIMING_WHEEL_INIT_NODE(&pcb->packTimerNode);
    pcb->packTimerNode.cbNode.cb = FillpPackTimerCb;
    pcb->packTimerNode.cbNode.arg = (void *)pcb;

    FILLP_TIMING_WHEEL_INIT_NODE(&pcb->FcTimerNode);
    pcb->FcTimerNode.cbNode.cb = FillpFcTimerCb;
    pcb->FcTimerNode.cbNode.arg = (void *)pcb;

    FILLP_TIMING_WHEEL_INIT_NODE(&pcb->sendTimerNode);
    pcb->sendTimerNode.cbNode.cb = FillpSendTimerCb;
    pcb->sendTimerNode.cbNode.arg = (void *)pcb;

    FILLP_TIMING_WHEEL_INIT_NODE(&pcb->keepAliveTimerNode);
    pcb->keepAliveTimerNode.cbNode.cb = FillpFcCycle;
    pcb->keepAliveTimerNode.cbNode.arg = (void *)pcb;

    pcb->keepAliveTimerNode.interval = FILLP_UTILS_MS2US(sock->resConf.common.keepAliveTime);

    FILLP_TIMING_WHEEL_INIT_NODE(&pcb->delayNackTimerNode);
    pcb->delayNackTimerNode.cbNode.cb = FillpCheckPcbNackListToSend;
    pcb->delayNackTimerNode.cbNode.arg = (void *)pcb;

    FILLP_TIMING_WHEEL_INIT_NODE(&pcb->dataBurstTimerNode);
    pcb->dataBurstTimerNode.cbNode.cb = SpungePushRecvdDataToStack;
    pcb->dataBurstTimerNode.cbNode.arg = (void *)pcb;

    FILLP_TIMING_WHEEL_INIT_NODE(&pcb->finCheckTimer);
    pcb->finCheckTimer.cbNode.arg = (void *)FILLP_PCB_GET_CONN(pcb);
    pcb->finCheckTimer.cbNode.cb = SpungeCheckDisconn;
    pcb->finCheckTimer.interval = FILLP_WR_DATA_CHECK_INTERVAL;
}

FILLP_INT FillpInitPcb(struct FillpPcb *pcb, FILLP_INT mpSendSize, FILLP_INT mpRecvSize)
{
    pcb->mpSendSize = (FILLP_UINT32)mpSendSize;
    pcb->mpRecvSize = (FILLP_UINT32)mpRecvSize;

    pcb->connReqInputTimestamp = 0;
    pcb->dataNullTimestamp = 0;
    pcb->clientCookiePreserveTime = 0;

    FillpInitPcbTimeNode(pcb);
    pcb->packState = FILLP_PACK_STATE_NORMAL;
    pcb->adhocPackReplied = FILLP_FALSE;

    FillpFrameInit(&pcb->frameHandle);

    HLIST_INIT_NODE(&pcb->sendNode);
    if (FillpInitRecvpcb(pcb) != ERR_OK) {
        FILLP_LOGERR("Failed to init the RecvPCB");
        return ERR_NORES;
    }

    if (FillpInitSendpcb(pcb) != ERR_OK) {
        FILLP_LOGERR("Failed to init the SendPCB");
        FillpPcbRemoveRecv(pcb);
        return ERR_NOBUFS;
    }

    if (FillpFcInit(pcb) != FILLP_OK) {
        FILLP_LOGERR("FillpFcInit failed");
        FillpPcbRemoveRecv(pcb);
        FillpPcbRemoveSend(pcb);
        return ERR_NORES;
    }

    FillpInitStastics(pcb);
    pcb->isFinAckReceived = FILLP_FALSE;
    pcb->resInited = FILLP_TRUE;
    return ERR_OK;
}

void FillpRemovePcb(struct FillpPcb *pcb)
{
    if (!pcb->resInited) {
        return;
    }

    FillpPcbRemoveRecv(pcb);
    FillpPcbRemoveSend(pcb);
    FillpPcbRemoveTimers(pcb);
    FillpFcDeinit(pcb);

    pcb->isFinAckReceived = FILLP_FALSE;
    pcb->resInited = FILLP_FALSE;
}

FILLP_UINT32 FillpGetSendpcbUnackListPktNum(struct FillpSendPcb *pcb)
{
    if (pcb == FILLP_NULL_PTR) {
        return 0;
    }

    return pcb->unackList.count;
}

FILLP_UINT32 FillpGetRecvpcbRecvlistPktNum(struct FillpRecvPcb *pcb)
{
    if (pcb == FILLP_NULL_PTR) {
        return 0;
    }

    return SkiplistGetNodeNum(&(pcb->recvList));
}

FILLP_UINT32 FillpGetSockPackInterval(FILLP_CONST struct FillpPcb *pcb)
{
    FILLP_CONST struct FtSocket *sock = FILLP_GET_SOCKET(pcb);
    return sock->resConf.flowControl.packInterval;
}

#ifdef __cplusplus
}
#endif
