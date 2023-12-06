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

#include "fillp_flow_control.h"
#include "res.h"
#include "spunge_stack.h"
#include "fillp_algorithm.h"
#include "fillp_common.h"
#include "fillp_output.h"
#include "fillp_dfx.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FILLP_RECV_RATE_INDEX_FIRST 0
#define FILLP_RECV_RATE_INDEX_NEXT 1
#define FILLP_RECV_RATE_INDEX_THIRD 2

FILLP_UINT16 FillpAlg2GetRedunCount(void *argPcb, void *argItem)
{
    (void)argPcb;
    (void)argItem;
    return 1;
}

FILLP_UINT16 FillpAlg1GetRedunCount(void *argPcb, void *argItem)
{
    (void)argPcb;
    (void)argItem;
    return 1;
}

static FILLP_BOOL FillpRecvRateIsBigger(struct FillpRateSample *rateSample, FILLP_UINT32 maxCnt,
    FILLP_UINT32 indexK)
{
    FILLP_UINT32 indexN = indexK - 1;
    if (rateSample[indexK].v > rateSample[indexN].v) {
        struct FillpRateSample tmp = rateSample[indexK];
        rateSample[indexK] = rateSample[indexN];
        rateSample[indexN] = tmp;
        return FILLP_TRUE;
    }
    FILLP_UNUSED_PARA(maxCnt);

    return FILLP_FALSE;
}

void FillpUpdateRecvRateSample(struct FillpMaxRateSample *maxRateSample, FILLP_UINT32 rateValue,
    FILLP_UINT8 rateI)
{
    FILLP_UINT32 index;
    FILLP_UINT32 indexK;
    struct FillpRateSample val;
    struct FillpRateSample *rateSample = maxRateSample->rateSample;

    val.i = rateI;
    val.v = rateValue;

    // m->s[] stores few numbers of maximal rates, when do update, if the index is already in s->m[], just resort
    // or , we need to insert a new one
    for (index = 0; index < maxRateSample->maxCnt; index++) {
        if (rateSample[index].i == val.i) {
            break;
        }
    }
    // Now m->s[index] not include pack_index, means we need to update the m->s[]
    if (index >= maxRateSample->maxCnt) {
        for (indexK = 0; indexK < maxRateSample->maxCnt; indexK++) {
            if (val.v > rateSample[indexK].v) {
                struct FillpRateSample tmp = rateSample[indexK];
                rateSample[indexK] = val;
                val = tmp;
            }
        }
        return;
    }

    // Don't need to re-sort the whole list, because the list always be sorted already
    // such as if val.v > m->s[index].v, then just need to update the upper ones
    if (rateSample[index].v > val.v) { // The new value is lighter , then float up
        rateSample[index].v = val.v;

        for (indexK = index; indexK < maxRateSample->maxCnt - 1; indexK++) {
            FILLP_UINT32 indexN = indexK + 1;
            if (rateSample[indexK].v < rateSample[indexN].v) {
                struct FillpRateSample tmp = rateSample[indexK];
                rateSample[indexK] = rateSample[indexN];
                rateSample[indexN] = tmp;
                continue;
            }

            break;
        }
    } else { // The new value is bigger, then sink down
        rateSample[index].v = val.v;

        for (indexK = index; indexK > 0; indexK--) {
            if (FillpRecvRateIsBigger(rateSample, maxRateSample->maxCnt - 1, indexK)) {
                continue;
            }

            break;
        }
    }

    FILLP_LOGDBG("max expired pack_index %u the max is %u the 2ed max is %u the 3th max is %u,recv rate is %u", rateI,
        rateSample[FILLP_RECV_RATE_INDEX_FIRST].v, rateSample[FILLP_RECV_RATE_INDEX_NEXT].v,
        rateSample[FILLP_RECV_RATE_INDEX_THIRD].v, rateValue);
}

FILLP_BOOL FillpAppLimitedStatus(struct FillpPcb *pcb, FILLP_UINT32 beginPktNum, FILLP_UINT32 endPktNum)
{
    struct FillpHashLlist *mapList = &pcb->send.pktSeqMap;
    struct Hlist *list = FILLP_NULL_PTR;
    struct HlistNode *pos = FILLP_NULL_PTR;
    struct FillpPcbItem *item = FILLP_NULL_PTR;
    FILLP_UINT32 i, j;
    FILLP_UINT32 mapLevel;
    FILLP_BOOL appLimited = FILLP_FALSE;

    if (!FillpNumIsbigger(endPktNum, beginPktNum)) {
        return appLimited;
    }

    for (i = beginPktNum, j = 0; !FillpNumIsbigger(i, endPktNum) && j < mapList->count; i++, j++) {
        mapLevel = (FILLP_UINT32)(i & mapList->hashModSize);
        list = &mapList->hashMap[mapLevel];
        pos = HLIST_FIRST(list);
        while (pos != FILLP_NULL_PTR) {
            item = FillpPcbPktSeqMapNodeEntry(pos);
            if (FillpNumIsbigger(item->pktNum, endPktNum)) {
                break;
            }

            if ((!FillpNumIsbigger(beginPktNum, item->pktNum)) &&
                UTILS_FLAGS_CHECK(item->flags, FILLP_ITEM_FLAGS_APP_LIMITED)) {
                appLimited = FILLP_TRUE;
                break;
            }
            pos = pos->next;
        }

        if (appLimited == FILLP_TRUE) {
            break;
        }
    }

    return appLimited;
}

void FillpCalSendInterval(struct FillpPcb *pcb)
{
    struct FillpFlowControl *flowControl = &pcb->send.flowControl;
    struct FtSocket *sock = FILLP_GET_SOCKET(pcb);

    if (sock->resConf.flowControl.constRateEnbale) {
        flowControl->sendRate = sock->resConf.flowControl.maxRate;
    }

    if (flowControl->sendRate == 0) {
        flowControl->sendInterval = FILLP_NULL;
        return;
    }

    /* The rate is calculated based on Kbps, hence multiplied by 8 and 1000 */
    flowControl->sendInterval = (FILLP_LLONG)(pcb->pktSize * FILLP_FC_IN_KBPS * FILLP_FC_IN_BIT);
    /* need round up to avoid sendInterval is smaller */
    flowControl->sendInterval = FILLP_DIV_ROUND_UP(flowControl->sendInterval, (FILLP_LLONG)flowControl->sendRate);
    if (flowControl->sendInterval < FILLP_NULL) {
        flowControl->sendInterval = FILLP_NULL;
    }

    pcb->sendTimerNode.interval = (FILLP_UINT32)(flowControl->sendInterval / FILLP_FC_IN_BIT);
    FILLP_LOGDBG("Send interval %lld, timer_interval:%u", flowControl->sendInterval, pcb->sendTimerNode.interval);
}

void FillpFcTailProtected(struct FillpPcb *pcb, struct FillpPktPack *pack)
{
    struct FillpTailLostProtected *tailProtect = FILLP_NULL_PTR;
    FILLP_LLONG deltaUs;
    FILLP_BOOL isDataWaitedEmpty;
    FILLP_UINT32 infBytes = 0;
    FILLP_UINT32 infCap = 0;

    struct FillpPktHead *pktHdr = (struct FillpPktHead *)pack->head;
    FILLP_UINT32 ackSeqNum = pktHdr->seqNum;
    FILLP_UINT32 lostSeqNum = pack->lostSeq;

    FILLP_UINT32 unackNum = pcb->send.unackList.count;
    FILLP_UINT32 unsendSize =
        pcb->send.unrecvList.nodeNum + pcb->send.itemWaitTokenLists.nodeNum + pcb->send.redunList.nodeNum;
    isDataWaitedEmpty = (unsendSize == 0);

    unsendSize += pcb->send.unSendList.size;
    isDataWaitedEmpty = (unsendSize == 0) && (SpungeConnCheckUnsendBoxEmpty(FILLP_GET_CONN(pcb)) == FILLP_TRUE);

    deltaUs = pcb->pcbInst->curTime - pcb->send.lastSendTs;

    /* ackSeqNum equal to lostSeqNum, peer doesn't recv valid packet which can be give to app */
    tailProtect = &pcb->send.tailProtect;
    if ((ackSeqNum == lostSeqNum) && (ackSeqNum == tailProtect->lastPackSeq) && (unackNum != 0) &&
        (pack->rate == 0) && isDataWaitedEmpty && (pcb->statistics.debugPcb.curPackDeltaUs != 0) &&
        (deltaUs >= pcb->statistics.pack.packIntervalBackup)) {
        tailProtect->samePackCount++;
        if (tailProtect->samePackCount >= tailProtect->judgeThreshold) {
            FILLP_LOGDTL("fillp_sock_id:%d tail protection active,Threshold:%u,infBytes:%u,"
                         "infCap:%u,unSendList:%u,unackList:%u, ackSeqNum%u",
                         FILLP_GET_SOCKET(pcb)->index, tailProtect->judgeThreshold, infBytes, infCap,
                         pcb->send.unSendList.size, pcb->send.unackList.count, ackSeqNum);
            FillpMoveUnackToUnrecv(ackSeqNum, pcb->send.seqNum, pcb, FILLP_FALSE);
            tailProtect->judgeThreshold = tailProtect->maxJudgeThreshold;
            tailProtect->samePackCount = FILLP_NULL;
        }
    } else {
        pcb->send.tailProtect.judgeThreshold = tailProtect->minJudgeThreshold;
        pcb->send.tailProtect.samePackCount = FILLP_NULL;
        pcb->send.tailProtect.lastPackSeq = ackSeqNum;
    }
}

void FillpFcPackInput(struct FillpPcb *pcb, struct FillpPktPack *pack)
{
    if (pcb->algFuncs.analysisPack != FILLP_NULL_PTR) {
        pcb->algFuncs.analysisPack(pcb, (void *)pack);
    }

    if (!(pack->flag & FILLP_PACK_FLAG_REQURE_RTT)) {
        FillpFcTailProtected(pcb, pack);
    }
}

void FillpFcNackInput(struct FillpPcb *pcb, struct FillpPktNack *nack)
{
    if (pcb->algFuncs.analysisNack != FILLP_NULL_PTR) {
        pcb->algFuncs.analysisNack(pcb, (void *)nack);
    }
}

static int FillpGetAlgFun(struct FillpPcb *pcb)
{
    switch (pcb->fcAlg) {
        case FILLP_SUPPORT_ALG_BASE:
            pcb->algFuncs = g_fillpAlg0;
            break;
        case FILLP_SUPPORT_ALG_3:
            pcb->algFuncs = g_fillpAlg0;
            break;
        default:
            FILLP_LOGERR("flow control not set");
            return -1;
    }
    return 0;
}

FILLP_INT FillpFcInit(struct FillpPcb *pcb)
{
    FILLP_INT ret = ERR_OK;

    if (pcb == FILLP_NULL_PTR) {
        FILLP_LOGERR("pcb null");
        return -1;
    }

    if (pcb->send.slowStart) {
        /* Sender interval, be used to control the sending rate kbits/s */
        pcb->send.flowControl.sendRate = FILLP_INITIAL_RATE;
        FILLP_LOGDBG("slowStart:%u init_rate:%u", pcb->send.slowStart, pcb->send.flowControl.sendRate);
    } else {
        /* The maxRate configured by the user is in Mbps, hence multiplied by
              100 to get the value in Kbps */
        pcb->send.flowControl.sendRate = g_resource.flowControl.maxRate;
        FILLP_LOGDBG("slowStart not enabled, init_rate:%u", pcb->send.flowControl.sendRate);
    }

    pcb->send.flowControl.sendTime = 0;
    pcb->send.flowControl.sendRateLimit = 0;
    pcb->send.flowControl.remainBytes = 0;
    pcb->send.flowControl.lastCycleNoEnoughData = FILLP_FALSE;
    pcb->send.flowControl.sendOneNoData = FILLP_TRUE;

    pcb->send.tailProtect.lastPackSeq = 0;
    pcb->send.tailProtect.samePackCount = 0;

    pcb->statistics.keepAlive.lastRecvTime = pcb->pcbInst->curTime;
    pcb->statistics.keepAlive.lastDataRecvTime = pcb->pcbInst->curTime;

    pcb->send.flowControl.fcAlg = FILLP_NULL_PTR;
    FILLP_LOGERR("fillp_sock_id:%d, fc alg:%xh, characters:%xh, peer_alg:%xh, peerCharacters:%xh",
        FILLP_GET_SOCKET(pcb)->index, pcb->fcAlg, pcb->characters, FILLP_GET_CONN(pcb)->peerFcAlgs,
        FILLP_GET_CONN(pcb)->peerCharacters);
    if (FillpGetAlgFun(pcb) != 0) {
        return -1;
    }

    FillpAdjustFcParamsByRtt(pcb);

    if (pcb->algFuncs.fcInit != FILLP_NULL_PTR) {
        ret = pcb->algFuncs.fcInit(pcb);
    }

    return ret;
}

void FillpFcDeinit(struct FillpPcb *pcb)
{
    if (pcb->algFuncs.fcDeinit != FILLP_NULL_PTR) {
        pcb->algFuncs.fcDeinit(pcb);
    }
    pcb->send.flowControl.fcAlg = FILLP_NULL_PTR;
}

/* recv a data packet  */
void FillpFcDataInput(struct FillpPcb *pcb, FILLP_CONST struct FillpPktHead *pkt)
{
    pcb->statistics.traffic.totalRecved++;

    if (pcb->statistics.traffic.totalRecved == 1) {
        FILLP_LOGDBG("fillp_sock_id:%d "
                     "First data receiving time =%lld, recv seq num = %u, recv pkt num = %u \r\n",
            FILLP_GET_SOCKET(pcb)->index, pcb->pcbInst->curTime, pcb->recv.seqNum, pcb->recv.pktNum);
    }

    pcb->statistics.traffic.totalRecvedBytes += ((FILLP_UINT32)pkt->dataLen);
    pcb->statistics.pack.periodRecvedOnes++;
    pcb->statistics.pack.periodRecvBits += FILLP_FC_VAL_IN_BITS((FILLP_ULLONG)pkt->dataLen);
}

/* discard a data packet */
void FillpFcRecvDropOne(struct FillpPcb *pcb)
{
    pcb->statistics.pack.periodDroped++;
    pcb->statistics.traffic.totalDroped++;
}

/* recv an packet outof order */
void FillpFcRecvOutOfOrder(struct FillpPcb *pcb)
{
    pcb->statistics.traffic.totalOutOfOrder++;
}

/* calculate the lost packets on recv side */
void FillpFcRecvLost(struct FillpPcb *pcb, FILLP_UINT32 ones)
{
    pcb->statistics.traffic.totalRecvLost += ones;
}

void FillpFcCycle(void *arg)
{
    struct FillpPcb *pcb = (struct FillpPcb *)arg;
    /* The unit of the time returned here is micro seconds */
    FILLP_LLONG detaTime;
    struct FtNetconn *netconn = FILLP_GET_CONN(pcb);
    struct FtSocket *sock;

    sock = (struct FtSocket *)netconn->sock;

    if (sock->isListenSock) {
        FILLP_LOGERR("Listen socket should not hit here!!!");
        return;
    }

    detaTime = pcb->pcbInst->curTime - pcb->statistics.keepAlive.lastRecvTime;

    if (detaTime >= (FILLP_LLONG)FILLP_UTILS_MS2US((FILLP_LLONG)sock->resConf.common.keepAliveTime)) {
        FILLP_LOGERR("Keep alive timeout, fillp_sock_id:%d,detaTime:%lld,keepAliveTime:%u(ms)",
            sock->index, detaTime, sock->resConf.common.keepAliveTime);

        FillpDfxSockLinkAndQosNotify(sock, FILLP_DFX_LINK_KEEPALIVE_TIMEOUT);
        SpungeShutdownSock(sock, SPUNGE_SHUT_RDWR);
        sock->errEvent |= SPUNGE_EPOLLERR;
        SpungeEpollEventCallback(sock, (FILLP_INT)SPUNGE_EPOLLIN | (FILLP_INT)SPUNGE_EPOLLERR, 1);
        SpungeConnClosed(FILLP_GET_CONN(pcb));
        return;
    }

    pcb->keepAliveTimerNode.interval =
        (FILLP_UINT32)(FILLP_UTILS_MS2US((FILLP_LLONG)sock->resConf.common.keepAliveTime) - detaTime);
    FILLP_LOGDTL("update the keep alive interval to %u, fillp_sock_id:%d, detaTime:%lld, keepAliveTime:%u(ms)",
        pcb->keepAliveTimerNode.interval, sock->index, detaTime, sock->resConf.common.keepAliveTime);
    FillpEnableKeepAliveTimer(pcb);
}

#ifdef __cplusplus
}
#endif
