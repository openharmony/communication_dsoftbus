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

#include "fillp_flow_control_alg0.h"
#include "res.h"
#include "fillp_algorithm.h"
#include "fillp_common.h"
#include "fillp_output.h"

#ifdef FILLP_SUPPORT_GSO
#include "check_gso_support.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

void FillpAlg0CalSendInterval(struct FillpPcb *pcb)
{
    struct FillpFlowControl *flowControl = &pcb->send.flowControl;
    struct FillpFlowControlAlg0 *alg = (struct FillpFlowControlAlg0 *)flowControl->fcAlg;
    FILLP_UINT32 minRate = FILLP_FC0_DEFAULT_RATE;

    if (flowControl->sendRate < minRate) {
        flowControl->sendRate = minRate;
    } else if (flowControl->sendRate > alg->maxRateAllowed) {
        flowControl->sendRate = alg->maxRateAllowed;
    }

    FillpCalSendInterval(pcb);
}

static void FillpAlg0UpdateMaxRecvRate(struct FillpFlowControlAlg0 *alg, FILLP_UINT32 recvRate)
{
    FillpUpdateRecvRateSample(&alg->historyMaxRecvRate, recvRate, alg->historyMaxRecvRateIndex);
    alg->historyMaxRecvRateIndex = alg->historyMaxRecvRateIndex + 1;
    alg->historyMaxRecvRateIndex %= FILLP_FC0_PROBE_HISTORY_PACK_MAX_RATE_NUM;
}

static void FillpAlg0FlowControlInit(struct FillpPcb *pcb, struct FillpFlowControlAlg0 *alg)
{
    FILLP_UINT32 i;
    alg->flowControl = &pcb->send.flowControl;
    alg->fcState = FILLP_FC0_STATE_INIT;

    alg->historyMaxRecvRate.maxCnt = FILLP_FC0_PROBE_HISTORY_PACK_MAX_RATE_NUM;
    alg->historyMaxRecvRateIndex = 0;

    for (i = 0; i < FILLP_FC0_PROBE_HISTORY_PACK_MAX_RATE_NUM; i++) {
        alg->historyMaxRecvRate.rateSample[i].i = (FILLP_UINT8)i;
        alg->historyMaxRecvRate.rateSample[i].v = 0;
    }

    alg->maxRecvRate = 0;
    alg->maxRateAllowed = FILLP_GET_SOCKET(pcb)->resConf.flowControl.maxRate;

    alg->sendRateIncreaseGainIndex = 0;

    alg->packDeltaUsArrayIndex = 0;
    for (i = 0; i < FILLP_FC0_PACK_RECV_INTERVAL_SAMPLE_NUM; i++) {
        alg->packDeltaUsArray[i] = 0;
    }
    alg->historyMaxRecvRate.rateSample[0].v = FILLP_DEFAULT_INITIAL_RATE;
}

FILLP_INT FillpAlg0FcInit(void *argPcb)
{
    struct FillpPcb *pcb = (struct FillpPcb *)argPcb;
    struct FillpFlowControlAlg0 *alg = FILLP_NULL_PTR;

    if (SockUpdatePktDataOpt(FILLP_GET_SOCKET(pcb), FILLP_OPT_FLAG_TIMESTAMP, 0) != ERR_OK) {
        return -1;
    }

    alg = SpungeAlloc(1, sizeof(struct FillpFlowControlAlg0), SPUNGE_ALLOC_TYPE_CALLOC);
    if (alg == FILLP_NULL_PTR) {
        return -1;
    }

    alg->historyMaxRecvRate.rateSample = SpungeAlloc(FILLP_FC0_PROBE_HISTORY_PACK_MAX_RATE_NUM,
        sizeof(struct FillpRateSample), SPUNGE_ALLOC_TYPE_MALLOC);
    if (alg->historyMaxRecvRate.rateSample == FILLP_NULL_PTR) {
        SpungeFree(alg, SPUNGE_ALLOC_TYPE_CALLOC);
        FILLP_LOGERR("fillp to alloc historyMaxRecvRate.rateSample");
        return -1;
    }

    FillpAlg0FlowControlInit(pcb, alg);
    pcb->send.flowControl.fcAlg = alg;
    pcb->lastCalcTime = 0;

    /* in INIT state, tail protect judge threshold should be large than one RTT */
    pcb->send.tailProtect.judgeThreshold = FILLP_ONE_FIFTH_OF_RTT;
    pcb->send.retramistRto = (FILLP_ULLONG)pcb->rtt;
    pcb->send.flowControl.sendRate = FILLP_FC0_DEFAULT_RATE;

    FillpAlg0CalSendInterval(pcb);
#ifdef FILLP_SUPPORT_GSO
    CheckGSOSupport();
#endif

    return 0;
}

void FillpAlg0FcDeinit(void *argPcb)
{
    struct FillpPcb *pcb = (struct FillpPcb *)argPcb;
    struct FillpFlowControlAlg0 *alg = (struct FillpFlowControlAlg0 *)pcb->send.flowControl.fcAlg;

    if (pcb->send.flowControl.fcAlg == FILLP_NULL_PTR) {
        return;
    }

    if (alg->historyMaxRecvRate.rateSample != FILLP_NULL_PTR) {
        SpungeFree(alg->historyMaxRecvRate.rateSample, SPUNGE_ALLOC_TYPE_CALLOC);
        alg->historyMaxRecvRate.rateSample = FILLP_NULL_PTR;
    }

    SpungeFree(alg, SPUNGE_ALLOC_TYPE_CALLOC);
    pcb->send.flowControl.fcAlg = FILLP_NULL_PTR;
}

void FillpAlg0CalPackInterval(void *argPcb)
{
    struct FillpPcb *pcb = (struct FillpPcb *)argPcb;
    FILLP_UINT32 packInterval = FillpGetSockPackInterval(pcb);
    pcb->statistics.pack.packInterval = packInterval;
}

static void FillpAlg0CalMaxPackRcvInterval(struct FillpPcb *pcb, FILLP_LLONG detaUs, FILLP_UINT32 packRate,
    FILLP_UINT32 periodSendRate)
{
    struct FillpFlowControlAlg0 *alg = (struct FillpFlowControlAlg0 *)pcb->send.flowControl.fcAlg;

    pcb->statistics.debugPcb.curPackDeltaUs = detaUs;
    pcb->statistics.pack.periodAckByPackRate = packRate;
    pcb->statistics.pack.periodSendRate = periodSendRate;

    alg->packDeltaUsArrayIndex++;
    alg->packDeltaUsArrayIndex %= FILLP_FC0_PACK_RECV_INTERVAL_SAMPLE_NUM;
    alg->packDeltaUsArray[alg->packDeltaUsArrayIndex] = (FILLP_UINT32)((FILLP_ULONG)detaUs);
}

static void FillpAlg0FcHandleInit(struct FillpPcb *pcb, FILLP_CONST struct FillpPktPack *pack)
{
    struct FillpFlowControl *flowControl = &pcb->send.flowControl;
    struct FillpFlowControlAlg0 *alg = (struct FillpFlowControlAlg0 *)flowControl->fcAlg;
    FILLP_UINT32 baseSendRate;

    /* fc state keeps in INIT state until socket start send data */
    if (pcb->statistics.traffic.totalSend == 0) {
        return;
    }

    /* in INIT state, tail protect judge threshold should be large than one RTT */
    pcb->send.tailProtect.judgeThreshold = FILLP_ONE_FIFTH_OF_RTT;
    alg->sendRateIncreaseGainIndex++;
    if ((alg->sendRateIncreaseGainIndex < FILLP_FC_RTT_PACK_RATIO) && (pack->rate == 0)) {
        /* In send rate increase period and recv rate getting nothing currently */
        return;
    }

    alg->maxRecvRate = pack->rate;
    alg->historyMaxRecvRate.rateSample[0].v = pack->rate;
    alg->historyMaxRecvRate.rateSample[0].i = 0;

    baseSendRate = UTILS_MAX(alg->maxRecvRate, FILLP_FC0_DEFAULT_RATE);
    flowControl->sendRate = baseSendRate;
    FillpAlg0CalSendInterval(pcb);

    pcb->send.tailProtect.judgeThreshold = pcb->send.tailProtect.minJudgeThreshold;
    alg->fcState = FILLP_FC0_STATE_BW_PROBE;
    FILLP_LOGDTL("fillp_sock_id:%d, fcState INIT -> BW_PROBE, maxRate:%u, sendRateIncreaseGainIndex:%hhu",
        FILLP_GET_SOCKET(pcb)->index, alg->maxRecvRate, alg->sendRateIncreaseGainIndex);
}

static void FillpAlg0FcHandleBwProbe(struct FillpPcb *pcb, FILLP_CONST struct FillpPktPack *pack)
{
    struct FillpFlowControl *flowControl = &pcb->send.flowControl;
    struct FillpFlowControlAlg0 *alg = (struct FillpFlowControlAlg0 *)flowControl->fcAlg;
    struct FillpRateSample *historyMaxRecvRate = alg->historyMaxRecvRate.rateSample;
    FILLP_UINT32 baseSendRate;
    FILLP_UINT32 recvRate = pack->rate;

    recvRate = UTILS_MAX(recvRate, FILLP_FC0_DEFAULT_RATE);

    FillpAlg0UpdateMaxRecvRate(alg, recvRate);
    baseSendRate = historyMaxRecvRate[0].v;
    flowControl->sendRate = baseSendRate;

    FillpAlg0CalSendInterval(pcb);
}

static void FillpAlg0PackStateProcess(struct FillpPcb *pcb, struct FillpPktPack *pack)
{
    struct FillpFlowControl *flowControl = &pcb->send.flowControl;
    struct FillpFlowControlAlg0 *alg = (struct FillpFlowControlAlg0 *)flowControl->fcAlg;
    FILLP_UINT32 maxRateAllowed;
    struct FtSocket *sock = FILLP_GET_SOCKET(pcb);

    /* Update the allowed max rate */
    maxRateAllowed = FILLP_GET_SOCKET(pcb)->resConf.flowControl.maxRate;
    if (pack->oppositeSetRate && (pack->flag & FILLP_PACK_FLAG_WITH_RATE_LIMIT) &&
        (pack->oppositeSetRate < maxRateAllowed)) {
        alg->maxRateAllowed = pack->oppositeSetRate;
    } else {
        alg->maxRateAllowed = maxRateAllowed;
    }

    switch (alg->fcState) {
        case FILLP_FC0_STATE_INIT:
            FillpAlg0FcHandleInit(pcb, pack);
            break;
        case FILLP_FC0_STATE_BW_PROBE:
            FillpAlg0FcHandleBwProbe(pcb, pack);
            break;
        default:
            FILLP_LOGDTL("fillp_sock_id:%d fcState:%u wrong", sock->index, alg->fcState);
            break;
    }
}

void FillpAlg0AnalysePack(void *argPcb, FILLP_CONST void *argPack)
{
    struct FillpPcb *pcb = (struct FillpPcb *)argPcb;
    struct FillpPktPack *pack = (struct FillpPktPack *)argPack;
    FILLP_LLONG detaUs;

    FILLP_UINT32 periodSendRate; /* Kbps */

    detaUs = pcb->pcbInst->curTime - pcb->statistics.debugPcb.packRecvedTimeInterval;
    if (detaUs == 0) {
        periodSendRate = 0;
    } else {
        double rate = (double)pcb->statistics.debugPcb.packIntervalSendBytes * FILLP_FC_IN_BIT;
        rate *= FILLP_BPS_TO_KBPS;
        rate /= detaUs;
        periodSendRate = (FILLP_UINT32)rate;
    }

    FillpAlg0CalMaxPackRcvInterval(pcb, detaUs, pack->rate, periodSendRate);

    pcb->statistics.debugPcb.packRecvedTimeInterval = pcb->pcbInst->curTime;
    pcb->statistics.debugPcb.packIntervalSendBytes = FILLP_NULL;
    pcb->statistics.debugPcb.packIntervalSendPkt = FILLP_NULL;

    FillpAlg0PackStateProcess(pcb, pack);
}

#ifdef __cplusplus
}
#endif
