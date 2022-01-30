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
#include "fillp_output.h"
#include "opt.h"

#define FILLP_FRAME_INTVL_MIN_INDEX(len) ((FILLP_UINT16)((((FILLP_UINT32)(len)) * 5) / 100))
#define FILLP_FRAME_INTVL_MAX_INDEX(len) ((FILLP_UINT16)((((FILLP_UINT32)(len)) * 95) / 100))
#define FILLP_UNLIMIT_SEND_INTERVAL 100 /* try to send every 100us */

#ifdef __cplusplus
extern "C" {
#endif

static void FillpEnablePackTimerInCb(struct FillpPcb *pcb, FILLP_BOOL enNormalPackTimer)
{
    (void)enNormalPackTimer;
    FillpEnablePackTimer(pcb);
}

static void LogFcFcAppStastics(const struct FillpPcb *pcb, const struct FillAppFcStastics *appFcStastics)
{
    FILLP_LOGDBG("fillp_sock_id:%d periodRtt:<%u>, periodRecvRate: <%u, %llu>, periodRecvPktLoss: <%u, %u>, "
        "periodSendRate: <%llu>, period_send_pkt_loss: %u",
        FILLP_GET_SOCKET(pcb)->index, appFcStastics->periodRtt, appFcStastics->periodRecvRate,
        appFcStastics->periodRecvRateBps, appFcStastics->periodRecvPktLoss,
        appFcStastics->periodRecvPktLossHighPrecision, appFcStastics->periodSendRateBps,
        appFcStastics->periodSendPktLossHighPrecision);
}

static void FillpCalFcAppStastics(struct FillpPcb *pcb)
{
    struct FtSocket *sock = FILLP_GET_SOCKET(pcb);
    struct FillpPackStastics *packStastics = &pcb->statistics.pack;
    struct FillAppFcStastics *appFcStastics = &pcb->statistics.appFcStastics;

    appFcStastics->periodTimePassed += packStastics->packTimePassed;
    appFcStastics->periodRecvBits += (FILLP_LLONG)packStastics->periodRecvBits;
    appFcStastics->periodRecvPkts += packStastics->periodRecvedOnes;

    if (appFcStastics->periodTimePassed < (FILLP_LLONG)(sock->resConf.common.fcStasticsInterval)) {
        return;
    }

    FILLP_UINT32 pktData = pcb->recv.pktNum - appFcStastics->pktNum;
    if (pktData == 0) {
        appFcStastics->periodRecvPktLossHighPrecision = 0;
    } else if (pktData >= appFcStastics->periodRecvPkts) {
        appFcStastics->periodRecvPktLossHighPrecision = (pktData - appFcStastics->periodRecvPkts) *
            FILLP_RECV_PKT_LOSS_H_PERCISION * FILLP_RECV_PKT_LOSS_MAX / pktData;
    } else {
        appFcStastics->periodRecvPktLossHighPrecision = 0;
        FILLP_LOGINF("fillp_sock_id:%d, recv_pkt_num:%u, pre_pkt_num:%u, periodRecvPkts:%u",
            FILLP_GET_SOCKET(pcb)->index, pcb->recv.pktNum, appFcStastics->pktNum,
            appFcStastics->periodRecvPkts);
    }
    appFcStastics->periodRecvPktLoss =
        appFcStastics->periodRecvPktLossHighPrecision / (FILLP_UINT32)FILLP_RECV_PKT_LOSS_H_PERCISION;

    /* bits num / (us / 1,000,000) equal to (bits num * 1,000,000) / us */
    appFcStastics->periodRecvRateBps =
        (FILLP_ULLONG)(((FILLP_ULLONG)appFcStastics->periodRecvBits * FILLP_UTILS_MS2US(FILLP_ONE_SECOND)) /
        (FILLP_ULLONG)appFcStastics->periodTimePassed);
    appFcStastics->periodRecvRate = (FILLP_UINT32)FILLP_UTILS_BPS2KBPS(appFcStastics->periodRecvRateBps);

    if ((appFcStastics->periodSendPkts == 0) ||
        (appFcStastics->periodSendPkts < appFcStastics->periodSendLostPkts)) {
        appFcStastics->periodSendPktLossHighPrecision = 0;
    } else {
        appFcStastics->periodSendPktLossHighPrecision = appFcStastics->periodSendLostPkts *
            FILLP_RECV_PKT_LOSS_H_PERCISION * FILLP_RECV_PKT_LOSS_MAX / appFcStastics->periodSendPkts;
    }

    appFcStastics->periodSendRateBps =
        (FILLP_ULLONG)((appFcStastics->periodSendBits * FILLP_UTILS_MS2US(FILLP_ONE_SECOND)) /
        (FILLP_ULLONG)appFcStastics->periodTimePassed);

    appFcStastics->periodTimePassed = 0;
    appFcStastics->periodRecvBits = 0;
    appFcStastics->periodRecvPkts = 0;
    appFcStastics->pktNum = pcb->recv.pktNum;
    appFcStastics->periodSendLostPkts = 0;
    appFcStastics->periodSendPkts = 0;
    appFcStastics->periodSendBits = 0;
    LogFcFcAppStastics(pcb, appFcStastics);
}

static void FillpCalRecvRate(struct FillpPcb *pcb)
{
    struct FillpPackStastics *packStastics = &pcb->statistics.pack;
    FILLP_UINT32 recvRate;

    /* Cal Pkt loss and rate */
    FILLP_UINT32 pktData = pcb->recv.pktNum - packStastics->packPktNum;
    if (pktData == 0) {
        packStastics->periodRecvPktLoss = 0;
    } else {
        if (pktData <= packStastics->periodRecvedOnes) {
            packStastics->periodRecvPktLoss = 0;
        } else {
            packStastics->periodRecvPktLoss = (FILLP_UINT16)(
                (FILLP_ULLONG)(pktData - packStastics->periodRecvedOnes) * FILLP_RECV_PKT_LOSS_MAX / pktData);
        }
    }
    /*  kbps  */
    recvRate = (FILLP_UINT32)((packStastics->periodRecvBits * FILLP_ONE_SECOND) /
        (FILLP_ULLONG)packStastics->packTimePassed);
    packStastics->periodRecvRate = (packStastics->lastPackRecvRate + recvRate) >> 1;
    packStastics->lastPackRecvRate = recvRate;

    if (packStastics->maxRecvRate < packStastics->periodRecvRate) {
        packStastics->maxRecvRate = packStastics->periodRecvRate;
    }
    FILLP_LOGDBG("fillp_sock_id:%d nackSend: %u nackFailed: %u nackRcv: %u "
                 "packSend: %u packFailed: %u packRcv: %u nackPktNum: %u "
                 "totalSendBytes: %u packIntervalSendPkt: %u "
                 "total_recvd_count: %u recv rate: %u pack input interval: %lld",
                 FILLP_GET_SOCKET(pcb)->index, pcb->statistics.debugPcb.nackSend,
                 pcb->statistics.debugPcb.nackFailed, pcb->statistics.debugPcb.nackRcv,
                 pcb->statistics.debugPcb.packSend, pcb->statistics.debugPcb.packFailed,
                 pcb->statistics.debugPcb.packRcv, pcb->statistics.debugPcb.nackPktNum,
                 pcb->statistics.traffic.totalSendBytes, pcb->statistics.debugPcb.packIntervalSendPkt,
                 pcb->statistics.traffic.totalRecved, pcb->statistics.pack.periodRecvRate,
                 pcb->statistics.debugPcb.packRecvedTimeInterval);

    FILLP_LOGDBG("fillp_sock_id:%d periodRecvRate: %u, maxRecvRate: %u \n", FILLP_GET_SOCKET(pcb)->index,
        packStastics->periodRecvRate, packStastics->maxRecvRate);

    pcb->recv.prePackPktNum = packStastics->packPktNum;
    packStastics->packPktNum = pcb->recv.pktNum;
    packStastics->periodRecvBits = 0;
    packStastics->periodRecvedOnes = 0;
}

void FillpPackTimerCb(void *argPcb)
{
    struct FillpPcb *pcb = (struct FillpPcb *)argPcb;
    struct FtSocket *sock = FILLP_GET_SOCKET(pcb);
    struct FillpPackStastics *pack = &pcb->statistics.pack;
    FILLP_BOOL enableNormalTimer;
    FILLP_LLONG curTime = SYS_ARCH_GET_CUR_TIME_LONGLONG();

    pack->packTimePassed = curTime - pack->packSendTime;
    pack->packSendTime = curTime;

    FILLP_LOGDBG("pack fire time =%lld", pcb->pcbInst->curTime);
    FillpCalFcAppStastics(pcb);
    FillpCalRecvRate(pcb);
    FillpUploadRecvBox(pcb);

    if (pcb->algFuncs.packTimer != FILLP_NULL_PTR) {
        pcb->algFuncs.packTimer(pcb);
    }

    enableNormalTimer = FillpSendPackWithPcbBuffer(pcb);
    if (enableNormalTimer &&
        (curTime - pack->packRttDetectTime) > (FILLP_LLONG)(sock->resConf.common.fcStasticsInterval)) {
        FillpSendAdhocpackToDetectRtt(pcb);
        pack->packRttDetectTime = curTime;
    }

    pack->packSendTime = pcb->pcbInst->curTime;
    FillpEnablePackTimerInCb(pcb, enableNormalTimer);
}

void FillpSendTimerCb(void *argPcb)
{
    struct FillpPcb *pcb = (struct FillpPcb *)argPcb;
    struct FillpFlowControl *flowControl = &pcb->send.flowControl;
    FILLP_LLONG detaTime = (FILLP_LLONG)(pcb->pcbInst->curTime - flowControl->sendTime);
    FILLP_LLONG realDetaTime = (FILLP_LLONG)((FILLP_ULLONG)detaTime << FILLP_TIME_PRECISION);

    FILLP_LOGDBG("cur %lld, deta_time:%lld, send_interval:%lld",
        pcb->pcbInst->curTime, realDetaTime, flowControl->sendInterval);
    if (realDetaTime >= flowControl->sendInterval) {
        SpungeDoSendCycle((struct SpungePcb *)pcb->spcb, pcb->pcbInst, realDetaTime);
    } else {
        FillpEnableSendTimer(pcb);
    }
}

void FillpEnableSendTimer(struct FillpPcb *pcb)
{
    if (pcb->send.flowControl.sendInterval < pcb->pcbInst->minSendInterval) {
        pcb->pcbInst->minSendInterval = pcb->send.flowControl.sendInterval;
    }
    if (FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&pcb->sendTimerNode)) {
        return;
    }
    FILLP_LOGDBG("enable, pcb->send.flowControl.sendTime:%lld, interval:%u", pcb->send.flowControl.sendTime,
        pcb->sendTimerNode.interval);
    if (pcb->send.flowControl.sendTime == 0) {
        pcb->send.flowControl.remainBytes = 0;
        pcb->send.flowControl.sendTime = pcb->pcbInst->curTime;
    }
    FILLP_LOGDBG("enable time =%lld\t next expire timer=%lld", pcb->pcbInst->curTime,
        pcb->send.flowControl.sendTime + pcb->sendTimerNode.interval);
    FillpTimingWheelAddTimer(&pcb->pcbInst->timingWheel,
        pcb->send.flowControl.sendTime + pcb->sendTimerNode.interval, &pcb->sendTimerNode);
}

void FillpDisableSendTimer(struct FillpPcb *pcb)
{
    if (FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&pcb->sendTimerNode)) {
        FillpTimingWheelDelTimer(pcb->sendTimerNode.wheel, &pcb->sendTimerNode);
    }
}

void FillpEnablePackTimer(struct FillpPcb *pcb)
{
    if (!FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&pcb->packTimerNode)) {
        FILLP_LOGDBG("enable time =%lld\t next expire timer=%u", pcb->pcbInst->curTime,
            pcb->packTimerNode.interval);
        FillpTimingWheelAddTimer(&pcb->pcbInst->timingWheel,
            pcb->packTimerNode.interval + pcb->pcbInst->curTime, &pcb->packTimerNode);
    }
}

void FillpDisablePackTimer(struct FillpPcb *pcb)
{
    if (FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&pcb->packTimerNode)) {
        FillpTimingWheelDelTimer(pcb->packTimerNode.wheel, &pcb->packTimerNode);
    }
}

void FillpEnableFcTimer(struct FillpPcb *pcb)
{
    if (!FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&pcb->FcTimerNode)) {
        FillpTimingWheelAddTimer(&pcb->pcbInst->timingWheel,
            pcb->FcTimerNode.interval + pcb->pcbInst->curTime, &pcb->FcTimerNode);
    }
}
void FillpDisableFcTimer(struct FillpPcb *pcb)
{
    if (FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&pcb->FcTimerNode)) {
        FillpTimingWheelDelTimer(pcb->FcTimerNode.wheel, &pcb->FcTimerNode);
    }
}

void FillpEnableKeepAliveTimer(struct FillpPcb *pcb)
{
    if (!FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&pcb->keepAliveTimerNode)) {
        FillpTimingWheelAddTimer(&pcb->pcbInst->timingWheel,
            pcb->keepAliveTimerNode.interval + pcb->pcbInst->curTime, &pcb->keepAliveTimerNode);
    }
}

void FillpDisableKeepAliveTimer(struct FillpPcb *pcb)
{
    if (FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&pcb->keepAliveTimerNode)) {
        FillpTimingWheelDelTimer(pcb->keepAliveTimerNode.wheel, &pcb->keepAliveTimerNode);
    }
}

void FillpEnableDelayNackTimer(struct FillpPcb *pcb)
{
    if (!FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&pcb->delayNackTimerNode)) {
        FILLP_LOGDBG("Delay NACK Timer Enable: curTime:%lld, interval:%u", pcb->pcbInst->curTime,
            pcb->delayNackTimerNode.interval);
        FillpTimingWheelAddTimer(&pcb->pcbInst->timingWheel,
            pcb->pcbInst->curTime + pcb->delayNackTimerNode.interval, &pcb->delayNackTimerNode);
    }
}

void FillpDisableDelayNackTimer(struct FillpPcb *pcb)
{
    if (FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&pcb->delayNackTimerNode)) {
        FillpTimingWheelDelTimer(pcb->delayNackTimerNode.wheel, &pcb->delayNackTimerNode);
    }
}

void FillpEnableDataBurstTimer(struct FillpPcb *pcb)
{
    if (!FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&pcb->dataBurstTimerNode)) {
        FILLP_LOGDBG("Data Burst Timer Enable: curTime:%lld, interval:%u", pcb->pcbInst->curTime,
            pcb->dataBurstTimerNode.interval);
        FillpTimingWheelAddTimer(&pcb->pcbInst->timingWheel,
            pcb->pcbInst->curTime + pcb->dataBurstTimerNode.interval, &pcb->dataBurstTimerNode);
    }
}
void FillpDisableDataBurstTimer(struct FillpPcb *pcb)
{
    if (FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&pcb->dataBurstTimerNode)) {
        FillpTimingWheelDelTimer(pcb->dataBurstTimerNode.wheel, &pcb->dataBurstTimerNode);
    }
}

void FillpEnableConnRetryCheckTimer(struct FillpPcb *pcb)
{
    if (!FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&pcb->connRetryTimeoutTimerNode)) {
        FillpTimingWheelAddTimer(&pcb->pcbInst->timingWheel,
            pcb->pcbInst->curTime + pcb->connRetryTimeoutTimerNode.interval, &pcb->connRetryTimeoutTimerNode);
    }
}
void FillpDisableConnRetryCheckTimer(struct FillpPcb *pcb)
{
    if (FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&pcb->connRetryTimeoutTimerNode)) {
        FillpTimingWheelDelTimer(pcb->connRetryTimeoutTimerNode.wheel, &pcb->connRetryTimeoutTimerNode);
    }
}

void FillpEnableFinCheckTimer(struct FillpPcb *pcb)
{
    if (!FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&pcb->finCheckTimer)) {
        FillpTimingWheelAddTimer(&pcb->pcbInst->timingWheel,
            pcb->pcbInst->curTime + pcb->finCheckTimer.interval, &pcb->finCheckTimer);
    }
}

void FillpDisableFinCheckTimer(struct FillpPcb *pcb)
{
    if (FILLP_TIMING_WHEEL_IS_NODE_ENABLED(&pcb->finCheckTimer)) {
        FillpTimingWheelDelTimer(pcb->finCheckTimer.wheel, &pcb->finCheckTimer);
    }
}

void FillpFcTimerCb(void *argPcb)
{
    struct FillpPcb *pcb = (struct FillpPcb *)argPcb;

    if (pcb->algFuncs.fcTime != FILLP_NULL_PTR) {
        pcb->algFuncs.fcTime(pcb);
        FillpEnableFcTimer(pcb);
    }
}

#ifdef __cplusplus
}
#endif
