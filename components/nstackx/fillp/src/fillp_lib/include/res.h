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

#ifndef FILLP_RES_H
#define FILLP_RES_H

#include "sockets.h"

#ifdef FILLP_LINUX
#define __FAVOR_BSD
#include <netinet/tcp.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct GlobalUdpRes {
    FILLP_UINT16 rxBurst; /* max pkt number to recv each cycle */
    FILLP_UINT16 numMsgSend;
    FILLP_BOOL supportMmsg;
    FILLP_UINT8 padd;
};


struct GlobalCommon {
    FILLP_UINT32 recvCachePktNumBufferSize;
    FILLP_UINT16 recvCachePktNumBufferTimeout;
    FILLP_UINT16 maxSockNum;
    FILLP_UINT16 maxConnNum;
    FILLP_UINT16 maxInstNum;
    FILLP_BOOL fullCpuEnable;
    FILLP_BOOL outOfOrderCacheEnable;
    FILLP_UINT8 cpuCoreUse;
    FILLP_UINT8 reserve;
    FILLP_UINT32 sendCache; /* size of send cache */
    FILLP_UINT32 recvCache; /* size of recv cache  */
    FILLP_UINT32 padd;
};

struct GlobalFlowControl {
    FILLP_UINT32 maxRate;
    FILLP_UINT32 maxRecvRate;
    FILLP_UINT32 initialRate;
    FILLP_UINT16 oppositeSetPercentage; /* Only for Server */
    FILLP_UINT16 maxRatePercentage;
    FILLP_UINT16 nackRepeatTimes;
    FILLP_UINT16 pktLossAllow;
    FILLP_UINT8 fcAlg;
    FILLP_UINT8 supportFairness;
    FILLP_UINT32 limitRate;
};


struct GlobalResource {
    struct GlobalUdpRes udp;
    struct GlobalCommon common;
    struct GlobalFlowControl flowControl;
    FILLP_UINT8 pktLossThresHoldMax;
    FILLP_UINT16 timingWheelAccuracy;
    FILLP_UINT32 maximalAckNumLimit;
    FILLP_UINT32 sendOneAckNum;
    FILLP_UINT16 cpuPauseTime;
    FILLP_UINT8 retransmitCmpTime;
    FILLP_UINT8 reserve;
    FILLP_UINT16 minRate;
    FILLP_UINT16 minPackInterval;
    FILLP_UINT16 unsendBoxLoopCheckBurst;
    FILLP_UINT16 reserv;
    FILLP_UINT32 instUnsendBoxSize;
    FILLP_UINT16 nackRetryLen;
    FILLP_UINT16 reserved;
    double fcControlMultiNumInitialValue;
    double fcMultiAdjustConst;
    double fcMultiNumStep;
    double fcNightyPercentVal;
    FILLP_UINT32 fullCpuUseThresholdRate;
    FILLP_UINT32 padd;
};

void InitGlobalResourceDefault(void);

extern struct GlobalResource g_resource;

#ifdef __cplusplus
}
#endif

#endif /* FILLP_RES_H */
