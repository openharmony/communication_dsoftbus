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

#ifndef FILLP_FC_H
#define FILLP_FC_H

#include "fillp/fillp_pcb.h"
#include "fillp/fillp.h"

#ifdef __cplusplus
extern "C" {
#endif


#define FILLP_FC_IN_KBPS (8 * 1000)
#define FILLP_FC_IN_BIT 8

#define FILLP_FC_VAL_IN_BITS(value) ((value) << 3) // value*8

#define FILLP_FC_KEEP_ALIVE_DURATION        (180 * 1000 * 1000)
#define FILLP_INITIAL_RATE (g_resource.flowControl.initialRate)

#define NACK_HISTORY_BY_MEMBER_INDEX 1

#define FILLP_FC_RTT_PACK_RATIO 4 // The ratio of rtt and pack period

#define FILLP_FC_OWD_NEW 1 /* Update one-way-delay(owd) at receiver, new_owd = (7 * old_owd + current_owd) / 8 */
#define FILLP_FC_OWD_OLD 7
#define FILLP_FC_OWD_DIVISOR 8

#define FILLP_MAX_LOST_NUM_FOR_REDUN 8

struct FillpRateSample {
    FILLP_UINT8 i;  /* pack index  measurement was taken */
    FILLP_UINT32 v; /* value measured */
};

struct FillpMaxRateSample {
    FILLP_UINT32 maxCnt;
    struct FillpRateSample *rateSample;
};

void FillpUpdateRecvRateSample(struct FillpMaxRateSample *maxRateSample, FILLP_UINT32 rateValue, FILLP_UINT8 rateI);
void FillpCalSendInterval(struct FillpPcb *flowControl);
void fillp_analyse_pack(struct FillpPcb *pcb, struct FillpPktPack *pack);
void FillpFcTailProtected(struct FillpPcb *pcb, struct FillpPktPack *pack);
void FillpFcPackInput(struct FillpPcb *pcb, struct FillpPktPack *pack);
void FillpFcNackInput(struct FillpPcb *pcb, struct FillpPktNack *nack);

FILLP_INT FillpFcInit(struct FillpPcb *pcb);
void FillpFcDeinit(struct FillpPcb *pcb);
void FillpFcDataInput(struct FillpPcb *pcb, FILLP_CONST struct FillpPktHead *pkt);
void FillpFcRecvDropOne(struct FillpPcb *pcb);
void FillpFcRecvOutOfOrder(struct FillpPcb *pcb);
void FillpFcCycle(void *arg);
void FillpFcRecvLost(struct FillpPcb *pcb, FILLP_UINT32 ones);
FILLP_BOOL FillpAppLimitedStatus(struct FillpPcb *pcb, FILLP_UINT32 beginPktNum, FILLP_UINT32 endPktNum);

#ifdef __cplusplus
}
#endif

#endif
