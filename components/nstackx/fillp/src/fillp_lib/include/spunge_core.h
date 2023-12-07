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

#ifndef SPUNGE_CORE_H
#define SPUNGE_CORE_H
#include "fillpinc.h"
#include "spunge.h"
#include "lf_ring.h"
#include "queue.h"
#include "log.h"
#include "hlist.h"
#include "pcb.h"
#include "spunge_mem.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Refresh time is 30 minutes */
#define FILLP_KEY_REFRESH_TIME 1800000000

#define SPUNGE_SOCKET_BOX_SIZE 1024


#define FILLP_FC_PREV_ADJUSTMENT_RATE_LOW_VAL 0.98
#define FILLP_FC_PREV_ADJUSTMENT_RATE_HIGH_VAL 1.02

/* fillp value to calcuate  the send rate */
#define FILLP_FC_STABLESTATE_VAL_1 10

/* fillp value to calcuate the send rate */
#define FILLP_FC_STABLESTATE_VAL_2 5


/* fillp send rate multiple factor value */

#define FILLP_FC_SEND_RATE_MULTIPLE_FACTOR 0.95

/* fillp send rate value */
#define FILL_FC_SEND_RATE_TOTAL_1 1.5

/* fillp send rate value */
#define FILL_FC_SEND_RATE_TOTAL_2 1.05

/* fillp max rate limit value */
#define FILLP_FC_MAX_RATE_LIMIT_VAL 1000

/* FillP needs to calculate the fairness every 200 milliseconds */
#define SPUNGE_WEIGHT_ADJUST_INTERVAL 200000
#define SPUNGE_TOKEN_TIMER_MAX_INTERVAL 1000 /* 1 ms */

#define SPUNGE_TOKEN_TIMER_MAX_INTERVAL_RATE_ZERO SPUNGE_TOKEN_TIMER_MAX_INTERVAL

#define SPUNGE_TOKEN_MAX_BURST_TIME 10000 /* 10 ms */

#define SPUNGE_MAX_THREAD_NAME_LENGTH 16

FILLP_INT SpungeInstInit(struct SpungeInstance *inst);

void SpungeHandleMsgCycle(struct SpungeInstance *inst);

void SpungeFreeAcceptBox(struct FtSocket *sock);
void SpungeIncFreeCntPostEagain(struct FtSocket *sock);

void SpungeFreeSock(struct FtSocket *sock);

void SpungeInstanceMainThread(void *p);
void SpungePushRecvdDataToStack(void *arg);

void SpungeDestroySockTable(struct FtSocketTable *table);
struct FtSocketTable *SpungeCreateSockTable(FILLP_UINT maxSock);


static __inline struct SockOsSocket *SockOsListEntry(struct HlistNode *node)
{
    return (struct SockOsSocket *)((char *)(node) - (uintptr_t)(&(((struct SockOsSocket *)0)->osListNode)));
}

void FillpServerRecvRateAdjustment(struct SpungeInstance *inst, FILLP_UINT32 calcRecvTotalRate, FILLP_INT realRecvConn,
    FILLP_UINT32 *connRecvCalLimit);

void FillpServerSendRateAdjustment(struct SpungeInstance *inst, FILLP_UINT32 calcSendTotalRate, FILLP_INT realSendConn,
    FILLP_UINT32 *connSendCalLimit);


/* Implementing Fair Bandwidth sharing among sockets */
void FillpCalculateFairness(struct SpungeInstance *inst);

FILLP_BOOL FillpKillCore(void);

void FillpCheckPcbNackListToSend(void *args);

void SpinstLoopFairnessChecker(void *p);

void SpinstLoopMacTimerChecker(void *p);

void FtGlobalTimerInit(struct SpungeInstance *inst);

void SpungeDestroyInstance(struct SpungeInstance *inst);

void SpungeInitTokenBucket(struct SpungeInstance *inst);
void SpungeEnableTokenTimer(struct SpungeTokenBucke *stb);
void SpungeDisableTokenTimer(struct SpungeTokenBucke *stb);
void SpungeTokenTimerCb(void *p);
FILLP_INT SpungeItemRouteByToken(struct FillpPcbItem *item, struct FillpPcb *fpcb);
void SpungeCheckItemWaitTokenList(struct SpungeTokenBucke *stb);
void SpungeTokenBucketAddFpcb(struct FillpPcb *fpcb);
void SpungeTokenBucketDelFpcb(struct FillpPcb *fpcb);

#ifdef __cplusplus
}
#endif


#endif /* SPUNGE_CORE_H */
