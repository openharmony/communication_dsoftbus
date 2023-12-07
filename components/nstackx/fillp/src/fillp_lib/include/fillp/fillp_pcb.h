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

#ifndef FILLP_PCB_H
#define FILLP_PCB_H
#include "opt.h"
#include "fillp_os.h"
#include "fillpinc.h"
#include "hlist.h"
#include "lf_ring.h"
#include "queue.h"
#include "log.h"
#include "opt.h"
#include "skiplist.h"
#include "timing_wheel.h"
#include "fillp_algorithm.h"
#include "fillp_frame.h"

#ifdef __cplusplus
extern "C" {
#endif


#define FILLP_UNACK_HASH_MOD 1024


typedef FILLP_INT (*fillpRecvFunc)(void *arg, void **buf, FILLP_INT count);
typedef FILLP_INT (*fillpSendFunc)(void *arg, FILLP_CONST char *buf, FILLP_INT size, void *pcb);
typedef FILLP_INT (*fillpSendmsgFunc)(void *arg, FILLP_CONST char *buf, FILLP_INT size, void *pcb);

struct FillpHashLlist {
    FILLP_UINT32 size;
    FILLP_UINT32 hashModSize;
    struct Hlist *hashMap;
    FILLP_UINT32 count; /* keeps the number of entries in the unacklist currently */

#ifdef FILLP_64BIT_ALIGN
    FILLP_UINT8 padd[4];
#endif
};

struct FillpNackNode {
    struct HlistNode hnode;
    FILLP_LLONG timestamp;
    FILLP_UINT32 startPktNum;
    FILLP_UINT32 endPktNum;
};

static __inline struct FillpNackNode *FillpNackNodeEntry(struct HlistNode *node)
{
    return (struct FillpNackNode *)((char *)(node) - (uintptr_t)(&(((struct FillpNackNode *)0)->hnode)));
}

#define FILLP_HISTORY_OWD_EXPIRE_TIME \
    (10 * 1000 * 1000)                       /* us,need to update min owd when it does not update until 10s */
#define FILLP_HISTORY_OWD_MAX_SAMPLE_NUM 500 /* (FILLP_HISTORY_OWD_EXPIRE_TIME / FILLP_DEFAULT_APP_PACK_INTERVAL) */

struct FillpOwdSample {
    FILLP_LLONG maxOwd; /* max owd value */
    FILLP_LLONG minOwd; /* min owd value */
};

struct FillpRecvPcb {
    struct SkipList recvBoxPlaceInOrder;
    struct SkipList recvList;
    FillpQueue *recvBox;
    struct Hlist nackList;
    void *itemPool;
    void *privItemPool;
    FILLP_UINT32 oppositeSetRate; /* The Max Opposite Rate Allowed */
    FILLP_UINT32 seqNum;          /* the newest continuous seq num received */
    FILLP_UINT32 endSeqNum;       /* the newest seq num received */
    FILLP_UINT32 pktNum;          /* the newest pkt num received */
    FILLP_UINT32 lastPackSeqNum;
    FILLP_UINT32 lastPackPktNum;
    FILLP_UINT32 pktStartNum;
    FILLP_UINT32 seqStartNum;
    FILLP_UINT32 pktRecvCache;
    FILLP_BOOL isRecvingData;
    FILLP_UINT8 frcPadd[3];
    FILLP_ULLONG recvBytes; /* data size in received but not in recvBox */
    SYS_ARCH_SEM recvSem;
    FILLP_UINT32 curItemCount;
    FILLP_UINT32 prePackPktNum;
};

struct FillpFlowControl {
    FILLP_LLONG sendTime; /* pre send time */
    /* for time Accuracy, if don't use realInterval * 8, the interval of 10GE will be 0  */
    FILLP_LLONG sendInterval; /* Real itnerval(us) * 8 */

    FILLP_UINT32 sendRate; /* kbps */

    FILLP_UINT32 sendRateLimit; /* Kbps, Implementing Fair Bandwidth sharing among sockets */
    FILLP_UINT32 remainBytes;
    FILLP_BOOL lastCycleNoEnoughData;
    FILLP_BOOL sendOneNoData;
    FILLP_CHAR pad[2];
    void *fcAlg;
};

struct FillpTailLostProtected {
    FILLP_UINT32 lastPackSeq;
    FILLP_UINT8 samePackCount;
    FILLP_UINT8 judgeThreshold;
    FILLP_UINT8 minJudgeThreshold;
    FILLP_UINT8 maxJudgeThreshold;
};

#define FILLP_DIFFER_TRANSMIT_PCB_MAX_CNT 32 /* max count of the pcb which will using differentiated transmission
                                              * after the pkts inserted to unsent list */

struct FillpSendPcb {
    struct SkipList unrecvList;
    struct SkipList redunList;
    struct FillpHashLlist pktSeqMap; /* use to find seq num by Pkt num  */
    struct FillpHashLlist unackList;
    FillpQueue *unsendBox; /* data pkt wait to send APP will fill pkt to it */
    struct SkipList itemWaitTokenLists;
    struct Hlist unSendList;
    void *itemPool;
    void *preItem;
    FILLP_ULLONG nackRandomNum;
    FILLP_ULLONG packRandomNum;

    struct FillpPktNack **retryNackQueue;
    FILLP_UINT32 retryIndex;
    FILLP_UINT32 pktNum;

    struct FillpFlowControl flowControl;
    struct FillpTailLostProtected tailProtect;

    FILLP_UINT32 seqNum;
    FILLP_UINT32 pktStartNum;
    FILLP_UINT32 seqStartNum;
    FILLP_UINT32 ackSeqNum; // The current acked number
    FILLP_UINT32 nackPktStartNum;
    FILLP_UINT32 nackPktEndNum;
    FILLP_UINT32 maxAckNumFromReceiver; // The maximal seqNum from receiver
    FILLP_UINT32 newDataSendComplete;
    FILLP_UINT32 pktSendCache;
    FILLP_UINT32 curItemCount;
    SYS_ARCH_SEM sendSem;

    FILLP_BOOL slowStart;
    FILLP_BOOL appLimited;
    FILLP_UINT8 packMoveToUnrecvThreshold;
    FILLP_UINT8 packSameAckNum;
    FILLP_UINT32 lastPackAckSeq;
    FILLP_ULLONG inSendBytes; /* total in sending data size */
    FILLP_ULLONG retramistRto;
    FILLP_LLONG lastSendTs;
    FILLP_ULLONG unrecvRedunListBytes; /* total byte in unrecvList and redunList */

    FILLP_INT directlySend;
};

struct FillpPcb {
    struct HlistNode stbNode;
    struct FillpSendPcb send;
    struct FillpRecvPcb recv;
    struct FillpStatisticsPcb statistics;
    void *spcb;
    FILLP_UINT32 mpSendSize;
    FILLP_UINT32 mpRecvSize;
    /* connection start timestamp */
    FILLP_LLONG connTimestamp;
    FILLP_LLONG dataNullTimestamp;

    struct FillpFrameHandle frameHandle;

    struct FillpTimingWheelTimerNode packTimerNode;
    struct FillpTimingWheelTimerNode FcTimerNode;
    struct FillpTimingWheelTimerNode sendTimerNode;
    struct FillpTimingWheelTimerNode keepAliveTimerNode;
    struct FillpTimingWheelTimerNode delayNackTimerNode;
    struct FillpTimingWheelTimerNode dataBurstTimerNode;
    struct FillpTimingWheelTimerNode connRetryTimeoutTimerNode;
    /* Check if all the unsend data are acked, or retry the fin message */
    struct FillpTimingWheelTimerNode finCheckTimer;

    struct HlistNode sendNode;

    FILLP_UINT32 localUniqueId;
    FILLP_UINT32 peerUniqueId;
    /* us */
    FILLP_ULLONG rtt;

    fillpRecvFunc recvFunc;
    /* Just used for non-data packets */
    fillpSendFunc sendFunc;
#ifdef FILLP_SUPPORT_GSO
    FILLP_BOOL sendmsgEio;
    fillpSendmsgFunc sendmsgFunc;
#endif
    /* At the server side, at this point we receive the connect_request from client */
    FILLP_LLONG connReqInputTimestamp;
    FILLP_SIZE_T pktSize;
    /* Valid at the client side, when the server rejects the CONFRIM message giving reason of STALE_COOKIE,
       then client will send the connect request again with this cookiePreserveTime time */
    FILLP_UINT32 clientCookiePreserveTime;
    FILLP_INT resInited;
    FILLP_UINT8 fcAlg;
    FILLP_UINT8 packState;
    /* Indicates if any ADHOC PACK with RTT_REQUIRE flag has been replied after this flag has been cleared */
    FILLP_BOOL adhocPackReplied;
    FILLP_UINT32 characters;
    struct SpungeInstance *pcbInst;
    struct FillpAlgFuncs algFuncs;
    FILLP_INT isLast;
    FILLP_LLONG lastCalcTime;

    FILLP_BOOL isFinAckReceived;
};

static __inline struct FillpPcb *FillpPcbStbNodeEntry(struct HlistNode *node)
{
    return (struct FillpPcb *)((char *)(node) - (uintptr_t)(&(((struct FillpPcb *)0)->stbNode)));
}

static __inline struct FillpPcb *FillpSendNodeEntry(FILLP_CONST struct HlistNode *node)
{
    return (struct FillpPcb *)((char *)(node) - (uintptr_t)(&(((struct FillpPcb *)0)->sendNode)));
}

static __inline FILLP_UINT32 FillpPcbGetTotalPktCnt(struct FillpPcb *pcb)
{
    return (pcb->send.unSendList.size + pcb->send.unrecvList.nodeNum +
        pcb->send.redunList.nodeNum + pcb->send.unackList.count + pcb->send.itemWaitTokenLists.nodeNum);
}

static __inline FILLP_BOOL FillpPcbGetDirectlySend(struct FillpPcb *pcb)
{
    return (pcb->send.directlySend == 0) ? FILLP_FALSE : FILLP_TRUE;
}

static __inline FILLP_UINT32 FillpPcbGetSendCacheSize(struct FillpPcb *pcb)
{
    return pcb->mpSendSize;
}

FILLP_INT FillpInitPcb(struct FillpPcb *pcb, FILLP_INT mpSendSize, FILLP_INT mpRecvSize);
void FillpRemovePcb(struct FillpPcb *pcb);

FILLP_UINT32 FillpGetSendpcbUnackListPktNum(struct FillpSendPcb *pcb);
FILLP_UINT32 FillpGetRecvpcbRecvlistPktNum(struct FillpRecvPcb *pcb);

void FillpPcbRemoveTimers(struct FillpPcb *fpcb);
struct FillpPcbItem;
void FillpPcbSendFc(struct FillpPcb *fpcb);
void FillpPcbSend(struct FillpPcb *fpcb, struct FillpPcbItem *item[], FILLP_UINT32 itemCnt);
FILLP_UINT32 FillpGetSockPackInterval(FILLP_CONST struct FillpPcb *pcb);

#ifdef __cplusplus
}
#endif

#endif /* FILLP_PCB_H */
