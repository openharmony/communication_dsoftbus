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

#ifndef PCB_H
#define PCB_H

#include "fillp_os.h"
#include "fillp/fillp_pcb.h"
#include "lf_ring.h"
#include "log.h"
#include "queue.h"
#include "hlist.h"

#ifdef __cplusplus
extern "C" {
#endif


/* Implementing Fair Bandwidth sharing among sockets */
struct SpungePcbRateControlItem {
    FILLP_UINT32 curMaxRateLimitation;
    FILLP_INT weight;
};

struct SpungePcbRateControl {
    struct SpungePcbRateControlItem send;
    struct SpungePcbRateControlItem recv;
};

#ifndef IFNAMESIZE
#define IFNAMESIZE 64
#endif
struct SpungePcb {
    struct HlistNode udpNode;
    struct HlistNode hashNode;
    struct FillpPcb fpcb;

    void *conn;

    /* Implementing Fair Bandwidth sharing among sockets */
    struct SpungePcbRateControl rateControl;

    struct sockaddr_in6 localAddr;
    struct sockaddr_in6 remoteAddr;

    FILLP_INT localPort;
    FILLP_UINT16 addrType;
    FILLP_UINT16 addrLen;

    FILLP_CHAR devName[IFNAMESIZE];
    FILLP_INT ifIndex;
};

static __inline struct SpungePcb *SpungePcbListNodeEntry(struct HlistNode *node)
{
    return (struct SpungePcb *)((char *)(node) - (uintptr_t)(&(((struct SpungePcb *)0)->udpNode)));
}

static __inline struct SpungePcb *SpungePcbHashNodeEntry(struct HlistNode *node)
{
    return (struct SpungePcb *)((char *)(node) - (uintptr_t)(&(((struct SpungePcb *)0)->hashNode)));
}

void SpcbAddPcbToSpinst(struct SpungeInstance *inst, struct SpungePcb *pcb);
void SpcbDeleteFromSpinst(struct SpungeInstance *inst, struct SpungePcb *pcb);


struct SpungePcb *SpungePcbNew(void *argConn, struct SpungeInstance *inst);

void SpungePcbRemove(struct SpungePcb *pcb);

void SpungePcbSetSendCacheSize(struct SpungePcb *pcb, FILLP_UINT32 cahceSize);
void SpungePcbSetRecvCacheSize(struct SpungePcb *pcb, FILLP_UINT32 cahceSize);
void SpungePcbSetPktSize(struct SpungePcb *pcb, FILLP_UINT32 pktSize);
void SpungePcbSetOppositeRate(struct SpungePcb *pcb, FILLP_UINT32 rate);
void SpungePcbSetSlowStart(struct SpungePcb *pcb, FILLP_BOOL slowStart);
void SpungePcbSetPackInterval(struct SpungePcb *pcb, FILLP_UINT32 interval);
void SpungePcbSetAddrType(struct SpungePcb *pcb, FILLP_UINT16 addrType);
void SpungePcbSetLocalPort(struct SpungePcb *pcb, FILLP_INT port);
void SpungePcbSetDirectlySend(struct SpungePcb *pcb, FILLP_INT directlySend);

#ifdef __cplusplus
}
#endif

#endif /* PCB_H */
