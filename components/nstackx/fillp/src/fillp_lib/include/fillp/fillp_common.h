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

#ifndef FILLP_COMMON_H
#define FILLP_COMMON_H

#include "fillptypes.h"
#include "fillp_os.h"
#include "spunge_stack.h"
#include "socket_common.h"
#include "hmac.h"
#include "res.h"
#include "fillp_buf_item.h"
#include "dympool.h"
#include "spunge_message.h"
#include "fillp_flow_control.h"
#include "utils.h"
#include "fillp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FILLP_GET_CONN(pcb) ((struct FtNetconn*) ((struct SpungePcb*) ((pcb)->spcb))->conn)
#define FILLP_GET_SOCKET(pcb) ((struct FtSocket*)(FILLP_GET_CONN(pcb)->sock))
#define FILLP_GET_CONN_STATE(pcb) NETCONN_GET_STATE(FILLP_GET_CONN(pcb))

#define FILLP_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#define FILLP_UNACKLIST_HASHINDEX(seqNum, pcb) \
    (((seqNum) / FILLP_UNACK_HASH_MOD) & (pcb)->send.unackList.hashModSize)

#define FILLP_INTERVAL_THRESHOLD 5000
#define FILLP_INTERVAL_DEFAULT 1000
void InsertUnrecvListFail(struct FillpPcb *pcb, struct FillpPcbItem *item);
void FillpAjustTlpParameterByRtt(struct FillpPcb *pcb, FILLP_LLONG rtt);
void FillpFreeItemAndEvent(struct FillpPcb *pcb, struct FillpPcbItem *item);
void FillpAdjustFcParamsByRtt(struct FillpPcb *pcb);
IGNORE_OVERFLOW void FillpAckSendPcb(struct FillpPcb *pcb, FILLP_INT seqNum);
IGNORE_OVERFLOW void FillpUploadRecvBox(struct FillpPcb *pcb);
void FillpSendNack(struct FillpPcb *pcb, FILLP_UINT32 startPktNum, FILLP_UINT32 endPktNum);
void FillpBuildAndSendPack(struct FillpPcb *pcb, struct FtSocket *ftSock, struct FillpPktPack *pack,
    FILLP_UINT16 dataLen);
void FillpMoveUnackToUnrecv(FILLP_UINT32 last_seq, FILLP_UINT32 cur_seq, struct FillpPcb *pcb,
    FILLP_BOOL isFromPack);
void FillpMoveUnackToUnrecvAll(FILLP_UINT32 ackSeq, FILLP_UINT32 lostSeq, struct FillpPcb *pcb,
    FILLP_BOOL isFromPack, FILLP_BOOL onePktOnly);
void FillpDataToStack(struct FillpPcb *pcb, struct FillpPcbItem *buf);
#ifdef __cplusplus
}
#endif

#endif /* FILLP_COMMON_H */