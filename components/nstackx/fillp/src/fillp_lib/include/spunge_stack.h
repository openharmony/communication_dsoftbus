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

#ifndef SPUNGE_STACK_H
#define SPUNGE_STACK_H

#include "spunge_core.h"

#ifdef __cplusplus
extern "C" {
#endif

void SpungeDoRecvCycle(struct SockOsSocket *osSock, struct SpungeInstance *inst);
void SpungeDoPackCycle(struct SpungePcb *pcb, struct SpungeInstance *inst);
void SpungeSendConnectMsg(void *argConn);
void SpungeDoSendCycle(struct SpungePcb *pcb, struct SpungeInstance *inst, FILLP_LLONG detaTime);
void SpungeCheckDisconn(void *argConn);

struct SockOsSocket *SpungeAllocSystemSocket(FILLP_INT domain, FILLP_INT type, FILLP_INT protocol);
FillpQueue *SpungeAllocUnsendBox(struct SpungeInstance *inst);
void SpungeFreeUnsendBox(struct FillpPcb *pcb);

void SpungeShutdownSock(void *argSock, FILLP_INT how);
void SpungeConnClosed(struct FtNetconn *conn);
void SpungeConnConnectSuccess(void *argSock);
void SpungeConnConnectFail(void *argSock);
FILLP_BOOL SpungeConnCheckUnsendBoxEmpty(struct FtNetconn *conn);
void SpungEpollClose(struct FtSocket *sock);

#ifdef __cplusplus
}
#endif
#endif /* SPUNGE_STACK_H */
