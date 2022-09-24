/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef P2PLINK_STATE_MACHINE_H
#define P2PLINK_STATE_MACHINE_H

#include <stdint.h>

#include "common_list.h"
#include "p2plink_loop.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef void (*StateEnter)(void);
typedef void (*StateExit)(void);
typedef void (*StateProcess)(P2pLoopMsg msgType, void *para);

typedef struct {
    ListNode node;
    StateEnter enter;
    StateProcess process;
    StateExit exit;
} FsmState;

typedef struct {
    FsmState *currentState;
    ListNode stateList;
} FsmStateMachine;

int32_t P2pLinkFsmInit(FsmStateMachine *fsm);
void P2pLinkFsmDeinit(FsmStateMachine *fsm);

void P2pLinkFsmAddState(FsmStateMachine *fsm, FsmState *state);
void P2pLinkFsmStart(FsmStateMachine *fsm, FsmState *initialState);
void P2pLinkFsmStop(FsmStateMachine *fsm);
void P2pLinkFsmMsgProc(const FsmStateMachine *fsm, int32_t msgType, void *param);
void P2pLinkFsmMsgProcDelay(const FsmStateMachine *fsm, int32_t msgType, void *param, uint64_t delayMs);
void P2pLinkFsmMsgProcDelayDel(int32_t msgType);

void P2pLinkFsmTransactState(FsmStateMachine *fsm, FsmState *state);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* P2PLINK_STATE_MACHINE_H */