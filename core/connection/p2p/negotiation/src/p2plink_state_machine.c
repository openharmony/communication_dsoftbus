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

#include "p2plink_state_machine.h"

#include "p2plink_loop.h"
#include "securec.h"
#include "softbus_errcode.h"
#include "softbus_log.h"

static bool IsExistState(const FsmStateMachine *fsm, const FsmState *state)
{
    struct ListNode *item = NULL;

    LIST_FOR_EACH(item, &fsm->stateList) {
        if (item == (struct ListNode *)state) {
            return true;
        }
    }
    return false;
}

int32_t P2pLinkFsmInit(FsmStateMachine *fsm)
{
    if (fsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    (void)memset_s(fsm, sizeof(*fsm), 0, sizeof(*fsm));
    ListInit(&fsm->stateList);
    return SOFTBUS_OK;
}

void P2pLinkFsmDeinit(FsmStateMachine *fsm)
{
    if (fsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "fsm already deinit.");
        return;
    }

    if (fsm->currentState == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_DBG, "unexpected state in deinit process");
    }
    fsm->currentState = NULL;
}

void P2pLinkFsmAddState(FsmStateMachine *fsm, FsmState *state)
{
    if (fsm == NULL || state == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "invalid param");
        return;
    }

    if (IsExistState(fsm, state)) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "already exist state");
        return;
    }
    ListInit(&state->node);
    ListAdd(&fsm->stateList, &state->node);
}

void P2pLinkFsmStart(FsmStateMachine *fsm, FsmState *initialState)
{
    if (fsm->currentState != NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unexpected state in start msg process");
        return;
    }
    if (IsExistState(fsm, initialState)) {
        fsm->currentState = initialState;
        if (fsm->currentState->enter != NULL) {
            fsm->currentState->enter();
        }
    }
}

void P2pLinkFsmStop(FsmStateMachine *fsm)
{
    if (fsm->currentState == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unexpected state in stop msg process");
        return;
    }
    fsm->currentState = NULL;
}

void P2pLinkFsmTransactState(FsmStateMachine *fsm, FsmState *state)
{
    if (fsm == NULL || state == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "invalid param");
        return;
    }

    if (fsm->currentState == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unexpected state in change state process");
        return;
    }

    if (IsExistState(fsm, state)) {
        if (fsm->currentState->exit != NULL) {
            fsm->currentState->exit();
        }
        fsm->currentState = state;
        if (fsm->currentState->enter != NULL) {
            fsm->currentState->enter();
        }
    } else {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "unexpected state in state list");
        return;
    }
}

void P2pLinkFsmMsgProc(const FsmStateMachine *fsm, int32_t msgType, void *param)
{
    if (fsm->currentState == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "current state is null");
        return;
    }
    if (fsm->currentState->process != NULL) {
        fsm->currentState->process(msgType, param);
    }
}

void P2pLinkFsmMsgProcDelay(const FsmStateMachine *fsm, int32_t msgType, void *param, uint64_t delayMs)
{
    if (fsm->currentState == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "current state is null");
        return;
    }
    if (fsm->currentState->process == NULL) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_ERROR, "current process is null");
        return;
    }
    (void)P2pLoopProcDelay(fsm->currentState->process, param, delayMs, msgType);
}

void P2pLinkFsmMsgProcDelayDel(int32_t msgType)
{
    SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "delete delay msg type %d", msgType);
    (void)P2pLoopProcDelayDel(NULL, msgType);
}