/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "lnn_state_machine.h"

#include <stdlib.h>

#include <securec.h>

#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

static bool IsDuplicateState(FsmStateMachine *fsm, FsmState *state)
{
    struct ListNode *item = NULL;

    LIST_FOR_EACH(item, &fsm->stateList) {
        if (item == (struct ListNode *)state) {
            return true;
        }
    }
    return false;
}

static void FreeFsmHandleMsg(SoftBusMessage *msg)
{
    if (msg != NULL) {
        if (msg->obj != NULL) {
            SoftBusFree(msg->obj);
        }
        SoftBusFree(msg);
    }
}

static void FreeFsmHandleMsgObj(FsmCtrlMsgObj *ctrlMsgObj)
{
    if (ctrlMsgObj == NULL) {
        return;
    }
    if (ctrlMsgObj->obj != NULL) {
        SoftBusFree(ctrlMsgObj->obj);
        ctrlMsgObj->obj = NULL;
    }
}

static SoftBusMessage *CreateFsmHandleMsg(FsmStateMachine *fsm,
    int32_t what, uint64_t arg1, uint64_t arg2, void *obj)
{
    SoftBusMessage *msg = NULL;
    FsmCtrlMsgObj *ctrlMsgObj = NULL;

    msg = SoftBusCalloc(sizeof(*msg));
    if (msg == NULL) {
        LNN_LOGE(LNN_STATE, "calloc msg failed");
        return NULL;
    }
    msg->what = what;
    msg->arg1 = arg1;
    msg->arg2 = arg2;
    msg->handler = &fsm->handler;
    msg->FreeMessage = FreeFsmHandleMsg;

    ctrlMsgObj = SoftBusMalloc(sizeof(*ctrlMsgObj));
    if (ctrlMsgObj == NULL) {
        LNN_LOGE(LNN_STATE, "calloc ctrl msg obj failed");
        SoftBusFree(msg);
        return NULL;
    }
    ctrlMsgObj->fsm = fsm;
    ctrlMsgObj->obj = obj;
    msg->obj = ctrlMsgObj;
    return msg;
}

static void ProcessStartMessage(SoftBusMessage *msg)
{
    FsmCtrlMsgObj *ctrlMsgObj = msg->obj;
    FsmStateMachine *fsm = NULL;
    FsmState *state = NULL;

    if (ctrlMsgObj == NULL) {
        LNN_LOGE(LNN_STATE, "unexpected state in start msg process");
        return;
    }
    fsm = ctrlMsgObj->fsm;
    state = (FsmState *)ctrlMsgObj->obj;
    if (fsm == NULL || state == NULL) {
        return;
    }
    if (fsm->curState != NULL || (fsm->flag & FSM_FLAG_RUNNING) != 0) {
        LNN_LOGE(LNN_STATE, "unexpected state in start msg process");
        return;
    }
    if (IsDuplicateState(fsm, state) == true) {
        fsm->curState = state;
        if (fsm->curState->enter != NULL) {
            fsm->curState->enter(fsm);
        }
        fsm->flag |= FSM_FLAG_RUNNING;
    }
}

static void ProcessDataMessage(SoftBusMessage *msg)
{
    FsmCtrlMsgObj *ctrlMsgObj = msg->obj;
    FsmStateMachine *fsm = NULL;

    if (ctrlMsgObj == NULL) {
        LNN_LOGE(LNN_STATE, "unexpected state in data msg=%{public}d process, ctrlMsgObj is null", (int32_t)msg->arg1);
        return;
    }
    fsm = ctrlMsgObj->fsm;
    if (fsm == NULL) {
        LNN_LOGE(LNN_STATE, "unexpected state in data msg=%{public}d process, fsm is null", (int32_t)msg->arg1);
        return;
    }
    if (fsm->curState == NULL || (fsm->flag & FSM_FLAG_RUNNING) == 0) {
        LNN_LOGE(LNN_STATE, "unexpected state in data msg process, arg1=%{public}d, flag=0x%{public}x",
            (int32_t)msg->arg1, fsm->flag);
        return;
    }
    if (fsm->curState->process != NULL) {
        fsm->curState->process(fsm, (int32_t)msg->arg1, ctrlMsgObj->obj);
    }
}

static void ProcessStopMessage(SoftBusMessage *msg)
{
    FsmCtrlMsgObj *ctrlMsgObj = msg->obj;
    FsmStateMachine *fsm = NULL;

    if (ctrlMsgObj == NULL) {
        return;
    }
    fsm = ctrlMsgObj->fsm;
    if (fsm == NULL) {
        LNN_LOGE(LNN_STATE, "unexpected state in stop msg process");
        return;
    }
    if (fsm->curState == NULL || (fsm->flag & FSM_FLAG_RUNNING) == 0) {
        LNN_LOGE(LNN_STATE, "unexpected state in stop msg process");
        return;
    }
    fsm->curState = NULL;
    fsm->flag &= ~FSM_FLAG_RUNNING;
}

/* remove message when return 0, else return 1 */
static int32_t RemoveAllMessageFunc(const SoftBusMessage *msg, void *para)
{
    (void)para;

    FreeFsmHandleMsgObj((FsmCtrlMsgObj *)msg->obj);
    return 0;
}

static void ProcessDeinitMessage(SoftBusMessage *msg)
{
    FsmCtrlMsgObj *ctrlMsgObj = msg->obj;
    FsmStateMachine *fsm = NULL;

    if (ctrlMsgObj == NULL) {
        LNN_LOGE(LNN_STATE, "unexpected state in deinit msg process");
        return;
    }
    fsm = ctrlMsgObj->fsm;
    if (fsm == NULL) {
        LNN_LOGE(LNN_STATE, "fsm is null in deinit msg process");
        return;
    }
    if (fsm->looper != NULL && fsm->looper->RemoveMessageCustom != NULL) {
        fsm->looper->RemoveMessageCustom(fsm->looper, &fsm->handler, RemoveAllMessageFunc, NULL);
    }
    if (fsm->deinitCallback != NULL) {
        fsm->deinitCallback(fsm);
    }
}

static void FsmStateMsgHandler(SoftBusMessage *msg)
{
    if (msg == NULL) {
        LNN_LOGE(LNN_STATE, "process msg is null");
        return;
    }

    if (msg->what != FSM_CTRL_MSG_DATA) {
        LNN_LOGI(LNN_STATE, "process fsm ctrl msgType=%{public}d", msg->what);
    }
    switch (msg->what) {
        case FSM_CTRL_MSG_START:
            ProcessStartMessage(msg);
            break;
        case FSM_CTRL_MSG_DATA:
            ProcessDataMessage(msg);
            break;
        case FSM_CTRL_MSG_STOP:
            ProcessStopMessage(msg);
            break;
        case FSM_CTRL_MSG_DEINIT:
            ProcessDeinitMessage(msg);
            break;
        default:
            break;
    }
}

static int32_t PostMessageToFsm(FsmStateMachine *fsm, int32_t what, uint64_t arg1,
    uint64_t arg2, void *obj)
{
    SoftBusMessage *msg = NULL;

    msg = CreateFsmHandleMsg(fsm, what, arg1, arg2, obj);
    if (msg == NULL) {
        LNN_LOGE(LNN_STATE, "create fsm handle msg fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (fsm->looper->PostMessage == NULL) {
        LNN_LOGE(LNN_STATE, "PostMessage is null");
        FreeFsmHandleMsg(msg);
        return SOFTBUS_INVALID_PARAM;
    }
    fsm->looper->PostMessage(fsm->looper, msg);
    return SOFTBUS_OK;
}

/* remove message when return 0, else return 1 */
static int32_t RemoveMessageFunc(const SoftBusMessage *msg, void *para)
{
    int32_t msgType;

    if (msg == NULL || para == NULL) {
        return 1;
    }
    msgType = (int32_t)(intptr_t)para;
    if (msg->what == FSM_CTRL_MSG_DATA && (int32_t)msg->arg1 == msgType) {
        LNN_LOGI(LNN_STATE, "remove fsm data msgType=%{public}d", msgType);
        FreeFsmHandleMsgObj((FsmCtrlMsgObj *)msg->obj);
        return 0;
    }
    return 1;
}

int32_t LnnFsmInit(FsmStateMachine *fsm, SoftBusLooper *looper, char *name, FsmDeinitCallback cb)
{
    if (fsm == NULL || name == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    (void)memset_s(fsm, sizeof(*fsm), 0, sizeof(*fsm));
    ListInit(&fsm->stateList);
    fsm->looper = looper == NULL ? GetLooper(LOOP_TYPE_DEFAULT) : looper;
    if (fsm->looper == NULL) {
        LNN_LOGE(LNN_STATE, "get looper fail");
        return SOFTBUS_LOOPER_ERR;
    }
    fsm->handler.name = name;
    fsm->handler.HandleMessage = FsmStateMsgHandler;
    fsm->handler.looper = fsm->looper;
    fsm->deinitCallback = cb;
    return SOFTBUS_OK;
}

int32_t LnnFsmDeinit(FsmStateMachine *fsm)
{
    if (fsm == NULL || fsm->looper == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToFsm(fsm, FSM_CTRL_MSG_DEINIT, 0, 0, NULL);
}

int32_t LnnFsmAddState(FsmStateMachine *fsm, FsmState *state)
{
    if (fsm == NULL || fsm->looper == NULL || state == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (IsDuplicateState(fsm, state)) {
        LNN_LOGE(LNN_STATE, "already exist state");
        return SOFTBUS_ALREADY_EXISTED;
    }
    ListInit(&state->list);
    ListAdd(&fsm->stateList, &state->list);
    return SOFTBUS_OK;
}

int32_t LnnFsmStart(FsmStateMachine *fsm, FsmState *initialState)
{
    if (fsm == NULL || fsm->looper == NULL || initialState == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToFsm(fsm, FSM_CTRL_MSG_START, 0, 0, initialState);
}

int32_t LnnFsmStop(FsmStateMachine *fsm)
{
    if (fsm == NULL || fsm->looper == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToFsm(fsm, FSM_CTRL_MSG_STOP, 0, 0, NULL);
}

int32_t LnnFsmPostMessage(FsmStateMachine *fsm, uint32_t msgType, void *data)
{
    if (fsm == NULL || fsm->looper == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToFsm(fsm, FSM_CTRL_MSG_DATA, msgType, 0, data);
}

int32_t LnnFsmPostMessageDelay(FsmStateMachine *fsm, uint32_t msgType,
    void *data, uint64_t delayMillis)
{
    SoftBusMessage *msg = NULL;

    if (fsm == NULL || fsm->looper == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    msg = CreateFsmHandleMsg(fsm, FSM_CTRL_MSG_DATA, msgType, 0, data);
    if (msg == NULL) {
        LNN_LOGE(LNN_STATE, "create fsm handle msg fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (fsm->looper->PostMessageDelay == NULL) {
        LNN_LOGE(LNN_STATE, "PostMessageDelay is null");
        FreeFsmHandleMsg(msg);
        return SOFTBUS_INVALID_PARAM;
    }
    fsm->looper->PostMessageDelay(fsm->looper, msg, delayMillis);
    return SOFTBUS_OK;
}

int32_t LnnFsmRemoveMessageByType(FsmStateMachine *fsm, int32_t what)
{
    if (fsm == NULL || fsm->looper == NULL || fsm->looper->RemoveMessage == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    fsm->looper->RemoveMessage(fsm->looper, &fsm->handler, what);
    return SOFTBUS_OK;
}

int32_t LnnFsmRemoveMessage(FsmStateMachine *fsm, int32_t msgType)
{
    if (fsm == NULL || fsm->looper == NULL || fsm->looper->RemoveMessageCustom == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    fsm->looper->RemoveMessageCustom(fsm->looper, &fsm->handler,
        RemoveMessageFunc, (void *)(intptr_t)msgType);
    return SOFTBUS_OK;
}

int32_t LnnFsmRemoveMessageSpecific(FsmStateMachine *fsm,
    int32_t (*customFunc)(const SoftBusMessage*, void*), void *args)
{
    if (fsm == NULL || fsm->looper == NULL || fsm->looper->RemoveMessageCustom == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    fsm->looper->RemoveMessageCustom(fsm->looper, &fsm->handler,
        customFunc == NULL ? RemoveMessageFunc : customFunc, args);
    return SOFTBUS_OK;
}

/* we must change state of state machine during its procedure, otherwise it will introduce concurrency */
int32_t LnnFsmTransactState(FsmStateMachine *fsm, FsmState *state)
{
    if (fsm == NULL || state == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (fsm->curState == NULL || (fsm->flag & FSM_FLAG_RUNNING) == 0) {
        LNN_LOGE(LNN_STATE, "unexpected state in change state process");
        return SOFTBUS_INVALID_PARAM;
    }

    if (IsDuplicateState(fsm, state)) {
        if (fsm->curState->exit != NULL) {
            fsm->curState->exit(fsm);
        }
        fsm->curState = state;
        if (fsm->curState->enter != NULL) {
            fsm->curState->enter(fsm);
        }
    }
    return SOFTBUS_OK;
}
