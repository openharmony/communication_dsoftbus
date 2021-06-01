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

#include "lnn_state_machine.h"

#include <stdlib.h>

#include <securec.h>

#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"

#define FSM_CTRL_MSG_START 0
#define FSM_CTRL_MSG_CHANGE_STATE 1
#define FSM_CTRL_MSG_DATA 2
#define FSM_CTRL_MSG_STOP 3
#define FSM_CTRL_MSG_DEINIT 4

typedef struct {
    FsmStateMachine *fsm;
    void *obj;
} FsmCtrlMsgObj;

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
        return NULL;
    }
    msg->what = what;
    msg->arg1 = arg1;
    msg->arg2 = arg2;
    msg->handler = &fsm->handler;
    msg->FreeMessage = FreeFsmHandleMsg;

    ctrlMsgObj = SoftBusMalloc(sizeof(*ctrlMsgObj));
    if (ctrlMsgObj == NULL) {
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
        return;
    }
    fsm = ctrlMsgObj->fsm;
    state = (FsmState *)ctrlMsgObj->obj;
    if (fsm == NULL || state == NULL) {
        return;
    }
    if (fsm->curState != NULL || (fsm->flag & FSM_FLAG_RUNNING) != 0) {
        LOG_ERR("unexpected state");
        return;
    }
    if (IsDuplicateState(fsm, state) == true) {
        fsm->curState = state;
        if (fsm->curState->enter != NULL) {
            fsm->curState->enter();
        }
        fsm->flag |= FSM_FLAG_RUNNING;
    }
}

static void ProcessChangeStateMessage(SoftBusMessage *msg)
{
    FsmCtrlMsgObj *ctrlMsgObj = msg->obj;
    FsmStateMachine *fsm = NULL;
    FsmState *state = NULL;

    if (ctrlMsgObj == NULL) {
        return;
    }
    fsm = ctrlMsgObj->fsm;
    state = (FsmState *)ctrlMsgObj->obj;
    if (fsm == NULL || state == NULL) {
        return;
    }

    if (fsm->curState == NULL || (fsm->flag & FSM_FLAG_RUNNING) == 0) {
        LOG_ERR("unexpected state");
        return;
    }

    if (IsDuplicateState(fsm, state)) {
        if (fsm->curState->exit != NULL) {
            fsm->curState->exit();
        }
        fsm->curState = state;
        if (fsm->curState->enter != NULL) {
            fsm->curState->enter();
        }
    }
}

static void ProcessDataMessage(SoftBusMessage *msg)
{
    FsmCtrlMsgObj *ctrlMsgObj = msg->obj;
    FsmStateMachine *fsm = NULL;

    if (ctrlMsgObj == NULL) {
        return;
    }
    fsm = ctrlMsgObj->fsm;
    if (fsm == NULL) {
        return;
    }
    if (fsm->curState == NULL || (fsm->flag & FSM_FLAG_RUNNING) == 0) {
        LOG_ERR("unexpected state");
        return;
    }
    if (fsm->curState->process != NULL) {
        fsm->curState->process((int32_t)msg->arg1, ctrlMsgObj->obj);
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
        return;
    }
    if (fsm->curState == NULL || (fsm->flag & FSM_FLAG_RUNNING) == 0) {
        LOG_ERR("unexpected state");
        return;
    }
    fsm->curState = NULL;
    fsm->flag &= ~FSM_FLAG_RUNNING;
}

static void ProcessDeinitMessage(SoftBusMessage *msg)
{
    FsmCtrlMsgObj *ctrlMsgObj = msg->obj;
    FsmStateMachine *fsm = NULL;

    if (ctrlMsgObj == NULL) {
        return;
    }
    fsm = ctrlMsgObj->fsm;
    if (fsm == NULL) {
        return;
    }
    if (fsm->deinitCallback != NULL) {
        fsm->deinitCallback(fsm);
    }
}

static void FsmStateMsgHandler(SoftBusMessage *msg)
{
    if (msg == NULL) {
        return;
    }

    if (msg->what != FSM_CTRL_MSG_DATA) {
        LOG_INFO("process fsm ctrl msg: %d", msg->what);
    }
    switch (msg->what) {
        case FSM_CTRL_MSG_START:
            ProcessStartMessage(msg);
            break;
        case FSM_CTRL_MSG_CHANGE_STATE:
            ProcessChangeStateMessage(msg);
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

static int32_t PostMessageToFsm(FsmStateMachine *fsm, int32_t what, uint64_t arg1, uint64_t arg2, void *obj)
{
    SoftBusMessage *msg = NULL;

    msg = CreateFsmHandleMsg(fsm, what, arg1, arg2, obj);
    if (msg == NULL) {
        LOG_ERR("create fsm handle msg fail");
        return SOFTBUS_ERR;
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
    msgType = (int32_t)para;
    if (msg->what == FSM_CTRL_MSG_DATA && (int32_t)msg->arg1 == msgType) {
        LOG_INFO("remove fsm data message: %d", msgType);
        FreeFsmHandleMsgObj((FsmCtrlMsgObj *)msg->obj);
        return 0;
    }
    return 1;
}

int32_t LnnFsmInit(FsmStateMachine *fsm, char *name, FsmDinitCallback cb)
{
    if (fsm == NULL || name == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    (void)memset_s(fsm, sizeof(*fsm), 0, sizeof(*fsm));
    ListInit(&fsm->stateList);
    fsm->looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (fsm->looper == NULL) {
        LOG_ERR("get looper fail");
        return SOFTBUS_ERR;
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
        LOG_ERR("already exist state");
        return SOFTBUS_ERR;
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

int32_t LnnFsmPostMessage(FsmStateMachine *fsm, int32_t msgType, void *data)
{
    if (fsm == NULL || fsm->looper == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToFsm(fsm, FSM_CTRL_MSG_DATA, msgType, 0, data);
}

int32_t LnnFsmPostMessageDelay(FsmStateMachine *fsm, int32_t msgType,
    void *data, uint64_t delayMillis)
{
    SoftBusMessage *msg = NULL;

    if (fsm == NULL || fsm->looper == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    msg = CreateFsmHandleMsg(fsm, FSM_CTRL_MSG_DATA, msgType, 0, data);
    if (msg == NULL) {
        LOG_ERR("create fsm handle msg fail");
        return SOFTBUS_ERR;
    }
    fsm->looper->PostMessageDelay(fsm->looper, msg, delayMillis);
    return SOFTBUS_OK;
}

int32_t LnnFsmRemoveMessage(FsmStateMachine *fsm, int32_t msgType)
{
    if (fsm == NULL || fsm->looper == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    fsm->looper->RemoveMessageCustom(fsm->looper, &fsm->handler,
        RemoveMessageFunc, (void *)msgType);
    return SOFTBUS_OK;
}

int32_t LnnFsmTransactState(FsmStateMachine *fsm, FsmState *state)
{
    if (fsm == NULL || fsm->looper == NULL || state == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMessageToFsm(fsm, FSM_CTRL_MSG_CHANGE_STATE, 0, 0, state);
}
