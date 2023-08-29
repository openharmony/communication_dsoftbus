/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "lnn_heartbeat_fsm.h"

#include <securec.h>
#include <string.h>

#include "bus_center_manager.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_deviceinfo_to_profile.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_net_builder.h"
#include "lnn_node_info.h"
#include "message_handler.h"

#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_hisysevt_bus_center.h"
#include "softbus_log.h"
#include "softbus_utils.h"

#define TO_HEARTBEAT_FSM(ptr) CONTAINER_OF(ptr, LnnHeartbeatFsm, fsm)

typedef int32_t (*LnnHeartbeatEventHandler)(FsmStateMachine *, int32_t, void *);

typedef struct {
    int32_t eventType;
    LnnHeartbeatEventHandler eventHandler;
} LnnHeartbeatStateHandler;

typedef struct {
    int32_t eventNum;
    LnnHeartbeatStateHandler *stateHandler;
} LnnHeartbeatFsmHandler;

static int32_t OnCheckDevStatus(FsmStateMachine *fsm, int32_t msgType, void *para);
static int32_t OnTransHbFsmState(FsmStateMachine *fsm, int32_t msgType, void *para);
static int32_t OnStartHbProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
static int32_t OnStopHbByType(FsmStateMachine *fsm, int32_t msgType, void *para);
static int32_t OnSendOneHbBegin(FsmStateMachine *fsm, int32_t msgType, void *para);
static int32_t OnSendOneHbEnd(FsmStateMachine *fsm, int32_t msgType, void *para);
static int32_t OnProcessSendOnce(FsmStateMachine *fsm, int32_t msgType, void *para);
static int32_t OnSetMediumParam(FsmStateMachine *fsm, int32_t msgType, void *para);
static int32_t OnUpdateSendInfo(FsmStateMachine *fsm, int32_t msgType, void *para);
static int32_t OnScreeOffCheckDevStatus(FsmStateMachine *fsm, int32_t msgType, void *para);
static int32_t OnReStartHbProcess(FsmStateMachine *fsm, int32_t msgType, void *para);
static bool IsSupportBurstFeature(const char *newworkId);

static LnnHeartbeatStateHandler g_hbNoneStateHandler[] = {
    {EVENT_HB_CHECK_DEV_STATUS, OnCheckDevStatus},
    {EVENT_HB_START_PROCESS, OnStartHbProcess},
    {EVENT_HB_STOP_SPECIFIC, OnStopHbByType},
    {EVENT_HB_AS_MASTER_NODE, OnTransHbFsmState},
    {EVENT_HB_AS_NORMAL_NODE, OnTransHbFsmState},
    {EVENT_HB_IN_NONE_STATE, OnTransHbFsmState},
    {EVENT_HB_SCREEN_OFF_CHECK_STATUS, OnScreeOffCheckDevStatus},
};

static LnnHeartbeatStateHandler g_normalNodeHandler[] = {
    {EVENT_HB_SEND_ONE_BEGIN, OnSendOneHbBegin},
    {EVENT_HB_SEND_ONE_END, OnSendOneHbEnd},
    {EVENT_HB_CHECK_DEV_STATUS, OnCheckDevStatus},
    {EVENT_HB_PROCESS_SEND_ONCE, OnProcessSendOnce},
    {EVENT_HB_AS_MASTER_NODE, OnTransHbFsmState},
    {EVENT_HB_AS_NORMAL_NODE, OnTransHbFsmState},
    {EVENT_HB_IN_NONE_STATE, OnTransHbFsmState},
    {EVENT_HB_SET_MEDIUM_PARAM, OnSetMediumParam},
    {EVENT_HB_UPDATE_SEND_INFO, OnUpdateSendInfo},
    {EVENT_HB_STOP_SPECIFIC, OnStopHbByType},
    {EVENT_HB_SCREEN_OFF_CHECK_STATUS, OnScreeOffCheckDevStatus},
    {EVENT_HB_START_PROCESS, OnReStartHbProcess},
};

static LnnHeartbeatStateHandler g_masterNodeHandler[] = {
    {EVENT_HB_SEND_ONE_BEGIN, OnSendOneHbBegin},
    {EVENT_HB_SEND_ONE_END, OnSendOneHbEnd},
    {EVENT_HB_CHECK_DEV_STATUS, OnCheckDevStatus},
    {EVENT_HB_PROCESS_SEND_ONCE, OnProcessSendOnce},
    {EVENT_HB_AS_MASTER_NODE, OnTransHbFsmState},
    {EVENT_HB_AS_NORMAL_NODE, OnTransHbFsmState},
    {EVENT_HB_IN_NONE_STATE, OnTransHbFsmState},
    {EVENT_HB_SET_MEDIUM_PARAM, OnSetMediumParam},
    {EVENT_HB_UPDATE_SEND_INFO, OnUpdateSendInfo},
    {EVENT_HB_STOP_SPECIFIC, OnStopHbByType},
    {EVENT_HB_SCREEN_OFF_CHECK_STATUS, OnScreeOffCheckDevStatus},
    {EVENT_HB_START_PROCESS, OnReStartHbProcess},
};

static LnnHeartbeatFsmHandler g_hbFsmHandler[] = {
    [STATE_HB_NONE_INDEX] = {
        .eventNum = sizeof(g_hbNoneStateHandler) / sizeof(LnnHeartbeatStateHandler),
        .stateHandler = g_hbNoneStateHandler,
    },
    [STATE_HB_NORMAL_NODE_INDEX] = {
        .eventNum = sizeof(g_normalNodeHandler) / sizeof(LnnHeartbeatStateHandler),
        .stateHandler = g_normalNodeHandler,
    },
    [STATE_HB_MASTER_NODE_INDEX] = {
        .eventNum = sizeof(g_masterNodeHandler) / sizeof(LnnHeartbeatStateHandler),
        .stateHandler = g_masterNodeHandler,
    }
};

static void HbNoneStateEnter(FsmStateMachine *fsm);
static void HbNoneStateExit(FsmStateMachine *fsm);
static void HbNormalNodeStateEnter(FsmStateMachine *fsm);
static void HbMasterNodeStateEnter(FsmStateMachine *fsm);
static void HbMasterNodeStateExit(FsmStateMachine *fsm);
static bool HbFsmStateProcessFunc(FsmStateMachine *fsm, int32_t msgType, void *para);

static FsmState g_hbState[STATE_HB_INDEX_MAX] = {
    [STATE_HB_NONE_INDEX] = {
        .enter = HbNoneStateEnter,
        .process = HbFsmStateProcessFunc,
        .exit = HbNoneStateExit,
    },
    [STATE_HB_NORMAL_NODE_INDEX] = {
        .enter = HbNormalNodeStateEnter,
        .process = HbFsmStateProcessFunc,
        .exit = NULL,
    },
    [STATE_HB_MASTER_NODE_INDEX] = {
        .enter = HbMasterNodeStateEnter,
        .process = HbFsmStateProcessFunc,
        .exit = HbMasterNodeStateExit,
    },
};

static bool CheckHbFsmStateMsgArgs(const FsmStateMachine *fsm)
{
    if (fsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB fsm is null");
        return false;
    }
    LnnHeartbeatFsm * hbFsm = TO_HEARTBEAT_FSM(fsm);
    if (hbFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB hbFsm is null");
        return false;
    }
    if (hbFsm->state < STATE_HB_INDEX_MIN || hbFsm->state >= STATE_HB_INDEX_MAX) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB fsmId(%d) is in invalid state=%d", hbFsm->id, hbFsm->state);
        return false;
    }
    return true;
}

static void FreeUnhandledHbMessage(int32_t msgType, void *para)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB free unhandled msg(%d)", msgType);
    if (msgType == EVENT_HB_UPDATE_SEND_INFO) {
        /* this event use pointer to transfer parameters */
        return;
    }
    if (para != NULL) {
        SoftBusFree(para);
    }
}

static bool HbFsmStateProcessFunc(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    int32_t i, eventNum, ret;
    LnnHeartbeatStateHandler *stateHandler = NULL;

    if (!CheckHbFsmStateMsgArgs(fsm) || msgType <= EVENT_HB_MIN || msgType >= EVENT_HB_MAX) {
        FreeUnhandledHbMessage(msgType, para);
        return false;
    }
    LnnHeartbeatFsm * hbFsm = TO_HEARTBEAT_FSM(fsm);
    eventNum = g_hbFsmHandler[hbFsm->state].eventNum;
    stateHandler = g_hbFsmHandler[hbFsm->state].stateHandler;

    for (i = 0; i < eventNum; ++i) {
        if (stateHandler[i].eventType != msgType) {
            continue;
        }
        /* in this case, free the memory of para in eventHandler FUNC */
        ret = (stateHandler[i].eventHandler)(fsm, msgType, para);
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB FSM process msg(%d) fail, ret=%d", msgType, ret);
            return false;
        }
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB FSM process msg(%d) succ, state=%d", msgType, hbFsm->state);
        return true;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB no eventHandler msg(%d) in state=%d", msgType, hbFsm->state);
    FreeUnhandledHbMessage(msgType, para);
    return false;
}

static bool CheckRemoveHbMsgParams(const SoftBusMessage *msg, void *args)
{
    if (msg == NULL || args == NULL) {
        return false;
    }
    FsmCtrlMsgObj *ctrlMsgObj = (FsmCtrlMsgObj *)msg->obj;
    if (ctrlMsgObj == NULL || ctrlMsgObj->obj == NULL) {
        return false;
    }
    SoftBusMessage *delMsg = (SoftBusMessage *)args;
    if (delMsg == NULL || delMsg->obj == NULL) {
        return false;
    }
    return true;
}

static int32_t RemoveCheckDevStatusMsg(FsmCtrlMsgObj *ctrlMsgObj, SoftBusMessage *delMsg)
{
    LnnCheckDevStatusMsgPara *msgPara = (LnnCheckDevStatusMsgPara *)ctrlMsgObj->obj;
    LnnCheckDevStatusMsgPara *delMsgPara = (LnnCheckDevStatusMsgPara *)delMsg->obj;

    if (delMsgPara->hasNetworkId != msgPara->hasNetworkId) {
        return 1;
    }
    if (!delMsgPara->hasNetworkId && msgPara->hbType == delMsgPara->hbType) {
        SoftBusFree(msgPara);
        msgPara = NULL;
        return 0;
    }
    if (delMsgPara->hasNetworkId && msgPara->hbType == delMsgPara->hbType &&
        strcmp(msgPara->networkId, delMsgPara->networkId) == 0) {
        SoftBusFree(msgPara);
        msgPara = NULL;
        return 0;
    }
    return 1;
}

static int32_t RemoveSendOnceMsg(FsmCtrlMsgObj *ctrlMsgObj, SoftBusMessage *delMsg)
{
    LnnProcessSendOnceMsgPara *msgPara = (LnnProcessSendOnceMsgPara *)ctrlMsgObj->obj;
    LnnProcessSendOnceMsgPara *delMsgPara = (LnnProcessSendOnceMsgPara *)delMsg->obj;

    if (((msgPara->hbType & delMsgPara->hbType) == delMsgPara->hbType) &&
        msgPara->strategyType == delMsgPara->strategyType) {
        SoftBusFree(msgPara);
        msgPara = NULL;
        return 0;
    }
    return 1;
}

static int32_t RemoveSendOneEndMsg(FsmCtrlMsgObj *ctrlMsgObj, SoftBusMessage *delMsg)
{
    LnnHeartbeatSendEndData *msgPara = (LnnHeartbeatSendEndData *)ctrlMsgObj->obj;
    LnnRemoveSendEndMsgPara *delMsgPara = (LnnRemoveSendEndMsgPara *)delMsg->obj;

    if (!msgPara->wakeupFlag && delMsgPara->wakeupFlag) {
        *delMsgPara->isRemoved = true;
        SoftBusFree(msgPara);
        msgPara = NULL;
        return SOFTBUS_OK;
    }
    if (msgPara->wakeupFlag && !delMsgPara->wakeupFlag) {
        *delMsgPara->isRemoved = false;
        return SOFTBUS_ERR;
    }
    if (msgPara->isRelay && (msgPara->hbType & HEARTBEAT_TYPE_BLE_V0) != 0) {
        *delMsgPara->isRemoved = true;
        SoftBusFree(msgPara);
        msgPara = NULL;
        return SOFTBUS_OK;
    }
    if (delMsgPara->isRelay && (delMsgPara->hbType & HEARTBEAT_TYPE_BLE_V0) != 0) {
        *delMsgPara->isRemoved = false;
        return SOFTBUS_ERR;
    }
    if ((msgPara->hbType & HEARTBEAT_TYPE_BLE_V1) != 0 && (delMsgPara->hbType & HEARTBEAT_TYPE_BLE_V0) != 0) {
        *delMsgPara->isRemoved = true;
        SoftBusFree(msgPara);
        msgPara = NULL;
        return SOFTBUS_OK;
    }
    if ((msgPara->hbType & HEARTBEAT_TYPE_BLE_V0) != 0 && (delMsgPara->hbType & HEARTBEAT_TYPE_BLE_V1) != 0) {
        *delMsgPara->isRemoved = false;
        return SOFTBUS_ERR;
    }
    if (msgPara->hbType == delMsgPara->hbType && (delMsgPara->hbType & HEARTBEAT_TYPE_BLE_V0) != 0) {
        *delMsgPara->isRemoved = true;
        SoftBusFree(msgPara);
        msgPara = NULL;
        return SOFTBUS_OK;
    }
    if (msgPara->hbType == delMsgPara->hbType && (delMsgPara->hbType & HEARTBEAT_TYPE_BLE_V1) != 0) {
        *delMsgPara->isRemoved = false;
        return SOFTBUS_ERR;
    }
    *delMsgPara->isRemoved = false;
    return SOFTBUS_ERR;
}

static int32_t RemoveScreenOffCheckStatus(FsmCtrlMsgObj *ctrlMsgObj, SoftBusMessage *delMsg)
{
    LnnCheckDevStatusMsgPara *msgPara = (LnnCheckDevStatusMsgPara *)ctrlMsgObj->obj;
    LnnCheckDevStatusMsgPara *delMsgPara = (LnnCheckDevStatusMsgPara *)delMsg->obj;

    if (delMsgPara->hasNetworkId != msgPara->hasNetworkId) {
        return SOFTBUS_ERR;
    }
    if (!delMsgPara->hasNetworkId && msgPara->hbType == delMsgPara->hbType) {
        SoftBusFree(msgPara);
        msgPara = NULL;
        return SOFTBUS_OK;
    }
    if (delMsgPara->hasNetworkId && msgPara->hbType == delMsgPara->hbType &&
        strcmp(msgPara->networkId, delMsgPara->networkId) == 0) {
        SoftBusFree(msgPara);
        msgPara = NULL;
        return SOFTBUS_OK;
    }
    return SOFTBUS_ERR;
}

static int32_t CustomFuncRemoveHbMsg(const SoftBusMessage *msg, void *args)
{
    if (!CheckRemoveHbMsgParams(msg, args)) {
        return 1;
    }

    SoftBusMessage *delMsg = (SoftBusMessage *)args;
    if (msg->what != delMsg->what || msg->arg1 != delMsg->arg1) {
        return 1;
    }
    FsmCtrlMsgObj *ctrlMsgObj = (FsmCtrlMsgObj *)msg->obj;
    switch (delMsg->arg1) {
        case EVENT_HB_CHECK_DEV_STATUS:
            return RemoveCheckDevStatusMsg(ctrlMsgObj, delMsg);
        case EVENT_HB_PROCESS_SEND_ONCE:
            return RemoveSendOnceMsg(ctrlMsgObj, delMsg);
        case EVENT_HB_SEND_ONE_END:
            return RemoveSendOneEndMsg(ctrlMsgObj, delMsg);
        case EVENT_HB_SCREEN_OFF_CHECK_STATUS:
            return RemoveScreenOffCheckStatus(ctrlMsgObj, delMsg);
        default:
            break;
    }
    return 1;
}

static void RemoveHbMsgByCustObj(LnnHeartbeatFsm *hbFsm, LnnHeartbeatEventType evtType, void *obj)
{
    int32_t ret;

    SoftBusMessage removeMsg = {
        .what = FSM_CTRL_MSG_DATA,
        .arg1 = evtType,
        .obj = obj,
    };
    ret = LnnFsmRemoveMessageSpecific(&hbFsm->fsm, CustomFuncRemoveHbMsg, (void *)&removeMsg);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB fsmId(%d) remove offline msg(%d) fail", hbFsm->id, evtType);
    }
}

void LnnRemoveSendEndMsg(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType type, bool wakeupFlag,
    bool isRelay, bool *isRemoved)
{
    if (hbFsm == NULL || isRemoved == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB remove send end msg get invalid param");
        return;
    }

    *isRemoved = true;
    LnnRemoveSendEndMsgPara msgPara = {
        .hbType = type,
        .wakeupFlag = wakeupFlag,
        .isRelay = isRelay,
        .isRemoved = isRemoved,
    };
    RemoveHbMsgByCustObj(hbFsm, EVENT_HB_SEND_ONE_END, (void *)&msgPara);
    msgPara.isRemoved = NULL;
}

void LnnRemoveCheckDevStatusMsg(LnnHeartbeatFsm *hbFsm, LnnCheckDevStatusMsgPara *msgPara)
{
    if (hbFsm == NULL || msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB remove check msg get invalid param");
        return;
    }
    RemoveHbMsgByCustObj(hbFsm, EVENT_HB_CHECK_DEV_STATUS, (void *)msgPara);
}

void LnnRemoveScreenOffCheckStatusMsg(LnnHeartbeatFsm *hbFsm, LnnCheckDevStatusMsgPara *msgPara)
{
    if (hbFsm == NULL || msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB remove check msg get invalid param");
        return;
    }
    RemoveHbMsgByCustObj(hbFsm, EVENT_HB_SCREEN_OFF_CHECK_STATUS, (void *)msgPara);
}

void LnnRemoveProcessSendOnceMsg(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType hbType,
    LnnHeartbeatStrategyType strategyType)
{
    if (hbFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB remove process send once msg get invalid param");
        return;
    }
    LnnProcessSendOnceMsgPara msgPara = {
        .hbType = hbType,
        .strategyType = strategyType,
    };
    RemoveHbMsgByCustObj(hbFsm, EVENT_HB_PROCESS_SEND_ONCE, (void *)&msgPara);
}

static void HbMasterNodeStateEnter(FsmStateMachine *fsm)
{
    if (!CheckHbFsmStateMsgArgs(fsm)) {
        return;
    }
    LnnHeartbeatFsm *hbFsm = TO_HEARTBEAT_FSM(fsm);
    hbFsm->state = STATE_HB_MASTER_NODE_INDEX;
    LnnProcessSendOnceMsgPara *msgPara = (LnnProcessSendOnceMsgPara *)SoftBusMalloc(sizeof(LnnProcessSendOnceMsgPara));
    if (msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB fsmId(%d) enter master node malloc err", hbFsm->id);
        return;
    }
    msgPara->hbType = hbFsm->hbType;
    msgPara->strategyType = hbFsm->strategyType;
    msgPara->isRelay = false;
    msgPara->isSyncData = false;
    LnnRemoveProcessSendOnceMsg(hbFsm, hbFsm->hbType, hbFsm->strategyType);
    if (LnnFsmPostMessage(fsm, EVENT_HB_PROCESS_SEND_ONCE, (void *)msgPara) != SOFTBUS_OK) {
        SoftBusFree(msgPara);
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) fsmId(%d) perform as master node", hbFsm->id);
}

static void HbMasterNodeStateExit(FsmStateMachine *fsm)
{
    if (!CheckHbFsmStateMsgArgs(fsm)) {
        return;
    }
    LnnHeartbeatFsm *hbFsm = TO_HEARTBEAT_FSM(fsm);
    LnnRemoveProcessSendOnceMsg(hbFsm, hbFsm->hbType, STRATEGY_HB_SEND_FIXED_PERIOD);
}

static void HbNormalNodeStateEnter(FsmStateMachine *fsm)
{
    LnnDumpHbMgrRecvList();
    LnnDumpHbOnlineNodeList();
    if (!CheckHbFsmStateMsgArgs(fsm)) {
        return;
    }
    LnnHeartbeatFsm *hbFsm = TO_HEARTBEAT_FSM(fsm);
    hbFsm->state = STATE_HB_NORMAL_NODE_INDEX;
    LnnRemoveProcessSendOnceMsg(hbFsm, hbFsm->hbType, STRATEGY_HB_SEND_FIXED_PERIOD);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) fsmId(%d) perform as normal node", hbFsm->id);
}

static void HbNoneStateEnter(FsmStateMachine *fsm)
{
    if (!CheckHbFsmStateMsgArgs(fsm)) {
        return;
    }
    LnnHeartbeatFsm *hbFsm = TO_HEARTBEAT_FSM(fsm);
    hbFsm->state = STATE_HB_NONE_INDEX;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) fsmId(%d) perform none HB state", hbFsm->id);

    if (LnnHbMediumMgrStop(&hbFsm->hbType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB stop medium manager fail");
        return;
    }
    LnnFsmRemoveMessage(fsm, EVENT_HB_PROCESS_SEND_ONCE);
}

static void HbNoneStateExit(FsmStateMachine *fsm)
{
    if (!CheckHbFsmStateMsgArgs(fsm)) {
        return;
    }
    LnnFsmPostMessage(fsm, EVENT_HB_UPDATE_SEND_INFO, (void *)(uintptr_t)UPDATE_HB_ACCOUNT_INFO);
    LnnFsmPostMessage(fsm, EVENT_HB_UPDATE_SEND_INFO, (void *)(uintptr_t)UPDATE_HB_NETWORK_INFO);
}

static int32_t OnProcessSendOnce(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    (void)msgType;
    int32_t ret = SOFTBUS_ERR;
    LnnHeartbeatFsm *hbFsm = NULL;
    LnnHeartbeatStrategyManager strategyMgr = {0};

    LnnDumpHbMgrRecvList();
    LnnDumpHbOnlineNodeList();
    LnnProcessSendOnceMsgPara *msgPara = (LnnProcessSendOnceMsgPara *)para;
    if (msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process send once get invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    do {
        if (!CheckHbFsmStateMsgArgs(fsm)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process send once get invalid fsm");
            break;
        }
        hbFsm = TO_HEARTBEAT_FSM(fsm);
        if (LnnGetHbStrategyManager(&strategyMgr, msgPara->hbType, msgPara->strategyType) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process send once get strategy fail");
            break;
        }
        if (strategyMgr.onProcess != NULL) {
            ret = strategyMgr.onProcess(hbFsm, para);
        } else {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB process send once get NULL process FUNC");
            break;
        }
        if (ret != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process send once fail, hbType:%d, strategyType:%d, "
                "ret=%d", msgPara->hbType, msgPara->strategyType, ret);
            break;
        }
        ret = SOFTBUS_OK;
    } while (false);
    SoftBusFree(msgPara);
    return ret;
}

static void ReportSendBroadcastResultEvt(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "report send broadcast result evt enter");
    if (SoftBusRecordDiscoveryResult(SEND_BROADCAST, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "report send broadcast result fail");
    }
}

static int32_t OnSendOneHbBegin(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    (void)fsm;
    (void)msgType;
    int32_t ret = SOFTBUS_ERR;

    LnnHeartbeatSendBeginData *custData = (LnnHeartbeatSendBeginData *)para;
    if (custData == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB send once begin get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    do {
        if (LnnHbMediumMgrSendBegin(custData) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB send once begin to manager fail");
            LnnCheckDevStatusMsgPara checkMsg = {.hbType = custData->hbType, .hasNetworkId = false};
            LnnRemoveCheckDevStatusMsg(TO_HEARTBEAT_FSM(fsm), &checkMsg);
            break;
        }
        ret = SOFTBUS_OK;
        ReportSendBroadcastResultEvt();
    } while (false);
    SoftBusFree(custData);
    return ret;
}

static int32_t OnSendOneHbEnd(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    (void)msgType;
    int32_t ret = SOFTBUS_ERR;

    LnnHeartbeatSendEndData *custData = (LnnHeartbeatSendEndData *)para;
    if (custData == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB send once end get invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    do {
        if (!CheckHbFsmStateMsgArgs(fsm)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB send once end get invalid fsm");
            break;
        }
        if (LnnHbMediumMgrSendEnd(custData) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB send once end to manager fail");
            (void)LnnFsmRemoveMessage(fsm, EVENT_HB_SEND_ONE_END);
            (void)LnnFsmRemoveMessage(fsm, EVENT_HB_CHECK_DEV_STATUS);
            break;
        }
        ret = SOFTBUS_OK;
    } while (false);
    SoftBusFree(custData);
    return ret;
}

static int32_t OnStartHbProcess(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    (void)msgType;
    (void)para;
    if (!CheckHbFsmStateMsgArgs(fsm)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB start process get invalid fsm");
        return SOFTBUS_ERR;
    }
    LnnHeartbeatFsm *hbFsm = TO_HEARTBEAT_FSM(fsm);
    LnnFsmPostMessage(&hbFsm->fsm, EVENT_HB_AS_MASTER_NODE, NULL);
    if (LnnIsHeartbeatEnable(HEARTBEAT_TYPE_BLE_V0)) {
        /* Send once ble v0 heartbeat to recovery ble network. */
        LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_SINGLE, false);
    }
    return SOFTBUS_OK;
}

static int32_t OnReStartHbProcess(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    (void)msgType;
    (void)para;

    if (!CheckHbFsmStateMsgArgs(fsm)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB start process get invalid fsm");
        return SOFTBUS_ERR;
    }
    if (LnnIsHeartbeatEnable(HEARTBEAT_TYPE_BLE_V0)) {
        LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_SINGLE, false);
    }
    return SOFTBUS_OK;
}

static int32_t OnStopHbByType(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    (void)msgType;
    int32_t ret = SOFTBUS_ERR;

    LnnHeartbeatType *hbType = (LnnHeartbeatType *)para;
    if (hbType == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB stop specific get invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    do {
        if (!CheckHbFsmStateMsgArgs(fsm)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB stop specific get invalid fsm");
            break;
        }
        if (LnnHbMediumMgrStop(hbType) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB stop specific manager fail");
            break;
        }
        LnnHeartbeatFsm *hbFsm = TO_HEARTBEAT_FSM(fsm);
        if ((*hbType & HEARTBEAT_TYPE_BLE_V0) != 0) {
            LnnFsmRemoveMessage(&hbFsm->fsm, EVENT_HB_CHECK_DEV_STATUS);
            LnnRemoveProcessSendOnceMsg(hbFsm, HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_SINGLE);
            LnnRemoveProcessSendOnceMsg(hbFsm, HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_ADJUSTABLE_PERIOD);
            LnnFsmRemoveMessage(&hbFsm->fsm, EVENT_HB_SEND_ONE_END);
        }
        ret = SOFTBUS_OK;
    } while (false);
    SoftBusFree(hbType);
    return ret;
}

static int32_t OnSetMediumParam(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    (void)fsm;
    (void)msgType;
    int32_t ret;

    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB set medium param get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    ret = LnnHbMediumMgrSetParam((const LnnHeartbeatMediumParam *)para);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB set medium param process fail, ret:%d", ret);
    }
    SoftBusFree(para);
    return ret;
}

static int32_t OnUpdateSendInfo(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    (void)fsm;
    (void)msgType;

    return LnnHbMediumMgrUpdateSendInfo((LnnHeartbeatUpdateInfoType)(uintptr_t)para);
}

static void TryAsMasterNodeNextLoop(FsmStateMachine *fsm)
{
    uint64_t delayMillis;
    GearMode mode;
    (void)memset_s(&mode, sizeof(GearMode), 0, sizeof(GearMode));
    if (LnnGetGearModeBySpecificType(&mode, HEARTBEAT_TYPE_BLE_V1) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB try as master node get gearmode fail");
        return;
    }
    delayMillis = (uint64_t)mode.cycle * HB_TIME_FACTOR + HB_NOTIFY_DEV_LOST_DELAY_LEN;
    if (LnnFsmPostMessageDelay(fsm, EVENT_HB_AS_MASTER_NODE, NULL, delayMillis) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB try as master node post msg fail");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) try as master node in %" PRIu64 " msec", delayMillis);
}

static int32_t OnTransHbFsmState(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    (void)para;
    LnnHeartbeatState nextState;
    LnnHeartbeatFsm *hbFsm = NULL;

    if (!CheckHbFsmStateMsgArgs(fsm)) {
        return SOFTBUS_INVALID_PARAM;
    }
    switch (msgType) {
        case EVENT_HB_AS_MASTER_NODE:
            nextState = STATE_HB_MASTER_NODE_INDEX;
            LnnFsmRemoveMessage(fsm, EVENT_HB_AS_NORMAL_NODE);
            break;
        case EVENT_HB_AS_NORMAL_NODE:
            nextState = STATE_HB_NORMAL_NODE_INDEX;
            LnnFsmRemoveMessage(fsm, EVENT_HB_AS_MASTER_NODE);
            TryAsMasterNodeNextLoop(fsm);
            break;
        case EVENT_HB_IN_NONE_STATE:
            nextState = STATE_HB_NONE_INDEX;
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process transact state get invalid msgType");
            return SOFTBUS_ERR;
    }
    hbFsm = TO_HEARTBEAT_FSM(fsm);
    if (hbFsm->state == nextState) {
        return SOFTBUS_OK;
    }
    if (LnnFsmTransactState(fsm, g_hbState + nextState) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process transact fsm state fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static bool ProcOfflineWithoutSoftbus(const char *networkId, ConnectionAddrType addrType)
{
    NodeInfo node;
    (void)memset_s(&node, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &node) != SOFTBUS_OK) {
        LLOGW("can not find node");
        return false;
    }
    LLOGD("node deviceTypeId:%d", node.deviceInfo.deviceTypeId);
    if (node.deviceInfo.deviceTypeId == TYPE_PC_ID &&
        strcmp(node.networkId, node.deviceInfo.deviceUdid) == 0) {
        LLOGI("remove node because lost heartbeat");
        DeleteFromProfile(node.deviceInfo.deviceUdid);
        LnnRemoveNode(node.deviceInfo.deviceUdid);
        return true;
    }
    return false;
}

static int32_t ProcessLostHeartbeat(const char *networkId, ConnectionAddrType addrType, bool isWakeUp)
{
    char udidHash[HB_SHORT_UDID_HASH_HEX_LEN + 1] = {0};
    char *anoyNetworkId = NULL;
    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process dev lost networkId is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (ProcOfflineWithoutSoftbus(networkId, addrType)) {
        LLOGI("proc offline, that device online without softbus");
        return SOFTBUS_OK;
    }
    if (!LnnGetOnlineStateById(networkId, CATEGORY_NETWORK_ID)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB process dev lost is offline, networkId:%s",
            ToSecureStrDeviceID(networkId, &anoyNetworkId));
        SoftBusFree(anoyNetworkId);
        return SOFTBUS_OK;
    }
    if (LnnHasActiveConnection(networkId, addrType)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB process dev lost in next period, networkId:%s",
            ToSecureStrDeviceID(networkId, &anoyNetworkId));
        SoftBusFree(anoyNetworkId);
        if (LnnOfflineTimingByHeartbeat(networkId, addrType) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process dev lost start new offline timing err");
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    }
    if (IsSupportBurstFeature(networkId) && isWakeUp) {
        LLOGI("HB is support burst and is not wakeup, don't check");
        return SOFTBUS_OK;
    }
    const char *udid = LnnConvertDLidToUdid(networkId, CATEGORY_NETWORK_ID);
    (void)LnnGenerateHexStringHash((const unsigned char *)udid, udidHash, HB_SHORT_UDID_HASH_HEX_LEN);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB process dev lost, udidHash:%s, networkId:%s",
        AnonymizesUDID(udidHash), ToSecureStrDeviceID(networkId, &anoyNetworkId));
    SoftBusFree(anoyNetworkId);
    if (LnnRequestLeaveSpecific(networkId, addrType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process dev lost send request to NetBuilder fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static bool IsTimestampExceedLimit(uint64_t nowTime, uint64_t oldTimeStamp, LnnHeartbeatType hbType)
{
    GearMode mode;
    (void)memset_s(&mode, sizeof(GearMode), 0, sizeof(GearMode));
    uint64_t offlineToleranceLen;

    switch (hbType) {
        case HEARTBEAT_TYPE_BLE_V0:
            if ((nowTime - oldTimeStamp) <= HB_CHECK_OFFLINE_TOLERANCE_LEN) {
                return false;
            }
            break;
        case HEARTBEAT_TYPE_BLE_V1:
            if (LnnGetGearModeBySpecificType(&mode, HEARTBEAT_TYPE_BLE_V1) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB is timestamp exceed limit get Gearmode err");
                return false;
            }
            /* BLE_V1 have priority over BLE_V0 */
            offlineToleranceLen = (uint64_t)mode.cycle * HB_TIME_FACTOR + HB_CHECK_DELAY_LEN + HB_SEND_ONCE_LEN;
            if (nowTime - oldTimeStamp <= offlineToleranceLen) {
                return false;
            }
            break;
        default:
            break;
    }
    return true;
}

static bool IsSupportBurstFeature(const char *networkId)
{
    uint64_t localFeature;
    uint64_t peerFeature;
    if (LnnGetLocalNumU64Info(NUM_KEY_FEATURE_CAPA, &localFeature) != SOFTBUS_OK ||
        LnnGetRemoteNumU64Info(networkId, NUM_KEY_FEATURE_CAPA, &peerFeature) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "get local or remote feature fail");
        return false;
    }
    if (IsFeatureSupport(localFeature, BIT_BLE_SUPPORT_SENSORHUB_HEARTBEAT) &&
        IsFeatureSupport(peerFeature, BIT_BLE_SUPPORT_SENSORHUB_HEARTBEAT)) {
        return true;
    }
    return false;
}

static void CheckDevStatusByNetworkId(LnnHeartbeatFsm *hbFsm, const char *networkId, LnnCheckDevStatusMsgPara *msgPara,
    uint64_t nowTime)
{
    uint64_t oldTimeStamp;
    DiscoveryType discType;

    LnnHeartbeatType hbType = msgPara->hbType;
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &nodeInfo) != SOFTBUS_OK) {
        LLOGE("HB check dev status get nodeInfo fail");
        return;
    }
    discType = LnnConvAddrTypeToDiscType(LnnConvertHbTypeToConnAddrType(hbType));
    if (!LnnHasDiscoveryType(&nodeInfo, discType)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB check dev status node networkId:%s dont has discType:%d",
            AnonymizesNetworkID(networkId), discType);
        return;
    }
    if (LnnGetDLHeartbeatTimestamp(networkId, &oldTimeStamp) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB check dev status get timestamp err, networkId:%s",
            AnonymizesNetworkID(networkId));
        return;
    }
    if (!IsTimestampExceedLimit(nowTime, oldTimeStamp, hbType)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB check dev status receive heartbeat in time, networkId:%s, "
            "now:%" PRIu64 ", old:%" PRIu64, AnonymizesNetworkID(networkId), nowTime, oldTimeStamp);
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB notify node lost heartbeat, networkId:%s, timestamp:"
        "%" PRIu64 ", now:%" PRIu64, AnonymizesNetworkID(networkId), oldTimeStamp, nowTime);
    if (LnnStopOfflineTimingStrategy(networkId, LnnConvertHbTypeToConnAddrType(hbType)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB check dev status stop offline timing fail");
        return;
    }
    if (ProcessLostHeartbeat(networkId, LnnConvertHbTypeToConnAddrType(hbType), msgPara->isWakeUp) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process dev lost err, networkId:%s",
            AnonymizesNetworkID(networkId));
    }
}

static void CheckDevStatusForScreenOff(LnnHeartbeatFsm *hbFsm, const char *networkId,
    LnnHeartbeatType hbType, uint64_t nowTime)
{
    (void)hbFsm;
    uint64_t oldTimeStamp;
    if (LnnHasActiveConnection(networkId, LnnConvertHbTypeToConnAddrType(hbType))) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB process screen off dev lost in next period, networkId:%s",
            AnonymizesNetworkID(networkId));
        if (LnnStartScreenChangeOfflineTiming(networkId, LnnConvertHbTypeToConnAddrType(hbType)) != SOFTBUS_OK) {
            LLOGE("HB process screen off dev lost start new offline timing err");
        }
        return;
    }
    if (LnnGetDLHeartbeatTimestamp(networkId, &oldTimeStamp) != SOFTBUS_OK) {
        LLOGE("hb check dev status get timestamp err");
        return;
    }
    if ((nowTime - oldTimeStamp) <= (HB_OFFLINE_PERIOD * HB_OFFLINE_TIME)) {
        LLOGI("hb check dev status , receive heartbeat in 2 * period time");
        if (GetScreenState() == SOFTBUS_SCREEN_OFF && LnnStartScreenChangeOfflineTiming(networkId,
        LnnConvertHbTypeToConnAddrType(hbType)) != SOFTBUS_OK) {
            LLOGI("post next period screen off offline check msg");
        }
        return;
    }
    LLOGW("the screen has been closed for more than 2 cycles, networkId:%s, will offline",
        AnonymizesNetworkID(networkId));
    if (!LnnGetOnlineStateById(networkId, CATEGORY_NETWORK_ID)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB process dev lost is offline, networkId:%s",
            AnonymizesNetworkID(networkId));
        return;
    }
    if (IsSupportBurstFeature(networkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "target device support burst, screen off don't need offline");
        return;
    }
    if (LnnRequestLeaveSpecific(networkId, LnnConvertHbTypeToConnAddrType(hbType)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process dev lost send request to NetBuilder fail");
        return;
    }
}

static int32_t OnCheckDevStatus(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    (void)msgType;
    int32_t ret = SOFTBUS_ERR;
    uint64_t nowTime;
    SoftBusSysTime times = {0};

    LnnCheckDevStatusMsgPara *msgPara = (LnnCheckDevStatusMsgPara *)para;
    if (msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB check dev status get invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    do {
        if (GetScreenState() == SOFTBUS_SCREEN_OFF) {
            ret = SOFTBUS_OK;
            LLOGI("screen if off, dont need hb check");
            break;
        }
        SoftBusGetTime(&times);
        nowTime = (uint64_t)times.sec * HB_TIME_FACTOR + (uint64_t)times.usec / HB_TIME_FACTOR;
        if (!CheckHbFsmStateMsgArgs(fsm)) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB check dev status get invalid fsm");
            break;
        }
        LnnHeartbeatFsm *hbFsm = TO_HEARTBEAT_FSM(fsm);
        if (msgPara->hasNetworkId) {
            CheckDevStatusByNetworkId(hbFsm, msgPara->networkId, msgPara, nowTime);
            ret = SOFTBUS_OK;
            break;
        }

        int32_t i, infoNum;
        NodeBasicInfo *info = NULL;
        if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
            break;
        }
        if (info == NULL || infoNum == 0) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB check dev status get none online node");
            ret = SOFTBUS_OK;
            break;
        }
        for (i = 0; i < infoNum; ++i) {
            if (LnnIsLSANode(&info[i])) {
                continue;
            }
            CheckDevStatusByNetworkId(hbFsm, info[i].networkId, msgPara, nowTime);
        }
        SoftBusFree(info);
        ret = SOFTBUS_OK;
    } while (false);
    SoftBusFree(msgPara);
    return ret;
}

static int32_t OnScreeOffCheckDevStatus(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    (void)msgType;
    int32_t ret = SOFTBUS_OK;
    uint64_t nowTime;
    SoftBusSysTime times = {0};
    LnnCheckDevStatusMsgPara *msgPara = (LnnCheckDevStatusMsgPara *)para;
    if (msgPara == NULL) {
        LLOGE("HB check dev status get invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    do {
        SoftBusGetTime(&times);
        nowTime = (uint64_t)times.sec * HB_TIME_FACTOR + (uint64_t)times.usec / HB_TIME_FACTOR;
        if (!CheckHbFsmStateMsgArgs(fsm)) {
            LLOGE("HB check dev status get invalid fsm");
            ret = SOFTBUS_ERR;
            break;
        }
        LnnHeartbeatFsm *hbFsm = TO_HEARTBEAT_FSM(fsm);
        if (msgPara->hasNetworkId) {
            CheckDevStatusForScreenOff(hbFsm, msgPara->networkId, msgPara->hbType, nowTime);
            break;
        }
        int32_t infoNum;
        NodeBasicInfo *info = NULL;
        if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
            LLOGE("HB check dev status get online node info fail");
            ret = SOFTBUS_ERR;
            break;
        }
        if (info == NULL || infoNum == 0) {
            LLOGI("HB check dev status get none online node");
            break;
        }
        for (int32_t i = 0; i < infoNum; ++i) {
            if (LnnIsLSANode(&info[i])) {
                continue;
            }
            CheckDevStatusForScreenOff(hbFsm, info[i].networkId, msgPara->hbType, nowTime);
        }
        SoftBusFree(info);
    } while (false);
    SoftBusFree(msgPara);
    return ret;
}

void LnnDestroyHeartbeatFsm(LnnHeartbeatFsm *hbFsm)
{
    if (hbFsm == NULL) {
        return;
    }
    if (hbFsm->fsm.looper != NULL) {
        DestroyLooper(hbFsm->fsm.looper);
        hbFsm->fsm.looper = NULL;
    }
    SoftBusFree(hbFsm);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB destroy heartbeat fsmId(%u)", hbFsm->id);
}

static void DeinitHbFsmCallback(FsmStateMachine *fsm)
{
    LnnHeartbeatFsm *hbFsm = NULL;

    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB fsm deinit callback enter");
    if (!CheckHbFsmStateMsgArgs(fsm)) {
        return;
    }
    hbFsm = TO_HEARTBEAT_FSM(fsm);
    LnnDestroyHeartbeatFsm(hbFsm);
}

static int32_t InitHeartbeatFsm(LnnHeartbeatFsm *hbFsm)
{
    int32_t i;

    if (sprintf_s(hbFsm->fsmName, HB_FSM_NAME_LEN, "LnnHbFsm-%u", hbFsm->id) == -1) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB format fsm name fail");
        return SOFTBUS_ERR;
    }
    SoftBusLooper *looper = CreateNewLooper("Heartbeat-Looper");
    if (looper == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB create looper fail");
        return SOFTBUS_ERR;
    }
    if (LnnFsmInit(&hbFsm->fsm, looper, hbFsm->fsmName, DeinitHbFsmCallback) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB init lnn fsm fail");
        return SOFTBUS_ERR;
    }
    for (i = 0; i < STATE_HB_INDEX_MAX; ++i) {
        LnnFsmAddState(&hbFsm->fsm, &g_hbState[i]);
    }
    return SOFTBUS_OK;
}

LnnHeartbeatFsm *LnnCreateHeartbeatFsm(void)
{
    LnnHeartbeatFsm *hbFsm = NULL;

    hbFsm = (LnnHeartbeatFsm *)SoftBusCalloc(sizeof(LnnHeartbeatFsm));
    if (hbFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB malloc fsm fail");
        return NULL;
    }
    ListInit(&hbFsm->node);
    if (InitHeartbeatFsm(hbFsm) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB init fsm fail");
        LnnDestroyHeartbeatFsm(hbFsm);
        return NULL;
    }
    hbFsm->state = STATE_HB_NONE_INDEX;
    return hbFsm;
}

int32_t LnnStartHeartbeatFsm(LnnHeartbeatFsm *hbFsm)
{
    if (hbFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB start fsm is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnFsmStart(&hbFsm->fsm, g_hbState + STATE_HB_NONE_INDEX) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB start fsmId(%u) failed", hbFsm->id);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB fsmId(%u) is starting", hbFsm->id);
    return SOFTBUS_OK;
}

int32_t LnnStopHeartbeatFsm(LnnHeartbeatFsm *hbFsm)
{
    if (hbFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB stop fsm is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (LnnFsmStop(&hbFsm->fsm) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB stop fsmId(%u) failed", hbFsm->id);
        return SOFTBUS_ERR;
    }
    return LnnFsmDeinit(&hbFsm->fsm);
}

int32_t LnnPostNextSendOnceMsgToHbFsm(LnnHeartbeatFsm *hbFsm, const LnnProcessSendOnceMsgPara *para,
    uint64_t delayMillis)
{
    LnnProcessSendOnceMsgPara *dupPara = NULL;

    if (hbFsm == NULL || para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post next loop msg get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    dupPara = (LnnProcessSendOnceMsgPara *)SoftBusMalloc(sizeof(LnnProcessSendOnceMsgPara));
    if (dupPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post next loop msg malloc dupPara fail");
        return SOFTBUS_MALLOC_ERR;
    }
    *dupPara = *para;
    if (LnnFsmPostMessageDelay(&hbFsm->fsm, EVENT_HB_PROCESS_SEND_ONCE, (void *)dupPara, delayMillis) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post next loop msg to hbFsm fail");
        SoftBusFree(dupPara);
        return SOFTBUS_ERR;
    }
    LnnNotifyHBRepeat();
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB post next loop msg, delayMillis: %" PRIu64, delayMillis);
    return SOFTBUS_OK;
}

int32_t LnnPostSendBeginMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType type,
    bool wakeupFlag, LnnProcessSendOnceMsgPara *msgPara, uint64_t delayMillis)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "LnnPostSendBeginMsgToHbFsm enter hbType=%d, isSyncData=%d",
        type, msgPara->isSyncData);
    LnnHeartbeatSendBeginData *custData = NULL;

    if (hbFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post send begin msg get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    custData = (LnnHeartbeatSendBeginData *)SoftBusCalloc(sizeof(LnnHeartbeatSendBeginData));
    if (custData == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB new hbType obj msg malloc err");
        return SOFTBUS_MALLOC_ERR;
    }
    custData->hbType = type;
    custData->wakeupFlag = wakeupFlag;
    custData->isRelay = msgPara->isRelay;
    custData->isSyncData = msgPara->isSyncData;
    custData->isFirstBegin = delayMillis == 0 ? true : false;
    if (LnnFsmPostMessageDelay(&hbFsm->fsm, EVENT_HB_SEND_ONE_BEGIN, (void *)custData, delayMillis) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post send begin msg to hbFsm fail");
        SoftBusFree(custData);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnPostSendEndMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatSendEndData *custData,
    uint64_t delayMillis)
{
    LnnHeartbeatSendEndData *dupData = NULL;
    if (hbFsm == NULL || custData == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post send end msg get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "LnnPostSendEndMsgToHbFsm enter hbType=%d", custData->hbType);
    dupData = (LnnHeartbeatSendEndData *)SoftBusCalloc(sizeof(LnnHeartbeatSendEndData));
    if (dupData == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post send end msg malloc error");
        return SOFTBUS_MALLOC_ERR;
    }
    *dupData = *custData;
    if (LnnFsmPostMessageDelay(&hbFsm->fsm, EVENT_HB_SEND_ONE_END, (void *)dupData, delayMillis) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post send end msg to hbFsm fail");
        SoftBusFree(dupData);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnPostStartMsgToHbFsm(LnnHeartbeatFsm *hbFsm, uint64_t delayMillis)
{
    if (hbFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post start msg get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnFsmPostMessageDelay(&hbFsm->fsm, EVENT_HB_START_PROCESS, NULL, delayMillis);
}

int32_t LnnPostStopMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType type)
{
    LnnHeartbeatType *newType = NULL;

    if (hbFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post stop msg get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    newType = (LnnHeartbeatType *)SoftBusCalloc(sizeof(LnnHeartbeatType));
    if (newType == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post stop msg malloc newType err");
        return SOFTBUS_MALLOC_ERR;
    }
    *newType = type;
    if (LnnFsmPostMessage(&hbFsm->fsm, EVENT_HB_STOP_SPECIFIC, (void *)newType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post stop msg to hbFsm fail");
        SoftBusFree(newType);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnPostTransStateMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatEventType evtType)
{
    if (hbFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post trans state msg get invalid hbFsm");
        return SOFTBUS_INVALID_PARAM;
    }
    if (evtType != EVENT_HB_AS_MASTER_NODE && evtType != EVENT_HB_AS_NORMAL_NODE && evtType != EVENT_HB_IN_NONE_STATE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post trans state msg get invalid evtType");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnFsmPostMessage(&hbFsm->fsm, evtType, NULL);
}

int32_t LnnPostSetMediumParamMsgToHbFsm(LnnHeartbeatFsm *hbFsm, const LnnHeartbeatMediumParam *para)
{
    LnnHeartbeatMediumParam *dupPara = NULL;

    if (hbFsm == NULL || para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post set medium param msg get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    dupPara = (LnnHeartbeatMediumParam *)SoftBusCalloc(sizeof(LnnHeartbeatMediumParam));
    if (dupPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post set medium param msg malloc msgPara fail");
        return SOFTBUS_MALLOC_ERR;
    }
    *dupPara = *para;
    if (LnnFsmPostMessage(&hbFsm->fsm, EVENT_HB_SET_MEDIUM_PARAM, (void *)dupPara) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post set medium param msg to hbFsm fail");
        SoftBusFree(dupPara);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnPostCheckDevStatusMsgToHbFsm(LnnHeartbeatFsm *hbFsm,
    const LnnCheckDevStatusMsgPara *para, uint64_t delayMillis)
{
    LnnCheckDevStatusMsgPara *dupPara = NULL;

    if (hbFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post check dev status msg get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (para == NULL) {
        return LnnFsmPostMessageDelay(&hbFsm->fsm, EVENT_HB_CHECK_DEV_STATUS, NULL, delayMillis);
    }
    dupPara = (LnnCheckDevStatusMsgPara *)SoftBusCalloc(sizeof(LnnCheckDevStatusMsgPara));
    if (dupPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post check dev status msg malloc msgPara fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(dupPara, sizeof(LnnCheckDevStatusMsgPara), para, sizeof(LnnCheckDevStatusMsgPara)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post check dev status msg memcpy_s msgPara fail");
        SoftBusFree(dupPara);
        return SOFTBUS_MEM_ERR;
    }
    if (LnnFsmPostMessageDelay(&hbFsm->fsm, EVENT_HB_CHECK_DEV_STATUS, (void *)dupPara, delayMillis) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post check dev status msg to hbFsm fail");
        SoftBusFree(dupPara);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnPostScreenOffCheckDevMsgToHbFsm(LnnHeartbeatFsm *hbFsm,
    const LnnCheckDevStatusMsgPara *para, uint64_t delayMillis)
{
    LnnCheckDevStatusMsgPara *dupPara = NULL;

    if (hbFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post check dev status msg get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (para == NULL) {
        return LnnFsmPostMessageDelay(&hbFsm->fsm, EVENT_HB_SCREEN_OFF_CHECK_STATUS, NULL, delayMillis);
    }
    dupPara = (LnnCheckDevStatusMsgPara *)SoftBusCalloc(sizeof(LnnCheckDevStatusMsgPara));
    if (dupPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post check dev status msg malloc msgPara fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(dupPara, sizeof(LnnCheckDevStatusMsgPara), para, sizeof(LnnCheckDevStatusMsgPara)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post check dev status msg memcpy_s msgPara fail");
        SoftBusFree(dupPara);
        return SOFTBUS_MEM_ERR;
    }
    if (LnnFsmPostMessageDelay(&hbFsm->fsm, EVENT_HB_SCREEN_OFF_CHECK_STATUS,
        (void *)dupPara, delayMillis) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post check dev status msg to hbFsm fail");
        SoftBusFree(dupPara);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnPostUpdateSendInfoMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatUpdateInfoType type)
{
    if (hbFsm == NULL || type <= UPDATE_HB_INFO_MIN || type >= UPDATE_HB_MAX_INFO) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post update info msg get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnFsmPostMessage(&hbFsm->fsm, EVENT_HB_UPDATE_SEND_INFO, (void *)(uintptr_t)type);
}
