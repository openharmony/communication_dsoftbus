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
#include "lnn_distributed_net_ledger.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_net_builder.h"
#include "lnn_node_info.h"
#include "message_handler.h"

#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_errcode.h"
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
static int32_t OnStopHeartbeat(FsmStateMachine *fsm, int32_t msgType, void *para);
static int32_t OnSendOneHbBegin(FsmStateMachine *fsm, int32_t msgType, void *para);
static int32_t OnSendOneHbEnd(FsmStateMachine *fsm, int32_t msgType, void *para);
static int32_t OnProcessSendOnce(FsmStateMachine *fsm, int32_t msgType, void *para);

static LnnHeartbeatStateHandler g_hbNoneStateHandler[] = {
    {EVENT_HB_CHECK_DEV_STATUS, OnCheckDevStatus},
    {EVENT_HB_STOP, OnStopHeartbeat},
};

static LnnHeartbeatStateHandler g_normalNodeHandler[] = {
    {EVENT_HB_SEND_ONE_BEGIN, OnSendOneHbBegin},
    {EVENT_HB_SEND_ONE_END, OnSendOneHbEnd},
    {EVENT_HB_CHECK_DEV_STATUS, OnCheckDevStatus},
    {EVENT_HB_AS_MASTER_NODE, OnTransHbFsmState},
    {EVENT_HB_AS_NORMAL_NODE, OnTransHbFsmState},
    {EVENT_HB_STOP, OnStopHeartbeat},
};

static LnnHeartbeatStateHandler g_masterNodeHandler[] = {
    {EVENT_HB_SEND_ONE_BEGIN, OnSendOneHbBegin},
    {EVENT_HB_SEND_ONE_END, OnSendOneHbEnd},
    {EVENT_HB_CHECK_DEV_STATUS, OnCheckDevStatus},
    {EVENT_HB_PROCESS_SEND_ONCE, OnProcessSendOnce},
    {EVENT_HB_AS_MASTER_NODE, OnTransHbFsmState},
    {EVENT_HB_AS_NORMAL_NODE, OnTransHbFsmState},
    {EVENT_HB_STOP, OnStopHeartbeat},
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
static void HbNormalNodeStateEnter(FsmStateMachine *fsm);
static void HbMasterNodeStateEnter(FsmStateMachine *fsm);
static void HbMasterNodeStateExit(FsmStateMachine *fsm);
static bool HbFsmStateProcessFunc(FsmStateMachine *fsm, int32_t msgType, void *para);

static FsmState g_hbState[STATE_HB_INDEX_MAX] = {
    [STATE_HB_NONE_INDEX] = {
        .enter = HbNoneStateEnter,
        .process = HbFsmStateProcessFunc,
        .exit = NULL,
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
    LnnHeartbeatFsm *hbFsm = NULL;

    if (fsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB fsm is null");
        return false;
    }
    hbFsm = TO_HEARTBEAT_FSM(fsm);
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
    if (para != NULL) {
        SoftBusFree(para);
    }
}

static bool HbFsmStateProcessFunc(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    int32_t i, eventNum, ret;
    LnnHeartbeatFsm *hbFsm = NULL;
    LnnHeartbeatStateHandler *stateHandler = NULL;

    if (!CheckHbFsmStateMsgArgs(fsm)) {
        return false;
    }
    hbFsm = TO_HEARTBEAT_FSM(fsm);
    eventNum = g_hbFsmHandler[hbFsm->state].eventNum;
    stateHandler = g_hbFsmHandler[hbFsm->state].stateHandler;

    for (i = 0; i < eventNum; ++i) {
        if (stateHandler[i].eventType != msgType) {
            continue;
        }
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

    if (msgPara->hbType == delMsgPara->hbType &&
        strcmp(msgPara->networkId, delMsgPara->networkId) == 0) {
        SoftBusFree(msgPara);
        return 0;
    }
    return 1;
}

static int32_t RemoveSendOnceMsg(FsmCtrlMsgObj *ctrlMsgObj, SoftBusMessage *delMsg)
{
    LnnProcessSendOnceMsgPara *msgPara = (LnnProcessSendOnceMsgPara *)ctrlMsgObj->obj;
    LnnProcessSendOnceMsgPara *delMsgPara = (LnnProcessSendOnceMsgPara *)delMsg->obj;

    if (((msgPara->hbType & delMsgPara->hbType) == delMsgPara->hbType)  &&
        msgPara->strategyType == delMsgPara->strategyType) {
        SoftBusFree(msgPara);
        return 0;
    }
    return 1;
}

static int32_t RemoveSendOneEndMsg(FsmCtrlMsgObj *ctrlMsgObj, SoftBusMessage *delMsg)
{
    LnnHeartbeatType *hbType = (LnnHeartbeatType *)ctrlMsgObj->obj;
    LnnRemoveSendEndMsgPara *delMsgPara = (LnnRemoveSendEndMsgPara *)delMsg->obj;

    if (*hbType == HEARTBEAT_TYPE_BLE_V0 && delMsgPara->hbType == HEARTBEAT_TYPE_BLE_V1) {
        *delMsgPara->isRemoved = false;
        return 1;
    }
    if ((*hbType == delMsgPara->hbType) ||
        (*hbType == HEARTBEAT_TYPE_BLE_V1 && delMsgPara->hbType == HEARTBEAT_TYPE_BLE_V0)) {
        *delMsgPara->isRemoved = true;
        SoftBusFree(hbType);
        return 0;
    }
    return 1;
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

void LnnRemoveSendEndMsg(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType type, bool *isRemoved)
{
    if (hbFsm == NULL || isRemoved == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB remove send end msg get invalid param");
        return;
    }

    *isRemoved = true;
    LnnRemoveSendEndMsgPara msgPara = {
        .hbType = type,
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

void LnnRemoveProcessSendOnceMsg(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType)
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
    LnnHeartbeatFsm *hbFsm = NULL;
    LnnProcessSendOnceMsgPara *msgPara = NULL;

    if (!CheckHbFsmStateMsgArgs(fsm)) {
        return;
    }
    hbFsm = TO_HEARTBEAT_FSM(fsm);
    hbFsm->state = STATE_HB_MASTER_NODE_INDEX;
    msgPara = (LnnProcessSendOnceMsgPara *)SoftBusMalloc(sizeof(LnnProcessSendOnceMsgPara));
    if (msgPara == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB fsmId(%d) enter master node malloc err", hbFsm->id);
        return;
    }
    msgPara->hbType = hbFsm->hbType;
    msgPara->strategyType = hbFsm->strategyType;
    LnnRemoveProcessSendOnceMsg(hbFsm, hbFsm->hbType, hbFsm->strategyType);
    if (LnnFsmPostMessage(fsm, EVENT_HB_PROCESS_SEND_ONCE, (void *)msgPara) != SOFTBUS_OK) {
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) fsmId(%d) perform as master node", hbFsm->id);
}

static void HbMasterNodeStateExit(FsmStateMachine *fsm)
{
    LnnHeartbeatFsm *hbFsm = NULL;

    if (!CheckHbFsmStateMsgArgs(fsm)) {
        return;
    }
    hbFsm = TO_HEARTBEAT_FSM(fsm);
    LnnRemoveProcessSendOnceMsg(hbFsm, hbFsm->hbType, STRATEGY_HB_SEND_FIXED_PERIOD);
}

static void HbNormalNodeStateEnter(FsmStateMachine *fsm)
{
    GearMode mode = {0};
    LnnHeartbeatFsm *hbFsm = NULL;

    LnnDumpHbMgrRecvList();
    LnnDumpHbOnlineNodeList();
    if (!CheckHbFsmStateMsgArgs(fsm)) {
        return;
    }
    hbFsm = TO_HEARTBEAT_FSM(fsm);
    hbFsm->state = STATE_HB_NORMAL_NODE_INDEX;
    LnnRemoveProcessSendOnceMsg(hbFsm, hbFsm->hbType, STRATEGY_HB_SEND_FIXED_PERIOD);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) fsmId(%d) perform as normal node", hbFsm->id);

    if (LnnGetGearModeBySpecificType(&mode, HEARTBEAT_TYPE_BLE_V1) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB perform normal node get gearmode fail");
        return;
    }
    uint64_t delayMillis = (uint64_t)mode.cycle * HB_TIME_FACTOR + HB_ENABLE_DELAY_LEN;
    if (LnnFsmPostMessageDelay(fsm, EVENT_HB_AS_MASTER_NODE, NULL, delayMillis) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB perform normal node post msg fail");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) try as master node in %" PRIu64 " mecs", delayMillis);
}

static void HbNoneStateEnter(FsmStateMachine *fsm)
{
    LnnHeartbeatFsm *hbFsm = NULL;

    if (!CheckHbFsmStateMsgArgs(fsm)) {
        return;
    }
    hbFsm = TO_HEARTBEAT_FSM(fsm);
    hbFsm->state = STATE_HB_NONE_INDEX;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) fsmId(%d) perform none HB state", hbFsm->id);

    if (LnnHbMediumMgrStop(&hbFsm->hbType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB stop medium manager fail");
        return;
    }
    LnnFsmRemoveMessage(fsm, EVENT_HB_PROCESS_SEND_ONCE);
}

static int32_t OnProcessSendOnce(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    (void)msgType;
    int32_t ret = SOFTBUS_OK;
    LnnHeartbeatFsm *hbFsm = NULL;
    LnnProcessSendOnceMsgPara *msgPara = NULL;
    LnnHeartbeatStrategyManager strategyMgr = {0};

    LnnDumpHbMgrRecvList();
    LnnDumpHbOnlineNodeList();
    if (!CheckHbFsmStateMsgArgs(fsm) || para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process send once get invalid param");
        return SOFTBUS_ERR;
    }
    hbFsm = TO_HEARTBEAT_FSM(fsm);
    msgPara = (LnnProcessSendOnceMsgPara *)para;
    if (LnnGetHbStrategyManager(&strategyMgr, msgPara->hbType, msgPara->strategyType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process send once get strategy fail");
        SoftBusFree(msgPara);
        return SOFTBUS_ERR;
    }
    if (strategyMgr.onProcess != NULL) {
        ret = strategyMgr.onProcess(hbFsm, para);
    }
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process send once fail, hbType:%d, strategyType:%d, ret=%d",
            msgPara->hbType, msgPara->strategyType, ret);
        SoftBusFree(msgPara);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t OnSendOneHbBegin(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    (void)fsm;
    (void)msgType;

    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB send once begin get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnHeartbeatType *hbType = (LnnHeartbeatType *)para;
    if (LnnHbMediumMgrSendBegin(hbType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB send once begin to manager fail");
        SoftBusFree(hbType);
        return SOFTBUS_ERR;
    }
    SoftBusFree(hbType);
    return SOFTBUS_OK;
}

static int32_t OnSendOneHbEnd(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    (void)fsm;
    (void)msgType;

    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB send once end get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnHeartbeatType *hbType = (LnnHeartbeatType *)para;
    if (LnnHbMediumMgrSendEnd(hbType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB send once end to manager fail");
        SoftBusFree(hbType);
        return SOFTBUS_ERR;
    }
    SoftBusFree(hbType);
    return SOFTBUS_OK;
}

static int32_t OnStopHeartbeat(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    (void)fsm;
    (void)msgType;

    if (para == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB stop specific get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    LnnHeartbeatType *hbType = (LnnHeartbeatType *)para;
    if (LnnHbMediumMgrStop(hbType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB stop specific manager fail");
        SoftBusFree(hbType);
        return SOFTBUS_ERR;
    }
    SoftBusFree(hbType);
    return SOFTBUS_OK;
}

static int32_t OnTransHbFsmState(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    (void)para;
    LnnHeartbeatState nextState;
    LnnHeartbeatFsm *hbFsm = NULL;

    switch (msgType) {
        case EVENT_HB_AS_MASTER_NODE:
            nextState = STATE_HB_MASTER_NODE_INDEX;
            break;
        case EVENT_HB_AS_NORMAL_NODE:
            nextState = STATE_HB_NORMAL_NODE_INDEX;
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process transact state get invalid msgType");
            return SOFTBUS_ERR;
    }
    if (!CheckHbFsmStateMsgArgs(fsm)) {
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

static int32_t ProcessLostHeartbeat(const char *networkId, ConnectionAddrType addrType)
{
    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process dev lost networkId is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!LnnGetOnlineStateById(networkId, CATEGORY_NETWORK_ID)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB process dev lost is offline, networkId:%s",
            AnonymizesNetworkID(networkId));
        return SOFTBUS_OK;
    }
    if (LnnHasActiveConnection(networkId, addrType)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB process dev lost in next period, networkId:%s",
            AnonymizesNetworkID(networkId));
        if (LnnOfflineTimingByHeartbeat(networkId, addrType) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process dev lost start new offline timing err");
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB process dev lost, networkId:%s", AnonymizesNetworkID(networkId));
    if (LnnRequestLeaveSpecific(networkId, addrType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process dev lost send request to NetBuilder fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static bool IsTimestampExceedLimit(uint64_t nowTime, uint64_t oldTimeStamp, LnnHeartbeatType hbType)
{
    GearMode mode = {0};
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

static void CheckDevStatusByNetworkId(LnnHeartbeatFsm *hbFsm, const char *networkId, LnnHeartbeatType hbType,
    uint64_t nowTime)
{
    uint64_t oldTimeStamp;
    DiscoveryType discType;

    NodeInfo *nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB check dev status get nodeInfo fail");
        return;
    }
    discType = LnnConvAddrTypeToDiscType(LnnConvertHbTypeToConnAddrType(hbType));
    if (!LnnHasDiscoveryType(nodeInfo, discType)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB check dev status node dont has the discType");
        return;
    }
    if (LnnGetDLHeartbeatTimestamp(networkId, &oldTimeStamp) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB check dev status get timestamp err, networkId:%s",
            AnonymizesNetworkID(networkId));
        return;
    }
    if (!IsTimestampExceedLimit(nowTime, oldTimeStamp, hbType)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB check dev status receive heartbeat in time");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB notify node lost heartbeat, networkId:%s, timestamp:"
        "%" PRIu64 ", now:%" PRIu64, AnonymizesNetworkID(networkId), oldTimeStamp, nowTime);
    if (LnnStopOfflineTimingStrategy(networkId, LnnConvertHbTypeToConnAddrType(hbType)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB check dev status stop offline timing fail");
        return;
    }
    if (ProcessLostHeartbeat(networkId, LnnConvertHbTypeToConnAddrType(hbType)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB process dev lost err, networkId:%s",
            AnonymizesNetworkID(networkId));
    }
}

static int32_t OnCheckDevStatus(FsmStateMachine *fsm, int32_t msgType, void *para)
{
    (void)msgType;
    uint64_t nowTime;
    SoftBusSysTime times = {0};

    SoftBusGetTime(&times);
    nowTime = (uint64_t)times.sec * HB_TIME_FACTOR + (uint64_t)times.usec / HB_TIME_FACTOR;
    if (!CheckHbFsmStateMsgArgs(fsm)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB check dev status get invalid param");
        return SOFTBUS_ERR;
    }
    LnnHeartbeatFsm *hbFsm = TO_HEARTBEAT_FSM(fsm);
    if (para != NULL) {
        LnnCheckDevStatusMsgPara *msgPara = (LnnCheckDevStatusMsgPara *)para;
        CheckDevStatusByNetworkId(hbFsm, msgPara->networkId, msgPara->hbType, nowTime);
        SoftBusFree(msgPara);
        return SOFTBUS_OK;
    }

    int32_t i, infoNum;
    NodeBasicInfo *info = NULL;
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB check dev status get online node info fail");
        return SOFTBUS_ERR;
    }
    if (info == NULL || infoNum == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB check dev status get none online node");
        return SOFTBUS_OK;
    }
    for (i = 0; i < infoNum; ++i) {
        CheckDevStatusByNetworkId(hbFsm, info[i].networkId, hbFsm->hbType, nowTime);
    }
    SoftBusFree(info);
    return SOFTBUS_OK;
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

    if (sprintf_s(hbFsm->fsmName, HB_FSM_NAME_LEN, "LnnHeartbeatFsm-%u", hbFsm->id) == -1) {
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

    hbFsm = SoftBusCalloc(sizeof(LnnHeartbeatFsm));
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
    if (LnnFsmStart(&hbFsm->fsm, g_hbState + STATE_HB_MASTER_NODE_INDEX) != SOFTBUS_OK) {
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

int32_t LnnPostNextSendOnceMsgToHbFsm(LnnHeartbeatFsm *hbFsm, void *obj, uint64_t delayMillis)
{
    if (hbFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post next loop msg get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (delayMillis == 0) {
        return LnnFsmPostMessage(&hbFsm->fsm, EVENT_HB_PROCESS_SEND_ONCE, obj);
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB post next loop msg, delayMillis: %" PRIu64, delayMillis);
    return LnnFsmPostMessageDelay(&hbFsm->fsm, EVENT_HB_PROCESS_SEND_ONCE, obj, delayMillis);
}

static int32_t CreateNewHbTypeObjMsg(LnnHeartbeatType srcType, LnnHeartbeatType **dstType)
{
    *dstType = SoftBusCalloc(sizeof(LnnHeartbeatType));
    if (*dstType == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB new hbType obj msg malloc err");
        return SOFTBUS_MALLOC_ERR;
    }
    **dstType = srcType;
    return SOFTBUS_OK;
}

int32_t LnnPostSendBeginMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType type)
{
    LnnHeartbeatType *newType = NULL;

    if (hbFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post send begin msg get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (CreateNewHbTypeObjMsg(type, &newType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post send begin msg create obj para err");
        return SOFTBUS_ERR;
    }
    return LnnFsmPostMessage(&hbFsm->fsm, EVENT_HB_SEND_ONE_BEGIN, (void *)newType);
}

int32_t LnnPostSendEndMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType type, uint64_t delayMillis)
{
    LnnHeartbeatType *newType = NULL;

    if (hbFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post send end msg get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (CreateNewHbTypeObjMsg(type, &newType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post send end msg create obj para err");
        return SOFTBUS_ERR;
    }
    return LnnFsmPostMessageDelay(&hbFsm->fsm, EVENT_HB_SEND_ONE_END, (void *)newType, delayMillis);
}

int32_t LnnPostStopMsgToHbFsm(LnnHeartbeatFsm *hbFsm, LnnHeartbeatType type)
{
    LnnHeartbeatType *newType = NULL;

    if (hbFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post stop msg get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (CreateNewHbTypeObjMsg(type, &newType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post stop msg create obj para err");
        return SOFTBUS_ERR;
    }
    return LnnFsmPostMessage(&hbFsm->fsm, EVENT_HB_STOP, (void *)newType);
}

int32_t LnnPostTransStateMsgToHbFsm(LnnHeartbeatFsm *hbFsm, bool isMasterNode)
{
    if (hbFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post trans state msg get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnFsmPostMessage(&hbFsm->fsm, isMasterNode ? EVENT_HB_AS_MASTER_NODE : EVENT_HB_AS_NORMAL_NODE, NULL);
}

int32_t LnnPostCheckDevStatusMsgToHbFsm(LnnHeartbeatFsm *hbFsm, const LnnCheckDevStatusMsgPara *para,
    uint64_t delayMillis)
{
    if (hbFsm == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB post check dev status msg get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    return LnnFsmPostMessageDelay(&hbFsm->fsm, EVENT_HB_CHECK_DEV_STATUS, (void *)para, delayMillis);
}
