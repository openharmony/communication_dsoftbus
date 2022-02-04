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

#include "lnn_heartbeat_fsm.h"

#include <securec.h>
#include <string.h>

#include "bus_center_manager.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_net_builder.h"
#include "lnn_node_info.h"
#include "lnn_node_weight.h"
#include "message_handler.h"

#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

typedef int32_t (*LnnHeartbeatHandler)(const SoftBusMessage *msg);

typedef struct {
    int32_t eventType;
    LnnHeartbeatHandler handler;
} LnnHeartbeatEventHandler;

typedef struct {
    int32_t eventNum;
    LnnHeartbeatEventHandler *eventHandler;
} LnnHeartbeatStateHandler;

static SoftBusHandler g_beatHandler = {0};
static int32_t g_curentState = -1;

static int32_t OnTryAsMasterNode(const SoftBusMessage *msg);
static int32_t OnBeatRepeatCycle(const SoftBusMessage *msg);
static int32_t onBeatMasterNodeEnter(const SoftBusMessage *msg);
static int32_t onBeatMasterNodeExit(const SoftBusMessage *msg);
static int32_t OnElectAsMasterNode(const SoftBusMessage *msg);
static int32_t OnElectAsNormalNode(const SoftBusMessage *msg);
static int32_t OnStartHeartbeat(const SoftBusMessage *msg);
static int32_t OnBeatOnceEnter(const SoftBusMessage *msg);
static int32_t OnBeatOnceOut(const SoftBusMessage *msg);
static int32_t OnStopHeartbeat(const SoftBusMessage *msg);
static int32_t OnBeatDeviceLost(const SoftBusMessage *msg);
static int32_t OnMonitorDeviceStatus(const SoftBusMessage *msg);
static int32_t OnBeatTimeOut(const SoftBusMessage *msg);

static LnnHeartbeatEventHandler g_noneBeatStateHandler[] = {
    {EVENT_BEAT_ENTER, OnStopHeartbeat},
    {EVENT_BEAT_START, OnStartHeartbeat},
    {EVENT_BEAT_EXIT, NULL}
};

static LnnHeartbeatEventHandler g_beatNormalNodeStateHandler[] = {
    {EVENT_BEAT_ENTER, OnTryAsMasterNode},
    {EVENT_BEAT_START, OnStartHeartbeat},
    {EVENT_BEAT_ONCE_ENTER, OnBeatOnceEnter},
    {EVENT_BEAT_DEVICE_LOST, OnBeatDeviceLost},
    {EVENT_BEAT_MONITOR_DEV, OnMonitorDeviceStatus},
    {EVENT_BEAT_AS_MASTER_NODE, OnElectAsMasterNode},
    {EVENT_BEAT_AS_NORMAL_NODE, OnElectAsNormalNode},
    {EVENT_BEAT_ONCE_OUT, OnBeatOnceOut},
    {EVENT_BEAT_STOP, OnStopHeartbeat},
    {EVENT_BEAT_TIMEOUT, OnBeatTimeOut},
    {EVENT_BEAT_EXIT, NULL}
};

static LnnHeartbeatEventHandler g_beatMasterNodeStateHandler[] = {
    {EVENT_BEAT_ENTER, onBeatMasterNodeEnter},
    {EVENT_BEAT_START, OnStartHeartbeat},
    {EVENT_BEAT_ONCE_ENTER, OnBeatOnceEnter},
    {EVENT_BEAT_DEVICE_LOST, OnBeatDeviceLost},
    {EVENT_BEAT_MONITOR_DEV, OnMonitorDeviceStatus},
    {EVENT_BEAT_REPEAT_CYCLE, OnBeatRepeatCycle},
    {EVENT_BEAT_AS_MASTER_NODE, OnElectAsMasterNode},
    {EVENT_BEAT_AS_NORMAL_NODE, OnElectAsNormalNode},
    {EVENT_BEAT_ONCE_OUT, OnBeatOnceOut},
    {EVENT_BEAT_STOP, OnStopHeartbeat},
    {EVENT_BEAT_TIMEOUT, OnBeatTimeOut},
    {EVENT_BEAT_EXIT, onBeatMasterNodeExit}
};

static LnnHeartbeatStateHandler g_beatStatHandler[] = {
    [STATE_NONE_BEAT_INDEX] = {
        .eventNum = sizeof(g_noneBeatStateHandler) / sizeof(LnnHeartbeatEventHandler),
        .eventHandler = g_noneBeatStateHandler,
    },
    [STATE_BEAT_NORMAL_NODE_INDEX] = {
        .eventNum = sizeof(g_beatNormalNodeStateHandler) / sizeof(LnnHeartbeatEventHandler),
        .eventHandler = g_beatNormalNodeStateHandler,
    },
    [STATE_BEAT_MASTER_NODE_INDEX] = {
        .eventNum = sizeof(g_beatMasterNodeStateHandler) / sizeof(LnnHeartbeatEventHandler),
        .eventHandler = g_beatMasterNodeStateHandler,
    }
};

static void FreeBeatHandlerMsg(SoftBusMessage *msg)
{
    if (msg != NULL) {
        if (msg->obj != NULL) {
            SoftBusFree(msg->obj);
        }
        SoftBusFree(msg);
    }
}

static SoftBusMessage *CreateBeatHandlerMsg(int32_t what, uint64_t arg1, uint64_t arg2, void *obj)
{
    SoftBusMessage *msg = (SoftBusMessage *)SoftBusCalloc(sizeof(SoftBusMessage));
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat create handler msg fail");
        return NULL;
    }
    msg->what = what;
    msg->arg1 = arg1;
    msg->arg2 = arg2;
    msg->handler = &g_beatHandler;
    msg->FreeMessage = FreeBeatHandlerMsg;
    msg->obj = obj;
    return msg;
}

static void HeartbeatFsmTransactState(int32_t fromState, int32_t toState, const SoftBusMessage *msg)
{
    LnnHeartbeatEventHandler *eventHandler = g_beatStatHandler[fromState].eventHandler;
    int32_t eventNum = g_beatStatHandler[fromState].eventNum;
    if (eventHandler[eventNum - 1].eventType != EVENT_BEAT_EXIT) {
        return;
    }
    if ((eventHandler[eventNum - 1].handler != NULL) && (eventHandler[eventNum - 1].handler(msg) < 0)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat FSM process exit err");
        return;
    }
    eventHandler = g_beatStatHandler[toState].eventHandler;
    if (eventHandler[0].eventType != EVENT_BEAT_ENTER) {
        return;
    }
    if ((eventHandler[0].handler != NULL) && (eventHandler[EVENT_BEAT_ENTER].handler(msg) < 0)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat FSM process enter err");
        return;
    }
}

static void HeartbeatMsgHandler(SoftBusMessage *msg)
{
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat msg handler invalid param");
        return;
    }
    if (g_curentState < 0 || g_curentState >= STATE_BEAT_INDEX_MAX) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat unknow state or not init");
        return;
    }

    int32_t actIdx, ret;
    int32_t eventType = msg->what;
    int32_t nextStatus = g_curentState;
    int32_t eventNum = g_beatStatHandler[g_curentState].eventNum;
    LnnHeartbeatEventHandler *eventHandler = g_beatStatHandler[g_curentState].eventHandler;
    for (actIdx = 0; actIdx < eventNum; ++actIdx) {
        if (eventHandler[actIdx].eventType == eventType) {
            ret = (eventHandler[actIdx].handler)(msg);
            if (ret < 0) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat FSM process msg(%d) fail, ret=%d", eventType, ret);
                return;
            }
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "beat FSM process msg(%d) done, ret=%d, nowstatus=%d",
                eventType, ret, g_curentState);
            nextStatus = ret;
            break;
        }
    }

    if (actIdx == eventNum) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "no handler what=%d in status=%d", eventType, g_curentState);
    }
    if (nextStatus != g_curentState) {
        HeartbeatFsmTransactState(g_curentState, nextStatus, msg);
    }
    g_curentState = nextStatus;
}

static int32_t PostMsgToBeatHandler(int32_t what, uint64_t arg1, uint64_t arg2, void *obj)
{
    SoftBusMessage *msg = CreateBeatHandlerMsg(what, arg1, arg2, obj);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create softbus beat message fail");
        return SOFTBUS_ERR;
    }
    g_beatHandler.looper->PostMessage(g_beatHandler.looper, msg);
    return SOFTBUS_OK;
}

static int32_t PostDelayMsgToBeatHandler(int32_t what, uint64_t arg1, uint64_t arg2, void *obj, uint64_t delayMillis)
{
    SoftBusMessage *msg = CreateBeatHandlerMsg(what, arg1, arg2, obj);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create softbus beat delay message fail");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "PostDelayMsgToBeatHandler what = %d, delayMillis = %d msec",
        what, delayMillis);
    g_beatHandler.looper->PostMessageDelay(g_beatHandler.looper, msg, delayMillis);
    return SOFTBUS_OK;
}

/* remove message when return 0, else return 1 */
static int32_t RemoveBeatMsgFunc(const SoftBusMessage *msg, void *args)
{
    if (msg == NULL || args == NULL) {
        return 1;
    }
    SoftBusMessage *delMsg = (SoftBusMessage *)args;
    if (delMsg->obj == NULL) {
        if (msg->what == delMsg->what) {
            return 0;
        }
    } else {
        if ((msg->obj != NULL) && (msg->what == delMsg->what) && (msg->arg2 == delMsg->arg2) &&
            (strcmp((const char *)msg->obj, (const char *)delMsg->obj) == 0)) {
            return 0;
        }
    }
    return 1;
}

int32_t LnnPostMsgToBeatFsm(int32_t eventType, void *obj)
{
    if (eventType < 0 || eventType >= EVENT_BEAT_MAX) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostMsgToBeatHandler(eventType, 0, 0, obj);
}

int32_t LnnPostDelayMsgToBeatFsm(int32_t eventType, void *obj, uint64_t delayMillis)
{
    if (eventType < 0 || eventType >= EVENT_BEAT_MAX || delayMillis < 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostDelayMsgToBeatHandler(eventType, 0, 0, obj, delayMillis);
}

int32_t LnnRemoveBeatFsmMsg(int32_t eventType, uint64_t para, void *obj)
{
    if (eventType < 0 || eventType >= EVENT_BEAT_MAX) {
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusMessage *msg = CreateBeatHandlerMsg(eventType, 0, para, obj);
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "create softbus beat message fail");
        return SOFTBUS_ERR;
    }
    g_beatHandler.looper->RemoveMessageCustom(g_beatHandler.looper, &g_beatHandler, RemoveBeatMsgFunc, msg);
    return SOFTBUS_OK;
}

int32_t LnnHeartbeatMonitorDevInfo(ConnectionAddrType type, uint64_t delayMillis)
{
    return PostDelayMsgToBeatHandler(EVENT_BEAT_MONITOR_DEV, 0, (uint64_t)type, NULL, delayMillis);
}

int32_t LnnHeartbeatAsNormalNode(void)
{
    return PostMsgToBeatHandler(EVENT_BEAT_AS_NORMAL_NODE, 0, 0, NULL);
}

int32_t LnnHeartbeatRelayBeat(ConnectionAddrType type)
{
    (void)LnnHeartbeatAsNormalNode();
    return PostMsgToBeatHandler(EVENT_BEAT_ONCE_ENTER, 0, (uint64_t)type, NULL);
}

int32_t LnnHeartbeatNodeOffline(const char *networkId, ConnectionAddrType addrType, uint64_t delayMillis)
{
    if (networkId == NULL || addrType > CONNECTION_ADDR_MAX || delayMillis < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "device networkId is null");
        return SOFTBUS_ERR;
    }
    char *tempId = (char *)SoftBusCalloc(NETWORK_ID_BUF_LEN);
    if (tempId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat malloc networkId err");
        return SOFTBUS_MALLOC_ERR;
    }
    if (strncpy_s(tempId, NETWORK_ID_BUF_LEN, networkId, strlen(networkId)) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat strncpy_s err");
        SoftBusFree(tempId);
        return SOFTBUS_ERR;
    }
    return PostDelayMsgToBeatHandler(EVENT_BEAT_DEVICE_LOST, 0, (uint64_t)addrType, (void *)tempId, delayMillis);
}

int32_t LnnHeartbeatFsmStart(int32_t beatStateIndex, uint64_t delayMillis)
{
    if (beatStateIndex < 0 || beatStateIndex >= STATE_BEAT_INDEX_MAX) {
        return SOFTBUS_INVALID_PARAM;
    }
    return PostDelayMsgToBeatHandler(EVENT_BEAT_START, (uint64_t)beatStateIndex, 0, NULL, delayMillis);
}

int32_t LnnHeartbeatFsmStop(uint64_t delayMillis)
{
    return PostDelayMsgToBeatHandler(EVENT_BEAT_STOP, 0, 0, NULL, delayMillis);
}

int32_t LnnHeartbeatFsmInit(void)
{
    g_curentState = STATE_NONE_BEAT_INDEX;
    g_beatHandler.name = "heartbeat_handler";
    g_beatHandler.HandleMessage = HeartbeatMsgHandler;
    g_beatHandler.looper = GetLooper(LOOP_TYPE_DEFAULT);
    if (g_beatHandler.looper == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat get looper fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void LnnHeartbeatFsmDeinit(void)
{
    g_curentState = -1;
}

static int32_t OnTryAsMasterNode(const SoftBusMessage *msg)
{
    (void)msg;
    LnnDumpBeatMgrUpdateList();
    LnnDumpBeatOnlineNodeList();
    if (g_curentState == STATE_BEAT_MASTER_NODE_INDEX) {
        return STATE_BEAT_MASTER_NODE_INDEX;
    }
    if (LnnRemoveBeatFsmMsg(EVENT_BEAT_AS_MASTER_NODE, 0, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat remove master beat timing error");
        return SOFTBUS_ERR;
    }
    if (LnnRemoveBeatFsmMsg(EVENT_BEAT_REPEAT_CYCLE, 0, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat remove master beat timing error");
        return SOFTBUS_ERR;
    }

    GearMode gearMode;
    if (LnnGetHeartbeatGearMode(&gearMode) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    uint64_t delayMillis = (uint64_t)gearMode.modeCycle * HEARTBEAT_TIME_FACTOR + HEARTBEAT_ENABLE_DELAY_LEN;
    LnnPostDelayMsgToBeatFsm(EVENT_BEAT_AS_MASTER_NODE, NULL, delayMillis);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "beat as normal node");
    return STATE_BEAT_NORMAL_NODE_INDEX;
}

static int32_t onBeatMasterNodeEnter(const SoftBusMessage *msg)
{
    (void)msg;
    char udid[UDID_BUF_LEN] = {0};

    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "get local udid err");
        return SOFTBUS_ERR;
    }
    LnnSetLocalStrInfo(STRING_KEY_MASTER_NODE_UDID, udid);
    LnnSetLocalNumInfo(NUM_KEY_MASTER_NODE_WEIGHT, LnnGetLocalWeight());
    if (LnnRemoveBeatFsmMsg(EVENT_BEAT_REPEAT_CYCLE, 0, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat remove master beat timing err");
        return SOFTBUS_ERR;
    }
    LnnPostDelayMsgToBeatFsm(EVENT_BEAT_REPEAT_CYCLE, NULL, HEARTBEAT_ENABLE_DELAY_LEN);
    return STATE_BEAT_MASTER_NODE_INDEX;
}

static int32_t onBeatMasterNodeExit(const SoftBusMessage *msg)
{
    (void)msg;
    if (LnnRemoveBeatFsmMsg(EVENT_BEAT_REPEAT_CYCLE, 0, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat remove master beat timing err");
        return SOFTBUS_ERR;
    }
    return STATE_BEAT_MASTER_NODE_INDEX;
}

static int32_t OnBeatRepeatCycle(const SoftBusMessage *msg)
{
    (void)msg;
    LnnDumpBeatMgrUpdateList();
    LnnDumpBeatOnlineNodeList();
    PostMsgToBeatHandler(EVENT_BEAT_ONCE_ENTER, 0, CONNECTION_ADDR_MAX, NULL);
    LnnPostDelayMsgToBeatFsm(EVENT_BEAT_TIMEOUT, NULL, HEARTBEAT_MANAGER_TIMEOUT_LEN);

    GearMode gearMode;
    if (LnnGetHeartbeatGearMode(&gearMode) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    uint64_t delayMillis = (uint64_t)gearMode.modeCycle * HEARTBEAT_TIME_FACTOR;
    LnnPostDelayMsgToBeatFsm(EVENT_BEAT_REPEAT_CYCLE, NULL, delayMillis);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "beat as master node");
    return STATE_BEAT_MASTER_NODE_INDEX;
}

static int32_t OnElectAsMasterNode(const SoftBusMessage *msg)
{
    (void)msg;
    g_curentState = STATE_NONE_BEAT_INDEX;
    if (LnnRemoveBeatFsmMsg(EVENT_BEAT_AS_MASTER_NODE, 0, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat remove master beat trans err");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "beat elect as master node");
    return STATE_BEAT_MASTER_NODE_INDEX;
}

static int32_t OnElectAsNormalNode(const SoftBusMessage *msg)
{
    (void)msg;
    g_curentState = STATE_NONE_BEAT_INDEX;
    if (LnnRemoveBeatFsmMsg(EVENT_BEAT_AS_MASTER_NODE, 0, NULL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat remove master beat trans err");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "beat elect as normal node");
    return STATE_BEAT_NORMAL_NODE_INDEX;
}

static int32_t OnBeatOnceEnter(const SoftBusMessage *msg)
{
    if (LnnHeartbeatMgrStart() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "start beat adv or scan fail");
        (void)LnnRemoveBeatFsmMsg(EVENT_BEAT_TIMEOUT, 0, NULL);
        return SOFTBUS_ERR;
    }
    LnnPostDelayMsgToBeatFsm(EVENT_BEAT_ONCE_OUT, NULL, HEARTBEAT_TOCK_TIME_LEN);
    LnnHeartbeatMonitorDevInfo((ConnectionAddrType)msg->arg2, HEARTBEAT_MONITOR_DELAY_LEN);
    return g_curentState;
}

static int32_t OnBeatOnceOut(const SoftBusMessage *msg)
{
    (void)msg;
    if (LnnHeartbeatMgrStopAdv() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "stop once beat adv fail");
        return SOFTBUS_ERR;
    }
    return g_curentState;
}

static int32_t OnStartHeartbeat(const SoftBusMessage *msg)
{
    g_curentState = STATE_NONE_BEAT_INDEX;
    int32_t beatStateIndex = (int32_t)msg->arg1;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "beat start in status: %d", beatStateIndex);
    return beatStateIndex;
}

static int32_t OnStopHeartbeat(const SoftBusMessage *msg)
{
    (void)msg;
    if (LnnHeartbeatMgrStop() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat manager stop fail");
        return SOFTBUS_ERR;
    }
    return STATE_NONE_BEAT_INDEX;
}

static int32_t OnBeatTimeOut(const SoftBusMessage *msg)
{
    (void)msg;
    (void)LnnRemoveBeatFsmMsg(EVENT_BEAT_ONCE_ENTER, 0, NULL);
    (void)LnnRemoveBeatFsmMsg(EVENT_BEAT_ONCE_OUT, 0, NULL);
    return g_curentState;
}

static bool BeatCheckActiveConn(ConnectionAddrType addrType, const char *networkId)
{
    ConnectOption option = {0};
    NodeInfo *nodeInfo = NULL;
    const char *mac = NULL;

    switch (addrType) {
        case CONNECTION_ADDR_WLAN:
        case CONNECTION_ADDR_ETH:
        case CONNECTION_ADDR_BR:
        /* heartbeat dont support this medium type yet, so dont take the dev offline */
            return true;
        case CONNECTION_ADDR_MAX:
        case CONNECTION_ADDR_BLE:
            nodeInfo = LnnGetNodeInfoById(networkId, CATEGORY_NETWORK_ID);
            if (nodeInfo == NULL) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "beat not find node, no need to notify lost");
                return true;
            }
            mac = LnnGetBtMac(nodeInfo);
            if (mac == NULL) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat get bt mac err");
                return true;
            }
            option.type = CONNECT_BR;
            if (strncpy_s(option.info.brOption.brMac, BT_MAC_LEN, mac, strlen(mac)) != EOK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat strncpy_s bt mac err");
                return true;
            }
            break;
        default:
            break;
    }
    return CheckActiveConnection(&option);
}

static int32_t OnBeatDeviceLost(const SoftBusMessage *msg)
{
    ConnectionAddrType addrType = (ConnectionAddrType)msg->arg2;
    const char *networkId = (const char *)msg->obj;

    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat device networkId is null");
        return SOFTBUS_ERR;
    }
    if (BeatCheckActiveConn(addrType, networkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "beat cannot offline dev, set new offline check begin");
        if (LnnOfflineTimingByHeartbeat(networkId, addrType) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat set new offline check err");
            return SOFTBUS_ERR;
        }
        return SOFTBUS_OK;
    }
    if (addrType == CONNECTION_ADDR_MAX) {
    /* heartbeat dont support medium type except ble now, so only offline ble devices */
        if (LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_BLE) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat notify device lost fail");
            return SOFTBUS_ERR;
        }
        return g_curentState;
    }
    if (LnnRequestLeaveSpecific(networkId, addrType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat notify device lost fail");
        return SOFTBUS_ERR;
    }
    return g_curentState;
}

static int32_t OnMonitorDeviceStatus(const SoftBusMessage *msg)
{
    NodeBasicInfo *info = NULL;
    int32_t infoNum, i;
    DiscoveryType discType = LnnGetDiscoveryType(msg->arg2);
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat get node info fail");
        return SOFTBUS_ERR;
    }
    if (info == NULL || infoNum == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "beat no online node");
        return g_curentState;
    }

    GearMode gearMode;
    SoftBusSysTime times;
    SoftBusGetTime(&times);
    uint64_t oldTimeStamp;
    if (LnnGetHeartbeatGearMode(&gearMode) != SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    uint64_t offlineMillis = (uint64_t)gearMode.modeCycle * HEARTBEAT_TIME_FACTOR + HEARTBEAT_ENABLE_DELAY_LEN;
    uint64_t nowTime = (uint64_t)times.sec * HEARTBEAT_TIME_FACTOR + (uint64_t)times.usec / HEARTBEAT_TIME_FACTOR;
    for (i = 0; i < infoNum; i++) {
        NodeInfo *nodeInfo = LnnGetNodeInfoById(info[i].networkId, CATEGORY_NETWORK_ID);
        if (nodeInfo == NULL || (msg->arg2 != CONNECTION_ADDR_MAX && !LnnHasDiscoveryType(nodeInfo, discType))) {
            continue;
        }
        if (LnnGetDistributedHeartbeatTimestamp(info[i].networkId, &oldTimeStamp) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat get timeStamp err, networkId:%s", info[i].networkId);
            continue;
        }
        if ((nowTime - oldTimeStamp) > offlineMillis) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "beat Notify networkId:%s offline, timestamp:%llu, now:%llu",
                info[i].networkId, oldTimeStamp, nowTime);
            if (LnnRemoveBeatFsmMsg(EVENT_BEAT_DEVICE_LOST, msg->arg2, info[i].networkId) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "beat remove offline timing err");
                SoftBusFree(info);
                return SOFTBUS_ERR;
            }
            LnnHeartbeatNodeOffline(info[i].networkId, (ConnectionAddrType)msg->arg2, 0);
        }
    }
    SoftBusFree(info);
    return g_curentState;
}
