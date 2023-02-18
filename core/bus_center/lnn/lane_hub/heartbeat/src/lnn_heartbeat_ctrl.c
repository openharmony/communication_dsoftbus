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

#include "lnn_heartbeat_ctrl.h"

#include <string.h>

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_ohos_account.h"

#include "softbus_adapter_ble_gatt.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "lnn_net_builder.h"
#include "softbus_utils.h"
#include "lnn_heartbeat_utils.h"

/*
* This macro is used to control that the heartbeat can be started
* only when the account is logged in or there is a trusted relationship with other devices.
*/
#ifdef HB_CONDITION_HAS_TRUSTED_RELATION
#undef HB_CONDITION_HAS_TRUSTED_RELATION
#endif

#define HB_LOOPBACK_IP "127.0.0.1"
SoftBusScreenState g_screenState = SOFTBUS_SCREEN_UNKNOWN;
static int64_t g_lastScreenOnTime;
static int64_t g_lastScreenOffTime;

SoftBusScreenState GetScreenState(void)
{
    return g_screenState;
}

void SetScreenState(SoftBusScreenState state)
{
    g_screenState = state;
}
static void HbIpAddrChangeEventHandler(const LnnEventBasicInfo *info)
{
    char localIp[IP_LEN] = {0};

    if (info == NULL || info->event != LNN_EVENT_IP_ADDR_CHANGED) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB ip addr change evt handler get invalid param");
        return;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, localIp, IP_LEN) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB get local ip err");
        return;
    }
    if (strcmp(localIp, HB_LOOPBACK_IP) == 0 &&
        LnnEnableHeartbeatByType(HEARTBEAT_TYPE_TCP_FLUSH, false) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB ctrl disable tcp flush fail");
        return;
    }
    if (LnnEnableHeartbeatByType(HEARTBEAT_TYPE_TCP_FLUSH, true) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB ctrl enable tcp flush fail");
        return;
    }
}

static void HbBtStateChangeEventHandler(const LnnEventBasicInfo *info)
{
    int32_t ret;

    if (info == NULL || info->event != LNN_EVENT_BT_STATE_CHANGED) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB bt state change evt handler get invalid param");
        return;
    }
    const LnnMonitorBtStateChangedEvent *event = (const LnnMonitorBtStateChangedEvent *)info;
    SoftBusBtState btState = (SoftBusBtState)event->status;
    switch (btState) {
        case SOFTBUS_BLE_TURN_ON:
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB get SOFTBUS_BLE_TURN_ON");
            if (LnnEnableHeartbeatByType(HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1, true) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB ctrl enable ble heartbeat fail");
                return;
            }
            ret = LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_SINGLE, false);
            if (ret != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB start ble heartbeat fail, ret=%d", ret);
                return;
            }
            break;
        case SOFTBUS_BLE_TURN_OFF:
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB get SOFTBUS_BLE_TURN_OFF");
            if (LnnEnableHeartbeatByType(HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1, false) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB ctrl disable ble heartbeat fail");
                return;
            }
            ret = LnnStopHeartbeatByType(HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1);
            if (ret != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB stop ble heartbeat fail, ret=%d", ret);
                return;
            }
            break;
        default:
            return;
    }
}

static void HbMasterNodeChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_NODE_MASTER_STATE_CHANGED) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB master node change evt handler get invalid param");
        return;
    }

    const LnnMasterNodeChangedEvent *event = (LnnMasterNodeChangedEvent *)info;
    if (LnnSetHbAsMasterNodeState(event->isMasterNode) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB ctrl change master node state fail");
    }
}

static void SendCheckOffLineMessage(SoftBusScreenState state, LnnHeartbeatType hbType)
{
    int32_t i, infoNum;
    NodeBasicInfo *info = NULL;
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        LLOGE("HB check dev status get online node info failed");
        return;
    }
    if (info == NULL || infoNum == 0) {
        LLOGE("HB check dev status get online node is 0");
        return;
    }
    for (i = 0; i < infoNum; ++i) {
        (void)LnnStopScreenChangeOfflineTiming(info[i].networkId, LnnConvertHbTypeToConnAddrType(hbType));
        if (LnnStartScreenChangeOfflineTiming(info[i].networkId,
            LnnConvertHbTypeToConnAddrType(hbType)) != SOFTBUS_OK) {
            LLOGE("send check offline target msg failed");
        }
    }
    SoftBusFree(info);
}

static void RemoveCheckOffLineMessage(LnnHeartbeatType hbType)
{
    if (hbType <= HEARTBEAT_TYPE_MIN || hbType >= HEARTBEAT_TYPE_MAX) {
        LLOGE("get invalid hbtype param");
        return;
    }
    int32_t i, infoNum;
    NodeBasicInfo *info = NULL;
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        LLOGE("HB check dev status get online node info failed");
        return;
    }
    if (info == NULL || infoNum == 0) {
        LLOGE("HB check dev status get online node is 0");
        return;
    }
    for (i = 0; i < infoNum; ++i) {
        if (LnnStopScreenChangeOfflineTiming(info[i].networkId, LnnConvertHbTypeToConnAddrType(hbType)) != SOFTBUS_OK) {
            LLOGE("stop check offline target msg failed,networkid:%s", AnonymizesNetworkID(info[i].networkId));
        }
    }
    SoftBusFree(info);
}

static void ChangeMediumParamByState(SoftBusScreenState state)
{
    LnnHeartbeatMediumParam param = {
        .type = HEARTBEAT_TYPE_BLE_V1,
    };
    switch (state) {
        case SOFTBUS_SCREEN_ON:
            param.info.ble.scanInterval = SOFTBUS_BLE_SCAN_INTERVAL_P10;
            param.info.ble.scanWindow = SOFTBUS_BLE_SCAN_WINDOW_P10;
            break;
        case SOFTBUS_SCREEN_OFF:
            param.info.ble.scanInterval = SOFTBUS_BLE_SCAN_INTERVAL_P2;
            param.info.ble.scanWindow = SOFTBUS_BLE_SCAN_WINDOW_P2;
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB ctrl reset ble scan medium param get invalid state");
            return;
    }
    if (LnnSetMediumParamBySpecificType(&param) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB ctrl reset ble scan medium param fail");
        return;
    }
    LnnUpdateHeartbeatInfo(UPDATE_SCREEN_STATE_INFO);
}

static void HbScreenStateChangeEventHandler(const LnnEventBasicInfo *info)
{
    int64_t nowTime;
    SoftBusSysTime time = {0};
    if (info == NULL || info->event != LNN_EVENT_SCREEN_STATE_CHANGED) {
        LLOGE("HB screen state evt handler get invalid param");
        return;
    }
    const LnnMonitorScreenStateChangedEvent *event = (LnnMonitorScreenStateChangedEvent *)info;
    SoftBusScreenState oldstate = g_screenState;
    if ((SoftBusScreenState)event->status == SOFTBUS_SCREEN_UNKNOWN) {
        LLOGE("err screen state");
        return;
    }
    g_screenState = (SoftBusScreenState)event->status;
    SoftBusGetTime(&time);
    nowTime = time.sec * HB_TIME_FACTOR + time.usec / HB_TIME_FACTOR;
    if (g_screenState == SOFTBUS_SCREEN_ON) {
        RemoveCheckOffLineMessage(HEARTBEAT_TYPE_BLE_V1);
        ChangeMediumParamByState(g_screenState);
        g_lastScreenOnTime = nowTime;
        if (g_lastScreenOnTime - g_lastScreenOffTime >= HB_OFFLINE_TIME && g_lastScreenOffTime > 0) {
            LLOGI("screen on & screen has been off > 5min");
            int ret = LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_SINGLE, false);
            if (ret != SOFTBUS_OK) {
                LLOGE("HB start ble heartbeat failed, ret = %d", ret);
                return;
            }
        }
    }
    if (g_screenState == SOFTBUS_SCREEN_OFF) {
        if (oldstate == SOFTBUS_SCREEN_ON) {
            g_lastScreenOffTime = nowTime;
            if (StopHeartBeatAdvByTypeNow(HEARTBEAT_TYPE_BLE_V1) != SOFTBUS_OK) {
                LLOGE("HB ctrl disable ble heartbeat failed");
                return;
            }
            ChangeMediumParamByState(g_screenState);
            SendCheckOffLineMessage(g_screenState, HEARTBEAT_TYPE_BLE_V1);
        }
        if (oldstate == SOFTBUS_SCREEN_OFF) {
            LLOGI("screen off happen when screenoff");
        }
    }
}


static void HbToRecoveryNetwork(void)
{
    if (SoftBusGetBtState() != BLE_ENABLE || LnnIsHeartbeatEnable(HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB no need to recovery ble network.");
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB BT has been turned on, enable ble heartbeat process");
    if (LnnEnableHeartbeatByType(HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1, true) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB ctrl enable ble heartbeat to recovery fail");
        return;
    }
}

NO_SANITIZE("cfi") int32_t LnnStartHeartbeatFrameDelay(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) FSM start.");
    if (LnnHbMediumMgrInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB medium manager init fail");
        return SOFTBUS_ERR;
    }
    HbToRecoveryNetwork();
    if (LnnStartNewHbStrategyFsm() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB ctrl start strategy fsm fail");
        return SOFTBUS_ERR;
    }
#ifdef HB_CONDITION_HAS_TRUSTED_RELATION
    if (LnnIsDefaultOhosAccount() && !AuthHasTrustedRelation()) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "no trusted relation, heartbeat(HB) process start later.");
        return SOFTBUS_OK;
    }
#endif
    return LnnStartHeartbeat(0);
}

NO_SANITIZE("cfi") int32_t LnnSetHeartbeatMediumParam(const LnnHeartbeatMediumParam *param)
{
    return LnnSetMediumParamBySpecificType(param);
}

NO_SANITIZE("cfi") int32_t LnnOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType)
{
    if (networkId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB offline timing get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    /* only support ble medium type yet. */
    if (addrType != CONNECTION_ADDR_BLE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB offline timing not support addrType:%d now.", addrType);
        return SOFTBUS_INVALID_PARAM;
    }
    (void)LnnStopOfflineTimingStrategy(networkId, addrType);
    if (LnnStartOfflineTimingStrategy(networkId, addrType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB ctrl start offline timing strategy fail");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) start offline countdown");
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t LnnShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId,
    const GearMode *mode)
{
    if (pkgName == NULL || mode == NULL || callerId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB shift lnn gear get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (targetNetworkId != NULL && !LnnGetOnlineStateById(targetNetworkId, CATEGORY_NETWORK_ID)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB target networkId:%s is offline",
            AnonymizesNetworkID(targetNetworkId));
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB ShiftLnnGear >> [callerId:%s networkId:%s, cycle:%d, "
        "duration:%d, wakeupFlag:%d]", callerId, targetNetworkId != NULL ? AnonymizesNetworkID(targetNetworkId) : "",
        mode->cycle, mode->duration, mode->wakeupFlag);
    if (LnnSetGearModeBySpecificType(callerId, mode, HEARTBEAT_TYPE_BLE_V0) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB ctrl reset medium mode fail");
        return SOFTBUS_ERR;
    }
    if (LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_ADJUSTABLE_PERIOD, false) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB ctrl start adjustable ble heatbeat fail");
        return SOFTBUS_ERR;
    }
    NodeInfo *nodeInfo = LnnGetNodeInfoById(targetNetworkId, CATEGORY_NETWORK_ID);
    if (nodeInfo == NULL) {
        LLOGE("HB get info by networkid failed");
        return SOFTBUS_OK;
    }
    if (AuthFlushDevice(nodeInfo->uuid) != SOFTBUS_OK) {
        LLOGI("HB tcp flush failed, wifi will offline");
        return LnnRequestLeaveSpecific(targetNetworkId, CONNECTION_ADDR_WLAN);
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") void LnnUpdateHeartbeatInfo(LnnHeartbeatUpdateInfoType type)
{
    LnnUpdateSendInfoStrategy(type);
}

NO_SANITIZE("cfi") void LnnHbOnAuthGroupCreated(int32_t groupType)
{
    int32_t ret;

#ifdef HB_CONDITION_HAS_TRUSTED_RELATION
    /* If it is a peer-to-peer group, delay initialization to give BR networking priority. */
    ret = LnnStartHeartbeat(groupType == AUTH_PEER_TO_PEER_GROUP ? HB_START_DELAY_LEN : 0);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB account group created start heartbeat fail, ret=%d", ret);
        return;
    }
#endif
    if (groupType != AUTH_IDENTICAL_ACCOUNT_GROUP) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB not get same account group created.");
        return;
    }
    ret = LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_SINGLE, false);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB account group created send ble heartbeat fail, ret=%d", ret);
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB send once ble broadcast to notify account group created.");
}

NO_SANITIZE("cfi") void LnnHbOnAuthGroupDeleted(void)
{
#ifdef HB_CONDITION_HAS_TRUSTED_RELATION
    if (LnnIsDefaultOhosAccount() && !AuthHasTrustedRelation()) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "no trusted relation, heartbeat(HB) process stop.");
        LnnStopHeartbeatByType(HEARTBEAT_TYPE_UDP | HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1 |
            HEARTBEAT_TYPE_TCP_FLUSH);
        return;
    }
#endif

    int32_t ret = LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_SINGLE, false);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB account group deleted send ble heartbeat fail, ret=%d", ret);
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB send once ble broadcast to notify account group deleted.");
}

NO_SANITIZE("cfi") int32_t LnnInitHeartbeat(void)
{
    if (LnnHbStrategyInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB strategy module init fail!");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_IP_ADDR_CHANGED, HbIpAddrChangeEventHandler) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB regist ip addr change evt handler fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_BT_STATE_CHANGED, HbBtStateChangeEventHandler) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB regist bt state change evt handler fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_NODE_MASTER_STATE_CHANGED, HbMasterNodeChangeEventHandler) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB regist node state change evt handler fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_SCREEN_STATE_CHANGED, HbScreenStateChangeEventHandler) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB regist screen state change evt handler fail!");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) init success");
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") void LnnDeinitHeartbeat(void)
{
    LnnHbStrategyDeinit();
    LnnHbMediumMgrDeinit();
    LnnUnregisterEventHandler(LNN_EVENT_IP_ADDR_CHANGED, HbIpAddrChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_BT_STATE_CHANGED, HbBtStateChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_NODE_MASTER_STATE_CHANGED, HbMasterNodeChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_SCREEN_STATE_CHANGED, HbScreenStateChangeEventHandler);
}
