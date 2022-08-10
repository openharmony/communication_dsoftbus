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
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_distributed_net_ledger.h"

#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

#define HB_LOOPBACK_IP "127.0.0.1"

#define HB_SCREEN_ON_BLE_SCAN_INTERVAL 600
#define HB_SCREEN_ON_BLE_SCAN_WINDOW 60
#define HB_SCREEN_OFF_BLE_SCAN_INTERVAL 3000
#define HB_SCREEN_OFF_BLE_SCAN_WINDOW 60

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
            if (LnnEnableHeartbeatByType(HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1, true) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB ctrl enable ble heartbeat fail");
                return;
            }
            ret = LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_SINGLE);
            if (ret != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB start ble heartbeat fail, ret=%d", ret);
                return;
            }
            break;
        case SOFTBUS_BLE_TURN_OFF:
            if (LnnEnableHeartbeatByType(HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1, false) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB ctrl disable ble heartbeat fail");
                return;
            }
            ret = LnnStopHbByType(HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1);
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

static void HbScreenStateChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_SCREEN_STATE_CHANGED) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB screen state evt handler get invalid param");
        return;
    }

    LnnHeartbeatMediumParam param = {
        .type = HEARTBEAT_TYPE_BLE_V1,
    };
    const LnnMonitorScreenStateChangedEvent *event = (LnnMonitorScreenStateChangedEvent *)info;
    SoftBusScreenState state = (SoftBusScreenState)event->status;
    switch (state) {
        case SOFTBUS_SCREEN_ON:
            param.info.ble.scanInterval = HB_SCREEN_ON_BLE_SCAN_INTERVAL;
            param.info.ble.scanWindow = HB_SCREEN_ON_BLE_SCAN_WINDOW;
            break;
        case SOFTBUS_SCREEN_OFF:
            param.info.ble.scanInterval = HB_SCREEN_OFF_BLE_SCAN_INTERVAL;
            param.info.ble.scanWindow = HB_SCREEN_OFF_BLE_SCAN_WINDOW;
            break;
        default:
            break;
    }
    if (!LnnIsHeartbeatEnable(param.type)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB this hbType is not enabled yet", param.type);
        return;
    }
    if (LnnSetMediumParamBySpecificType(&param) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB ctrl reset ble scan medium param fail");
        return;
    }
}

int32_t LnnStartHeartbeatFrameDelay(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) process start.");
    return LnnStartNewHbStrategyFsm();
}

int32_t LnnSetHeartbeatMediumParam(const LnnHeartbeatMediumParam *param)
{
    return LnnSetMediumParamBySpecificType(param);
}

int32_t LnnOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType)
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
    if (LnnStartOfflineTimingStrategy(networkId, addrType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB ctrl start offline timing strategy fail");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) start offline countdown");
    return SOFTBUS_OK;
}

int32_t LnnShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId, const GearMode *mode)
{
    if (pkgName == NULL || mode == NULL || callerId == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB shift gear get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (targetNetworkId != NULL && !LnnGetOnlineStateById(targetNetworkId, CATEGORY_NETWORK_ID)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB target networkId:%s is offline",
            AnonymizesNetworkID(targetNetworkId));
    }
    if (LnnSetGearModeBySpecificType(callerId, mode, HEARTBEAT_TYPE_BLE_V0) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB ctrl reset medium mode fail");
        return SOFTBUS_ERR;
    }
    if (LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_ADJUSTABLE_PERIOD) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB ctrl start adjustable ble heatbeat fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void HbOnAuthGroupChanged(const char *groupId)
{
    (void)groupId;
    int32_t ret;

    ret = LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_SINGLE);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB account group changed send ble heartbeat fail, ret=%d", ret);
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB send once ble broadcast to notify account group changed.");
}

static VerifyCallback g_authVerifyCb = {
    .onGroupCreated = HbOnAuthGroupChanged,
    .onGroupDeleted = HbOnAuthGroupChanged,
};

int32_t LnnInitHeartbeat(void)
{
    if (LnnHbMediumMgrInit() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB medium manager init fail");
        return SOFTBUS_ERR;
    }
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
    if (AuthRegCallback(HEARTBEAT_MONITOR, &g_authVerifyCb) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB regist account group change callback fail");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) init success");
    return SOFTBUS_OK;
}

void LnnDeinitHeartbeat(void)
{
    LnnHbStrategyDeinit();
    LnnHbMediumMgrDeinit();
    LnnUnregisterEventHandler(LNN_EVENT_IP_ADDR_CHANGED, HbIpAddrChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_BT_STATE_CHANGED, HbBtStateChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_NODE_MASTER_STATE_CHANGED, HbMasterNodeChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_SCREEN_STATE_CHANGED, HbScreenStateChangeEventHandler);
}
