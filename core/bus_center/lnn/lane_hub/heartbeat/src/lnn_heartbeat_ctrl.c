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
#include "auth_manager.h"
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "device_auth.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_ohos_account.h"

#include "softbus_adapter_ble_gatt.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

/*
* This macro is used to control that the heartbeat can be started
* only when the account is logged in or there is a trusted relationship with other devices.
*/
#ifdef HB_CONDITION_HAS_TRUSTED_RELATION
#undef HB_CONDITION_HAS_TRUSTED_RELATION
#endif

#define HB_LOOPBACK_IP "127.0.0.1"

#define HB_SAME_AUTH_GROUP_INDEX 1
#define HB_POINT_TO_POINT_INDEX 256

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
            param.info.ble.scanInterval = SOFTBUS_BLE_SCAN_INTERVAL_P10;
            param.info.ble.scanWindow = SOFTBUS_BLE_SCAN_WINDOW_P10;
            break;
        case SOFTBUS_SCREEN_OFF:
            param.info.ble.scanInterval = SOFTBUS_BLE_SCAN_INTERVAL_P10;
            param.info.ble.scanWindow = SOFTBUS_BLE_SCAN_WINDOW_P10;
            break;
        default:
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB ctrl reset ble scan medium param get invalid state");
            return;
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

#ifdef HB_CONDITION_HAS_TRUSTED_RELATION
static void HbFreeAccountGroups(char *accountGroups)
{
    if (accountGroups != NULL) {
        SoftBusFree(accountGroups);
    }
}

static bool HbHasTrustedDeviceRelation(void)
{
    uint32_t sameGroupCnt, pointGroupCnt;
    char *accountGroups = NULL;

    /* device auth service inited by auth_manager.c */
    DeviceGroupManager *gmInstance = GetGmInstance();
    if (gmInstance == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB GetGmInstance fail");
        return false;
    }
    if (gmInstance->getJoinedGroups(0, AUTH_APPID, HB_SAME_AUTH_GROUP_INDEX, &accountGroups, &sameGroupCnt) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB getJoinedGroups sameGroupCnt fail");
        HbFreeAccountGroups(accountGroups);
        return false;
    }
    if (gmInstance->getJoinedGroups(0, AUTH_APPID, HB_POINT_TO_POINT_INDEX, &accountGroups, &pointGroupCnt) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB getJoinedGroups pointGroupCnt fail");
        HbFreeAccountGroups(accountGroups);
        return false;
    }
    HbFreeAccountGroups(accountGroups);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB ctrl get sameGroupCnt: %u and pointGroupCnt: %u",
        sameGroupCnt, pointGroupCnt);
    if (LnnIsDefaultOhosAccount() && sameGroupCnt == 0 && pointGroupCnt == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HB no login account, no trusted relationship");
        return false;
    }
    return true;
}
#endif

int32_t LnnStartHeartbeatFrameDelay(void)
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
    if (!HbHasTrustedDeviceRelation()) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "no trusted relation, heartbeat(HB) process start later.");
        return SOFTBUS_OK;
    }
#endif
    return LnnStartHeartbeat();
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
    (void)LnnStopOfflineTimingStrategy(networkId, addrType);
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
    return SOFTBUS_OK;
}

void LnnUpdateHeartbeatInfo(LnnHeartbeatUpdateInfoType type)
{
    LnnUpdateSendInfoStrategy(type);
}

void LnnHbOnAuthGroupCreated(void)
{
    int32_t ret;

#ifdef HB_CONDITION_HAS_TRUSTED_RELATION
    ret = LnnStartHeartbeat();
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB account group created start heartbeat fail, ret=%d", ret);
        return;
    }
#endif
    ret = LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_SINGLE, false);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB account group created send ble heartbeat fail, ret=%d", ret);
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB send once ble broadcast to notify account group created.");
}

void LnnHbOnAuthGroupDeleted(void)
{
#ifdef HB_CONDITION_HAS_TRUSTED_RELATION
    if (!HbHasTrustedDeviceRelation()) {
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

int32_t LnnInitHeartbeat(void)
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

void LnnDeinitHeartbeat(void)
{
    LnnHbStrategyDeinit();
    LnnHbMediumMgrDeinit();
    LnnUnregisterEventHandler(LNN_EVENT_IP_ADDR_CHANGED, HbIpAddrChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_BT_STATE_CHANGED, HbBtStateChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_NODE_MASTER_STATE_CHANGED, HbMasterNodeChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_SCREEN_STATE_CHANGED, HbScreenStateChangeEventHandler);
}
