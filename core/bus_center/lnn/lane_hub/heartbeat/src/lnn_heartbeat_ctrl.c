/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <securec.h>
#include <stdatomic.h>
#include <string.h>

#include "anonymizer.h"
#include "auth_device_common_key.h"
#include "auth_interface.h"
#include "auth_manager.h"
#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_ble_heartbeat.h"
#include "lnn_common_utils.h"
#include "lnn_connection_fsm.h"
#include "lnn_data_cloud_sync.h"
#include "lnn_decision_db.h"
#include "lnn_device_info_recovery.h"
#include "lnn_deviceinfo_to_profile.h"
#include "lnn_devicename_info.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_fast_offline.h"
#include "lnn_feature_capability.h"
#include "lnn_heartbeat_fsm.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_kv_adapter_wrapper.h"
#include "lnn_local_net_ledger.h"
#include "lnn_log.h"
#include "lnn_meta_node_ledger.h"
#include "lnn_net_builder.h"
#include "lnn_network_info.h"
#include "lnn_network_manager.h"
#include "lnn_ohos_account.h"
#include "lnn_parameter_utils.h"
#include "lnn_settingdata_event_monitor.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_broadcast_type.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hisysevt_bus_center.h"
#include "softbus_utils.h"

#define HB_LOOPBACK_IP "127.0.0.1"
#define INVALID_DELAY_TIME (-1)

typedef struct {
    SoftBusBtState btState;
    SoftBusScreenLockState lockState;
    SoftBusScreenState screenState;
    SoftBusAccountState accountState;
    SoftBusUserState backgroundState;
    SoftBusNightModeState nightModeState;
    SoftBusOOBEState OOBEState;
    bool hasTrustedRelation;
    bool heartbeatEnable;
    bool isRequestDisable;
} HbConditionState;

static HbConditionState g_hbConditionState;
static int64_t g_lastScreenOnTime = 0;
static int64_t g_lastScreenOffTime = 0;
static atomic_bool g_enableState = false;
static bool g_isScreenOnOnce = false;
static atomic_bool g_isCloudSyncEnd = false;

static void InitHbConditionState(void)
{
    g_hbConditionState.btState = SOFTBUS_BT_UNKNOWN;
    g_hbConditionState.screenState = SOFTBUS_SCREEN_UNKNOWN;
    g_hbConditionState.lockState = SOFTBUS_SCREEN_LOCK_UNKNOWN;
    // need suit for same account
    g_hbConditionState.accountState = SOFTBUS_ACCOUNT_UNKNOWN;
    g_hbConditionState.backgroundState = SOFTBUS_USER_FOREGROUND;
    g_hbConditionState.nightModeState = SOFTBUS_NIGHT_MODE_UNKNOWN;
    g_hbConditionState.hasTrustedRelation = false;
    g_hbConditionState.isRequestDisable = false;
    g_hbConditionState.heartbeatEnable = false;
    g_hbConditionState.OOBEState = SOFTBUS_OOBE_UNKNOWN;
    LNN_LOGI(LNN_INIT, "condition state:heartbeat=%{public}d", g_hbConditionState.heartbeatEnable);
}

static void InitHbSpecificConditionState(void)
{
    int32_t localDevTypeId = 0;
    if (LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &localDevTypeId) != SOFTBUS_OK) {
        return;
    }
    if (localDevTypeId == TYPE_WATCH_ID) {
        LNN_LOGD(LNN_INIT, "localDevTypeId=%{public}d", localDevTypeId);
        g_hbConditionState.isRequestDisable = true;
    }
}

bool IsHeartbeatEnable(void)
{
    if ((g_hbConditionState.lockState == SOFTBUS_SCREEN_LOCK_UNKNOWN) && IsActiveOsAccountUnlocked()) {
        g_hbConditionState.lockState = SOFTBUS_SCREEN_UNLOCK;
    }
    bool isBtOn = ((g_hbConditionState.btState != SOFTBUS_BLE_TURN_OFF) &&
        (g_hbConditionState.btState != SOFTBUS_BT_UNKNOWN));
    bool isScreenUnlock = g_hbConditionState.lockState == SOFTBUS_SCREEN_UNLOCK;
    bool isLogIn = g_hbConditionState.accountState == SOFTBUS_ACCOUNT_LOG_IN;
    bool isBackground = g_hbConditionState.backgroundState == SOFTBUS_USER_BACKGROUND;
    bool isNightMode = g_hbConditionState.nightModeState == SOFTBUS_NIGHT_MODE_ON;
    bool isOOBEEnd =
        g_hbConditionState.OOBEState == SOFTBUS_OOBE_END || g_hbConditionState.OOBEState == SOFTBUS_FACK_OOBE_END;

    LNN_LOGI(LNN_HEART_BEAT,
        "HB condition state: bt=%{public}d, screenUnlock=%{public}d, account=%{public}d, trustedRelation=%{public}d, "
        "background=%{public}d, nightMode=%{public}d, OOBEEnd=%{public}d, heartbeatEnable=%{public}d, "
        "request=%{public}d",
        isBtOn, isScreenUnlock, isLogIn, g_hbConditionState.hasTrustedRelation, isBackground, isNightMode, isOOBEEnd,
        g_hbConditionState.heartbeatEnable, g_hbConditionState.isRequestDisable);
    return g_hbConditionState.heartbeatEnable && isBtOn && isScreenUnlock && !g_hbConditionState.isRequestDisable &&
        (isLogIn || g_hbConditionState.hasTrustedRelation) && !isBackground && !isNightMode && isOOBEEnd;
}

SoftBusScreenState GetScreenState(void)
{
    return g_hbConditionState.screenState;
}

bool LnnIsCloudSyncEnd(void)
{
    return g_isCloudSyncEnd;
}

void SetScreenState(SoftBusScreenState state)
{
    g_hbConditionState.screenState = state;
}

static void HbRefreshConditionState(void)
{
    if (SoftBusGetBtState() == BLE_ENABLE) {
        g_hbConditionState.btState = SOFTBUS_BLE_TURN_ON;
    }
    LnnUpdateOhosAccount(UPDATE_ACCOUNT_ONLY);
    if (!LnnIsDefaultOhosAccount()) {
        g_hbConditionState.accountState = SOFTBUS_ACCOUNT_LOG_IN;
    }
    if (IsActiveOsAccountUnlocked()) {
        g_hbConditionState.lockState = SOFTBUS_SCREEN_UNLOCK;
    }
    TrustedReturnType ret = AuthHasTrustedRelation();
    if (ret == TRUSTED_RELATION_YES) {
        g_hbConditionState.hasTrustedRelation = true;
    } else if (ret == TRUSTED_RELATION_NO) {
        g_hbConditionState.hasTrustedRelation = false;
    }
    if (g_hbConditionState.lockState == SOFTBUS_SCREEN_UNLOCK &&
        (g_hbConditionState.accountState == SOFTBUS_ACCOUNT_LOG_IN || g_hbConditionState.hasTrustedRelation)) {
        g_hbConditionState.heartbeatEnable = IsEnableSoftBusHeartbeat();
    }
}

static void HbIpAddrChangeEventHandler(const LnnEventBasicInfo *info)
{
    char localIp[IP_LEN] = { 0 };

    if (info == NULL || info->event != LNN_EVENT_IP_ADDR_CHANGED) {
        LNN_LOGE(LNN_HEART_BEAT, "ip addr change evt handler get invalid param");
        return;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, localIp, IP_LEN) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "get local ip err");
        return;
    }
    if (strcmp(localIp, HB_LOOPBACK_IP) == 0 &&
        LnnEnableHeartbeatByType(HEARTBEAT_TYPE_TCP_FLUSH, false) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl disable tcp flush fail");
        return;
    }
    if (LnnEnableHeartbeatByType(HEARTBEAT_TYPE_TCP_FLUSH, true) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl enable tcp flush fail");
        return;
    }
}

static void HbSendCheckOffLineMessage(LnnHeartbeatType hbType)
{
    int32_t i, infoNum;
    NodeBasicInfo *info = NULL;
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "check dev status get online node info failed");
        return;
    }
    if (info == NULL || infoNum == 0) {
        LNN_LOGE(LNN_HEART_BEAT, "check dev status get online node is 0");
        return;
    }
    for (i = 0; i < infoNum; ++i) {
        if (LnnIsLSANode(&info[i])) {
            continue;
        }
        (void)LnnStopScreenChangeOfflineTiming(info[i].networkId, LnnConvertHbTypeToConnAddrType(hbType));
        if (LnnStartScreenChangeOfflineTiming(info[i].networkId, LnnConvertHbTypeToConnAddrType(hbType)) !=
            SOFTBUS_OK) {
            LNN_LOGE(LNN_HEART_BEAT, "send check offline target msg failed");
        }
    }
    SoftBusFree(info);
}

static void HbConditionChanged(bool isOnlySetState)
{
    HbRefreshConditionState();
    bool isEnable = IsHeartbeatEnable();
    if (g_enableState == isEnable) {
        LNN_LOGI(LNN_HEART_BEAT, "ctrl ignore same enable request, isEnable=%{public}d", isEnable);
        return;
    }
    LnnNotifyNetworkStateChanged(isEnable ? SOFTBUS_BLE_NETWORKD_ENABLE : SOFTBUS_BLE_NETWORKD_DISABLE);
    if (LnnEnableHeartbeatByType(HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1 | HEARTBEAT_TYPE_BLE_V3, isEnable) !=
        SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl enable ble heartbeat fail");
        return;
    }
    if (isOnlySetState) {
        LNN_LOGD(LNN_HEART_BEAT, "condition changed only set state");
        g_enableState = isEnable;
        return;
    }
    if (isEnable) {
        LNN_LOGD(LNN_HEART_BEAT, "condition changed to enabled");
        if (LnnStartHbByTypeAndStrategy(
            HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V3, STRATEGY_HB_SEND_SINGLE, false) != SOFTBUS_OK) {
            LNN_LOGE(LNN_HEART_BEAT, "start ble heartbeat fail");
        }
        g_enableState = true;
        LnnStartHeartbeat(0);
    } else {
        LNN_LOGD(LNN_HEART_BEAT, "condition changed to disabled");
        if (LnnStopHeartbeatByType(HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1 | HEARTBEAT_TYPE_BLE_V3) !=
            SOFTBUS_OK) {
            LNN_LOGE(LNN_HEART_BEAT, "stop ble heartbeat fail");
        }
        g_enableState = false;
    }
}

static uint64_t GetDisEnableBleDiscoveryTime(uint64_t modeDuration)
{
    uint64_t timeout = 0ULL;
    if (modeDuration < MIN_DISABLE_BLE_DISCOVERY_TIME) {
        timeout = MIN_DISABLE_BLE_DISCOVERY_TIME;
    } else {
        timeout = (modeDuration > MAX_DISABLE_BLE_DISCOVERY_TIME) ? MAX_DISABLE_BLE_DISCOVERY_TIME : modeDuration;
    }
    return timeout;
}

static void RequestEnableDiscovery(void *para)
{
    (void)para;
    if (!g_hbConditionState.isRequestDisable) {
        LNN_LOGI(LNN_HEART_BEAT, "ble has been enabled, don't need  restore enabled");
        return;
    }
    g_hbConditionState.isRequestDisable = false;
    LNN_LOGI(LNN_HEART_BEAT, "ble has been requestEnable");
    HbConditionChanged(false);
}

static void RequestDisableDiscovery(int64_t timeout)
{
    if (g_hbConditionState.isRequestDisable) {
        LNN_LOGI(LNN_HEART_BEAT, "ble has been requestDisabled, need wait timeout or enabled");
        return;
    }
    if (timeout != INVALID_DELAY_TIME) {
        uint64_t time = GetDisEnableBleDiscoveryTime((uint64_t)timeout);
        if (LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), RequestEnableDiscovery, NULL, time) !=
            SOFTBUS_OK) {
            LNN_LOGI(LNN_HEART_BEAT, "ble has been requestDisabled fail, due to async callback fail");
            return;
        }
    }
    g_hbConditionState.isRequestDisable = true;
    LNN_LOGI(LNN_HEART_BEAT, "ble has been requestDisabled");
    HbConditionChanged(false);
}

static int32_t SameAccountDevDisableDiscoveryProcess(void)
{
    bool addrType[CONNECTION_ADDR_MAX] = {false};
    addrType[CONNECTION_ADDR_BLE] = true;
    if (LnnRequestLeaveByAddrType(addrType, CONNECTION_ADDR_MAX) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "leave ble network fail");
    }
    return LnnSyncBleOfflineMsg();
}

void LnnRequestBleDiscoveryProcess(int32_t strategy, int64_t timeout)
{
    LNN_LOGI(LNN_HEART_BEAT, "LnnRequestBleDiscoveryProcess enter");
    switch (strategy) {
        case REQUEST_DISABLE_BLE_DISCOVERY:
            RequestDisableDiscovery(timeout);
            break;
        case REQUEST_ENABLE_BLE_DISCOVERY:
            RequestEnableDiscovery(NULL);
            break;
        case SAME_ACCOUNT_REQUEST_DISABLE_BLE_DISCOVERY:
            RequestDisableDiscovery(INVALID_DELAY_TIME);
            SameAccountDevDisableDiscoveryProcess();
            break;
        case SAME_ACCOUNT_REQUEST_ENABLE_BLE_DISCOVERY:
            RequestEnableDiscovery(NULL);
            break;
        default:
            LNN_LOGE(LNN_HEART_BEAT, "error strategy, not need to deal. strategy=%{public}d", strategy);
    }
}

static int32_t HbHandleLeaveLnn(void)
{
    int32_t i;
    int32_t infoNum;
    NodeBasicInfo *info = NULL;
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "get online node info failed");
        return SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR;
    }
    if (info == NULL || infoNum == 0) {
        LNN_LOGE(LNN_HEART_BEAT, "get online node is 0");
        return SOFTBUS_NO_ONLINE_DEVICE;
    }
    int32_t ret;
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    for (i = 0; i < infoNum; ++i) {
        ret = LnnGetRemoteNodeInfoById(info[i].networkId, CATEGORY_NETWORK_ID, &nodeInfo);
        if (ret != SOFTBUS_OK) {
            continue;
        }
        if ((nodeInfo.feature & (1 << BIT_SUPPORT_THREE_STATE)) == 0 && SoftBusGetBrState() == BR_DISABLE) {
            LNN_LOGI(LNN_HEART_BEAT, "peer don't support three state and local br off");
            LnnRequestLeaveSpecific(info[i].networkId, CONNECTION_ADDR_BLE);
        }
    }
    SoftBusFree(info);
    return SOFTBUS_OK;
}

static void HbDelaySetNormalScanParam(void *para)
{
    (void)para;
    LnnHeartbeatMediumParam param;
    (void)memset_s(&param, sizeof(LnnHeartbeatMediumParam), 0, sizeof(LnnHeartbeatMediumParam));
    if (g_hbConditionState.screenState == SOFTBUS_SCREEN_OFF && !LnnIsLocalSupportBurstFeature()) {
        param.type = HEARTBEAT_TYPE_BLE_V1;
        param.info.ble.scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P2;
        param.info.ble.scanWindow = SOFTBUS_BC_SCAN_WINDOW_P2;
    } else {
        param.type = HEARTBEAT_TYPE_BLE_V1;
        param.info.ble.scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P10;
        param.info.ble.scanWindow = SOFTBUS_BC_SCAN_WINDOW_P10;
    }
    LNN_LOGI(LNN_HEART_BEAT, "scanInterval=%{public}hu, scanWindow=%{public}hu", param.info.ble.scanInterval,
        param.info.ble.scanWindow);
    if (LnnSetMediumParamBySpecificType(&param) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl reset ble scan medium param fail");
    }
}

static void HbDelaySetHighScanParam(void *para)
{
    (void)para;

    if (g_hbConditionState.screenState == SOFTBUS_SCREEN_OFF) {
        LNN_LOGD(LNN_HEART_BEAT, "screen off, no need handle");
        return;
    }
    LnnHeartbeatMediumParam param = {
        .type = HEARTBEAT_TYPE_BLE_V1,
        .info.ble.scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P25,
        .info.ble.scanWindow = SOFTBUS_BC_SCAN_WINDOW_P25,
    };
    LNN_LOGI(LNN_HEART_BEAT, "scanInterval=%{public}hu, scanWindow=%{public}hu", param.info.ble.scanInterval,
        param.info.ble.scanWindow);
    if (LnnSetMediumParamBySpecificType(&param) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl reset ble scan medium param fail");
    }
}

static void DfxRecordBleTriggerTimestamp(LnnTriggerReason reason)
{
    DfxRecordTriggerTime(reason, EVENT_STAGE_LNN_BLE_TRIGGER);
}

static void HbHandleBleStateChange(SoftBusBtState btState)
{
    g_enableState = false;
    LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_BLE_TURN_ON, state=%{public}d", btState);
    LnnUpdateHeartbeatInfo(UPDATE_BT_STATE_OPEN_INFO);
    ClearAuthLimitMap();
    ClearLnnBleReportExtraMap();
    HbConditionChanged(false);
    if (LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), HbDelaySetHighScanParam, NULL, 0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB async set high param fail");
    }
    if (LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), HbDelaySetNormalScanParam, NULL,
        HB_START_DELAY_LEN + HB_SEND_RELAY_LEN_ONCE) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB async set normal param fail");
    }
    if (LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V3,
        STRATEGY_HB_SEND_ADJUSTABLE_PERIOD, false) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "start ble heartbeat fail");
    }
    if (btState == SOFTBUS_BR_TURN_ON) {
        LnnUpdateHeartbeatInfo(UPDATE_BR_TURN_ON_INFO);
    }
    DfxRecordBleTriggerTimestamp(BLE_TURN_ON);
}

static void HbBtStateChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_BT_STATE_CHANGED) {
        LNN_LOGE(LNN_HEART_BEAT, "bt state change evt handler get invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusBtState btState = (SoftBusBtState)event->status;
    g_hbConditionState.btState = btState;
    switch (btState) {
        case SOFTBUS_BLE_TURN_ON:
        case SOFTBUS_BR_TURN_ON:
            HbHandleBleStateChange(btState);
            break;
        case SOFTBUS_BR_TURN_OFF:
            if (SoftBusGetBtState() == BLE_DISABLE) {
                LNN_LOGE(LNN_HEART_BEAT, "ble is off");
                return;
            }
            g_enableState = false;
            LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_BR_TURN_OFF, state=%{public}d", btState);
            (void)HbHandleLeaveLnn();
            HbConditionChanged(false);
            if (LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V3,
                STRATEGY_HB_SEND_ADJUSTABLE_PERIOD, false) != SOFTBUS_OK) {
                LNN_LOGE(LNN_HEART_BEAT, "start ble heartbeat fail");
            }
            DfxRecordBleTriggerTimestamp(BLE_TURN_OFF);
            break;
        case SOFTBUS_BLE_TURN_OFF:
            LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_BLE_TURN_OFF");
            HbConditionChanged(false);
            DfxRecordBleTriggerTimestamp(BLE_TURN_OFF);
            ClearAuthLimitMap();
            ClearLnnBleReportExtraMap();
            break;
        default:
            return;
    }
}

static void HbLaneVapChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_LANE_VAP_CHANGE) {
        LNN_LOGE(LNN_HEART_BEAT, "invalid param");
        return;
    }
    LnnLaneVapChangeEvent *vap = (LnnLaneVapChangeEvent *)info;
    if (SoftBusGetBtState() == BLE_DISABLE) {
        LNN_LOGE(LNN_HEART_BEAT, "ble is off");
        return;
    }
    LNN_LOGI(LNN_HEART_BEAT, "HB handle vapChange, channel=%{public}d", vap->vapPreferChannel);
    if (LnnStartHbByTypeAndStrategy(
        HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V3, STRATEGY_HB_SEND_SINGLE, false) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "start ble heartbeat fail");
    }
    DfxRecordBleTriggerTimestamp(BLE_LANE_VAP_CHANGED);
}

static void HbMasterNodeChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_NODE_MASTER_STATE_CHANGED) {
        LNN_LOGE(LNN_HEART_BEAT, "master node change evt handler get invalid param");
        return;
    }

    const LnnMasterNodeChangedEvent *event = (LnnMasterNodeChangedEvent *)info;
    if (LnnSetHbAsMasterNodeState(event->isMasterNode) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl change master node state fail");
    }
}

static void HbRemoveCheckOffLineMessage(LnnHeartbeatType hbType)
{
    if (hbType <= HEARTBEAT_TYPE_MIN || hbType >= HEARTBEAT_TYPE_MAX) {
        LNN_LOGE(LNN_HEART_BEAT, "get invalid hbType param");
        return;
    }
    int32_t i, infoNum;
    NodeBasicInfo *info = NULL;
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "check dev status get online node info failed");
        return;
    }
    if (info == NULL || infoNum == 0) {
        LNN_LOGE(LNN_HEART_BEAT, "check dev status get online node is 0");
        return;
    }
    for (i = 0; i < infoNum; ++i) {
        if (LnnIsLSANode(&info[i])) {
            continue;
        }
        if (LnnStopScreenChangeOfflineTiming(info[i].networkId, LnnConvertHbTypeToConnAddrType(hbType)) != SOFTBUS_OK) {
            char *anonyNetworkId = NULL;
            Anonymize(info[i].networkId, &anonyNetworkId);
            LNN_LOGE(LNN_HEART_BEAT, "stop check offline target msg failed, networkId=%{public}s",
                AnonymizeWrapper(anonyNetworkId));
            AnonymizeFree(anonyNetworkId);
        }
    }
    SoftBusFree(info);
}

static void HbChangeMediumParamByState(SoftBusScreenState state)
{
    LnnHeartbeatMediumParam param = {
        .type = HEARTBEAT_TYPE_BLE_V1,
    };
    switch (state) {
        case SOFTBUS_SCREEN_ON:
            param.info.ble.scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P10;
            param.info.ble.scanWindow = SOFTBUS_BC_SCAN_WINDOW_P10;
            break;
        case SOFTBUS_SCREEN_OFF:
            param.info.ble.scanInterval = SOFTBUS_BC_SCAN_INTERVAL_P2;
            param.info.ble.scanWindow = SOFTBUS_BC_SCAN_WINDOW_P2;
            break;
        default:
            LNN_LOGD(LNN_HEART_BEAT, "ctrl reset ble scan medium param get invalid state");
            return;
    }
    if (!LnnIsLocalSupportBurstFeature() && (LnnSetMediumParamBySpecificType(&param) != SOFTBUS_OK)) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl reset ble scan medium param fail");
        return;
    }
    LnnUpdateHeartbeatInfo(UPDATE_SCREEN_STATE_INFO);
}

static void HbDelayConditionChanged(void *para)
{
    (void)para;

    g_isCloudSyncEnd = true;
    LNN_LOGI(LNN_HEART_BEAT, "HB handle delay condition changed");
    LnnUpdateOhosAccount(UPDATE_HEARTBEAT);
    LnnUpdateSendInfoStrategy(UPDATE_HB_ACCOUNT_INFO);
    LnnHbOnTrustedRelationIncreased(AUTH_IDENTICAL_ACCOUNT_GROUP);
    g_hbConditionState.heartbeatEnable = IsEnableSoftBusHeartbeat();
    HbConditionChanged(false);
}

static int32_t HbTryCloudSync(void)
{
    NodeInfo info;

    if (LnnIsDefaultOhosAccount()) {
        LNN_LOGW(LNN_HEART_BEAT, "HB accountId is null, no need sync");
        return SOFTBUS_NOT_LOGIN;
    }
    (void)memset_s(&info, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    if (LnnGetLocalNodeInfoSafe(&info) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "HB save local device info fail");
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
    }
    int32_t ret = LnnLedgerAllDataSyncToDB(&info);
    if (ret == SOFTBUS_OK) {
        LNN_LOGI(LNN_HEART_BEAT, "HB sync to cloud end");
    } else {
        LNN_LOGE(LNN_HEART_BEAT, "HB sync to cloud fail");
    }
    return ret;
}

static void HbScreenOnOnceTryCloudSync(void)
{
    HbRefreshConditionState();
    if (g_hbConditionState.screenState == SOFTBUS_SCREEN_ON && !g_isScreenOnOnce &&
        g_hbConditionState.accountState == SOFTBUS_ACCOUNT_LOG_IN &&
        g_hbConditionState.lockState == SOFTBUS_SCREEN_UNLOCK) {
        LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), HbDelayConditionChanged, NULL,
            HbTryCloudSync() == SOFTBUS_OK ? HB_CLOUD_SYNC_DELAY_LEN : 0);
    }
}

static void DfxRecordScreenChangeTimestamp(LnnTriggerReason reason)
{
    DfxRecordTriggerTime(reason, EVENT_STAGE_LNN_SCREEN_STATE_CHANGED);
}

static void HbScreenOnChangeEventHandler(int64_t nowTime)
{
    LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_SCREEN_ON");
    g_lastScreenOnTime = nowTime;
    g_isScreenOnOnce = true;
    if (LnnIsLocalSupportBurstFeature()) {
        LnnRemoveV0BroadcastAndCheckDev();
    }
    HbRemoveCheckOffLineMessage(HEARTBEAT_TYPE_BLE_V1);
    HbChangeMediumParamByState(g_hbConditionState.screenState);
    if (g_lastScreenOnTime - g_lastScreenOffTime >= HB_SCREEN_ON_COAP_TIME) {
        LNN_LOGD(LNN_HEART_BEAT, "screen on start coap discovery");
        RestartCoapDiscovery();
    }
    int32_t ret = LnnStartHbByTypeAndStrategy(
        HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V3, STRATEGY_HB_SEND_SINGLE, false);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "start ble heartbeat failed, ret=%{public}d", ret);
    }
    DfxRecordScreenChangeTimestamp(SCREEN_ON);
}

static void HbScreenStateChangeEventHandler(const LnnEventBasicInfo *info)
{
    int64_t nowTime;
    SoftBusSysTime time = { 0 };
    if (info == NULL || info->event != LNN_EVENT_SCREEN_STATE_CHANGED) {
        LNN_LOGE(LNN_HEART_BEAT, "screen state evt handler get invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (LnnMonitorHbStateChangedEvent *)info;
    if ((SoftBusScreenState)event->status == SOFTBUS_SCREEN_UNKNOWN) {
        LNN_LOGE(LNN_HEART_BEAT, "get invalid screen state");
        return;
    }
    SoftBusScreenState oldstate = g_hbConditionState.screenState;
    g_hbConditionState.screenState = (SoftBusScreenState)event->status;
    SoftBusGetRealTime(&time);
    nowTime = time.sec * HB_TIME_FACTOR + time.usec / HB_TIME_FACTOR;
    HbScreenOnOnceTryCloudSync();
    if (g_hbConditionState.screenState == SOFTBUS_SCREEN_ON && oldstate != SOFTBUS_SCREEN_ON) {
        (void)LnnUpdateLocalScreenStatus(true);
        HbScreenOnChangeEventHandler(nowTime);
        return;
    }
    if (g_hbConditionState.screenState == SOFTBUS_SCREEN_OFF && oldstate != SOFTBUS_SCREEN_OFF) {
        LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_SCREEN_OFF");
        g_lastScreenOffTime = nowTime;
        (void)LnnUpdateLocalScreenStatus(false);
        if (!LnnIsLocalSupportBurstFeature()) {
            if (LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_SINGLE, false) != SOFTBUS_OK) {
                LNN_LOGE(LNN_HEART_BEAT, "start ble heartbeat failed");
                return;
            }
            DfxRecordScreenChangeTimestamp(SCREEN_OFF);
        }
        if (LnnStopHeartBeatAdvByTypeNow(HEARTBEAT_TYPE_BLE_V1) != SOFTBUS_OK) {
            LNN_LOGE(LNN_HEART_BEAT, "ctrl disable ble heartbeat failed");
            return;
        }
        HbChangeMediumParamByState(g_hbConditionState.screenState);
        HbSendCheckOffLineMessage(HEARTBEAT_TYPE_BLE_V1);
    }
}

static void HbScreenLockChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_SCREEN_LOCK_CHANGED) {
        LNN_LOGE(LNN_HEART_BEAT, "lock state change evt handler get invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusScreenLockState lockState = (SoftBusScreenLockState)event->status;
    if (lockState == SOFTBUS_USER_UNLOCK) {
        LNN_LOGI(LNN_HEART_BEAT, "user unlocked");
        (void)LnnGenerateCeParams();
        AuthLoadDeviceKey();
        LnnUpdateOhosAccount(UPDATE_ACCOUNT_ONLY);
        if (!LnnIsDefaultOhosAccount()) {
            LnnNotifyAccountStateChangeEvent(SOFTBUS_ACCOUNT_LOG_IN);
        }
    }
    lockState = lockState == SOFTBUS_USER_UNLOCK ? SOFTBUS_SCREEN_UNLOCK : lockState;
    if (g_hbConditionState.lockState == SOFTBUS_SCREEN_UNLOCK) {
        LNN_LOGI(LNN_HEART_BEAT, "screen unlocked once already, ignoring this event");
        return;
    }
    g_hbConditionState.lockState = lockState;
    LNN_LOGI(LNN_HEART_BEAT, "ScreenLock state: heartbeat=%{public}d", g_hbConditionState.heartbeatEnable);
    switch (lockState) {
        case SOFTBUS_SCREEN_UNLOCK:
            LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_SCREEN_UNLOCK");
            HbRefreshConditionState();
            if (g_hbConditionState.screenState == SOFTBUS_SCREEN_ON &&
                g_hbConditionState.accountState == SOFTBUS_ACCOUNT_LOG_IN) {
                LnnAsyncCallbackDelayHelper(
                    GetLooper(LOOP_TYPE_DEFAULT), HbDelaySetHighScanParam, NULL, HB_CLOUD_SYNC_DELAY_LEN);
                LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), HbDelaySetNormalScanParam, NULL,
                    HB_CLOUD_SYNC_DELAY_LEN + HB_START_DELAY_LEN + HB_SEND_RELAY_LEN_ONCE);
                LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), HbDelayConditionChanged, NULL,
                    HbTryCloudSync() == SOFTBUS_OK ? HB_CLOUD_SYNC_DELAY_LEN : 0);
            }
            if (g_hbConditionState.screenState == SOFTBUS_SCREEN_ON &&
                g_hbConditionState.accountState != SOFTBUS_ACCOUNT_LOG_IN) {
                HbConditionChanged(false);
            }
            break;
        case SOFTBUS_SCREEN_LOCK:
            LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_SCREEN_LOCK");
            break;
        default:
            return;
    }
}

static void HbAccountStateChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_ACCOUNT_CHANGED) {
        LNN_LOGE(LNN_HEART_BEAT, "account state change evt handler get invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusAccountState accountState = (SoftBusAccountState)event->status;
    g_hbConditionState.accountState = accountState;
    switch (accountState) {
        case SOFTBUS_ACCOUNT_LOG_IN:
            LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_ACCOUNT_LOG_IN");
            LnnAsyncCallbackDelayHelper(
                GetLooper(LOOP_TYPE_DEFAULT), HbDelaySetHighScanParam, NULL, HB_CLOUD_SYNC_DELAY_LEN);
            LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), HbDelaySetNormalScanParam, NULL,
                HB_CLOUD_SYNC_DELAY_LEN + HB_START_DELAY_LEN + HB_SEND_RELAY_LEN_ONCE);
            LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), HbDelayConditionChanged, NULL,
                HbTryCloudSync() == SOFTBUS_OK ? HB_CLOUD_SYNC_DELAY_LEN : 0);
            break;
        case SOFTBUS_ACCOUNT_LOG_OUT:
            LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_ACCOUNT_LOG_OUT");
            LnnSetCloudAbility(false);
            if (LnnDeleteSyncToDB() != SOFTBUS_OK) {
                LNN_LOGE(LNN_LEDGER, "HB clear local cache fail");
            }
            LnnOnOhosAccountLogout();
            HbConditionChanged(false);
            break;
        default:
            return;
    }
}

static void HbHomeGroupStateChangeEventHandler(const LnnEventBasicInfo *info)
{
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusHomeGroupState homeGroupState = (SoftBusHomeGroupState)event->status;
    LnnUpdateHeartbeatInfo(UPDATE_HB_NETWORK_INFO);
    switch (homeGroupState) {
        case SOFTBUS_HOME_GROUP_CHANGE:
            LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_HOME_GROUP_CHANGE");
            HbConditionChanged(false);
            break;
        case SOFTBUS_HOME_GROUP_LEAVE:
            LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_HOME_GROUP_LEAVE");
            break;
        default:
            return;
    }
}

static void HbDifferentAccountEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_DIF_ACCOUNT_DEV_CHANGED) {
        LNN_LOGE(LNN_HEART_BEAT, "account state change evt handler get invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusDifferentAccountState difAccountState = (SoftBusDifferentAccountState)event->status;
    if ((LnnEventType)difAccountState == LNN_EVENT_DIF_ACCOUNT_DEV_CHANGED) {
        HbConditionChanged(false);
    }
}

static void HbUserBackgroundEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_USER_STATE_CHANGED) {
        LNN_LOGE(LNN_HEART_BEAT, "user background state change evt handler get invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusUserState userState = (SoftBusUserState)event->status;
    switch (userState) {
        case SOFTBUS_USER_FOREGROUND:
            g_hbConditionState.backgroundState = userState;
            LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_USER_FOREGROUND");
            HbConditionChanged(false);
            break;
        case SOFTBUS_USER_BACKGROUND:
            g_hbConditionState.backgroundState = userState;
            LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_USER_BACKGROUND");
            HbConditionChanged(false);
            break;
        default:
            return;
    }
}

static void HbNightModeStateEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_NIGHT_MODE_CHANGED) {
        LNN_LOGE(LNN_HEART_BEAT, "user background state change evt handler get invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusNightModeState nightModeState = (SoftBusNightModeState)event->status;
    g_hbConditionState.nightModeState = nightModeState;
    switch (nightModeState) {
        case SOFTBUS_NIGHT_MODE_ON:
            LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_NIGHT_MODE_ON");
            HbConditionChanged(false);
            break;
        case SOFTBUS_NIGHT_MODE_OFF:
            LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_NIGHT_MODE_OFF");
            HbConditionChanged(false);
            break;
        default:
            return;
    }
}

static void HbOOBEStateEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_OOBE_STATE_CHANGED) {
        LNN_LOGE(LNN_HEART_BEAT, "OOBE state change evt handler get invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusOOBEState state = (SoftBusOOBEState)event->status;
    LNN_LOGI(
        LNN_HEART_BEAT, "HB handle oobe state=%{public}d, g_state=%{public}d", state, g_hbConditionState.OOBEState);
    switch (state) {
        case SOFTBUS_OOBE_RUNNING:
            if (g_hbConditionState.OOBEState != SOFTBUS_FACK_OOBE_END) {
                g_hbConditionState.OOBEState = state;
                HbConditionChanged(false);
            }
            break;
        case SOFTBUS_FACK_OOBE_END:
            if (g_hbConditionState.OOBEState != SOFTBUS_OOBE_END &&
                g_hbConditionState.OOBEState != SOFTBUS_FACK_OOBE_END) {
                g_hbConditionState.OOBEState = state;
                HbConditionChanged(false);
            }
            break;
        case SOFTBUS_OOBE_END:
            if (g_hbConditionState.OOBEState != SOFTBUS_OOBE_END) {
                g_hbConditionState.OOBEState = state;
                HbConditionChanged(false);
            }
            break;
        default:
            return;
    }
}

static void RefreshBleBroadcastByUserSwitched()
{
    LnnProcessSendOnceMsgPara msgPara = {
        .hbType = HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V3,
        .strategyType = STRATEGY_HB_SEND_SINGLE,
        .isRelay = false,
        .isSyncData = false,
        .isDirectBoardcast = false,
        .callerId = HB_USER_SWITCH_CALLER_ID,
    };
    if (LnnStartHbByTypeAndStrategyEx(&msgPara) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "refresh ble broadcast fail");
    }
}

static void HbUserSwitchedHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_USER_SWITCHED) {
        LNN_LOGW(LNN_HEART_BEAT, "invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusUserSwitchState userSwitchState = (SoftBusUserSwitchState)event->status;
    switch (userSwitchState) {
        case SOFTBUS_USER_SWITCHED:
            {
                LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_USER_SWITCHED");
                uint8_t userIdCheckSum[USERID_CHECKSUM_LEN];
                int32_t userId = GetActiveOsAccountIds();
                LNN_LOGI(LNN_HEART_BEAT, "userswitch userId:%{public}d", userId);
                int32_t ret = LnnSetLocalNumInfo(NUM_KEY_USERID, userId);
                if (ret != SOFTBUS_OK) {
                    LNN_LOGW(LNN_EVENT, "set userId to local failed! userId:%{public}d", userId);
                }
                ret = HbBuildUserIdCheckSum(&userId, 1, userIdCheckSum, USERID_CHECKSUM_LEN);
                if (ret != SOFTBUS_OK) {
                    LNN_LOGW(LNN_EVENT, "construct useridchecksum failed! userId:%{public}d", userId);
                }
                ret = LnnSetLocalByteInfo(BYTE_KEY_USERID_CHECKSUM, userIdCheckSum, USERID_CHECKSUM_LEN);
                if (ret != SOFTBUS_OK) {
                    LNN_LOGW(LNN_EVENT, "set useridchecksum to local failed! userId:%{public}d", userId);
                }
                LnnUpdateOhosAccount(UPDATE_USER_SWITCH);
                HbConditionChanged(false);
                RefreshBleBroadcastByUserSwitched();
                if (IsHeartbeatEnable()) {
                    DfxRecordTriggerTime(USER_SWITCHED, EVENT_STAGE_LNN_USER_SWITCHED);
                }
                break;
            }
        default:
            return;
    }
}

static void HbLpEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_LP_EVENT_REPORT) {
        LNN_LOGE(LNN_HEART_BEAT, "lp report evt handler get invalid param");
        return;
    }
    int32_t ret;
    const LnnLpReportEvent *event = (const LnnLpReportEvent *)info;
    SoftBusLpEventType type = (SoftBusLpEventType)event->type;
    switch (type) {
        case SOFTBUS_MSDP_MOVEMENT_AND_STATIONARY:
            LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_MSDP_MOVEMENT_AND_STATIONARY");
            ret = LnnStartHbByTypeAndStrategy(
                HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V3, STRATEGY_HB_SEND_SINGLE, false);
            if (ret != SOFTBUS_OK) {
                LNN_LOGE(LNN_HEART_BEAT, "start ble heartbeat failed, ret=%{public}d", ret);
                return;
            }
            DfxRecordBleTriggerTimestamp(MSDP_MOVEMENT_AND_STATIONARY);
            break;
        default:
            LNN_LOGE(LNN_HEART_BEAT, "lp evt handler get invalid type=%{public}d", type);
            return;
    }
}

static void HbTryRecoveryNetwork(void)
{
    HbConditionChanged(true);
}

static void PeriodDumpLocalInfo(void *para)
{
    (void)para;

    LnnDumpLocalBasicInfo();
    (void)IsHeartbeatEnable();
    LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), PeriodDumpLocalInfo, NULL, HB_PERIOD_DUMP_LOCAL_INFO_LEN);
}

int32_t LnnStartHeartbeatFrameDelay(void)
{
    LNN_LOGI(LNN_HEART_BEAT, "heartbeat(HB) FSM start");
    LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), PeriodDumpLocalInfo, NULL, HB_PERIOD_DUMP_LOCAL_INFO_LEN);
    if (LnnHbMediumMgrInit() != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "medium manager init fail");
        return SOFTBUS_NETWORK_HB_MGR_INIT_FAIL;
    }
    HbTryRecoveryNetwork();
    if (LnnStartNewHbStrategyFsm() != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl start strategy fsm fail");
        return SOFTBUS_NETWORK_FSM_START_FAIL;
    }
    bool hasTrustedRelation = (AuthHasTrustedRelation() == TRUSTED_RELATION_YES) ? true : false;
    if (LnnIsDefaultOhosAccount() && !hasTrustedRelation) {
        LNN_LOGD(LNN_HEART_BEAT, "no trusted relation, heartbeat(HB) process start later");
        return SOFTBUS_OK;
    }
    return LnnStartHeartbeat(0);
}

int32_t LnnSetHeartbeatMediumParam(const LnnHeartbeatMediumParam *param)
{
    return LnnSetMediumParamBySpecificType(param);
}

int32_t LnnOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType)
{
    if (networkId == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "offline timing get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    /* only support ble medium type yet. */
    if (addrType != CONNECTION_ADDR_BLE) {
        LNN_LOGD(LNN_HEART_BEAT, "offline timing not support addrType now. addrType=%{public}d", addrType);
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusSysTime time = { 0 };
    (void)SoftBusGetTime(&time);
    uint64_t timeStamp = (uint64_t)time.sec * HB_TIME_FACTOR + (uint64_t)time.usec / HB_TIME_FACTOR;
    LnnSetDLHeartbeatTimestamp(networkId, timeStamp);
    (void)LnnStopOfflineTimingStrategy(networkId, addrType);
    if (LnnStartOfflineTimingStrategy(networkId, addrType) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl start offline timing strategy fail");
        return SOFTBUS_NETWORK_HB_START_STRATEGY_FAIL;
    }
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    LNN_LOGI(LNN_HEART_BEAT, "heartbeat(HB) start offline countdown, networkId=%{public}s, timeStamp=%{public}" PRIu64,
        AnonymizeWrapper(anonyNetworkId), timeStamp);
    AnonymizeFree(anonyNetworkId);
    if (SoftBusGetBtState() == BLE_ENABLE) {
        g_hbConditionState.btState = SOFTBUS_BLE_TURN_ON;
    }
    return SOFTBUS_OK;
}

void LnnStopOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType)
{
    if (networkId == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "HB stop offline timing get invalid param");
        return;
    }
    /* only support ble medium type yet. */
    if (addrType != CONNECTION_ADDR_BLE) {
        LNN_LOGE(LNN_HEART_BEAT, "HB stop offline timing not support addrType:%{public}d now", addrType);
        return;
    }
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    LNN_LOGD(LNN_HEART_BEAT, "heartbeat(HB) stop offline timing, networkId:%{public}s",
        AnonymizeWrapper(anonyNetworkId));
    AnonymizeFree(anonyNetworkId);
    (void)LnnStopScreenChangeOfflineTiming(networkId, addrType);
    (void)LnnStopOfflineTimingStrategy(networkId, addrType);
}

static void ReportBusinessDiscoveryResultEvt(const char *pkgName, int32_t discCnt)
{
    LNN_LOGI(LNN_HEART_BEAT, "report business discovery result evt enter");
    AppDiscNode appInfo;
    (void)memset_s(&appInfo, sizeof(AppDiscNode), 0, sizeof(AppDiscNode));
    appInfo.appDiscCnt = discCnt;
    if (memcpy_s(appInfo.appName, SOFTBUS_HISYSEVT_NAME_LEN, pkgName, SOFTBUS_HISYSEVT_NAME_LEN) != EOK) {
        LNN_LOGE(LNN_HEART_BEAT, "copy app name fail");
        return;
    }
    if (SoftBusRecordDiscoveryResult(BUSINESS_DISCOVERY, &appInfo) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "report business discovery result fail");
    }
}

int32_t LnnShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId, const GearMode *mode)
{
    char *anonyNetworkId = NULL;
    if (pkgName == NULL || mode == NULL || callerId == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "shift lnn gear get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    Anonymize(targetNetworkId, &anonyNetworkId);
    if (targetNetworkId != NULL && !LnnGetOnlineStateById(targetNetworkId, CATEGORY_NETWORK_ID)) {
        LNN_LOGD(LNN_HEART_BEAT, "target is offline, networkId=%{public}s", AnonymizeWrapper(anonyNetworkId));
    }
    LNN_LOGI(LNN_HEART_BEAT,
        "shift lnn gear mode, callerId=%{public}s, networkId=%{public}s, cycle=%{public}d, "
        "duration=%{public}d, wakeupFlag=%{public}d, action=%{public}d",
        callerId, targetNetworkId != NULL ? AnonymizeWrapper(anonyNetworkId) : "", mode->cycle, mode->duration,
        mode->wakeupFlag, mode->action);
    AnonymizeFree(anonyNetworkId);
    char uuid[UUID_BUF_LEN] = { 0 };
    if (targetNetworkId != NULL) {
        int32_t ret = LnnConvertDlId(targetNetworkId, CATEGORY_NETWORK_ID, CATEGORY_UUID, uuid, UUID_BUF_LEN);
        if (ret != SOFTBUS_OK) {
            LNN_LOGE(LNN_HEART_BEAT, "targetNetworkId convert uuid fail");
            return ret;
        }
    }
    if (mode->action == CHANGE_TCP_KEEPALIVE) {
        if (AuthSendKeepaliveOption(uuid, mode->cycle) != SOFTBUS_OK) {
            LNN_LOGE(LNN_HEART_BEAT, "auth send keepalive option fail");
            return SOFTBUS_NETWORK_SET_KEEPALIVE_OPTION_FAIL;
        }
        return SOFTBUS_OK;
    }
    if (LnnSetGearModeBySpecificType(callerId, mode, HEARTBEAT_TYPE_BLE_V0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl reset medium mode fail");
        return SOFTBUS_NETWORK_HB_SET_GEAR_MODE_FAIL;
    }
    if (LnnStartHbByTypeAndStrategy(
        HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V3, STRATEGY_HB_SEND_ADJUSTABLE_PERIOD, false) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl start adjustable ble heatbeat fail");
        return SOFTBUS_NETWORK_HB_START_STRATEGY_FAIL;
    }
    DfxRecordTriggerTime(DM_TRIGGER, EVENT_STAGE_LNN_SHIFT_GEAR);
    int32_t ret = AuthFlushDevice(uuid);
    if (ret != SOFTBUS_OK && ret != SOFTBUS_INVALID_PARAM) {
        LNN_LOGI(LNN_HEART_BEAT, "tcp flush failed, wifi will offline");
        return LnnRequestLeaveSpecific(targetNetworkId, CONNECTION_ADDR_WLAN);
    }
    return SOFTBUS_OK;
}

int32_t LnnShiftLNNGearWithoutPkgName(const char *callerId, const GearMode *mode, LnnHeartbeatStrategyType strategyType)
{
    if (mode == NULL || callerId == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "shift lnn gear get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    ReportBusinessDiscoveryResultEvt(callerId, 1);
    LNN_LOGD(LNN_HEART_BEAT,
        "shift lnn gear mode, callerId=%{public}s, cycle=%{public}d, duration=%{public}d, wakeupFlag=%{public}d",
        callerId, mode->cycle, mode->duration, mode->wakeupFlag);
    if (LnnSetGearModeBySpecificType(callerId, mode, HEARTBEAT_TYPE_BLE_V0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl reset medium mode fail");
        return SOFTBUS_NETWORK_HB_SET_GEAR_MODE_FAIL;
    }
    if (LnnStartHbByTypeAndStrategy(
        HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V3, strategyType, false) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl start adjustable ble heatbeat fail");
        return SOFTBUS_NETWORK_HB_START_STRATEGY_FAIL;
    }
    int32_t i, infoNum;
    char uuid[UUID_BUF_LEN] = { 0 };
    NodeBasicInfo *info = NULL;
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "get online node info failed");
        return SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR;
    }
    if (info == NULL || infoNum == 0) {
        LNN_LOGE(LNN_HEART_BEAT, "get online node is 0");
        return SOFTBUS_NO_ONLINE_DEVICE;
    }
    int32_t ret;
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    for (i = 0; i < infoNum; ++i) {
        ret = LnnGetRemoteNodeInfoById(info[i].networkId, CATEGORY_NETWORK_ID, &nodeInfo);
        if (ret != SOFTBUS_OK || !LnnHasDiscoveryType(&nodeInfo, DISCOVERY_TYPE_WIFI)) {
            continue;
        }
        (void)LnnConvertDlId(info[i].networkId, CATEGORY_NETWORK_ID, CATEGORY_UUID, uuid, UUID_BUF_LEN);
        if (AuthFlushDevice(uuid) != SOFTBUS_OK) {
            char *anonyUuid = NULL;
            Anonymize(uuid, &anonyUuid);
            LNN_LOGE(LNN_HEART_BEAT, "tcp flush failed, wifi will offline, uuid=%{public}s",
                AnonymizeWrapper(anonyUuid));
            AnonymizeFree(anonyUuid);
            LnnRequestLeaveSpecific(info[i].networkId, CONNECTION_ADDR_WLAN);
        }
    }
    SoftBusFree(info);
    return SOFTBUS_OK;
}

void LnnUpdateHeartbeatInfo(LnnHeartbeatUpdateInfoType type)
{
    LNN_LOGI(LNN_HEART_BEAT, "update heartbeat infoType=%{public}d", type);
    if (type == UPDATE_HB_ACCOUNT_INFO && !LnnIsDefaultOhosAccount()) {
        g_hbConditionState.accountState = SOFTBUS_ACCOUNT_LOG_IN;
        LNN_LOGI(LNN_HEART_BEAT, "account is login");
        HbConditionChanged(false);
    }
    LnnUpdateSendInfoStrategy(type);
}

static void HbDelayCheckTrustedRelation(void *para)
{
    (void)para;
    TrustedReturnType ret = AuthHasTrustedRelation();
    if (ret == TRUSTED_RELATION_YES) {
        g_hbConditionState.heartbeatEnable = IsEnableSoftBusHeartbeat();
        g_hbConditionState.hasTrustedRelation = true;
    } else if (ret == TRUSTED_RELATION_NO) {
        g_hbConditionState.hasTrustedRelation = false;
    }
    LNN_LOGI(LNN_HEART_BEAT, "delay check trust relation=%{public}d", g_hbConditionState.hasTrustedRelation);
    HbConditionChanged(false);
    if (LnnIsDefaultOhosAccount() && !g_hbConditionState.hasTrustedRelation) {
        LNN_LOGW(LNN_HEART_BEAT, "no trusted relation, heartbeat(HB) process stop");
        LnnStopHeartbeatByType(
            HEARTBEAT_TYPE_UDP | HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1 | HEARTBEAT_TYPE_TCP_FLUSH);
    }
}

void LnnHbOnTrustedRelationIncreased(int32_t groupType)
{
    /* If it is a peer-to-peer group, delay initialization to give BR networking priority. */
    int32_t ret = LnnStartHeartbeat(0);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "account group created start heartbeat fail, ret=%{public}d", ret);
        return;
    }
    if (groupType == AUTH_PEER_TO_PEER_GROUP &&
        LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), HbDelayCheckTrustedRelation, NULL,
            CHECK_TRUSTED_RELATION_TIME) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "async check trusted relaion fail");
    }
}

void LnnHbOnTrustedRelationReduced(void)
{
    if (LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), HbDelayCheckTrustedRelation, NULL,
        CHECK_TRUSTED_RELATION_TIME) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "async check trusted relaion fail");
    }
}

static int32_t LnnRegisterCommonEvent(void)
{
    int32_t ret;
    ret = LnnRegisterEventHandler(LNN_EVENT_SCREEN_STATE_CHANGED, HbScreenStateChangeEventHandler);
    LNN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, LNN_INIT, "regist screen state change evt handler fail");
    ret = LnnRegisterEventHandler(LNN_EVENT_SCREEN_LOCK_CHANGED, HbScreenLockChangeEventHandler);
    LNN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, LNN_INIT, "regist screen lock state change evt handler fai");
    ret = LnnRegisterEventHandler(LNN_EVENT_NIGHT_MODE_CHANGED, HbNightModeStateEventHandler);
    LNN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, LNN_INIT, "regist night mode state evt handler fail");
    ret = LnnRegisterEventHandler(LNN_EVENT_OOBE_STATE_CHANGED, HbOOBEStateEventHandler);
    LNN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, LNN_INIT, "regist OOBE state evt handler fail");
    ret = LnnRegisterEventHandler(LNN_EVENT_USER_SWITCHED, HbUserSwitchedHandler);
    LNN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, LNN_INIT, "regist user switch evt handler fail");
    return SOFTBUS_OK;
}

static int32_t LnnRegisterNetworkEvent(void)
{
    if (LnnRegisterEventHandler(LNN_EVENT_IP_ADDR_CHANGED, HbIpAddrChangeEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist ip addr change evt handler fail");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_BT_STATE_CHANGED, HbBtStateChangeEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist bt state change evt handler fail");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_LANE_VAP_CHANGE, HbLaneVapChangeEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist vap state change evt handler fail");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t LnnRegisterHeartbeatEvent(void)
{
    if (LnnRegisterEventHandler(LNN_EVENT_NODE_MASTER_STATE_CHANGED, HbMasterNodeChangeEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist node state change evt handler fail");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_HOME_GROUP_CHANGED, HbHomeGroupStateChangeEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist homeGroup state change evt handler fail");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_ACCOUNT_CHANGED, HbAccountStateChangeEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist account change evt handler fail");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_DIF_ACCOUNT_DEV_CHANGED, HbDifferentAccountEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist different account evt handler fail");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_USER_STATE_CHANGED, HbUserBackgroundEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist user background evt handler fail");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_LP_EVENT_REPORT, HbLpEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist lp report evt handler fail");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnInitHeartbeat(void)
{
    if (LnnHbStrategyInit() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "strategy module init fail");
        return SOFTBUS_NETWORK_HB_INIT_STRATEGY_FAIL;
    }
    if (LnnRegisterCommonEvent() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist common event handler fail");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    if (LnnRegisterNetworkEvent() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist network event handler fail");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    if (LnnRegisterHeartbeatEvent() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist heartbeat event handler fail");
        return SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR;
    }
    InitHbConditionState();
    InitHbSpecificConditionState();
    LNN_LOGI(LNN_INIT, "heartbeat(HB) init success");
    return SOFTBUS_OK;
}

void LnnDeinitHeartbeat(void)
{
    LnnHbStrategyDeinit();
    LnnHbMediumMgrDeinit();
    LnnUnregisterEventHandler(LNN_EVENT_IP_ADDR_CHANGED, HbIpAddrChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_BT_STATE_CHANGED, HbBtStateChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_LANE_VAP_CHANGE, HbLaneVapChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_NODE_MASTER_STATE_CHANGED, HbMasterNodeChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_SCREEN_STATE_CHANGED, HbScreenStateChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_HOME_GROUP_CHANGED, HbHomeGroupStateChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_SCREEN_LOCK_CHANGED, HbScreenLockChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_ACCOUNT_CHANGED, HbAccountStateChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_DIF_ACCOUNT_DEV_CHANGED, HbDifferentAccountEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_USER_STATE_CHANGED, HbUserBackgroundEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_NIGHT_MODE_CHANGED, HbNightModeStateEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_OOBE_STATE_CHANGED, HbOOBEStateEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_LP_EVENT_REPORT, HbLpEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_USER_SWITCHED, HbUserSwitchedHandler);
}

int32_t LnnTriggerDataLevelHeartbeat(void)
{
    LNN_LOGD(LNN_HEART_BEAT, "LnnTriggerDataLevelHeartbeat");
    if (LnnStartHbByTypeAndStrategy(
        HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V3, STRATEGY_HB_SEND_SINGLE, false) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl start single ble heartbeat fail");
        return SOFTBUS_NETWORK_HB_START_STRATEGY_FAIL;
    }
    DfxRecordTriggerTime(DB_TRIGGER, EVENT_STAGE_LNN_DATA_LEVEL);
    return SOFTBUS_OK;
}

int32_t LnnTriggerDirectHeartbeat(const char *networkId, uint64_t timeout)
{
    LNN_LOGD(LNN_HEART_BEAT, "LnnTriggerDirectHeartbeat");
    if (networkId == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "networkId is null");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = LnnStartHbByTypeAndStrategyDirectly(HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_DIRECT,
        false, networkId, timeout);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl start direct ble heartbeat fail");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnTriggerCloudSyncHeartbeat(void)
{
    LNN_LOGD(LNN_HEART_BEAT, "LnnTriggerCloudSyncHeartbeat");
    if (LnnStartHbByTypeAndStrategy(
        HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V3, STRATEGY_HB_SEND_SINGLE, false) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl start single ble heartbeat fail");
        return SOFTBUS_NETWORK_HB_START_STRATEGY_FAIL;
    }
    DfxRecordBleTriggerTimestamp(TRIGGER_CLOUD_SYNC_HEARTBEAT);
    return SOFTBUS_OK;
}

void LnnRegDataLevelChangeCb(const IDataLevelChangeCallback *callback)
{
    LnnBleHbRegDataLevelChangeCb(callback);
}

void LnnUnregDataLevelChangeCb(void)
{
    LnnBleHbUnregDataLevelChangeCb();
}