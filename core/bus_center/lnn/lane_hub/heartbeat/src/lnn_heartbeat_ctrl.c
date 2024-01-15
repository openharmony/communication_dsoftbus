/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <string.h>

#include "anonymizer.h"
#include "auth_interface.h"
#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_common_utils.h"
#include "lnn_decision_center.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_deviceinfo_to_profile.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_log.h"
#include "lnn_meta_node_ledger.h"
#include "lnn_network_manager.h"
#include "lnn_net_builder.h"
#include "lnn_ohos_account.h"

#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_broadcast_type.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_hisysevt_bus_center.h"
#include "softbus_utils.h"

#define HB_LOOPBACK_IP "127.0.0.1"

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
static bool g_enableState = false;
static DcTask g_dcTask;

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
    g_hbConditionState.heartbeatEnable = IsEnableSoftBusHeartbeat();
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

static bool IsHeartbeatEnable(void)
{
    if ((g_hbConditionState.lockState == SOFTBUS_SCREEN_LOCK_UNKNOWN) && IsActiveOsAccountUnlocked()) {
        g_hbConditionState.lockState = SOFTBUS_SCREEN_UNLOCK;
    }
    bool isBtOn = g_hbConditionState.btState == SOFTBUS_BLE_TURN_ON ||
        g_hbConditionState.btState == SOFTBUS_BR_TURN_ON;
    bool isScreenUnlock = g_hbConditionState.lockState == SOFTBUS_SCREEN_UNLOCK;
    bool isLogIn = g_hbConditionState.accountState == SOFTBUS_ACCOUNT_LOG_IN;
    bool isBackground = g_hbConditionState.backgroundState == SOFTBUS_USER_BACKGROUND;
    bool isNightMode = g_hbConditionState.nightModeState == SOFTBUS_NIGHT_MODE_ON;
    bool isOOBEEnd = g_hbConditionState.OOBEState == SOFTBUS_OOBE_END;

    LNN_LOGI(LNN_HEART_BEAT,
        "HB condition state: bt=%{public}d, screenUnlock=%{public}d, account=%{public}d, trustedRelation=%{public}d, "
        "background=%{public}d, nightMode=%{public}d, OOBEEnd=%{public}d, heartbeatEnable=%{public}d, "
        "request=%{public}d",
        isBtOn, isScreenUnlock, isLogIn,
        g_hbConditionState.hasTrustedRelation, isBackground, isNightMode, isOOBEEnd,
        g_hbConditionState.heartbeatEnable, !g_hbConditionState.isRequestDisable);
    return g_hbConditionState.heartbeatEnable && isBtOn && isScreenUnlock &&
        (isLogIn || g_hbConditionState.hasTrustedRelation) && !isBackground && !isNightMode && isOOBEEnd;
}

SoftBusScreenState GetScreenState(void)
{
    return g_hbConditionState.screenState;
}

void SetScreenState(SoftBusScreenState state)
{
    g_hbConditionState.screenState = state;
}

static void HbIpAddrChangeEventHandler(const LnnEventBasicInfo *info)
{
    char localIp[IP_LEN] = {0};

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
        if (LnnStartScreenChangeOfflineTiming(info[i].networkId,
            LnnConvertHbTypeToConnAddrType(hbType)) != SOFTBUS_OK) {
            LNN_LOGE(LNN_HEART_BEAT, "send check offline target msg failed");
        }
    }
    SoftBusFree(info);
}

static void HbConditionChanged(bool isOnlySetState)
{
    bool isEnable = IsHeartbeatEnable();
    if (g_enableState == isEnable) {
        LNN_LOGI(LNN_HEART_BEAT, "ctrl ignore same enable request, isEnable=%{public}d", isEnable);
        return;
    }
    LnnNotifyNetworkStateChanged(isEnable ? SOFTBUS_BLE_NETWORKD_ENABLE : SOFTBUS_BLE_NETWORKD_DISABLE);
    if (LnnEnableHeartbeatByType(
        HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1 | HEARTBEAT_TYPE_BLE_V3, isEnable) != SOFTBUS_OK) {
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
    } else {
        LNN_LOGD(LNN_HEART_BEAT, "condition changed to disabled");
        if (LnnStopHeartbeatByType(
            HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1 | HEARTBEAT_TYPE_BLE_V3) != SOFTBUS_OK) {
            LNN_LOGE(LNN_HEART_BEAT, "stop ble heartbeat fail");
        }
        g_enableState = false;
    }
}

static uint64_t GettDisEnableBleDiscoveryTime(int64_t modeDuration)
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

void LnnRequestBleDiscoveryProcess(int32_t strategy, int64_t timeout)
{
    if (strategy == REQUEST_DISABLE_BLE_DISCOVERY) {
        if (g_hbConditionState.isRequestDisable) {
            LNN_LOGI(LNN_HEART_BEAT, "ble has been requestDisabled, need wait timeout or enabled");
            return;
        }
        uint64_t time = GettDisEnableBleDiscoveryTime(timeout);
        if (LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), RequestEnableDiscovery, NULL, time) !=
            SOFTBUS_OK) {
            LNN_LOGI(LNN_HEART_BEAT, "ble has been requestDisabled fail, due to async callback fail");
            return;
        }
        g_hbConditionState.isRequestDisable = true;
        LNN_LOGI(LNN_HEART_BEAT, "ble has been requestDisabled");
        HbConditionChanged(false);
    } else if (strategy == REQUEST_ENABLE_BLE_DISCOVERY) {
        RequestEnableDiscovery(NULL);
    } else {
        LNN_LOGE(LNN_HEART_BEAT, "error strategy, not need to deal. strategy=%{public}d", strategy);
    }
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
            LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_BLE_TURN_ON");
            LnnUpdateHeartbeatInfo(UPDATE_BT_STATE_OPEN_INFO);
            HbConditionChanged(false);
            if (LnnStartHbByTypeAndStrategy(
                HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_ADJUSTABLE_PERIOD, false) != SOFTBUS_OK) {
                LNN_LOGE(LNN_HEART_BEAT, "start ble heartbeat fail");
            }
            break;
        case SOFTBUS_BLE_TURN_OFF:
            LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_BLE_TURN_OFF");
            LnnUpdateHeartbeatInfo(UPDATE_BT_STATE_CLOSE_INFO);
            HbConditionChanged(false);
            break;
        default:
            return;
    }
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
            LNN_LOGE(LNN_HEART_BEAT, "stop check offline target msg failed, networkId=%{public}s", anonyNetworkId);
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
    if (LnnSetMediumParamBySpecificType(&param) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl reset ble scan medium param fail");
        return;
    }
    LnnUpdateHeartbeatInfo(UPDATE_SCREEN_STATE_INFO);
}

static void HbScreenStateChangeEventHandler(const LnnEventBasicInfo *info)
{
    int64_t nowTime;
    SoftBusSysTime time = {0};
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
    SoftBusGetTime(&time);
    nowTime = time.sec * HB_TIME_FACTOR + time.usec / HB_TIME_FACTOR;
    if (g_hbConditionState.screenState == SOFTBUS_SCREEN_ON && oldstate != SOFTBUS_SCREEN_ON) {
        LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_SCREEN_ON");
        HbRemoveCheckOffLineMessage(HEARTBEAT_TYPE_BLE_V1);
        HbChangeMediumParamByState(g_hbConditionState.screenState);
        g_lastScreenOnTime = nowTime;
        if (g_lastScreenOnTime - g_lastScreenOffTime >= HB_SCREEN_ON_COAP_TIME) {
            LNN_LOGI(LNN_HEART_BEAT, "screen on start coap discovery");
            RestartCoapDiscovery();
        }
        if (g_lastScreenOnTime - g_lastScreenOffTime >= HB_OFFLINE_TIME && g_lastScreenOffTime > 0) {
            LNN_LOGI(LNN_HEART_BEAT, "screen on & screen has been off > 5min");
            int32_t ret = LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_SINGLE, false);
            if (ret != SOFTBUS_OK) {
                LNN_LOGE(LNN_HEART_BEAT, "start ble heartbeat failed, ret=%{public}d", ret);
                return;
            }
        }
        return;
    }
    if (g_hbConditionState.screenState == SOFTBUS_SCREEN_OFF && oldstate != SOFTBUS_SCREEN_OFF) {
        LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_SCREEN_OFF");
        g_lastScreenOffTime = nowTime;
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
    if (g_hbConditionState.lockState == SOFTBUS_SCREEN_UNLOCK) {
        LNN_LOGD(LNN_HEART_BEAT, "screen unlocked once already, ignoring this event");
        return;
    }
    g_hbConditionState.lockState = lockState;
    g_hbConditionState.heartbeatEnable = IsEnableSoftBusHeartbeat();
    LNN_LOGI(LNN_HEART_BEAT, "ScreenLock state: heartbeat=%{public}d", g_hbConditionState.heartbeatEnable);
    switch (lockState) {
        case SOFTBUS_SCREEN_UNLOCK:
            LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_SCREEN_UNLOCK");
            LnnUpdateOhosAccount();
            HbConditionChanged(false);
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
            HbConditionChanged(true);
            break;
        case SOFTBUS_ACCOUNT_LOG_OUT:
            LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_ACCOUNT_LOG_OUT");
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
    // g_hbConditionState.accountState == difAccountState;
    if (difAccountState == LNN_EVENT_DIF_ACCOUNT_DEV_CHANGED) {
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
    switch (state) {
        case SOFTBUS_OOBE_RUNNING:
            LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_OOBE_RUNNING");
            g_hbConditionState.OOBEState = state;
            HbConditionChanged(false);
            break;
        case SOFTBUS_OOBE_END:
            LNN_LOGI(LNN_HEART_BEAT, "HB handle SOFTBUS_OOBE_END");
            g_hbConditionState.OOBEState = state;
            HbConditionChanged(false);
            break;
        default:
            return;
    }
}

static void HbTryRecoveryNetwork(void)
{
    if (SoftBusGetBtState() == BLE_ENABLE) {
        g_hbConditionState.btState = SOFTBUS_BR_TURN_ON;
    }
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
    LNN_LOGI(LNN_HEART_BEAT, "try to recovery heartbeat network, relation=%{public}d",
        g_hbConditionState.hasTrustedRelation);
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
        return SOFTBUS_ERR;
    }
    HbTryRecoveryNetwork();
    if (LnnStartNewHbStrategyFsm() != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl start strategy fsm fail");
        return SOFTBUS_ERR;
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
    SoftBusSysTime time = {0};
    (void)SoftBusGetTime(&time);
    uint64_t timeStamp = (uint64_t)time.sec * HB_TIME_FACTOR + (uint64_t)time.usec / HB_TIME_FACTOR;
    LnnSetDLHeartbeatTimestamp(networkId, timeStamp);
    (void)LnnStopOfflineTimingStrategy(networkId, addrType);
    if (LnnStartOfflineTimingStrategy(networkId, addrType) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl start offline timing strategy fail");
        return SOFTBUS_ERR;
    }
    char *anonyNetworkId = NULL;
    Anonymize(networkId, &anonyNetworkId);
    LNN_LOGI(LNN_HEART_BEAT, "heartbeat(HB) start offline countdown, networkId=%{public}s, timeStamp=%{public}" PRIu64,
        anonyNetworkId, timeStamp);
    AnonymizeFree(anonyNetworkId);
    if (SoftBusGetBtState() == BLE_ENABLE) {
        g_hbConditionState.btState = SOFTBUS_BR_TURN_ON;
    }
    return SOFTBUS_OK;
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

int32_t LnnShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId,
    const GearMode *mode)
{
    char *anonyNetworkId = NULL;
    if (pkgName == NULL || mode == NULL || callerId == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "shift lnn gear get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    Anonymize(targetNetworkId, &anonyNetworkId);
    if (targetNetworkId != NULL && !LnnGetOnlineStateById(targetNetworkId, CATEGORY_NETWORK_ID)) {
        LNN_LOGD(LNN_HEART_BEAT, "target is offline, networkId=%{public}s", anonyNetworkId);
    }
    LNN_LOGD(LNN_HEART_BEAT, "shift lnn gear mode, callerId=%{public}s, networkId=%{public}s, cycle=%{public}d, "
        "duration=%{public}d, wakeupFlag=%{public}d", callerId,
        targetNetworkId != NULL ? anonyNetworkId : "",
        mode->cycle, mode->duration, mode->wakeupFlag);
    AnonymizeFree(anonyNetworkId);
    if (LnnSetGearModeBySpecificType(callerId, mode, HEARTBEAT_TYPE_BLE_V0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl reset medium mode fail");
        return SOFTBUS_ERR;
    }
    if (LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_ADJUSTABLE_PERIOD, false) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl start adjustable ble heatbeat fail");
        return SOFTBUS_ERR;
    }
    char uuid[UUID_BUF_LEN] = {0};
    (void)LnnConvertDlId(targetNetworkId, CATEGORY_NETWORK_ID, CATEGORY_UUID, uuid, UUID_BUF_LEN);
    int32_t ret = AuthFlushDevice(uuid);
    if (ret != SOFTBUS_OK && ret != SOFTBUS_INVALID_PARAM) {
        LNN_LOGI(LNN_HEART_BEAT, "tcp flush failed, wifi will offline");
        return LnnRequestLeaveSpecific(targetNetworkId, CONNECTION_ADDR_WLAN);
    }
    return SOFTBUS_OK;
}

int32_t LnnShiftLNNGearWithoutPkgName(const char *callerId, const GearMode *mode,
    LnnHeartbeatStrategyType strategyType)
{
    if (mode == NULL || callerId == NULL) {
        LNN_LOGE(LNN_HEART_BEAT, "shift lnn gear get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    ReportBusinessDiscoveryResultEvt(callerId, 1);
    LNN_LOGD(LNN_HEART_BEAT, "shift lnn gear mode, callerId=%{public}s, cycle=%{public}d, "
        "duration=%{public}d, wakeupFlag=%{public}d", callerId, mode->cycle, mode->duration, mode->wakeupFlag);
    if (LnnSetGearModeBySpecificType(callerId, mode, HEARTBEAT_TYPE_BLE_V0) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl reset medium mode fail");
        return SOFTBUS_ERR;
    }
    if (LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0, strategyType, false) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "ctrl start adjustable ble heatbeat fail");
        return SOFTBUS_ERR;
    }
    int32_t i, infoNum;
    char uuid[UUID_BUF_LEN] = {0};
    NodeBasicInfo *info = NULL;
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "get online node info failed");
        return SOFTBUS_ERR;
    }
    if (info == NULL || infoNum == 0) {
        LNN_LOGE(LNN_HEART_BEAT, "get online node is 0");
        return SOFTBUS_ERR;
    }
    int32_t ret;
    NodeInfo nodeInfo = {0};
    for (i = 0; i < infoNum; ++i) {
        ret = LnnGetRemoteNodeInfoById(info[i].networkId, CATEGORY_NETWORK_ID, &nodeInfo);
        if (ret != SOFTBUS_OK || !LnnHasDiscoveryType(&nodeInfo, DISCOVERY_TYPE_WIFI)) {
            continue;
        }
        (void)LnnConvertDlId(info[i].networkId, CATEGORY_NETWORK_ID, CATEGORY_UUID, uuid, UUID_BUF_LEN);
        if (AuthFlushDevice(uuid) != SOFTBUS_OK) {
            char *anonyUuid = NULL;
            Anonymize(uuid, &anonyUuid);
            LNN_LOGE(LNN_HEART_BEAT, "tcp flush failed, wifi will offline, uuid=%{public}s", anonyUuid);
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
        HbConditionChanged(true);
    }
    LnnUpdateSendInfoStrategy(type);
}

static void HbDelayCheckTrustedRelation(void *para)
{
    (void)para;
    TrustedReturnType ret = AuthHasTrustedRelation();
    if (ret == TRUSTED_RELATION_YES) {
        g_hbConditionState.hasTrustedRelation = true;
    } else if (ret == TRUSTED_RELATION_NO) {
        g_hbConditionState.hasTrustedRelation = false;
    }
    LNN_LOGI(LNN_HEART_BEAT, "delay check trust relation=%{public}d",
        g_hbConditionState.hasTrustedRelation);
    HbConditionChanged(false);
    if (LnnIsDefaultOhosAccount() && !g_hbConditionState.hasTrustedRelation) {
        LNN_LOGW(LNN_HEART_BEAT, "no trusted relation, heartbeat(HB) process stop");
        LnnStopHeartbeatByType(HEARTBEAT_TYPE_UDP | HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1 |
            HEARTBEAT_TYPE_TCP_FLUSH);
    }
}

void LnnHbOnTrustedRelationChanged(int32_t groupType)
{
    if (groupType == AUTH_PEER_TO_PEER_GROUP && LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT),
        HbDelayCheckTrustedRelation, NULL, CHECK_TRUSTED_RELATION_TIME) != SOFTBUS_OK) {
        LNN_LOGE(LNN_HEART_BEAT, "async check trusted relaion fail after device bound");
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
    if (groupType == AUTH_PEER_TO_PEER_GROUP && LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT),
        HbDelayCheckTrustedRelation, NULL, CHECK_TRUSTED_RELATION_TIME) != SOFTBUS_OK) {
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

static int32_t LnnHbSubscribeTask(void)
{
    (void)memset_s(&g_dcTask, sizeof(DcTask), 0, sizeof(DcTask));
    g_dcTask.preferredSystem = TASK_RULE_SYSTEM;
    g_dcTask.optimizeStrategy = (void *)LnnHbMediumMgrSetParam;
    return LnnDcSubscribe(&g_dcTask);
}

static void LnnHbUnsubscribeTask(void)
{
    LnnDcUnsubscribe(&g_dcTask);
}

int32_t LnnInitHeartbeat(void)
{
    if (LnnHbStrategyInit() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "strategy module init fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_IP_ADDR_CHANGED, HbIpAddrChangeEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist ip addr change evt handler fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_BT_STATE_CHANGED, HbBtStateChangeEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist bt state change evt handler fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_NODE_MASTER_STATE_CHANGED, HbMasterNodeChangeEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist node state change evt handler fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_SCREEN_STATE_CHANGED, HbScreenStateChangeEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist screen state change evt handler fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_HOME_GROUP_CHANGED, HbHomeGroupStateChangeEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist homeGroup state change evt handler fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_SCREEN_LOCK_CHANGED, HbScreenLockChangeEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist screen lock state change evt handler fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_ACCOUNT_CHANGED, HbAccountStateChangeEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist account change evt handler fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_DIF_ACCOUNT_DEV_CHANGED, HbDifferentAccountEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist different account evt handler fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_USER_STATE_CHANGED, HbUserBackgroundEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist user background evt handler fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_NIGHT_MODE_CHANGED, HbNightModeStateEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist night mode state evt handler fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_OOBE_STATE_CHANGED, HbOOBEStateEventHandler) != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "regist OOBE state evt handler fail");
        return SOFTBUS_ERR;
    }
    InitHbConditionState();
    InitHbSpecificConditionState();
    if (LnnHbSubscribeTask() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "subscribe task fail");
        return SOFTBUS_ERR;
    }
    LNN_LOGI(LNN_INIT, "heartbeat(HB) init success");
    return SOFTBUS_OK;
}

void LnnDeinitHeartbeat(void)
{
    LnnHbUnsubscribeTask();
    LnnHbStrategyDeinit();
    LnnHbMediumMgrDeinit();
    LnnUnregisterEventHandler(LNN_EVENT_IP_ADDR_CHANGED, HbIpAddrChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_BT_STATE_CHANGED, HbBtStateChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_NODE_MASTER_STATE_CHANGED, HbMasterNodeChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_SCREEN_STATE_CHANGED, HbScreenStateChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_HOME_GROUP_CHANGED, HbHomeGroupStateChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_SCREEN_LOCK_CHANGED, HbScreenLockChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_ACCOUNT_CHANGED, HbAccountStateChangeEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_DIF_ACCOUNT_DEV_CHANGED, HbDifferentAccountEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_USER_STATE_CHANGED, HbUserBackgroundEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_NIGHT_MODE_CHANGED, HbNightModeStateEventHandler);
    LnnUnregisterEventHandler(LNN_EVENT_OOBE_STATE_CHANGED, HbOOBEStateEventHandler);
}
