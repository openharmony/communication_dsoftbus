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

#include "auth_interface.h"
#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_common_utils.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_deviceinfo_to_profile.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_meta_node_ledger.h"
#include "lnn_network_manager.h"
#include "lnn_net_builder.h"
#include "lnn_ohos_account.h"
#include "lnn_decision_center.h"

#include "softbus_adapter_ble_gatt.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_hisysevt_bus_center.h"
#include "softbus_log.h"
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

static HbConditionState g_hbConditionState; // TODO: fix concurrent problem
static int64_t g_lastScreenOnTime;
static int64_t g_lastScreenOffTime;
static bool g_enableState = false;
static DcTask g_dcTask;

static void InitHbConditionState(void)
{
    g_hbConditionState.btState = SOFTBUS_BT_UNKNOWN;
    g_hbConditionState.screenState = SOFTBUS_SCREEN_UNKNOWN;
    g_hbConditionState.lockState = SOFTBUS_SCREEN_LOCK_UNKNOWN;
    // need suit for same account
    g_hbConditionState.accountState = SOFTBUS_ACCOUNT_LOG_IN;
    g_hbConditionState.backgroundState = SOFTBUS_USER_FOREGROUND;
    g_hbConditionState.nightModeState = SOFTBUS_NIGHT_MODE_UNKNOWN;
    g_hbConditionState.hasTrustedRelation = false;
    g_hbConditionState.isRequestDisable = false;
    g_hbConditionState.heartbeatEnable = IsEnableSoftBusHeartbeat();
    g_hbConditionState.OOBEState = SOFTBUS_OOBE_UNKNOWN;
    LLOGI("HB condition state: heartbeat=%d", g_hbConditionState.heartbeatEnable);
}

static void InitHbSpecificConditionState(void)
{
    int32_t localDevTypeId = 0;
    if (LnnGetLocalNumInfo(NUM_KEY_DEV_TYPE_ID, &localDevTypeId) != SOFTBUS_OK) {
        localDevTypeId = 0;
    }
    if (localDevTypeId == TYPE_WATCH_ID) {
        LLOGD("HB localDevTypeId:%d", localDevTypeId);
        g_hbConditionState.isRequestDisable = true;
    }
}

static bool IsMetaDeviceHeartbeatEnable(void)
{
    bool isBtOn = g_hbConditionState.btState == SOFTBUS_BLE_TURN_ON ||
        g_hbConditionState.btState == SOFTBUS_BR_TURN_ON;
    bool isScreenUnlock = g_hbConditionState.lockState == SOFTBUS_SCREEN_UNLOCK;
    bool isBackground = g_hbConditionState.backgroundState == SOFTBUS_USER_BACKGROUND;
    bool isNightMode = g_hbConditionState.nightModeState == SOFTBUS_NIGHT_MODE_ON;
    bool isOOBEEnd = g_hbConditionState.OOBEState == SOFTBUS_OOBE_END;

    return g_hbConditionState.heartbeatEnable && isBtOn && isScreenUnlock && !isBackground && !isNightMode && isOOBEEnd;
}

static bool IsHeartbeatEnable(void)
{
    bool isBtOn = g_hbConditionState.btState == SOFTBUS_BLE_TURN_ON ||
        g_hbConditionState.btState == SOFTBUS_BR_TURN_ON;
    bool isScreenUnlock = g_hbConditionState.lockState == SOFTBUS_SCREEN_UNLOCK;
    bool isLogIn = g_hbConditionState.accountState == SOFTBUS_ACCOUNT_LOG_IN;
    bool isBackground = g_hbConditionState.backgroundState == SOFTBUS_USER_BACKGROUND;
    bool isNightMode = g_hbConditionState.nightModeState == SOFTBUS_NIGHT_MODE_ON;
    bool isOOBEEnd = g_hbConditionState.OOBEState == SOFTBUS_OOBE_END;

    LLOGI("HB condition state: bt=%d, screenUnlock=%d, account=%d, trustedRelation=%d, background=%d, nightMode=%d, "
        "OOBEEnd=%d, heartbeatEnable=%d, request=%d", isBtOn, isScreenUnlock, isLogIn,
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
        LLOGE("HB ip addr change evt handler get invalid param");
        return;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, localIp, IP_LEN) != SOFTBUS_OK) {
        LLOGE("HB get local ip err");
        return;
    }
    if (strcmp(localIp, HB_LOOPBACK_IP) == 0 &&
        LnnEnableHeartbeatByType(HEARTBEAT_TYPE_TCP_FLUSH, false) != SOFTBUS_OK) {
        LLOGE("HB ctrl disable tcp flush fail");
        return;
    }
    if (LnnEnableHeartbeatByType(HEARTBEAT_TYPE_TCP_FLUSH, true) != SOFTBUS_OK) {
        LLOGE("HB ctrl enable tcp flush fail");
        return;
    }
}

static void HbOfflineAllMetaNode(void)
{
    int32_t infoNum = MAX_META_NODE_NUM;
    MetaNodeInfo infos[MAX_META_NODE_NUM];

    if (LnnGetAllMetaNodeInfo(infos, &infoNum) != SOFTBUS_OK) {
        LLOGE("HB get all meta node err");
        return;
    }
    for (int32_t i = 0; i < infoNum; i++) {
        if (MetaNodeServerLeave(infos[i].metaNodeId) != SOFTBUS_OK) {
            LLOGE("HB offline meta node err, metaNodeId=%s", infos[i].metaNodeId);
        }
    }
}

static void HbSendCheckOffLineMessage(LnnHeartbeatType hbType)
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
        if (LnnIsLSANode(&info[i])) {
            continue;
        }
        (void)LnnStopScreenChangeOfflineTiming(info[i].networkId, LnnConvertHbTypeToConnAddrType(hbType));
        if (LnnStartScreenChangeOfflineTiming(info[i].networkId,
            LnnConvertHbTypeToConnAddrType(hbType)) != SOFTBUS_OK) {
            LLOGE("send check offline target msg failed");
        }
    }
    SoftBusFree(info);
}

static void HbConditionChanged(bool isOnlySetState)
{
    if (!IsMetaDeviceHeartbeatEnable()) {
        LLOGI("HB metaNode device heartbeat disabled, set all MetaDevice offline");
        HbOfflineAllMetaNode();
    }
    bool isEnable = IsHeartbeatEnable();
    if (g_enableState == isEnable) {
        LLOGI("HB ctrl ignore same enable request, is enable: %d", isEnable);
        return;
    }
    LnnNotifyNetworkStateChanged(isEnable ? SOFTBUS_BLE_NETWORKD_ENABLE : SOFTBUS_BLE_NETWORKD_DISABLE);
    if (LnnEnableHeartbeatByType(
        HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1 | HEARTBEAT_TYPE_BLE_V3, isEnable) != SOFTBUS_OK) {
        LLOGE("HB ctrl enable ble heartbeat fail");
        return;
    }
    if (isOnlySetState) {
        LLOGD("HB condition changed only set state");
        g_enableState = isEnable;
        return;
    }
    if (isEnable) {
        LLOGD("HB condition changed to enabled");
        if (LnnStartHbByTypeAndStrategy(
            HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V3, STRATEGY_HB_SEND_SINGLE, false) != SOFTBUS_OK) {
            LLOGE("HB start ble heartbeat fail");
        }
        g_enableState = true;
    } else {
        LLOGD("HB condition changed to disabled");
        if (LnnStopHeartbeatByType(
            HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1 | HEARTBEAT_TYPE_BLE_V3) != SOFTBUS_OK) {
            LLOGE("HB stop ble heartbeat fail");
        }
        g_enableState = false;
    }
}

static uint64_t GettDisEnableBleDiscoveryTime(int64_t modeDuration)
{
    uint64_t timeout = 0L;
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
        LLOGI("ble has been enabled, don't need  restore enabled");
        return;
    }
    g_hbConditionState.isRequestDisable = false;
    LLOGI("ble has been requestEnable");
    HbConditionChanged(false);
}

void LnnRequestBleDiscoveryProcess(int32_t strategy, int64_t timeout)
{
    if (strategy == REQUEST_DISABLE_BLE_DISCOVERY) {
        if (g_hbConditionState.isRequestDisable) {
            LLOGI("ble has been requestDisabled, need wait timeout or enabled");
            return;
        }
        uint64_t time = GettDisEnableBleDiscoveryTime(timeout);
        if (LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), RequestEnableDiscovery, NULL, time) !=
            SOFTBUS_OK) {
            LLOGI("ble has been requestDisabled fail, due to async callback fail");
            return;
        }
        g_hbConditionState.isRequestDisable = true;
        LLOGI("ble has been requestDisabled");
        HbConditionChanged(false);
    } else if (strategy == REQUEST_ENABLE_BLE_DISCOVERY) {
        RequestEnableDiscovery(NULL);
    } else {
        LLOGE("error strategy = %d, not need to deal", strategy);
    }
    return;
}

static void HbBtStateChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_BT_STATE_CHANGED) {
        LLOGE("HB bt state change evt handler get invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusBtState btState = (SoftBusBtState)event->status;
    g_hbConditionState.btState = btState;
    switch (btState) {
        case SOFTBUS_BLE_TURN_ON:
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB handle SOFTBUS_BLE_TURN_ON");
            LnnUpdateHeartbeatInfo(UPDATE_BT_STATE_OPEN_INFO);
            HbConditionChanged(false);
            if (LnnStartHbByTypeAndStrategy(
                HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_ADJUSTABLE_PERIOD, false) != SOFTBUS_OK) {
                LLOGE("HB start ble heartbeat fail");
            }
            break;
        case SOFTBUS_BLE_TURN_OFF:
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB handle SOFTBUS_BLE_TURN_OFF");
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
        LLOGE("HB master node change evt handler get invalid param");
        return;
    }

    const LnnMasterNodeChangedEvent *event = (LnnMasterNodeChangedEvent *)info;
    if (LnnSetHbAsMasterNodeState(event->isMasterNode) != SOFTBUS_OK) {
        LLOGE("HB ctrl change master node state fail");
    }
}

static void HbRemoveCheckOffLineMessage(LnnHeartbeatType hbType)
{
    if (hbType <= HEARTBEAT_TYPE_MIN || hbType >= HEARTBEAT_TYPE_MAX) {
        LLOGE("HB get invalid hbType param");
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
        if (LnnIsLSANode(&info[i])) {
            continue;
        }
        if (LnnStopScreenChangeOfflineTiming(info[i].networkId, LnnConvertHbTypeToConnAddrType(hbType)) != SOFTBUS_OK) {
            LLOGE("HB stop check offline target msg failed, networkId:%s", AnonymizesNetworkID(info[i].networkId));
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
        LLOGE("HB ctrl reset ble scan medium param fail");
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
    const LnnMonitorHbStateChangedEvent *event = (LnnMonitorHbStateChangedEvent *)info;
    if ((SoftBusScreenState)event->status == SOFTBUS_SCREEN_UNKNOWN) {
        LLOGE("HB get invalid screen state");
        return;
    }
    SoftBusScreenState oldstate = g_hbConditionState.screenState;
    g_hbConditionState.screenState = (SoftBusScreenState)event->status;
    SoftBusGetTime(&time);
    nowTime = time.sec * HB_TIME_FACTOR + time.usec / HB_TIME_FACTOR;
    if (g_hbConditionState.screenState == SOFTBUS_SCREEN_ON && oldstate != SOFTBUS_SCREEN_ON) {
        LLOGI("HB handle SOFTBUS_SCREEN_ON");
        HbRemoveCheckOffLineMessage(HEARTBEAT_TYPE_BLE_V1);
        HbChangeMediumParamByState(g_hbConditionState.screenState);
        g_lastScreenOnTime = nowTime;
        if (g_lastScreenOnTime - g_lastScreenOffTime >= HB_SCREEN_ON_COAP_TIME) {
            LLOGI("HB screen on start coap discovery");
            RestartCoapDiscovery();
        }
        if (g_lastScreenOnTime - g_lastScreenOffTime >= HB_OFFLINE_TIME && g_lastScreenOffTime > 0) {
            LLOGI("HB screen on & screen has been off > 5min");
            int32_t ret = LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_SINGLE, false);
            if (ret != SOFTBUS_OK) {
                LLOGE("HB start ble heartbeat failed, ret = %d", ret);
                return;
            }
        }
        return;
    }
    if (g_hbConditionState.screenState == SOFTBUS_SCREEN_OFF && oldstate != SOFTBUS_SCREEN_OFF) {
        LLOGI("HB handle SOFTBUS_SCREEN_OFF");
        g_lastScreenOffTime = nowTime;
        if (LnnStopHeartBeatAdvByTypeNow(HEARTBEAT_TYPE_BLE_V1) != SOFTBUS_OK) {
            LLOGE("HB ctrl disable ble heartbeat failed");
            return;
        }
        HbChangeMediumParamByState(g_hbConditionState.screenState);
        HbSendCheckOffLineMessage(HEARTBEAT_TYPE_BLE_V1);
    }
}

static void HbScreenLockChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_SCREEN_LOCK_CHANGED) {
        LLOGE("HB lock state change evt handler get invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusScreenLockState lockState = (SoftBusScreenLockState)event->status;
    if (g_hbConditionState.lockState == SOFTBUS_SCREEN_UNLOCK) {
        LLOGD("HB screen unlocked once already, ignoring this event");
        return;
    }
    g_hbConditionState.lockState = lockState;
    g_hbConditionState.heartbeatEnable = IsEnableSoftBusHeartbeat();
    LLOGI("HB ScreenLock state: heartbeat=%d", g_hbConditionState.heartbeatEnable);
    switch (lockState) {
        case SOFTBUS_SCREEN_UNLOCK:
            LLOGI("HB handle SOFTBUS_SCREEN_UNLOCK");
            // TODO: refactor update account process to boot complete event.
            LnnUpdateOhosAccount();
            HbConditionChanged(false);
            break;
        case SOFTBUS_SCREEN_LOCK:
            LLOGI("HB handle SOFTBUS_SCREEN_LOCK");
            break;
        default:
            return;
    }
}

static void HbAccountStateChangeEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_ACCOUNT_CHANGED) {
        LLOGE("HB account state change evt handler get invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusAccountState accountState = (SoftBusAccountState)event->status;
    g_hbConditionState.accountState = accountState;
    switch (accountState) {
        case SOFTBUS_ACCOUNT_LOG_IN:
            LLOGI("HB handle SOFTBUS_ACCOUNT_LOG_IN");
            HbConditionChanged(true);
            break;
        case SOFTBUS_ACCOUNT_LOG_OUT:
            LLOGI("HB handle SOFTBUS_ACCOUNT_LOG_OUT");
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
            LLOGI("HB handle SOFTBUS_HOME_GROUP_CHANGE");
            HbConditionChanged(false);
            break;
        case SOFTBUS_HOME_GROUP_LEAVE:
            LLOGI("HB handle SOFTBUS_HOME_GROUP_LEAVE");
            break;
        default:
            return;
    }
}

static void HbDifferentAccountEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_DIF_ACCOUNT_DEV_CHANGED) {
        LLOGE("HB account state change evt handler get invalid param");
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
        LLOGE("HB user background state change evt handler get invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusUserState userState = (SoftBusUserState)event->status;
    switch (userState) {
        case SOFTBUS_USER_FOREGROUND:
            g_hbConditionState.backgroundState = userState;
            LLOGI("HB handle SOFTBUS_USER_FOREGROUND");
            HbConditionChanged(false);
            break;
        case SOFTBUS_USER_BACKGROUND:
            g_hbConditionState.backgroundState = userState;
            LLOGI("HB handle SOFTBUS_USER_BACKGROUND");
            HbConditionChanged(false);
            break;
        default:
            return;
    }
}

static void HbNightModeStateEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_NIGHT_MODE_CHANGED) {
        LLOGE("HB user background state change evt handler get invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusNightModeState nightModeState = (SoftBusNightModeState)event->status;
    g_hbConditionState.nightModeState = nightModeState;
    switch (nightModeState) {
        case SOFTBUS_NIGHT_MODE_ON:
            LLOGI("HB handle SOFTBUS_NIGHT_MODE_ON");
            HbConditionChanged(false);
            break;
        case SOFTBUS_NIGHT_MODE_OFF:
            LLOGI("HB handle SOFTBUS_NIGHT_MODE_OFF");
            HbConditionChanged(false);
            break;
        default:
            return;
    }
}

static void HbOOBEStateEventHandler(const LnnEventBasicInfo *info)
{
    if (info == NULL || info->event != LNN_EVENT_OOBE_STATE_CHANGED) {
        LLOGE("HB OOBE state change evt handler get invalid param");
        return;
    }
    const LnnMonitorHbStateChangedEvent *event = (const LnnMonitorHbStateChangedEvent *)info;
    SoftBusOOBEState state = (SoftBusOOBEState)event->status;
    switch (state) {
        case SOFTBUS_OOBE_RUNNING:
            LLOGI("HB handle SOFTBUS_OOBE_RUNNING");
            g_hbConditionState.OOBEState = state;
            HbConditionChanged(false);
            break;
        case SOFTBUS_OOBE_END:
            LLOGI("HB handle SOFTBUS_OOBE_END");
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
    if (IsScreenUnlock()) {
        g_hbConditionState.lockState = SOFTBUS_SCREEN_UNLOCK;
    }
    TrustedReturnType ret = AuthHasTrustedRelation();
    if (ret == TRUSTED_RELATION_YES) {
        g_hbConditionState.hasTrustedRelation = true;
    } else if (ret == TRUSTED_RELATION_NO) {
        g_hbConditionState.hasTrustedRelation = false;
    }
    // TODO: get and set nightState, backgroundState.
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "HB try to recovery heartbeat network, relation=%d",
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

NO_SANITIZE("cfi") int32_t LnnStartHeartbeatFrameDelay(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) FSM start.");
    LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), PeriodDumpLocalInfo, NULL, HB_PERIOD_DUMP_LOCAL_INFO_LEN);
    if (LnnHbMediumMgrInit() != SOFTBUS_OK) {
        LLOGE("HB medium manager init fail");
        return SOFTBUS_ERR;
    }
    HbTryRecoveryNetwork();
    if (LnnStartNewHbStrategyFsm() != SOFTBUS_OK) {
        LLOGE("HB ctrl start strategy fsm fail");
        return SOFTBUS_ERR;
    }
    bool hasTrustedRelation = (AuthHasTrustedRelation() == TRUSTED_RELATION_YES) ? true : false;
    if (LnnIsDefaultOhosAccount() && !hasTrustedRelation) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "no trusted relation, heartbeat(HB) process start later.");
        return SOFTBUS_OK;
    }
    return LnnStartHeartbeat(0);
}

NO_SANITIZE("cfi") int32_t LnnSetHeartbeatMediumParam(const LnnHeartbeatMediumParam *param)
{
    return LnnSetMediumParamBySpecificType(param);
}

NO_SANITIZE("cfi") int32_t LnnOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType)
{
    if (networkId == NULL) {
        LLOGE("HB offline timing get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    /* only support ble medium type yet. */
    if (addrType != CONNECTION_ADDR_BLE) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "HB offline timing not support addrType:%d now.", addrType);
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusSysTime time = {0};
    (void)SoftBusGetTime(&time);
    uint64_t timeStamp = (uint64_t)time.sec * HB_TIME_FACTOR + (uint64_t)time.usec / HB_TIME_FACTOR;
    LnnSetDLHeartbeatTimestamp(networkId, timeStamp);
    (void)LnnStopOfflineTimingStrategy(networkId, addrType);
    if (LnnStartOfflineTimingStrategy(networkId, addrType) != SOFTBUS_OK) {
        LLOGE("HB ctrl start offline timing strategy fail");
        return SOFTBUS_ERR;
    }
    LLOGI("heartbeat(HB) start offline countdown, networkId:%s, timeStamp:%" PRIu64,
        AnonymizesNetworkID(networkId), timeStamp);
    return SOFTBUS_OK;
}

static void ReportBusinessDiscoveryResultEvt(const char *pkgName, int32_t discCnt)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "report business discovery result evt enter");
    AppDiscNode appInfo;
    (void)memset_s(&appInfo, sizeof(AppDiscNode), 0, sizeof(AppDiscNode));
    appInfo.appDiscCnt = discCnt;
    if (memcpy_s(appInfo.appName, SOFTBUS_HISYSEVT_NAME_LEN, pkgName, SOFTBUS_HISYSEVT_NAME_LEN) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "copy app name fail");
        return;
    }
    if (SoftBusRecordDiscoveryResult(BUSINESS_DISCOVERY, &appInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "report business discovery result fail");
    }
}

NO_SANITIZE("cfi") int32_t LnnShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId,
    const GearMode *mode)
{
    if (pkgName == NULL || mode == NULL || callerId == NULL) {
        LLOGE("HB shift lnn gear get invalid param");
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
        LLOGE("HB ctrl reset medium mode fail");
        return SOFTBUS_ERR;
    }
    if (LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0, STRATEGY_HB_SEND_ADJUSTABLE_PERIOD, false) != SOFTBUS_OK) {
        LLOGE("HB ctrl start adjustable ble heatbeat fail");
        return SOFTBUS_ERR;
    }
    char uuid[UUID_BUF_LEN] = {0};
    (void)LnnConvertDlId(targetNetworkId, CATEGORY_NETWORK_ID, CATEGORY_UUID, uuid, UUID_BUF_LEN);
    int32_t ret = AuthFlushDevice(uuid);
    if (ret != SOFTBUS_OK && ret != SOFTBUS_INVALID_PARAM) {
        LLOGI("HB tcp flush failed, wifi will offline");
        return LnnRequestLeaveSpecific(targetNetworkId, CONNECTION_ADDR_WLAN);
    }
    return SOFTBUS_OK;
}

int32_t HmosShiftLNNGear(const char *callerId, const GearMode *mode, LnnHeartbeatStrategyType strategyType)
{
    if (mode == NULL || callerId == NULL) {
        LLOGE("HB shift lnn gear get invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    ReportBusinessDiscoveryResultEvt(callerId, 1);
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "HmosShiftLNNGear >> [callerId:%s cycle:%d, "
        "duration:%d, wakeupFlag:%d]", callerId, mode->cycle, mode->duration, mode->wakeupFlag);
    if (LnnSetGearModeBySpecificType(callerId, mode, HEARTBEAT_TYPE_BLE_V0) != SOFTBUS_OK) {
        LLOGE("HB ctrl reset medium mode fail");
        return SOFTBUS_ERR;
    }
    if (LnnStartHbByTypeAndStrategy(HEARTBEAT_TYPE_BLE_V0, strategyType, false) != SOFTBUS_OK) {
        LLOGE("HB ctrl start adjustable ble heatbeat fail");
        return SOFTBUS_ERR;
    }
    int32_t i, infoNum;
    char uuid[UUID_BUF_LEN] = {0};
    NodeBasicInfo *info = NULL;
    if (LnnGetAllOnlineNodeInfo(&info, &infoNum) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ShiftLNNGear get online node info failed");
        return SOFTBUS_ERR;
    }
    if (info == NULL || infoNum == 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "ShiftLNNGear get online node is 0");
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
            LLOGE("tcp flush failed, wifi will offline uuid = %s", AnonymizesUUID(uuid));
            LnnRequestLeaveSpecific(info[i].networkId, CONNECTION_ADDR_WLAN);
        }
    }
    SoftBusFree(info);
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") void LnnUpdateHeartbeatInfo(LnnHeartbeatUpdateInfoType type)
{
    LLOGI("HB update heartbeat info, type:%d", type);
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
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "delay check trust relation=%d",
        g_hbConditionState.hasTrustedRelation);
    HbConditionChanged(false);
    if (LnnIsDefaultOhosAccount() && !g_hbConditionState.hasTrustedRelation) {
        LLOGW("no trusted relation, heartbeat(HB) process stop.");
        LnnStopHeartbeatByType(HEARTBEAT_TYPE_UDP | HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1 |
            HEARTBEAT_TYPE_TCP_FLUSH);
    }
}

NO_SANITIZE("cfi") void LnnHbOnTrustedRelationIncreased(int32_t groupType)
{
    /* If it is a peer-to-peer group, delay initialization to give BR networking priority. */
    int32_t ret = LnnStartHeartbeat(0);
    if (ret != SOFTBUS_OK) {
        LLOGE("HB account group created start heartbeat fail, ret=%d", ret);
        return;
    }
    if (groupType == AUTH_PEER_TO_PEER_GROUP && LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT),
        HbDelayCheckTrustedRelation, NULL, CHECK_TRUSTED_RELATION_TIME) != SOFTBUS_OK) {
        LLOGE("HB async check trusted relaion fail");
    }
}

NO_SANITIZE("cfi") void LnnHbOnTrustedRelationReduced(void)
{
    if (LnnAsyncCallbackDelayHelper(GetLooper(LOOP_TYPE_DEFAULT), HbDelayCheckTrustedRelation, NULL,
        CHECK_TRUSTED_RELATION_TIME) != SOFTBUS_OK) {
        LLOGE("HB async check trusted relaion fail");
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

NO_SANITIZE("cfi") int32_t LnnInitHeartbeat(void)
{
    if (LnnHbStrategyInit() != SOFTBUS_OK) {
        LLOGE("HB strategy module init fail!");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_IP_ADDR_CHANGED, HbIpAddrChangeEventHandler) != SOFTBUS_OK) {
        LLOGE("HB regist ip addr change evt handler fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_BT_STATE_CHANGED, HbBtStateChangeEventHandler) != SOFTBUS_OK) {
        LLOGE("HB regist bt state change evt handler fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_NODE_MASTER_STATE_CHANGED, HbMasterNodeChangeEventHandler) != SOFTBUS_OK) {
        LLOGE("HB regist node state change evt handler fail");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_SCREEN_STATE_CHANGED, HbScreenStateChangeEventHandler) != SOFTBUS_OK) {
        LLOGE("HB regist screen state change evt handler fail!");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_HOME_GROUP_CHANGED, HbHomeGroupStateChangeEventHandler) != SOFTBUS_OK) {
        LLOGE("HB regist homeGroup state change evt handler fail!");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_SCREEN_LOCK_CHANGED, HbScreenLockChangeEventHandler) != SOFTBUS_OK) {
        LLOGE("HB regist screen lock state change evt handler fail!");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_ACCOUNT_CHANGED, HbAccountStateChangeEventHandler) != SOFTBUS_OK) {
        LLOGE("HB regist account change evt handler fail!");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_DIF_ACCOUNT_DEV_CHANGED, HbDifferentAccountEventHandler) != SOFTBUS_OK) {
        LLOGE("HB regist different account evt handler fail!");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_USER_STATE_CHANGED, HbUserBackgroundEventHandler) != SOFTBUS_OK) {
        LLOGE("HB regist user background evt handler fail!");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_NIGHT_MODE_CHANGED, HbNightModeStateEventHandler) != SOFTBUS_OK) {
        LLOGE("HB regist night mode state evt handler fail!");
        return SOFTBUS_ERR;
    }
    if (LnnRegisterEventHandler(LNN_EVENT_OOBE_STATE_CHANGED, HbOOBEStateEventHandler) != SOFTBUS_OK) {
        LLOGE("HB regist OOBE state evt handler fail!");
        return SOFTBUS_ERR;
    }
    InitHbConditionState();
    InitHbSpecificConditionState();
    if (LnnHbSubscribeTask() != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "HB subscribe task fail!");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "heartbeat(HB) init success");
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") void LnnDeinitHeartbeat(void)
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
