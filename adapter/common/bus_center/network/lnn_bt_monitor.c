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

#include "lnn_event_monitor_impl.h"

#include <securec.h>

#include "bus_center_event.h"
#include "lnn_async_callback_utils.h"
#include "lnn_log.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

static int32_t g_btStateListenerId = -1;
static void LnnOnBtStateChanged(int32_t listenerId, int32_t state);
static void LnnOnBtAclStateChanged(int32_t listenerId, const SoftBusBtAddr *addr, int32_t aclState, int32_t hciReason);

static SoftBusBtStateListener g_btStateListener = {
    .OnBtStateChanged = LnnOnBtStateChanged,
    .OnBtAclStateChanged = LnnOnBtAclStateChanged,
};

static void LnnOnBtStateChanged(int32_t listenerId, int32_t state)
{
    if (listenerId < 0 || state < 0) {
        LNN_LOGE(LNN_STATE, "bt monitor get invalid param");
        return;
    }

    SoftBusBtStackState btState = (SoftBusBtStackState)state;
    SoftBusBtState *notifyState = (SoftBusBtState *)SoftBusMalloc(sizeof(SoftBusBtState));
    if (notifyState == NULL) {
        LNN_LOGE(LNN_STATE, "bt monitor malloc err");
        return;
    }
    *notifyState = SOFTBUS_BT_UNKNOWN;
    switch (btState) {
        case SOFTBUS_BLE_STATE_TURN_ON:
            *notifyState = SOFTBUS_BLE_TURN_ON;
            break;
        case SOFTBUS_BLE_STATE_TURN_OFF:
            *notifyState = SOFTBUS_BLE_TURN_OFF;
            break;
        case SOFTBUS_BR_STATE_TURN_ON:
            *notifyState = SOFTBUS_BR_TURN_ON;
            break;
        case SOFTBUS_BR_STATE_TURN_OFF:
            *notifyState = SOFTBUS_BR_TURN_OFF;
            break;
        default:
            break;
    }

    if (*notifyState == SOFTBUS_BT_UNKNOWN) {
        LNN_LOGD(LNN_STATE, "bt state changed but no need notify, btState=%{public}d", btState);
        SoftBusFree(notifyState);
        return;
    }
    LNN_LOGI(LNN_STATE, "async notify bt state changed, listenerId=%{public}d, notifyState=%{public}d",
        listenerId, *notifyState);
    int32_t ret = LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), LnnNotifyBtStateChangeEvent,
        (void *)notifyState);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "async notify bt state err, ret=%{public}d", ret);
        SoftBusFree(notifyState);
        return;
    }
}

static void LnnOnBtAclStateChanged(int32_t listenerId, const SoftBusBtAddr *addr, int32_t aclState, int32_t hciReason)
{
    (void)hciReason;
    if (listenerId < 0 || addr == NULL) {
        LNN_LOGE(LNN_STATE, "bt monitor get invalid param");
        return;
    }
    char btMac[BT_MAC_LEN] = {0};
    if (ConvertBtMacToStr(btMac, sizeof(btMac), addr->addr, sizeof(addr->addr)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "convert bt mac to str fail");
        return;
    }
    switch (aclState) {
        case SOFTBUS_ACL_STATE_CONNECTED:
            LnnNotifyBtAclStateChangeEvent(btMac, SOFTBUS_BR_ACL_CONNECTED);
            break;
        case SOFTBUS_ACL_STATE_DISCONNECTED:
            LnnNotifyBtAclStateChangeEvent(btMac, SOFTBUS_BR_ACL_DISCONNECTED);
            break;
        default:
            LNN_LOGD(LNN_STATE, "not support acl state=%{public}d", aclState);
            break;
    }
}

int32_t LnnInitBtStateMonitorImpl(void)
{
    g_btStateListenerId = SoftBusAddBtStateListener(&g_btStateListener);
    if (g_btStateListenerId < 0) {
        LNN_LOGE(LNN_INIT, "monitor add bt state listener fail");
        return SOFTBUS_COMM_BLUETOOTH_ADD_STATE_LISTENER_ERR;
    }
    LNN_LOGI(LNN_INIT, "lnn bt state monitor impl start success");
    return SOFTBUS_OK;
}

void LnnDeinitBtStateMonitorImpl(void)
{
    (void)SoftBusRemoveBtStateListener(g_btStateListenerId);
}