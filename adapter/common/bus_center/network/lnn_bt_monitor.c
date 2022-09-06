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
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

static int32_t g_btStateListenerId = -1;
static void LnnOnBtStateChanged(int32_t listenerId, int32_t state);
static void LnnOnBtAclStateChanged(int32_t listenerId, const SoftBusBtAddr *addr, int32_t aclState);

static SoftBusBtStateListener g_btStateListener = {
    .OnBtStateChanged = LnnOnBtStateChanged,
    .OnBtAclStateChanged = LnnOnBtAclStateChanged,
};

static void LnnOnBtStateChanged(int32_t listenerId, int32_t state)
{
    if (listenerId < 0 || state < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bt monitor get invalid param");
        return;
    }

    SoftBusBtStackState btState = (SoftBusBtStackState)state;
    SoftBusBtState *notifyState = (SoftBusBtState *)SoftBusMalloc(sizeof(SoftBusBtState));
    if (notifyState == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bt monitor malloc err");
        return;
    }
    *notifyState = SOFTBUS_BT_UNKNOWN;
    switch (btState) {
        case SOFTBUS_BT_STATE_TURN_ON:
            *notifyState = SOFTBUS_BLE_TURN_ON;
            break;
        case SOFTBUS_BT_STATE_TURN_OFF:
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
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_DBG, "lnn bt state changed but no need notify, btState:%d", btState);
        SoftBusFree(notifyState);
        return;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "lnn async notify bt state changed, listenerId:%d, notifyState:%d",
        listenerId, *notifyState);
    int32_t ret = LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), LnnNotifyBtStateChangeEvent, notifyState);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "lnn async notify bt state err, ret:%d", ret);
        SoftBusFree(notifyState);
        return;
    }
}

static void LnnOnBtAclStateChanged(int32_t listenerId, const SoftBusBtAddr *addr, int32_t aclState)
{
    if (listenerId < 0 || addr == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "bt monitor get invalid param");
        return;
    }
    char btMac[BT_MAC_LEN] = {0};
    if (ConvertBtMacToStr(btMac, sizeof(btMac), addr->addr, sizeof(addr->addr)) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "convert bt mac to str fail.");
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
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_WARN, "not support acl state: %d", aclState);
            break;
    }
}

int32_t LnnInitBtStateMonitorImpl(void)
{
    g_btStateListenerId = SoftBusAddBtStateListener(&g_btStateListener);
    if (g_btStateListenerId < 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "monitor add bt state listener fail");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_INFO, "lnn bt state monitor impl start success");
    return SOFTBUS_OK;
}

void LnnDeinitBtStateMonitorImpl(void)
{
    (void)SoftBusRemoveBtStateListener(g_btStateListenerId);
}