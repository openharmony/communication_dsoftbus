/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "lnn_sle_monitor.h"

#include <securec.h>
#include <stdatomic.h>

#include "bus_center_event.h"
#include "g_enhance_adapter_func_pack.h"
#include "lnn_async_callback_utils.h"
#include "lnn_log.h"
#include "softbus_adapter_sle_common_struct.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

static int32_t g_lnnsleListenerId = -1;
static void LnnOnSleStateChanged(int32_t sleState);

static SoftBusSleStateListener g_softbusLnnSleStateListener = {
    .onSleStateChanged = LnnOnSleStateChanged,
};

static void LnnOnSleStateChanged(int32_t sleState)
{
    SoftBusSleState *notifyState = (SoftBusSleState *)SoftBusCalloc(sizeof(SoftBusSleState));
    if (notifyState == NULL) {
        LNN_LOGE(LNN_STATE, "sle monitor malloc err");
        return;
    }
    *notifyState = SOFTBUS_SLE_UNKNOWN;
    switch (sleState) {
        case SOFTBUS_SLE_STATE_TURN_ON:
            *notifyState = SOFTBUS_SLE_TURN_ON;
            break;
        case SOFTBUS_SLE_STATE_TURN_OFF:
            *notifyState = SOFTBUS_SLE_TURN_OFF;
            break;
        default:
            break;
    }

    if (*notifyState == SOFTBUS_SLE_UNKNOWN) {
        LNN_LOGD(LNN_STATE, "sle state changed but no need notify, sleState=%{public}d", sleState);
        SoftBusFree(notifyState);
        return;
    }
    LNN_LOGI(LNN_STATE, "async notify sle state changed, notifyState=%{public}d", *notifyState);
    int32_t ret = LnnAsyncCallbackHelper(GetLooper(LOOP_TYPE_DEFAULT), LnnNotifySleStateChangeEvent,
        (void *)notifyState);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "async notify sle state err, ret=%{public}d", ret);
        SoftBusFree(notifyState);
        return;
    }
}

int32_t LnnInitSle(void)
{
    int32_t listenId = -1;
    int32_t ret = SoftBusAddSleStateListenerPacked(&g_softbusLnnSleStateListener, &listenId);
    if (ret != SOFTBUS_OK || listenId == -1) {
        LNN_LOGE(LNN_INIT, "monitor add sle state listener fail");
        return SOFTBUS_COMM_BLUETOOTH_ADD_STATE_LISTENER_ERR;
    }
    g_lnnsleListenerId = listenId;
    if (IsSleEnabledPacked()) {
        LnnOnSleStateChanged(SOFTBUS_SLE_STATE_TURN_ON);
    } else {
        LnnOnSleStateChanged(SOFTBUS_SLE_STATE_TURN_OFF);
    }
    LNN_LOGI(LNN_INIT, "lnn sle state monitor impl start success");
    return SOFTBUS_OK;
}

void LnnDeinitSle(void)
{
    (void)SoftBusRemoveSleStateListenerPacked(g_lnnsleListenerId);
}