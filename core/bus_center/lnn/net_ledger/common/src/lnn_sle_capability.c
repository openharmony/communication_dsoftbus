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

#include <stdatomic.h>
#include <securec.h>

#include "bus_center_manager.h"
#include "lnn_log.h"
#include "lnn_sle_capability.h"
#include "softbus_adapter_sle_common.h"
#include "softbus_error_code.h"

static void SleStateChangeEventHandler(int32_t state);

const SoftBusSleStateListener g_sleStateChangedListener = {
    .onSleStateChanged = SleStateChangeEventHandler,
};

static int32_t g_sleStateListenerId = -1;

int32_t SetSleRangeCapToLocalLedger()
{
    int32_t sleRangeCap = GetSleRangeCapacity();
    int32_t ret = LnnSetLocalNumInfo(NUM_KEY_SLE_RANGE_CAP, sleRangeCap);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnSetLocalNumInfo fail, ret=%u", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t SetSleAddrToLocalLedger()
{
    if (!IsSleEnabled()) {
        LNN_LOGI(LNN_LEDGER, "SLE not enabled!");
        return SOFTBUS_SLE_RANGING_NOT_ENABLE;
    }
    char sleMacAddr[MAC_LEN];
    int32_t ret = GetLocalSleAddr(sleMacAddr, MAC_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "GetLocalSleAddr fail, ret=%u", ret);
        return ret;
    }
    ret = LnnSetLocalStrInfo(STRING_KEY_SLE_ADDR, sleMacAddr);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "LnnSetLocalStrInfo fail, ret=%u", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static void SleStateChangeEventHandler(int32_t state)
{
    LNN_LOGE(LNN_LEDGER, "SleStateChangeEventHandler enter!");
    if (state != SOFTBUS_SLE_STATE_TURN_ON) {
        LNN_LOGI(LNN_LEDGER, "event is not sle turn on, ignore");
        return;
    }
    (void)SetSleAddrToLocalLedger();
}

int32_t LocalLedgerInitSleCapacity(NodeInfo* nodeInfo)
{
    if (nodeInfo == NULL) {
        LNN_LOGE(LNN_LEDGER, "NodeInfo is NULL");
        return SOFTBUS_ERR;
    }
    int32_t sleCapacity = GetSleRangeCapacity();
    char sleMacAddr[MAC_LEN] = { 0 };
    int32_t ret = GetLocalSleAddr(sleMacAddr, MAC_LEN);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "GetLocalSleAddr fail, ret=%u", ret);
        return ret;
    }
    nodeInfo->sleRangeCapacity = sleCapacity;
    memcpy_s(nodeInfo->connectInfo.sleMacAddr, MAC_LEN, sleMacAddr, MAC_LEN);
    ret = SoftBusAddSleStateListener(&g_sleStateChangedListener, &g_sleStateListenerId);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "Add sle state listener failed.");
        return ret;
    }
    return SOFTBUS_OK;
}

void LocalLedgerDeinitSleCapacity()
{
    SoftBusRemoveSleStateListener(g_sleStateListenerId);
    g_sleStateListenerId = -1;
}