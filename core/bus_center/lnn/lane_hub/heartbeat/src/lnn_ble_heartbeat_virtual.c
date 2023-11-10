/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "lnn_ble_heartbeat.h"

#include "lnn_log.h"
#include "lnn_heartbeat_medium_mgr.h"
#include "softbus_errcode.h"

static int32_t InitBleHeartbeat(const LnnHeartbeatMediumMgrCb *callback)
{
    (void)callback;

    LNN_LOGI(LNN_INIT, "ble heartbeat stub impl init");
    return SOFTBUS_OK;
}

static int32_t BleHeartbeatOnceBegin(const LnnHeartbeatSendBeginData *custData)
{
    (void)custData;

    LNN_LOGI(LNN_HEART_BEAT, "ble heartbeat stub impl beat once");
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t BleHeartbeatOnceEnd(const LnnHeartbeatSendEndData *custData)
{
    (void)custData;

    LNN_LOGI(LNN_HEART_BEAT, "ble heartbeat stub impl beat end");
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t SetBleMediumParam(const LnnHeartbeatMediumParam *param)
{
    (void)param;

    LNN_LOGI(LNN_HEART_BEAT, "ble heartbeat stub impl set medium param");
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t UpdateBleSendInfo(LnnHeartbeatUpdateInfoType type)
{
    (void)type;

    LNN_LOGI(LNN_HEART_BEAT, "ble heartbeat stub impl update send info");
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t StopBleHeartbeat(void)
{
    LNN_LOGI(LNN_HEART_BEAT, "ble heartbeat stub impl beat stop");
    return SOFTBUS_NOT_IMPLEMENT;
}

static void DeinitBleHeartbeat(void)
{
    LNN_LOGI(LNN_INIT, "ble heartbeat stub impl deinit");
    return;
}

static LnnHeartbeatMediumMgr g_bleMgr = {
    .supportType = HEARTBEAT_TYPE_BLE_V0 | HEARTBEAT_TYPE_BLE_V1,
    .init = InitBleHeartbeat,
    .onSendOneHbBegin = BleHeartbeatOnceBegin,
    .onSendOneHbEnd = BleHeartbeatOnceEnd,
    .onSetMediumParam = SetBleMediumParam,
    .onUpdateSendInfo = UpdateBleSendInfo,
    .onStopHbByType = StopBleHeartbeat,
    .deinit = DeinitBleHeartbeat,
};

int32_t LnnRegistBleHeartbeatMediumMgr(void)
{
    return LnnRegistHeartbeatMediumMgr(&g_bleMgr);
}

int32_t HbUpdateBleScanFilter(int32_t listenerId, LnnHeartbeatType type)
{
    (void)listenerId;
    (void)type;
    return SOFTBUS_OK;
}
