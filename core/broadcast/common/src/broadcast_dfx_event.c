/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
 
#include "broadcast_dfx_event.h"
#include "disc_log.h"
#include "softbus_adapter_timer.h"
 
void BroadcastDiscEvent(int32_t eventScene, int32_t eventStage, DiscEventExtra *discExtra, int32_t size)
{
    if (discExtra == NULL) {
        DISC_LOGE(DISC_BLE, "scanExtra is null");
        return;
    }
 
    DiscEventExtra extra = { 0 };
    int32_t stamptime = (int32_t)SoftBusGetSysTimeMs();
    for (int32_t i = 0; i < size; i++) {
        extra.capabilityBit = discExtra[i].capabilityBit;
        extra.discType = discExtra[i].discType;
        extra.broadcastType = discExtra[i].broadcastType;
        extra.minInterval = discExtra[i].minInterval;
        extra.maxInterval = discExtra[i].maxInterval;
        extra.successCnt = discExtra[i].successCnt;
        extra.failCnt = discExtra[i].failCnt;
        if (discExtra[i].isOn == 0) {
            extra.costTime = discExtra[i].costTime;
        } else {
            discExtra[i].costTime += (stamptime - discExtra[i].startTime);
            extra.costTime = discExtra[i].costTime;
            discExtra[i].startTime = stamptime;
        }
        DISC_LOGI(DISC_BLE, "capa=%{public}d, discType=%{public}d, broadcastType=%{public}d, minInterval=%{public}d, "
            "maxInterval=%{public}d, succCnt=%{public}d, failCnt=%{public}d, costTime=%{public}d, Scene=%{public}d",
            extra.capabilityBit, extra.discType, extra.broadcastType, extra.minInterval, extra.maxInterval,
            extra.successCnt, extra.failCnt, extra.costTime, eventScene);
        DISC_EVENT(eventScene, eventStage, extra);
    }
}
 
void BroadcastScanEvent(int32_t eventScene, int32_t eventStage, DiscEventExtra *scanExtra, int32_t size)
{
    if (scanExtra == NULL) {
        DISC_LOGE(DISC_BLE, "scanExtra is null");
        return;
    }
 
    DiscEventExtra extra = { 0 };
    for (int32_t i = 0; i < size; i++) {
        extra.capabilityBit = scanExtra[i].capabilityBit;
        extra.scanType = scanExtra[i].scanType;
        extra.scanCount = scanExtra[i].scanCount;
        DISC_LOGI(DISC_BLE, "capa = %{public}d, scanType = %{public}d, scanCount = %{public}d, Scene=%{public}d",
            extra.capabilityBit, extra.scanType, extra.scanCount, eventScene);
        DISC_EVENT(eventScene, eventStage, extra);
    }
}