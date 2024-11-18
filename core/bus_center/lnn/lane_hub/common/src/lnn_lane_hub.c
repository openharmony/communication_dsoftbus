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

#include "lnn_lane_hub.h"

#include "lnn_heartbeat_ctrl.h"
#include "lnn_lane.h"
#include "lnn_lane_qos.h"
#include "lnn_log.h"
#include "lnn_time_sync_manager.h"
#include "softbus_error_code.h"


int32_t LnnInitLaneHub(void)
{
    if (InitLane() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init lane fail");
        return SOFTBUS_NO_INIT;
    }
    if (LnnInitQos() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init laneQos fail");
        return SOFTBUS_NO_INIT;
    }
    if (LnnInitTimeSync() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init time sync fail");
        return SOFTBUS_NO_INIT;
    }
    if (LnnInitHeartbeat() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "init heart beat fail");
        return SOFTBUS_NO_INIT;
    }
    return SOFTBUS_OK;
}

int32_t LnnInitLaneHubDelay(void)
{
    if (LnnStartHeartbeatFrameDelay() != SOFTBUS_OK) {
        LNN_LOGE(LNN_INIT, "start heartbeat delay fail");
        return SOFTBUS_NO_INIT;
    }
    return SOFTBUS_OK;
}

void LnnDeinitLaneHub(void)
{
    LnnDeinitQos();
    DeinitLane();
    LnnDeinitTimeSync();
    LnnDeinitHeartbeat();
}
