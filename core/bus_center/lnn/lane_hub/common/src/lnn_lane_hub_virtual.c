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

#include "lnn_log.h"
#include "bus_center_manager.h"
#include "softbus_error_code.h"

int32_t LnnInitLaneHub(void)
{
    LNN_LOGI(LNN_INIT, "init virtual lane hub");
    return SOFTBUS_OK;
}

int32_t LnnInitLaneHubDelay(void)
{
    LNN_LOGI(LNN_INIT, "init virtual lane hub delay");
    return SOFTBUS_OK;
}

void LnnDeinitLaneHub(void)
{
}