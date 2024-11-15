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

#include "lnn_time_sync_manager.h"

#include "lnn_log.h"
#include "softbus_error_code.h"

int32_t LnnStartTimeSync(const char *pkgName, int32_t callingPid, const char *targetNetworkId,
    TimeSyncAccuracy accuracy, TimeSyncPeriod period)
{
    (void)pkgName;
    (void)callingPid;
    (void)targetNetworkId;
    (void)accuracy;
    (void)period;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnStopTimeSync(const char *pkgName, const char *targetNetworkId, int32_t callingPid)
{
    (void)pkgName;
    (void)targetNetworkId;
    (void)callingPid;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnInitTimeSync(void)
{
    LNN_LOGI(LNN_INIT, "time sync virtual init success");
    return SOFTBUS_OK;
}

void LnnDeinitTimeSync(void)
{
}