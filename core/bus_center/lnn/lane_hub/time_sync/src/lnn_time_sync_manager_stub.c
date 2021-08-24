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

#include "softbus_errcode.h"
#include "softbus_log.h"

int32_t LnnStartTimeSync(const char *pkgName, const char *targetNetworkId,
    TimeSyncAccuracy accuracy, TimeSyncPeriod period)
{
    (void)pkgName;
    (void)targetNetworkId;
    (void)accuracy;
    (void)period;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "start time sync stub enter");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnStopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    (void)targetNetworkId;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "stop time sync stub impl");
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnTimeSyncInit(LnnOnTimeSyncResult notifyCallback)
{
    (void)notifyCallback;
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "time sync stub init");
    return SOFTBUS_OK;
}

void LnnTimeSyncDeinit(void)
{
    SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "time sync stub deinit");
}