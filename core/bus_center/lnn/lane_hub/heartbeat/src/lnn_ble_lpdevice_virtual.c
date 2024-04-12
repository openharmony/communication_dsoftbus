/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "lnn_ble_lpdevice.h"
#include "softbus_errcode.h"

int32_t LnnRegisterBleLpDeviceMediumMgr(void)
{
    return SOFTBUS_OK;
}

void SendInfoToMlpsBleOnlineProcess(void *para)
{
    (void)para;
    return;
}

void SendInfoToMlpsBleOfflineProcess(void *para)
{
    (void)para;
    return;
}

int32_t GetBurstAdvId(void)
{
    return SOFTBUS_ERR;
}

int32_t SendDeviceInfoToSHByType(SensorHubFeatureType type)
{
    (void)type;
    return SOFTBUS_OK;
}

int32_t SendAdvInfoToMlps(LpBroadcastParam *lpAdvParam, SensorHubServerType type)
{
    (void)lpAdvParam;
    (void)type;
    return SOFTBUS_OK;
}

int32_t SwtichHeartbeatReportChannel(bool isToAP)
{
    (void)isToAP;
    return SOFTBUS_OK;
}