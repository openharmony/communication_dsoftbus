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
#include "softbus_error_code.h"
#include "softbus_adapter_mem.h"

int32_t LnnRegisterBleLpDeviceMediumMgr(void)
{
    return SOFTBUS_OK;
}

void SendDeviceStateToMlps(void *para)
{
    if (para != NULL) {
        SoftBusFree(para);
    }
}

void UpdateLocalDeviceInfoToMlps(const NodeInfo *localInfo)
{
    (void)localInfo;
}

void UpdateRemoteDeviceInfoToMlps(const NodeInfo *info)
{
    (void)info;
}

void UpdateRemoteDeviceInfoListToMlps(void)
{
}

int32_t GetBurstAdvId(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t SendDeviceInfoToSHByType(LpFeatureType type)
{
    (void)type;
    return SOFTBUS_OK;
}

int32_t SendAdvInfoToMlps(LpBroadcastParam *lpAdvParam, LpServerType type)
{
    (void)lpAdvParam;
    (void)type;
    return SOFTBUS_OK;
}

int32_t SwtichHeartbeatReportChannel(bool isToAP, uint16_t scanInterval, uint16_t scanWindow)
{
    (void)isToAP;
    (void)scanInterval;
    (void)scanWindow;
    return SOFTBUS_OK;
}

bool IsSupportLpFeature(void)
{
    return false;
}

void SetLpKeepAliveState(void *para)
{
    (void)para;
}

void AsyncSetBleBroadcastTimeStamp(const char *networkId)
{
    (void)networkId;
}

void SendCleanMsgToMlps(uint32_t cleanType)
{
    (void)cleanType;
}