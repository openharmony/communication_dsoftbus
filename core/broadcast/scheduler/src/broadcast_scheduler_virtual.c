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

#include "broadcast_scheduler.h"
#include "softbus_error_code.h"

int32_t SchedulerInitBroadcast(void)
{
    return SOFTBUS_OK;
}

int32_t SchedulerDeinitBroadcast(void)
{
    return SOFTBUS_OK;
}

int32_t SchedulerRegisterBroadcaster(BaseServiceType type, int32_t *bcId, const BroadcastCallback *cb)
{
    (void)type;
    (void)bcId;
    (void)cb;
    return SOFTBUS_OK;
}

int32_t SchedulerUnregisterBroadcaster(int32_t bcId)
{
    (void)bcId;
    return SOFTBUS_OK;
}

int32_t SchedulerRegisterScanListener(BaseServiceType type, int32_t *listenerId, const ScanCallback *cb)
{
    (void)type;
    (void)listenerId;
    (void)cb;
    return SOFTBUS_OK;
}

int32_t SchedulerUnregisterListener(int32_t listenerId)
{
    (void)listenerId;
    return SOFTBUS_OK;
}

int32_t SchedulerStartBroadcast(int32_t bcId, BroadcastContentType contentType, const BroadcastParam *param,
    const BroadcastPacket *packet)
{
    (void)bcId;
    (void)contentType;
    (void)param;
    (void)packet;
    return SOFTBUS_OK;
}

int32_t SchedulerUpdateBroadcast(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet)
{
    (void)bcId;
    (void)param;
    (void)packet;
    return SOFTBUS_OK;
}

int32_t SchedulerSetBroadcastData(int32_t bcId, const BroadcastPacket *packet)
{
    (void)bcId;
    (void)packet;
    return SOFTBUS_OK;
}

int32_t SchedulerStopBroadcast(int32_t bcId)
{
    (void)bcId;
    return SOFTBUS_OK;
}

int32_t SchedulerStartScan(int32_t listenerId, const BcScanParams *param)
{
    (void)listenerId;
    (void)param;
    return SOFTBUS_OK;
}

int32_t SchedulerStopScan(int32_t listenerId)
{
    (void)listenerId;
    return SOFTBUS_OK;
}

int32_t SchedulerSetScanFilter(int32_t listenerId, const BcScanFilter *scanFilter, uint8_t filterNum)
{
    (void)listenerId;
    (void)scanFilter;
    (void)filterNum;
    return SOFTBUS_OK;
}

int32_t SchedulerGetScanFilter(int32_t listenerId, BcScanFilter **scanFilter, uint8_t *filterNum)
{
    (void)listenerId;
    (void)scanFilter;
    (void)filterNum;
    return SOFTBUS_OK;
}

int32_t SchedulerQueryBroadcastStatus(int32_t bcId, int32_t *status)
{
    (void)bcId;
    (void)status;
    return SOFTBUS_OK;
}

bool SchedulerIsLpDeviceAvailable(void)
{
    return false;
}

bool SchedulerSetAdvDeviceParam(LpServerType type, const LpBroadcastParam *bcParam,
    const LpScanParam *scanParam)
{
    (void)type;
    (void)bcParam;
    (void)scanParam;
    return false;
}

int32_t SchedulerGetBroadcastHandle(int32_t bcId, int32_t *bcHandle)
{
    (void)bcId;
    (void)bcHandle;
    return SOFTBUS_OK;
}

int32_t SchedulerEnableSyncDataToLpDevice(void)
{
    return SOFTBUS_OK;
}

int32_t SchedulerDisableSyncDataToLpDevice(void)
{
    return SOFTBUS_OK;
}

int32_t SchedulerSetScanReportChannelToLpDevice(int32_t listenerId, bool enable)
{
    (void)listenerId;
    (void)enable;
    return SOFTBUS_OK;
}

int32_t SchedulerSetLpAdvParam(int32_t duration, int32_t maxExtAdvEvents, int32_t window,
    int32_t interval, int32_t bcHandle)
{
    (void)duration;
    (void)maxExtAdvEvents;
    (void)window;
    (void)interval;
    (void)bcHandle;
    return SOFTBUS_OK;
}
