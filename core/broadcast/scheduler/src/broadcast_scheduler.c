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
#include "disc_log.h"
#include "g_enhance_disc_func_pack.h"

int32_t SchedulerInitBroadcast(void)
{
    return SchedulerInitBroadcastPacked();
}

int32_t SchedulerDeinitBroadcast(void)
{
    return SchedulerDeinitBroadcastPacked();
}

int32_t SchedulerRegisterBroadcaster(
    BroadcastProtocol protocol, BaseServiceType type, int32_t *bcId, const BroadcastCallback *cb)
{
    return RegisterBroadcaster(protocol, type, bcId, cb);
}

int32_t SchedulerUnregisterBroadcaster(int32_t bcId)
{
    return UnRegisterBroadcaster(bcId);
}

int32_t SchedulerRegisterScanListener(
    BroadcastProtocol protocol, BaseServiceType type, int32_t *listenerId, const ScanCallback *cb)
{
    return RegisterScanListener(protocol, type, listenerId, cb);
}

int32_t SchedulerUnregisterListener(int32_t listenerId)
{
    return UnRegisterScanListener(listenerId);
}

int32_t SchedulerStartBroadcast(int32_t bcId, BroadcastContentType contentType, const BroadcastParam *param,
    const BroadcastPacket *packet)
{
    return SchedulerStartBroadcastPacked(bcId, contentType, param, packet);
}

int32_t SchedulerUpdateBroadcast(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet)
{
    return SchedulerUpdateBroadcastPacked(bcId, param, packet);
}

int32_t SchedulerSetBroadcastData(int32_t bcId, const BroadcastPacket *packet)
{
    return SchedulerSetBroadcastDataPacked(bcId, packet);
}

int32_t SchedulerSetBroadcastParam(int32_t bcId, const BroadcastParam *param)
{
    return SchedulerSetBroadcastParamPacked(bcId, param);
}

int32_t SchedulerStopBroadcast(int32_t bcId)
{
    return SchedulerStopBroadcastPacked(bcId);
}

int32_t SchedulerStartScan(int32_t listenerId, const BcScanParams *param)
{
    return StartScan(listenerId, param);
}

int32_t SchedulerStopScan(int32_t listenerId)
{
    return StopScan(listenerId);
}

int32_t SchedulerSetScanFilter(int32_t listenerId, const BcScanFilter *scanFilter, uint8_t filterNum)
{
    return SetScanFilter(listenerId, scanFilter, filterNum);
}

int32_t SchedulerGetScanFilter(int32_t listenerId, BcScanFilter **scanFilter, uint8_t *filterNum)
{
    return GetScanFilter(listenerId, scanFilter, filterNum);
}

int32_t SchedulerQueryBroadcastStatus(int32_t bcId, int32_t *status)
{
    return QueryBroadcastStatus(bcId, status);
}

bool SchedulerIsLpDeviceAvailable(void)
{
    return BroadcastIsLpDeviceAvailable();
}

bool SchedulerSetAdvDeviceParam(LpServerType type, const LpBroadcastParam *bcParam,
    const LpScanParam *scanParam)
{
    return BroadcastSetAdvDeviceParam(type, bcParam, scanParam);
}

int32_t SchedulerGetBroadcastHandle(int32_t bcId, int32_t *bcHandle)
{
    return BroadcastGetBroadcastHandle(bcId, bcHandle);
}

int32_t SchedulerEnableSyncDataToLpDevice(void)
{
    return BroadcastEnableSyncDataToLpDevice();
}

int32_t SchedulerDisableSyncDataToLpDevice(void)
{
    return BroadcastDisableSyncDataToLpDevice();
}

int32_t SchedulerSetScanReportChannelToLpDevice(int32_t listenerId, bool enable)
{
    return BroadcastSetScanReportChannelToLpDevice(listenerId, enable);
}

int32_t SchedulerSetLpAdvParam(int32_t duration, int32_t maxExtAdvEvents, int32_t window,
    int32_t interval, int32_t bcHandle)
{
    return BroadcastSetLpAdvParam(duration, maxExtAdvEvents, window, interval, bcHandle);
}
