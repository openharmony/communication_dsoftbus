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

#include "softbus_ble_mock.h"

#include "disc_log.h"
#include "softbus_error_code.h"

ManagerMock *ManagerMock::managerMock = nullptr;
const SoftbusBroadcastCallback *ManagerMock::broadcastCallback = nullptr;
const SoftbusScanCallback *ManagerMock::scanCallback = nullptr;

static int32_t g_advId = 0;
static int32_t g_listenerId = 0;
static void ActionOfSoftbusBleAdapterInit(void);

int32_t ActionOfSoftBusAddBtStateListener(const SoftBusBtStateListener *listener)
{
    return SOFTBUS_OK;
}

int32_t ActionOfSoftBusRemoveBtStateListener(int32_t listenerId)
{
    return SOFTBUS_OK;
}

ManagerMock::ManagerMock()
{
    ManagerMock::managerMock = this;
    EXPECT_CALL(*this, SoftbusBleAdapterInit).WillRepeatedly(ActionOfSoftbusBleAdapterInit);
    EXPECT_CALL(*this, SoftBusAddBtStateListener).WillRepeatedly(ActionOfSoftBusAddBtStateListener);
    EXPECT_CALL(*this, SoftBusRemoveBtStateListener).WillRepeatedly(ActionOfSoftBusRemoveBtStateListener);
}

ManagerMock::~ManagerMock()
{
    ManagerMock::managerMock = nullptr;
}

ManagerMock *ManagerMock::GetMock()
{
    return managerMock;
}

void SoftbusBleAdapterInit()
{
    ManagerMock::GetMock()->SoftbusBleAdapterInit();
}

static int32_t MockInit(void)
{
    return SOFTBUS_OK;
}

static int32_t MockDeInit(void)
{
    return SOFTBUS_OK;
}

int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener)
{
    return ManagerMock::GetMock()->SoftBusAddBtStateListener(listener);
}

int32_t SoftBusRemoveBtStateListener(int32_t listenerId)
{
    return ManagerMock::GetMock()->SoftBusRemoveBtStateListener(listenerId);
}

static int32_t MockRegisterBroadcaster(int32_t *bcId, const SoftbusBroadcastCallback *cb)
{
    ManagerMock::broadcastCallback = cb;
    *bcId = g_advId;
    g_advId++;
    return SOFTBUS_OK;
}

static int32_t MockUnRegisterBroadcaster(int32_t bcId)
{
    ManagerMock::broadcastCallback = nullptr;
    g_advId--;
    return SOFTBUS_OK;
}

static int32_t MockRegisterScanListener(int32_t *scanerId, const SoftbusScanCallback *cb)
{
    ManagerMock::scanCallback = cb;
    *scanerId = g_listenerId;
    g_listenerId++;
    return SOFTBUS_OK;
}

static int32_t MockUnRegisterScanListener(int32_t scanerId)
{
    ManagerMock::scanCallback = nullptr;
    g_listenerId--;
    return SOFTBUS_OK;
}

static int32_t MockStartBroadcasting(int32_t bcId, const SoftbusBroadcastParam *param, const SoftbusBroadcastData *data)
{
    ManagerMock::broadcastCallback->OnStartBroadcastingCallback(bcId, (int32_t)SOFTBUS_BC_STATUS_SUCCESS);
    return SOFTBUS_OK;
}

static int32_t MockStopBroadcasting(int32_t bcId)
{
    ManagerMock::broadcastCallback->OnStopBroadcastingCallback(bcId, (int32_t)SOFTBUS_BC_STATUS_SUCCESS);
    return SOFTBUS_OK;
}

static int32_t MockSetBroadcastingData(int32_t bcId, const SoftbusBroadcastData *data)
{
    ManagerMock::broadcastCallback->OnSetBroadcastingCallback(bcId, (int32_t)SOFTBUS_BC_STATUS_SUCCESS);
    return SOFTBUS_OK;
}

static int32_t MockUpdateBroadcasting(
    int32_t bcId, const SoftbusBroadcastParam *param, const SoftbusBroadcastData *data)
{
    ManagerMock::broadcastCallback->OnUpdateBroadcastingCallback(bcId, (int32_t)SOFTBUS_BC_STATUS_SUCCESS);
    return SOFTBUS_OK;
}

static int32_t MockStartScan(
    int32_t scanerId, const SoftBusBcScanParams *param, const SoftBusBcScanFilter *scanFilter, int32_t filterSize)
{
    return SOFTBUS_OK;
}

static int32_t MockStopScan(int32_t scanerId)
{
    return SOFTBUS_OK;
}

static bool MockIsLpDeviceAvailable(void)
{
    return true;
}

static bool MockSetAdvFilterParam(
    LpServerType type, const SoftBusLpBroadcastParam *bcParam, const SoftBusLpScanParam *scanParam)
{
    return SOFTBUS_OK;
}

static int32_t MockGetBroadcastHandle(int32_t bcId, int32_t *bcHandle)
{
    return SOFTBUS_OK;
}

static int32_t MockEnableSyncDataToLpDevice(void)
{
    return SOFTBUS_OK;
}

static int32_t MockDisableSyncDataToLpDevice(void)
{
    return SOFTBUS_OK;
}

static int32_t MockSetScanReportChannelToLpDevice(int32_t scannerId, bool enable)
{
    return SOFTBUS_OK;
}

static int32_t MockSetLpDeviceParam(
    int32_t duration, int32_t maxExtAdvEvents, int32_t window, int32_t interval, int32_t bcHandle)
{
    return SOFTBUS_OK;
}

static void ActionOfSoftbusBleAdapterInit()
{
    DISC_LOGI(DISC_TEST, "enter");
    static SoftbusBroadcastMediumInterface interface = {
        .Init = MockInit,
        .DeInit = MockDeInit,
        .RegisterBroadcaster = MockRegisterBroadcaster,
        .UnRegisterBroadcaster = MockUnRegisterBroadcaster,
        .RegisterScanListener = MockRegisterScanListener,
        .UnRegisterScanListener = MockUnRegisterScanListener,
        .StartBroadcasting = MockStartBroadcasting,
        .StopBroadcasting = MockStopBroadcasting,
        .SetBroadcastingData = MockSetBroadcastingData,
        .UpdateBroadcasting = MockUpdateBroadcasting,
        .StartScan = MockStartScan,
        .StopScan = MockStopScan,
        .IsLpDeviceAvailable = MockIsLpDeviceAvailable,
        .SetAdvFilterParam = MockSetAdvFilterParam,
        .GetBroadcastHandle = MockGetBroadcastHandle,
        .EnableSyncDataToLpDevice = MockEnableSyncDataToLpDevice,
        .DisableSyncDataToLpDevice = MockDisableSyncDataToLpDevice,
        .SetScanReportChannelToLpDevice = MockSetScanReportChannelToLpDevice,
        .SetLpDeviceParam = MockSetLpDeviceParam,
    };
    if (RegisterBroadcastMediumFunction(BROADCAST_MEDIUM_TYPE_BLE, &interface) != 0) {
        DISC_LOGE(DISC_TEST, "Register gatt interface failed.");
    }
}

void SoftbusBleAdapterDeInit(void)
{
    DISC_LOGI(DISC_TEST, "enter");
}
