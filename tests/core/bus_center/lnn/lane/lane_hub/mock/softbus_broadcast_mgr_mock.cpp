/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "softbus_broadcast_mgr_mock.h"

#include "disc_log.h"
#include "securec.h"
#include "softbus_error_code.h"

using OHOS::SoftbusBroadcastMgrMock;
using testing::_;
using testing::NotNull;

// implement related global function of SoftbusBroadcastMgrInterface

extern "C" {
int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener, int32_t *listenerId)
{
    return SoftbusBroadcastMgrMock::GetMock()->SoftBusAddBtStateListener(listener, listenerId);
}

int32_t InitBroadcastMgr()
{
    return SoftbusBroadcastMgrMock::GetMock()->InitBroadcastMgr();
}

int32_t DeInitBroadcastMgr()
{
    return SoftbusBroadcastMgrMock::GetMock()->DeInitBroadcastMgr();
}

int32_t SetScanFilter(int32_t listenerId, const BcScanFilter *scanFilter, uint8_t filterNum)
{
    return SoftbusBroadcastMgrMock::GetMock()->SetScanFilter(listenerId, scanFilter, filterNum);
}

int32_t UnRegisterBroadcaster(int32_t bcId)
{
    return SoftbusBroadcastMgrMock::GetMock()->UnRegisterBroadcaster(bcId);
}

int32_t SoftBusRemoveBtStateListener(int32_t listenerId)
{
    return SoftbusBroadcastMgrMock::GetMock()->SoftBusRemoveBtStateListener(listenerId);
}

int32_t UnRegisterScanListener(int32_t listenerId)
{
    return SoftbusBroadcastMgrMock::GetMock()->UnRegisterScanListener(listenerId);
}

int32_t UpdateBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet)
{
    return SoftbusBroadcastMgrMock::GetMock()->UpdateBroadcasting(bcId, param, packet);
}

int32_t StopBroadcasting(int32_t bcId)
{
    return SoftbusBroadcastMgrMock::GetMock()->StopBroadcasting(bcId);
}

int32_t StartScan(int32_t listenerId, const BcScanParams *param)
{
    return SoftbusBroadcastMgrMock::GetMock()->StartScan(listenerId, param);
}

int32_t BroadcastEnableSyncDataToLpDevice()
{
    return SoftbusBroadcastMgrMock::GetMock()->BroadcastEnableSyncDataToLpDevice();
}

int32_t BroadcastDisableSyncDataToLpDevice()
{
    return SoftbusBroadcastMgrMock::GetMock()->BroadcastDisableSyncDataToLpDevice();
}

int32_t StopScan(int32_t listenerId)
{
    return SoftbusBroadcastMgrMock::GetMock()->StopScan(listenerId);
}

int32_t BroadcastSetScanReportChannelToLpDevice(int32_t listenerId, bool enable)
{
    return SoftbusBroadcastMgrMock::GetMock()->BroadcastSetScanReportChannelToLpDevice(listenerId, enable);
}

int32_t RegisterScanListener(BaseServiceType type, int32_t *listenerId, const ScanCallback *cb)
{
    return SoftbusBroadcastMgrMock::GetMock()->RegisterScanListener(type, listenerId, cb);
}

int32_t SoftBusGetBtState()
{
    return SoftbusBroadcastMgrMock::GetMock()->SoftBusGetBtState();
}

int32_t RegisterBroadcaster(BaseServiceType type, int32_t *bcId, const BroadcastCallback *cb)
{
    return SoftbusBroadcastMgrMock::GetMock()->RegisterBroadcaster(type, bcId, cb);
}

int32_t BroadcastGetBroadcastHandle(int32_t bcId, int32_t *bcHandle)
{
    return SoftbusBroadcastMgrMock::GetMock()->BroadcastGetBroadcastHandle(bcId, bcHandle);
}

int32_t BroadcastSetLpAdvParam(
    int32_t duration, int32_t maxExtAdvEvents, int32_t window, int32_t interval, int32_t bcHandle)
{
    return SoftbusBroadcastMgrMock::GetMock()->BroadcastSetLpAdvParam(
        duration, maxExtAdvEvents, window, interval, bcHandle);
}

bool BroadcastSetAdvDeviceParam(LpServerType type, const LpBroadcastParam *bcParam, const LpScanParam *scanParam)
{
    return SoftbusBroadcastMgrMock::GetMock()->BroadcastSetAdvDeviceParam(type, bcParam, scanParam);
}

int32_t StartBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet)
{
    return SoftbusBroadcastMgrMock::GetMock()->StartBroadcasting(bcId, param, packet);
}

int32_t SetBroadcastingData(int32_t bcId, const BroadcastPacket *packet)
{
    return SoftbusBroadcastMgrMock::GetMock()->SetBroadcastingData(bcId, packet);
}

int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac)
{
    return SoftbusBroadcastMgrMock::GetMock()->SoftBusGetBtMacAddr(mac);
}

bool BroadcastIsLpDeviceAvailable()
{
    return SoftbusBroadcastMgrMock::GetMock()->BroadcastIsLpDeviceAvailable();
}
}
// definition for class SoftbusBroadcastMgrMock
namespace OHOS {
SoftbusBroadcastMgrMock::SoftbusBroadcastMgrMock()
{
    mock.store(this);
}

SoftbusBroadcastMgrMock::~SoftbusBroadcastMgrMock()
{
    mock.store(nullptr);
}

int32_t SoftbusBroadcastMgrMock::ActionOfInitBroadcastMgr()
{
    return SOFTBUS_OK;
}

int32_t SoftbusBroadcastMgrMock::ActionOfDeInitBroadcastMgr()
{
    return SOFTBUS_OK;
}

int32_t SoftbusBroadcastMgrMock::ActionOfAddBtStateListener(const SoftBusBtStateListener *listener, int32_t *listenerId)
{
    btStateListener_ = listener;
    *listenerId = btStateListenerId_;
    return SOFTBUS_OK;
}

int32_t SoftbusBroadcastMgrMock::ActionOfRemoveBtStateListener(int32_t listenerId)
{
    btStateListener_ = nullptr;
    return SOFTBUS_OK;
}

int32_t SoftbusBroadcastMgrMock::ActionOfRegisterScanListener(
    BaseServiceType type, int32_t *listenerId, const ScanCallback *cb)
{
    *listenerId = scanListenerId_;
    scanListener_ = cb;
    return SOFTBUS_OK;
}

int32_t SoftbusBroadcastMgrMock::ActionOfUnRegisterScanListener(int32_t listenerId)
{
    scanListener_ = nullptr;
    return SOFTBUS_OK;
}

int32_t SoftbusBroadcastMgrMock::ActionOfStartBroadcasting(
    int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet)
{
    (void)param;
    if (isAdvertising_[bcId]) {
        DISC_LOGE(DISC_TEST, "bcId already in advertising. bcId=%{public}d", bcId);
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    isAdvertising_[bcId] = true;
    if (advCallback_ != nullptr && advCallback_->OnStartBroadcastingCallback != nullptr) {
        advCallback_->OnStartBroadcastingCallback(bcId, SOFTBUS_BT_STATUS_SUCCESS);
    }
    return SOFTBUS_OK;
}

int32_t SoftbusBroadcastMgrMock::ActionOfStopBroadcasting(int32_t bcId)
{
    if (!isAdvertising_[bcId]) {
        DISC_LOGE(DISC_TEST, "bcId already has stopped. bcId=%{public}d", bcId);
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    isAdvertising_[bcId] = false;
    if (advCallback_ != nullptr && advCallback_->OnStopBroadcastingCallback != nullptr) {
        advCallback_->OnStopBroadcastingCallback(bcId, SOFTBUS_BT_STATUS_SUCCESS);
    }
    return SOFTBUS_OK;
}

int32_t SoftbusBroadcastMgrMock::ActionOfStartScan(int32_t listenerId, const BcScanParams *param)
{
    (void)param;
    if (listenerId != scanListenerId_) {
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    isScanning_[listenerId] = true;
    if (scanListener_ != nullptr && scanListener_->OnStartScanCallback != nullptr) {
        scanListener_->OnStartScanCallback(scanListenerId_, SOFTBUS_BT_STATUS_SUCCESS);
    }
    return SOFTBUS_OK;
}

int32_t SoftbusBroadcastMgrMock::ActionOfStopScan(int32_t listenerId)
{
    if (listenerId != scanListenerId_) {
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    isScanning_[listenerId] = false;
    if (scanListener_ != nullptr && scanListener_->OnStopScanCallback != nullptr) {
        scanListener_->OnStopScanCallback(scanListenerId_, SOFTBUS_BT_STATUS_SUCCESS);
    }
    return SOFTBUS_OK;
}

int32_t SoftbusBroadcastMgrMock::ActionOfSetScanFilter(
    int32_t listenerId, const BcScanFilter *scanFilter, uint8_t filterNum)
{
    DISC_LOGI(DISC_TEST, "listenerId=%{public}d, filterSize=%{public}d", listenerId, filterNum);
    return SOFTBUS_OK;
}

int32_t SoftbusBroadcastMgrMock::ActionOfRegisterBroadcaster(
    BaseServiceType type, int32_t *bcId, const BroadcastCallback *cb)
{
    static int32_t advChannel = 0;
    *bcId = advChannel;
    advChannel++;
    advCallback_ = cb;
    return SOFTBUS_OK;
}

int32_t SoftbusBroadcastMgrMock::ActionOfUnRegisterBroadcaster(int32_t bcId)
{
    (void)bcId;
    advCallback_ = nullptr;
    return SOFTBUS_OK;
}

int32_t SoftbusBroadcastMgrMock::ActionOfGetBtMacAddr(SoftBusBtAddr *mac)
{
    if (memcpy_s(mac->addr, sizeof(mac->addr), btMacAddr_, sizeof(btMacAddr_)) != EOK) {
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusBroadcastMgrMock::ActionOfGetBtState()
{
    return btState_ ? BLE_ENABLE : BLE_DISABLE;
}

void SoftbusBroadcastMgrMock::TurnOnBt()
{
    btState_ = true;
    if (btStateListener_ != nullptr && btStateListener_->OnBtStateChanged != nullptr) {
        btStateListener_->OnBtStateChanged(btStateListenerId_, SOFTBUS_BLE_STATE_TURN_ON);
    }
}

void SoftbusBroadcastMgrMock::TurnOffBt()
{
    btState_ = false;
    if (btStateListener_ != nullptr && btStateListener_->OnBtStateChanged != nullptr) {
        btStateListener_->OnBtStateChanged(btStateListenerId_, SOFTBUS_BLE_STATE_TURN_OFF);
    }
}

bool SoftbusBroadcastMgrMock::IsDeInitSuccess()
{
    return advCallback_ == nullptr;
}

void SoftbusBroadcastMgrMock::SetListenerId(const int32_t btStateListenerId, const int32_t scanListenerId)
{
    btStateListenerId_ = btStateListenerId;
    scanListenerId_ = scanListenerId;
}
} // namespace OHOS