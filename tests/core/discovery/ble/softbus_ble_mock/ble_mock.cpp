/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "ble_mock.h"
#include <string>
#include <sstream>
#include <thread>
#include "securec.h"
#include "softbus_log.h"
#include "softbus_error_code.h"

using testing::_;
using testing::NotNull;

/* implement related global function of BLE */
int BleGattLockInit()
{
    return BleMock::GetMock()->BleGattLockInit();
}

int SoftBusAddBtStateListener(const SoftBusBtStateListener *listener)
{
    return BleMock::GetMock()->SoftBusAddBtStateListener(listener);
}

int SoftBusAddScanListener(const SoftBusScanListener *listener)
{
    return BleMock::GetMock()->SoftBusAddScanListener(listener);
}

int SoftBusSetScanFilter(int listenerId, SoftBusBleScanFilter *filter, uint8_t filterSize)
{
    return BleMock::GetMock()->SoftBusSetScanFilter(listenerId, filter, filterSize);
}

int SoftBusGetAdvChannel(const SoftBusAdvCallback *callback)
{
    return BleMock::GetMock()->SoftBusGetAdvChannel(callback);
}

int SoftBusReleaseAdvChannel(int channel)
{
    return BleMock::GetMock()->SoftBusReleaseAdvChannel(channel);
}

int SoftBusStopScan(int listenerId)
{
    return BleMock::GetMock()->SoftBusStopScan(listenerId);
}

int SoftBusRemoveBtStateListener(int listenerId)
{
    return BleMock::GetMock()->SoftBusRemoveBtStateListener(listenerId);
}

int SoftBusRemoveScanListener(int listenerId)
{
    return BleMock::GetMock()->SoftBusRemoveScanListener(listenerId);
}

int SoftBusStopAdv(int channel)
{
    return BleMock::GetMock()->SoftBusStopAdv(channel);
}

int SoftBusUpdateAdv(int channel, const SoftBusBleAdvData *data, const SoftBusBleAdvParams *param)
{
    return BleMock::GetMock()->SoftBusUpdateAdv(channel, data, param);
}

int SoftBusStartScan(int listenerId, const SoftBusBleScanParams *param)
{
    return BleMock::GetMock()->SoftBusStartScan(listenerId, param);
}

int SoftBusSetAdvData(int channel, const SoftBusBleAdvData *data)
{
    return BleMock::GetMock()->SoftBusSetAdvData(channel, data);
}

int SoftBusStartAdv(int channel, const SoftBusBleAdvParams *param)
{
    return BleMock::GetMock()->SoftBusStartAdv(channel, param);
}

int SoftBusGetBtMacAddr(SoftBusBtAddr *mac)
{
    return BleMock::GetMock()->SoftBusGetBtMacAddr(mac);
}

int SoftBusGetBtState()
{
    return BleMock::GetMock()->SoftBusGetBtState();
}

/* definition for class BleMock */
BleMock::BleMock()
{
    mock.store(this);
    isAsyncAdvertiseSuccess = true;
}

BleMock::~BleMock()
{
    mock.store(nullptr);
}

int32_t BleMock::ActionOfBleGattLockInit()
{
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfAddBtStateListener(const SoftBusBtStateListener *listener)
{
    btStateListener = listener;
    return BT_STATE_LISTENER_ID;
}

int32_t BleMock::ActionOfRemoveBtStateListener(int listenerId)
{
    btStateListener = nullptr;
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfAddScanListener(const SoftBusScanListener *listener)
{
    scanListener = listener;
    return SCAN_LISTENER_ID;
}

int32_t BleMock::ActionOfRemoveScanListener(int listenerId)
{
    scanListener = nullptr;
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfSetScanFilter(int listenerId, const SoftBusBleScanFilter *filter, uint8_t filterSize)
{
    DLOGI("listenerId=%d filterSize=%d", listenerId, filterSize);
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfGetAdvChannel(const SoftBusAdvCallback *callback)
{
    static int32_t advChannel = 0;
    advCallback = callback;
    return advChannel++;
}

int32_t BleMock::ActionOfReleaseAdvChannel(int channel)
{
    advCallback = nullptr;
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfStartScan(int listenerId, const SoftBusBleScanParams *param)
{
    if (listenerId != SCAN_LISTENER_ID) {
        return SOFTBUS_ERR;
    }

    isScanning = true;
    if (scanListener && scanListener->OnScanStart) {
        scanListener->OnScanStart(SCAN_LISTENER_ID, SOFTBUS_BT_STATUS_SUCCESS);
    }
    GetMock()->UpdateScanStateDone();
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfStopScan(int listenerId)
{
    if (listenerId != SCAN_LISTENER_ID) {
        return SOFTBUS_ERR;
    }

    isScanning = false;
    if (scanListener && scanListener->OnScanStop) {
        scanListener->OnScanStop(SCAN_LISTENER_ID, SOFTBUS_BT_STATUS_SUCCESS);
    }
    GetMock()->UpdateScanStateDone();
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfStartAdv(int channel, const SoftBusBleAdvParams *param)
{
    if (isAdvertising) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "already in advertising");
        return SOFTBUS_ERR;
    }
    isAdvertising = !isAdvertising;
    if (advCallback) {
        advCallback->AdvEnableCallback(channel, SOFTBUS_BT_STATUS_SUCCESS);
    }
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfStopAdv(int channel)
{
    if (!isAdvertising) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "already has stopped");
        return SOFTBUS_ERR;
    }
    if (advCallback) {
        advCallback->AdvDisableCallback(channel, SOFTBUS_BT_STATUS_SUCCESS);
    }
    isAdvertising = !isAdvertising;
    return SOFTBUS_OK;
}

void BleMock::HexDump(const uint8_t *data, uint32_t len)
{
    std::stringstream ss;
    for (uint32_t i = 0; i < len; i++) {
        ss << std::uppercase << std::hex << std::setfill('0') << std::setw(BYTE_DUMP_LEN)
            << static_cast<uint32_t>(data[i]) << " ";
    }
    DLOGI("%s", ss.str().c_str());
}

void BleMock::ShowAdvData(int channel, const SoftBusBleAdvData *data)
{
    DLOGI("channel=%d advLen=%d rspLen=%d", channel, data->advLength, data->scanRspLength);
    DLOGI("adv data:");
    HexDump(reinterpret_cast<const uint8_t *>(data->advData), data->advLength);
    DLOGI("rsp data:");
    HexDump(reinterpret_cast<const uint8_t *>(data->scanRspData), data->scanRspLength);
}

int32_t BleMock::ActionOfSetAdvDataForActiveDiscovery(int channel, const SoftBusBleAdvData *data)
{
    ShowAdvData(channel, data);

    if (data->advLength != sizeof(activeDiscoveryAdvData) ||
        data->scanRspLength != sizeof(activeDiscoveryRspData) ||
        memcmp(data->advData, activeDiscoveryAdvData, data->advLength) != 0 ||
        memcmp(data->scanRspData, activeDiscoveryRspData, data->scanRspLength) != 0) {
        isAsyncAdvertiseSuccess = false;
        GetMock()->AsyncAdvertiseDone();
        return SOFTBUS_ERR;
    }
    if (advCallback) {
        advCallback->AdvDataCallback(channel, SOFTBUS_BT_STATUS_SUCCESS);
    }

    GetMock()->AsyncAdvertiseDone();
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfSetAdvDataForActivePublish(int channel, const SoftBusBleAdvData *data)
{
    ShowAdvData(channel, data);

    if (data->advLength != sizeof(activePublishAdvData) ||
        data->scanRspLength != sizeof(activePublishRspData) ||
        memcmp(data->advData, activePublishAdvData, data->advLength) != 0 ||
        memcmp(data->scanRspData, activePublishRspData, data->scanRspLength) != 0) {
        isAsyncAdvertiseSuccess = false;
        GetMock()->AsyncAdvertiseDone();
        return SOFTBUS_ERR;
    }
    if (advCallback) {
        advCallback->AdvDataCallback(channel, SOFTBUS_BT_STATUS_SUCCESS);
    }

    GetMock()->AsyncAdvertiseDone();
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfSetAdvDataForPassivePublish(int channel, const SoftBusBleAdvData *data)
{
    ShowAdvData(channel, data);

    if (data->advLength != sizeof(passivePublishAdvData) ||
        data->scanRspLength != sizeof(passivePublishRspData) ||
        memcmp(data->advData, passivePublishAdvData, data->advLength) != 0 ||
        memcmp(data->scanRspData, passivePublishRspData, data->scanRspLength) != 0) {
        isAsyncAdvertiseSuccess = false;
        GetMock()->AsyncAdvertiseDone();
        return SOFTBUS_ERR;
    }

    if (advCallback) {
        advCallback->AdvDataCallback(channel, SOFTBUS_BT_STATUS_SUCCESS);
    }

    GetMock()->AsyncAdvertiseDone();
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfUpdateAdvForActiveDiscovery(int channel, const SoftBusBleAdvData *data,
                                                     const SoftBusBleAdvParams *param)
{
    ShowAdvData(channel, data);

    if (data->advLength != sizeof(activeDiscoveryAdvData2) ||
        data->scanRspLength != sizeof(activeDiscoveryRspData) ||
        memcmp(data->advData, activeDiscoveryAdvData2, data->advLength) != 0 ||
        memcmp(data->scanRspData, activeDiscoveryRspData, data->scanRspLength) != 0) {
        isAsyncAdvertiseSuccess = false;
        GetMock()->AsyncAdvertiseDone();
        return SOFTBUS_ERR;
    }

    if (advCallback) {
        advCallback->AdvUpdateCallback(channel, SOFTBUS_BT_STATUS_SUCCESS);
    }

    GetMock()->AsyncAdvertiseDone();
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfUpdateAdvForPassivePublish(int channel, const SoftBusBleAdvData *data,
                                                    const SoftBusBleAdvParams *param)
{
    ShowAdvData(channel, data);

    if (data->advLength != sizeof(passivePublishAdvData) ||
        data->scanRspLength != sizeof(passivePublishRspData) ||
        memcmp(data->advData, passivePublishAdvData, data->advLength) != 0 ||
        memcmp(data->scanRspData, passivePublishRspData, data->scanRspLength) != 0) {
        isAsyncAdvertiseSuccess = false;
        GetMock()->AsyncAdvertiseDone();
        return SOFTBUS_ERR;
    }

    if (advCallback) {
        advCallback->AdvUpdateCallback(channel, SOFTBUS_BT_STATUS_SUCCESS);
    }

    GetMock()->AsyncAdvertiseDone();
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfGetBtMacAddr(SoftBusBtAddr *mac)
{
    if (memcpy_s(mac->addr, sizeof(mac->addr), btMacAddr, sizeof(btMacAddr)) != EOK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfGetBtState()
{
    return btState ? BLE_ENABLE : BLE_DISABLE;
}

void BleMock::InjectPassiveNonPacket()
{
    if (scanListener && scanListener->OnScanResult) {
        constexpr uint32_t advLen = sizeof(passivePublishAdvData);
        constexpr uint32_t rspLen = sizeof(passivePublishRspData);
        uint8_t data[advLen + rspLen];
        if (memcpy_s(data, sizeof(data), passivePublishAdvData, advLen) != EOK) {
            return;
        }
        if (memcpy_s(data + advLen, sizeof(data) - advLen, passivePublishRspData, rspLen) != EOK) {
            return;
        }

        SoftBusBleScanResult result;
        result.advData = data;
        result.advLen = sizeof(data);
        scanListener->OnScanResult(SCAN_LISTENER_ID, &result);
    }
}

void BleMock::InjectActiveNonPacket()
{
    if (scanListener && scanListener->OnScanResult) {
        constexpr uint32_t advLen = sizeof(activePublishAdvData);
        constexpr uint32_t rspLen = sizeof(activePublishRspData);
        uint8_t data[advLen + rspLen];
        if (memcpy_s(data, sizeof(data), activePublishAdvData, advLen) != EOK) {
            return;
        }
        if (memcpy_s(data + advLen, sizeof(data) - advLen, activePublishRspData, rspLen) != EOK) {
            return;
        }

        SoftBusBleScanResult result;
        result.advData = data;
        result.advLen = sizeof(data);
        scanListener->OnScanResult(SCAN_LISTENER_ID, &result);
    }
}

void BleMock::InjectActiveConPacket()
{
    if (scanListener && scanListener->OnScanResult) {
        constexpr uint32_t advLen = sizeof(activeDiscoveryAdvData);
        constexpr uint32_t rspLen = sizeof(activeDiscoveryRspData);
        uint8_t data[advLen + rspLen];
        if (memcpy_s(data, sizeof(data), activeDiscoveryAdvData, advLen) != EOK) {
            return;
        }
        if (memcpy_s(data + advLen, sizeof(data) - advLen, activeDiscoveryRspData, rspLen) != EOK) {
            return;
        }

        SoftBusBleScanResult result;
        result.advData = data;
        result.advLen = sizeof(data);
        scanListener->OnScanResult(SCAN_LISTENER_ID, &result);
    }
}

void BleMock::TurnOnBt()
{
    DLOGI("enter");
    btState = true;
    if (btStateListener) {
        btStateListener->OnBtStateChanged(BT_STATE_LISTENER_ID, SOFTBUS_BT_STATE_TURN_ON);
    }
}

void BleMock::TurnOffBt()
{
    DLOGI("enter");
    btState = false;
    if (btStateListener) {
        btStateListener->OnBtStateChanged(BT_STATE_LISTENER_ID, SOFTBUS_BT_STATE_TURN_OFF);
    }
}

bool BleMock::IsScanning()
{
    std::unique_lock lock(scanMutex_);
    if (scanCv_.wait_for(lock, std::chrono::seconds(WAIT_ASYNC_TIMEOUT)) == std::cv_status::timeout) {
        return false;
    }
    return isScanning;
}

void BleMock::WaitRecvMessageObsolete()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(BLE_MSG_TIME_OUT_MS));
}

bool BleMock::IsDeInitSuccess()
{
    return advCallback == nullptr;
}

void BleMock::SetupSuccessStub()
{
    EXPECT_CALL(*this, SoftBusGetBtState).WillRepeatedly(BleMock::ActionOfGetBtState);
    EXPECT_CALL(*this, SoftBusStartAdv).WillRepeatedly(BleMock::ActionOfStartAdv);
    EXPECT_CALL(*this, SoftBusStopAdv).WillRepeatedly(BleMock::ActionOfStopAdv);
    EXPECT_CALL(*this, SoftBusStartScan).WillRepeatedly(BleMock::ActionOfStartScan);
    EXPECT_CALL(*this, SoftBusStopScan).WillRepeatedly(BleMock::ActionOfStopScan);
    EXPECT_CALL(*this, SoftBusGetBtMacAddr(NotNull())).WillRepeatedly(BleMock::ActionOfGetBtMacAddr);
    EXPECT_CALL(*this, SoftBusRemoveBtStateListener).WillRepeatedly(BleMock::ActionOfRemoveBtStateListener);
    EXPECT_CALL(*this, BleGattLockInit).WillRepeatedly(BleMock::ActionOfBleGattLockInit);
    EXPECT_CALL(*this, SoftBusAddBtStateListener(NotNull())).WillRepeatedly(BleMock::ActionOfAddBtStateListener);
    EXPECT_CALL(*this, SoftBusAddScanListener(NotNull())).WillRepeatedly(BleMock::ActionOfAddScanListener);
    EXPECT_CALL(*this, SoftBusGetAdvChannel).WillRepeatedly(BleMock::ActionOfGetAdvChannel);
    EXPECT_CALL(*this, SoftBusSetScanFilter).WillRepeatedly(BleMock::ActionOfSetScanFilter);
    EXPECT_CALL(*this, SoftBusRemoveScanListener).WillRepeatedly(BleMock::ActionOfRemoveScanListener);
    EXPECT_CALL(*this, SoftBusReleaseAdvChannel).WillRepeatedly(BleMock::ActionOfReleaseAdvChannel);
}

void BleMock::AsyncAdvertiseDone()
{
    cv_.notify_all();
}

void BleMock::UpdateScanStateDone()
{
    scanCv_.notify_all();
}

bool BleMock::GetAsyncAdvertiseResult()
{
    std::unique_lock lock(mutex_);
    if (cv_.wait_for(lock, std::chrono::seconds(WAIT_ASYNC_TIMEOUT)) == std::cv_status::timeout) {
        DLOGE("time out");
        return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_LOOPER_DONE_MS));
    return isAsyncAdvertiseSuccess;
}