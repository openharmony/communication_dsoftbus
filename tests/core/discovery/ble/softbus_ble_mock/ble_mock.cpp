/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include "disc_ble_constant.h"
#include "disc_log.h"
#include "securec.h"
#include "softbus_error_code.h"

using testing::_;
using testing::NotNull;

/* implement related global function of BLE */
int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener)
{
    return BleMock::GetMock()->SoftBusAddBtStateListener(listener);
}

int32_t InitBroadcastMgr()
{
    return BleMock::GetMock()->InitBroadcastMgr();
}

int32_t DeInitBroadcastMgr()
{
    return BleMock::GetMock()->DeInitBroadcastMgr();
}

int32_t RegisterScanListener(BaseServiceType type, int32_t *listenerId, const ScanCallback *cb)
{
    return BleMock::GetMock()->RegisterScanListener(type, listenerId, cb);
}

int32_t SetScanFilter(int32_t listenerId, const BcScanFilter *scanFilter, uint8_t filterNum)
{
    return BleMock::GetMock()->SetScanFilter(listenerId, scanFilter, filterNum);
}

int32_t RegisterBroadcaster(BaseServiceType type, int32_t *bcId, const BroadcastCallback *cb)
{
    return BleMock::GetMock()->RegisterBroadcaster(type, bcId, cb);
}

int32_t UnRegisterBroadcaster(int32_t bcId)
{
    return BleMock::GetMock()->UnRegisterBroadcaster(bcId);
}

int32_t StopScan(int32_t listenerId)
{
    return BleMock::GetMock()->StopScan(listenerId);
}

int32_t SoftBusRemoveBtStateListener(int32_t listenerId)
{
    return BleMock::GetMock()->SoftBusRemoveBtStateListener(listenerId);
}

int32_t UnRegisterScanListener(int32_t listenerId)
{
    return BleMock::GetMock()->UnRegisterScanListener(listenerId);
}

int32_t StopBroadcasting(int32_t bcId)
{
    return BleMock::GetMock()->StopBroadcasting(bcId);
}

int32_t UpdateBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet)
{
    return BleMock::GetMock()->UpdateBroadcasting(bcId, param, packet);
}

int32_t StartScan(int32_t listenerId, const BcScanParams *param)
{
    return BleMock::GetMock()->StartScan(listenerId, param);
}

int32_t SetBroadcastingData(int32_t bcId, const BroadcastPacket *packet)
{
    return BleMock::GetMock()->SetBroadcastingData(bcId, packet);
}

int32_t StartBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet)
{
    return BleMock::GetMock()->StartBroadcasting(bcId, param, packet);
}

int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac)
{
    return BleMock::GetMock()->SoftBusGetBtMacAddr(mac);
}

int32_t SoftBusGetBtState()
{
    return BleMock::GetMock()->SoftBusGetBtState();
}

int32_t SoftBusGetBrState()
{
    return BleMock::GetMock()->SoftBusGetBrState();
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

int32_t BleMock::ActionOfInitBroadcastMgr()
{
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfDeInitBroadcastMgr()
{
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfAddBtStateListener(const SoftBusBtStateListener *listener)
{
    btStateListener = listener;
    return BT_STATE_LISTENER_ID;
}

int32_t BleMock::ActionOfRemoveBtStateListener(int32_t listenerId)
{
    btStateListener = nullptr;
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfRegisterScanListener(BaseServiceType type, int32_t *listenerId, const ScanCallback *cb)
{
    *listenerId = SCAN_LISTENER_ID;
    scanListener = cb;
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfUnRegisterScanListener(int32_t listenerId)
{
    scanListener = nullptr;
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfSetScanFilter(int32_t listenerId, const BcScanFilter *scanFilter, uint8_t filterNum)
{
    DISC_LOGI(DISC_TEST, "listenerId=%{public}d, filterSize=%{public}d", listenerId, filterNum);
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfRegisterBroadcaster(BaseServiceType type, int32_t *bcId, const BroadcastCallback *cb)
{
    static int32_t advChannel = 0;
    *bcId = advChannel;
    advChannel++;
    advCallback = cb;
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfUnRegisterBroadcaster(int32_t bcId)
{
    advCallback = nullptr;
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfStartScan(int32_t listenerId, const BcScanParams *param)
{
    if (listenerId != SCAN_LISTENER_ID) {
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }

    isScanning = true;
    if (scanListener && scanListener->OnStartScanCallback) {
        scanListener->OnStartScanCallback(SCAN_LISTENER_ID, SOFTBUS_BT_STATUS_SUCCESS);
    }
    GetMock()->UpdateScanStateDone();
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfStopScan(int32_t listenerId)
{
    if (listenerId != SCAN_LISTENER_ID) {
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }

    isScanning = false;
    if (scanListener && scanListener->OnStopScanCallback) {
        scanListener->OnStopScanCallback(SCAN_LISTENER_ID, SOFTBUS_BT_STATUS_SUCCESS);
    }
    GetMock()->UpdateScanStateDone();
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfStartBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet)
{
    ShowAdvData(bcId, packet);
    if (isAdvertising) {
        DISC_LOGE(DISC_TEST, "already in advertising");
        GetMock()->AsyncAdvertiseDone();
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    isAdvertising = !isAdvertising;
    if (advCallback) {
        advCallback->OnStartBroadcastingCallback(bcId, SOFTBUS_BT_STATUS_SUCCESS);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_LOCK_LOCKED_MS));
    GetMock()->AsyncAdvertiseDone();
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfStopBroadcasting(int32_t bcId)
{
    if (!isAdvertising) {
        DISC_LOGE(DISC_TEST, "already has stopped");
        GetMock()->AsyncAdvertiseDone();
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    if (advCallback) {
        advCallback->OnStopBroadcastingCallback(bcId, SOFTBUS_BT_STATUS_SUCCESS);
    }
    isAdvertising = !isAdvertising;
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_LOCK_LOCKED_MS));
    GetMock()->AsyncAdvertiseDone();
    return SOFTBUS_OK;
}

void BleMock::HexDump(const uint8_t *data, uint32_t len)
{
    std::stringstream ss;
    for (uint32_t i = 0; i < len; i++) {
        ss << std::uppercase << std::hex << std::setfill('0') << std::setw(BYTE_DUMP_LEN)
           << static_cast<uint32_t>(data[i]) << " ";
    }
    DISC_LOGI(DISC_TEST, "ss=%{public}s", ss.str().c_str());
    std::cout << ss.str() << std::endl;
}

void BleMock::ShowAdvData(int32_t bcId, const BroadcastPacket *packet)
{
    DISC_LOGI(DISC_TEST, "bcId=%{public}d, advLen=%{public}d, rspLen=%{public}d", bcId, packet->bcData.payloadLen,
        packet->rspData.payloadLen);
    DISC_LOGI(DISC_TEST, "adv data:");
    HexDump(reinterpret_cast<const uint8_t *>(packet->bcData.payload), packet->bcData.payloadLen);
    DISC_LOGI(DISC_TEST, "rsp data:");
    HexDump(reinterpret_cast<const uint8_t *>(packet->rspData.payload), packet->rspData.payloadLen);
}

int32_t BleMock::ActionOfSetAdvDataForActiveDiscovery(int32_t bcId, const BroadcastPacket *packet)
{
    ShowAdvData(bcId, packet);

    if (packet->bcData.payloadLen != sizeof(activeDiscoveryAdvData) ||
        packet->rspData.payloadLen != sizeof(activeDiscoveryRspData) ||
        memcmp(packet->bcData.payload, activeDiscoveryAdvData, packet->bcData.payloadLen) != 0 ||
        memcmp(packet->rspData.payload, activeDiscoveryRspData, packet->rspData.payloadLen) != 0) {
        isAsyncAdvertiseSuccess = false;
        GetMock()->AsyncAdvertiseDone();
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    if (advCallback) {
        advCallback->OnSetBroadcastingCallback(bcId, SOFTBUS_BT_STATUS_SUCCESS);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_LOCK_LOCKED_MS));
    GetMock()->AsyncAdvertiseDone();
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfUpdateAdvForActiveDiscovery(int32_t bcId, const BroadcastParam *param,
    const BroadcastPacket *packet)
{
    ShowAdvData(bcId, packet);

    if (packet->bcData.payloadLen != sizeof(activeDiscoveryAdvData) ||
        packet->rspData.payloadLen != sizeof(activeDiscoveryRspData) ||
        memcmp(packet->bcData.payload, activeDiscoveryAdvData, packet->bcData.payloadLen) != 0 ||
        memcmp(packet->rspData.payload, activeDiscoveryRspData, packet->rspData.payloadLen) != 0) {
        isAsyncAdvertiseSuccess = false;
        GetMock()->AsyncAdvertiseDone();
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    if (advCallback) {
        advCallback->OnUpdateBroadcastingCallback(bcId, SOFTBUS_BT_STATUS_SUCCESS);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_LOCK_LOCKED_MS));
    GetMock()->AsyncAdvertiseDone();
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfSetAdvDataForActivePublish(int32_t bcId, const BroadcastPacket *packet)
{
    ShowAdvData(bcId, packet);

    if (packet->bcData.payloadLen != sizeof(activePublishAdvData) ||
        packet->rspData.payloadLen != sizeof(activePublishRspData) ||
        memcmp(packet->bcData.payload, activePublishAdvData, packet->bcData.payloadLen) != 0 ||
        memcmp(packet->rspData.payload, activePublishRspData, packet->rspData.payloadLen) != 0) {
        isAsyncAdvertiseSuccess = false;
        GetMock()->AsyncAdvertiseDone();
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    if (advCallback) {
        advCallback->OnSetBroadcastingCallback(bcId, SOFTBUS_BT_STATUS_SUCCESS);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_LOCK_LOCKED_MS));
    GetMock()->AsyncAdvertiseDone();
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfUpdateAdvForActivePublish(int32_t bcId, const BroadcastParam *param,
    const BroadcastPacket *packet)
{
    ShowAdvData(bcId, packet);

    if (packet->bcData.payloadLen != sizeof(activePublishAdvData) ||
        packet->rspData.payloadLen != sizeof(activePublishRspData) ||
        memcmp(packet->bcData.payload, activePublishAdvData, packet->bcData.payloadLen) != 0 ||
        memcmp(packet->rspData.payload, activePublishRspData, packet->rspData.payloadLen) != 0) {
        isAsyncAdvertiseSuccess = false;
        GetMock()->AsyncAdvertiseDone();
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    if (advCallback) {
        advCallback->OnUpdateBroadcastingCallback(bcId, SOFTBUS_BT_STATUS_SUCCESS);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_LOCK_LOCKED_MS));
    GetMock()->AsyncAdvertiseDone();
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfSetAdvDataForPassivePublish(int32_t bcId, const BroadcastPacket *packet)
{
    ShowAdvData(bcId, packet);

    if (packet->bcData.payloadLen != sizeof(passivePublishAdvData) ||
        packet->rspData.payloadLen != sizeof(passivePublishRspData) ||
        memcmp(packet->bcData.payload, passivePublishAdvData, packet->bcData.payloadLen) != 0 ||
        memcmp(packet->rspData.payload, passivePublishRspData, packet->rspData.payloadLen) != 0) {
        isAsyncAdvertiseSuccess = false;
        GetMock()->AsyncAdvertiseDone();
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }

    if (advCallback) {
        advCallback->OnSetBroadcastingCallback(bcId, SOFTBUS_BT_STATUS_SUCCESS);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_LOCK_LOCKED_MS));
    GetMock()->AsyncAdvertiseDone();
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfUpdateAdvForPassivePublish(
    int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet)
{
    ShowAdvData(bcId, packet);

    if (packet->bcData.payloadLen != sizeof(passivePublishAdvData) ||
        packet->rspData.payloadLen != sizeof(passivePublishRspData) ||
        memcmp(packet->bcData.payload, passivePublishAdvData, packet->bcData.payloadLen) != 0 ||
        memcmp(packet->rspData.payload, passivePublishRspData, packet->rspData.payloadLen) != 0) {
        isAsyncAdvertiseSuccess = false;
        GetMock()->AsyncAdvertiseDone();
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }

    if (advCallback) {
        advCallback->OnUpdateBroadcastingCallback(bcId, SOFTBUS_BT_STATUS_SUCCESS);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_LOCK_LOCKED_MS));
    GetMock()->AsyncAdvertiseDone();
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfGetBtMacAddr(SoftBusBtAddr *mac)
{
    if (memcpy_s(mac->addr, sizeof(mac->addr), btMacAddr, sizeof(btMacAddr)) != EOK) {
        return SOFTBUS_DISCOVER_TEST_CASE_ERRCODE;
    }
    return SOFTBUS_OK;
}

int32_t BleMock::ActionOfGetBtState()
{
    return btState ? BLE_ENABLE : BLE_DISABLE;
}

int32_t BleMock::ActionOfGetBrState()
{
    return brState ? BR_ENABLE : BR_DISABLE;
}

void BleMock::InjectPassiveNonPacket()
{
    if (scanListener && scanListener->OnReportScanDataCallback) {
        constexpr uint32_t advLen = sizeof(passivePublishAdvData);
        constexpr uint32_t rspLen = sizeof(passivePublishRspData);
        BroadcastReportInfo reportInfo = {};
        reportInfo.packet.bcData.id = SERVICE_UUID;
        reportInfo.packet.bcData.type = BC_DATA_TYPE_SERVICE;
        reportInfo.packet.rspData.id = MANU_COMPANY_ID;
        reportInfo.packet.rspData.type = BC_DATA_TYPE_MANUFACTURER;
        reportInfo.packet.bcData.payload = &passivePublishAdvData[0];
        reportInfo.packet.bcData.payloadLen = advLen;
        reportInfo.packet.rspData.payload = &passivePublishRspData[0];
        reportInfo.packet.rspData.payloadLen = rspLen;
        scanListener->OnReportScanDataCallback(SCAN_LISTENER_ID, &reportInfo);
    }
}

void BleMock::InjectActiveNonPacket()
{
    if (scanListener && scanListener->OnReportScanDataCallback) {
        constexpr uint32_t advLen = sizeof(activePublishAdvData);
        constexpr uint32_t rspLen = sizeof(activePublishRspData);
        BroadcastReportInfo reportInfo = {};
        reportInfo.packet.bcData.id = SERVICE_UUID;
        reportInfo.packet.bcData.type = BC_DATA_TYPE_SERVICE;
        reportInfo.packet.rspData.id = MANU_COMPANY_ID;
        reportInfo.packet.rspData.type = BC_DATA_TYPE_MANUFACTURER;
        reportInfo.packet.bcData.payload = &activePublishAdvData[0];
        reportInfo.packet.bcData.payloadLen = advLen;
        reportInfo.packet.rspData.payload = &activePublishRspData[0];
        reportInfo.packet.rspData.payloadLen = rspLen;
        scanListener->OnReportScanDataCallback(SCAN_LISTENER_ID, &reportInfo);
    }
}

void BleMock::InjectPassiveNonPacketOfCust()
{
    if (scanListener && scanListener->OnReportScanDataCallback) {
        constexpr uint32_t advLen = sizeof(passivePublishAdvDataOfCust);
        constexpr uint32_t rspLen = sizeof(passivePublishRspDataOfCust);
        BroadcastReportInfo reportInfo = {};
        reportInfo.packet.bcData.id = SERVICE_UUID;
        reportInfo.packet.bcData.type = BC_DATA_TYPE_SERVICE;
        reportInfo.packet.rspData.id = MANU_COMPANY_ID;
        reportInfo.packet.rspData.type = BC_DATA_TYPE_MANUFACTURER;
        reportInfo.packet.bcData.payload = &passivePublishAdvDataOfCust[0];
        reportInfo.packet.bcData.payloadLen = advLen;
        reportInfo.packet.rspData.payload = &passivePublishRspDataOfCust[0];
        reportInfo.packet.rspData.payloadLen = rspLen;
        scanListener->OnReportScanDataCallback(SCAN_LISTENER_ID, &reportInfo);
    }
}

void BleMock::InjectActiveConPacket()
{
    if (scanListener && scanListener->OnReportScanDataCallback) {
        constexpr uint32_t advLen = sizeof(activeDiscoveryAdvData);
        constexpr uint32_t rspLen = sizeof(activeDiscoveryRspData);
        BroadcastReportInfo reportInfo = {};
        reportInfo.packet.bcData.id = SERVICE_UUID;
        reportInfo.packet.bcData.type = BC_DATA_TYPE_SERVICE;
        reportInfo.packet.rspData.id = MANU_COMPANY_ID;
        reportInfo.packet.rspData.type = BC_DATA_TYPE_MANUFACTURER;
        reportInfo.packet.bcData.payload = &activeDiscoveryAdvData[0];
        reportInfo.packet.bcData.payloadLen = advLen;
        reportInfo.packet.rspData.payload = &activeDiscoveryRspData[0];
        reportInfo.packet.rspData.payloadLen = rspLen;
        scanListener->OnReportScanDataCallback(SCAN_LISTENER_ID, &reportInfo);
    }
}

void BleMock::TurnOnBt()
{
    btState = true;
    if (btStateListener) {
        btStateListener->OnBtStateChanged(BT_STATE_LISTENER_ID, SOFTBUS_BLE_STATE_TURN_ON);
    }
}

void BleMock::TurnOffBt()
{
    btState = false;
    if (btStateListener) {
        btStateListener->OnBtStateChanged(BT_STATE_LISTENER_ID, SOFTBUS_BLE_STATE_TURN_OFF);
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
    EXPECT_CALL(*this, InitBroadcastMgr).WillRepeatedly(BleMock::ActionOfInitBroadcastMgr);
    EXPECT_CALL(*this, DeInitBroadcastMgr).WillRepeatedly(BleMock::ActionOfDeInitBroadcastMgr);
    EXPECT_CALL(*this, SoftBusGetBtState).WillRepeatedly(BleMock::ActionOfGetBtState);
    EXPECT_CALL(*this, SoftBusGetBrState).WillRepeatedly(BleMock::ActionOfGetBrState);
    EXPECT_CALL(*this, SoftBusAddBtStateListener(NotNull())).WillRepeatedly(BleMock::ActionOfAddBtStateListener);
    EXPECT_CALL(*this, SoftBusRemoveBtStateListener).WillRepeatedly(BleMock::ActionOfRemoveBtStateListener);
    EXPECT_CALL(*this, StartBroadcasting).WillRepeatedly(BleMock::ActionOfStartBroadcasting);
    EXPECT_CALL(*this, StopBroadcasting).WillRepeatedly(BleMock::ActionOfStopBroadcasting);
    EXPECT_CALL(*this, StartScan).WillRepeatedly(BleMock::ActionOfStartScan);
    EXPECT_CALL(*this, StopScan).WillRepeatedly(BleMock::ActionOfStopScan);
    EXPECT_CALL(*this, SetScanFilter).WillRepeatedly(BleMock::ActionOfSetScanFilter);
    EXPECT_CALL(*this, SoftBusGetBtMacAddr(NotNull())).WillRepeatedly(BleMock::ActionOfGetBtMacAddr);
    EXPECT_CALL(*this, RegisterScanListener).WillRepeatedly(BleMock::ActionOfRegisterScanListener);
    EXPECT_CALL(*this, UnRegisterScanListener).WillRepeatedly(BleMock::ActionOfUnRegisterScanListener);
    EXPECT_CALL(*this, RegisterBroadcaster).WillRepeatedly(BleMock::ActionOfRegisterBroadcaster);
    EXPECT_CALL(*this, UnRegisterBroadcaster).WillRepeatedly(BleMock::ActionOfUnRegisterBroadcaster);
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
        DISC_LOGE(DISC_TEST, "time out");
        return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_LOOPER_DONE_MS));
    return isAsyncAdvertiseSuccess;
}