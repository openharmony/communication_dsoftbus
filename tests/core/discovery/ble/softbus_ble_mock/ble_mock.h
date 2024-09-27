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

#ifndef BLE_MOCK_H
#define BLE_MOCK_H

#include <atomic>
#include <condition_variable>
#include <gmock/gmock.h>
#include <mutex>

#include "softbus_adapter_ble_gatt_client.h"
#include "softbus_adapter_ble_gatt_server.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_broadcast_manager.h"
#include "softbus_broadcast_utils.h"

class BleInterface {
public:
    virtual int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener) = 0;
    virtual int32_t SoftBusRemoveBtStateListener(int32_t listenerId) = 0;

    virtual int32_t InitBroadcastMgr() = 0;
    virtual int32_t DeInitBroadcastMgr() = 0;

    virtual int32_t RegisterScanListener(BaseServiceType type, int32_t *listenerId, const ScanCallback *cb) = 0;
    virtual int32_t UnRegisterScanListener(int32_t listenerId) = 0;

    virtual int32_t SetScanFilter(int32_t listenerId, const BcScanFilter *scanFilter, uint8_t filterNum) = 0;

    virtual int32_t RegisterBroadcaster(BaseServiceType type, int32_t *bcId, const BroadcastCallback *cb) = 0;
    virtual int32_t UnRegisterBroadcaster(int32_t bcId) = 0;

    virtual int32_t StartScan(int32_t listenerId, const BcScanParams *param) = 0;
    virtual int32_t StopScan(int32_t listenerId) = 0;

    virtual int32_t StartBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet) = 0;
    virtual int32_t StopBroadcasting(int32_t bcId) = 0;

    virtual int32_t UpdateBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet) = 0;
    virtual int32_t SetBroadcastingData(int32_t bcId, const BroadcastPacket *packet) = 0;

    virtual int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac) = 0;
    virtual int32_t SoftBusGetBtState() = 0;
    virtual int32_t SoftBusGetBrState() = 0;
};

class BleMock : public BleInterface {
public:
    static BleMock* GetMock()
    {
        return mock.load();
    }

    BleMock();
    ~BleMock();

    MOCK_METHOD(int32_t, SoftBusAddBtStateListener, (const SoftBusBtStateListener *listener), (override));
    MOCK_METHOD(int32_t, SoftBusRemoveBtStateListener, (int32_t listenerId), (override));
    MOCK_METHOD(int32_t, InitBroadcastMgr, (), (override));
    MOCK_METHOD(int32_t, DeInitBroadcastMgr, (), (override));
    MOCK_METHOD(
        int32_t, RegisterScanListener, (BaseServiceType type, int32_t *listenerId, const ScanCallback *cb), (override));
    MOCK_METHOD(int32_t, UnRegisterScanListener, (int32_t listenerId), (override));
    MOCK_METHOD(
        int32_t, SetScanFilter, (int32_t listenerId, const BcScanFilter *scanFilter, uint8_t filterNum), (override));
    MOCK_METHOD(
        int32_t, RegisterBroadcaster, (BaseServiceType type, int32_t *bcId, const BroadcastCallback *cb), (override));
    MOCK_METHOD(int32_t, UnRegisterBroadcaster, (int32_t bcId), (override));
    MOCK_METHOD(int32_t, StartScan, (int32_t listenerId, const BcScanParams *param), (override));
    MOCK_METHOD(int32_t, StopScan, (int32_t listenerId), (override));
    MOCK_METHOD(int32_t, StartBroadcasting, (int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet),
        (override));
    MOCK_METHOD(int32_t, StopBroadcasting, (int32_t bcId), (override));
    MOCK_METHOD(int32_t, SetBroadcastingData, (int32_t bcId, const BroadcastPacket *packet), (override));
    MOCK_METHOD(int32_t, UpdateBroadcasting, (int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet),
        (override));
    MOCK_METHOD(int32_t, SoftBusGetBtMacAddr, (SoftBusBtAddr * mac), (override));
    MOCK_METHOD(int32_t, SoftBusGetBtState, (), (override));
    MOCK_METHOD(int32_t, SoftBusGetBrState, (), (override));

    void SetupSuccessStub();
    void AsyncAdvertiseDone();
    void UpdateScanStateDone();
    bool GetAsyncAdvertiseResult();
    bool IsScanning();

    static int32_t ActionOfAddBtStateListener(const SoftBusBtStateListener *listener);
    static int32_t ActionOfRemoveBtStateListener(int32_t listenerId);
    static int32_t ActionOfInitBroadcastMgr();
    static int32_t ActionOfDeInitBroadcastMgr();
    static int32_t ActionOfRegisterScanListener(BaseServiceType type, int32_t *listenerId, const ScanCallback *cb);
    static int32_t ActionOfUnRegisterScanListener(int32_t listenerId);
    static int32_t ActionOfSetScanFilter(int32_t listenerId, const BcScanFilter *scanFilter, uint8_t filterNum);
    static int32_t ActionOfRegisterBroadcaster(BaseServiceType type, int32_t *bcId, const BroadcastCallback *cb);
    static int32_t ActionOfUnRegisterBroadcaster(int32_t bcId);
    static int32_t ActionOfStartScan(int32_t listenerId, const BcScanParams *param);
    static int32_t ActionOfStopScan(int32_t listenerId);
    static int32_t ActionOfStartBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet);
    static int32_t ActionOfStopBroadcasting(int32_t bcId);
    static int32_t ActionOfSetAdvDataForActiveDiscovery(int32_t bcId, const BroadcastPacket *packet);
    static int32_t ActionOfSetAdvDataForActivePublish(int32_t bcId, const BroadcastPacket *packet);
    static int32_t ActionOfSetAdvDataForPassivePublish(int32_t bcId, const BroadcastPacket *packet);
    static int32_t ActionOfUpdateAdvForActiveDiscovery(
        int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet);
    static int32_t ActionOfUpdateAdvForActivePublish(
        int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet);
    static int32_t ActionOfUpdateAdvForPassivePublish(
        int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet);
    static int32_t ActionOfGetBtMacAddr(SoftBusBtAddr *mac);
    static int32_t ActionOfGetBtState();
    static int32_t ActionOfGetBrState();

    static void InjectPassiveNonPacket();
    static void InjectActiveNonPacket();
    static void InjectActiveConPacket();
    static void InjectPassiveNonPacketOfCust();
    static void TurnOnBt();
    static void TurnOffBt();
    static void WaitRecvMessageObsolete();
    static bool IsDeInitSuccess();

    static constexpr int32_t CON_ADV_ID = 0;
    static constexpr int32_t NON_ADV_ID = 1;
    static constexpr int32_t BT_STATE_LISTENER_ID = 1;
    static constexpr int32_t SCAN_LISTENER_ID = 2;
    static constexpr int32_t BLE_MSG_TIME_OUT_MS = 6000;

    static inline const ScanCallback *scanListener {};
    static inline const SoftBusBtStateListener *btStateListener {};
    static inline const BroadcastCallback *advCallback {};
    static inline bool isAdvertising {};
    static inline bool isScanning {};
    static inline bool btState {};
    static inline bool brState = true;
    static inline uint8_t btMacAddr[] = { 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    static inline uint8_t activeDiscoveryAdvData[] = { 0x04, 0x05, 0x90, 0x00, 0x00, 0x12, 0x00, 0x18, 0xE8, 0x31, 0xF7,
        0x63, 0x0B, 0x76, 0x19, 0xAE, 0x21, 0x0E, 0x3A, 0x4D, 0x79, 0x20, 0x44, 0x65 };
    static inline uint8_t activeDiscoveryRspData[] = { 0x76, 0x69, 0x63, 0x65, 0x00 };

    static inline uint8_t activePublishAdvData[] = { 0x04, 0x05, 0x10, 0x00, 0x00, 0x02, 0x00, 0x18, 0xE8, 0x31, 0xF7,
        0x63, 0x0B, 0x76, 0x19, 0xAE, 0x21, 0x0E, 0x3A, 0x4D, 0x79, 0x20, 0x44, 0x65 };
    static inline uint8_t activePublishRspData[] = { 0x76, 0x69, 0x63, 0x65, 0x00 };

    static inline uint8_t passivePublishAdvData[] = { 0x04, 0x05, 0x10, 0x00, 0x00, 0x02, 0x00, 0x18, 0xE8, 0x31, 0xF7,
        0x63, 0x0B, 0x76, 0x19, 0xAE, 0x21, 0x0E, 0x56, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E };
    static inline uint8_t passivePublishRspData[] = { 0x0F, 0x3A, 0x4D, 0x79, 0x20, 0x44, 0x65,
        0x76, 0x69, 0x63, 0x65, 0x00 };

    static inline uint8_t passivePublishAdvDataOfCust[] = { 0x04, 0x05, 0x10, 0x00, 0x00, 0x02, 0x00, 0x18, 0xE8, 0x31,
        0xF7, 0x63, 0x0B, 0x76, 0x19, 0xAE, 0x21, 0x0E, 0x56, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E };
    static inline uint8_t passivePublishRspDataOfCust[] = { 0x0F, 0x43, 0x01, 0xAA, 0x00, 0x3A, 0x4D, 0x79, 0x20, 0x44,
        0x65, 0x76, 0x69, 0x63, 0x65, 0x00 };

private:
    static void HexDump(const uint8_t *data, uint32_t len);
    static void ShowAdvData(int32_t bcId, const BroadcastPacket *packet);

    static inline std::atomic<BleMock*> mock = nullptr;
    static inline std::atomic_bool isAsyncAdvertiseSuccess;

    static constexpr int32_t BYTE_DUMP_LEN = 2;
    static constexpr int32_t WAIT_LOOPER_DONE_MS = 500;
    static constexpr int32_t WAIT_LOCK_LOCKED_MS = 100;
    static constexpr int32_t WAIT_ASYNC_TIMEOUT = 1;

    std::mutex mutex_;
    std::condition_variable cv_;
    std::mutex scanMutex_;
    std::condition_variable scanCv_;
};
#endif