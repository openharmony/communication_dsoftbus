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

#ifndef BLE_MOCK_H
#define BLE_MOCK_H

#include <atomic>
#include <mutex>
#include <condition_variable>
#include <gmock/gmock.h>

#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_ble_gatt.h"
#include "softbus_adapter_ble_gatt_client.h"
#include "softbus_adapter_ble_gatt_server.h"

class BleInterface {
public:
    virtual int BleGattLockInit() = 0;
    virtual int SoftBusAddBtStateListener(const SoftBusBtStateListener *listener) = 0;
    virtual int SoftBusRemoveBtStateListener(int listenerId) = 0;

    virtual int SoftBusAddScanListener(const SoftBusScanListener *listener) = 0;
    virtual int SoftBusRemoveScanListener(int listenerId) = 0;

    virtual int SoftBusSetScanFilter(int listenerId, SoftBusBleScanFilter *filter, uint8_t filterSize) = 0;

    virtual int SoftBusGetAdvChannel(const SoftBusAdvCallback *callback) = 0;
    virtual int SoftBusReleaseAdvChannel(int channel) = 0;

    virtual int SoftBusStartScan(int listenerId, const SoftBusBleScanParams *param) = 0;
    virtual int SoftBusStopScan(int listenerId) = 0;

    virtual int SoftBusStartAdv(int channel, const SoftBusBleAdvParams *param) = 0;
    virtual int SoftBusStopAdv(int channel) = 0;

    virtual int SoftBusUpdateAdv(int channel, const SoftBusBleAdvData *data, const SoftBusBleAdvParams *param) = 0;
    virtual int SoftBusSetAdvData(int channel, const SoftBusBleAdvData *data) = 0;

    virtual int SoftBusGetBtMacAddr(SoftBusBtAddr *mac) = 0;
    virtual int SoftBusGetBtState() = 0;
};

class BleMock : public BleInterface {
public:
    static BleMock* GetMock()
    {
        return mock.load();
    }

    BleMock();
    ~BleMock();

    MOCK_METHOD(int, BleGattLockInit, (), (override));

    MOCK_METHOD(int, SoftBusAddBtStateListener, (const SoftBusBtStateListener *listener), (override));
    MOCK_METHOD(int, SoftBusRemoveBtStateListener, (int listenerId), (override));

    MOCK_METHOD(int, SoftBusAddScanListener, (const SoftBusScanListener *listener), (override));
    MOCK_METHOD(int, SoftBusRemoveScanListener, (int listenerId), (override));

    MOCK_METHOD(int, SoftBusSetScanFilter, (int listenerId, SoftBusBleScanFilter *filter, uint8_t filterSize),
                (override));

    MOCK_METHOD(int, SoftBusGetAdvChannel, (const SoftBusAdvCallback *callback), (override));
    MOCK_METHOD(int, SoftBusReleaseAdvChannel, (int channel), (override));

    MOCK_METHOD(int, SoftBusStartScan, (int listenerId, const SoftBusBleScanParams *param), (override));
    MOCK_METHOD(int, SoftBusStopScan, (int listenerId), (override));

    MOCK_METHOD(int, SoftBusStartAdv, (int channel, const SoftBusBleAdvParams *param), (override));
    MOCK_METHOD(int, SoftBusStopAdv, (int channel), (override));

    MOCK_METHOD(int, SoftBusSetAdvData, (int channel, const SoftBusBleAdvData *data), (override));
    MOCK_METHOD(int, SoftBusUpdateAdv, (int channel, const SoftBusBleAdvData *data, const SoftBusBleAdvParams *param),
                (override));

    MOCK_METHOD(int, SoftBusGetBtMacAddr, (SoftBusBtAddr *mac), (override));
    MOCK_METHOD(int, SoftBusGetBtState, (), (override));

    void SetupSuccessStub();
    void AsyncAdvertiseDone();
    void UpdateScanStateDone();
    bool GetAsyncAdvertiseResult();
    bool IsScanning();

    static int32_t ActionOfBleGattLockInit();
    static int32_t ActionOfAddBtStateListener(const SoftBusBtStateListener *listener);
    static int32_t ActionOfRemoveBtStateListener(int listenerId);
    static int32_t ActionOfAddScanListener(const SoftBusScanListener *listener);
    static int32_t ActionOfRemoveScanListener(int listenerId);
    static int32_t ActionOfSetScanFilter(int listenerId, const SoftBusBleScanFilter *filter, uint8_t filterSize);
    static int32_t ActionOfGetAdvChannel(const SoftBusAdvCallback *callback);
    static int32_t ActionOfReleaseAdvChannel(int channel);
    static int32_t ActionOfStartScan(int listenerId, const SoftBusBleScanParams *param);
    static int32_t ActionOfStopScan(int listenerId);
    static int32_t ActionOfStartAdv(int channel, const SoftBusBleAdvParams *param);
    static int32_t ActionOfStopAdv(int channel);
    static int32_t ActionOfSetAdvDataForActiveDiscovery(int channel, const SoftBusBleAdvData *data);
    static int32_t ActionOfUpdateAdvForActiveDiscovery(int channel, const SoftBusBleAdvData *data,
                                                       const SoftBusBleAdvParams *param);
    static int32_t ActionOfSetAdvDataForActivePublish(int channel, const SoftBusBleAdvData *data);
    static int32_t ActionOfSetAdvDataForPassivePublish(int channel, const SoftBusBleAdvData *data);
    static int32_t ActionOfUpdateAdvForPassivePublish(int channel, const SoftBusBleAdvData *data,
                                                      const SoftBusBleAdvParams *param);
    static int32_t ActionOfGetBtMacAddr(SoftBusBtAddr *mac);
    static int32_t ActionOfGetBtState();

    static void InjectPassiveNonPacket();
    static void InjectActiveNonPacket();
    static void InjectActiveConPacket();
    static void TurnOnBt();
    static void TurnOffBt();
    static void WaitRecvMessageObsolete();
    static bool IsDeInitSuccess();

    static constexpr int CON_ADV_ID = 0;
    static constexpr int NON_ADV_ID = 1;
    static constexpr int BT_STATE_LISTENER_ID = 1;
    static constexpr int SCAN_LISTENER_ID = 2;
    static constexpr int BLE_MSG_TIME_OUT_MS = 6000;

    static inline const SoftBusScanListener *scanListener {};
    static inline const SoftBusBtStateListener *btStateListener {};
    static inline const SoftBusAdvCallback *advCallback {};
    static inline bool isAdvertising {};
    static inline bool isScanning {};
    static inline bool btState {};
    static inline uint8_t btMacAddr[] = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    static inline uint8_t activeDiscoveryAdvData[] = {
        0x02, 0x01, 0x02, 0x15, 0x16, 0xEE, 0xFD, 0x04,
        0x05, 0x90, 0x00, 0x01, 0x02, 0x00, 0x18, 0x64,
        0x30, 0x31, 0x35, 0x35, 0x39, 0x62, 0x62, 0x21,
        0x0E
    };
    static inline uint8_t activeDiscoveryAdvData2[] = {
        0x02, 0x01, 0x02, 0x15, 0x16, 0xEE, 0xFD, 0x04,
        0x05, 0x90, 0x00, 0x01, 0x12, 0x00, 0x18, 0x64,
        0x30, 0x31, 0x35, 0x35, 0x39, 0x62, 0x62, 0x21,
        0x0E
    };
    static inline uint8_t activeDiscoveryRspData[] = {
        0x03, 0xFF, 0x7D, 0x02
    };

    static inline uint8_t activePublishAdvData[] = {
        0x02, 0x01, 0x02, 0x15, 0x16, 0xEE, 0xFD, 0x04,
        0x05, 0x10, 0x00, 0x01, 0x02, 0x00, 0x18, 0x64,
        0x30, 0x31, 0x35, 0x35, 0x39, 0x62, 0x62, 0x21,
        0x0E
    };
    static inline uint8_t activePublishRspData[] = {
        0x03, 0xFF, 0x7D, 0x02
    };

    static inline uint8_t passivePublishAdvData[] = {
        0x02, 0x01, 0x02, 0x1B, 0x16, 0xEE, 0xFD, 0x04,
        0x05, 0x10, 0x00, 0x01, 0x02, 0x00, 0x18, 0x64,
        0x30, 0x31, 0x35, 0x35, 0x39, 0x62, 0x62, 0x21,
        0x0E, 0x56, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    };
    static inline uint8_t passivePublishRspData[] = {
        0x04, 0xFF, 0x7D, 0x02, 0x0F
    };

private:
    static void HexDump(const uint8_t *data, uint32_t len);
    static void ShowAdvData(int channel, const SoftBusBleAdvData *data);

    static inline std::atomic<BleMock*> mock = nullptr;
    static inline std::atomic_bool isAsyncAdvertiseSuccess;

    static constexpr int32_t BYTE_DUMP_LEN = 2;
    static constexpr int32_t WAIT_LOOPER_DONE_MS = 500;
    static constexpr int32_t WAIT_ASYNC_TIMEOUT = 1;

    std::mutex mutex_;
    std::condition_variable cv_;
    std::mutex scanMutex_;
    std::condition_variable scanCv_;
};
#endif