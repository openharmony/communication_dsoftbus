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

#ifndef BLUETOOTH_MOCK_H
#define BLUETOOTH_MOCK_H

#include <gmock/gmock.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "c_header/ohos_bt_gap.h"
#include "c_header/ohos_bt_gatt.h"

namespace OHOS {
using testing::NiceMock;
using testing::AtMost;

class BluetoothInterface {
public:
    // bt_gap
    virtual bool EnableBle() = 0;
    virtual bool DisableBle() = 0;
    virtual bool IsBleEnabled() = 0;
    virtual bool EnableBr() = 0;
    virtual bool DisableBr() = 0;
    virtual int32_t GetBtState() = 0;
    virtual bool GetLocalAddr(unsigned char *mac, uint32_t len) = 0;
    virtual bool SetLocalName(unsigned char *localName, unsigned char length) = 0;
    virtual int32_t GapRegisterCallbacks(BtGapCallBacks *func) = 0;
    virtual bool PairRequestReply(const BdAddr *bdAddr, int32_t transport, bool accept) = 0;
    virtual bool SetDevicePairingConfirmation(const BdAddr *bdAddr, int32_t transport, bool accept) = 0;
    // bt_gatt
    virtual int32_t BleGattRegisterCallbacks(BtGattCallbacks *func) = 0;
    virtual int32_t BleRegisterScanCallbacks(BleScanCallbacks *func, int32_t *scannerId) = 0;
    virtual int32_t BleDeregisterScanCallbacks(int32_t scannerId) = 0;
    virtual int32_t BleStartScanEx(int32_t scannerId, const BleScanConfigs *configs, const BleScanNativeFilter *filter,
        uint32_t filterSize) = 0;
    virtual int32_t BleStopScan(int32_t scannerId) = 0;
    virtual int32_t BleStartAdvEx(int32_t *advId, const StartAdvRawData rawData, BleAdvParams advParam) = 0;
    virtual int32_t BleStopAdv(int32_t advId) = 0;
    virtual int32_t BleSetAdvData(int32_t advId, const StartAdvRawData data) = 0;
    // lp
    virtual int32_t GetAdvHandle(int32_t advId, int32_t *advHandle) = 0;
    virtual int32_t EnableSyncDataToLpDevice() = 0;
    virtual int32_t DisableSyncDataToLpDevice() = 0;
    virtual int32_t SetScanReportChannelToLpDevice(int32_t scannerId, bool enable) = 0;
    virtual int32_t SetLpDeviceAdvParam(int32_t duration, int32_t maxExtAdvEvents, int32_t window, int32_t interval,
        int32_t bcHandle) = 0;
    virtual int32_t IsLpDeviceAvailable() = 0;
    virtual int32_t SetLpDeviceParam(const BtLpDeviceParam *lpParam) = 0;
};

class BluetoothMock : public BluetoothInterface {
public:
    enum BtState {
        BT_STATE_OFF = 0,
        BT_STATE_ON,
        BT_STATE_RESTRICT,
        BT_STATE_BUTT,
    };

    explicit BluetoothMock(BtState btState = BT_STATE_OFF);
    ~BluetoothMock();

    MOCK_METHOD(bool, EnableBle, (), (override));
    MOCK_METHOD(bool, DisableBle, (), (override));
    MOCK_METHOD(bool, IsBleEnabled, (), (override));
    MOCK_METHOD(bool, EnableBr, (), (override));
    MOCK_METHOD(bool, DisableBr, (), (override));
    MOCK_METHOD(int32_t, GetBtState, (), (override));
    MOCK_METHOD(bool, GetLocalAddr, (unsigned char *mac, uint32_t len), (override));
    MOCK_METHOD(bool, SetLocalName, (unsigned char *localName, unsigned char length), (override));
    MOCK_METHOD(int32_t, GapRegisterCallbacks, (BtGapCallBacks *func), (override));
    MOCK_METHOD(bool, PairRequestReply, (const BdAddr *bdAddr, int32_t transport, bool accept), (override));
    MOCK_METHOD(bool, SetDevicePairingConfirmation, (const BdAddr *bdAddr, int32_t transport, bool accept), (override));

    MOCK_METHOD(int32_t, BleGattRegisterCallbacks, (BtGattCallbacks *func), (override));
    MOCK_METHOD(int32_t, BleRegisterScanCallbacks, (BleScanCallbacks *func, int32_t *scannerId), (override));
    MOCK_METHOD(int32_t, BleDeregisterScanCallbacks, (int32_t scannerId), (override));
    MOCK_METHOD(int32_t, BleStartScanEx, (int32_t scannerId, const BleScanConfigs *configs,
        const BleScanNativeFilter *filter, uint32_t filterSize), (override));
    MOCK_METHOD(int32_t, BleStopScan, (int32_t scannerId), (override));
    MOCK_METHOD(int32_t, BleStartAdvEx, (int32_t *advId, const StartAdvRawData rawData,
        BleAdvParams advParam), (override));
    MOCK_METHOD(int32_t, BleStopAdv, (int32_t advId), (override));
    MOCK_METHOD(int32_t, BleSetAdvData, (int32_t advId, const StartAdvRawData data), (override));

    MOCK_METHOD(int32_t, GetAdvHandle, (int32_t advId, int32_t *advHandle), (override));
    MOCK_METHOD(int32_t, EnableSyncDataToLpDevice, (), (override));
    MOCK_METHOD(int32_t, DisableSyncDataToLpDevice, (), (override));
    MOCK_METHOD(int32_t, SetScanReportChannelToLpDevice, (int32_t scannerId, bool enable), (override));
    MOCK_METHOD(int32_t, SetLpDeviceAdvParam, (int32_t duration, int32_t maxExtAdvEvents, int32_t window,
        int32_t interval, int32_t bcHandle), (override));
    MOCK_METHOD(int32_t, IsLpDeviceAvailable, (), (override));
    MOCK_METHOD(int32_t, SetLpDeviceParam, (const BtLpDeviceParam *lpParam), (override));

    static BluetoothMock *GetMock(void);
    static bool ActionEnableBle(void);
    static bool ActionDisableBle(void);
    static bool ActionIsBleEnabled(void);
    static bool ActionEnableBr(void);
    static bool ActionDisableBr(void);
    static int32_t ActionGetBtState(void);
    static int32_t ActionGapRegisterCallbacks(BtGapCallBacks *func);
    static int32_t ActionBleGattRegisterCallbacks(BtGattCallbacks *func);
    static int32_t ActionBleRegisterScanCallbacks(BleScanCallbacks *func, int32_t *scannerId);
    static int32_t ActionBleDeregisterScanCallbacks(int32_t scannerId);
    static int32_t ActionBleStartAdvEx(int32_t *advId, const StartAdvRawData rawData, BleAdvParams advParam);
    static int32_t ActionBleStopAdv(int32_t advId);
    static bool ActionGetLocalAddr(unsigned char *mac, uint32_t len);
    static void CallbackAdvEnable();
    static void CallbackScanResult(const std::string &hexStr);
    static void ConvertBtState(BtState newBtState);

private:
    static inline BluetoothMock *mock_ = nullptr;
    static inline BtGapCallBacks *btGapCallbacks_ = nullptr;
    static inline BtGattCallbacks *btGattCallbacks_ = nullptr;
    static inline std::unordered_map<int32_t, BleScanCallbacks*> bleScanCallbacks_ = {};
    static inline bool isBrEnabled_ = false;
    static inline bool isBleEnabled_ = false;
    static inline BtState currentBtState_ = BtState::BT_STATE_OFF;
    static inline std::unordered_set<int32_t> advIds_ = {};
    static inline uint8_t brAddr_[OHOS_BD_ADDR_LEN] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB};
};

class ExpectWrapper {
public:
    enum ExpectCommand {
        BLE_START_SCAN_EX = 0,
        BLE_STOP_SCAN,
        BLE_START_ADV_EX,
        BLE_SET_ADV_DATA,
        BLE_STOP_ADV,
        GET_LOCAL_ADDR,
        EXPECT_COMMAND_BUTT,
    };

    explicit ExpectWrapper(NiceMock<BluetoothMock> &mock) : mock_(mock)
    {
        Clear();
    }

    ~ExpectWrapper()
    {
    }

    ExpectWrapper &Call(ExpectCommand command, uint32_t count)
    {
        assert(0 <= command && command < EXPECT_COMMAND_BUTT);
        expectCallCount_[command] = count;
        return *this;
    }

    ExpectWrapper &Clear()
    {
        for (uint32_t i = 0; i < EXPECT_COMMAND_BUTT; ++i) {
            expectCallCount_[i] = 0;
        }
        return *this;
    }

    void Build()
    {
        EXPECT_CALL(mock_, BleStartScanEx).Times(expectCallCount_[BLE_START_SCAN_EX]);
        EXPECT_CALL(mock_, BleStopScan).Times(expectCallCount_[BLE_STOP_SCAN]);
        EXPECT_CALL(mock_, BleStartAdvEx).Times(expectCallCount_[BLE_START_ADV_EX]);
        EXPECT_CALL(mock_, BleSetAdvData).Times(expectCallCount_[BLE_SET_ADV_DATA]);
        EXPECT_CALL(mock_, BleStopAdv).Times(expectCallCount_[BLE_STOP_ADV]);
        EXPECT_CALL(mock_, GetLocalAddr).Times(expectCallCount_[GET_LOCAL_ADDR]);
        Clear();
    }

private:
    uint32_t expectCallCount_[EXPECT_COMMAND_BUTT];
    NiceMock<BluetoothMock> &mock_;
};

void SleepMs(int64_t ms);
bool HexStr2Bytes(const std::string &hexStr, std::vector<uint8_t> &bytes);
} // namespace OHOS

#endif /* BLUETOOTH_MOCK_H */
