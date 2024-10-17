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

#include "bluetooth_mock.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <thread>

#include "disc_log.h"
#include "securec.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

extern "C" {
bool EnableBr(void);
bool DisableBr(void);
}

#define LOG(fmt, ...)                    \
    do {                                 \
        printf(fmt "\n", ##__VA_ARGS__); \
    } while (false)

namespace {
using OHOS::BluetoothMock;
using BtState = OHOS::BluetoothMock::BtState;

constexpr int64_t SLEEP_TIME = 200;

const std::function<void(void)> BT_STATE_FSM[BtState::BT_STATE_BUTT][BtState::BT_STATE_BUTT] = {
    // BT_STATE_OFF
    {
        // BT_STATE_OFF -> BT_STATE_OFF
        nullptr,
        // BT_STATE_OFF -> BT_STATE_ON
        []() {
            std::thread(EnableBle).detach();
            std::thread(EnableBr).detach();
        },
        // BT_STATE_OFF -> BT_STATE_RESTRICT
        nullptr,
    },
    // BT_STATE_ON
    {
        // BT_STATE_ON -> BT_STATE_OFF
        []() {
            std::thread(DisableBr).detach();
            std::thread(DisableBle).detach();
        },
        // BT_STATE_ON -> BT_STATE_ON
        nullptr,
        // BT_STATE_ON -> BT_STATE_RESTRICT
        []() {
            DisableBr();
        },
    },
    // BT_STATE_RESTRICT
    {
        // BT_STATE_RESTRICT -> BT_STATE_OFF
        []() {
            DisableBle();
        }, // BT_STATE_RESTRICT -> BT_STATE_ON
        []() {
            EnableBr();
        }, // BT_STATE_RESTRICT -> BT_STATE_RESTRICT
        nullptr, },
};
} // anonymous namespace

namespace OHOS {
BluetoothMock::BluetoothMock(BluetoothMock::BtState btState)
{
    BluetoothMock::mock_ = this;
    BluetoothMock::currentBtState_ = btState;
    BluetoothMock::isBleEnabled_ = (btState != BluetoothMock::BtState::BT_STATE_OFF);
    BluetoothMock::isBrEnabled_ = (btState == BluetoothMock::BtState::BT_STATE_ON);

    ON_CALL(*this, EnableBle).WillByDefault(BluetoothMock::ActionEnableBle);
    ON_CALL(*this, DisableBle).WillByDefault(BluetoothMock::ActionDisableBle);
    ON_CALL(*this, IsBleEnabled).WillByDefault(BluetoothMock::ActionIsBleEnabled);
    ON_CALL(*this, EnableBr).WillByDefault(BluetoothMock::ActionEnableBr);
    ON_CALL(*this, DisableBr).WillByDefault(BluetoothMock::ActionDisableBr);
    ON_CALL(*this, GetBtState).WillByDefault(BluetoothMock::ActionGetBtState);
    ON_CALL(*this, GapRegisterCallbacks).WillByDefault(BluetoothMock::ActionGapRegisterCallbacks);
    ON_CALL(*this, BleGattRegisterCallbacks).WillByDefault(BluetoothMock::ActionBleGattRegisterCallbacks);
    ON_CALL(*this, BleRegisterScanCallbacks).WillByDefault(BluetoothMock::ActionBleRegisterScanCallbacks);
    ON_CALL(*this, BleDeregisterScanCallbacks).WillByDefault(BluetoothMock::ActionBleDeregisterScanCallbacks);
    ON_CALL(*this, BleStartAdvEx).WillByDefault(BluetoothMock::ActionBleStartAdvEx);
    ON_CALL(*this, BleStopAdv).WillByDefault(BluetoothMock::ActionBleStopAdv);
    ON_CALL(*this, GetLocalAddr).WillByDefault(BluetoothMock::ActionGetLocalAddr);
}

BluetoothMock::~BluetoothMock()
{
    BluetoothMock::mock_ = nullptr;
    BluetoothMock::advIds_.clear();
}

BluetoothMock *BluetoothMock::GetMock()
{
    return BluetoothMock::mock_;
}

void BluetoothMock::ConvertBtState(BluetoothMock::BtState newBtState)
{
    if (newBtState < 0 || newBtState >= BT_STATE_BUTT) {
        LOG("btState invalid");
        return;
    }

    if (BT_STATE_FSM[BluetoothMock::currentBtState_][newBtState]) {
        BT_STATE_FSM[BluetoothMock::currentBtState_][newBtState]();
    }
    BluetoothMock::currentBtState_ = newBtState;
    SleepMs(SLEEP_TIME);
}

bool BluetoothMock::ActionEnableBle()
{
    if (!BluetoothMock::isBleEnabled_) {
        BluetoothMock::isBleEnabled_ = true;
        if (BluetoothMock::btGapCallbacks_ && BluetoothMock::btGapCallbacks_->stateChangeCallback) {
            BluetoothMock::btGapCallbacks_->stateChangeCallback(OHOS_BT_TRANSPORT_LE, OHOS_GAP_STATE_TURNING_ON);
            BluetoothMock::btGapCallbacks_->stateChangeCallback(OHOS_BT_TRANSPORT_LE, OHOS_GAP_STATE_TURN_ON);
        } else {
            DISC_LOGW(DISC_TEST, "callback is null");
        }
    }
    return true;
}

bool BluetoothMock::ActionDisableBle()
{
    if (BluetoothMock::isBleEnabled_) {
        BluetoothMock::isBleEnabled_ = false;
        if (BluetoothMock::btGapCallbacks_ && BluetoothMock::btGapCallbacks_->stateChangeCallback) {
            BluetoothMock::btGapCallbacks_->stateChangeCallback(OHOS_BT_TRANSPORT_LE, OHOS_GAP_STATE_TURNING_OFF);
            BluetoothMock::btGapCallbacks_->stateChangeCallback(OHOS_BT_TRANSPORT_LE, OHOS_GAP_STATE_TURN_OFF);
        } else {
            DISC_LOGW(DISC_TEST, "callback is null");
        }
    }
    return true;
}

bool BluetoothMock::ActionEnableBr()
{
    if (!BluetoothMock::isBrEnabled_) {
        BluetoothMock::isBrEnabled_ = true;
        if (BluetoothMock::btGapCallbacks_ && BluetoothMock::btGapCallbacks_->stateChangeCallback) {
            BluetoothMock::btGapCallbacks_->stateChangeCallback(OHOS_BT_TRANSPORT_BR_EDR, OHOS_GAP_STATE_TURNING_ON);
            BluetoothMock::btGapCallbacks_->stateChangeCallback(OHOS_BT_TRANSPORT_BR_EDR, OHOS_GAP_STATE_TURN_ON);
        } else {
            DISC_LOGW(DISC_TEST, "callback is null");
        }
    }
    return true;
}

bool BluetoothMock::ActionDisableBr()
{
    if (BluetoothMock::isBrEnabled_) {
        BluetoothMock::isBrEnabled_ = false;
        if (BluetoothMock::btGapCallbacks_ && BluetoothMock::btGapCallbacks_->stateChangeCallback) {
            BluetoothMock::btGapCallbacks_->stateChangeCallback(OHOS_BT_TRANSPORT_BR_EDR, OHOS_GAP_STATE_TURNING_OFF);
            BluetoothMock::btGapCallbacks_->stateChangeCallback(OHOS_BT_TRANSPORT_BR_EDR, OHOS_GAP_STATE_TURN_OFF);
        } else {
            DISC_LOGW(DISC_TEST, "callback is null");
        }
    }
    return true;
}

bool BluetoothMock::ActionIsBleEnabled()
{
    return BluetoothMock::isBleEnabled_;
}

int32_t BluetoothMock::ActionGetBtState()
{
    if (BluetoothMock::isBrEnabled_) {
        return OHOS_GAP_STATE_TURN_ON;
    }
    return OHOS_GAP_STATE_TURN_OFF;
}

int32_t BluetoothMock::ActionGapRegisterCallbacks(BtGapCallBacks *func)
{
    if (func == nullptr) {
        return OHOS_BT_STATUS_PARM_INVALID;
    }
    BluetoothMock::btGapCallbacks_ = func;
    return OHOS_BT_STATUS_SUCCESS;
}

int32_t BluetoothMock::ActionBleGattRegisterCallbacks(BtGattCallbacks *func)
{
    if (func == nullptr) {
        return OHOS_BT_STATUS_PARM_INVALID;
    }
    BluetoothMock::btGattCallbacks_ = func;
    return OHOS_BT_STATUS_SUCCESS;
}

int32_t BluetoothMock::ActionBleRegisterScanCallbacks(BleScanCallbacks *func, int32_t *scannerId)
{
    if (func == nullptr || scannerId == nullptr) {
        return OHOS_BT_STATUS_PARM_INVALID;
    }

    static int32_t freeScannerId = 0;
    *scannerId = freeScannerId++;

    BluetoothMock::bleScanCallbacks_[*scannerId] = func;
    return OHOS_BT_STATUS_SUCCESS;
}

int32_t BluetoothMock::ActionBleDeregisterScanCallbacks(int32_t scannerId)
{
    auto it = BluetoothMock::bleScanCallbacks_.find(scannerId);
    if (it == BluetoothMock::bleScanCallbacks_.end()) {
        return OHOS_BT_STATUS_FAIL;
    }
    BluetoothMock::bleScanCallbacks_.erase(it);
    return OHOS_BT_STATUS_SUCCESS;
}

bool BluetoothMock::ActionGetLocalAddr(unsigned char *mac, uint32_t len)
{
    if (mac == nullptr || len < OHOS_BD_ADDR_LEN) {
        return false;
    }
    return memcpy_s(mac, len, BluetoothMock::brAddr_, OHOS_BD_ADDR_LEN) == EOK;
}

int32_t BluetoothMock::ActionBleStartAdvEx(int32_t *advId, const StartAdvRawData rawData, BleAdvParams advParam)
{
    if (advId == nullptr) {
        return OHOS_BT_STATUS_PARM_INVALID;
    }

    static int32_t freeAdvId = 0;
    *advId = freeAdvId++;
    BluetoothMock::advIds_.insert(*advId);
    return OHOS_BT_STATUS_SUCCESS;
}

int32_t BluetoothMock::ActionBleStopAdv(int32_t advId)
{
    if (advId < 0) {
        return OHOS_BT_STATUS_PARM_INVALID;
    }

    if (BluetoothMock::btGattCallbacks_ && BluetoothMock::btGattCallbacks_->advDisableCb) {
        std::thread(BluetoothMock::btGattCallbacks_->advDisableCb, advId, OHOS_BT_STATUS_SUCCESS).detach();
    } else {
        DISC_LOGW(DISC_TEST, "callback is null");
    }

    BluetoothMock::advIds_.erase(advId);
    return OHOS_BT_STATUS_SUCCESS;
}

void BluetoothMock::CallbackAdvEnable()
{
    if (!BluetoothMock::btGattCallbacks_ || !BluetoothMock::btGattCallbacks_->advEnableCb) {
        DISC_LOGE(DISC_TEST, "callback is null");
        return;
    }

    for (int32_t advId : BluetoothMock::advIds_) {
        BluetoothMock::btGattCallbacks_->advEnableCb(advId, OHOS_BT_STATUS_SUCCESS);
    }
}

bool HexStr2Bytes(const std::string &hexStr, std::vector<uint8_t> &bytes)
{
    constexpr int32_t HEX_CHAR_LEN = 2;
    constexpr int32_t NUMBER_BASE = 16;

    int32_t hexLen = hexStr.length();
    if (hexLen == 0 || hexLen % HEX_CHAR_LEN != 0) {
        return false;
    }

    bool isValid = std::all_of(hexStr.begin(), hexStr.end(), [](char chr) {
        return ('0' <= chr && chr <= '9') || ('A' <= chr && chr <= 'F');
    });
    if (!isValid) {
        return false;
    }

    int32_t advLen = hexLen / HEX_CHAR_LEN;
    bytes.clear();
    bytes.resize(advLen);

    for (int32_t index = 0; index < advLen; ++index) {
        const auto &subHexStr = hexStr.substr(index * HEX_CHAR_LEN, HEX_CHAR_LEN);
        bytes[index] = strtol(subHexStr.c_str(), nullptr, NUMBER_BASE);
    }
    return true;
}

void BluetoothMock::CallbackScanResult(const std::string &hexStr)
{
    std::vector<uint8_t> advData;
    if (!HexStr2Bytes(hexStr, advData)) {
        LOG("hexStr invalid");
        return;
    }

    BtScanResultData scanResult = {
        .eventType = OHOS_BLE_EVT_LEGACY_CONNECTABLE,
        .dataStatus = OHOS_BLE_DATA_COMPLETE,
        .addrType = OHOS_BLE_RANDOM_DEVICE_ADDRESS,
        .addr = {
            .addr = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
        },
        .primaryPhy = OHOS_BLE_SCAN_PHY_1M,
        .secondaryPhy = OHOS_BLE_SCAN_PHY_1M,
        .advSid = 1,
        .txPower = 1,
        .rssi = -38,
        .directAddrType = OHOS_BLE_RANDOM_DEVICE_ADDRESS,
        .advLen = advData.size(),
        .advData = &advData[0],
    };

    for (auto &[scannerId, scanCallback] : BluetoothMock::bleScanCallbacks_) {
        if (scanCallback->scanResultCb) {
            scanCallback->scanResultCb(&scanResult);
        }
    }
    SleepMs(SLEEP_TIME);
}

void DumpBleAdvRawData(const StartAdvRawData &rawData)
{
    constexpr uint32_t BUFF_LEN = 200;
    char advData[BUFF_LEN] = { 0 };
    char rspData[BUFF_LEN] = { 0 };
    if (ConvertBytesToUpperCaseHexString(advData, BUFF_LEN, rawData.advData, rawData.advDataLen) == SOFTBUS_OK &&
        ConvertBytesToUpperCaseHexString(rspData, BUFF_LEN, rawData.rspData, rawData.rspDataLen) == SOFTBUS_OK) {
        LOG("%s adv=%s, rsp=%s", __func__, advData, rspData);
    }
}

void SleepMs(int64_t ms)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}
} // namespace OHOS

using OHOS::BluetoothMock;

bool EnableBle()
{
    return BluetoothMock::GetMock()->EnableBle();
}

bool DisableBle()
{
    return BluetoothMock::GetMock()->DisableBle();
}

bool IsBleEnabled()
{
    return BluetoothMock::GetMock()->IsBleEnabled();
}

bool EnableBr()
{
    return BluetoothMock::GetMock()->EnableBr();
}

bool DisableBr()
{
    return BluetoothMock::GetMock()->DisableBr();
}

int32_t GetBtState()
{
    return BluetoothMock::GetMock()->GetBtState();
}

bool GetLocalAddr(unsigned char *mac, uint32_t len)
{
    LOG("%s", __func__);
    return BluetoothMock::GetMock()->GetLocalAddr(mac, len);
}

bool SetLocalName(unsigned char *localName, unsigned char length)
{
    LOG("%s", __func__);
    return BluetoothMock::GetMock()->SetLocalName(localName, length);
}

int32_t GapRegisterCallbacks(BtGapCallBacks *func)
{
    LOG("%s", __func__);
    return BluetoothMock::GetMock()->GapRegisterCallbacks(func);
}

bool PairRequestReply(const BdAddr *bdAddr, int32_t transport, bool accept)
{
    LOG("%s", __func__);
    return BluetoothMock::GetMock()->PairRequestReply(bdAddr, transport, accept);
}

bool SetDevicePairingConfirmation(const BdAddr *bdAddr, int32_t transport, bool accept)
{
    LOG("%s", __func__);
    return BluetoothMock::GetMock()->SetDevicePairingConfirmation(bdAddr, transport, accept);
}

int32_t BleGattRegisterCallbacks(BtGattCallbacks *func)
{
    LOG("%s", __func__);
    return BluetoothMock::GetMock()->BleGattRegisterCallbacks(func);
}

int32_t BleRegisterScanCallbacks(BleScanCallbacks *func, int32_t *scannerId)
{
    LOG("%s", __func__);
    return BluetoothMock::GetMock()->BleRegisterScanCallbacks(func, scannerId);
}

int32_t BleDeregisterScanCallbacks(int32_t scannerId)
{
    LOG("%s", __func__);
    return BluetoothMock::GetMock()->BleDeregisterScanCallbacks(scannerId);
}

int32_t BleStartScanEx(int32_t scannerId, const BleScanConfigs *configs, const BleScanNativeFilter *filter,
    uint32_t filterSize)
{
    LOG("%s", __func__);
    return BluetoothMock::GetMock()->BleStartScanEx(scannerId, configs, filter, filterSize);
}

int32_t BleStopScan(int32_t scannerId)
{
    LOG("%s", __func__);
    return BluetoothMock::GetMock()->BleStopScan(scannerId);
}

int32_t BleStartAdvEx(int32_t *advId, const StartAdvRawData rawData, BleAdvParams advParam)
{
    LOG("%s", __func__);
    OHOS::DumpBleAdvRawData(rawData);
    return BluetoothMock::GetMock()->BleStartAdvEx(advId, rawData, advParam);
}

int32_t BleStopAdv(int32_t advId)
{
    LOG("%s", __func__);
    return BluetoothMock::GetMock()->BleStopAdv(advId);
}

int32_t BleSetAdvData(int32_t advId, const StartAdvRawData data)
{
    LOG("%s", __func__);
    OHOS::DumpBleAdvRawData(data);
    return BluetoothMock::GetMock()->BleSetAdvData(advId, data);
}

int32_t GetAdvHandle(int32_t advId, int32_t *advHandle)
{
    LOG("%s", __func__);
    return BluetoothMock::GetMock()->GetAdvHandle(advId, advHandle);
}

int32_t EnableSyncDataToLpDevice()
{
    LOG("%s", __func__);
    return BluetoothMock::GetMock()->EnableSyncDataToLpDevice();
}

int32_t DisableSyncDataToLpDevice()
{
    LOG("%s", __func__);
    return BluetoothMock::GetMock()->DisableSyncDataToLpDevice();
}

int32_t SetScanReportChannelToLpDevice(int32_t scannerId, bool enable)
{
    LOG("%s", __func__);
    return BluetoothMock::GetMock()->SetScanReportChannelToLpDevice(scannerId, enable);
}

int32_t SetLpDeviceAdvParam(int32_t duration, int32_t maxExtAdvEvents, int32_t window, int32_t interval,
    int32_t bcHandle)
{
    LOG("%s", __func__);
    return BluetoothMock::GetMock()->SetLpDeviceAdvParam(duration, maxExtAdvEvents, window, interval, bcHandle);
}

bool IsLpDeviceAvailable()
{
    LOG("%s", __func__);
    return BluetoothMock::GetMock()->IsLpDeviceAvailable();
}

int32_t SetLpDeviceParam(const BtLpDeviceParam *lpParam)
{
    LOG("%s", __func__);
    return BluetoothMock::GetMock()->SetLpDeviceParam(lpParam);
}
