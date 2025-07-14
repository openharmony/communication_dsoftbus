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

#ifndef SOFTBUS_BROADCAST_MGR_MOCK_H
#define SOFTBUS_BROADCAST_MGR_MOCK_H

#include <atomic>
#include <gmock/gmock.h>

#include "softbus_adapter_bt_common_struct.h"
#include "softbus_broadcast_manager_struct.h"
#include "softbus_broadcast_utils_struct.h"

#define DEFAULT_LISTENER_ID 1

namespace OHOS {
class SoftbusBroadcastMgrInterface {
public:
    virtual int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener, int32_t *listenerId) = 0;
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
    virtual bool BroadcastIsLpDeviceAvailable(void) = 0;
    virtual bool BroadcastSetAdvDeviceParam(
        LpServerType type, const LpBroadcastParam *bcParam, const LpScanParam *scanParam) = 0;
    virtual int32_t BroadcastGetBroadcastHandle(int32_t bcId, int32_t *bcHandle) = 0;
    virtual int32_t BroadcastEnableSyncDataToLpDevice(void) = 0;
    virtual int32_t BroadcastDisableSyncDataToLpDevice(void) = 0;
    virtual int32_t BroadcastSetScanReportChannelToLpDevice(int32_t listenerId, bool enable) = 0;
    virtual int32_t BroadcastSetLpAdvParam(
        int32_t duration, int32_t maxExtAdvEvents, int32_t window, int32_t interval, int32_t bcHandle) = 0;

    virtual int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac) = 0;
    virtual int32_t SoftBusGetBtState() = 0;
};

class SoftbusBroadcastMgrMock : public SoftbusBroadcastMgrInterface {
public:
    static SoftbusBroadcastMgrMock *GetMock()
    {
        return mock.load();
    }

    SoftbusBroadcastMgrMock();
    virtual ~SoftbusBroadcastMgrMock();

    MOCK_METHOD(int32_t, SoftBusAddBtStateListener, (const SoftBusBtStateListener *listener,
        int32_t *listenerId), (override));
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
    MOCK_METHOD(bool, BroadcastIsLpDeviceAvailable, (), (override));
    MOCK_METHOD(bool, BroadcastSetAdvDeviceParam,
        (LpServerType type, const LpBroadcastParam *bcParam, const LpScanParam *scanParam), (override));
    MOCK_METHOD(int32_t, BroadcastGetBroadcastHandle, (int32_t bcId, int32_t *bcHandle), (override));
    MOCK_METHOD(int32_t, BroadcastEnableSyncDataToLpDevice, (), (override));
    MOCK_METHOD(int32_t, BroadcastDisableSyncDataToLpDevice, (), (override));
    MOCK_METHOD(int32_t, BroadcastSetScanReportChannelToLpDevice, (int32_t listenerId, bool enable), (override));
    MOCK_METHOD(int32_t, BroadcastSetLpAdvParam,
        (int32_t duration, int32_t maxExtAdvEvents, int32_t window, int32_t interval, int32_t bcHandle), (override));

    static void TurnOnBt();
    static void TurnOffBt();
    static bool IsDeInitSuccess();

public:
    static int32_t ActionOfAddBtStateListener(const SoftBusBtStateListener *listener, int32_t *listenerId);
    static int32_t ActionOfRemoveBtStateListener(int32_t listenerId);
    static int32_t ActionOfInitBroadcastMgr();
    static int32_t ActionOfDeInitBroadcastMgr();
    static int32_t ActionOfStartScan(int32_t listenerId, const BcScanParams *param);
    static int32_t ActionOfStopScan(int32_t listenerId);
    static int32_t ActionOfStartBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet);
    static int32_t ActionOfStopBroadcasting(int32_t bcId);
    static int32_t ActionOfRegisterScanListener(BaseServiceType type, int32_t *listenerId, const ScanCallback *cb);
    static int32_t ActionOfUnRegisterScanListener(int32_t listenerId);
    static int32_t ActionOfSetScanFilter(int32_t listenerId, const BcScanFilter *scanFilter, uint8_t filterNum);
    static int32_t ActionOfRegisterBroadcaster(BaseServiceType type, int32_t *bcId, const BroadcastCallback *cb);
    static int32_t ActionOfUnRegisterBroadcaster(int32_t bcId);
    static int32_t ActionOfGetBtMacAddr(SoftBusBtAddr *mac);
    static int32_t ActionOfGetBtState();

    static inline const ScanCallback *scanListener_ {};
    static inline const SoftBusBtStateListener *btStateListener_ {};
    static inline const BroadcastCallback *advCallback_ {};

private:
    static inline bool isAdvertising_[BC_NUM_MAX] = {};
    static inline bool isScanning_[SCAN_NUM_MAX] = {};
    static inline bool btState_ {};
    static inline uint8_t btMacAddr_[] = { 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    static inline int32_t btStateListenerId_ = DEFAULT_LISTENER_ID;
    static inline int32_t scanListenerId_ = DEFAULT_LISTENER_ID;

    static inline std::atomic<SoftbusBroadcastMgrMock *> mock = nullptr;
};

extern "C"
{
    int32_t UnRegisterBroadcaster(int32_t bcId);
    int32_t RegisterBroadcaster(BaseServiceType type, int32_t *bcId, const BroadcastCallback *cb);
    int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener, int32_t *listenerId);
    int32_t RegisterScanListener(BaseServiceType type, int32_t *listenerId, const ScanCallback *cb);
    int32_t SetScanFilter(int32_t listenerId, const BcScanFilter *scanFilter, uint8_t filterNum);

    int32_t SoftBusRemoveBtStateListener(int32_t listenerId);
    int32_t InitBroadcastMgr();
    int32_t DeInitBroadcastMgr();
    int32_t UnRegisterScanListener(int32_t listenerId);
    int32_t UnRegisterBroadcaster(int32_t bcId);
    int32_t StartScan(int32_t listenerId, const BcScanParams *param);
    int32_t StopScan(int32_t listenerId);
    int32_t StartBroadcasting(int32_t bcId, const BroadcastParam *param, const BroadcastPacket *packet);
    int32_t StopBroadcasting(int32_t bcId);
    int32_t SetBroadcastingData(int32_t bcId, const BroadcastPacket *packet);
    bool BroadcastIsLpDeviceAvailable(void);
    bool BroadcastSetAdvDeviceParam(
        LpServerType type, const LpBroadcastParam *bcParam, const LpScanParam *scanParam);
    int32_t BroadcastGetBroadcastHandle(int32_t bcId, int32_t *bcHandle);
    int32_t BroadcastEnableSyncDataToLpDevice(void);
    int32_t BroadcastDisableSyncDataToLpDevice(void);
    int32_t BroadcastSetScanReportChannelToLpDevice(int32_t listenerId, bool enable);
    int32_t BroadcastSetLpAdvParam(
        int32_t duration, int32_t maxExtAdvEvents, int32_t window, int32_t interval, int32_t bcHandle);
    int32_t SoftBusGetBtState();
}
} // namespace OHOS
#endif