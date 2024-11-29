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

#ifndef HEARTBEAT_STRATEGY_H
#define HEARTBEAT_STRATEGY_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_hichain_adapter.h"
#include "auth_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_device_info_recovery.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_net_builder.h"

namespace OHOS {
class HeartBeatStategyInterface {
public:
    HeartBeatStategyInterface() {};
    virtual ~HeartBeatStategyInterface() {};

    virtual int32_t LnnStartOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t LnnStopOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t LnnNotifyDiscoveryDevice(
        const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport, bool isNeedConnect) = 0;
    virtual int32_t LnnSetHbAsMasterNodeState(bool isMasterNode) = 0;
    virtual int32_t LnnNotifyMasterElect(const char *networkId, const char *masterUdid, int32_t masterWeight) = 0;
    virtual int32_t LnnStartHbByTypeAndStrategy(
        LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType, bool isRelay) = 0;
    virtual int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual AuthVerifyCallback *LnnGetReAuthVerifyCallback(void) = 0;
    virtual int32_t LnnSetGearModeBySpecificType(
        const char *callerId, const GearMode *mode, LnnHeartbeatType type) = 0;
    virtual int32_t LnnEnableHeartbeatByType(LnnHeartbeatType type, bool isEnable) = 0;
    virtual int32_t LnnStopHeartbeatByType(LnnHeartbeatType type) = 0;
    virtual int32_t LnnHbStrategyInit(void) = 0;
    virtual int32_t LnnUpdateSendInfoStrategy(LnnHeartbeatUpdateInfoType type) = 0;
    virtual int32_t LnnStopScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t LnnSetMediumParamBySpecificType(const LnnHeartbeatMediumParam *param) = 0;
    virtual int32_t LnnStartScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t LnnStopHeartBeatAdvByTypeNow(LnnHeartbeatType registedHbType) = 0;
    virtual int32_t LnnAsyncCallbackDelayHelper(
        SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis) = 0;
    virtual int32_t LnnStartHeartbeat(uint64_t delayMillis) = 0;
    virtual bool IsNeedAuthLimit(const char *udidHash) = 0;
    virtual bool IsExistLnnDfxNodeByUdidHash(const char *udidHash, LnnBleReportExtra *bleExtra) = 0;
    virtual int32_t LnnRetrieveDeviceInfo(const char *udid, NodeInfo *deviceInfo) = 0;
    virtual bool IsSameAccountGroupDevice(void) = 0;
    virtual uint32_t AuthGenRequestId(void) = 0;
    virtual int32_t AuthStartVerify(const AuthConnInfo *connInfo, uint32_t requestId,
        const AuthVerifyCallback *verifyCallback, AuthVerifyModule module, bool isFastAuth) = 0;
    virtual void AddNodeToLnnBleReportExtraMap(const char *udidHash, const LnnBleReportExtra *bleExtra) = 0;
    virtual int32_t GetNodeFromLnnBleReportExtraMap(const char *udidHash, LnnBleReportExtra *bleExtra) = 0;
    virtual void DeleteNodeFromLnnBleReportExtraMap(const char *udidHash) = 0;
    virtual int32_t LnnUpdateRemoteDeviceInfo(const NodeInfo *deviceInfo) = 0;
    virtual int32_t GetNodeFromPcRestrictMap(const char *udidHash, uint32_t *count) = 0;
    virtual int32_t LnnSetDLConnUserIdCheckSum(const char *networkId, int32_t userIdCheckSum) = 0;
    virtual void LnnNotifyDeviceTrustedChange(int32_t type, const char *msg, uint32_t msgLen) = 0;
    virtual void NotifyForegroundUseridChange(char *networkId, uint32_t discoveryType, bool isChange) = 0;
};
class HeartBeatStategyInterfaceMock : public HeartBeatStategyInterface {
public:
    HeartBeatStategyInterfaceMock();
    ~HeartBeatStategyInterfaceMock() override;

    MOCK_METHOD2(LnnStartOfflineTimingStrategy, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD2(LnnStopOfflineTimingStrategy, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD3(LnnNotifyDiscoveryDevice, int32_t(const ConnectionAddr *, const LnnDfxDeviceInfoReport *, bool));
    MOCK_METHOD3(LnnNotifyMasterElect, int32_t(const char *, const char *, int32_t));
    MOCK_METHOD1(LnnSetHbAsMasterNodeState, int32_t(bool));
    MOCK_METHOD3(LnnStartHbByTypeAndStrategy, int32_t(LnnHeartbeatType, LnnHeartbeatStrategyType, bool));
    MOCK_METHOD2(LnnRequestLeaveSpecific, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD0(LnnGetReAuthVerifyCallback, AuthVerifyCallback *(void));
    MOCK_METHOD3(LnnSetGearModeBySpecificType, int32_t(const char *, const GearMode *, LnnHeartbeatType));
    MOCK_METHOD2(LnnEnableHeartbeatByType, int32_t(LnnHeartbeatType, bool));
    MOCK_METHOD1(LnnStopHeartbeatByType, int32_t(LnnHeartbeatType));
    MOCK_METHOD0(LnnHbStrategyInit, int32_t(void));
    MOCK_METHOD1(LnnUpdateSendInfoStrategy, int32_t(LnnHeartbeatUpdateInfoType));
    MOCK_METHOD2(LnnStopScreenChangeOfflineTiming, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD1(LnnSetMediumParamBySpecificType, int32_t(const LnnHeartbeatMediumParam *));
    MOCK_METHOD2(LnnStartScreenChangeOfflineTiming, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD1(LnnStopHeartBeatAdvByTypeNow, int32_t(LnnHeartbeatType));
    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t(SoftBusLooper *, LnnAsyncCallbackFunc, void *, uint64_t));
    MOCK_METHOD1(LnnStartHeartbeat, int32_t(uint64_t));
    MOCK_METHOD1(IsNeedAuthLimit, bool(const char *));
    MOCK_METHOD2(IsExistLnnDfxNodeByUdidHash, bool(const char *, LnnBleReportExtra *));
    MOCK_METHOD2(LnnRetrieveDeviceInfo, int32_t(const char *, NodeInfo *));
    MOCK_METHOD0(IsSameAccountGroupDevice, bool(void));
    MOCK_METHOD0(AuthGenRequestId, uint32_t(void));
    MOCK_METHOD5(
        AuthStartVerify, int32_t(const AuthConnInfo *, uint32_t, const AuthVerifyCallback *, AuthVerifyModule, bool));
    MOCK_METHOD2(AddNodeToLnnBleReportExtraMap, void(const char *, const LnnBleReportExtra *));
    MOCK_METHOD2(GetNodeFromLnnBleReportExtraMap, int32_t(const char *, LnnBleReportExtra *));
    MOCK_METHOD1(DeleteNodeFromLnnBleReportExtraMap, void(const char *));
    MOCK_METHOD1(LnnUpdateRemoteDeviceInfo, int32_t(const NodeInfo *));
    MOCK_METHOD2(GetNodeFromPcRestrictMap, int32_t(const char *, uint32_t *));
    MOCK_METHOD2(LnnSetDLConnUserIdCheckSum, int32_t(const char *networkId, int32_t userIdCheckSum));
    MOCK_METHOD3(LnnNotifyDeviceTrustedChange, void(int32_t type, const char *msg, uint32_t msgLen));
    MOCK_METHOD3(NotifyForegroundUseridChange, void(char *, uint32_t, bool));
};
} // namespace OHOS
#endif // HEARTBEAT_STRATEGY_H
