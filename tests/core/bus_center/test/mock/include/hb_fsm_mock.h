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

#ifndef HEARTBEAT_FSM_H
#define HEARTBEAT_FSM_H

#include <gmock/gmock.h>
#include <mutex>

#include "lnn_connection_addr_utils.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_heartbeat_medium_mgr.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_net_builder.h"
#include "wifi_direct_manager.h"

namespace OHOS {
class HeartBeatFSMInterface {
public:
    HeartBeatFSMInterface() {};
    virtual ~HeartBeatFSMInterface() {};

    virtual int32_t LnnStartOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t LnnStopOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t LnnNotifyDiscoveryDevice(
        const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport, bool isNeedConnect) = 0;
    virtual int32_t LnnSetHbAsMasterNodeState(bool isMasterNode) = 0;
    virtual int32_t LnnNotifyMasterElect(const char *networkId, const char *masterUdid, int32_t masterWeight) = 0;
    virtual void LnnNotifyHBRepeat(void);
    virtual int32_t LnnStartHbByTypeAndStrategy(
        LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType, bool isRelay) = 0;
    virtual int32_t LnnHbMediumMgrStop(LnnHeartbeatType *type) = 0;
    virtual void LnnDumpHbMgrRecvList(void) = 0;
    virtual void LnnDumpHbOnlineNodeList(void) = 0;
    virtual bool LnnIsHeartbeatEnable(LnnHeartbeatType type) = 0;
    virtual int32_t LnnGetGearModeBySpecificType(GearMode *mode, char *callerId, LnnHeartbeatType type) = 0;
    virtual DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type) = 0;
    virtual int32_t LnnOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t LnnHbMediumMgrSendBegin(LnnHeartbeatSendBeginData *custData) = 0;
    virtual int32_t LnnHbMediumMgrSendEnd(LnnHeartbeatSendEndData *type) = 0;
    virtual int32_t LnnGetHbStrategyManager(
        LnnHeartbeatStrategyManager *mgr, LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType) = 0;
    virtual int32_t LnnHbMediumMgrSetParam(void *param) = 0;
    virtual int32_t LnnHbMediumMgrUpdateSendInfo(LnnHeartbeatUpdateInfoType type) = 0;
    virtual int32_t LnnStartScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t LnnStopScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t StopHeartBeatAdvByTypeNow(LnnHeartbeatType registedHbType) = 0;
    virtual SoftBusScreenState GetScreenState(void) = 0;
    virtual void SetScreenState(SoftBusScreenState state) = 0;
    virtual struct WifiDirectManager *GetWifiDirectManager(void) = 0;
};
class HeartBeatFSMInterfaceMock : public HeartBeatFSMInterface {
public:
    HeartBeatFSMInterfaceMock();
    ~HeartBeatFSMInterfaceMock() override;

    MOCK_METHOD2(LnnStartOfflineTimingStrategy, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD2(LnnStopOfflineTimingStrategy, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD3(LnnNotifyDiscoveryDevice, int32_t(const ConnectionAddr *, const LnnDfxDeviceInfoReport *, bool));
    MOCK_METHOD3(LnnNotifyMasterElect, int32_t(const char *, const char *, int32_t));
    MOCK_METHOD1(LnnSetHbAsMasterNodeState, int32_t(bool));
    MOCK_METHOD0(LnnNotifyHBRepeat, void());
    MOCK_METHOD3(LnnStartHbByTypeAndStrategy, int32_t(LnnHeartbeatType, LnnHeartbeatStrategyType, bool));
    MOCK_METHOD1(LnnHbMediumMgrStop, int32_t(LnnHeartbeatType *));
    MOCK_METHOD0(LnnDumpHbMgrRecvList, void(void));
    MOCK_METHOD0(LnnDumpHbOnlineNodeList, void(void));
    MOCK_METHOD1(LnnIsHeartbeatEnable, bool(LnnHeartbeatType));
    MOCK_METHOD3(LnnGetGearModeBySpecificType, int32_t(GearMode *, char *, LnnHeartbeatType));
    MOCK_METHOD1(LnnConvAddrTypeToDiscType, DiscoveryType(ConnectionAddrType));
    MOCK_METHOD2(LnnOfflineTimingByHeartbeat, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD2(LnnRequestLeaveSpecific, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD1(LnnHbMediumMgrSendBegin, int32_t(LnnHeartbeatSendBeginData *));
    MOCK_METHOD1(LnnHbMediumMgrSendEnd, int32_t(LnnHeartbeatSendEndData *));
    MOCK_METHOD3(
        LnnGetHbStrategyManager, int32_t(LnnHeartbeatStrategyManager *, LnnHeartbeatType, LnnHeartbeatStrategyType));
    MOCK_METHOD1(LnnHbMediumMgrSetParam, int32_t(void *));
    MOCK_METHOD1(LnnHbMediumMgrUpdateSendInfo, int32_t(LnnHeartbeatUpdateInfoType));
    MOCK_METHOD2(LnnStartScreenChangeOfflineTiming, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD2(LnnStopScreenChangeOfflineTiming, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD1(StopHeartBeatAdvByTypeNow, int32_t(LnnHeartbeatType));
    MOCK_METHOD0(GetScreenState, SoftBusScreenState(void));
    MOCK_METHOD1(SetScreenState, void(SoftBusScreenState));
    MOCK_METHOD0(GetWifiDirectManager, WifiDirectManager *(void));
};
} // namespace OHOS
#endif // AUTH_CONNECTION_MOCK_H