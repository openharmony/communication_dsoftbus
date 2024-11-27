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

#include "hb_fsm_mock.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_hbFSMInterface;
HeartBeatFSMInterfaceMock::HeartBeatFSMInterfaceMock()
{
    g_hbFSMInterface = reinterpret_cast<void *>(this);
}

HeartBeatFSMInterfaceMock::~HeartBeatFSMInterfaceMock()
{
    g_hbFSMInterface = nullptr;
}

static HeartBeatFSMInterface *HeartBeatFSMInterfaceInstance()
{
    return reinterpret_cast<HeartBeatFSMInterfaceMock *>(g_hbFSMInterface);
}

extern "C" {
int32_t LnnStartOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType)
{
    return HeartBeatFSMInterfaceInstance()->LnnStartOfflineTimingStrategy(networkId, addrType);
}

int32_t LnnStopOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType)
{
    return HeartBeatFSMInterfaceInstance()->LnnStopOfflineTimingStrategy(networkId, addrType);
}

int32_t LnnNotifyDiscoveryDevice(
    const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport, bool isNeedConnect)
{
    return HeartBeatFSMInterfaceInstance()->LnnNotifyDiscoveryDevice(addr, infoReport, isNeedConnect);
}

int32_t LnnNotifyMasterElect(const char *networkId, const char *masterUdid, int32_t masterWeight)
{
    return HeartBeatFSMInterfaceInstance()->LnnNotifyMasterElect(networkId, masterUdid, masterWeight);
}

int32_t LnnSetHbAsMasterNodeState(bool isMasterNode)
{
    return HeartBeatFSMInterfaceInstance()->LnnSetHbAsMasterNodeState(isMasterNode);
}

void LnnNotifyHBRepeat(void)
{
    return HeartBeatFSMInterfaceInstance()->LnnNotifyHBRepeat();
}

int32_t LnnStartHbByTypeAndStrategy(LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType, bool isRelay)
{
    return HeartBeatFSMInterfaceInstance()->LnnStartHbByTypeAndStrategy(hbType, strategyType, isRelay);
}

int32_t LnnHbMediumMgrStop(LnnHeartbeatType *type)
{
    return HeartBeatFSMInterfaceInstance()->LnnHbMediumMgrStop(type);
}

void LnnDumpHbMgrRecvList(void)
{
    return HeartBeatFSMInterfaceInstance()->LnnDumpHbMgrRecvList();
}

void LnnDumpHbOnlineNodeList(void)
{
    return HeartBeatFSMInterfaceInstance()->LnnDumpHbOnlineNodeList();
}

bool LnnIsHeartbeatEnable(LnnHeartbeatType type)
{
    return HeartBeatFSMInterfaceInstance()->LnnIsHeartbeatEnable(type);
}

int32_t LnnGetGearModeBySpecificType(GearMode *mode, char *callerId, LnnHeartbeatType type)
{
    return HeartBeatFSMInterfaceInstance()->LnnGetGearModeBySpecificType(mode, callerId, type);
}

DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type)
{
    return HeartBeatFSMInterfaceInstance()->LnnConvAddrTypeToDiscType(type);
}

int32_t LnnOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType)
{
    return HeartBeatFSMInterfaceInstance()->LnnOfflineTimingByHeartbeat(networkId, addrType);
}

int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType)
{
    return HeartBeatFSMInterfaceInstance()->LnnRequestLeaveSpecific(networkId, addrType);
}

int32_t LnnHbMediumMgrSendBegin(LnnHeartbeatSendBeginData *custData)
{
    return HeartBeatFSMInterfaceInstance()->LnnHbMediumMgrSendBegin(custData);
}

int32_t LnnHbMediumMgrSendEnd(LnnHeartbeatSendEndData *type)
{
    return HeartBeatFSMInterfaceInstance()->LnnHbMediumMgrSendEnd(type);
}

int32_t LnnGetHbStrategyManager(
    LnnHeartbeatStrategyManager *mgr, LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType)
{
    return HeartBeatFSMInterfaceInstance()->LnnGetHbStrategyManager(mgr, hbType, strategyType);
}

int32_t LnnHbMediumMgrSetParam(void *param)
{
    return HeartBeatFSMInterfaceInstance()->LnnHbMediumMgrSetParam(param);
}

int32_t LnnHbMediumMgrUpdateSendInfo(LnnHeartbeatUpdateInfoType type)
{
    return HeartBeatFSMInterfaceInstance()->LnnHbMediumMgrUpdateSendInfo(type);
}

int32_t LnnStartScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType)
{
    return HeartBeatFSMInterfaceInstance()->LnnStartScreenChangeOfflineTiming(networkId, addrType);
}

int32_t LnnStopScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType)
{
    return HeartBeatFSMInterfaceInstance()->LnnStopScreenChangeOfflineTiming(networkId, addrType);
}

int32_t StopHeartBeatAdvByTypeNow(LnnHeartbeatType registedHbType)
{
    return HeartBeatFSMInterfaceInstance()->StopHeartBeatAdvByTypeNow(registedHbType);
}

SoftBusScreenState GetScreenState(void)
{
    return HeartBeatFSMInterfaceInstance()->GetScreenState();
}

void SetScreenState(SoftBusScreenState state)
{
    return HeartBeatFSMInterfaceInstance()->SetScreenState(state);
}

struct WifiDirectManager *GetWifiDirectManager(void)
{
    return HeartBeatFSMInterfaceInstance()->GetWifiDirectManager();
}
}
} // namespace OHOS