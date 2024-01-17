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

#include "hb_strategy_mock.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_hbStrategyInterface;
HeartBeatStategyInterfaceMock::HeartBeatStategyInterfaceMock()
{
    g_hbStrategyInterface = reinterpret_cast<void *>(this);
}

HeartBeatStategyInterfaceMock::~HeartBeatStategyInterfaceMock()
{
    g_hbStrategyInterface = nullptr;
}

static HeartBeatStategyInterface *HeartBeatStrategyInterface()
{
    return reinterpret_cast<HeartBeatStategyInterfaceMock *>(g_hbStrategyInterface);
}

extern "C" {
int32_t LnnStartOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType)
{
    return HeartBeatStrategyInterface()->LnnStartOfflineTimingStrategy(networkId, addrType);
}

int32_t LnnStopOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType)
{
    return HeartBeatStrategyInterface()->LnnStopOfflineTimingStrategy(networkId, addrType);
}

int32_t LnnNotifyDiscoveryDevice(const ConnectionAddr *addr, bool isNeedConnect)
{
    return HeartBeatStrategyInterface()->LnnNotifyDiscoveryDevice(addr, isNeedConnect);
}

int32_t LnnNotifyMasterElect(const char *networkId, const char *masterUdid, int32_t masterWeight)
{
    return HeartBeatStrategyInterface()->LnnNotifyMasterElect(networkId, masterUdid, masterWeight);
}

int32_t LnnSetHbAsMasterNodeState(bool isMasterNode)
{
    return HeartBeatStrategyInterface()->LnnSetHbAsMasterNodeState(isMasterNode);
}

int32_t LnnStartHbByTypeAndStrategy(LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType, bool isRelay)
{
    return HeartBeatStrategyInterface()->LnnStartHbByTypeAndStrategy(hbType, strategyType, isRelay);
}

int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType)
{
    return HeartBeatStrategyInterface()->LnnRequestLeaveSpecific(networkId, addrType);
}

int32_t AuthStartVerify(const AuthConnInfo *connInfo, uint32_t requestId,
    const AuthVerifyCallback *callback, bool isFastAuth)
{
    return HeartBeatStrategyInterface()->AuthStartVerify(connInfo, requestId, callback, isFastAuth);
}

AuthVerifyCallback *LnnGetReAuthVerifyCallback(void)
{
    return HeartBeatStrategyInterface()->LnnGetReAuthVerifyCallback();
}

uint32_t AuthGenRequestId(void)
{
    return HeartBeatStrategyInterface()->AuthGenRequestId();
}

int32_t LnnSetGearModeBySpecificType(const char *callerId, const GearMode *mode, LnnHeartbeatType type)
{
    return HeartBeatStrategyInterface()->LnnSetGearModeBySpecificType(callerId, mode, type);
}

int32_t LnnEnableHeartbeatByType(LnnHeartbeatType type, bool isEnable)
{
    return HeartBeatStrategyInterface()->LnnEnableHeartbeatByType(type, isEnable);
}

int32_t LnnStopHeartbeatByType(LnnHeartbeatType type)
{
    return HeartBeatStrategyInterface()->LnnStopHeartbeatByType(type);
}

int32_t LnnHbStrategyInit(void)
{
    return HeartBeatStrategyInterface()->LnnHbStrategyInit();
}

int32_t LnnUpdateSendInfoStrategy(LnnHeartbeatUpdateInfoType type)
{
    return HeartBeatStrategyInterface()->LnnUpdateSendInfoStrategy(type);
}

int32_t LnnStopScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType)
{
    return HeartBeatStrategyInterface()->LnnStopScreenChangeOfflineTiming(networkId, addrType);
}

int32_t LnnSetMediumParamBySpecificType(const LnnHeartbeatMediumParam *param)
{
    return HeartBeatStrategyInterface()->LnnSetMediumParamBySpecificType(param);
}

int32_t LnnStartScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType)
{
    return HeartBeatStrategyInterface()->LnnStartScreenChangeOfflineTiming(networkId, addrType);
}

int32_t LnnStopHeartBeatAdvByTypeNow(LnnHeartbeatType registedHbType)
{
    return HeartBeatStrategyInterface()->LnnStopHeartBeatAdvByTypeNow(registedHbType);
}
}
} // namespace OHOS
