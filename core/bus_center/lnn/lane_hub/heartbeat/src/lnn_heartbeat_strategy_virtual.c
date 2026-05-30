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

#include "lnn_heartbeat_strategy.h"

#include "softbus_error_code.h"

int32_t LnnStartHbByTypeAndStrategy(LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType, bool isRelay)
{
    (void)hbType;
    (void)strategyType;
    (void)isRelay;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnStartHeartbeat(uint64_t delayMillis)
{
    (void)delayMillis;
    return SOFTBUS_OK;
}

int32_t LnnStartHbByTypeAndStrategyEx(LnnProcessSendOnceMsgPara *msgPara)
{
    (void)msgPara;
    return SOFTBUS_NOT_IMPLEMENT;
}

LnnHeartbeatStrategyType GetStrategyTypeByPolicy(int32_t policy)
{
    (void)policy;
    return STRATEGY_HB_SEND_SINGLE;
}

int32_t LnnEnableHeartbeatByType(LnnHeartbeatType type, bool isEnable)
{
    (void)type;
    (void)isEnable;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetGearModeBySpecificType(GearMode *mode, char *callerId, LnnHeartbeatType type)
{
    (void)mode;
    (void)callerId;
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetHbStrategyManager(LnnHeartbeatStrategyManager *mgr, LnnHeartbeatType hbType,
    LnnHeartbeatStrategyType strategyType)
{
    (void)mgr;
    (void)hbType;
    (void)strategyType;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetMediumParamBySpecificType(LnnHeartbeatMediumParam *param, LnnHeartbeatType type)
{
    (void)param;
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnHbStrategyDeinit(void) { }

int32_t LnnHbStrategyInit(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

bool LnnIsHeartbeatEnable(LnnHeartbeatType type)
{
    (void)type;
    return false;
}

int32_t LnnRegistParamMgrByType(LnnHeartbeatType type)
{
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnRemoveV0BroadcastAndCheckDev(void) { }

int32_t LnnSetGearModeBySpecificType(const char *callerId, const GearMode *mode, LnnHeartbeatType type)
{
    (void)callerId;
    (void)mode;
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetHbAsMasterNodeState(bool isMasterNode)
{
    (void)isMasterNode;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetMediumParamBySpecificType(const LnnHeartbeatMediumParam *param)
{
    (void)param;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnStartHbByTypeAndStrategyDirectly(LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType,
    bool isRelay, const char *networkId, uint64_t timeout)
{
    (void)hbType;
    (void)strategyType;
    (void)isRelay;
    (void)networkId;
    (void)timeout;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnStartNewHbStrategyFsm(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnStartOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType)
{
    (void)networkId;
    (void)addrType;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnStartScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType)
{
    (void)networkId;
    (void)addrType;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnStartSleOfflineTimingStrategy(const char *networkId)
{
    (void)networkId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnStopHeartBeatAdvByTypeNow(LnnHeartbeatType registedHbType)
{
    (void)registedHbType;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnStopHeartbeatByType(LnnHeartbeatType type)
{
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnStopOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType)
{
    (void)networkId;
    (void)addrType;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnStopScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType)
{
    (void)networkId;
    (void)addrType;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnStopSleOfflineTimingStrategy(const char *networkId)
{
    (void)networkId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnStopV0HeartbeatAndNotTransState()
{
    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnUnRegistParamMgrByType(LnnHeartbeatType type)
{
    (void)type;
}

int32_t LnnUpdateSendInfoStrategy(LnnHeartbeatUpdateInfoType type)
{
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

