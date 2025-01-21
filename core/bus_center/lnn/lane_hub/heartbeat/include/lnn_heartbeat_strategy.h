/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef LNN_HEARTBEAT_STRATEGY_H
#define LNN_HEARTBEAT_STRATEGY_H

#include "lnn_heartbeat_fsm.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    LnnHeartbeatType supportType;
    int32_t (*onProcess)(LnnHeartbeatFsm *hbFsm, void *obj);
} LnnHeartbeatStrategyManager;

int32_t LnnSetGearModeBySpecificType(const char *callerId, const GearMode *mode, LnnHeartbeatType type);
int32_t LnnGetGearModeBySpecificType(GearMode *mode, char *callerId, LnnHeartbeatType type);
int32_t LnnSetMediumParamBySpecificType(const LnnHeartbeatMediumParam *param);
int32_t LnnGetMediumParamBySpecificType(LnnHeartbeatMediumParam *param, LnnHeartbeatType type);

int32_t LnnSetHbAsMasterNodeState(bool isMasterNode);
int32_t LnnGetHbStrategyManager(
    LnnHeartbeatStrategyManager *mgr, LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType);

int32_t LnnStartNewHbStrategyFsm(void);
int32_t LnnStartHbByTypeAndStrategy(LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType, bool isRelay);
int32_t LnnStartHbByTypeAndStrategyEx(LnnProcessSendOnceMsgPara *msgPara);
int32_t LnnStartHbByTypeAndStrategyDirectly(LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType,
    bool isRelay, const char *networkId, uint64_t timeout);
int32_t LnnStartHeartbeat(uint64_t delayMillis);
int32_t LnnStopHeartbeatByType(LnnHeartbeatType type);
int32_t LnnStopV0HeartbeatAndNotTransState();
int32_t LnnStartOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType);
int32_t LnnStopOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType);
int32_t LnnStartScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType);
int32_t LnnStopScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType);
int32_t LnnStopHeartBeatAdvByTypeNow(LnnHeartbeatType registedHbType);
int32_t LnnUpdateSendInfoStrategy(LnnHeartbeatUpdateInfoType type);
LnnHeartbeatStrategyType GetStrategyTypeByPolicy(int32_t policy);

bool LnnIsHeartbeatEnable(LnnHeartbeatType type);
int32_t LnnEnableHeartbeatByType(LnnHeartbeatType type, bool isEnable);

int32_t LnnRegistParamMgrByType(LnnHeartbeatType type);
void LnnUnRegistParamMgrByType(LnnHeartbeatType type);

int32_t LnnHbStrategyInit(void);
void LnnHbStrategyDeinit(void);
void LnnRemoveV0BroadcastAndCheckDev(void);

#ifdef __cplusplus
}
#endif
#endif /* LNN_HEARTBEAT_STRATEGY_H */
