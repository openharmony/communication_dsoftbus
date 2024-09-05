/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef LNN_HEARTBEAT_CTRL_H
#define LNN_HEARTBEAT_CTRL_H

#include "bus_center_event.h"
#include "lnn_heartbeat_medium_mgr.h"
#include "softbus_bus_center.h"

#ifdef __cplusplus
extern "C" {
#endif

SoftBusScreenState GetScreenState(void);
void SetScreenState(SoftBusScreenState state);
int32_t LnnStartHeartbeatFrameDelay(void);
int32_t LnnSetHeartbeatMediumParam(const LnnHeartbeatMediumParam *param);
int32_t LnnOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType);
void LnnStopOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType);
int32_t LnnShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId, const GearMode *mode);
int32_t LnnShiftLNNGearWithoutPkgName(
    const char *callerId, const GearMode *mode, LnnHeartbeatStrategyType strategyType);
void LnnUpdateHeartbeatInfo(LnnHeartbeatUpdateInfoType type);
void LnnRequestBleDiscoveryProcess(int32_t strategy, int64_t timeout);

void LnnHbOnTrustedRelationIncreased(int32_t groupType);
void LnnHbOnTrustedRelationReduced(void);
int32_t LnnTriggerDirectHeartbeat(const char *networkId, uint64_t timeout);

int32_t LnnInitHeartbeat(void);
void LnnDeinitHeartbeat(void);

int32_t LnnTriggerDataLevelHeartbeat(void);
int32_t LnnTriggerCloudSyncHeartbeat(void);
void LnnRegDataLevelChangeCb(const IDataLevelChangeCallback *callback);
void LnnUnregDataLevelChangeCb(void);
bool IsHeartbeatEnable(void);
bool LnnIsCloudSyncEnd(void);

#ifdef __cplusplus
}
#endif
#endif /* LNN_HEARTBEAT_CTRL_H */
