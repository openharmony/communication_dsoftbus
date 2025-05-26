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


#ifndef LNN_CONNECTION_FSM_H
#define LNN_CONNECTION_FSM_H

#include <stdint.h>

#include "auth_interface.h"
#include "common_list.h"
#include "lnn_node_info.h"
#include "lnn_state_machine.h"
#include "softbus_bus_center.h"
#include "legacy/softbus_hisysevt_bus_center.h"
#include "lnn_net_builder.h"
#include "lnn_connection_fsm_struct.h"
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

LnnConnectionFsm *LnnCreateConnectionFsm(const ConnectionAddr *target, const char *pkgName, bool isNeedConnect);
void LnnDestroyConnectionFsm(LnnConnectionFsm *connFsm);

int32_t LnnStartConnectionFsm(LnnConnectionFsm *connFsm);
int32_t LnnStopConnectionFsm(LnnConnectionFsm *connFsm, LnnConnectionFsmStopCallback callback);
bool LnnIsNeedCleanConnectionFsm(const NodeInfo *nodeInfo, ConnectionAddrType type);

int32_t LnnSendJoinRequestToConnFsm(LnnConnectionFsm *connFsm, bool isForceJoin);
int32_t LnnSendAuthResultMsgToConnFsm(LnnConnectionFsm *connFsm, int32_t retCode);
int32_t LnnSendNotTrustedToConnFsm(LnnConnectionFsm *connFsm);
int32_t LnnSendDisconnectMsgToConnFsm(LnnConnectionFsm *connFsm);
int32_t LnnSendLeaveRequestToConnFsm(LnnConnectionFsm *connFsm);
int32_t LnnSendSyncOfflineFinishToConnFsm(LnnConnectionFsm *connFsm);
int32_t LnnSendNewNetworkOnlineToConnFsm(LnnConnectionFsm *connFsm);
bool CheckRemoteBasicInfoChanged(const NodeInfo *newNodeInfo);

int32_t ProcessBleOnline(NodeInfo *nodeInfo, const ConnectionAddr *oldAddr, AuthCapability authCapability);
void SetLnnTriggerInfo(uint64_t triggerTime, int32_t deviceCnt, int32_t triggerReason);
void GetLnnTriggerInfo(LnnTriggerInfo *triggerInfo);
void DfxRecordTriggerTime(LnnTriggerReason reason, LnnEventLnnStage stage);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* LNN_CONNECTION_FSM_H */