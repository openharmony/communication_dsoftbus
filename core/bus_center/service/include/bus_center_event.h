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

#ifndef BUS_CENTER_EVENT_H
#define BUS_CENTER_EVENT_H

#include "softbus_bus_center.h"
#include "bus_center_info_key.h"
#include "bus_center_event_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t LnnInitBusCenterEvent(void);
void LnnDeinitBusCenterEvent(void);

int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler);
void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler);

void LnnNotifyJoinResult(ConnectionAddr *addr,
    const char *networkId, int32_t retCode);
void LnnNotifyLeaveResult(const char *networkId, int32_t retCode);

void LnnNotifyOnlineState(bool isOnline, NodeBasicInfo *info);
void LnnNotifyBasicInfoChanged(NodeBasicInfo *info, NodeBasicInfoType type);
void LnnNotifyNodeStatusChanged(NodeStatus *info, NodeStatusType type);
void LnnNotifyLocalNetworkIdChanged(void);
void LnnNotifyDeviceTrustedChange(int32_t type, const char *msg, uint32_t msgLen);
void LnnNotifyHichainProofException(
    const char *proofInfo, uint32_t proofLen, uint16_t deviceTypeId, int32_t errCode);
void LnnNotifyMigrate(bool isOnline, NodeBasicInfo *info);

void LnnNotifyWlanStateChangeEvent(void *state);
void LnnNotifyScreenStateChangeEvent(SoftBusScreenState state);
void LnnNotifyDifferentAccountChangeEvent(void *state);
void LnnNotifyBtStateChangeEvent(void *state);
void LnnNotifySleStateChangeEvent(void *state);
void LnnNotifyScreenLockStateChangeEvent(SoftBusScreenLockState state);
void LnnNotifyAccountStateChangeEvent(SoftBusAccountState state);
void LnnNotifyUserStateChangeEvent(SoftBusUserState state);
void LnnNotifyHomeGroupChangeEvent(SoftBusHomeGroupState state);
void LnnNotifyNightModeStateChangeEvent(void *state);
void LnnNotifyOOBEStateChangeEvent(SoftBusOOBEState state);
void LnnNotifyBtAclStateChangeEvent(const char *btMac, SoftBusBtAclState state);
void LnnNotifyAddressChangedEvent(const char* ifName);
void LnnNotifyLnnRelationChanged(const char *udid, ConnectionAddrType type, uint8_t relation, bool isJoin);
void LnnNotifyDeviceVerified(const char *udid);
void LnnNotifySysTimeChangeEvent(void);

void LnnNotifyTimeSyncResult(const char *pkgName, int32_t pid, const TimeSyncResultInfo *info, int32_t retCode);

void LnnNotifyMasterNodeChanged(bool isMaster, const char* masterNodeUdid, int32_t weight);

void LnnNotifyNodeAddressChanged(const char *addr, const char *networkId, bool isLocal);

void LnnNotifyNetworkStateChanged(SoftBusNetworkState state);

void LnnNotifySingleOffLineEvent(const ConnectionAddr *addr, NodeBasicInfo *basicInfo);

void LnnNotifyNetworkIdChangeEvent(const char *networkId);

void LnnNotifyLpReportEvent(SoftBusLpEventType type);

void LnnNotifyHBRepeat(void);

void LnnNotifyUserSwitchEvent(SoftBusUserSwitchState state);

void LnnNotifyDataShareStateChangeEvent(SoftBusDataShareState state);

void LnnNotifyVapInfoChangeEvent(int32_t preferChannel);

void LnnNotifyStateForSession(char *udid, int32_t retCode);

void LnnNotifyOnlineNetType(const char *networkId, ConnectionAddrType addrType);

void LnnNotifyDeviceInfoChanged(SoftBusDeviceInfoState state);

void LnnNotifyNetlinkStateChangeEvent(NetManagerIfNameState state, const char *ifName);

void LnnNotifyWifiServiceStart(void *para);

void LnnNotifyAddRawEnhanceP2pEvent(LnnNotifyRawEnhanceP2pEvent *event);

void LnnNotifyDeviceRiskStateChangeEvent(void);

void LnnNotifyHaLeaveMetaNodeEvent(const char *metaNodeId);

void LnnNotifyLpMcuInit(SoftBusHbApState state, int32_t strategy);

void LnnNotifyLpMcuUpdateHbInfo(int32_t type);

#ifdef __cplusplus
}
#endif
#endif
