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

#ifndef LNN_NET_BUILDER_H
#define LNN_NET_BUILDER_H

#include "auth_interface.h"
#include "lnn_connId_callback_manager.h"
#include "lnn_event.h"
#include "lnn_net_builder_struct.h"
#include "lnn_sync_info_manager.h"
#include "message_handler.h"
#include "softbus_bus_center.h"

#define SPARK_GROUP_DELAY_TIME_MS 10000

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool addrType[CONNECTION_ADDR_MAX];
    bool needCheckHml;
} LeaveMsgByAddrType;

int32_t LnnInitNetBuilder(void);
int32_t LnnInitNetBuilderDelay(void);
void LnnDeinitNetBuilder(void);

int32_t LnnSetReSyncDeviceName(void);
int32_t LnnNotifyDiscoveryDevice(
    const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport, bool isNeedConnect);
void LnnSyncOfflineComplete(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len);
int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen, bool hasMcuRequestDisable);
int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType, DeviceLeaveReason leaveReason);
void LnnRequestLeaveAllOnlineNodes(void);
int32_t LnnRequestLeaveInvalidConn(const char *oldNetworkId, ConnectionAddrType addrType, const char *newNetworkId);
int32_t LnnRequestCleanConnFsm(uint16_t connFsmId);
int32_t LnnNotifyNodeStateChanged(const ConnectionAddr *addr);
int32_t LnnNotifyMasterElect(const char *networkId, const char *masterUdid, int32_t masterWeight);
int32_t LnnNotifyAuthHandleLeaveLNN(AuthHandle authHandle);
int32_t LnnNotifyEmptySessionKey(int64_t authId);
int32_t LnnNotifyLeaveLnnByAuthHandle(AuthHandle *authHandle);
int32_t LnnUpdateNodeAddr(const char *addr);
NodeInfo *FindNodeInfoByRquestId(uint32_t requestId);
AuthVerifyCallback *LnnGetVerifyCallback(void);
AuthVerifyCallback *LnnGetReAuthVerifyCallback(void);
void SetWatchdogFlag(bool flag);
bool GetWatchdogFlag(void);
NetBuilder* LnnGetNetBuilder(void);
void AddNodeToLnnBleReportExtraMap(const char *udidHash, const LnnBleReportExtra *bleExtra);
int32_t GetNodeFromLnnBleReportExtraMap(const char *udidHash, LnnBleReportExtra *bleExtra);
bool IsExistLnnDfxNodeByUdidHash(const char *udidHash, LnnBleReportExtra *bleExtra);
void DeleteNodeFromLnnBleReportExtraMap(const char *udidHash);
void ClearLnnBleReportExtraMap(void);
void DfxRecordLnnServerjoinStart(const ConnectionAddr *addr, const char *packageName, bool needReportFailure);
bool TryPendingJoinRequest(const JoinLnnMsgPara *para, bool needReportFailure);
bool IsNeedWifiReauth(const char *networkId, const char *newAccountHash, int32_t len);
void DfxRecordLnnAuthStart(const AuthConnInfo *connInfo, const JoinLnnMsgPara *para, uint32_t requestId);
void TryRemovePendingJoinRequest(void);
void UpdateLocalMasterNode(bool isCurrentNode, const char *masterUdid, int32_t weight);
void SendElectMessageToAll(const char *skipNetworkId);
bool IsNodeOnline(const char *networkId);
void RemovePendingRequestByAddrType(const bool *addrType, uint32_t typeLen);
void UpdateLocalNetCapability(void);
void OnReceiveMasterElectMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len);
void OnReceiveNodeAddrChangedMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t size);
int32_t ConfigLocalLedger(void);
int32_t SyncElectMessage(const char *networkId);
ConnectionAddrType GetCurrentConnectType(AuthLinkType linkType);
NodeInfo *DupNodeInfo(const NodeInfo *nodeInfo);
bool NeedPendingJoinRequest(void);
void PostVerifyResult(uint32_t requestId, int32_t retCode, AuthHandle authHandle, const NodeInfo *info);
int32_t TrySendJoinLNNRequest(const JoinLnnMsgPara *para, bool needReportFailure, bool isShort);
int32_t PostBuildMessageToHandler(int32_t msgType, void *para);
bool DeletePcNodeInfo(const char *peerUdid);
const char *SelectUseUdid(const char *peerUdid, const char *lowerUdid);
void LnnDeleteLinkFinderInfo(const char *peerUdid);
void LnnProcessCompleteNotTrustedMsg(LnnSyncInfoType syncType, const char *networkId,
    const uint8_t *msg, uint32_t len);
void OnLnnProcessNotTrustedMsgDelay(void *para);
void LnnBlePcRestrictMapInit(void);
void AddNodeToPcRestrictMap(const char *udidHash);
void ClearPcRestrictMap(void);
void DeleteNodeFromPcRestrictMap(const char *udidHash);
int32_t GetNodeFromPcRestrictMap(const char *udidHash, uint32_t *count);
int32_t UpdateNodeFromPcRestrictMap(const char *udidHash);
int32_t JoinLnnWithNodeInfo(ConnectionAddr *addr, NodeInfo *info, bool isSession);
int32_t LnnServerJoinExt(ConnectionAddr *addr, LnnServerJoinExtCallBack *callback);
int32_t AuthFailNotifyProofInfo(int32_t errCode, const char *errorReturn, uint32_t errorReturnLen);
void NotifyForegroundUseridChange(char *networkId, uint32_t discoveryType, bool isChange);
int32_t LnnUpdateLocalUuidAndIrk(void);
#ifdef __cplusplus
}
#endif

#endif