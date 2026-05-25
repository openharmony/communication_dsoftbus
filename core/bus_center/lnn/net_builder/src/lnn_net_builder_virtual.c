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

#include "lnn_net_builder.h"

#include "lnn_log.h"
#include "lnn_p2p_info.h"
#include "softbus_error_code.h"

int32_t LnnInitNetBuilder(void)
{
    LNN_LOGI(LNN_INIT, "init virtual net builder");
    return SOFTBUS_OK;
}

int32_t LnnInitNetBuilderDelay(void)
{
    return SOFTBUS_OK;
}

void LnnDeinitNetBuilder(void) { }

int32_t LnnServerJoin(ConnectionAddr *addr, const char *pkgName, bool isForceJoin)
{
    (void)addr;
    (void)pkgName;
    (void)isForceJoin;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnServerLeave(const char *networkId, const char *pkgName)
{
    (void)networkId;
    (void)pkgName;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnNotifyDiscoveryDevice(
    const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport, bool isNeedConnec)
{
    (void)addr;
    (void)infoReport;
    (void)isNeedConnec;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen, bool hasMcuRequestDisable)
{
    (void)type;
    (void)typeLen;
    (void)hasMcuRequestDisable;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnInitLocalP2pInfo(NodeInfo *info)
{
    (void)info;
    return SOFTBUS_OK;
}

void ClearLnnBleReportExtraMap(void)
{
    return;
}

void ClearPcRestrictMap(void)
{
    return;
}

int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType, DeviceLeaveReason leaveReason)
{
    (void)networkId;
    (void)addrType;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnSetReSyncDeviceName(void)
{
    return SOFTBUS_OK;
}

void AddNodeToLnnBleReportExtraMap(const char *udidHash, const LnnBleReportExtra *bleExtra)
{
    (void)udidHash;
    (void)bleExtra;
}

void AddNodeToPcRestrictMap(const char *udidHash)
{
    (void)udidHash;
}

int32_t AuthFailNotifyProofInfo(int32_t errCode, const char *errorReturn, uint32_t errorReturnLen)
{
    (void)errCode;
    (void)errorReturn;
    (void)errorReturnLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t ConfigLocalLedger(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

void DeleteNodeFromLnnBleReportExtraMap(const char *udidHash)
{
    (void)udidHash;
}

void DeleteNodeFromPcRestrictMap(const char *udidHash)
{
    (void)udidHash;
}

bool DeletePcNodeInfo(const char *peerUdid)
{
    (void)peerUdid;
    return false;
}

void DfxRecordLnnAuthStart(const AuthConnInfo *connInfo, const JoinLnnMsgPara *para, uint32_t requestId)
{
    (void)connInfo;
    (void)para;
    (void)requestId;
}

void DfxRecordLnnServerjoinStart(const ConnectionAddr *addr, const char *packageName, bool needReportFailure)
{
    (void)addr;
    (void)packageName;
    (void)needReportFailure;
}

ConnectionAddrType GetCurrentConnectType(AuthLinkType linkType)
{
    (void)linkType;
    return CONNECTION_ADDR_MAX;
}

int32_t GetNodeFromLnnBleReportExtraMap(const char *udidHash, LnnBleReportExtra *bleExtra)
{
    (void)udidHash;
    (void)bleExtra;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t GetNodeFromPcRestrictMap(const char *udidHash, uint32_t *count)
{
    (void)udidHash;
    (void)count;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool GetWatchdogFlag(void)
{
    return false;
}

bool IsExistLnnDfxNodeByUdidHash(const char *udidHash, LnnBleReportExtra *bleExtra)
{
    (void)udidHash;
    (void)bleExtra;
    return false;
}

bool IsNeedWifiReauth(const char *networkId, const char *newAccountHash, int32_t len)
{
    (void)networkId;
    (void)newAccountHash;
    (void)len;
    return false;
}

bool IsNodeOnline(const char *networkId)
{
    (void)networkId;
    return false;
}

int32_t JoinLnnWithNodeInfo(ConnectionAddr *addr, NodeInfo *info, bool isSession)
{
    (void)addr;
    (void)info;
    (void)isSession;
    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnBlePcRestrictMapInit(void) { }

void LnnDeleteLinkFinderInfo(const char *peerUdid)
{
    (void)peerUdid;
}

NetBuilder* LnnGetNetBuilder(void)
{
    return NULL;
}

int32_t LnnNotifyAuthHandleLeaveLNN(AuthHandle authHandle)
{
    (void)authHandle;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnNotifyEmptySessionKey(int64_t authId)
{
    (void)authId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnNotifyLeaveLnnByAuthHandle(AuthHandle *authHandle)
{
    (void)authHandle;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnNotifyMasterElect(const char *networkId, const char *masterUdid, int32_t masterWeight)
{
    (void)networkId;
    (void)masterUdid;
    (void)masterWeight;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnNotifyNodeStateChanged(const ConnectionAddr *addr)
{
    (void)addr;
    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnProcessCompleteNotTrustedMsg(LnnSyncInfoType syncType, const char *networkId, const uint8_t *msg, uint32_t len)
{
    (void)syncType;
    (void)networkId;
    (void)msg;
    (void)len;
}

int32_t LnnRequestCleanConnFsm(uint16_t connFsmId)
{
    (void)connFsmId;
    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnRequestLeaveAllOnlineNodes(void) { }

int32_t LnnRequestLeaveInvalidConn(const char *oldNetworkId, ConnectionAddrType addrType, const char *newNetworkId)
{
    (void)oldNetworkId;
    (void)addrType;
    (void)newNetworkId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnServerJoinExt(ConnectionAddr *addr, LnnServerJoinExtCallBack *callback)
{
    (void)addr;
    (void)callback;
    return SOFTBUS_NOT_IMPLEMENT;
}

void LnnSyncOfflineComplete(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    (void)type;
    (void)networkId;
    (void)msg;
    (void)len;
}

int32_t LnnUpdateLocalUuidAndIrk(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnUpdateNodeAddr(const char *addr)
{
    (void)addr;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool NeedPendingJoinRequest(void)
{
    return false;
}

void NotifyForegroundUseridChange(char *networkId, uint32_t discoveryType, bool isChange)
{
    (void)networkId;
    (void)discoveryType;
    (void)isChange;
}

void OnLnnProcessNotTrustedMsgDelay(void *para)
{
    (void)para;
}

void OnReceiveMasterElectMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len)
{
    (void)type;
    (void)networkId;
    (void)msg;
    (void)len;
}

void OnReceiveNodeAddrChangedMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t size)
{
    (void)type;
    (void)networkId;
    (void)msg;
    (void)size;
}

int32_t PostBuildMessageToHandler(int32_t msgType, void *para)
{
    (void)msgType;
    (void)para;
    return SOFTBUS_NOT_IMPLEMENT;
}

void PostVerifyResult(uint32_t requestId, int32_t retCode, AuthHandle authHandle, const NodeInfo *info)
{
    (void)requestId;
    (void)retCode;
    (void)authHandle;
    (void)info;
}

void RemovePendingRequestByAddrType(const bool *addrType, uint32_t typeLen)
{
    (void)addrType;
    (void)typeLen;
}

void SendElectMessageToAll(const char *skipNetworkId)
{
    (void)skipNetworkId;
}

void SetWatchdogFlag(bool flag)
{
    (void)flag;
}

int32_t SyncElectMessage(const char *networkId)
{
    (void)networkId;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool TryPendingJoinRequest(const JoinLnnMsgPara *para, bool needReportFailure)
{
    (void)para;
    (void)needReportFailure;
    return false;
}

void TryRemovePendingJoinRequest(void) { }

int32_t TrySendJoinLNNRequest(const JoinLnnMsgPara *para, bool needReportFailure, bool isShort)
{
    (void)para;
    (void)needReportFailure;
    (void)isShort;
    return SOFTBUS_NOT_IMPLEMENT;
}

void UpdateLocalMasterNode(bool isCurrentNode, const char *masterUdid, int32_t weight)
{
    (void)isCurrentNode;
    (void)masterUdid;
    (void)weight;
}

void UpdateLocalNetCapability(void) { }

int32_t UpdateNodeFromPcRestrictMap(const char *udidHash)
{
    (void)udidHash;
    return SOFTBUS_NOT_IMPLEMENT;
}

