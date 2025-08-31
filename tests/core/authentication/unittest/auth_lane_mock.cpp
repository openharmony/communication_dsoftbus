/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "auth_lane_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_authLaneInterface;
AuthLaneInterfaceMock::AuthLaneInterfaceMock()
{
    g_authLaneInterface = reinterpret_cast<void *>(this);
}

AuthLaneInterfaceMock::~AuthLaneInterfaceMock()
{
    g_authLaneInterface = nullptr;
}

static AuthLaneInterface *GetAuthLaneMockInterface()
{
    return reinterpret_cast<AuthLaneInterfaceMock *>(g_authLaneInterface);
}

extern "C" {
int32_t LnnGetRemoteStrInfo(const char *networkId, InfoKey key, char *info, uint32_t len)
{
    return GetAuthLaneMockInterface()->LnnGetRemoteStrInfo(networkId, key, info, len);
}

int32_t LnnDeleteMetaInfo(const char *udid, AuthLinkType type)
{
    return GetAuthLaneMockInterface()->LnnDeleteMetaInfo(udid, type);
}

int32_t TransGetConnByChanId(int32_t channelId, int32_t channelType, int32_t *connId)
{
    return GetAuthLaneMockInterface()->TransGetConnByChanId(channelId, channelType, connId);
}

int32_t AuthMetaStartVerify(uint32_t connectionId, const AuthKeyInfo *authKeyInfo, uint32_t requestId,
    int32_t callingPid, const AuthVerifyCallback *callBack)
{
    return GetAuthLaneMockInterface()->AuthMetaStartVerify(connectionId, authKeyInfo, requestId, callingPid, callBack);
}

void LnnSetUnlockState(void)
{
    return GetAuthLaneMockInterface()->LnnSetUnlockState();
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    return GetAuthLaneMockInterface()->LnnSetLocalStrInfo(key, info);
}

int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info)
{
    return GetAuthLaneMockInterface()->LnnSetLocalNumInfo(key, info);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetAuthLaneMockInterface()->LnnGetLocalStrInfo(key, info, len);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return GetAuthLaneMockInterface()->LnnGetLocalNumInfo(key, info);
}

int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info)
{
    return GetAuthLaneMockInterface()->LnnGetLocalNumU32Info(key, info);
}

int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len)
{
    return GetAuthLaneMockInterface()->LnnGetNetworkIdByUdid(udid, buf, len);
}

int32_t LnnGetRemoteNumInfo(const char *netWorkId, InfoKey key, int32_t *info)
{
    return GetAuthLaneMockInterface()->LnnGetRemoteNumInfo(netWorkId, key, info);
}

int32_t LnnGetRemoteNumU32Info(const char *netWorkId, InfoKey key, uint32_t *info)
{
    return GetAuthLaneMockInterface()->LnnGetRemoteNumU32Info(netWorkId, key, info);
}

bool LnnIsSameConnectionAddr(const ConnectionAddr *addr1, const ConnectionAddr *addr2, bool isShort)
{
    return GetAuthLaneMockInterface()->LnnIsSameConnectionAddr(addr1, addr2, isShort);
}

bool LnnConvertAddrToOption(const ConnectionAddr *addr, ConnectOption *option)
{
    return GetAuthLaneMockInterface()->LnnConvertAddrToOption(addr, option);
}

DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type)
{
    return GetAuthLaneMockInterface()->LnnConvAddrTypeToDiscType(type);
}

ConnectionAddrType LnnDiscTypeToConnAddrType(DiscoveryType type)
{
    return GetAuthLaneMockInterface()->LnnDiscTypeToConnAddrType(type);
}

bool LnnConvertAuthConnInfoToAddr(ConnectionAddr *addr, const AuthConnInfo *connInfo, ConnectionAddrType hintType)
{
    return GetAuthLaneMockInterface()->LnnConvertAuthConnInfoToAddr(addr, connInfo, hintType);
}

bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value)
{
    return GetAuthLaneMockInterface()->AddStringToJsonObject(json, string, value);
}

bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num)
{
    return GetAuthLaneMockInterface()->AddNumberToJsonObject(json, string, num);
}

int32_t LnnSendSyncInfoMsg(
    LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len, LnnSyncInfoMsgComplete complete)
{
    return GetAuthLaneMockInterface()->LnnSendSyncInfoMsg(type, networkId, msg, len, complete);
}

NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type)
{
    return GetAuthLaneMockInterface()->LnnGetNodeInfoById(id, type);
}

int32_t LnnUpdateNodeInfo(NodeInfo *newInfo, int32_t connectionType)
{
    return GetAuthLaneMockInterface()->LnnUpdateNodeInfo(newInfo, connectionType);
}

int32_t LnnAddMetaInfo(NodeInfo *info)
{
    return GetAuthLaneMockInterface()->LnnAddMetaInfo(info);
}

int32_t LnnConvertDlId(
    const char *srcId, IdCategory srcIdType, IdCategory dstIdType, char *dstIdBuf, uint32_t dstIdBufLen)
{
    return GetAuthLaneMockInterface()->LnnConvertDlId(srcId, srcIdType, dstIdType, dstIdBuf, dstIdBufLen);
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    return GetAuthLaneMockInterface()->LnnGetOnlineStateById(id, type);
}

bool LnnIsNodeOnline(const NodeInfo *info)
{
    return GetAuthLaneMockInterface()->LnnIsNodeOnline(info);
}

int32_t LnnSetSupportDiscoveryType(char *info, const char *type)
{
    return GetAuthLaneMockInterface()->LnnSetSupportDiscoveryType(info, type);
}

bool LnnHasSupportDiscoveryType(const char *destType, const char *type)
{
    return GetAuthLaneMockInterface()->LnnHasSupportDiscoveryType(destType, type);
}

bool LnnPeerHasExchangeDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetAuthLaneMockInterface()->LnnPeerHasExchangeDiscoveryType(info, type);
}

const char *LnnGetDeviceUdid(const NodeInfo *info)
{
    return GetAuthLaneMockInterface()->LnnGetDeviceUdid(info);
}

int32_t LnnCompareNodeWeight(int32_t weight1, const char *masterUdid1, int32_t weight2, const char *masterUdid2)
{
    return GetAuthLaneMockInterface()->LnnCompareNodeWeight(weight1, masterUdid1, weight2, masterUdid2);
}

void LnnNotifyAllTypeOffline(ConnectionAddrType type)
{
    return GetAuthLaneMockInterface()->LnnNotifyAllTypeOffline(type);
}

void LnnNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    return GetAuthLaneMockInterface()->LnnNotifyLeaveResult(networkId, retCode);
}

int32_t LnnGetAddrTypeByIfName(const char *ifName, ConnectionAddrType *type)
{
    return GetAuthLaneMockInterface()->LnnGetAddrTypeByIfName(ifName, type);
}

int32_t LnnSendNotTrustedInfo(const NotTrustedDelayInfo *info, uint32_t num, LnnSyncInfoMsgComplete complete)
{
    return GetAuthLaneMockInterface()->LnnSendNotTrustedInfo(info, num, complete);
}

int32_t ConnDisconnectDeviceAllConn(const ConnectOption *option)
{
    return GetAuthLaneMockInterface()->ConnDisconnectDeviceAllConn(option);
}

int32_t LnnGenLocalUuid(char *uuid, uint32_t len, bool isUpdate)
{
    return GetAuthLaneMockInterface()->LnnGenLocalUuid(uuid, len, isUpdate);
}

int32_t LnnGenLocalIrk(unsigned char *irk, uint32_t len, bool isUpdate)
{
    return GetAuthLaneMockInterface()->LnnGenLocalIrk(irk, len, isUpdate);
}

int32_t LnnGenLocalNetworkId(char *networkId, uint32_t len)
{
    return GetAuthLaneMockInterface()->LnnGenLocalNetworkId(networkId, len);
}

int32_t LnnSetDLNodeAddr(const char *id, IdCategory type, const char *addr)
{
    return GetAuthLaneMockInterface()->LnnSetDLNodeAddr(id, type, addr);
}

int32_t LnnSetDLProxyPort(const char *id, IdCategory type, int32_t proxyPort)
{
    return GetAuthLaneMockInterface()->LnnSetDLProxyPort(id, type, proxyPort);
}

int32_t LnnSetDLSessionPort(const char *id, IdCategory type, int32_t sessionPort)
{
    return GetAuthLaneMockInterface()->LnnSetDLSessionPort(id, type, sessionPort);
}

int32_t LnnSetDLAuthPort(const char *id, IdCategory type, int32_t authPort)
{
    return GetAuthLaneMockInterface()->LnnSetDLAuthPort(id, type, authPort);
}

int32_t LnnInitP2p(void)
{
    return GetAuthLaneMockInterface()->LnnInitP2p();
}

int32_t LnnInitWifiDirect(void)
{
    return GetAuthLaneMockInterface()->LnnInitWifiDirect();
}

void LnnDeinitP2p(void)
{
    return GetAuthLaneMockInterface()->LnnDeinitP2p();
}

void LnnDeinitWifiDirect(void)
{
    return GetAuthLaneMockInterface()->LnnDeinitWifiDirect();
}

int32_t LnnInitNetworkInfo(void)
{
    return GetAuthLaneMockInterface()->LnnInitNetworkInfo();
}

int32_t LnnInitDevicename(void)
{
    return GetAuthLaneMockInterface()->LnnInitDevicename();
}

int32_t LnnInitSyncInfoManager(void)
{
    return GetAuthLaneMockInterface()->LnnInitSyncInfoManager();
}

void LnnDeinitSyncInfoManager(void)
{
    return GetAuthLaneMockInterface()->LnnDeinitSyncInfoManager();
}

int32_t LnnInitTopoManager(void)
{
    return GetAuthLaneMockInterface()->LnnInitTopoManager();
}

void LnnDeinitTopoManager(void)
{
    return GetAuthLaneMockInterface()->LnnDeinitTopoManager();
}

int32_t LnnRegSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler)
{
    return GetAuthLaneMockInterface()->LnnRegSyncInfoHandler(type, handler);
}

int32_t LnnUnregSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler)
{
    return GetAuthLaneMockInterface()->LnnUnregSyncInfoHandler(type, handler);
}

int32_t LnnStopConnectionFsm(LnnConnectionFsm *connFsm, LnnConnectionFsmStopCallback callback)
{
    return GetAuthLaneMockInterface()->LnnStopConnectionFsm(connFsm, callback);
}

void LnnDeinitFastOffline(void)
{
    return GetAuthLaneMockInterface()->LnnDeinitFastOffline();
}

int32_t LnnSendNewNetworkOnlineToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetAuthLaneMockInterface()->LnnSendNewNetworkOnlineToConnFsm(connFsm);
}

int32_t LnnSendAuthResultMsgToConnFsm(LnnConnectionFsm *connFsm, int32_t retCode)
{
    return GetAuthLaneMockInterface()->LnnSendAuthResultMsgToConnFsm(connFsm, retCode);
}

int32_t LnnSendDisconnectMsgToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetAuthLaneMockInterface()->LnnSendDisconnectMsgToConnFsm(connFsm);
}

int32_t LnnSendNotTrustedToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetAuthLaneMockInterface()->LnnSendNotTrustedToConnFsm(connFsm);
}

int32_t LnnSendLeaveRequestToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetAuthLaneMockInterface()->LnnSendLeaveRequestToConnFsm(connFsm);
}

int32_t LnnSendSyncOfflineFinishToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetAuthLaneMockInterface()->LnnSendSyncOfflineFinishToConnFsm(connFsm);
}

int32_t LnnGetLocalWeight(void)
{
    return GetAuthLaneMockInterface()->LnnGetLocalWeight();
}

void AuthMetaReleaseVerify(int64_t authId)
{
    return GetAuthLaneMockInterface()->AuthMetaReleaseVerify(authId);
}

int32_t LnnSendJoinRequestToConnFsm(LnnConnectionFsm *connFsm, bool isForceJoin)
{
    return GetAuthLaneMockInterface()->LnnSendJoinRequestToConnFsm(connFsm, isForceJoin);
}

void LnnNotifyJoinResult(ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    return GetAuthLaneMockInterface()->LnnNotifyJoinResult(addr, networkId, retCode);
}

void LnnDestroyConnectionFsm(LnnConnectionFsm *connFsm)
{
    return GetAuthLaneMockInterface()->LnnDestroyConnectionFsm(connFsm);
}

LnnConnectionFsm *LnnCreateConnectionFsm(const ConnectionAddr *target, const char *pkgName, bool isNeedConnect)
{
    return GetAuthLaneMockInterface()->LnnCreateConnectionFsm(target, pkgName, false);
}

int32_t LnnStartConnectionFsm(LnnConnectionFsm *connFsm)
{
    return GetAuthLaneMockInterface()->LnnStartConnectionFsm(connFsm);
}

void LnnNotifyMasterNodeChanged(bool isMaster, const char *masterNodeUdid, int32_t weight)
{
    return GetAuthLaneMockInterface()->LnnNotifyMasterNodeChanged(isMaster, masterNodeUdid, weight);
}

int32_t LnnInitFastOffline(void)
{
    return GetAuthLaneMockInterface()->LnnInitFastOffline();
}

int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetAuthLaneMockInterface()->LnnGetAllOnlineNodeInfo(info, infoNum);
}

bool LnnIsLSANode(const NodeBasicInfo *info)
{
    return GetAuthLaneMockInterface()->LnnIsLSANode(info);
}

void LnnNotifyNodeAddressChanged(const char *addr, const char *networkId, bool isLocal)
{
    return GetAuthLaneMockInterface()->LnnNotifyNodeAddressChanged(addr, networkId, isLocal);
}

int32_t LnnInitOffline(void)
{
    return GetAuthLaneMockInterface()->LnnInitOffline();
}

void LnnDeinitOffline(void)
{
    return GetAuthLaneMockInterface()->LnnDeinitOffline();
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetAuthLaneMockInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}

bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetAuthLaneMockInterface()->LnnHasDiscoveryType(info, type);
}

const char *LnnConvertDLidToUdid(const char *id, IdCategory type)
{
    return GetAuthLaneMockInterface()->LnnConvertDLidToUdid(id, type);
}

int32_t GetAuthRequest(uint32_t requestId, AuthRequest *request)
{
    return GetAuthLaneMockInterface()->GetAuthRequest(requestId, request);
}

int32_t SoftBusGetBtState(void)
{
    return GetAuthLaneMockInterface()->SoftBusGetBtState();
}

int32_t SoftBusGetBrState(void)
{
    return GetAuthLaneMockInterface()->SoftBusGetBrState();
}

int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type)
{
    return GetAuthLaneMockInterface()->LnnSetNetCapability(capability, type);
}

int32_t LnnClearNetCapability(uint32_t *capability, NetCapability type)
{
    return GetAuthLaneMockInterface()->LnnClearNetCapability(capability, type);
}

int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetAuthLaneMockInterface()->LnnRegisterEventHandler(event, handler);
}

void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetAuthLaneMockInterface()->LnnUnregisterEventHandler(event, handler);
}

void LnnNotifyDeviceVerified(const char *udid)
{
    return GetAuthLaneMockInterface()->LnnNotifyDeviceVerified(udid);
}

int32_t LnnInitBusCenterEvent(void)
{
    return GetAuthLaneMockInterface()->LnnInitBusCenterEvent();
}

int32_t LnnInitBatteryInfo(void)
{
    return GetAuthLaneMockInterface()->LnnInitBatteryInfo();
}

void LnnDeinitBatteryInfo(void)
{
    return GetAuthLaneMockInterface()->LnnDeinitBatteryInfo();
}

int32_t LnnSetLocalByteInfo(InfoKey key, const uint8_t *info, uint32_t len)
{
    return GetAuthLaneMockInterface()->LnnSetLocalByteInfo(key, info, len);
}

void LnnDeinitNetworkInfo(void)
{
    return GetAuthLaneMockInterface()->LnnDeinitNetworkInfo();
}

void LnnDeinitDevicename(void)
{
    return GetAuthLaneMockInterface()->LnnDeinitDevicename();
}

void LnnRemoveNode(const char *udid)
{
    return GetAuthLaneMockInterface()->LnnRemoveNode(udid);
}

int32_t LnnClearDiscoveryType(NodeInfo *info, DiscoveryType type)
{
    return GetAuthLaneMockInterface()->LnnClearDiscoveryType(info, type);
}

const char *LnnPrintConnectionAddr(const ConnectionAddr *addr)
{
    return GetAuthLaneMockInterface()->LnnPrintConnectionAddr(addr);
}

int32_t LnnUpdateGroupType(const NodeInfo *info)
{
    return GetAuthLaneMockInterface()->LnnUpdateGroupType(info);
}

int32_t LnnUpdateAccountInfo(const NodeInfo *info)
{
    return GetAuthLaneMockInterface()->LnnUpdateAccountInfo(info);
}

int32_t LnnUpdateRemoteDeviceName(const NodeInfo *info)
{
    return GetAuthLaneMockInterface()->LnnUpdateRemoteDeviceName(info);
}

bool LnnConvertAddrToAuthConnInfo(const ConnectionAddr *addr, AuthConnInfo *connInfo)
{
    return GetAuthLaneMockInterface()->LnnConvertAddrToAuthConnInfo(addr, connInfo);
}

int32_t LnnFsmRemoveMessageByType(FsmStateMachine *fsm, int32_t what)
{
    return GetAuthLaneMockInterface()->LnnFsmRemoveMessageByType(fsm, what);
}

void LnnDeinitBusCenterEvent(void)
{
    return GetAuthLaneMockInterface()->LnnDeinitBusCenterEvent();
}

bool LnnIsNeedCleanConnectionFsm(const NodeInfo *nodeInfo, ConnectionAddrType type)
{
    return GetAuthLaneMockInterface()->LnnIsNeedCleanConnectionFsm(nodeInfo, type);
}

int32_t LnnPutDBData(int32_t dbId, char *putKey, uint32_t putKeyLen, char *putValue, uint32_t putValueLen)
{
    return GetAuthLaneMockInterface()->LnnPutDBData(dbId, putKey, putKeyLen, putValue, putValueLen);
}

int32_t LnnCloudSync(int32_t dbId)
{
    return GetAuthLaneMockInterface()->LnnCloudSync(dbId);
}
}
} // namespace OHOS
