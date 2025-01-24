/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "lnn_net_builder_deps_mock.h"

#include <gtest/gtest.h>
#include <securec.h>

#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_netBuilderDepsInterface;
NetBuilderDepsInterfaceMock::NetBuilderDepsInterfaceMock()
{
    g_netBuilderDepsInterface = reinterpret_cast<void *>(this);
}

NetBuilderDepsInterfaceMock::~NetBuilderDepsInterfaceMock()
{
    g_netBuilderDepsInterface = nullptr;
}

static NetBuilderDepsInterface *GetNetBuilderDepsInterface()
{
    return reinterpret_cast<NetBuilderDepsInterfaceMock *>(g_netBuilderDepsInterface);
}

int32_t NetBuilderDepsInterfaceMock::ActionOfLnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    if (info == NULL || infoNum == NULL) {
        LNN_LOGW(LNN_TEST, "invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    *infoNum = 1;
    *info = reinterpret_cast<NodeBasicInfo *>(SoftBusMalloc((*infoNum) * sizeof(NodeBasicInfo)));
    if (*info == NULL) {
        LNN_LOGI(LNN_TEST, "malloc info fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s((*info)->networkId, sizeof((*info)->networkId), "abc", strlen("abc") + 1) != EOK) {
        LNN_LOGE(LNN_TEST, "memcpy networkId fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

extern "C" {
int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    return GetNetBuilderDepsInterface()->AuthGetDeviceUuid(authId, uuid, size);
}

int32_t LnnDeleteMetaInfo(const char *udid, AuthLinkType type)
{
    return GetNetBuilderDepsInterface()->LnnDeleteMetaInfo(udid, type);
}

int32_t TransGetConnByChanId(int32_t channelId, int32_t channelType, int32_t *connId)
{
    return GetNetBuilderDepsInterface()->TransGetConnByChanId(channelId, channelType, connId);
}

int32_t AuthMetaStartVerify(uint32_t connectionId, const AuthKeyInfo *authKeyInfo, uint32_t requestId,
    int32_t callingPid, const AuthVerifyCallback *callBack)
{
    return GetNetBuilderDepsInterface()->AuthMetaStartVerify(
        connectionId, authKeyInfo, requestId, callingPid, callBack);
}

uint32_t AuthGenRequestId(void)
{
    return GetNetBuilderDepsInterface()->AuthGenRequestId();
}

void LnnSetUnlockState(void)
{
    return GetNetBuilderDepsInterface()->LnnSetUnlockState();
}

void AuthHandleLeaveLNN(AuthHandle authHandle)
{
    return GetNetBuilderDepsInterface()->AuthHandleLeaveLNN(authHandle);
}

int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    return GetNetBuilderDepsInterface()->SoftbusGetConfig(type, val, len);
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    return GetNetBuilderDepsInterface()->LnnSetLocalStrInfo(key, info);
}

int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info)
{
    return GetNetBuilderDepsInterface()->LnnSetLocalNumInfo(key, info);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetNetBuilderDepsInterface()->LnnGetLocalStrInfo(key, info, len);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return GetNetBuilderDepsInterface()->LnnGetLocalNumInfo(key, info);
}

int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info)
{
    return GetNetBuilderDepsInterface()->LnnGetLocalNumU32Info(key, info);
}

int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len)
{
    return GetNetBuilderDepsInterface()->LnnGetNetworkIdByUdid(udid, buf, len);
}

int32_t LnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len)
{
    return GetNetBuilderDepsInterface()->LnnGetRemoteStrInfo(netWorkId, key, info, len);
}

int32_t LnnGetRemoteNumInfo(const char *netWorkId, InfoKey key, int32_t *info)
{
    return GetNetBuilderDepsInterface()->LnnGetRemoteNumInfo(netWorkId, key, info);
}

int32_t LnnGetRemoteNumU32Info(const char *netWorkId, InfoKey key, uint32_t *info)
{
    return GetNetBuilderDepsInterface()->LnnGetRemoteNumU32Info(netWorkId, key, info);
}

bool LnnIsSameConnectionAddr(const ConnectionAddr *addr1, const ConnectionAddr *addr2, bool isShort)
{
    return GetNetBuilderDepsInterface()->LnnIsSameConnectionAddr(addr1, addr2, isShort);
}

bool LnnConvertAddrToOption(const ConnectionAddr *addr, ConnectOption *option)
{
    return GetNetBuilderDepsInterface()->LnnConvertAddrToOption(addr, option);
}

DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type)
{
    return GetNetBuilderDepsInterface()->LnnConvAddrTypeToDiscType(type);
}

ConnectionAddrType LnnDiscTypeToConnAddrType(DiscoveryType type)
{
    return GetNetBuilderDepsInterface()->LnnDiscTypeToConnAddrType(type);
}

bool LnnConvertAuthConnInfoToAddr(ConnectionAddr *addr, const AuthConnInfo *connInfo, ConnectionAddrType hintType)
{
    return GetNetBuilderDepsInterface()->LnnConvertAuthConnInfoToAddr(addr, connInfo, hintType);
}

bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value)
{
    return GetNetBuilderDepsInterface()->AddStringToJsonObject(json, string, value);
}

bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num)
{
    return GetNetBuilderDepsInterface()->AddNumberToJsonObject(json, string, num);
}

int32_t LnnSendSyncInfoMsg(
    LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len, LnnSyncInfoMsgComplete complete)
{
    return GetNetBuilderDepsInterface()->LnnSendSyncInfoMsg(type, networkId, msg, len, complete);
}

NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type)
{
    return GetNetBuilderDepsInterface()->LnnGetNodeInfoById(id, type);
}

int32_t LnnUpdateNodeInfo(NodeInfo *newInfo, int32_t connectionType)
{
    return GetNetBuilderDepsInterface()->LnnUpdateNodeInfo(newInfo, connectionType);
}

int32_t LnnAddMetaInfo(NodeInfo *info)
{
    return GetNetBuilderDepsInterface()->LnnAddMetaInfo(info);
}

int32_t AuthGetLatestAuthSeqList(const char *udid, int64_t *authSeq, uint32_t num)
{
    return GetNetBuilderDepsInterface()->AuthGetLatestAuthSeqList(udid, authSeq, num);
}

int32_t LnnConvertDlId(
    const char *srcId, IdCategory srcIdType, IdCategory dstIdType, char *dstIdBuf, uint32_t dstIdBufLen)
{
    return GetNetBuilderDepsInterface()->LnnConvertDlId(srcId, srcIdType, dstIdType, dstIdBuf, dstIdBufLen);
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    return GetNetBuilderDepsInterface()->LnnGetOnlineStateById(id, type);
}

bool LnnIsNodeOnline(const NodeInfo *info)
{
    return GetNetBuilderDepsInterface()->LnnIsNodeOnline(info);
}

int32_t LnnSetSupportDiscoveryType(char *info, const char *type)
{
    return GetNetBuilderDepsInterface()->LnnSetSupportDiscoveryType(info, type);
}

bool LnnHasSupportDiscoveryType(const char *destType, const char *type)
{
    return GetNetBuilderDepsInterface()->LnnHasSupportDiscoveryType(destType, type);
}

bool LnnPeerHasExchangeDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetNetBuilderDepsInterface()->LnnPeerHasExchangeDiscoveryType(info, type);
}

const char *LnnGetDeviceUdid(const NodeInfo *info)
{
    return GetNetBuilderDepsInterface()->LnnGetDeviceUdid(info);
}

int32_t LnnCompareNodeWeight(int32_t weight1, const char *masterUdid1, int32_t weight2, const char *masterUdid2)
{
    return GetNetBuilderDepsInterface()->LnnCompareNodeWeight(weight1, masterUdid1, weight2, masterUdid2);
}

void LnnNotifyAllTypeOffline(ConnectionAddrType type)
{
    return GetNetBuilderDepsInterface()->LnnNotifyAllTypeOffline(type);
}

int32_t SoftBusGetTime(SoftBusSysTime *sysTime)
{
    return GetNetBuilderDepsInterface()->SoftBusGetTime(sysTime);
}

int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo)
{
    return GetNetBuilderDepsInterface()->AuthGetConnInfo(authHandle, connInfo);
}

void LnnNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    return GetNetBuilderDepsInterface()->LnnNotifyLeaveResult(networkId, retCode);
}

int32_t LnnGetAddrTypeByIfName(const char *ifName, ConnectionAddrType *type)
{
    return GetNetBuilderDepsInterface()->LnnGetAddrTypeByIfName(ifName, type);
}

int32_t LnnSendNotTrustedInfo(const NotTrustedDelayInfo *info, uint32_t num, LnnSyncInfoMsgComplete complete)
{
    return GetNetBuilderDepsInterface()->LnnSendNotTrustedInfo(info, num, complete);
}

int32_t LnnAsyncCallbackDelayHelper(
    SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis)
{
    return GetNetBuilderDepsInterface()->LnnAsyncCallbackDelayHelper(looper, callback, para, delayMillis);
}

SoftBusLooper *GetLooper(int32_t looper)
{
    return GetNetBuilderDepsInterface()->GetLooper(looper);
}

int32_t ConnDisconnectDeviceAllConn(const ConnectOption *option)
{
    return GetNetBuilderDepsInterface()->ConnDisconnectDeviceAllConn(option);
}

int32_t LnnGenLocalUuid(char *uuid, uint32_t len)
{
    return GetNetBuilderDepsInterface()->LnnGenLocalUuid(uuid, len);
}

int32_t LnnGenLocalIrk(unsigned char *irk, uint32_t len)
{
    return GetNetBuilderDepsInterface()->LnnGenLocalIrk(irk, len);
}

int32_t LnnGenLocalNetworkId(char *networkId, uint32_t len)
{
    return GetNetBuilderDepsInterface()->LnnGenLocalNetworkId(networkId, len);
}

int32_t LnnSetDLNodeAddr(const char *id, IdCategory type, const char *addr)
{
    return GetNetBuilderDepsInterface()->LnnSetDLNodeAddr(id, type, addr);
}

int32_t LnnSetDLProxyPort(const char *id, IdCategory type, int32_t proxyPort)
{
    return GetNetBuilderDepsInterface()->LnnSetDLProxyPort(id, type, proxyPort);
}

int32_t LnnSetDLSessionPort(const char *id, IdCategory type, int32_t sessionPort)
{
    return GetNetBuilderDepsInterface()->LnnSetDLSessionPort(id, type, sessionPort);
}

int32_t LnnSetDLAuthPort(const char *id, IdCategory type, int32_t authPort)
{
    return GetNetBuilderDepsInterface()->LnnSetDLAuthPort(id, type, authPort);
}

int32_t LnnInitP2p(void)
{
    return GetNetBuilderDepsInterface()->LnnInitP2p();
}

int32_t LnnInitWifiDirect(void)
{
    return GetNetBuilderDepsInterface()->LnnInitWifiDirect();
}

void LnnDeinitP2p(void)
{
    return GetNetBuilderDepsInterface()->LnnDeinitP2p();
}

void LnnDeinitWifiDirect(void)
{
    return GetNetBuilderDepsInterface()->LnnDeinitWifiDirect();
}

int32_t LnnInitNetworkInfo(void)
{
    return GetNetBuilderDepsInterface()->LnnInitNetworkInfo();
}

int32_t LnnInitDevicename(void)
{
    return GetNetBuilderDepsInterface()->LnnInitDevicename();
}

int32_t LnnInitSyncInfoManager(void)
{
    return GetNetBuilderDepsInterface()->LnnInitSyncInfoManager();
}

void LnnDeinitSyncInfoManager(void)
{
    return GetNetBuilderDepsInterface()->LnnDeinitSyncInfoManager();
}

int32_t LnnInitTopoManager(void)
{
    return GetNetBuilderDepsInterface()->LnnInitTopoManager();
}

void LnnDeinitTopoManager(void)
{
    return GetNetBuilderDepsInterface()->LnnDeinitTopoManager();
}

int32_t RegAuthVerifyListener(const AuthVerifyListener *listener)
{
    return GetNetBuilderDepsInterface()->RegAuthVerifyListener(listener);
}

void UnregAuthVerifyListener(void)
{
    return GetNetBuilderDepsInterface()->UnregAuthVerifyListener();
}

int32_t LnnRegSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler)
{
    return GetNetBuilderDepsInterface()->LnnRegSyncInfoHandler(type, handler);
}

int32_t LnnUnregSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler)
{
    return GetNetBuilderDepsInterface()->LnnUnregSyncInfoHandler(type, handler);
}

int32_t LnnStopConnectionFsm(LnnConnectionFsm *connFsm, LnnConnectionFsmStopCallback callback)
{
    return GetNetBuilderDepsInterface()->LnnStopConnectionFsm(connFsm, callback);
}

void LnnDeinitFastOffline(void)
{
    return GetNetBuilderDepsInterface()->LnnDeinitFastOffline();
}

int32_t LnnSendNewNetworkOnlineToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetNetBuilderDepsInterface()->LnnSendNewNetworkOnlineToConnFsm(connFsm);
}

int32_t LnnSendAuthResultMsgToConnFsm(LnnConnectionFsm *connFsm, int32_t retCode)
{
    return GetNetBuilderDepsInterface()->LnnSendAuthResultMsgToConnFsm(connFsm, retCode);
}

int32_t LnnSendDisconnectMsgToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetNetBuilderDepsInterface()->LnnSendDisconnectMsgToConnFsm(connFsm);
}

int32_t LnnSendNotTrustedToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetNetBuilderDepsInterface()->LnnSendNotTrustedToConnFsm(connFsm);
}

int32_t LnnSendLeaveRequestToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetNetBuilderDepsInterface()->LnnSendLeaveRequestToConnFsm(connFsm);
}

int32_t LnnSendSyncOfflineFinishToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetNetBuilderDepsInterface()->LnnSendSyncOfflineFinishToConnFsm(connFsm);
}

int32_t LnnGetLocalWeight(void)
{
    return GetNetBuilderDepsInterface()->LnnGetLocalWeight();
}

void AuthMetaReleaseVerify(int64_t authId)
{
    return GetNetBuilderDepsInterface()->AuthMetaReleaseVerify(authId);
}

int32_t LnnSendJoinRequestToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetNetBuilderDepsInterface()->LnnSendJoinRequestToConnFsm(connFsm);
}

void LnnNotifyJoinResult(ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    return GetNetBuilderDepsInterface()->LnnNotifyJoinResult(addr, networkId, retCode);
}

void LnnDestroyConnectionFsm(LnnConnectionFsm *connFsm)
{
    return GetNetBuilderDepsInterface()->LnnDestroyConnectionFsm(connFsm);
}

LnnConnectionFsm *LnnCreateConnectionFsm(const ConnectionAddr *target, const char *pkgName, bool isNeedConnect)
{
    return GetNetBuilderDepsInterface()->LnnCreateConnectionFsm(target, pkgName, false);
}

int32_t LnnStartConnectionFsm(LnnConnectionFsm *connFsm)
{
    return GetNetBuilderDepsInterface()->LnnStartConnectionFsm(connFsm);
}

void LnnNotifyMasterNodeChanged(bool isMaster, const char *masterNodeUdid, int32_t weight)
{
    return GetNetBuilderDepsInterface()->LnnNotifyMasterNodeChanged(isMaster, masterNodeUdid, weight);
}

int32_t LnnInitFastOffline(void)
{
    return GetNetBuilderDepsInterface()->LnnInitFastOffline();
}

int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetNetBuilderDepsInterface()->LnnGetAllOnlineNodeInfo(info, infoNum);
}

bool LnnIsLSANode(const NodeBasicInfo *info)
{
    return GetNetBuilderDepsInterface()->LnnIsLSANode(info);
}

void LnnNotifyNodeAddressChanged(const char *addr, const char *networkId, bool isLocal)
{
    return GetNetBuilderDepsInterface()->LnnNotifyNodeAddressChanged(addr, networkId, isLocal);
}

int32_t LnnInitOffline(void)
{
    return GetNetBuilderDepsInterface()->LnnInitOffline();
}

void LnnDeinitOffline(void)
{
    return GetNetBuilderDepsInterface()->LnnDeinitOffline();
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetNetBuilderDepsInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}

bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetNetBuilderDepsInterface()->LnnHasDiscoveryType(info, type);
}

const char *LnnConvertDLidToUdid(const char *id, IdCategory type)
{
    return GetNetBuilderDepsInterface()->LnnConvertDLidToUdid(id, type);
}

int32_t GetAuthRequest(uint32_t requestId, AuthRequest *request)
{
    return GetNetBuilderDepsInterface()->GetAuthRequest(requestId, request);
}

int32_t SoftBusGetBtState(void)
{
    return GetNetBuilderDepsInterface()->SoftBusGetBtState();
}

int32_t SoftBusGetBrState(void)
{
    return GetNetBuilderDepsInterface()->SoftBusGetBrState();
}

int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type)
{
    return GetNetBuilderDepsInterface()->LnnSetNetCapability(capability, type);
}

int32_t LnnClearNetCapability(uint32_t *capability, NetCapability type)
{
    return GetNetBuilderDepsInterface()->LnnClearNetCapability(capability, type);
}

int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetNetBuilderDepsInterface()->LnnRegisterEventHandler(event, handler);
}

void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetNetBuilderDepsInterface()->LnnUnregisterEventHandler(event, handler);
}

void LnnNotifyDeviceVerified(const char *udid)
{
    return GetNetBuilderDepsInterface()->LnnNotifyDeviceVerified(udid);
}

int32_t LnnInitBusCenterEvent(void)
{
    return GetNetBuilderDepsInterface()->LnnInitBusCenterEvent();
}

int32_t LnnInitBatteryInfo(void)
{
    return GetNetBuilderDepsInterface()->LnnInitBatteryInfo();
}

void LnnDeinitBatteryInfo(void)
{
    return GetNetBuilderDepsInterface()->LnnDeinitBatteryInfo();
}

int32_t LnnSetLocalByteInfo(InfoKey key, const uint8_t *info, uint32_t len)
{
    return GetNetBuilderDepsInterface()->LnnSetLocalByteInfo(key, info, len);
}

void LnnDeinitNetworkInfo(void)
{
    return GetNetBuilderDepsInterface()->LnnDeinitNetworkInfo();
}

void LnnDeinitDevicename(void)
{
    return GetNetBuilderDepsInterface()->LnnDeinitDevicename();
}

const NodeInfo *LnnGetLocalNodeInfo(void)
{
    return GetNetBuilderDepsInterface()->LnnGetLocalNodeInfo();
}

void LnnRemoveNode(const char *udid)
{
    return GetNetBuilderDepsInterface()->LnnRemoveNode(udid);
}

int32_t LnnClearDiscoveryType(NodeInfo *info, DiscoveryType type)
{
    return GetNetBuilderDepsInterface()->LnnClearDiscoveryType(info, type);
}

const char *LnnPrintConnectionAddr(const ConnectionAddr *addr)
{
    return GetNetBuilderDepsInterface()->LnnPrintConnectionAddr(addr);
}

int32_t LnnUpdateGroupType(const NodeInfo *info)
{
    return GetNetBuilderDepsInterface()->LnnUpdateGroupType(info);
}

int32_t LnnUpdateAccountInfo(const NodeInfo *info)
{
    return GetNetBuilderDepsInterface()->LnnUpdateAccountInfo(info);
}

int32_t LnnUpdateRemoteDeviceName(const NodeInfo *info)
{
    return GetNetBuilderDepsInterface()->LnnUpdateRemoteDeviceName(info);
}

bool LnnConvertAddrToAuthConnInfo(const ConnectionAddr *addr, AuthConnInfo *connInfo)
{
    return GetNetBuilderDepsInterface()->LnnConvertAddrToAuthConnInfo(addr, connInfo);
}

int32_t LnnFsmRemoveMessageByType(FsmStateMachine *fsm, int32_t what)
{
    return GetNetBuilderDepsInterface()->LnnFsmRemoveMessageByType(fsm, what);
}

int32_t TransAuthGetConnIdByChanId(int32_t channelId, int32_t *connId)
{
    return GetNetBuilderDepsInterface()->TransAuthGetConnIdByChanId(channelId, connId);
}

int32_t TransAuthGetPeerUdidByChanId(int32_t channelId, char *peerUdid, uint32_t len)
{
    return GetNetBuilderDepsInterface()->TransAuthGetPeerUdidByChanId(channelId, peerUdid, len);
}

void LnnNotifyStateForSession(char *udid, int32_t retCode)
{
    return GetNetBuilderDepsInterface()->LnnNotifyStateForSession(udid, retCode);
}

void AuthRemoveAuthManagerByAuthHandle(AuthHandle authHandle)
{
    return GetNetBuilderDepsInterface()->AuthRemoveAuthManagerByAuthHandle(authHandle);
}

void LnnDeinitBusCenterEvent(void)
{
    return GetNetBuilderDepsInterface()->LnnDeinitBusCenterEvent();
}

int32_t AuthStartVerify(const AuthConnInfo *connInfo, uint32_t requestId, const AuthVerifyCallback *callback,
    AuthVerifyModule module, bool isFastAuth)
{
    return GetNetBuilderDepsInterface()->AuthStartVerify(connInfo, requestId, callback, module, isFastAuth);
}

bool LnnIsNeedCleanConnectionFsm(const NodeInfo *nodeInfo, ConnectionAddrType type)
{
    return GetNetBuilderDepsInterface()->LnnIsNeedCleanConnectionFsm(nodeInfo, type);
}

int32_t AuthFlushDevice(const char *uuid)
{
    return GetNetBuilderDepsInterface()->AuthFlushDevice(uuid);
}

bool IsSupportLpFeature(void)
{
    return GetNetBuilderDepsInterface()->IsSupportLpFeature();
}

void LnnNotifyLocalNetworkIdChanged(void)
{
    return GetNetBuilderDepsInterface()->LnnNotifyLocalNetworkIdChanged();
}

bool LnnIsDefaultOhosAccount()
{
    return GetNetBuilderDepsInterface()->LnnIsDefaultOhosAccount();
}

void DeleteFromProfile(const char *udid)
{
    return GetNetBuilderDepsInterface()->DeleteFromProfile(udid);
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return GetNetBuilderDepsInterface()->SoftBusGenerateStrHash(str, len, hash);
}

void UpdateProfile(const NodeInfo *info)
{
    return GetNetBuilderDepsInterface()->UpdateProfile(info);
}

bool IsSupportFeatureByCapaBit(uint32_t feature, AuthCapability capaBit)
{
    return GetNetBuilderDepsInterface()->IsSupportFeatureByCapaBit(feature, capaBit);
}

int32_t LnnGetRemoteNodeInfoByKey(const char *key, NodeInfo *info)
{
    return GetNetBuilderDepsInterface()->LnnGetRemoteNodeInfoByKey(key, info);
}

void RegisterOOBEMonitor(void *p)
{
    (void)p;
    return GetNetBuilderDepsInterface()->RegisterOOBEMonitor(p);
}

bool CheckRemoteBasicInfoChanged(const NodeInfo *newNodeInfo)
{
    return GetNetBuilderDepsInterface()->CheckRemoteBasicInfoChanged(newNodeInfo);
}

int32_t ProcessBleOnline(NodeInfo *nodeInfo, const ConnectionAddr *connAddr, AuthCapability authCapability)
{
    return GetNetBuilderDepsInterface()->ProcessBleOnline(nodeInfo, connAddr, authCapability);
}

int32_t CheckAuthChannelIsExit(ConnectOption *connInfo)
{
    return GetNetBuilderDepsInterface()->CheckAuthChannelIsExit(connInfo);
}

void GetLnnTriggerInfo(LnnTriggerInfo *triggerInfo)
{
    return GetNetBuilderDepsInterface()->GetLnnTriggerInfo(triggerInfo);
}

int32_t LnnSetDLConnUserIdCheckSum(const char *networkId, int32_t userIdCheckSum)
{
    return GetNetBuilderDepsInterface()->LnnSetDLConnUserIdCheckSum(networkId, userIdCheckSum);
}

void LnnNotifyDeviceTrustedChange(int32_t type, const char *msg, uint32_t msgLen)
{
    return GetNetBuilderDepsInterface()->LnnNotifyDeviceTrustedChange(type, msg, msgLen);
}

void LnnGetDataShareInitResult(bool *isDataShareInit)
{
    return GetNetBuilderDepsInterface()->LnnGetDataShareInitResult(isDataShareInit);
}
} // extern "C"
} // namespace OHOS
