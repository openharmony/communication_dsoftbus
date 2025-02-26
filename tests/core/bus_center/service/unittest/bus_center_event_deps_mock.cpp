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

#include "bus_center_event_deps_mock.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_busCenterEventDepsInterface = nullptr;
BusCenterEventDepsInterfaceMock::BusCenterEventDepsInterfaceMock()
{
    g_busCenterEventDepsInterface = reinterpret_cast<void *>(this);
}

BusCenterEventDepsInterfaceMock::~BusCenterEventDepsInterfaceMock()
{
    g_busCenterEventDepsInterface = nullptr;
}

static BusCenterEventDepsInterface *GetBusCenterEventDepsInterface()
{
    return reinterpret_cast<BusCenterEventDepsInterface *>(g_busCenterEventDepsInterface);
}

extern "C" {
void Anonymize(const char *plainStr, char **anonymizedStr)
{
    return GetBusCenterEventDepsInterface()->Anonymize(plainStr, anonymizedStr);
}

void AnonymizeFree(char *anonymizedStr)
{
    return GetBusCenterEventDepsInterface()->AnonymizeFree(anonymizedStr);
}

int32_t SetDefaultQdisc(void)
{
    return GetBusCenterEventDepsInterface()->SetDefaultQdisc();
}

int32_t LnnGetAllOnlineNodeNum(int32_t *nodeNum)
{
    return GetBusCenterEventDepsInterface()->LnnGetAllOnlineNodeNum(nodeNum);
}

int32_t LnnGetLocalNum64Info(InfoKey key, int64_t *info)
{
    return GetBusCenterEventDepsInterface()->LnnGetLocalNum64Info(key, info);
}

int32_t LnnIpcNotifyDeviceNotTrusted(const char *msg)
{
    return GetBusCenterEventDepsInterface()->LnnIpcNotifyDeviceNotTrusted(msg);
}

int32_t LnnIpcNotifyJoinResult(void *addr, uint32_t addrTypeLen, const char *networkId,
    int32_t retCode)
{
    return GetBusCenterEventDepsInterface()->LnnIpcNotifyJoinResult(addr, addrTypeLen, networkId, retCode);
}

int32_t LnnIpcNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    return GetBusCenterEventDepsInterface()->LnnIpcNotifyLeaveResult(networkId, retCode);
}

int32_t LnnIpcNotifyTimeSyncResult(const char *pkgName, int32_t pid, const void *info,
    uint32_t infoTypeLen, int32_t retCode)
{
    return GetBusCenterEventDepsInterface()->LnnIpcNotifyTimeSyncResult(pkgName, pid, info, infoTypeLen, retCode);
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetBusCenterEventDepsInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}

bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetBusCenterEventDepsInterface()->LnnHasDiscoveryType(info, type);
}

DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type)
{
    return GetBusCenterEventDepsInterface()->LnnConvAddrTypeToDiscType(type);
}

SoftBusLooper *CreateNewLooper(const char *name)
{
    return GetBusCenterEventDepsInterface()->CreateNewLooper(name);
}

int32_t  LnnIpcNotifyOnlineState(bool isOnline, void *info, uint32_t infoTypeLen)
{
    return GetBusCenterEventDepsInterface()->LnnIpcNotifyOnlineState(isOnline, info, infoTypeLen);
}

void LnnDCProcessOnlineState(bool isOnline, const NodeBasicInfo *info)
{
    return GetBusCenterEventDepsInterface()->LnnDCProcessOnlineState(isOnline, info);
}

int32_t LnnIpcNotifyBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    return GetBusCenterEventDepsInterface()->LnnIpcNotifyBasicInfoChanged(info, infoTypeLen, type);
}

int32_t LnnGenLocalNetworkId(char *networkId, uint32_t len)
{
    return GetBusCenterEventDepsInterface()->LnnGenLocalNetworkId(networkId, len);
}

int32_t LnnIpcLocalNetworkIdChanged(void)
{
    return GetBusCenterEventDepsInterface()->LnnIpcLocalNetworkIdChanged();
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    return GetBusCenterEventDepsInterface()->LnnSetLocalStrInfo(key, info);
}

void LnnUpdateAuthExchangeUdid(void)
{
    return GetBusCenterEventDepsInterface()->LnnUpdateAuthExchangeUdid();
}

bool LnnIsSameConnectionAddr(const ConnectionAddr *addr1, const ConnectionAddr *addr2, bool isShort)
{
    return GetBusCenterEventDepsInterface()->LnnIsSameConnectionAddr(addr1, addr2, isShort);
}

int32_t LnnServerLeave(const char *networkId, const char *pkgName)
{
    return GetBusCenterEventDepsInterface()->LnnServerLeave(networkId, pkgName);
}

int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetBusCenterEventDepsInterface()->LnnGetAllOnlineNodeInfo(info, infoNum);
}

bool LnnIsLSANode(const NodeBasicInfo *info)
{
    return GetBusCenterEventDepsInterface()->LnnIsLSANode(info);
}

int32_t LnnGetLocalDeviceInfo(NodeBasicInfo *info)
{
    return GetBusCenterEventDepsInterface()->LnnGetLocalDeviceInfo(info);
}

int32_t LnnGetNodeKeyInfo(const char *networkId, int32_t key, uint8_t *info, uint32_t infoLen)
{
    return GetBusCenterEventDepsInterface()->LnnGetNodeKeyInfo(networkId, key, info, infoLen);
}

int32_t LnnSetNodeDataChangeFlag(const char *networkId, uint16_t dataChangeFlag)
{
    return GetBusCenterEventDepsInterface()->LnnSetNodeDataChangeFlag(networkId, dataChangeFlag);
}

int32_t LnnStartTimeSync(const char *pkgName, int32_t callingPid, const char *targetNetworkId,
    TimeSyncAccuracy accuracy, TimeSyncPeriod period)
{
    return GetBusCenterEventDepsInterface()->LnnStartTimeSync(pkgName, callingPid, targetNetworkId, accuracy, period);
}

int32_t LnnStopTimeSync(const char *pkgName, const char *targetNetworkId, int32_t callingPid)
{
    return GetBusCenterEventDepsInterface()->LnnStopTimeSync(pkgName, targetNetworkId, callingPid);
}

int32_t LnnPublishService(const char *pkgName, const PublishInfo *info, bool isInnerRequest)
{
    return GetBusCenterEventDepsInterface()->LnnPublishService(pkgName, info, isInnerRequest);
}

int32_t LnnUnPublishService(const char *pkgName, int32_t publishId, bool isInnerRequest)
{
    return GetBusCenterEventDepsInterface()->LnnUnPublishService(pkgName, publishId, isInnerRequest);
}

int32_t LnnStartDiscDevice(
    const char *pkgName, const SubscribeInfo *info, const InnerCallback *cb, bool isInnerRequest)
{
    return GetBusCenterEventDepsInterface()->LnnStartDiscDevice(pkgName, info, cb, isInnerRequest);
}

int32_t LnnStopDiscDevice(const char *pkgName, int32_t subscribeId, bool isInnerRequest)
{
    return GetBusCenterEventDepsInterface()->LnnStopDiscDevice(pkgName, subscribeId, isInnerRequest);
}

int32_t LnnActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId)
{
    return GetBusCenterEventDepsInterface()->LnnActiveMetaNode(info, metaNodeId);
}

int32_t LnnDeactiveMetaNode(const char *metaNodeId)
{
    return GetBusCenterEventDepsInterface()->LnnDeactiveMetaNode(metaNodeId);
}

int32_t LnnGetAllMetaNodeInfo(MetaNodeInfo *infos, int32_t *infoNum)
{
    return GetBusCenterEventDepsInterface()->LnnGetAllMetaNodeInfo(infos, infoNum);
}

int32_t LnnShiftLNNGear(
    const char *pkgName, const char *callerId, const char *targetNetworkId, const GearMode *mode)
{
    return GetBusCenterEventDepsInterface()->LnnShiftLNNGear(pkgName, callerId, targetNetworkId, mode);
}

int32_t ClientOnJoinLNNResult(
    PkgNameAndPidInfo *info, void *addr, uint32_t addrTypeLen, const char *networkId, int32_t retCode)
{
    return GetBusCenterEventDepsInterface()->ClientOnJoinLNNResult(info, addr, addrTypeLen, networkId, retCode);
}

int32_t ClientOnLeaveLNNResult(const char *pkgName, int32_t pid, const char *networkId, int32_t retCode)
{
    return GetBusCenterEventDepsInterface()->ClientOnLeaveLNNResult(pkgName, pid, networkId, retCode);
}

int32_t ClinetOnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen)
{
    return GetBusCenterEventDepsInterface()->ClinetOnNodeOnlineStateChanged(isOnline, info, infoTypeLen);
}

int32_t ClinetOnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    return GetBusCenterEventDepsInterface()->ClinetOnNodeBasicInfoChanged(info, infoTypeLen, type);
}

int32_t ClientOnTimeSyncResult(
    const char *pkgName, int32_t pid, const void *info, uint32_t infoTypeLen, int32_t retCode)
{
    return GetBusCenterEventDepsInterface()->ClientOnTimeSyncResult(pkgName, pid, info, infoTypeLen, retCode);
}

int32_t ClientOnPublishLNNResult(const char *pkgName, int32_t pid, int32_t publishId, int32_t reason)
{
    return GetBusCenterEventDepsInterface()->ClientOnPublishLNNResult(pkgName, pid, publishId, reason);
}

int32_t ClientOnRefreshLNNResult(const char *pkgName, int32_t pid, int32_t refreshId, int32_t reason)
{
    return GetBusCenterEventDepsInterface()->ClientOnRefreshLNNResult(pkgName, pid, refreshId, reason);
}

int32_t ClientOnRefreshDeviceFound(const char *pkgName, int32_t pid, const void *device, uint32_t deviceLen)
{
    return GetBusCenterEventDepsInterface()->ClientOnRefreshDeviceFound(pkgName, pid, device, deviceLen);
}

int32_t LnnServerJoin(ConnectionAddr *addr, const char *pkgName)
{
    return GetBusCenterEventDepsInterface()->LnnServerJoin(addr, pkgName);
}

int32_t LnnEnableHeartbeatByType(LnnHeartbeatType type, bool isEnable)
{
    return GetBusCenterEventDepsInterface()->LnnEnableHeartbeatByType(type, isEnable);
}

int32_t LnnStartHbByTypeAndStrategy(LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType, bool isRelay)
{
    return GetBusCenterEventDepsInterface()->LnnStartHbByTypeAndStrategy(hbType, strategyType, isRelay);
}

int32_t LnnStartHeartbeat(uint64_t delayMillis)
{
    return GetBusCenterEventDepsInterface()->LnnStartHeartbeat(delayMillis);
}

int32_t LnnStopHeartbeatByType(LnnHeartbeatType type)
{
    return GetBusCenterEventDepsInterface()->LnnStopHeartbeatByType(type);
}

int32_t LnnSetHbAsMasterNodeState(bool isMasterNode)
{
    return GetBusCenterEventDepsInterface()->LnnSetHbAsMasterNodeState(isMasterNode);
}

int32_t LnnUpdateSendInfoStrategy(LnnHeartbeatUpdateInfoType type)
{
    return GetBusCenterEventDepsInterface()->LnnUpdateSendInfoStrategy(type);
}

int32_t LnnAsyncCallbackDelayHelper(
    SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis)
{
    return GetBusCenterEventDepsInterface()->LnnAsyncCallbackDelayHelper(looper, callback, para, delayMillis);
}

int32_t LnnSetCloudAbility(const bool isEnableCloud)
{
    return GetBusCenterEventDepsInterface()->LnnSetCloudAbility(isEnableCloud);
}

int32_t LnnDeleteSyncToDB(void)
{
    return GetBusCenterEventDepsInterface()->LnnDeleteSyncToDB();
}

void LnnOnOhosAccountLogout(void)
{
    GetBusCenterEventDepsInterface()->LnnOnOhosAccountLogout();
}

void LnnUpdateOhosAccount(UpdateAccountReason reason)
{
    GetBusCenterEventDepsInterface()->LnnUpdateOhosAccount(reason);
}

TrustedReturnType AuthHasTrustedRelation(void)
{
    return GetBusCenterEventDepsInterface()->AuthHasTrustedRelation();
}

bool IsEnableSoftBusHeartbeat(void)
{
    return GetBusCenterEventDepsInterface()->IsEnableSoftBusHeartbeat();
}

int32_t LnnSetMediumParamBySpecificType(const LnnHeartbeatMediumParam *param)
{
    return GetBusCenterEventDepsInterface()->LnnSetMediumParamBySpecificType(param);
}

int32_t LnnGetLocalNodeInfoSafe(NodeInfo *info)
{
    return GetBusCenterEventDepsInterface()->LnnGetLocalNodeInfoSafe(info);
}

int32_t LnnLedgerAllDataSyncToDB(NodeInfo *info, bool isAckSeq, char *peerudid)
{
    return GetBusCenterEventDepsInterface()->LnnLedgerAllDataSyncToDB(info, isAckSeq, peerudid);
}

ConnectionAddrType LnnConvertHbTypeToConnAddrType(LnnHeartbeatType type)
{
    return GetBusCenterEventDepsInterface()->LnnConvertHbTypeToConnAddrType(type);
}

int32_t LnnStopScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType)
{
    return GetBusCenterEventDepsInterface()->LnnStopScreenChangeOfflineTiming(networkId, addrType);
}

int32_t LnnStartScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType)
{
    return GetBusCenterEventDepsInterface()->LnnStartScreenChangeOfflineTiming(networkId, addrType);
}

void LnnMapDelete(Map *map)
{
    GetBusCenterEventDepsInterface()->LnnMapDelete(map);
}

void ClearAuthLimitMap(void)
{
    GetBusCenterEventDepsInterface()->ClearAuthLimitMap();
}

int32_t LnnStopHeartBeatAdvByTypeNow(LnnHeartbeatType registedHbType)
{
    return GetBusCenterEventDepsInterface()->LnnStopHeartBeatAdvByTypeNow(registedHbType);
}

void RestartCoapDiscovery(void)
{
    GetBusCenterEventDepsInterface()->RestartCoapDiscovery();
}

bool LnnIsLocalSupportBurstFeature(void)
{
    return GetBusCenterEventDepsInterface()->LnnIsLocalSupportBurstFeature();
}

void AuthLoadDeviceKey(void)
{
    return GetBusCenterEventDepsInterface()->AuthLoadDeviceKey();
}

int32_t LnnGenerateCeParams(void)
{
    return GetBusCenterEventDepsInterface()->LnnGenerateCeParams();
}

void DfxRecordTriggerTime(LnnTriggerReason reason, LnnEventLnnStage stage)
{
    return GetBusCenterEventDepsInterface()->DfxRecordTriggerTime(reason, stage);
}

int32_t LnnHbMediumMgrInit(void)
{
    return GetBusCenterEventDepsInterface()->LnnHbMediumMgrInit();
}

int32_t LnnStartNewHbStrategyFsm(void)
{
    return GetBusCenterEventDepsInterface()->LnnStartNewHbStrategyFsm();
}

int32_t AuthSendKeepaliveOption(const char *uuid, ModeCycle cycle)
{
    return GetBusCenterEventDepsInterface()->AuthSendKeepaliveOption(uuid, cycle);
}

int32_t LnnSetGearModeBySpecificType(const char *callerId, const GearMode *mode, LnnHeartbeatType type)
{
    return GetBusCenterEventDepsInterface()->LnnSetGearModeBySpecificType(callerId, mode, type);
}

void LnnDumpLocalBasicInfo(void)
{
    return GetBusCenterEventDepsInterface()->LnnDumpLocalBasicInfo();
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    return GetBusCenterEventDepsInterface()->LnnGetOnlineStateById(id, type);
}

int32_t AuthFlushDevice(const char *uuid)
{
    return GetBusCenterEventDepsInterface()->AuthFlushDevice(uuid);
}

int32_t LnnHbStrategyInit(void)
{
    return GetBusCenterEventDepsInterface()->LnnHbStrategyInit();
}

void LnnBleHbUnregDataLevelChangeCb(void)
{
    return GetBusCenterEventDepsInterface()->LnnBleHbUnregDataLevelChangeCb();
}

int32_t LnnStopOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType)
{
    return GetBusCenterEventDepsInterface()->LnnStopOfflineTimingStrategy(networkId, addrType);
}

int32_t HbBuildUserIdCheckSum(const int32_t *userIdArray, int32_t num, uint8_t *custData, int32_t len)
{
    return GetBusCenterEventDepsInterface()->HbBuildUserIdCheckSum(userIdArray, num, custData, len);
}

int32_t LnnSetLocalByteInfo(InfoKey key, const uint8_t *info, uint32_t len)
{
    return GetBusCenterEventDepsInterface()->LnnSetLocalByteInfo(key, info, len);
}

int32_t LnnStartHbByTypeAndStrategyEx(LnnProcessSendOnceMsgPara *msgPara)
{
    return GetBusCenterEventDepsInterface()->LnnStartHbByTypeAndStrategyEx(msgPara);
}

int32_t LnnSyncBleOfflineMsg(void)
{
    return GetBusCenterEventDepsInterface()->LnnSyncBleOfflineMsg();
}

void LnnRemoveV0BroadcastAndCheckDev(void)
{
    return GetBusCenterEventDepsInterface()->LnnRemoveV0BroadcastAndCheckDev();
}

int32_t LnnStartOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType)
{
    return GetBusCenterEventDepsInterface()->LnnStartOfflineTimingStrategy(networkId, addrType);
}

int32_t LnnNotifyDiscoveryDevice(
    const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport, bool isNeedConnect)
{
    return GetBusCenterEventDepsInterface()->LnnNotifyDiscoveryDevice(addr, infoReport, isNeedConnect);
}

int32_t LnnNotifyMasterElect(const char *networkId, const char *masterUdid, int32_t masterWeight)
{
    return GetBusCenterEventDepsInterface()->LnnNotifyMasterElect(networkId, masterUdid, masterWeight);
}

int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType)
{
    return GetBusCenterEventDepsInterface()->LnnRequestLeaveSpecific(networkId, addrType);
}

AuthVerifyCallback *LnnGetReAuthVerifyCallback(void)
{
    return GetBusCenterEventDepsInterface()->LnnGetReAuthVerifyCallback();
}

bool IsNeedAuthLimit(const char *udidHash)
{
    return GetBusCenterEventDepsInterface()->IsNeedAuthLimit(udidHash);
}

bool IsExistLnnDfxNodeByUdidHash(const char *udidHash, LnnBleReportExtra *bleExtra)
{
    return GetBusCenterEventDepsInterface()->IsExistLnnDfxNodeByUdidHash(udidHash, bleExtra);
}

int32_t LnnRetrieveDeviceInfo(const char *udid, NodeInfo *deviceInfo)
{
    return GetBusCenterEventDepsInterface()->LnnRetrieveDeviceInfo(udid, deviceInfo);
}

bool IsSameAccountGroupDevice(void)
{
    return GetBusCenterEventDepsInterface()->IsSameAccountGroupDevice();
}

uint32_t AuthGenRequestId(void)
{
    return GetBusCenterEventDepsInterface()->AuthGenRequestId();
}

int32_t AuthStartVerify(const AuthConnInfo *connInfo, uint32_t requestId, const AuthVerifyCallback *verifyCallback,
    AuthVerifyModule module, bool isFastAuth)
{
    return GetBusCenterEventDepsInterface()->AuthStartVerify(connInfo, requestId, verifyCallback, module, isFastAuth);
}

void AddNodeToLnnBleReportExtraMap(const char *udidHash, const LnnBleReportExtra *bleExtra)
{
    return GetBusCenterEventDepsInterface()->AddNodeToLnnBleReportExtraMap(udidHash, bleExtra);
}

int32_t GetNodeFromLnnBleReportExtraMap(const char *udidHash, LnnBleReportExtra *bleExtra)
{
    return GetBusCenterEventDepsInterface()->GetNodeFromLnnBleReportExtraMap(udidHash, bleExtra);
}

void DeleteNodeFromLnnBleReportExtraMap(const char *udidHash)
{
    return GetBusCenterEventDepsInterface()->DeleteNodeFromLnnBleReportExtraMap(udidHash);
}

int32_t LnnUpdateRemoteDeviceInfo(const NodeInfo *deviceInfo)
{
    return GetBusCenterEventDepsInterface()->LnnUpdateRemoteDeviceInfo(deviceInfo);
}

int32_t GetNodeFromPcRestrictMap(const char *udidHash, uint32_t *count)
{
    return GetBusCenterEventDepsInterface()->GetNodeFromPcRestrictMap(udidHash, count);
}

int32_t LnnSetDLConnUserIdCheckSum(const char *networkId, int32_t userIdCheckSum)
{
    return GetBusCenterEventDepsInterface()->LnnSetDLConnUserIdCheckSum(networkId, userIdCheckSum);
}

void NotifyForegroundUseridChange(char *networkId, uint32_t discoveryType, bool isChange)
{
    return GetBusCenterEventDepsInterface()->NotifyForegroundUseridChange(networkId, discoveryType, isChange);
}

int32_t LnnHbMediumMgrStop(LnnHeartbeatType *type)
{
    return GetBusCenterEventDepsInterface()->LnnHbMediumMgrStop(type);
}

void LnnDumpHbMgrRecvList(void)
{
    return GetBusCenterEventDepsInterface()->LnnDumpHbMgrRecvList();
}

void LnnDumpHbOnlineNodeList(void)
{
    return GetBusCenterEventDepsInterface()->LnnDumpHbOnlineNodeList();
}

bool LnnIsHeartbeatEnable(LnnHeartbeatType type)
{
    return GetBusCenterEventDepsInterface()->LnnIsHeartbeatEnable(type);
}

int32_t LnnGetGearModeBySpecificType(GearMode *mode, char *callerId, LnnHeartbeatType type)
{
    return GetBusCenterEventDepsInterface()->LnnGetGearModeBySpecificType(mode, callerId, type);
}

int32_t LnnOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType)
{
    return GetBusCenterEventDepsInterface()->LnnOfflineTimingByHeartbeat(networkId, addrType);
}

int32_t LnnHbMediumMgrSendBegin(LnnHeartbeatSendBeginData *custData)
{
    return GetBusCenterEventDepsInterface()->LnnHbMediumMgrSendBegin(custData);
}

int32_t LnnHbMediumMgrSendEnd(LnnHeartbeatSendEndData *type)
{
    return GetBusCenterEventDepsInterface()->LnnHbMediumMgrSendEnd(type);
}

int32_t LnnGetHbStrategyManager(
    LnnHeartbeatStrategyManager *mgr, LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType)
{
    return GetBusCenterEventDepsInterface()->LnnGetHbStrategyManager(mgr, hbType, strategyType);
}

int32_t LnnHbMediumMgrSetParam(void *param)
{
    return GetBusCenterEventDepsInterface()->LnnHbMediumMgrSetParam(param);
}

int32_t LnnHbMediumMgrUpdateSendInfo(LnnHeartbeatUpdateInfoType type)
{
    return GetBusCenterEventDepsInterface()->LnnHbMediumMgrUpdateSendInfo(type);
}

int32_t StopHeartBeatAdvByTypeNow(LnnHeartbeatType registedHbType)
{
    return GetBusCenterEventDepsInterface()->StopHeartBeatAdvByTypeNow(registedHbType);
}

SoftBusScreenState GetScreenState(void)
{
    return GetBusCenterEventDepsInterface()->GetScreenState();
}

void SetScreenState(SoftBusScreenState state)
{
    return GetBusCenterEventDepsInterface()->SetScreenState(state);
}

struct WifiDirectManager *GetWifiDirectManager(void)
{
    return GetBusCenterEventDepsInterface()->GetWifiDirectManager();
}
}
} // namespace OHOS
