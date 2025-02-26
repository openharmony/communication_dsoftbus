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

#ifndef BUS_CENTER_EVENT_DEPS_MOCK_H
#define BUS_CENTER_EVENT_DEPS_MOCK_H

#include <gmock/gmock.h>

#include "auth_hichain_adapter.h"
#include "auth_manager.h"
#include "bus_center_client_proxy.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_device_info_recovery.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_heartbeat_medium_mgr.h"
#include "lnn_heartbeat_strategy.h"
#include "lnn_local_net_ledger.h"
#include "lnn_net_builder.h"
#include "lnn_node_info.h"
#include "lnn_ohos_account.h"
#include "message_handler.h"
#include "softbus_common.h"
#include "softbus_utils.h"
#include "wifi_direct_manager.h"

namespace OHOS {
class BusCenterEventDepsInterface {
public:
    BusCenterEventDepsInterface() {};
    virtual ~BusCenterEventDepsInterface() {};

    virtual void Anonymize(const char *plainStr, char **anonymizedStr);
    virtual void AnonymizeFree(char *anonymizedStr);
    virtual int32_t SetDefaultQdisc(void);
    virtual int32_t LnnGetAllOnlineNodeNum(int32_t *nodeNum);
    virtual int32_t LnnGetLocalNum64Info(InfoKey key, int64_t *info);
    virtual int32_t LnnIpcNotifyDeviceNotTrusted(const char *msg);
    virtual int32_t LnnIpcNotifyJoinResult(void *addr, uint32_t addrTypeLen, const char *networkId,
        int32_t retCode);
    virtual int32_t LnnIpcNotifyLeaveResult(const char *networkId, int32_t retCode);
    virtual int32_t LnnIpcNotifyTimeSyncResult(const char *pkgName, int32_t pid, const void *info,
        uint32_t infoTypeLen, int32_t retCode);
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info);
    virtual bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type);
    virtual DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type);
    virtual SoftBusLooper *CreateNewLooper(const char *name);
    virtual int32_t LnnIpcNotifyOnlineState(bool isOnline, void *info, uint32_t infoTypeLen);
    virtual void LnnDCProcessOnlineState(bool isOnline, const NodeBasicInfo *info);
    virtual int32_t LnnIpcNotifyBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type);
    virtual int32_t LnnGenLocalNetworkId(char *networkId, uint32_t len);
    virtual int32_t LnnIpcLocalNetworkIdChanged(void);
    virtual int32_t LnnSetLocalStrInfo(InfoKey key, const char *info);
    virtual void LnnUpdateAuthExchangeUdid(void);
    virtual bool LnnIsSameConnectionAddr(const ConnectionAddr *addr1, const ConnectionAddr *addr2, bool isShort) = 0;
    virtual int32_t LnnServerLeave(const char *networkId, const char *pkgName) = 0;
    virtual int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum) = 0;
    virtual bool LnnIsLSANode(const NodeBasicInfo *info) = 0;
    virtual int32_t LnnGetLocalDeviceInfo(NodeBasicInfo *info) = 0;
    virtual int32_t LnnGetNodeKeyInfo(const char *networkId, int32_t key, uint8_t *info, uint32_t infoLen) = 0;
    virtual int32_t LnnSetNodeDataChangeFlag(const char *networkId, uint16_t dataChangeFlag) = 0;
    virtual int32_t LnnStartTimeSync(const char *pkgName, int32_t callingPid, const char *targetNetworkId,
        TimeSyncAccuracy accuracy, TimeSyncPeriod period) = 0;
    virtual int32_t LnnStopTimeSync(const char *pkgName, const char *targetNetworkId, int32_t callingPid) = 0;
    virtual int32_t LnnPublishService(const char *pkgName, const PublishInfo *info, bool isInnerRequest) = 0;
    virtual int32_t LnnUnPublishService(const char *pkgName, int32_t publishId, bool isInnerRequest) = 0;
    virtual int32_t LnnStartDiscDevice(
        const char *pkgName, const SubscribeInfo *info, const InnerCallback *cb, bool isInnerRequest) = 0;
    virtual int32_t LnnStopDiscDevice(const char *pkgName, int32_t subscribeId, bool isInnerRequest) = 0;
    virtual int32_t LnnActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId) = 0;
    virtual int32_t LnnDeactiveMetaNode(const char *metaNodeId) = 0;
    virtual int32_t LnnGetAllMetaNodeInfo(MetaNodeInfo *infos, int32_t *infoNum) = 0;
    virtual int32_t LnnShiftLNNGear(
        const char *pkgName, const char *callerId, const char *targetNetworkId, const GearMode *mode) = 0;
    virtual int32_t ClientOnJoinLNNResult(
        PkgNameAndPidInfo *info, void *addr, uint32_t addrTypeLen, const char *networkId, int32_t retCode) = 0;
    virtual int32_t ClientOnLeaveLNNResult(
        const char *pkgName, int32_t pid, const char *networkId, int32_t retCode) = 0;
    virtual int32_t ClinetOnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen) = 0;
    virtual int32_t ClinetOnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type) = 0;
    virtual int32_t ClientOnTimeSyncResult(
        const char *pkgName, int32_t pid, const void *info, uint32_t infoTypeLen, int32_t retCode) = 0;
    virtual int32_t ClientOnPublishLNNResult(const char *pkgName, int32_t pid, int32_t publishId, int32_t reason) = 0;
    virtual int32_t ClientOnRefreshLNNResult(const char *pkgName, int32_t pid, int32_t refreshId, int32_t reason) = 0;
    virtual int32_t ClientOnRefreshDeviceFound(
        const char *pkgName, int32_t pid, const void *device, uint32_t deviceLen) = 0;
    virtual int32_t LnnServerJoin(ConnectionAddr *addr, const char *pkgName) = 0;
    virtual int32_t LnnEnableHeartbeatByType(LnnHeartbeatType type, bool isEnable) = 0;
    virtual int32_t LnnStartHbByTypeAndStrategy(
        LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategy, bool isRelay) = 0;
    virtual int32_t LnnStartHeartbeat(uint64_t delayMillis) = 0;
    virtual int32_t LnnStopHeartbeatByType(LnnHeartbeatType type) = 0;
    virtual int32_t LnnSetHbAsMasterNodeState(bool isMasterNode) = 0;
    virtual int32_t LnnUpdateSendInfoStrategy(LnnHeartbeatUpdateInfoType type) = 0;
    virtual int32_t LnnAsyncCallbackDelayHelper(
        SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis) = 0;
    virtual int32_t LnnSetCloudAbility(const bool isEnableCloud) = 0;
    virtual int32_t LnnDeleteSyncToDB(void) = 0;
    virtual void LnnOnOhosAccountLogout(void) = 0;
    virtual void LnnUpdateOhosAccount(UpdateAccountReason reason) = 0;
    virtual TrustedReturnType AuthHasTrustedRelation(void) = 0;
    virtual bool IsEnableSoftBusHeartbeat(void) = 0;
    virtual int32_t LnnSetMediumParamBySpecificType(const LnnHeartbeatMediumParam *param) = 0;
    virtual int32_t LnnGetLocalNodeInfoSafe(NodeInfo *info) = 0;
    virtual int32_t LnnLedgerAllDataSyncToDB(NodeInfo *info, bool isAckSeq, char *peerudid) = 0;
    virtual ConnectionAddrType LnnConvertHbTypeToConnAddrType(LnnHeartbeatType type) = 0;
    virtual int32_t LnnStopScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t LnnStartScreenChangeOfflineTiming(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual void LnnMapDelete(Map *map) = 0;
    virtual void ClearAuthLimitMap(void) = 0;
    virtual int32_t LnnStopHeartBeatAdvByTypeNow(LnnHeartbeatType registedHbType) = 0;
    virtual void RestartCoapDiscovery(void) = 0;
    virtual bool LnnIsLocalSupportBurstFeature(void) = 0;
    virtual void AuthLoadDeviceKey(void) = 0;
    virtual int32_t LnnGenerateCeParams(void) = 0;
    virtual void DfxRecordTriggerTime(LnnTriggerReason reason, LnnEventLnnStage stage) = 0;
    virtual int32_t LnnHbMediumMgrInit(void) = 0;
    virtual int32_t LnnStartNewHbStrategyFsm(void) = 0;
    virtual int32_t AuthSendKeepaliveOption(const char *uuid, ModeCycle cycle) = 0;
    virtual int32_t LnnSetGearModeBySpecificType(
        const char *callerId, const GearMode *mode, LnnHeartbeatType type) = 0;
    virtual void LnnDumpLocalBasicInfo(void) = 0;
    virtual bool LnnGetOnlineStateById(const char *id, IdCategory type) = 0;
    virtual int32_t AuthFlushDevice(const char *uuid) = 0;
    virtual int32_t LnnHbStrategyInit(void) = 0;
    virtual void LnnBleHbUnregDataLevelChangeCb(void) = 0;
    virtual int32_t LnnStopOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t HbBuildUserIdCheckSum(const int32_t *userIdArray, int32_t num, uint8_t *custData, int32_t len) = 0;
    virtual int32_t LnnSetLocalByteInfo(InfoKey key, const uint8_t *info, uint32_t len) = 0;
    virtual int32_t LnnStartHbByTypeAndStrategyEx(LnnProcessSendOnceMsgPara *msgPara) = 0;
    virtual int32_t LnnSyncBleOfflineMsg(void) = 0;
    virtual void LnnRemoveV0BroadcastAndCheckDev(void) = 0;
    virtual int32_t LnnNotifyDiscoveryDevice(
        const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport, bool isNeedConnect) = 0;
    virtual int32_t LnnNotifyMasterElect(const char *networkId, const char *masterUdid, int32_t masterWeight) = 0;
    virtual int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual AuthVerifyCallback *LnnGetReAuthVerifyCallback(void) = 0;
    virtual bool IsNeedAuthLimit(const char *udidHash) = 0;
    virtual bool IsExistLnnDfxNodeByUdidHash(const char *udidHash, LnnBleReportExtra *bleExtra) = 0;
    virtual int32_t LnnRetrieveDeviceInfo(const char *udid, NodeInfo *deviceInfo) = 0;
    virtual bool IsSameAccountGroupDevice(void) = 0;
    virtual uint32_t AuthGenRequestId(void) = 0;
    virtual int32_t AuthStartVerify(const AuthConnInfo *connInfo, uint32_t requestId,
        const AuthVerifyCallback *verifyCallback, AuthVerifyModule module, bool isFastAuth) = 0;
    virtual void AddNodeToLnnBleReportExtraMap(const char *udidHash, const LnnBleReportExtra *bleExtra) = 0;
    virtual int32_t GetNodeFromLnnBleReportExtraMap(const char *udidHash, LnnBleReportExtra *bleExtra) = 0;
    virtual void DeleteNodeFromLnnBleReportExtraMap(const char *udidHash) = 0;
    virtual int32_t LnnUpdateRemoteDeviceInfo(const NodeInfo *deviceInfo) = 0;
    virtual int32_t GetNodeFromPcRestrictMap(const char *udidHash, uint32_t *count) = 0;
    virtual int32_t LnnSetDLConnUserIdCheckSum(const char *networkId, int32_t userIdCheckSum) = 0;
    virtual void NotifyForegroundUseridChange(char *networkId, uint32_t discoveryType, bool isChange) = 0;
    virtual int32_t LnnStartOfflineTimingStrategy(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t LnnHbMediumMgrStop(LnnHeartbeatType *type) = 0;
    virtual void LnnDumpHbMgrRecvList(void) = 0;
    virtual void LnnDumpHbOnlineNodeList(void) = 0;
    virtual bool LnnIsHeartbeatEnable(LnnHeartbeatType type) = 0;
    virtual int32_t LnnGetGearModeBySpecificType(GearMode *mode, char *callerId, LnnHeartbeatType type) = 0;
    virtual int32_t LnnOfflineTimingByHeartbeat(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t LnnHbMediumMgrSendBegin(LnnHeartbeatSendBeginData *custData) = 0;
    virtual int32_t LnnHbMediumMgrSendEnd(LnnHeartbeatSendEndData *type) = 0;
    virtual int32_t LnnGetHbStrategyManager(
        LnnHeartbeatStrategyManager *mgr, LnnHeartbeatType hbType, LnnHeartbeatStrategyType strategyType) = 0;
    virtual int32_t LnnHbMediumMgrSetParam(void *param) = 0;
    virtual int32_t LnnHbMediumMgrUpdateSendInfo(LnnHeartbeatUpdateInfoType type) = 0;
    virtual int32_t StopHeartBeatAdvByTypeNow(LnnHeartbeatType registedHbType) = 0;
    virtual SoftBusScreenState GetScreenState(void) = 0;
    virtual void SetScreenState(SoftBusScreenState state) = 0;
    virtual struct WifiDirectManager *GetWifiDirectManager(void) = 0;
};

class BusCenterEventDepsInterfaceMock : public BusCenterEventDepsInterface {
public:
    BusCenterEventDepsInterfaceMock();
    ~BusCenterEventDepsInterfaceMock() override;

    MOCK_METHOD2(Anonymize, void (const char *, char **));
    MOCK_METHOD1(AnonymizeFree, void (char *));
    MOCK_METHOD0(SetDefaultQdisc, int32_t (void));
    MOCK_METHOD1(LnnGetAllOnlineNodeNum, int32_t (int32_t *));
    MOCK_METHOD2(LnnGetLocalNum64Info, int32_t  (InfoKey key, int64_t *info));
    MOCK_METHOD1(LnnIpcNotifyDeviceNotTrusted, int32_t (const char *));
    MOCK_METHOD4(LnnIpcNotifyJoinResult, int32_t  (void *, uint32_t, const char *, int32_t));
    MOCK_METHOD2(LnnIpcNotifyLeaveResult, int32_t  (const char *, int32_t));
    MOCK_METHOD5(LnnIpcNotifyTimeSyncResult, int32_t  (const char *, int32_t, const void *, uint32_t, int32_t));
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t  (const char *, IdCategory, NodeInfo *));
    MOCK_METHOD2(LnnHasDiscoveryType, bool  (const NodeInfo *, DiscoveryType));
    MOCK_METHOD1(LnnConvAddrTypeToDiscType, DiscoveryType (ConnectionAddrType));
    MOCK_METHOD1(CreateNewLooper, SoftBusLooper * (const char *));
    MOCK_METHOD3(LnnIpcNotifyOnlineState, int32_t (bool, void *, uint32_t));
    MOCK_METHOD2(LnnDCProcessOnlineState, void (bool, const NodeBasicInfo *));
    MOCK_METHOD3(LnnIpcNotifyBasicInfoChanged, int32_t (void *, uint32_t, int32_t));
    MOCK_METHOD2(LnnGenLocalNetworkId, int32_t (char *, uint32_t));
    MOCK_METHOD0(LnnIpcLocalNetworkIdChanged, int32_t (void));
    MOCK_METHOD2(LnnSetLocalStrInfo, int32_t (InfoKey, const char *));
    MOCK_METHOD0(LnnUpdateAuthExchangeUdid, void (void));
    MOCK_METHOD3(LnnIsSameConnectionAddr, bool(const ConnectionAddr *, const ConnectionAddr *, bool));
    MOCK_METHOD2(LnnServerLeave, int32_t(const char *, const char *));
    MOCK_METHOD2(LnnGetAllOnlineNodeInfo, int32_t(NodeBasicInfo **, int32_t *));
    MOCK_METHOD1(LnnIsLSANode, bool(const NodeBasicInfo *));
    MOCK_METHOD1(LnnGetLocalDeviceInfo, int32_t(NodeBasicInfo *));
    MOCK_METHOD4(LnnGetNodeKeyInfo, int32_t(const char *, int, uint8_t *, uint32_t));
    MOCK_METHOD2(LnnSetNodeDataChangeFlag, int32_t(const char *, uint16_t));
    MOCK_METHOD5(LnnStartTimeSync, int32_t(const char *, int32_t, const char *, TimeSyncAccuracy, TimeSyncPeriod));
    MOCK_METHOD3(LnnStopTimeSync, int32_t(const char *, const char *, int32_t));
    MOCK_METHOD3(LnnPublishService, int32_t(const char *, const PublishInfo *, bool));
    MOCK_METHOD3(LnnUnPublishService, int32_t(const char *, int32_t, bool));
    MOCK_METHOD4(LnnStartDiscDevice, int32_t(const char *, const SubscribeInfo *, const InnerCallback *, bool));
    MOCK_METHOD3(LnnStopDiscDevice, int32_t(const char *, int32_t, bool));
    MOCK_METHOD2(LnnActiveMetaNode, int32_t(const MetaNodeConfigInfo *, char *));
    MOCK_METHOD1(LnnDeactiveMetaNode, int32_t(const char *));
    MOCK_METHOD2(LnnGetAllMetaNodeInfo, int32_t(MetaNodeInfo *, int32_t *));
    MOCK_METHOD4(LnnShiftLNNGear, int32_t(const char *, const char *, const char *, const GearMode *));
    MOCK_METHOD5(ClientOnJoinLNNResult, int32_t(PkgNameAndPidInfo *, void *, uint32_t, const char *, int32_t));
    MOCK_METHOD4(ClientOnLeaveLNNResult, int32_t(const char *, int32_t, const char *, int32_t));
    MOCK_METHOD3(ClinetOnNodeOnlineStateChanged, int32_t(bool, void *, uint32_t));
    MOCK_METHOD3(ClinetOnNodeBasicInfoChanged, int32_t(void *, uint32_t, int32_t));
    MOCK_METHOD5(ClientOnTimeSyncResult, int32_t(const char *, int32_t, const void *, uint32_t, int32_t));
    MOCK_METHOD4(ClientOnPublishLNNResult, int32_t(const char *, int32_t, int32_t, int32_t));
    MOCK_METHOD4(ClientOnRefreshLNNResult, int32_t(const char *, int32_t, int32_t, int32_t));
    MOCK_METHOD4(ClientOnRefreshDeviceFound, int32_t(const char *, int32_t, const void *, uint32_t));
    MOCK_METHOD2(LnnServerJoin, int32_t(ConnectionAddr *, const char *));
    MOCK_METHOD2(LnnEnableHeartbeatByType, int32_t(LnnHeartbeatType, bool));
    MOCK_METHOD3(LnnStartHbByTypeAndStrategy, int32_t(LnnHeartbeatType, LnnHeartbeatStrategyType, bool));
    MOCK_METHOD1(LnnStartHeartbeat, int32_t(uint64_t));
    MOCK_METHOD1(LnnStopHeartbeatByType, int32_t(LnnHeartbeatType));
    MOCK_METHOD1(LnnSetHbAsMasterNodeState, int32_t(bool));
    MOCK_METHOD1(LnnUpdateSendInfoStrategy, int32_t(LnnHeartbeatUpdateInfoType));
    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t(SoftBusLooper *, LnnAsyncCallbackFunc, void *, uint64_t));
    MOCK_METHOD1(LnnSetCloudAbility, int32_t(const bool));
    MOCK_METHOD0(LnnDeleteSyncToDB, int32_t());
    MOCK_METHOD0(LnnOnOhosAccountLogout, void(void));
    MOCK_METHOD1(LnnUpdateOhosAccount, void(UpdateAccountReason));
    MOCK_METHOD0(AuthHasTrustedRelation, TrustedReturnType(void));
    MOCK_METHOD0(IsEnableSoftBusHeartbeat, bool(void));
    MOCK_METHOD1(LnnSetMediumParamBySpecificType, int32_t(const LnnHeartbeatMediumParam *));
    MOCK_METHOD1(LnnGetLocalNodeInfoSafe, int32_t(NodeInfo *info));
    MOCK_METHOD3(LnnLedgerAllDataSyncToDB, int32_t(NodeInfo *info, bool, char *));
    MOCK_METHOD1(LnnConvertHbTypeToConnAddrType, ConnectionAddrType(LnnHeartbeatType type));
    MOCK_METHOD2(LnnStopScreenChangeOfflineTiming, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD2(LnnStartScreenChangeOfflineTiming, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD1(LnnMapDelete, void(Map *));
    MOCK_METHOD0(ClearAuthLimitMap, void(void));
    MOCK_METHOD1(LnnStopHeartBeatAdvByTypeNow, int32_t(LnnHeartbeatType));
    MOCK_METHOD0(RestartCoapDiscovery, void(void));
    MOCK_METHOD0(LnnIsLocalSupportBurstFeature, bool(void));
    MOCK_METHOD0(AuthLoadDeviceKey, void(void));
    MOCK_METHOD0(LnnGenerateCeParams, int32_t(void));
    MOCK_METHOD2(DfxRecordTriggerTime, void(LnnTriggerReason, LnnEventLnnStage));
    MOCK_METHOD0(LnnHbMediumMgrInit, int32_t(void));
    MOCK_METHOD0(LnnStartNewHbStrategyFsm, int32_t(void));
    MOCK_METHOD2(AuthSendKeepaliveOption, int32_t(const char *, ModeCycle));
    MOCK_METHOD3(LnnSetGearModeBySpecificType, int32_t(const char *, const GearMode *, LnnHeartbeatType));
    MOCK_METHOD0(LnnDumpLocalBasicInfo, void(void));
    MOCK_METHOD2(LnnGetOnlineStateById, bool(const char *, IdCategory));
    MOCK_METHOD1(AuthFlushDevice, int32_t(const char *));
    MOCK_METHOD0(LnnHbStrategyInit, int32_t(void));
    MOCK_METHOD0(LnnBleHbUnregDataLevelChangeCb, void(void));
    MOCK_METHOD2(LnnStopOfflineTimingStrategy, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD4(
        HbBuildUserIdCheckSum, int32_t(const int32_t *userIdArray, int32_t num, uint8_t *custData, int32_t len));
    MOCK_METHOD3(LnnSetLocalByteInfo, int32_t(InfoKey, const uint8_t *, uint32_t));
    MOCK_METHOD1(LnnStartHbByTypeAndStrategyEx, int32_t (LnnProcessSendOnceMsgPara *));
    MOCK_METHOD0(LnnSyncBleOfflineMsg, int32_t (void));
    MOCK_METHOD0(LnnRemoveV0BroadcastAndCheckDev, void (void));
    MOCK_METHOD3(LnnNotifyDiscoveryDevice, int32_t(const ConnectionAddr *, const LnnDfxDeviceInfoReport *, bool));
    MOCK_METHOD3(LnnNotifyMasterElect, int32_t(const char *, const char *, int32_t));
    MOCK_METHOD2(LnnRequestLeaveSpecific, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD0(LnnGetReAuthVerifyCallback, AuthVerifyCallback *(void));
    MOCK_METHOD1(IsNeedAuthLimit, bool(const char *));
    MOCK_METHOD2(IsExistLnnDfxNodeByUdidHash, bool(const char *, LnnBleReportExtra *));
    MOCK_METHOD2(LnnRetrieveDeviceInfo, int32_t(const char *, NodeInfo *));
    MOCK_METHOD0(IsSameAccountGroupDevice, bool(void));
    MOCK_METHOD0(AuthGenRequestId, uint32_t(void));
    MOCK_METHOD5(
        AuthStartVerify, int32_t(const AuthConnInfo *, uint32_t, const AuthVerifyCallback *, AuthVerifyModule, bool));
    MOCK_METHOD2(AddNodeToLnnBleReportExtraMap, void(const char *, const LnnBleReportExtra *));
    MOCK_METHOD2(GetNodeFromLnnBleReportExtraMap, int32_t(const char *, LnnBleReportExtra *));
    MOCK_METHOD1(DeleteNodeFromLnnBleReportExtraMap, void(const char *));
    MOCK_METHOD1(LnnUpdateRemoteDeviceInfo, int32_t(const NodeInfo *));
    MOCK_METHOD2(GetNodeFromPcRestrictMap, int32_t(const char *, uint32_t *));
    MOCK_METHOD2(LnnSetDLConnUserIdCheckSum, int32_t(const char *networkId, int32_t userIdCheckSum));
    MOCK_METHOD3(NotifyForegroundUseridChange, void(char *, uint32_t, bool));
    MOCK_METHOD2(LnnStartOfflineTimingStrategy, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD1(LnnHbMediumMgrStop, int32_t(LnnHeartbeatType *));
    MOCK_METHOD0(LnnDumpHbMgrRecvList, void(void));
    MOCK_METHOD0(LnnDumpHbOnlineNodeList, void(void));
    MOCK_METHOD1(LnnIsHeartbeatEnable, bool(LnnHeartbeatType));
    MOCK_METHOD3(LnnGetGearModeBySpecificType, int32_t(GearMode *, char *, LnnHeartbeatType));
    MOCK_METHOD2(LnnOfflineTimingByHeartbeat, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD1(LnnHbMediumMgrSendBegin, int32_t(LnnHeartbeatSendBeginData *));
    MOCK_METHOD1(LnnHbMediumMgrSendEnd, int32_t(LnnHeartbeatSendEndData *));
    MOCK_METHOD3(
        LnnGetHbStrategyManager, int32_t(LnnHeartbeatStrategyManager *, LnnHeartbeatType, LnnHeartbeatStrategyType));
    MOCK_METHOD1(LnnHbMediumMgrSetParam, int32_t(void *));
    MOCK_METHOD1(LnnHbMediumMgrUpdateSendInfo, int32_t(LnnHeartbeatUpdateInfoType));
    MOCK_METHOD1(StopHeartBeatAdvByTypeNow, int32_t(LnnHeartbeatType));
    MOCK_METHOD0(GetScreenState, SoftBusScreenState(void));
    MOCK_METHOD1(SetScreenState, void(SoftBusScreenState));
    MOCK_METHOD0(GetWifiDirectManager, WifiDirectManager *(void));
};
} // namespace OHOS
#endif // BUS_CENTER_EVENT_DEPS_MOCK_H
