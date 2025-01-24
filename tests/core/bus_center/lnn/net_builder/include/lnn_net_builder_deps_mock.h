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

#ifndef LNN_NET_BUILDER_DEPS_MOCK_H
#define LNN_NET_BUILDER_DEPS_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_interface.h"
#include "auth_request.h"
#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_async_callback_utils.h"
#include "lnn_battery_info.h"
#include "lnn_bus_center_ipc.h"
#include "lnn_connection_addr_utils.h"
#include "lnn_connection_fsm.h"
#include "lnn_deviceinfo_to_profile.h"
#include "lnn_devicename_info.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_fast_offline.h"
#include "lnn_local_net_ledger.h"
#include "lnn_net_capability.h"
#include "lnn_network_id.h"
#include "lnn_network_info.h"
#include "lnn_network_manager.h"
#include "lnn_node_info.h"
#include "lnn_node_weight.h"
#include "lnn_ohos_account.h"
#include "lnn_p2p_info.h"
#include "lnn_physical_subnet_manager.h"
#include "lnn_settingdata_event_monitor.h"
#include "lnn_state_machine.h"
#include "lnn_sync_info_manager.h"
#include "lnn_sync_item_info.h"
#include "lnn_topo_manager.h"
#include "message_handler.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_timer.h"
#include "softbus_bus_center.h"
#include "softbus_conn_interface.h"
#include "softbus_feature_config.h"
#include "softbus_json_utils.h"

namespace OHOS {
class NetBuilderDepsInterface {
public:
    NetBuilderDepsInterface() {};
    virtual ~NetBuilderDepsInterface() {};
    virtual int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size) = 0;
    virtual int32_t LnnDeleteMetaInfo(const char *udid, AuthLinkType type) = 0;
    virtual int32_t TransGetConnByChanId(int32_t channelId, int32_t channelType, int32_t *connId) = 0;
    virtual int32_t AuthMetaStartVerify(uint32_t connectionId, const AuthKeyInfo *authKeyInfo, uint32_t requestId,
        int32_t callingPid, const AuthVerifyCallback *callBack) = 0;
    virtual uint32_t AuthGenRequestId(void) = 0;
    virtual void LnnSetUnlockState(void) = 0;
    virtual void AuthHandleLeaveLNN(AuthHandle authHandle) = 0;
    virtual LnnConnectionFsm *LnnCreateConnectionFsm(
        const ConnectionAddr *target, const char *pkgName, bool isNeedConnect);
    virtual int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len);
    virtual int32_t LnnSetLocalStrInfo(InfoKey key, const char *info);
    virtual int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info);
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len);
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info);
    virtual int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info);
    virtual int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len);
    virtual int32_t LnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len);
    virtual int32_t LnnGetRemoteNumInfo(const char *netWorkId, InfoKey key, int32_t *info);
    virtual int32_t LnnGetRemoteNumU32Info(const char *netWorkId, InfoKey key, uint32_t *info);
    virtual bool LnnIsSameConnectionAddr(const ConnectionAddr *addr1, const ConnectionAddr *addr2, bool isShort);
    virtual bool LnnConvertAddrToOption(const ConnectionAddr *addr, ConnectOption *option);
    virtual DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type);
    virtual ConnectionAddrType LnnDiscTypeToConnAddrType(DiscoveryType type);
    virtual bool LnnConvertAuthConnInfoToAddr(
        ConnectionAddr *addr, const AuthConnInfo *connInfo, ConnectionAddrType hintType);
    virtual bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value);
    virtual bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num);
    virtual int32_t LnnSendSyncInfoMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len,
        LnnSyncInfoMsgComplete complete);
    virtual NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type);
    virtual int32_t LnnUpdateNodeInfo(NodeInfo *newInfo, int32_t connectionType);
    virtual int32_t LnnAddMetaInfo(NodeInfo *info);
    virtual int32_t AuthGetLatestAuthSeqList(const char *udid, int64_t *authSeq, uint32_t num);
    virtual int32_t LnnConvertDlId(
        const char *srcId, IdCategory srcIdType, IdCategory dstIdType, char *dstIdBuf, uint32_t dstIdBufLen);
    virtual bool LnnGetOnlineStateById(const char *id, IdCategory type);
    virtual bool LnnIsNodeOnline(const NodeInfo *info);
    virtual int32_t LnnSetSupportDiscoveryType(char *info, const char *type) = 0;
    virtual bool LnnHasSupportDiscoveryType(const char *destType, const char *type) = 0;
    virtual bool LnnPeerHasExchangeDiscoveryType(const NodeInfo *info, DiscoveryType type) = 0;
    virtual const char *LnnGetDeviceUdid(const NodeInfo *info);
    virtual int32_t LnnCompareNodeWeight(
        int32_t weight1, const char *masterUdid1, int32_t weight2, const char *masterUdid2);
    virtual void LnnNotifyAllTypeOffline(ConnectionAddrType type);
    virtual int32_t SoftBusGetTime(SoftBusSysTime *sysTime);
    virtual int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo);
    virtual void LnnNotifyLeaveResult(const char *networkId, int32_t retCode);
    virtual int32_t LnnGetAddrTypeByIfName(const char *ifName, ConnectionAddrType *type);
    virtual int32_t LnnSendNotTrustedInfo(
        const NotTrustedDelayInfo *info, uint32_t num, LnnSyncInfoMsgComplete complete);
    virtual int32_t LnnAsyncCallbackDelayHelper(
        SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis);
    virtual SoftBusLooper *GetLooper(int32_t looper);
    virtual int32_t ConnDisconnectDeviceAllConn(const ConnectOption *option);
    virtual int32_t LnnGenLocalIrk(unsigned char *irk, uint32_t len);
    virtual int32_t LnnGenLocalUuid(char *uuid, uint32_t len);
    virtual int32_t LnnGenLocalNetworkId(char *networkId, uint32_t len);
    virtual int32_t LnnSetDLNodeAddr(const char *id, IdCategory type, const char *addr);
    virtual int32_t LnnSetDLProxyPort(const char *id, IdCategory type, int32_t proxyPort);
    virtual int32_t LnnSetDLSessionPort(const char *id, IdCategory type, int32_t sessionPort);
    virtual int32_t LnnSetDLAuthPort(const char *id, IdCategory type, int32_t authPort);
    virtual int32_t LnnInitP2p(void);
    virtual void LnnDeinitP2p(void);
    virtual int32_t LnnInitWifiDirect(void);
    virtual void LnnDeinitWifiDirect(void);
    virtual int32_t LnnInitNetworkInfo(void);
    virtual int32_t LnnInitDevicename(void);
    virtual int32_t LnnInitSyncInfoManager(void);
    virtual void LnnDeinitSyncInfoManager(void);
    virtual int32_t LnnInitTopoManager(void);
    virtual void LnnDeinitTopoManager(void);
    virtual int32_t RegAuthVerifyListener(const AuthVerifyListener *listener);
    virtual void UnregAuthVerifyListener(void);
    virtual int32_t LnnRegSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler);
    virtual int32_t LnnUnregSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler);
    virtual int32_t LnnStopConnectionFsm(LnnConnectionFsm *connFsm, LnnConnectionFsmStopCallback callback);
    virtual void LnnDeinitFastOffline(void);
    virtual int32_t LnnSendNewNetworkOnlineToConnFsm(LnnConnectionFsm *connFsm);
    virtual int32_t LnnSendAuthResultMsgToConnFsm(LnnConnectionFsm *connFsm, int32_t retCode);
    virtual int32_t LnnSendDisconnectMsgToConnFsm(LnnConnectionFsm *connFsm);
    virtual int32_t LnnSendNotTrustedToConnFsm(LnnConnectionFsm *connFsm);
    virtual int32_t LnnSendLeaveRequestToConnFsm(LnnConnectionFsm *connFsm);
    virtual int32_t LnnSendSyncOfflineFinishToConnFsm(LnnConnectionFsm *connFsm);
    virtual int32_t LnnGetLocalWeight(void);
    virtual void AuthMetaReleaseVerify(int64_t authId);
    virtual int32_t LnnSendJoinRequestToConnFsm(LnnConnectionFsm *connFsm);
    virtual void LnnNotifyJoinResult(ConnectionAddr *addr, const char *networkId, int32_t retCode);
    virtual void LnnDestroyConnectionFsm(LnnConnectionFsm *connFsm);
    virtual int32_t LnnStartConnectionFsm(LnnConnectionFsm *connFsm);
    virtual bool LnnIsNeedCleanConnectionFsm(const NodeInfo *nodeInfo, ConnectionAddrType type);
    virtual int32_t AuthFlushDevice(const char *uuid);
    virtual void LnnNotifyMasterNodeChanged(bool isMaster, const char *masterNodeUdid, int32_t weight);
    virtual int32_t LnnInitFastOffline(void);
    virtual int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum);
    virtual bool LnnIsLSANode(const NodeBasicInfo *info) = 0;
    virtual void LnnNotifyNodeAddressChanged(const char *addr, const char *networkId, bool isLocal);
    virtual int32_t LnnInitOffline(void);
    virtual void LnnDeinitOffline(void);
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info);
    virtual bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type);
    virtual const char *LnnConvertDLidToUdid(const char *id, IdCategory type);
    virtual int32_t GetAuthRequest(uint32_t requestId, AuthRequest *request);
    virtual int32_t SoftBusGetBtState(void);
    virtual int32_t SoftBusGetBrState(void);
    virtual int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type);
    virtual int32_t LnnClearNetCapability(uint32_t *capability, NetCapability type);
    virtual int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler);
    virtual void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler);
    virtual void LnnNotifyDeviceVerified(const char *udid);
    virtual int32_t LnnInitBusCenterEvent(void);
    virtual int32_t LnnInitBatteryInfo(void);
    virtual void LnnDeinitBatteryInfo(void);
    virtual int32_t LnnSetLocalByteInfo(InfoKey key, const uint8_t *info, uint32_t len);
    virtual void LnnDeinitNetworkInfo(void);
    virtual void LnnDeinitDevicename(void);
    virtual const NodeInfo *LnnGetLocalNodeInfo(void);
    virtual void LnnRemoveNode(const char *udid);
    virtual int32_t LnnClearDiscoveryType(NodeInfo *info, DiscoveryType type);
    virtual const char *LnnPrintConnectionAddr(const ConnectionAddr *addr);
    virtual int32_t LnnUpdateGroupType(const NodeInfo *info);
    virtual int32_t LnnUpdateAccountInfo(const NodeInfo *info);
    virtual int32_t LnnUpdateRemoteDeviceName(const NodeInfo *info);
    virtual bool LnnConvertAddrToAuthConnInfo(const ConnectionAddr *addr, AuthConnInfo *connInfo);
    virtual int32_t LnnFsmRemoveMessageByType(FsmStateMachine *fsm, int32_t what);
    virtual void LnnDeinitBusCenterEvent(void);
    virtual int32_t AuthStartVerify(const AuthConnInfo *connInfo, uint32_t requestId,
        const AuthVerifyCallback *callback, AuthVerifyModule module, bool isFastAuth);
    virtual bool IsSupportLpFeature(void);
    virtual bool LnnSubcribeKvStoreService(void);
    virtual void LnnNotifyLocalNetworkIdChanged(void);
    virtual int32_t TransAuthGetConnIdByChanId(int32_t channelId, int32_t *connId) = 0;
    virtual int32_t TransAuthGetPeerUdidByChanId(int32_t channelId, char *peerUdid, uint32_t len) = 0;
    virtual void LnnNotifyStateForSession(char *udid, int32_t retCode) = 0;
    virtual void AuthRemoveAuthManagerByAuthHandle(AuthHandle authHandle) = 0;
    virtual bool LnnIsDefaultOhosAccount() = 0;
    virtual void DeleteFromProfile(const char *udid) = 0;
    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
    virtual void UpdateProfile(const NodeInfo *info) = 0;
    virtual bool IsSupportFeatureByCapaBit(uint32_t feature, AuthCapability capaBit) = 0;
    virtual int32_t LnnGetRemoteNodeInfoByKey(const char *key, NodeInfo *info) = 0;
    virtual void RegisterOOBEMonitor(void *p);
    virtual bool CheckRemoteBasicInfoChanged(const NodeInfo *newNodeInfo);
    virtual int32_t ProcessBleOnline(NodeInfo *nodeInfo, const ConnectionAddr *connAddr, AuthCapability authCapability);
    virtual int32_t CheckAuthChannelIsExit(ConnectOption *connInfo);
    virtual void GetLnnTriggerInfo(LnnTriggerInfo *triggerInfo) = 0;
    virtual int32_t LnnSetDLConnUserIdCheckSum(const char *networkId, int32_t userIdCheckSum) = 0;
    virtual void LnnNotifyDeviceTrustedChange(int32_t type, const char *msg, uint32_t msgLen) = 0;
    virtual void LnnGetDataShareInitResult(bool *isDataShareInit) = 0;
};
class NetBuilderDepsInterfaceMock : public NetBuilderDepsInterface {
public:
    NetBuilderDepsInterfaceMock();
    ~NetBuilderDepsInterfaceMock() override;
    MOCK_METHOD3(AuthGetDeviceUuid, int32_t(int64_t, char *, uint16_t));
    MOCK_METHOD2(LnnDeleteMetaInfo, int32_t(const char *, AuthLinkType));
    MOCK_METHOD3(TransGetConnByChanId, int32_t(int32_t, int32_t, int32_t *));
    MOCK_METHOD5(
        AuthMetaStartVerify, int32_t(uint32_t, const AuthKeyInfo *, uint32_t, int32_t, const AuthVerifyCallback *));
    MOCK_METHOD0(AuthGenRequestId, uint32_t());
    MOCK_METHOD0(LnnSetUnlockState, void());
    MOCK_METHOD1(AuthHandleLeaveLNN, void(AuthHandle));
    MOCK_METHOD3(SoftbusGetConfig, int32_t(ConfigType, unsigned char *, uint32_t));
    MOCK_METHOD2(LnnSetLocalStrInfo, int32_t(InfoKey, const char *));
    MOCK_METHOD2(LnnSetLocalNumInfo, int32_t(InfoKey, int32_t));
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t(InfoKey, char *, uint32_t));
    MOCK_METHOD2(LnnGetLocalNumInfo, int32_t(InfoKey, int32_t *));
    MOCK_METHOD2(LnnGetLocalNumU32Info, int32_t(InfoKey, uint32_t *));
    MOCK_METHOD3(LnnGetNetworkIdByUdid, int32_t(const char *, char *, uint32_t));
    MOCK_METHOD4(LnnGetRemoteStrInfo, int32_t(const char *, InfoKey, char *, uint32_t));
    MOCK_METHOD3(LnnGetRemoteNumInfo, int32_t(const char *, InfoKey, int32_t *));
    MOCK_METHOD3(LnnGetRemoteNumU32Info, int32_t(const char *, InfoKey, uint32_t *));
    MOCK_METHOD3(LnnIsSameConnectionAddr, bool(const ConnectionAddr *, const ConnectionAddr *, bool));
    MOCK_METHOD2(LnnConvertAddrToOption, bool(const ConnectionAddr *, ConnectOption *));
    MOCK_METHOD1(LnnConvAddrTypeToDiscType, DiscoveryType(ConnectionAddrType));
    MOCK_METHOD1(LnnDiscTypeToConnAddrType, ConnectionAddrType(DiscoveryType));
    MOCK_METHOD3(LnnConvertAuthConnInfoToAddr, bool(ConnectionAddr *, const AuthConnInfo *, ConnectionAddrType));
    MOCK_METHOD3(AddStringToJsonObject, bool(cJSON *, const char * const, const char *));
    MOCK_METHOD3(AddNumberToJsonObject, bool(cJSON *, const char * const, int));
    MOCK_METHOD5(
        LnnSendSyncInfoMsg, int32_t(LnnSyncInfoType, const char *, const uint8_t *, uint32_t, LnnSyncInfoMsgComplete));
    MOCK_METHOD2(LnnGetNodeInfoById, NodeInfo *(const char *, IdCategory));
    MOCK_METHOD2(LnnUpdateNodeInfo, int32_t(NodeInfo *, int32_t));
    MOCK_METHOD1(LnnAddMetaInfo, int32_t(NodeInfo *));
    MOCK_METHOD3(AuthGetLatestAuthSeqList, int32_t(const char *, int64_t *, uint32_t));
    MOCK_METHOD5(LnnConvertDlId, int32_t(const char *, IdCategory, IdCategory, char *, uint32_t));
    MOCK_METHOD2(LnnGetOnlineStateById, bool(const char *, IdCategory));
    MOCK_METHOD1(LnnIsNodeOnline, bool(const NodeInfo *));
    MOCK_METHOD2(LnnSetSupportDiscoveryType, int32_t(char *, const char *));
    MOCK_METHOD2(LnnHasSupportDiscoveryType, bool(const char *, const char *));
    MOCK_METHOD2(LnnPeerHasExchangeDiscoveryType, bool(const NodeInfo *, DiscoveryType));
    MOCK_METHOD1(LnnGetDeviceUdid, const char *(const NodeInfo *));
    MOCK_METHOD4(LnnCompareNodeWeight, int32_t(int32_t, const char *, int32_t, const char *));
    MOCK_METHOD1(LnnNotifyAllTypeOffline, void(ConnectionAddrType));
    MOCK_METHOD1(SoftBusGetTime, int32_t(SoftBusSysTime *));
    MOCK_METHOD2(AuthGetConnInfo, int32_t(AuthHandle, AuthConnInfo *));
    MOCK_METHOD2(LnnNotifyLeaveResult, void(const char *, int32_t));
    MOCK_METHOD2(LnnGetAddrTypeByIfName, int32_t(const char *, ConnectionAddrType *));
    MOCK_METHOD3(LnnSendNotTrustedInfo, int32_t(const NotTrustedDelayInfo *, uint32_t, LnnSyncInfoMsgComplete));
    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t(SoftBusLooper *, LnnAsyncCallbackFunc, void *, uint64_t));
    MOCK_METHOD1(GetLooper, SoftBusLooper *(int));
    MOCK_METHOD1(ConnDisconnectDeviceAllConn, int32_t(const ConnectOption *));
    MOCK_METHOD2(LnnGenLocalUuid, int32_t(char *, uint32_t));
    MOCK_METHOD2(LnnGenLocalIrk, int32_t(unsigned char *, uint32_t));
    MOCK_METHOD2(LnnGenLocalNetworkId, int32_t(char *, uint32_t));
    MOCK_METHOD3(LnnSetDLNodeAddr, int32_t(const char *, IdCategory, const char *));
    MOCK_METHOD3(LnnSetDLProxyPort, int32_t(const char *, IdCategory, int32_t));
    MOCK_METHOD3(LnnSetDLSessionPort, int32_t(const char *, IdCategory, int32_t));
    MOCK_METHOD3(LnnSetDLAuthPort, int32_t(const char *, IdCategory, int32_t));
    MOCK_METHOD0(LnnInitP2p, int32_t());
    MOCK_METHOD0(LnnDeinitP2p, void());
    MOCK_METHOD0(LnnInitWifiDirect, int32_t());
    MOCK_METHOD0(LnnDeinitWifiDirect, void());
    MOCK_METHOD0(LnnInitNetworkInfo, int32_t());
    MOCK_METHOD0(LnnInitDevicename, int32_t());
    MOCK_METHOD0(LnnInitSyncInfoManager, int32_t());
    MOCK_METHOD0(LnnDeinitSyncInfoManager, void());
    MOCK_METHOD0(LnnInitTopoManager, int32_t());
    MOCK_METHOD0(LnnDeinitTopoManager, void());
    MOCK_METHOD1(RegAuthVerifyListener, int32_t(const AuthVerifyListener *));
    MOCK_METHOD0(UnregAuthVerifyListener, void());
    MOCK_METHOD2(LnnRegSyncInfoHandler, int32_t(LnnSyncInfoType, LnnSyncInfoMsgHandler));
    MOCK_METHOD2(LnnUnregSyncInfoHandler, int32_t(LnnSyncInfoType, LnnSyncInfoMsgHandler));
    MOCK_METHOD2(LnnStopConnectionFsm, int32_t(LnnConnectionFsm *, LnnConnectionFsmStopCallback));
    MOCK_METHOD0(LnnDeinitFastOffline, void());
    MOCK_METHOD1(LnnSendNewNetworkOnlineToConnFsm, int32_t(LnnConnectionFsm *));
    MOCK_METHOD2(LnnSendAuthResultMsgToConnFsm, int32_t(LnnConnectionFsm *, int32_t));
    MOCK_METHOD1(LnnSendDisconnectMsgToConnFsm, int32_t(LnnConnectionFsm *));
    MOCK_METHOD1(LnnSendNotTrustedToConnFsm, int32_t(LnnConnectionFsm *));
    MOCK_METHOD1(LnnSendLeaveRequestToConnFsm, int32_t(LnnConnectionFsm *));
    MOCK_METHOD1(LnnSendSyncOfflineFinishToConnFsm, int32_t(LnnConnectionFsm *));
    MOCK_METHOD0(LnnGetLocalWeight, int32_t());
    MOCK_METHOD1(AuthMetaReleaseVerify, void(int64_t));
    MOCK_METHOD1(LnnSendJoinRequestToConnFsm, int32_t(LnnConnectionFsm *));
    MOCK_METHOD3(LnnNotifyJoinResult, void(ConnectionAddr *, const char *, int32_t));
    MOCK_METHOD1(LnnDestroyConnectionFsm, void(LnnConnectionFsm *));
    MOCK_METHOD3(LnnCreateConnectionFsm,
        LnnConnectionFsm *(const ConnectionAddr *target, const char *pkgName, bool isNeedConnect));
    MOCK_METHOD1(LnnStartConnectionFsm, int32_t(LnnConnectionFsm *));
    MOCK_METHOD3(LnnNotifyMasterNodeChanged, void(bool, const char *, int32_t));
    MOCK_METHOD0(LnnInitFastOffline, int32_t());
    MOCK_METHOD2(LnnGetAllOnlineNodeInfo, int32_t(NodeBasicInfo **, int32_t *));
    MOCK_METHOD1(LnnIsLSANode, bool(const NodeBasicInfo *));
    MOCK_METHOD3(LnnNotifyNodeAddressChanged, void(const char *, const char *, bool));
    MOCK_METHOD0(LnnInitOffline, int32_t());
    MOCK_METHOD0(LnnDeinitOffline, void());
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t(const char *, IdCategory, NodeInfo *));
    MOCK_METHOD2(LnnHasDiscoveryType, bool(const NodeInfo *, DiscoveryType));
    MOCK_METHOD2(LnnConvertDLidToUdid, const char *(const char *, IdCategory));
    MOCK_METHOD2(GetAuthRequest, int32_t(uint32_t, AuthRequest *));
    MOCK_METHOD0(SoftBusGetBtState, int32_t());
    MOCK_METHOD0(SoftBusGetBrState, int32_t());
    MOCK_METHOD2(LnnSetNetCapability, int32_t(uint32_t *, NetCapability));
    MOCK_METHOD2(LnnClearNetCapability, int32_t(uint32_t *, NetCapability));
    MOCK_METHOD2(LnnRegisterEventHandler, int32_t(LnnEventType, LnnEventHandler));
    MOCK_METHOD2(LnnUnregisterEventHandler, void(LnnEventType, LnnEventHandler));
    MOCK_METHOD1(LnnNotifyDeviceVerified, void(const char *));
    MOCK_METHOD0(LnnInitBusCenterEvent, int32_t());
    MOCK_METHOD0(LnnSubcribeKvStoreService, bool());
    MOCK_METHOD0(LnnInitBatteryInfo, int32_t());
    MOCK_METHOD0(LnnDeinitBatteryInfo, void());
    MOCK_METHOD3(LnnSetLocalByteInfo, int32_t(InfoKey, const uint8_t *, uint32_t));
    MOCK_METHOD0(LnnDeinitNetworkInfo, void());
    MOCK_METHOD0(LnnDeinitDevicename, void());
    MOCK_METHOD0(LnnGetLocalNodeInfo, NodeInfo *());
    MOCK_METHOD1(LnnRemoveNode, void(const char *));
    MOCK_METHOD2(LnnClearDiscoveryType, int32_t(NodeInfo *, DiscoveryType));
    MOCK_METHOD1(LnnPrintConnectionAddr, const char *(const ConnectionAddr *));
    MOCK_METHOD1(LnnUpdateGroupType, int32_t(const NodeInfo *));
    MOCK_METHOD1(LnnUpdateAccountInfo, int32_t(const NodeInfo *));
    MOCK_METHOD1(LnnUpdateRemoteDeviceName, int32_t(const NodeInfo *));
    MOCK_METHOD2(LnnConvertAddrToAuthConnInfo, bool(const ConnectionAddr *, AuthConnInfo *));
    MOCK_METHOD2(LnnFsmRemoveMessageByType, int32_t(FsmStateMachine *, int32_t));
    MOCK_METHOD0(LnnDeinitBusCenterEvent, void());
    MOCK_METHOD5(
        AuthStartVerify, int32_t(const AuthConnInfo *, uint32_t, const AuthVerifyCallback *, AuthVerifyModule, bool));
    MOCK_METHOD2(LnnIsNeedCleanConnectionFsm, bool(const NodeInfo *, ConnectionAddrType));
    MOCK_METHOD1(AuthFlushDevice, int32_t(const char *uuid));
    MOCK_METHOD0(IsSupportLpFeature, bool());
    MOCK_METHOD0(LnnNotifyLocalNetworkIdChanged, void());
    MOCK_METHOD(bool, LnnIsDefaultOhosAccount, (), (override));
    MOCK_METHOD1(DeleteFromProfile, void(const char *));
    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t(const unsigned char *, uint32_t, unsigned char *));
    MOCK_METHOD1(UpdateProfile, void(const NodeInfo *));
    MOCK_METHOD2(IsSupportFeatureByCapaBit, bool(uint32_t, AuthCapability));
    MOCK_METHOD2(LnnGetRemoteNodeInfoByKey, int32_t(const char *, NodeInfo *));
    MOCK_METHOD1(RegisterOOBEMonitor, void(void *p));
    MOCK_METHOD1(CheckAuthChannelIsExit, int32_t(ConnectOption *connInfo));
    static int32_t ActionOfLnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum);
    MOCK_METHOD1(CheckRemoteBasicInfoChanged, bool(const NodeInfo *));
    MOCK_METHOD2(TransAuthGetConnIdByChanId, int32_t(int32_t, int32_t *));
    MOCK_METHOD3(TransAuthGetPeerUdidByChanId, int32_t(int32_t, char *, uint32_t));
    MOCK_METHOD2(LnnNotifyStateForSession, void(char *, int32_t));
    MOCK_METHOD1(AuthRemoveAuthManagerByAuthHandle, void(AuthHandle));
    MOCK_METHOD3(ProcessBleOnline, int32_t(NodeInfo *, const ConnectionAddr *, AuthCapability));
    MOCK_METHOD1(GetLnnTriggerInfo, void(LnnTriggerInfo *));
    MOCK_METHOD2(LnnSetDLConnUserIdCheckSum, int32_t(const char *networkId, int32_t userIdCheckSum));
    MOCK_METHOD3(LnnNotifyDeviceTrustedChange, void(int32_t type, const char *msg, uint32_t msgLen));
    MOCK_METHOD1(LnnGetDataShareInitResult, void(bool *));
};
} // namespace OHOS
#endif // LNN_NET_BUILDER_DEPS_MOCK_H
