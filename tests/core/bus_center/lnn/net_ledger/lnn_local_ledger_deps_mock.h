/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef LNN_LOCAL_LEDGER_DEPS_MOCK_H
#define LNN_LOCAL_LEDGER_DEPS_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_interface.h"
#include "auth_request.h"
#include "bus_center_adapter.h"
#include "bus_center_event.h"
#include "disc_interface.h"
#include "legacy/softbus_hidumper_buscenter.h"
#include "lnn_async_callback_utils.h"
#include "lnn_cipherkey_manager_struct.h"
#include "lnn_connection_fsm.h"
#include "lnn_device_info.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_event_form.h"
#include "lnn_fast_offline_struct.h"
#include "lnn_feature_capability.h"
#include "lnn_file_utils.h"
#include "lnn_file_utils_struct.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_net_capability.h"
#include "lnn_network_manager.h"
#include "lnn_ohos_account.h"
#include "lnn_p2p_info.h"
#include "lnn_physical_subnet_manager.h"
#include "message_handler.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_sle_common_struct.h"
#include "softbus_adapter_thread.h"
#include "softbus_config_type.h"
#include "sqlite3_utils.h"

namespace OHOS {
class LocalLedgerDepsInterface {
public:
    LocalLedgerDepsInterface() {};
    virtual ~LocalLedgerDepsInterface() {};

    virtual uint32_t LnnGetNetCapabilty(void);
    virtual int32_t SoftBusGenerateRandomArray(unsigned char *randStr, uint32_t len);
    virtual int32_t GetCommonDevInfo(const CommonDeviceKey key, char *value, uint32_t len);
    virtual int32_t LnnInitLocalP2pInfo(NodeInfo *info);
    virtual int32_t SoftBusRegBusCenterVarDump(char *dumpVar, SoftBusVarDumpCb cb);
    virtual int32_t LnnInitOhosAccount(void);
    virtual uint64_t LnnGetFeatureCapabilty(void);
    virtual bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit);
    virtual int32_t GetCommonOsType(int32_t *value);
    virtual int32_t GetCommonOsVersion(char *value, uint32_t len);
    virtual int32_t GetCommonDeviceVersion(char *value, uint32_t len);
    virtual int32_t GetDeviceSecurityLevel(int32_t *level);
    virtual int32_t SoftBusGetBtState(void) = 0;
    virtual int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac) = 0;
    virtual bool IsSleEnabled(void);
    virtual int SoftBusAddSleStateListener(const SoftBusSleStateListener *listener, int *listenerId);
    virtual void SoftBusRemoveSleStateListener(int listenerId);
    virtual int32_t GetSleRangeCapacity();
    virtual int32_t GetLocalSleAddr(char *sleAddr, uint32_t sleAddrLen);
    virtual int32_t LnnGenerateKeyByHuks(struct HksBlob *keyAlias);
    virtual int32_t LnnDeleteKeyByHuks(struct HksBlob *keyAlias);
    virtual int32_t LnnEncryptDataByHuks(
        const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData);
    virtual int32_t LnnDecryptDataByHuks(
        const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData);
    virtual int32_t LnnGenerateRandomByHuks(uint8_t *randomKey, uint32_t len);
    virtual int32_t OpenDatabase(DbContext **ctx);
    virtual int32_t CloseDatabase(DbContext *ctx);
    virtual int32_t CreateTable(DbContext *ctx, TableNameID id);
    virtual int32_t CheckTableExist(DbContext *ctx, TableNameID id, bool *isExist);
    virtual int32_t RemoveRecordByKey(DbContext *ctx, TableNameID id, uint8_t *data);
    virtual int32_t GetRecordNumByKey(DbContext *ctx, TableNameID id, uint8_t *data);
    virtual int32_t EncryptedDb(DbContext *ctx, const uint8_t *password, uint32_t len);
    virtual int32_t UpdateDbPassword(DbContext *ctx, const uint8_t *password, uint32_t len);
    virtual int32_t QueryRecordByKey(
        DbContext *ctx, TableNameID id, uint8_t *data, uint8_t **replyInfo, int32_t infoNum);
    virtual int32_t LnnGetFullStoragePath(LnnFileId id, char *path, uint32_t len);
    virtual int32_t SoftBusReadFullFile(const char *fileName, char *readBuf, uint32_t maxLen);
    virtual int32_t SoftBusWriteFile(const char *fileName, const char *writeBuf, uint32_t len);
    virtual int32_t SoftBusAccessFile(const char *pathName, int32_t mode);
    virtual int32_t LnnAsyncCallbackHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para);
    virtual int32_t ConvertBytesToHexString(
        char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen);
    virtual void LnnNotifyNetworkStateChanged(SoftBusNetworkState state);
    virtual TrustedReturnType AuthHasTrustedRelation(void);
    virtual bool IsEnableSoftBusHeartbeat(void);
    virtual void LnnNotifyHBRepeat(void);
    virtual void LnnHbClearRecvList(void);
    virtual int32_t LnnConvertHbTypeToId(LnnHeartbeatType type);
    virtual bool LnnVisitHbTypeSet(VisitHbTypeCb callback, LnnHeartbeatType *typeSet, void *data);
    virtual int32_t LnnCeEncryptDataByHuks(
        const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData);
    virtual int32_t LnnCeDecryptDataByHuks(
        const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData);
    virtual int32_t RegistIPProtocolManager(void);
    virtual int32_t LnnInitPhysicalSubnetManager(void);
    virtual void LnnOnOhosAccountChanged(void);
    virtual void LnnStopDiscovery(void);
    virtual int32_t LnnStartDiscovery(void);
    virtual int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len);
    virtual void DiscLinkStatusChanged(LinkStatus status, ExchangeMedium medium, int32_t ifnameIdx);
    virtual void LnnStopPublish(void);
    virtual int32_t LnnStartPublish(void);
    virtual void LnnUpdateOhosAccount(UpdateAccountReason reason);
    virtual void LnnOnOhosAccountLogout(void);
    virtual int32_t LnnNotifyDiscoveryDevice(
        const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport, bool isNeedConnect);
    virtual int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen, bool hasMcuRequestDisable);
    virtual int32_t LnnAsyncCallbackDelayHelper(
        SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis);
    virtual int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler);
    virtual void LnnNotifyOOBEStateChangeEvent(SoftBusOOBEState state);
    virtual void LnnNotifyAccountStateChangeEvent(SoftBusAccountState state);
    virtual void LnnDeinitPhysicalSubnetManager(void);
    virtual void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler);
    virtual void DfxRecordTriggerTime(LnnTriggerReason reason, LnnEventLnnStage stage);
    virtual int32_t LnnRegistPhysicalSubnet(LnnPhysicalSubnet *manager);
    virtual bool LnnVisitPhysicalSubnet(LnnVisitPhysicalSubnetCallback callback, void *data);
    virtual void LnnIpAddrChangeEventHandler(void);
    virtual void AuthStopListening(AuthLinkType type);
    virtual int32_t TransTdcStopSessionListener(ListenerModule module);
    virtual int32_t ConnStopLocalListening(const LocalListenerInfo *info);
    virtual int32_t LnnGetAddrTypeByIfName(const char *ifName, ConnectionAddrType *type);
    virtual bool LnnIsAutoNetWorkingEnabled(void);
    virtual int32_t AuthStartListening(AuthLinkType type, const char *ip, int32_t port);
    virtual int32_t TransTdcStartSessionListener(ListenerModule module, const LocalListenerInfo *info);
    virtual int32_t ConnStartLocalListening(const LocalListenerInfo *info);
    virtual bool LnnIsLinkReady(const char *iface);
    virtual void LnnNotifyPhysicalSubnetStatusChanged(const char *ifName, ProtocolType protocolType, void *status);
    virtual bool LnnVisitNetif(VisitNetifCallback callback, void *data);
    virtual int32_t GetNetworkIpByIfName(const char *ifName, char *ip, char *netmask, uint32_t len);
    virtual int32_t LnnRegistProtocol(LnnProtocolManager *protocolMgr);
    virtual int32_t GetWlanIpv4Addr(char *ip, uint32_t size);
    virtual int32_t ConnCoapStartServerListen(void);
    virtual void ConnCoapStopServerListen(void);
    virtual int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size);
    virtual int32_t TransGetConnByChanId(int32_t channelId, int32_t channelType, int32_t *connId);
    virtual int32_t AuthMetaStartVerify(uint32_t connectionId, const AuthKeyInfo *authKeyInfo, uint32_t requestId,
        int32_t callingPid, const AuthVerifyCallback *callBack);
    virtual uint32_t AuthGenRequestId(void);
    virtual void LnnSetUnlockState(void);
    virtual void AuthHandleLeaveLNN(AuthHandle authHandle);
    virtual LnnConnectionFsm *LnnCreateConnectionFsm(
        const ConnectionAddr *target, const char *pkgName, bool isNeedConnect);
    virtual bool LnnIsSameConnectionAddr(const ConnectionAddr *addr1, const ConnectionAddr *addr2, bool isShort);
    virtual bool LnnConvertAddrToOption(const ConnectionAddr *addr, ConnectOption *option);
    virtual DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type);
    virtual ConnectionAddrType LnnDiscTypeToConnAddrType(DiscoveryType type);
    virtual bool LnnConvertAuthConnInfoToAddr(
        ConnectionAddr *addr, const AuthConnInfo *connInfo, ConnectionAddrType hintType);
    virtual bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value);
    virtual bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num);
    virtual int32_t LnnSendSyncInfoMsg(
        LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len, LnnSyncInfoMsgComplete complete);
    virtual int32_t AuthGetLatestAuthSeqList(const char *udid, int64_t *authSeq, uint32_t num);
    virtual int32_t LnnSetSupportDiscoveryType(char *info, const char *type);
    virtual bool LnnHasSupportDiscoveryType(const char *destType, const char *type);
    virtual bool LnnPeerHasExchangeDiscoveryType(const NodeInfo *info, DiscoveryType type);
    virtual int32_t LnnCompareNodeWeight(
        int32_t weight1, const char *masterUdid1, int32_t weight2, const char *masterUdid2);
    virtual void LnnNotifyAllTypeOffline(ConnectionAddrType type);
    virtual int32_t SoftBusGetTime(SoftBusSysTime *sysTime);
    virtual int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo);
    virtual void LnnNotifyLeaveResult(const char *networkId, int32_t retCode);
    virtual int32_t LnnSendNotTrustedInfo(
        const NotTrustedDelayInfo *info, uint32_t num, LnnSyncInfoMsgComplete complete);
    virtual SoftBusLooper *GetLooper(int32_t looper);
    virtual int32_t ConnDisconnectDeviceAllConn(const ConnectOption *option);
    virtual int32_t LnnGenLocalIrk(unsigned char *irk, uint32_t len);
    virtual int32_t LnnGenLocalUuid(char *uuid, uint32_t len);
    virtual int32_t LnnGenLocalNetworkId(char *networkId, uint32_t len);
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
    virtual int32_t LnnSendJoinRequestToConnFsm(LnnConnectionFsm *connFsm, bool isForceJoin);
    virtual void LnnNotifyJoinResult(ConnectionAddr *addr, const char *networkId, int32_t retCode);
    virtual void LnnDestroyConnectionFsm(LnnConnectionFsm *connFsm);
    virtual int32_t LnnStartConnectionFsm(LnnConnectionFsm *connFsm);
    virtual bool LnnIsNeedCleanConnectionFsm(const NodeInfo *nodeInfo, ConnectionAddrType type);
    virtual int32_t AuthFlushDevice(const char *uuid, AuthLinkType type);
    virtual void LnnNotifyMasterNodeChanged(bool isMaster, const char *masterNodeUdid, int32_t weight);
    virtual int32_t LnnInitFastOffline(void);
    virtual void LnnNotifyNodeAddressChanged(const char *addr, const char *networkId, bool isLocal);
    virtual int32_t LnnInitOffline(void);
    virtual void LnnDeinitOffline(void);
    virtual int32_t GetAuthRequest(uint32_t requestId, AuthRequest *request);
    virtual int32_t SoftBusGetBrState(void);
    virtual int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type);
    virtual int32_t LnnClearNetCapability(uint32_t *capability, NetCapability type);
    virtual void LnnNotifyDeviceVerified(const char *udid);
    virtual int32_t LnnInitBusCenterEvent(void);
    virtual int32_t LnnInitBatteryInfo(void);
    virtual void LnnDeinitBatteryInfo(void);
    virtual void LnnDeinitNetworkInfo(void);
    virtual void LnnDeinitDevicename(void);
    virtual const char *LnnPrintConnectionAddr(const ConnectionAddr *addr);
    virtual bool LnnConvertAddrToAuthConnInfo(const ConnectionAddr *addr, AuthConnInfo *connInfo);
    virtual int32_t LnnFsmRemoveMessageByType(FsmStateMachine *fsm, int32_t what);
    virtual void LnnDeinitBusCenterEvent(void);
    virtual int32_t AuthStartVerify(
        const AuthConnInfo *connInfo, const AuthVerifyParam *authVerifyParam, const AuthVerifyCallback *callback);
    virtual bool LnnSubcribeKvStoreService(void);
    virtual int32_t LnnPutDBData(int32_t dbId, char *putKey, uint32_t putKeyLen, char *putValue, uint32_t putValueLen);
    virtual int32_t LnnCloudSync(int32_t dbId);

    virtual int32_t LnnSyncP2pInfo(void);
    virtual int32_t LnnSyncWifiDirectAddr(void);
    virtual int32_t LnnInitPtk(void);
    virtual int32_t LnnGetLocalPtkByUdid(const char *udid, char *localPtk, uint32_t len);
    virtual int32_t LnnGetLocalPtkByUuid(const char *uuid, char *localPtk, uint32_t len);
    virtual int32_t LnnGetLocalDefaultPtkByUuid(const char *uuid, char *localPtk, uint32_t len);
    virtual int32_t LnnGetRemoteDefaultPtkByUuid(const char *uuid, char *remotePtk, uint32_t len);
    virtual int32_t LnnSyncPtk(const char *networkId);
    virtual int32_t UpdateLocalPtkIfValid(char *udid);
    virtual int32_t LnnSetLocalPtkConn(char *udid);
    virtual int32_t LnnGenerateLocalPtk(char *udid, char *uuid);
    virtual int32_t LnnGenerateMetaPtk(uint32_t connId);
    virtual int32_t LnnGetMetaPtk(uint32_t connId, char *metaPtk, uint32_t len);
    virtual int32_t LnnDeleteMetaPtk(uint32_t connectionId);
    virtual int32_t UpdatePtkByAuth(char *networkId, AuthHandle authHandle);

    virtual int32_t SoftBusEnableBt(void) = 0;
    virtual int32_t SoftBusDisableBt(void) = 0;
    virtual int32_t SoftBusGetBtName(unsigned char *name, unsigned int *len) = 0;
    virtual int32_t SoftBusSetBtName(const char *name) = 0;
    virtual int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener, int *listenerId) = 0;
    virtual int32_t SoftBusRemoveBtStateListener(int listenerId) = 0;
    virtual int32_t SoftBusBtInit(void) = 0;

    virtual int32_t SoftBusBase64Encode(
        unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen);
    virtual int32_t SoftBusBase64Decode(
        unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen);
    virtual int32_t SoftBusGenerateSessionKey(char *key, uint32_t len);
    virtual uint32_t SoftBusCryptoRand(void);
    virtual int32_t LnnGetLocalDevInfoPacked(NodeInfo *deviceInfo) = 0;
    virtual int32_t LnnRemoveStorageConfigPath(LnnFileId id) = 0;
    virtual int32_t InitTrustedDevInfoTable(void) = 0;
    virtual int32_t LnnLoadLocalBroadcastCipherKeyPacked(void) = 0;
    virtual int32_t LnnUpdateLocalBroadcastCipherKeyPacked(BroadcastCipherKey *broadcastKey) = 0;
    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
    virtual int32_t LnnGetLocalBroadcastCipherKeyPacked(BroadcastCipherKey *broadcastKey) = 0;
};
class LocalLedgerDepsInterfaceMock : public LocalLedgerDepsInterface {
public:
    LocalLedgerDepsInterfaceMock();
    ~LocalLedgerDepsInterfaceMock() override;
    MOCK_METHOD0(LnnGetNetCapabilty, uint32_t());
    MOCK_METHOD2(SoftBusGenerateRandomArray, int32_t(unsigned char *, uint32_t));
    MOCK_METHOD3(GetCommonDevInfo, int32_t(const CommonDeviceKey, char *, uint32_t));
    MOCK_METHOD1(LnnInitLocalP2pInfo, int32_t(NodeInfo *info));
    MOCK_METHOD2(SoftBusRegBusCenterVarDump, int32_t(char *, SoftBusVarDumpCb));
    MOCK_METHOD0(LnnInitOhosAccount, int32_t());
    MOCK_METHOD0(LnnGetFeatureCapabilty, uint64_t());
    MOCK_METHOD2(IsFeatureSupport, bool(uint64_t, FeatureCapability));
    MOCK_METHOD1(GetCommonOsType, int32_t(int32_t *));
    MOCK_METHOD2(GetCommonOsVersion, int32_t(char *, uint32_t));
    MOCK_METHOD2(GetCommonDeviceVersion, int32_t(char *, uint32_t));
    MOCK_METHOD1(GetDeviceSecurityLevel, int32_t(int32_t *));
    MOCK_METHOD0(SoftBusGetBtState, int32_t(void));
    MOCK_METHOD1(SoftBusGetBtMacAddr, int32_t(SoftBusBtAddr *));
    MOCK_METHOD0(IsSleEnabled, bool(void));
    MOCK_METHOD2(SoftBusAddSleStateListener, int(const SoftBusSleStateListener *, int *));
    MOCK_METHOD1(SoftBusRemoveSleStateListener, void(int));
    MOCK_METHOD0(GetSleRangeCapacity, int32_t(void));
    MOCK_METHOD2(GetLocalSleAddr, int32_t(char *, uint32_t));
    MOCK_METHOD1(LnnGenerateKeyByHuks, int32_t(struct HksBlob *));
    MOCK_METHOD1(LnnDeleteKeyByHuks, int32_t(struct HksBlob *));
    MOCK_METHOD3(LnnEncryptDataByHuks, int32_t(const struct HksBlob *, const struct HksBlob *, struct HksBlob *));
    MOCK_METHOD3(LnnDecryptDataByHuks, int32_t(const struct HksBlob *, const struct HksBlob *, struct HksBlob *));
    MOCK_METHOD2(LnnGenerateRandomByHuks, int32_t(uint8_t *, uint32_t));
    MOCK_METHOD1(OpenDatabase, int32_t(DbContext **));
    MOCK_METHOD1(CloseDatabase, int32_t(DbContext *));
    MOCK_METHOD2(CreateTable, int32_t(DbContext *, TableNameID));
    MOCK_METHOD3(CheckTableExist, int32_t(DbContext *, TableNameID, bool *));
    MOCK_METHOD3(RemoveRecordByKey, int32_t(DbContext *, TableNameID, uint8_t *));
    MOCK_METHOD3(GetRecordNumByKey, int32_t(DbContext *, TableNameID, uint8_t *));
    MOCK_METHOD3(EncryptedDb, int32_t(DbContext *, const uint8_t *, uint32_t));
    MOCK_METHOD3(UpdateDbPassword, int32_t(DbContext *, const uint8_t *, uint32_t));
    MOCK_METHOD5(QueryRecordByKey, int32_t(DbContext *, TableNameID, uint8_t *, uint8_t **, int));
    MOCK_METHOD3(LnnGetFullStoragePath, int32_t(LnnFileId, char *, uint32_t));
    MOCK_METHOD3(SoftBusReadFullFile, int32_t(const char *, char *, uint32_t));
    MOCK_METHOD3(SoftBusWriteFile, int32_t(const char *, const char *, uint32_t));
    MOCK_METHOD2(SoftBusAccessFile, int32_t(const char *, int32_t));
    MOCK_METHOD3(LnnAsyncCallbackHelper, int32_t(SoftBusLooper *, LnnAsyncCallbackFunc, void *));
    MOCK_METHOD4(ConvertBytesToHexString, int32_t(char *, uint32_t, const unsigned char *, uint32_t));
    MOCK_METHOD1(LnnNotifyNetworkStateChanged, void(SoftBusNetworkState));
    MOCK_METHOD0(AuthHasTrustedRelation, TrustedReturnType(void));
    MOCK_METHOD0(IsEnableSoftBusHeartbeat, bool(void));
    MOCK_METHOD0(LnnNotifyHBRepeat, void(void));
    MOCK_METHOD0(LnnHbClearRecvList, void(void));
    MOCK_METHOD3(LnnVisitHbTypeSet, bool(VisitHbTypeCb, LnnHeartbeatType *, void *));
    MOCK_METHOD1(LnnConvertHbTypeToId, int32_t(LnnHeartbeatType));
    MOCK_METHOD3(LnnCeEncryptDataByHuks, int32_t(const struct HksBlob *, const struct HksBlob *, struct HksBlob *));
    MOCK_METHOD3(LnnCeDecryptDataByHuks, int32_t(const struct HksBlob *, const struct HksBlob *, struct HksBlob *));
    MOCK_METHOD0(RegistIPProtocolManager, int32_t(void));
    MOCK_METHOD0(LnnInitPhysicalSubnetManager, int32_t(void));
    MOCK_METHOD0(LnnOnOhosAccountChanged, void(void));
    MOCK_METHOD0(LnnStopDiscovery, void(void));
    MOCK_METHOD0(LnnStartDiscovery, int32_t(void));
    MOCK_METHOD3(SoftbusGetConfig, int32_t(ConfigType, unsigned char *, uint32_t));
    MOCK_METHOD3(DiscLinkStatusChanged, void(LinkStatus, ExchangeMedium, int32_t));
    MOCK_METHOD0(LnnStopPublish, void(void));
    MOCK_METHOD0(LnnStartPublish, int32_t(void));
    MOCK_METHOD1(LnnUpdateOhosAccount, void(UpdateAccountReason));
    MOCK_METHOD0(LnnOnOhosAccountLogout, void(void));
    MOCK_METHOD3(LnnNotifyDiscoveryDevice, int32_t(const ConnectionAddr *, const LnnDfxDeviceInfoReport *, bool));
    MOCK_METHOD3(LnnRequestLeaveByAddrType, int32_t(const bool *, uint32_t, bool));
    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t(SoftBusLooper *, LnnAsyncCallbackFunc, void *, uint64_t));
    MOCK_METHOD2(LnnRegisterEventHandler, int32_t(LnnEventType, LnnEventHandler));
    MOCK_METHOD1(LnnNotifyOOBEStateChangeEvent, void(SoftBusOOBEState));
    MOCK_METHOD1(LnnNotifyAccountStateChangeEvent, void(SoftBusAccountState));
    MOCK_METHOD0(LnnDeinitPhysicalSubnetManager, void(void));
    MOCK_METHOD2(LnnUnregisterEventHandler, void(LnnEventType, LnnEventHandler));
    MOCK_METHOD2(DfxRecordTriggerTime, void(LnnTriggerReason, LnnEventLnnStage));
    MOCK_METHOD1(LnnRegistPhysicalSubnet, int32_t(LnnPhysicalSubnet *));
    MOCK_METHOD2(LnnVisitPhysicalSubnet, bool(LnnVisitPhysicalSubnetCallback, void *));
    MOCK_METHOD0(LnnIpAddrChangeEventHandler, void(void));
    MOCK_METHOD1(AuthStopListening, void(AuthLinkType));
    MOCK_METHOD1(TransTdcStopSessionListener, int32_t(ListenerModule));
    MOCK_METHOD1(ConnStopLocalListening, int32_t(const LocalListenerInfo *));
    MOCK_METHOD2(LnnGetAddrTypeByIfName, int32_t(const char *, ConnectionAddrType *));
    MOCK_METHOD0(LnnIsAutoNetWorkingEnabled, bool(void));
    MOCK_METHOD3(AuthStartListening, int32_t(AuthLinkType, const char *, int32_t));
    MOCK_METHOD2(TransTdcStartSessionListener, int32_t(ListenerModule, const LocalListenerInfo *));
    MOCK_METHOD1(ConnStartLocalListening, int32_t(const LocalListenerInfo *));
    MOCK_METHOD1(LnnIsLinkReady, bool(const char *));
    MOCK_METHOD3(LnnNotifyPhysicalSubnetStatusChanged, void(const char *, ProtocolType, void *));
    MOCK_METHOD2(LnnVisitNetif, bool(VisitNetifCallback, void *));
    MOCK_METHOD4(GetNetworkIpByIfName, int32_t(const char *, char *, char *, uint32_t));
    MOCK_METHOD1(LnnRegistProtocol, int32_t(LnnProtocolManager *));
    MOCK_METHOD2(GetWlanIpv4Addr, int32_t(char *, uint32_t));
    MOCK_METHOD0(ConnCoapStartServerListen, int32_t(void));
    MOCK_METHOD0(ConnCoapStopServerListen, void(void));
    MOCK_METHOD3(AuthGetDeviceUuid, int32_t(int64_t, char *, uint16_t));
    MOCK_METHOD3(TransGetConnByChanId, int32_t(int32_t, int32_t, int32_t *));
    MOCK_METHOD5(
        AuthMetaStartVerify, int32_t(uint32_t, const AuthKeyInfo *, uint32_t, int32_t, const AuthVerifyCallback *));
    MOCK_METHOD0(AuthGenRequestId, uint32_t());
    MOCK_METHOD0(LnnSetUnlockState, void());
    MOCK_METHOD1(AuthHandleLeaveLNN, void(AuthHandle));
    MOCK_METHOD3(LnnIsSameConnectionAddr, bool(const ConnectionAddr *, const ConnectionAddr *, bool));
    MOCK_METHOD2(LnnConvertAddrToOption, bool(const ConnectionAddr *, ConnectOption *));
    MOCK_METHOD1(LnnConvAddrTypeToDiscType, DiscoveryType(ConnectionAddrType));
    MOCK_METHOD1(LnnDiscTypeToConnAddrType, ConnectionAddrType(DiscoveryType));
    MOCK_METHOD3(LnnConvertAuthConnInfoToAddr, bool(ConnectionAddr *, const AuthConnInfo *, ConnectionAddrType));
    MOCK_METHOD3(AddStringToJsonObject, bool(cJSON *, const char * const, const char *));
    MOCK_METHOD3(AddNumberToJsonObject, bool(cJSON *, const char * const, int));
    MOCK_METHOD5(
        LnnSendSyncInfoMsg, int32_t(LnnSyncInfoType, const char *, const uint8_t *, uint32_t, LnnSyncInfoMsgComplete));
    MOCK_METHOD3(AuthGetLatestAuthSeqList, int32_t(const char *, int64_t *, uint32_t));
    MOCK_METHOD2(LnnSetSupportDiscoveryType, int32_t(char *, const char *));
    MOCK_METHOD2(LnnHasSupportDiscoveryType, bool(const char *, const char *));
    MOCK_METHOD2(LnnPeerHasExchangeDiscoveryType, bool(const NodeInfo *, DiscoveryType));
    MOCK_METHOD4(LnnCompareNodeWeight, int32_t(int32_t, const char *, int32_t, const char *));
    MOCK_METHOD1(LnnNotifyAllTypeOffline, void(ConnectionAddrType));
    MOCK_METHOD1(SoftBusGetTime, int32_t(SoftBusSysTime *));
    MOCK_METHOD2(AuthGetConnInfo, int32_t(AuthHandle, AuthConnInfo *));
    MOCK_METHOD2(LnnNotifyLeaveResult, void(const char *, int32_t));
    MOCK_METHOD3(LnnSendNotTrustedInfo, int32_t(const NotTrustedDelayInfo *, uint32_t, LnnSyncInfoMsgComplete));
    MOCK_METHOD1(GetLooper, SoftBusLooper *(int));
    MOCK_METHOD1(ConnDisconnectDeviceAllConn, int32_t(const ConnectOption *));
    MOCK_METHOD2(LnnGenLocalUuid, int32_t(char *, uint32_t));
    MOCK_METHOD2(LnnGenLocalIrk, int32_t(unsigned char *, uint32_t));
    MOCK_METHOD2(LnnGenLocalNetworkId, int32_t(char *, uint32_t));
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
    MOCK_METHOD2(LnnSendJoinRequestToConnFsm, int32_t(LnnConnectionFsm *, bool));
    MOCK_METHOD3(LnnNotifyJoinResult, void(ConnectionAddr *, const char *, int32_t));
    MOCK_METHOD1(LnnDestroyConnectionFsm, void(LnnConnectionFsm *));
    MOCK_METHOD3(LnnCreateConnectionFsm,
        LnnConnectionFsm *(const ConnectionAddr *target, const char *pkgName, bool isNeedConnect));
    MOCK_METHOD1(LnnStartConnectionFsm, int32_t(LnnConnectionFsm *));
    MOCK_METHOD3(LnnNotifyMasterNodeChanged, void(bool, const char *, int32_t));
    MOCK_METHOD0(LnnInitFastOffline, int32_t());
    MOCK_METHOD3(LnnNotifyNodeAddressChanged, void(const char *, const char *, bool));
    MOCK_METHOD0(LnnInitOffline, int32_t());
    MOCK_METHOD0(LnnDeinitOffline, void());
    MOCK_METHOD2(GetAuthRequest, int32_t(uint32_t, AuthRequest *));
    MOCK_METHOD0(SoftBusGetBrState, int32_t());
    MOCK_METHOD2(LnnSetNetCapability, int32_t(uint32_t *, NetCapability));
    MOCK_METHOD2(LnnClearNetCapability, int32_t(uint32_t *, NetCapability));
    MOCK_METHOD1(LnnNotifyDeviceVerified, void(const char *));
    MOCK_METHOD0(LnnInitBusCenterEvent, int32_t());
    MOCK_METHOD0(LnnSubcribeKvStoreService, bool());
    MOCK_METHOD0(LnnInitBatteryInfo, int32_t());
    MOCK_METHOD0(LnnDeinitBatteryInfo, void());
    MOCK_METHOD0(LnnDeinitNetworkInfo, void());
    MOCK_METHOD0(LnnDeinitDevicename, void());
    MOCK_METHOD1(LnnPrintConnectionAddr, const char *(const ConnectionAddr *));
    MOCK_METHOD2(LnnConvertAddrToAuthConnInfo, bool(const ConnectionAddr *, AuthConnInfo *));
    MOCK_METHOD2(LnnFsmRemoveMessageByType, int32_t(FsmStateMachine *, int32_t));
    MOCK_METHOD0(LnnDeinitBusCenterEvent, void());
    MOCK_METHOD3(AuthStartVerify, int32_t(const AuthConnInfo *, const AuthVerifyParam *, const AuthVerifyCallback *));
    MOCK_METHOD2(LnnIsNeedCleanConnectionFsm, bool(const NodeInfo *, ConnectionAddrType));
    MOCK_METHOD2(AuthFlushDevice, int32_t(const char *uuid, AuthLinkType type));
    MOCK_METHOD5(
        LnnPutDBData, int32_t(int32_t dbId, char *putKey, uint32_t putKeyLen, char *putValue, uint32_t putValueLen));
    MOCK_METHOD1(LnnCloudSync, int32_t(int32_t dbId));

    MOCK_METHOD0(LnnSyncP2pInfo, int32_t());
    MOCK_METHOD0(LnnSyncWifiDirectAddr, int32_t());
    MOCK_METHOD0(LnnInitPtk, int32_t());
    MOCK_METHOD3(LnnGetLocalPtkByUdid, int32_t(const char *, char *, uint32_t));
    MOCK_METHOD3(LnnGetLocalPtkByUuid, int32_t(const char *, char *, uint32_t));
    MOCK_METHOD3(LnnGetLocalDefaultPtkByUuid, int32_t(const char *, char *, uint32_t));
    MOCK_METHOD3(LnnGetRemoteDefaultPtkByUuid, int32_t(const char *, char *, uint32_t));
    MOCK_METHOD1(LnnSyncPtk, int32_t(const char *));
    MOCK_METHOD1(UpdateLocalPtkIfValid, int32_t(char *));
    MOCK_METHOD1(LnnSetLocalPtkConn, int32_t(char *));
    MOCK_METHOD2(LnnGenerateLocalPtk, int32_t(char *, char *));
    MOCK_METHOD1(LnnGenerateMetaPtk, int32_t(uint32_t));
    MOCK_METHOD3(LnnGetMetaPtk, int32_t(uint32_t, char *, uint32_t));
    MOCK_METHOD1(LnnDeleteMetaPtk, int32_t(uint32_t));
    MOCK_METHOD2(UpdatePtkByAuth, int32_t(char *, AuthHandle));

    MOCK_METHOD0(SoftBusEnableBt, int32_t());
    MOCK_METHOD0(SoftBusDisableBt, int32_t());
    MOCK_METHOD2(SoftBusGetBtName, int32_t(unsigned char *, unsigned int *));
    MOCK_METHOD1(SoftBusSetBtName, int32_t(const char *));
    MOCK_METHOD2(SoftBusAddBtStateListener, int32_t(const SoftBusBtStateListener *, int *));
    MOCK_METHOD1(SoftBusRemoveBtStateListener, int32_t(int));
    MOCK_METHOD0(SoftBusBtInit, int32_t());

    MOCK_METHOD5(SoftBusBase64Encode, int32_t(unsigned char *, size_t, size_t *, const unsigned char *, size_t));
    MOCK_METHOD5(SoftBusBase64Decode, int32_t(unsigned char *, size_t, size_t *, const unsigned char *, size_t));
    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t(const unsigned char *, uint32_t, unsigned char *));
    MOCK_METHOD2(SoftBusGenerateSessionKey, int32_t(char *, uint32_t));
    MOCK_METHOD0(SoftBusCryptoRand, uint32_t());
    MOCK_METHOD1(LnnGetLocalDevInfoPacked, int32_t(NodeInfo *));
    MOCK_METHOD1(LnnRemoveStorageConfigPath, int32_t(LnnFileId));
    MOCK_METHOD0(InitTrustedDevInfoTable, int32_t(void));
    MOCK_METHOD0(LnnLoadLocalBroadcastCipherKeyPacked, int32_t(void));
    MOCK_METHOD1(LnnUpdateLocalBroadcastCipherKeyPacked, int32_t(BroadcastCipherKey *));
    MOCK_METHOD1(LnnGetLocalBroadcastCipherKeyPacked, int32_t(BroadcastCipherKey *));

    static int32_t LedgerGetCommonDevInfo(const CommonDeviceKey key, char *value, uint32_t len);
    static int32_t LedgerGetCommonDevInfoGlass(const CommonDeviceKey key, char *value, uint32_t len);
    static int32_t LedgerSoftBusRegBusCenterVarDump(char *dumpVar, SoftBusVarDumpCb cb);
    static int32_t MockGetLocalSleAddrFunc(char *sleAddr, uint32_t sleAddrLen);
};
} // namespace OHOS
#endif // LNN_LOCAL_LEDGER_DEPS_MOCK_H
