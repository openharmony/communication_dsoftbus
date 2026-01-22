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

#ifndef LNN_OHOS_ACCOUNT_MOCK_H
#define LNN_OHOS_ACCOUNT_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_interface.h"
#include "bus_center_event.h"
#include "bus_center_event_struct.h"
#include "bus_center_info_key.h"
#include "cJSON.h"
#include "disc_interface.h"
#include "disc_interface_struct.h"
#include "lnn_async_callback_utils.h"
#include "lnn_connection_fsm.h"
#include "lnn_event_form.h"
#include "lnn_fast_offline_struct.h"
#include "lnn_file_utils.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_heartbeat_utils_struct.h"
#include "lnn_local_net_ledger.h"
#include "lnn_node_info.h"
#include "lnn_ohos_account_adapter.h"
#include "lnn_ohos_account.h"
#include "lnn_physical_subnet_manager.h"
#include "message_handler.h"
#include "softbus_adapter_crypto.h"
#include "softbus_config_type.h"
#include "softbus_conn_interface.h"
#include "sqlite3_utils.h"

namespace OHOS {
class LnnOhosAccountInterface {
public:
    LnnOhosAccountInterface() {};
    virtual ~LnnOhosAccountInterface() {};

    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
    virtual int32_t GetOsAccountId(char *id, uint32_t idLen, uint32_t *len) = 0;
    virtual int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len) = 0;
    virtual int32_t UpdateRecoveryDeviceInfoFromDb(void) = 0;
    virtual int32_t GetCurrentAccount(int64_t *account) = 0;
    virtual int32_t GetOsAccountUid(char *id, uint32_t idLen, uint32_t *len) = 0;
    virtual int32_t LnnGetOhosAccountInfo(uint8_t *accountHash, uint32_t len) = 0;
    virtual void DiscDeviceInfoChanged(InfoTypeChanged type) = 0;
    virtual void LnnNotifyDeviceInfoChanged(SoftBusDeviceInfoState state) = 0;
    virtual void LnnUpdateHeartbeatInfo(LnnHeartbeatUpdateInfoType type) = 0;
    virtual void ClearAuthLimitMap(void) = 0;
    virtual void ClearLnnBleReportExtraMap(void) = 0;
    virtual void ClearPcRestrictMap(void) = 0;
    virtual int32_t LnnSetLocalStrInfo(InfoKey key, const char *info) = 0;
    virtual int32_t LnnSetLocalByteInfo(InfoKey key, const uint8_t *info, uint32_t len) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnSetLocalNum64Info(InfoKey key, int64_t info) = 0;
    virtual void LnnAccoutIdStatusSet(int64_t accountId) = 0;
    virtual bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num);
    virtual bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value);
    virtual bool IsEnableSoftBusHeartbeat(void);
    virtual bool LnnConvertAddrToOption(const ConnectionAddr *addr, ConnectOption *option);
    virtual bool LnnConvertAuthConnInfoToAddr(ConnectionAddr *addr, const AuthConnInfo *connInfo,
        ConnectionAddrType hintType);
    virtual bool LnnHasSupportDiscoveryType(const char *destType, const char *type);
    virtual bool LnnIsAutoNetWorkingEnabled(void);
    virtual bool LnnIsLinkReady(const char *iface);
    virtual bool LnnIsSameConnectionAddr(const ConnectionAddr *addr1, const ConnectionAddr *addr2, bool isShort);
    virtual bool LnnPeerHasExchangeDiscoveryType(const NodeInfo *info, DiscoveryType type);
    virtual bool LnnVisitHbTypeSet(VisitHbTypeCb callback, LnnHeartbeatType *typeSet, void *data);
    virtual bool LnnVisitNetif(VisitNetifCallback callback, void *data);
    virtual bool LnnVisitPhysicalSubnet(LnnVisitPhysicalSubnetCallback callback, void *data);
    virtual ConnectionAddrType LnnDiscTypeToConnAddrType(DiscoveryType type);
    virtual DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type);
    virtual int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo);
    virtual int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size);
    virtual int32_t AuthGetLatestAuthSeqList(const char *udid, int64_t *authSeq, uint32_t num);
    virtual int32_t AuthMetaStartVerify(uint32_t connectionId, const AuthKeyInfo *authKeyInfo, uint32_t requestId,
        int32_t callingPid, const AuthVerifyCallback *callBack);
    virtual int32_t AuthStartListening(AuthLinkType type, const char *ip, int32_t port);
    virtual int32_t CheckTableExist(DbContext *ctx, TableNameID id, bool *isExist);
    virtual int32_t CloseDatabase(DbContext *ctx);
    virtual int32_t ConnCoapStartServerListen(void);
    virtual int32_t ConnDisconnectDeviceAllConn(const ConnectOption *option);
    virtual int32_t ConnStartLocalListening(const LocalListenerInfo *info);
    virtual int32_t ConnStopLocalListening(const LocalListenerInfo *info);
    virtual int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf,
        uint32_t inLen);
    virtual int32_t CreateTable(DbContext *ctx, TableNameID id);
    virtual int32_t EncryptedDb(DbContext *ctx, const uint8_t *password, uint32_t len);
    virtual int32_t GetNetworkIpByIfName(const char *ifName, char *ip, char *netmask, uint32_t len);
    virtual int32_t GetRecordNumByKey(DbContext *ctx, TableNameID id, uint8_t *data);
    virtual int32_t GetWlanIpv4Addr(char *ip, uint32_t size);
    virtual int32_t LnnAsyncCallbackDelayHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para,
        uint64_t delayMillis);
    virtual int32_t LnnAsyncCallbackHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para);
    virtual int32_t LnnCeDecryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData,
        struct HksBlob *outData);
    virtual int32_t LnnCeEncryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData,
        struct HksBlob *outData);
    virtual int32_t LnnCompareNodeWeight(int32_t weight1, const char *masterUdid1, int32_t weight2,
        const char *masterUdid2);
    virtual int32_t LnnConvertHbTypeToId(LnnHeartbeatType type);
    virtual int32_t LnnDecryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData,
        struct HksBlob *outData);
    virtual int32_t LnnDeleteKeyByHuks(struct HksBlob *keyAlias);
    virtual int32_t LnnEncryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData,
        struct HksBlob *outData);
    virtual int32_t LnnGenerateKeyByHuks(struct HksBlob *keyAlias);
    virtual int32_t LnnGenerateRandomByHuks(uint8_t *randomKey, uint32_t len);
    virtual int32_t LnnGenLocalIrk(unsigned char *irk, uint32_t len);
    virtual int32_t LnnGenLocalNetworkId(char *networkId, uint32_t len);
    virtual int32_t LnnGenLocalUuid(char *uuid, uint32_t len);
    virtual int32_t LnnGetAddrTypeByIfName(const char *ifName, ConnectionAddrType *type);
    virtual int32_t LnnGetFullStoragePath(LnnFileId id, char *path, uint32_t len);
    virtual int32_t LnnInitDevicename(void);
    virtual int32_t LnnInitNetworkInfo(void);
    virtual int32_t LnnInitP2p(void);
    virtual int32_t LnnInitPhysicalSubnetManager(void);
    virtual int32_t LnnInitSyncInfoManager(void);
    virtual int32_t LnnInitTopoManager(void);
    virtual int32_t LnnInitWifiDirect(void);
    virtual int32_t LnnNotifyDiscoveryDevice(const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport,
        bool isNeedConnect);
    virtual int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler);
    virtual int32_t LnnRegistPhysicalSubnet(LnnPhysicalSubnet *manager);
    virtual int32_t LnnRegistProtocol(LnnProtocolManager *protocolMgr);
    virtual int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen, bool hasMcuRequestDisable);
    virtual int32_t LnnSendNotTrustedInfo(const NotTrustedDelayInfo *info, uint32_t num,
        LnnSyncInfoMsgComplete complete);
    virtual int32_t LnnSendSyncInfoMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len,
        LnnSyncInfoMsgComplete complete);
    virtual int32_t LnnSetSupportDiscoveryType(char *info, const char *type);
    virtual int32_t LnnStartDiscovery(void);
    virtual int32_t LnnStartPublish(void);
    virtual int32_t OpenDatabase(DbContext **ctx);
    virtual int32_t QueryRecordByKey(DbContext *ctx, TableNameID id, uint8_t *data, uint8_t **replyInfo,
        int32_t infoNum);
    virtual int32_t RegistIPProtocolManager(void);
    virtual int32_t RemoveRecordByKey(DbContext *ctx, TableNameID id, uint8_t *data);
    virtual int32_t SoftBusAccessFile(const char *pathName, int32_t mode);
    virtual int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len);
    virtual int32_t SoftBusGetTime(SoftBusSysTime *sysTime);
    virtual int32_t SoftBusReadFullFile(const char *fileName, char *readBuf, uint32_t maxLen);
    virtual int32_t SoftBusWriteFile(const char *fileName, const char *writeBuf, uint32_t len);
    virtual int32_t TransGetConnByChanId(int32_t channelId, int32_t channelType, int32_t *connId);
    virtual int32_t TransTdcStartSessionListener(ListenerModule module, const LocalListenerInfo *info);
    virtual int32_t TransTdcStopSessionListener(ListenerModule module);
    virtual int32_t UpdateDbPassword(DbContext *ctx, const uint8_t *password, uint32_t len);
    virtual SoftBusLooper *GetLooper(int32_t looper);
    virtual TrustedReturnType AuthHasTrustedRelation(void);
    virtual uint32_t AuthGenRequestId(void);
    virtual void AuthHandleLeaveLNN(AuthHandle authHandle);
    virtual void AuthStopListening(AuthLinkType type);
    virtual void ConnCoapStopServerListen(void);
    virtual void DfxRecordTriggerTime(LnnTriggerReason reason, LnnEventLnnStage stage);
    virtual void DiscLinkStatusChanged(LinkStatus status, ExchangeMedium medium, int32_t ifnameIdx);
    virtual void LnnDeinitP2p(void);
    virtual void LnnDeinitPhysicalSubnetManager(void);
    virtual void LnnDeinitSyncInfoManager(void);
    virtual void LnnDeinitTopoManager(void);
    virtual void LnnDeinitWifiDirect(void);
    virtual void LnnHbClearRecvList(void);
    virtual void LnnIpAddrChangeEventHandler(void);
    virtual void LnnNotifyAccountStateChangeEvent(SoftBusAccountState state);
    virtual void LnnNotifyAllTypeOffline(ConnectionAddrType type);
    virtual void LnnNotifyHBRepeat(void);
    virtual void LnnNotifyLeaveResult(const char *networkId, int32_t retCode);
    virtual void LnnNotifyNetworkStateChanged(SoftBusNetworkState state);
    virtual void LnnNotifyOOBEStateChangeEvent(SoftBusOOBEState state);
    virtual void LnnNotifyPhysicalSubnetStatusChanged(const char *ifName, ProtocolType protocolType, void *status);
    virtual void LnnOnOhosAccountChanged(void);
    virtual void LnnOnOhosAccountLogout(void);
    virtual void LnnSetUnlockState(void);
    virtual void LnnStopDiscovery(void);
    virtual void LnnStopPublish(void);
    virtual void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler);
    virtual void LnnUpdateOhosAccount(UpdateAccountReason reason);
    virtual int32_t GetOsAccountIdByUserId(int32_t userId, char **id, uint32_t *len) = 0;
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t info) = 0;
};

class LnnOhosAccountInterfaceMock : public LnnOhosAccountInterface {
public:
    LnnOhosAccountInterfaceMock();
    ~LnnOhosAccountInterfaceMock() override;

    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t(const unsigned char *str, uint32_t len, unsigned char *hash));
    MOCK_METHOD3(GetOsAccountId, int32_t(char *id, uint32_t idLen, uint32_t *len));
    MOCK_METHOD3(LnnGetLocalByteInfo, int32_t(InfoKey key, uint8_t *info, uint32_t len));
    MOCK_METHOD0(UpdateRecoveryDeviceInfoFromDb, int32_t(void));
    MOCK_METHOD1(GetCurrentAccount, int32_t(int64_t *account));
    MOCK_METHOD3(GetOsAccountUid, int32_t(char *id, uint32_t idLen, uint32_t *len));
    MOCK_METHOD2(LnnGetOhosAccountInfo, int32_t(uint8_t *accountHash, uint32_t len));
    MOCK_METHOD1(DiscDeviceInfoChanged, void(InfoTypeChanged type));
    MOCK_METHOD1(LnnNotifyDeviceInfoChanged, void(SoftBusDeviceInfoState state));
    MOCK_METHOD1(LnnUpdateHeartbeatInfo, void(LnnHeartbeatUpdateInfoType type));
    MOCK_METHOD0(ClearAuthLimitMap, void());
    MOCK_METHOD0(ClearLnnBleReportExtraMap, void());
    MOCK_METHOD0(ClearPcRestrictMap, void());
    MOCK_METHOD2(LnnSetLocalStrInfo, int32_t(InfoKey key, const char *info));
    MOCK_METHOD3(LnnSetLocalByteInfo, int32_t(InfoKey key, const uint8_t *info, uint32_t len));
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t(InfoKey key, char *info, uint32_t len));
    MOCK_METHOD2(LnnSetLocalNum64Info, int32_t (InfoKey key, int64_t info));
    MOCK_METHOD1(LnnAccoutIdStatusSet, void(int64_t accountId));
    MOCK_METHOD0(AuthGenRequestId, uint32_t());
    MOCK_METHOD0(AuthHasTrustedRelation, TrustedReturnType(void));
    MOCK_METHOD0(ConnCoapStartServerListen, int32_t(void));
    MOCK_METHOD0(ConnCoapStopServerListen, void(void));
    MOCK_METHOD0(IsEnableSoftBusHeartbeat, bool(void));
    MOCK_METHOD0(LnnDeinitP2p, void());
    MOCK_METHOD0(LnnDeinitPhysicalSubnetManager, void(void));
    MOCK_METHOD0(LnnDeinitSyncInfoManager, void());
    MOCK_METHOD0(LnnDeinitTopoManager, void());
    MOCK_METHOD0(LnnDeinitWifiDirect, void());
    MOCK_METHOD0(LnnHbClearRecvList, void(void));
    MOCK_METHOD0(LnnInitDevicename, int32_t());
    MOCK_METHOD0(LnnInitNetworkInfo, int32_t());
    MOCK_METHOD0(LnnInitP2p, int32_t());
    MOCK_METHOD0(LnnInitPhysicalSubnetManager, int32_t(void));
    MOCK_METHOD0(LnnInitSyncInfoManager, int32_t());
    MOCK_METHOD0(LnnInitTopoManager, int32_t());
    MOCK_METHOD0(LnnInitWifiDirect, int32_t());
    MOCK_METHOD0(LnnIpAddrChangeEventHandler, void(void));
    MOCK_METHOD0(LnnIsAutoNetWorkingEnabled, bool(void));
    MOCK_METHOD0(LnnNotifyHBRepeat, void(void));
    MOCK_METHOD0(LnnOnOhosAccountChanged, void(void));
    MOCK_METHOD0(LnnOnOhosAccountLogout, void(void));
    MOCK_METHOD0(LnnSetUnlockState, void());
    MOCK_METHOD0(LnnStartDiscovery, int32_t(void));
    MOCK_METHOD0(LnnStartPublish, int32_t(void));
    MOCK_METHOD0(LnnStopDiscovery, void(void));
    MOCK_METHOD0(LnnStopPublish, void(void));
    MOCK_METHOD0(RegistIPProtocolManager, int32_t(void));
    MOCK_METHOD1(AuthHandleLeaveLNN, void(AuthHandle));
    MOCK_METHOD1(AuthStopListening, void(AuthLinkType));
    MOCK_METHOD1(CloseDatabase, int32_t(DbContext *));
    MOCK_METHOD1(ConnDisconnectDeviceAllConn, int32_t(const ConnectOption *));
    MOCK_METHOD1(ConnStartLocalListening, int32_t(const LocalListenerInfo *));
    MOCK_METHOD1(ConnStopLocalListening, int32_t(const LocalListenerInfo *));
    MOCK_METHOD1(GetLooper, SoftBusLooper *(int));
    MOCK_METHOD1(LnnConvAddrTypeToDiscType, DiscoveryType(ConnectionAddrType));
    MOCK_METHOD1(LnnConvertHbTypeToId, int32_t(LnnHeartbeatType));
    MOCK_METHOD1(LnnDeleteKeyByHuks, int32_t(struct HksBlob *));
    MOCK_METHOD1(LnnDiscTypeToConnAddrType, ConnectionAddrType(DiscoveryType));
    MOCK_METHOD1(LnnGenerateKeyByHuks, int32_t(struct HksBlob *));
    MOCK_METHOD1(LnnIsLinkReady, bool(const char *));
    MOCK_METHOD1(LnnNotifyAccountStateChangeEvent, void(SoftBusAccountState));
    MOCK_METHOD1(LnnNotifyAllTypeOffline, void(ConnectionAddrType));
    MOCK_METHOD1(LnnNotifyNetworkStateChanged, void(SoftBusNetworkState));
    MOCK_METHOD1(LnnNotifyOOBEStateChangeEvent, void(SoftBusOOBEState));
    MOCK_METHOD1(LnnRegistPhysicalSubnet, int32_t(LnnPhysicalSubnet *));
    MOCK_METHOD1(LnnRegistProtocol, int32_t(LnnProtocolManager *));
    MOCK_METHOD1(LnnUpdateOhosAccount, void(UpdateAccountReason));
    MOCK_METHOD1(OpenDatabase, int32_t(DbContext **));
    MOCK_METHOD1(SoftBusGetTime, int32_t(SoftBusSysTime *));
    MOCK_METHOD1(TransTdcStopSessionListener, int32_t(ListenerModule));
    MOCK_METHOD2(AuthGetConnInfo, int32_t(AuthHandle, AuthConnInfo *));
    MOCK_METHOD2(CreateTable, int32_t(DbContext *, TableNameID));
    MOCK_METHOD2(DfxRecordTriggerTime, void(LnnTriggerReason, LnnEventLnnStage));
    MOCK_METHOD3(DiscLinkStatusChanged, void(LinkStatus, ExchangeMedium, int32_t));
    MOCK_METHOD2(GetWlanIpv4Addr, int32_t(char *, uint32_t));
    MOCK_METHOD2(LnnConvertAddrToOption, bool(const ConnectionAddr *, ConnectOption *));
    MOCK_METHOD2(LnnGenerateRandomByHuks, int32_t(uint8_t *, uint32_t));
    MOCK_METHOD2(LnnGenLocalIrk, int32_t(unsigned char *, uint32_t));
    MOCK_METHOD2(LnnGenLocalNetworkId, int32_t(char *, uint32_t));
    MOCK_METHOD2(LnnGenLocalUuid, int32_t(char *, uint32_t));
    MOCK_METHOD2(LnnGetAddrTypeByIfName, int32_t(const char *, ConnectionAddrType *));
    MOCK_METHOD2(LnnHasSupportDiscoveryType, bool(const char *, const char *));
    MOCK_METHOD2(LnnNotifyLeaveResult, void(const char *, int32_t));
    MOCK_METHOD2(LnnPeerHasExchangeDiscoveryType, bool(const NodeInfo *, DiscoveryType));
    MOCK_METHOD2(LnnRegisterEventHandler, int32_t(LnnEventType, LnnEventHandler));
    MOCK_METHOD3(LnnRequestLeaveByAddrType, int32_t(const bool *, uint32_t, bool));
    MOCK_METHOD2(LnnSetSupportDiscoveryType, int32_t(char *, const char *));
    MOCK_METHOD2(LnnUnregisterEventHandler, void(LnnEventType, LnnEventHandler));
    MOCK_METHOD2(LnnVisitNetif, bool(VisitNetifCallback, void *));
    MOCK_METHOD2(LnnVisitPhysicalSubnet, bool(LnnVisitPhysicalSubnetCallback, void *));
    MOCK_METHOD2(SoftBusAccessFile, int32_t(const char *, int32_t));
    MOCK_METHOD2(TransTdcStartSessionListener, int32_t(ListenerModule, const LocalListenerInfo *));
    MOCK_METHOD3(AddNumberToJsonObject, bool(cJSON *, const char * const, int));
    MOCK_METHOD3(AddStringToJsonObject, bool(cJSON *, const char * const, const char *));
    MOCK_METHOD3(AuthGetDeviceUuid, int32_t(int64_t, char *, uint16_t));
    MOCK_METHOD3(AuthGetLatestAuthSeqList, int32_t(const char *, int64_t *, uint32_t));
    MOCK_METHOD3(AuthStartListening, int32_t(AuthLinkType, const char *, int32_t));
    MOCK_METHOD3(CheckTableExist, int32_t(DbContext *, TableNameID, bool *));
    MOCK_METHOD3(EncryptedDb, int32_t(DbContext *, const uint8_t *, uint32_t));
    MOCK_METHOD3(GetRecordNumByKey, int32_t(DbContext *, TableNameID, uint8_t *));
    MOCK_METHOD3(LnnAsyncCallbackHelper, int32_t(SoftBusLooper *, LnnAsyncCallbackFunc, void *));
    MOCK_METHOD3(LnnCeDecryptDataByHuks, int32_t(const struct HksBlob *, const struct HksBlob *, struct HksBlob *));
    MOCK_METHOD3(LnnCeEncryptDataByHuks, int32_t(const struct HksBlob *, const struct HksBlob *, struct HksBlob *));
    MOCK_METHOD3(LnnConvertAuthConnInfoToAddr, bool(ConnectionAddr *, const AuthConnInfo *, ConnectionAddrType));
    MOCK_METHOD3(LnnDecryptDataByHuks, int32_t(const struct HksBlob *, const struct HksBlob *, struct HksBlob *));
    MOCK_METHOD3(LnnEncryptDataByHuks, int32_t(const struct HksBlob *, const struct HksBlob *, struct HksBlob *));
    MOCK_METHOD3(LnnGetFullStoragePath, int32_t(LnnFileId, char *, uint32_t));
    MOCK_METHOD3(LnnIsSameConnectionAddr, bool(const ConnectionAddr *, const ConnectionAddr *, bool));
    MOCK_METHOD3(LnnNotifyDiscoveryDevice, int32_t(const ConnectionAddr *, const LnnDfxDeviceInfoReport *, bool));
    MOCK_METHOD3(LnnNotifyPhysicalSubnetStatusChanged, void(const char *, ProtocolType, void *));
    MOCK_METHOD3(LnnSendNotTrustedInfo, int32_t(const NotTrustedDelayInfo *, uint32_t, LnnSyncInfoMsgComplete));
    MOCK_METHOD3(LnnVisitHbTypeSet, bool(VisitHbTypeCb, LnnHeartbeatType *, void *));
    MOCK_METHOD3(RemoveRecordByKey, int32_t(DbContext *, TableNameID, uint8_t *));
    MOCK_METHOD3(SoftbusGetConfig, int32_t(ConfigType, unsigned char *, uint32_t));
    MOCK_METHOD3(SoftBusReadFullFile, int32_t(const char *, char *, uint32_t));
    MOCK_METHOD3(SoftBusWriteFile, int32_t(const char *, const char *, uint32_t));
    MOCK_METHOD3(TransGetConnByChanId, int32_t(int32_t, int32_t, int32_t *));
    MOCK_METHOD3(UpdateDbPassword, int32_t(DbContext *, const uint8_t *, uint32_t));
    MOCK_METHOD4(ConvertBytesToHexString, int32_t(char *, uint32_t, const unsigned char *, uint32_t));
    MOCK_METHOD4(GetNetworkIpByIfName, int32_t(const char *, char *, char *, uint32_t));
    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t(SoftBusLooper *, LnnAsyncCallbackFunc, void *, uint64_t));
    MOCK_METHOD4(LnnCompareNodeWeight, int32_t(int32_t, const char *, int32_t, const char *));
    MOCK_METHOD5(AuthMetaStartVerify,
        int32_t(uint32_t, const AuthKeyInfo *, uint32_t, int32_t, const AuthVerifyCallback *));
    MOCK_METHOD5(LnnSendSyncInfoMsg,
        int32_t(LnnSyncInfoType, const char *, const uint8_t *, uint32_t, LnnSyncInfoMsgComplete));
    MOCK_METHOD5(QueryRecordByKey, int32_t(DbContext *, TableNameID, uint8_t *, uint8_t **, int));
    MOCK_METHOD3(GetOsAccountIdByUserId, int32_t(int32_t userId, char **id, uint32_t *len));
    MOCK_METHOD2(LnnGetLocalNumInfo, int32_t(InfoKey key, int32_t info));
};
} // namespace OHOS
#endif // LNN_OHOS_ACCOUNT_MOCK_H
