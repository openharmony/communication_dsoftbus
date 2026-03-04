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

#include "lnn_ohos_account_mock.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_laneDepsInterface;
LnnOhosAccountInterfaceMock::LnnOhosAccountInterfaceMock()
{
    g_laneDepsInterface = reinterpret_cast<void *>(this);
}

LnnOhosAccountInterfaceMock::~LnnOhosAccountInterfaceMock()
{
    g_laneDepsInterface = nullptr;
}

static LnnOhosAccountInterface *GetLnnOhosAccountInterface()
{
    return reinterpret_cast<LnnOhosAccountInterface *>(g_laneDepsInterface);
}

extern "C" {
int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return GetLnnOhosAccountInterface()->SoftBusGenerateStrHash(str, len, hash);
}

int32_t GetOsAccountId(char *id, uint32_t idLen, uint32_t *len)
{
    return GetLnnOhosAccountInterface()->GetOsAccountId(id, idLen, len);
}

int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len)
{
    return GetLnnOhosAccountInterface()->LnnGetLocalByteInfo(key, info, len);
}

int32_t UpdateRecoveryDeviceInfoFromDb(void)
{
    return GetLnnOhosAccountInterface()->UpdateRecoveryDeviceInfoFromDb();
}

int32_t GetCurrentAccount(int64_t *account)
{
    return GetLnnOhosAccountInterface()->GetCurrentAccount(account);
}

int32_t GetOsAccountUid(char *id, uint32_t idLen, uint32_t *len)
{
    return GetLnnOhosAccountInterface()->GetOsAccountUid(id, idLen, len);
}

int32_t LnnGetOhosAccountInfo(uint8_t *accountHash, uint32_t len)
{
    return GetLnnOhosAccountInterface()->LnnGetOhosAccountInfo(accountHash, len);
}

void DiscDeviceInfoChanged(InfoTypeChanged type)
{
    return GetLnnOhosAccountInterface()->DiscDeviceInfoChanged(type);
}

void LnnNotifyDeviceInfoChanged(SoftBusDeviceInfoState state)
{
    return GetLnnOhosAccountInterface()->LnnNotifyDeviceInfoChanged(state);
}

void LnnUpdateHeartbeatInfo(LnnHeartbeatUpdateInfoType type)
{
    return GetLnnOhosAccountInterface()->LnnUpdateHeartbeatInfo(type);
}

void ClearAuthLimitMap(void)
{
    return GetLnnOhosAccountInterface()->ClearAuthLimitMap();
}

void ClearLnnBleReportExtraMap(void)
{
    return GetLnnOhosAccountInterface()->ClearLnnBleReportExtraMap();
}

void ClearPcRestrictMap(void)
{
    return GetLnnOhosAccountInterface()->ClearPcRestrictMap();
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    return GetLnnOhosAccountInterface()->LnnSetLocalStrInfo(key, info);
}

int32_t LnnSetLocalByteInfo(InfoKey key, const uint8_t *info, uint32_t len)
{
    return GetLnnOhosAccountInterface()->LnnSetLocalByteInfo(key, info, len);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetLnnOhosAccountInterface()->LnnGetLocalStrInfo(key, info, len);
}

int32_t LnnSetLocalNum64Info(InfoKey key, int64_t info)
{
    return GetLnnOhosAccountInterface()->LnnSetLocalNum64Info(key, info);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t info)
{
    return GetLnnOhosAccountInterface()->LnnGetLocalNumInfo(key, info);
}

void LnnAccoutIdStatusSet(int64_t accountId)
{
    return GetLnnOhosAccountInterface()->LnnAccoutIdStatusSet(accountId);
}

bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num)
{
    return GetLnnOhosAccountInterface()->AddNumberToJsonObject(json, string, num);
}

bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value)
{
    return GetLnnOhosAccountInterface()->AddStringToJsonObject(json, string, value);
}

bool IsEnableSoftBusHeartbeat(void)
{
    return GetLnnOhosAccountInterface()->IsEnableSoftBusHeartbeat();
}

bool LnnConvertAddrToOption(const ConnectionAddr *addr, ConnectOption *option)
{
    return GetLnnOhosAccountInterface()->LnnConvertAddrToOption(addr, option);
}

bool LnnConvertAuthConnInfoToAddr(
    ConnectionAddr *addr, const AuthConnInfo *connInfo, ConnectionAddrType hintType)
{
    return GetLnnOhosAccountInterface()->LnnConvertAuthConnInfoToAddr(addr, connInfo, hintType);
}

bool LnnHasSupportDiscoveryType(const char *destType, const char *type)
{
    return GetLnnOhosAccountInterface()->LnnHasSupportDiscoveryType(destType, type);
}

bool LnnIsAutoNetWorkingEnabled(void)
{
    return GetLnnOhosAccountInterface()->LnnIsAutoNetWorkingEnabled();
}

bool LnnIsLinkReady(const char *iface)
{
    return GetLnnOhosAccountInterface()->LnnIsLinkReady(iface);
}

bool LnnIsSameConnectionAddr(const ConnectionAddr *addr1, const ConnectionAddr *addr2, bool isShort)
{
    return GetLnnOhosAccountInterface()->LnnIsSameConnectionAddr(addr1, addr2, isShort);
}

bool LnnPeerHasExchangeDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetLnnOhosAccountInterface()->LnnPeerHasExchangeDiscoveryType(info, type);
}

bool LnnVisitHbTypeSet(VisitHbTypeCb callback, LnnHeartbeatType *typeSet, void *data)
{
    return GetLnnOhosAccountInterface()->LnnVisitHbTypeSet(callback, typeSet, data);
}

bool LnnVisitNetif(VisitNetifCallback callback, void *data)
{
    return GetLnnOhosAccountInterface()->LnnVisitNetif(callback, data);
}

bool LnnVisitPhysicalSubnet(LnnVisitPhysicalSubnetCallback callback, void *data)
{
    return GetLnnOhosAccountInterface()->LnnVisitPhysicalSubnet(callback, data);
}

ConnectionAddrType LnnDiscTypeToConnAddrType(DiscoveryType type)
{
    return GetLnnOhosAccountInterface()->LnnDiscTypeToConnAddrType(type);
}

DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type)
{
    return GetLnnOhosAccountInterface()->LnnConvAddrTypeToDiscType(type);
}

int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo)
{
    return GetLnnOhosAccountInterface()->AuthGetConnInfo(authHandle, connInfo);
}

int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    return GetLnnOhosAccountInterface()->AuthGetDeviceUuid(authId, uuid, size);
}

int32_t AuthGetLatestAuthSeqList(const char *udid, int64_t *authSeq, uint32_t num)
{
    return GetLnnOhosAccountInterface()->AuthGetLatestAuthSeqList(udid, authSeq, num);
}

int32_t AuthMetaStartVerify(uint32_t connectionId, const AuthKeyInfo *authKeyInfo, uint32_t requestId,
    int32_t callingPid, const AuthVerifyCallback *callBack)
{
    return GetLnnOhosAccountInterface()->AuthMetaStartVerify(
        connectionId, authKeyInfo, requestId, callingPid, callBack);
}

int32_t AuthStartListening(AuthLinkType type, const char *ip, int32_t port)
{
    return GetLnnOhosAccountInterface()->AuthStartListening(type, ip, port);
}

int32_t CheckTableExist(DbContext *ctx, TableNameID id, bool *isExist)
{
    return GetLnnOhosAccountInterface()->CheckTableExist(ctx, id, isExist);
}

int32_t CloseDatabase(DbContext *ctx)
{
    return GetLnnOhosAccountInterface()->CloseDatabase(ctx);
}

int32_t ConnCoapStartServerListen(void)
{
    return GetLnnOhosAccountInterface()->ConnCoapStartServerListen();
}

int32_t ConnDisconnectDeviceAllConn(const ConnectOption *option)
{
    return GetLnnOhosAccountInterface()->ConnDisconnectDeviceAllConn(option);
}

int32_t ConnStartLocalListening(const LocalListenerInfo *info)
{
    return GetLnnOhosAccountInterface()->ConnStartLocalListening(info);
}

int32_t ConnStopLocalListening(const LocalListenerInfo *info)
{
    return GetLnnOhosAccountInterface()->ConnStopLocalListening(info);
}

int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen)
{
    return GetLnnOhosAccountInterface()->ConvertBytesToHexString(outBuf, outBufLen, inBuf, inLen);
}

int32_t CreateTable(DbContext *ctx, TableNameID id)
{
    return GetLnnOhosAccountInterface()->CreateTable(ctx, id);
}

int32_t EncryptedDb(DbContext *ctx, const uint8_t *password, uint32_t len)
{
    return GetLnnOhosAccountInterface()->EncryptedDb(ctx, password, len);
}

int32_t GetNetworkIpByIfName(const char *ifName, char *ip, char *netmask, uint32_t len)
{
    return GetLnnOhosAccountInterface()->GetNetworkIpByIfName(ifName, ip, netmask, len);
}

int32_t GetRecordNumByKey(DbContext *ctx, TableNameID id, uint8_t *data)
{
    return GetLnnOhosAccountInterface()->GetRecordNumByKey(ctx, id, data);
}

int32_t LnnAsyncCallbackDelayHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para,
    uint64_t delayMillis)
{
    return GetLnnOhosAccountInterface()->LnnAsyncCallbackDelayHelper(looper, callback, para, delayMillis);
}

int32_t LnnAsyncCallbackHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para)
{
    return GetLnnOhosAccountInterface()->LnnAsyncCallbackHelper(looper, callback, para);
}

int32_t LnnCeDecryptDataByHuks(
    const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData)
{
    return GetLnnOhosAccountInterface()->LnnCeDecryptDataByHuks(keyAlias, inData, outData);
}

int32_t LnnCeEncryptDataByHuks(
    const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData)
{
    return GetLnnOhosAccountInterface()->LnnCeEncryptDataByHuks(keyAlias, inData, outData);
}

int32_t LnnCompareNodeWeight(int32_t weight1, const char *masterUdid1, int32_t weight2, const char *masterUdid2)
{
    return GetLnnOhosAccountInterface()->LnnCompareNodeWeight(weight1, masterUdid1, weight2, masterUdid2);
}

int32_t LnnConvertHbTypeToId(LnnHeartbeatType type)
{
    return GetLnnOhosAccountInterface()->LnnConvertHbTypeToId(type);
}

int32_t LnnDecryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData)
{
    return GetLnnOhosAccountInterface()->LnnDecryptDataByHuks(keyAlias, inData, outData);
}

int32_t LnnDeleteKeyByHuks(struct HksBlob *keyAlias)
{
    return GetLnnOhosAccountInterface()->LnnDeleteKeyByHuks(keyAlias);
}

int32_t LnnEncryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData)
{
    return GetLnnOhosAccountInterface()->LnnEncryptDataByHuks(keyAlias, inData, outData);
}

int32_t LnnGenerateKeyByHuks(struct HksBlob *keyAlias)
{
    return GetLnnOhosAccountInterface()->LnnGenerateKeyByHuks(keyAlias);
}

int32_t LnnGenerateRandomByHuks(uint8_t *randomKey, uint32_t len)
{
    return GetLnnOhosAccountInterface()->LnnGenerateRandomByHuks(randomKey, len);
}

int32_t LnnGenLocalIrk(unsigned char *irk, uint32_t len)
{
    return GetLnnOhosAccountInterface()->LnnGenLocalIrk(irk, len);
}

int32_t LnnGenLocalNetworkId(char *networkId, uint32_t len)
{
    return GetLnnOhosAccountInterface()->LnnGenLocalNetworkId(networkId, len);
}

int32_t LnnGenLocalUuid(char *uuid, uint32_t len)
{
    return GetLnnOhosAccountInterface()->LnnGenLocalUuid(uuid, len);
}

int32_t LnnGetAddrTypeByIfName(const char *ifName, ConnectionAddrType *type)
{
    return GetLnnOhosAccountInterface()->LnnGetAddrTypeByIfName(ifName, type);
}

int32_t LnnGetFullStoragePath(LnnFileId id, char *path, uint32_t len)
{
    return GetLnnOhosAccountInterface()->LnnGetFullStoragePath(id, path, len);
}

int32_t LnnGetWlanIpv4Addr(char *ip, uint32_t size)
{
    return GetLnnOhosAccountInterface()->GetWlanIpv4Addr(ip, size);
}

int32_t LnnInitDevicename(void)
{
    return GetLnnOhosAccountInterface()->LnnInitDevicename();
}

int32_t LnnInitNetworkInfo(void)
{
    return GetLnnOhosAccountInterface()->LnnInitNetworkInfo();
}

int32_t LnnInitP2p(void)
{
    return GetLnnOhosAccountInterface()->LnnInitP2p();
}

int32_t LnnInitPhysicalSubnetManager(void)
{
    return GetLnnOhosAccountInterface()->LnnInitPhysicalSubnetManager();
}

int32_t LnnInitSyncInfoManager(void)
{
    return GetLnnOhosAccountInterface()->LnnInitSyncInfoManager();
}

int32_t LnnInitTopoManager(void)
{
    return GetLnnOhosAccountInterface()->LnnInitTopoManager();
}

int32_t LnnInitWifiDirect(void)
{
    return GetLnnOhosAccountInterface()->LnnInitWifiDirect();
}

int32_t LnnNotifyDiscoveryDevice(const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport,
    bool isNeedConnect)
{
    return GetLnnOhosAccountInterface()->LnnNotifyDiscoveryDevice(addr, infoReport, isNeedConnect);
}

int32_t LnnRegistPhysicalSubnet(LnnPhysicalSubnet *manager)
{
    return GetLnnOhosAccountInterface()->LnnRegistPhysicalSubnet(manager);
}

int32_t lnnRegistProtocol(LnnProtocolManager *protocolMgr)
{
    return GetLnnOhosAccountInterface()->LnnRegistProtocol(protocolMgr);
}

int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen, bool hasMcuRequestDisable)
{
    return GetLnnOhosAccountInterface()->LnnRequestLeaveByAddrType(type, typeLen, hasMcuRequestDisable);
}

int32_t LnnSendNotTrustedInfo(const NotTrustedDelayInfo *info, uint32_t num, LnnSyncInfoMsgComplete complete)
{
    return GetLnnOhosAccountInterface()->LnnSendNotTrustedInfo(info, num, complete);
}

int32_t LnnSendSyncInfoMsg(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len,
    LnnSyncInfoMsgComplete complete)
{
    return GetLnnOhosAccountInterface()->LnnSendSyncInfoMsg(type, networkId, msg, len, complete);
}

int32_t LnnSetSupportDiscoveryType(char *info, const char *type)
{
    return GetLnnOhosAccountInterface()->LnnSetSupportDiscoveryType(info, type);
}

int32_t LnnStartDiscovery(void)
{
    return GetLnnOhosAccountInterface()->LnnStartDiscovery();
}

int32_t LnnStartPublish(void)
{
    return GetLnnOhosAccountInterface()->LnnStartPublish();
}

int32_t OpenDatabase(DbContext **ctx)
{
    return GetLnnOhosAccountInterface()->OpenDatabase(ctx);
}

int32_t QueryRecordByKey(DbContext *ctx, TableNameID id, uint8_t *data, uint8_t **replyInfo, int32_t infoNum)
{
    return GetLnnOhosAccountInterface()->QueryRecordByKey(ctx, id, data, replyInfo, infoNum);
}

int32_t RegistIPProtocolManager(void)
{
    return GetLnnOhosAccountInterface()->RegistIPProtocolManager();
}

int32_t RemoveRecordByKey(DbContext *ctx, TableNameID id, uint8_t *data)
{
    return GetLnnOhosAccountInterface()->RemoveRecordByKey(ctx, id, data);
}

int32_t SoftBusAccessFile(const char *pathName, int32_t mode)
{
    return GetLnnOhosAccountInterface()->SoftBusAccessFile(pathName, mode);
}

int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    return GetLnnOhosAccountInterface()->SoftbusGetConfig(type, val, len);
}

int32_t SoftBusGetTime(SoftBusSysTime *sysTime)
{
    return GetLnnOhosAccountInterface()->SoftBusGetTime(sysTime);
}

int32_t SoftBusReadFullFile(const char *fileName, char *readBuf, uint32_t maxLen)
{
    return GetLnnOhosAccountInterface()->SoftBusReadFullFile(fileName, readBuf, maxLen);
}

int32_t SoftBusWriteFile(const char *fileName, const char *writeBuf, uint32_t len)
{
    return GetLnnOhosAccountInterface()->SoftBusWriteFile(fileName, writeBuf, len);
}

int32_t TransGetConnByChanId(int32_t channelId, int32_t channelType, int32_t *connId)
{
    return GetLnnOhosAccountInterface()->TransGetConnByChanId(channelId, channelType, connId);
}

int32_t TransTdcStartSessionListener(ListenerModule module, const LocalListenerInfo *info)
{
    return GetLnnOhosAccountInterface()->TransTdcStartSessionListener(module, info);
}

int32_t TransTdcStopSessionListener(ListenerModule module)
{
    return GetLnnOhosAccountInterface()->TransTdcStopSessionListener(module);
}

int32_t UpdateDbPassword(DbContext *ctx, const uint8_t *password, uint32_t len)
{
    return GetLnnOhosAccountInterface()->UpdateDbPassword(ctx, password, len);
}

SoftBusLooper *GetLooper(int32_t looper)
{
    return GetLnnOhosAccountInterface()->GetLooper(looper);
}

TrustedReturnType AuthHasTrustedRelation(void)
{
    return GetLnnOhosAccountInterface()->AuthHasTrustedRelation();
}

uint32_t AuthGenRequestId(void)
{
    return GetLnnOhosAccountInterface()->AuthGenRequestId();
}

void AuthHandleLeaveLNN(AuthHandle authHandle)
{
    GetLnnOhosAccountInterface()->AuthHandleLeaveLNN(authHandle);
}

void AuthStopListening(AuthLinkType type)
{
    GetLnnOhosAccountInterface()->AuthStopListening(type);
}

void ConnCoapStopServerListen(void)
{
    GetLnnOhosAccountInterface()->ConnCoapStopServerListen();
}

void DfxRecordTriggerTime(LnnTriggerReason reason, LnnEventLnnStage stage)
{
    GetLnnOhosAccountInterface()->DfxRecordTriggerTime(reason, stage);
}

void DiscLinkStatusChanged(LinkStatus status, ExchangeMedium medium, int32_t ifnameIdx)
{
    GetLnnOhosAccountInterface()->DiscLinkStatusChanged(status, medium, ifnameIdx);
}

void LnnDeinitP2p(void)
{
    GetLnnOhosAccountInterface()->LnnDeinitP2p();
}

void LnnDeinitPhysicalSubnetManager(void)
{
    GetLnnOhosAccountInterface()->LnnDeinitPhysicalSubnetManager();
}

void LnnDeinitSyncInfoManager(void)
{
    GetLnnOhosAccountInterface()->LnnDeinitSyncInfoManager();
}

void LnnDeinitTopoManager(void)
{
    GetLnnOhosAccountInterface()->LnnDeinitTopoManager();
}

void LnnDeinitWifiDirect(void)
{
    GetLnnOhosAccountInterface()->LnnDeinitWifiDirect();
}

void LnnHbClearRecvList(void)
{
    GetLnnOhosAccountInterface()->LnnHbClearRecvList();
}

void LnnIpAddrChangeEventHandler(void)
{
    GetLnnOhosAccountInterface()->LnnIpAddrChangeEventHandler();
}

void LnnNotifyAccountStateChangeEvent(SoftBusAccountState state)
{
    GetLnnOhosAccountInterface()->LnnNotifyAccountStateChangeEvent(state);
}

void LnnNotifyAllTypeOffline(ConnectionAddrType type)
{
    GetLnnOhosAccountInterface()->LnnNotifyAllTypeOffline(type);
}

void LnnNotifyHBRepeat(void)
{
    GetLnnOhosAccountInterface()->LnnNotifyHBRepeat();
}

void LnnNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    GetLnnOhosAccountInterface()->LnnNotifyLeaveResult(networkId, retCode);
}

void LnnNotifyNetworkStateChanged(SoftBusNetworkState state)
{
    GetLnnOhosAccountInterface()->LnnNotifyNetworkStateChanged(state);
}

void LnnNotifyOOBEStateChangeEvent(SoftBusOOBEState state)
{
    GetLnnOhosAccountInterface()->LnnNotifyOOBEStateChangeEvent(state);
}

void LnnNotifyPhysicalSubnetStatusChanged(const char *ifName, ProtocolType protocolType, void *status)
{
    GetLnnOhosAccountInterface()->LnnNotifyPhysicalSubnetStatusChanged(ifName, protocolType, status);
}

void LnnOnOhosAccountChanged(void)
{
    GetLnnOhosAccountInterface()->LnnOnOhosAccountChanged();
}

void LnnOnOhosAccountLogout(void)
{
    GetLnnOhosAccountInterface()->LnnOnOhosAccountLogout();
}

void LnnSetUnlockState(void)
{
    GetLnnOhosAccountInterface()->LnnSetUnlockState();
}

void LnnStopDiscovery(void)
{
    GetLnnOhosAccountInterface()->LnnStopDiscovery();
}

void LnnStopPublish(void)
{
    GetLnnOhosAccountInterface()->LnnStopPublish();
}

void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    GetLnnOhosAccountInterface()->LnnUnregisterEventHandler(event, handler);
}

void LnnUpdateOhosAccount(UpdateAccountReason reason)
{
    GetLnnOhosAccountInterface()->LnnUpdateOhosAccount(reason);
}

int32_t GetOsAccountIdByUserId(int32_t userId, char **id, uint32_t *len)
{
    return GetLnnOhosAccountInterface()->GetOsAccountIdByUserId(userId, id, len);
}
}
} // namespace OHOS