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

#include <cstdint>
#include <securec.h>

#include "lnn_local_ledger_deps_mock.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_localLedgerDepsInterface;
constexpr char DEFAULT_DEVICE_NAME[] = "OpenHarmony";
constexpr char DEFAULT_DEVICE_UDID[] = "aaabbbcccdddeeefffggghhh";
constexpr char DEFAULT_DEVICE_TYPE[] = "default_type";
constexpr char GLASS_TYPE[] = "A31";
constexpr char WATCH_TYPE[] = "WATCH";
constexpr int32_t SOFTBUS_BUSCENTER_DUMP_LOCALDEVICEINFO_FD = -1;

LocalLedgerDepsInterfaceMock::LocalLedgerDepsInterfaceMock()
{
    g_localLedgerDepsInterface = reinterpret_cast<void *>(this);
}

LocalLedgerDepsInterfaceMock::~LocalLedgerDepsInterfaceMock()
{
    g_localLedgerDepsInterface = nullptr;
}

static LocalLedgerDepsInterfaceMock *GetLocalLedgerDepsInterface()
{
    return reinterpret_cast<LocalLedgerDepsInterfaceMock *>(g_localLedgerDepsInterface);
}

int32_t LocalLedgerDepsInterfaceMock::LedgerGetCommonDevInfo(const CommonDeviceKey key, char *value, uint32_t len)
{
    if (value == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    switch (key) {
        case COMM_DEVICE_KEY_DEVNAME:
            if (strncpy_s(value, len, DEFAULT_DEVICE_NAME, strlen(DEFAULT_DEVICE_NAME)) != EOK) {
                return SOFTBUS_STRCPY_ERR;
            }
            break;
        case COMM_DEVICE_KEY_UDID:
            if (strncpy_s(value, len, DEFAULT_DEVICE_UDID, UDID_BUF_LEN) != EOK) {
                return SOFTBUS_STRCPY_ERR;
            }
            break;
        case COMM_DEVICE_KEY_DEVTYPE:
            if (strncpy_s(value, len, DEFAULT_DEVICE_TYPE, strlen(DEFAULT_DEVICE_TYPE)) != EOK) {
                return SOFTBUS_STRCPY_ERR;
            }
            break;
        default:
            break;
    }
    return SOFTBUS_OK;
}

int32_t LocalLedgerDepsInterfaceMock::LedgerGetCommonDevInfoGlass(const CommonDeviceKey key, char *value, uint32_t len)
{
    static bool isFirst = true;
    const char *type = isFirst ? GLASS_TYPE : WATCH_TYPE;
    if (value == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    switch (key) {
        case COMM_DEVICE_KEY_DEVNAME:
            if (strncpy_s(value, len, DEFAULT_DEVICE_NAME, strlen(DEFAULT_DEVICE_NAME)) != EOK) {
                return SOFTBUS_STRCPY_ERR;
            }
            break;
        case COMM_DEVICE_KEY_UDID:
            if (strncpy_s(value, len, DEFAULT_DEVICE_UDID, UDID_BUF_LEN) != EOK) {
                return SOFTBUS_STRCPY_ERR;
            }
            break;
        case COMM_DEVICE_KEY_DEVTYPE:
            if (strncpy_s(value, len, type, strlen(type)) != EOK) {
                return SOFTBUS_STRCPY_ERR;
            }
            break;
        default:
            break;
    }
    isFirst = false;
    return SOFTBUS_OK;
}

int32_t LocalLedgerDepsInterfaceMock::LedgerSoftBusRegBusCenterVarDump(char *dumpVar, SoftBusVarDumpCb cb)
{
    int32_t ret = SOFTBUS_INVALID_PARAM;
    if (cb != nullptr) {
        ret = cb(SOFTBUS_BUSCENTER_DUMP_LOCALDEVICEINFO_FD);
    }
    return ret;
}

int32_t LocalLedgerDepsInterfaceMock::MockGetLocalSleAddrFunc(char *sleAddr, uint32_t sleAddrLen)
{
    if (sleAddr == nullptr) {
        return SOFTBUS_ERR;
    }
    static char mockSleAddr[MAC_LEN] = "11:11:11:11:11:11";
    if (memcpy_s(sleAddr, sleAddrLen, mockSleAddr, MAC_LEN) != EOK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

extern "C" {
uint32_t LnnGetNetCapabilty(void)
{
    return GetLocalLedgerDepsInterface()->LnnGetNetCapabilty();
}

int32_t SoftBusGenerateRandomArray(unsigned char *randStr, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->SoftBusGenerateRandomArray(randStr, len);
}

int32_t GetCommonDevInfo(const CommonDeviceKey key, char *value, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->GetCommonDevInfo(key, value, len);
}

int32_t LnnInitLocalP2pInfo(NodeInfo *info)
{
    return GetLocalLedgerDepsInterface()->LnnInitLocalP2pInfo(info);
}

int32_t SoftBusRegBusCenterVarDump(char *dumpVar, SoftBusVarDumpCb cb)
{
    return GetLocalLedgerDepsInterface()->SoftBusRegBusCenterVarDump(dumpVar, cb);
}

int32_t LnnInitOhosAccount(void)
{
    return GetLocalLedgerDepsInterface()->LnnInitOhosAccount();
}

uint64_t LnnGetFeatureCapabilty(void)
{
    return GetLocalLedgerDepsInterface()->LnnGetFeatureCapabilty();
}

bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit)
{
    return GetLocalLedgerDepsInterface()->IsFeatureSupport(feature, capaBit);
}

int32_t GetCommonOsType(int32_t *value)
{
    return GetLocalLedgerDepsInterface()->GetCommonOsType(value);
}

int32_t GetCommonOsVersion(char *value, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->GetCommonOsVersion(value, len);
}

int32_t GetCommonDeviceVersion(char *value, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->GetCommonDeviceVersion(value, len);
}

int32_t GetDeviceSecurityLevel(int32_t *level)
{
    return GetLocalLedgerDepsInterface()->GetDeviceSecurityLevel(level);
}

int32_t SoftBusGetBtState(void)
{
    return GetLocalLedgerDepsInterface()->SoftBusGetBtState();
}

int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac)
{
    return GetLocalLedgerDepsInterface()->SoftBusGetBtMacAddr(mac);
}

bool IsSleEnabled(void)
{
    return GetLocalLedgerDepsInterface()->IsSleEnabled();
}

int SoftBusAddSleStateListener(const SoftBusSleStateListener *listener, int *listenerId)
{
    return GetLocalLedgerDepsInterface()->SoftBusAddSleStateListener(listener, listenerId);
}

void SoftBusRemoveSleStateListener(int listenerId)
{
    return GetLocalLedgerDepsInterface()->SoftBusRemoveSleStateListener(listenerId);
}

int32_t GetSleRangeCapacity()
{
    return GetLocalLedgerDepsInterface()->GetSleRangeCapacity();
}

int32_t GetLocalSleAddr(char *sleAddr, uint32_t sleAddrLen)
{
    return GetLocalLedgerDepsInterface()->GetLocalSleAddr(sleAddr, sleAddrLen);
}

int32_t LnnGenerateKeyByHuks(struct HksBlob *keyAlias)
{
    return GetLocalLedgerDepsInterface()->LnnGenerateKeyByHuks(keyAlias);
}

int32_t LnnDeleteKeyByHuks(struct HksBlob *keyAlias)
{
    return GetLocalLedgerDepsInterface()->LnnDeleteKeyByHuks(keyAlias);
}

int32_t LnnEncryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData)
{
    return GetLocalLedgerDepsInterface()->LnnEncryptDataByHuks(keyAlias, inData, outData);
}

int32_t LnnDecryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData)
{
    return GetLocalLedgerDepsInterface()->LnnDecryptDataByHuks(keyAlias, inData, outData);
}

int32_t LnnGenerateRandomByHuks(uint8_t *randomKey, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->LnnGenerateRandomByHuks(randomKey, len);
}

int32_t OpenDatabase(DbContext **ctx)
{
    return GetLocalLedgerDepsInterface()->OpenDatabase(ctx);
}

int32_t CloseDatabase(DbContext *ctx)
{
    return GetLocalLedgerDepsInterface()->CloseDatabase(ctx);
}

int32_t CreateTable(DbContext *ctx, TableNameID id)
{
    return GetLocalLedgerDepsInterface()->CreateTable(ctx, id);
}

int32_t CheckTableExist(DbContext *ctx, TableNameID id, bool *isExist)
{
    return GetLocalLedgerDepsInterface()->CheckTableExist(ctx, id, isExist);
}

int32_t RemoveRecordByKey(DbContext *ctx, TableNameID id, uint8_t *data)
{
    return GetLocalLedgerDepsInterface()->RemoveRecordByKey(ctx, id, data);
}

int32_t GetRecordNumByKey(DbContext *ctx, TableNameID id, uint8_t *data)
{
    return GetLocalLedgerDepsInterface()->GetRecordNumByKey(ctx, id, data);
}

int32_t EncryptedDb(DbContext *ctx, const uint8_t *password, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->EncryptedDb(ctx, password, len);
}

int32_t UpdateDbPassword(DbContext *ctx, const uint8_t *password, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->UpdateDbPassword(ctx, password, len);
}

int32_t QueryRecordByKey(DbContext *ctx, TableNameID id, uint8_t *data, uint8_t **replyInfo, int32_t infoNum)
{
    return GetLocalLedgerDepsInterface()->QueryRecordByKey(ctx, id, data, replyInfo, infoNum);
}

int32_t LnnGetFullStoragePath(LnnFileId id, char *path, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->LnnGetFullStoragePath(id, path, len);
}

int32_t SoftBusReadFullFile(const char *fileName, char *readBuf, uint32_t maxLen)
{
    return GetLocalLedgerDepsInterface()->SoftBusReadFullFile(fileName, readBuf, maxLen);
}

int32_t SoftBusWriteFile(const char *fileName, const char *writeBuf, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->SoftBusWriteFile(fileName, writeBuf, len);
}

int32_t SoftBusAccessFile(const char *pathName, int32_t mode)
{
    return GetLocalLedgerDepsInterface()->SoftBusAccessFile(pathName, mode);
}

int32_t LnnAsyncCallbackHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para)
{
    return GetLocalLedgerDepsInterface()->LnnAsyncCallbackHelper(looper, callback, para);
}

int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen)
{
    return GetLocalLedgerDepsInterface()->ConvertBytesToHexString(outBuf, outBufLen, inBuf, inLen);
}

void LnnNotifyNetworkStateChanged(SoftBusNetworkState state)
{
    return GetLocalLedgerDepsInterface()->LnnNotifyNetworkStateChanged(state);
}

TrustedReturnType AuthHasTrustedRelation(void)
{
    return GetLocalLedgerDepsInterface()->AuthHasTrustedRelation();
}

bool IsEnableSoftBusHeartbeat(void)
{
    return GetLocalLedgerDepsInterface()->IsEnableSoftBusHeartbeat();
}

void LnnNotifyHBRepeat(void)
{
    return GetLocalLedgerDepsInterface()->LnnNotifyHBRepeat();
}

void LnnHbClearRecvList(void)
{
    return GetLocalLedgerDepsInterface()->LnnHbClearRecvList();
}

int32_t LnnConvertHbTypeToId(LnnHeartbeatType type)
{
    return GetLocalLedgerDepsInterface()->LnnConvertHbTypeToId(type);
}

bool LnnVisitHbTypeSet(VisitHbTypeCb callback, LnnHeartbeatType *typeSet, void *data)
{
    return GetLocalLedgerDepsInterface()->LnnVisitHbTypeSet(callback, typeSet, data);
}

int32_t LnnCeEncryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData)
{
    return GetLocalLedgerDepsInterface()->LnnCeEncryptDataByHuks(keyAlias, inData, outData);
}

int32_t LnnCeDecryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData)
{
    return GetLocalLedgerDepsInterface()->LnnCeDecryptDataByHuks(keyAlias, inData, outData);
}

int32_t RegistIPProtocolManager(void)
{
    return GetLocalLedgerDepsInterface()->RegistIPProtocolManager();
}

int32_t LnnInitPhysicalSubnetManager(void)
{
    return GetLocalLedgerDepsInterface()->LnnInitPhysicalSubnetManager();
}

void LnnOnOhosAccountChanged(void)
{
    return GetLocalLedgerDepsInterface()->LnnOnOhosAccountChanged();
}

int32_t LnnStartDiscovery(void)
{
    return GetLocalLedgerDepsInterface()->LnnStartDiscovery();
}

int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->SoftbusGetConfig(type, val, len);
}

int32_t LnnNotifyDiscoveryDevice(
    const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport, bool isNeedConnect)
{
    return GetLocalLedgerDepsInterface()->LnnNotifyDiscoveryDevice(addr, infoReport, isNeedConnect);
}

int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen, bool hasMcuRequestDisable)
{
    return GetLocalLedgerDepsInterface()->LnnRequestLeaveByAddrType(type, typeLen, hasMcuRequestDisable);
}

int32_t LnnAsyncCallbackDelayHelper(
    SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis)
{
    return GetLocalLedgerDepsInterface()->LnnAsyncCallbackDelayHelper(looper, callback, para, delayMillis);
}

void LnnUpdateOhosAccount(UpdateAccountReason reason)
{
    return GetLocalLedgerDepsInterface()->LnnUpdateOhosAccount(reason);
}

void LnnOnOhosAccountLogout(void)
{
    return GetLocalLedgerDepsInterface()->LnnOnOhosAccountLogout();
}

void LnnNotifyOOBEStateChangeEvent(SoftBusOOBEState state)
{
    return GetLocalLedgerDepsInterface()->LnnNotifyOOBEStateChangeEvent(state);
}

void LnnNotifyAccountStateChangeEvent(SoftBusAccountState state)
{
    return GetLocalLedgerDepsInterface()->LnnNotifyAccountStateChangeEvent(state);
}

void LnnDeinitPhysicalSubnetManager(void)
{
    return GetLocalLedgerDepsInterface()->LnnDeinitPhysicalSubnetManager();
}

void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetLocalLedgerDepsInterface()->LnnUnregisterEventHandler(event, handler);
}

void DfxRecordTriggerTime(LnnTriggerReason reason, LnnEventLnnStage stage)
{
    return GetLocalLedgerDepsInterface()->DfxRecordTriggerTime(reason, stage);
}

int32_t LnnRegistPhysicalSubnet(LnnPhysicalSubnet *manager)
{
    return GetLocalLedgerDepsInterface()->LnnRegistPhysicalSubnet(manager);
}

void DiscLinkStatusChanged(LinkStatus status, ExchangeMedium medium, int32_t ifnameIdx)
{
    return GetLocalLedgerDepsInterface()->DiscLinkStatusChanged(status, medium, ifnameIdx);
}

bool LnnVisitPhysicalSubnet(LnnVisitPhysicalSubnetCallback callback, void *data)
{
    return GetLocalLedgerDepsInterface()->LnnVisitPhysicalSubnet(callback, data);
}

void LnnStopPublish(void)
{
    return GetLocalLedgerDepsInterface()->LnnStopPublish();
}

void LnnStopDiscovery(void)
{
    return GetLocalLedgerDepsInterface()->LnnStopDiscovery();
}

void LnnIpAddrChangeEventHandler(void)
{
    return GetLocalLedgerDepsInterface()->LnnIpAddrChangeEventHandler();
}

void AuthStopListening(AuthLinkType type)
{
    return GetLocalLedgerDepsInterface()->AuthStopListening(type);
}

int32_t TransTdcStopSessionListener(ListenerModule module)
{
    return GetLocalLedgerDepsInterface()->TransTdcStopSessionListener(module);
}

int32_t ConnStopLocalListening(const LocalListenerInfo *info)
{
    return GetLocalLedgerDepsInterface()->ConnStopLocalListening(info);
}

int32_t LnnGetAddrTypeByIfName(const char *ifName, ConnectionAddrType *type)
{
    return GetLocalLedgerDepsInterface()->LnnGetAddrTypeByIfName(ifName, type);
}

int32_t LnnStartPublish(void)
{
    return GetLocalLedgerDepsInterface()->LnnStartPublish();
}

bool LnnIsAutoNetWorkingEnabled(void)
{
    return GetLocalLedgerDepsInterface()->LnnIsAutoNetWorkingEnabled();
}

int32_t AuthStartListening(AuthLinkType type, const char *ip, int32_t port)
{
    return GetLocalLedgerDepsInterface()->AuthStartListening(type, ip, port);
}

int32_t TransTdcStartSessionListener(ListenerModule module, const LocalListenerInfo *info)
{
    return GetLocalLedgerDepsInterface()->TransTdcStartSessionListener(module, info);
}

int32_t ConnStartLocalListening(const LocalListenerInfo *info)
{
    return GetLocalLedgerDepsInterface()->ConnStartLocalListening(info);
}

bool LnnIsLinkReady(const char *iface)
{
    return GetLocalLedgerDepsInterface()->LnnIsLinkReady(iface);
}

void LnnNotifyPhysicalSubnetStatusChanged(const char *ifName, ProtocolType protocolType, void *status)
{
    return GetLocalLedgerDepsInterface()->LnnNotifyPhysicalSubnetStatusChanged(ifName, protocolType, status);
}

bool LnnVisitNetif(VisitNetifCallback callback, void *data)
{
    return GetLocalLedgerDepsInterface()->LnnVisitNetif(callback, data);
}

int32_t GetNetworkIpByIfName(const char *ifName, char *ip, char *netmask, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->GetNetworkIpByIfName(ifName, ip, netmask, len);
}

int32_t lnnRegistProtocol(LnnProtocolManager *protocolMgr)
{
    return GetLocalLedgerDepsInterface()->LnnRegistProtocol(protocolMgr);
}

int32_t LnnGetWlanIpv4Addr(char *ip, uint32_t size)
{
    return GetLocalLedgerDepsInterface()->GetWlanIpv4Addr(ip, size);
}

int32_t ConnCoapStartServerListen(void)
{
    return GetLocalLedgerDepsInterface()->ConnCoapStartServerListen();
}

void ConnCoapStopServerListen(void)
{
    return GetLocalLedgerDepsInterface()->ConnCoapStopServerListen();
}

int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    return GetLocalLedgerDepsInterface()->AuthGetDeviceUuid(authId, uuid, size);
}

int32_t TransGetConnByChanId(int32_t channelId, int32_t channelType, int32_t *connId)
{
    return GetLocalLedgerDepsInterface()->TransGetConnByChanId(channelId, channelType, connId);
}

int32_t AuthMetaStartVerify(uint32_t connectionId, const AuthKeyInfo *authKeyInfo, uint32_t requestId,
    int32_t callingPid, const AuthVerifyCallback *callBack)
{
    return GetLocalLedgerDepsInterface()->AuthMetaStartVerify(
        connectionId, authKeyInfo, requestId, callingPid, callBack);
}

uint32_t AuthGenRequestId(void)
{
    return GetLocalLedgerDepsInterface()->AuthGenRequestId();
}

void LnnSetUnlockState(void)
{
    return GetLocalLedgerDepsInterface()->LnnSetUnlockState();
}

void AuthHandleLeaveLNN(AuthHandle authHandle)
{
    return GetLocalLedgerDepsInterface()->AuthHandleLeaveLNN(authHandle);
}

bool LnnIsSameConnectionAddr(const ConnectionAddr *addr1, const ConnectionAddr *addr2, bool isShort)
{
    return GetLocalLedgerDepsInterface()->LnnIsSameConnectionAddr(addr1, addr2, isShort);
}

bool LnnConvertAddrToOption(const ConnectionAddr *addr, ConnectOption *option)
{
    return GetLocalLedgerDepsInterface()->LnnConvertAddrToOption(addr, option);
}

DiscoveryType LnnConvAddrTypeToDiscType(ConnectionAddrType type)
{
    return GetLocalLedgerDepsInterface()->LnnConvAddrTypeToDiscType(type);
}

ConnectionAddrType LnnDiscTypeToConnAddrType(DiscoveryType type)
{
    return GetLocalLedgerDepsInterface()->LnnDiscTypeToConnAddrType(type);
}

bool LnnConvertAuthConnInfoToAddr(ConnectionAddr *addr, const AuthConnInfo *connInfo, ConnectionAddrType hintType)
{
    return GetLocalLedgerDepsInterface()->LnnConvertAuthConnInfoToAddr(addr, connInfo, hintType);
}

bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value)
{
    return GetLocalLedgerDepsInterface()->AddStringToJsonObject(json, string, value);
}

bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num)
{
    return GetLocalLedgerDepsInterface()->AddNumberToJsonObject(json, string, num);
}

int32_t LnnSendSyncInfoMsg(
    LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len, LnnSyncInfoMsgComplete complete)
{
    return GetLocalLedgerDepsInterface()->LnnSendSyncInfoMsg(type, networkId, msg, len, complete);
}

int32_t AuthGetLatestAuthSeqList(const char *udid, int64_t *authSeq, uint32_t num)
{
    return GetLocalLedgerDepsInterface()->AuthGetLatestAuthSeqList(udid, authSeq, num);
}

int32_t LnnSetSupportDiscoveryType(char *info, const char *type)
{
    return GetLocalLedgerDepsInterface()->LnnSetSupportDiscoveryType(info, type);
}

bool LnnHasSupportDiscoveryType(const char *destType, const char *type)
{
    return GetLocalLedgerDepsInterface()->LnnHasSupportDiscoveryType(destType, type);
}

bool LnnPeerHasExchangeDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetLocalLedgerDepsInterface()->LnnPeerHasExchangeDiscoveryType(info, type);
}

int32_t LnnCompareNodeWeight(int32_t weight1, const char *masterUdid1, int32_t weight2, const char *masterUdid2)
{
    return GetLocalLedgerDepsInterface()->LnnCompareNodeWeight(weight1, masterUdid1, weight2, masterUdid2);
}

void LnnNotifyAllTypeOffline(ConnectionAddrType type)
{
    return GetLocalLedgerDepsInterface()->LnnNotifyAllTypeOffline(type);
}

int32_t SoftBusGetTime(SoftBusSysTime *sysTime)
{
    return GetLocalLedgerDepsInterface()->SoftBusGetTime(sysTime);
}

int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo)
{
    return GetLocalLedgerDepsInterface()->AuthGetConnInfo(authHandle, connInfo);
}

void LnnNotifyLeaveResult(const char *networkId, int32_t retCode)
{
    return GetLocalLedgerDepsInterface()->LnnNotifyLeaveResult(networkId, retCode);
}

int32_t LnnSendNotTrustedInfo(const NotTrustedDelayInfo *info, uint32_t num, LnnSyncInfoMsgComplete complete)
{
    return GetLocalLedgerDepsInterface()->LnnSendNotTrustedInfo(info, num, complete);
}

SoftBusLooper *GetLooper(int32_t looper)
{
    return GetLocalLedgerDepsInterface()->GetLooper(looper);
}

int32_t ConnDisconnectDeviceAllConn(const ConnectOption *option)
{
    return GetLocalLedgerDepsInterface()->ConnDisconnectDeviceAllConn(option);
}

int32_t LnnGenLocalUuid(char *uuid, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->LnnGenLocalUuid(uuid, len);
}

int32_t LnnGenLocalIrk(unsigned char *irk, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->LnnGenLocalIrk(irk, len);
}

int32_t LnnGenLocalNetworkId(char *networkId, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->LnnGenLocalNetworkId(networkId, len);
}

int32_t LnnInitP2p(void)
{
    return GetLocalLedgerDepsInterface()->LnnInitP2p();
}

int32_t LnnInitWifiDirect(void)
{
    return GetLocalLedgerDepsInterface()->LnnInitWifiDirect();
}

void LnnDeinitP2p(void)
{
    return GetLocalLedgerDepsInterface()->LnnDeinitP2p();
}

void LnnDeinitWifiDirect(void)
{
    return GetLocalLedgerDepsInterface()->LnnDeinitWifiDirect();
}

int32_t LnnInitNetworkInfo(void)
{
    return GetLocalLedgerDepsInterface()->LnnInitNetworkInfo();
}

int32_t LnnInitDevicename(void)
{
    return GetLocalLedgerDepsInterface()->LnnInitDevicename();
}

int32_t LnnInitSyncInfoManager(void)
{
    return GetLocalLedgerDepsInterface()->LnnInitSyncInfoManager();
}

void LnnDeinitSyncInfoManager(void)
{
    return GetLocalLedgerDepsInterface()->LnnDeinitSyncInfoManager();
}

int32_t LnnInitTopoManager(void)
{
    return GetLocalLedgerDepsInterface()->LnnInitTopoManager();
}

void LnnDeinitTopoManager(void)
{
    return GetLocalLedgerDepsInterface()->LnnDeinitTopoManager();
}

int32_t RegAuthVerifyListener(const AuthVerifyListener *listener)
{
    return GetLocalLedgerDepsInterface()->RegAuthVerifyListener(listener);
}

void UnregAuthVerifyListener(void)
{
    return GetLocalLedgerDepsInterface()->UnregAuthVerifyListener();
}

int32_t LnnRegSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler)
{
    return GetLocalLedgerDepsInterface()->LnnRegSyncInfoHandler(type, handler);
}

int32_t LnnUnregSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler)
{
    return GetLocalLedgerDepsInterface()->LnnUnregSyncInfoHandler(type, handler);
}

int32_t LnnStopConnectionFsm(LnnConnectionFsm *connFsm, LnnConnectionFsmStopCallback callback)
{
    return GetLocalLedgerDepsInterface()->LnnStopConnectionFsm(connFsm, callback);
}

void LnnDeinitFastOffline(void)
{
    return GetLocalLedgerDepsInterface()->LnnDeinitFastOffline();
}

int32_t LnnSendNewNetworkOnlineToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetLocalLedgerDepsInterface()->LnnSendNewNetworkOnlineToConnFsm(connFsm);
}

int32_t LnnSendAuthResultMsgToConnFsm(LnnConnectionFsm *connFsm, int32_t retCode)
{
    return GetLocalLedgerDepsInterface()->LnnSendAuthResultMsgToConnFsm(connFsm, retCode);
}

int32_t LnnSendDisconnectMsgToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetLocalLedgerDepsInterface()->LnnSendDisconnectMsgToConnFsm(connFsm);
}

int32_t LnnSendNotTrustedToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetLocalLedgerDepsInterface()->LnnSendNotTrustedToConnFsm(connFsm);
}

int32_t LnnSendLeaveRequestToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetLocalLedgerDepsInterface()->LnnSendLeaveRequestToConnFsm(connFsm);
}

int32_t LnnSendSyncOfflineFinishToConnFsm(LnnConnectionFsm *connFsm)
{
    return GetLocalLedgerDepsInterface()->LnnSendSyncOfflineFinishToConnFsm(connFsm);
}

int32_t LnnGetLocalWeight(void)
{
    return GetLocalLedgerDepsInterface()->LnnGetLocalWeight();
}

void AuthMetaReleaseVerify(int64_t authId)
{
    return GetLocalLedgerDepsInterface()->AuthMetaReleaseVerify(authId);
}

int32_t LnnSendJoinRequestToConnFsm(LnnConnectionFsm *connFsm, bool isForceJoin)
{
    return GetLocalLedgerDepsInterface()->LnnSendJoinRequestToConnFsm(connFsm, isForceJoin);
}

void LnnNotifyJoinResult(ConnectionAddr *addr, const char *networkId, int32_t retCode)
{
    return GetLocalLedgerDepsInterface()->LnnNotifyJoinResult(addr, networkId, retCode);
}

void LnnDestroyConnectionFsm(LnnConnectionFsm *connFsm)
{
    return GetLocalLedgerDepsInterface()->LnnDestroyConnectionFsm(connFsm);
}

LnnConnectionFsm *LnnCreateConnectionFsm(const ConnectionAddr *target, const char *pkgName, bool isNeedConnect)
{
    return GetLocalLedgerDepsInterface()->LnnCreateConnectionFsm(target, pkgName, false);
}

int32_t LnnStartConnectionFsm(LnnConnectionFsm *connFsm)
{
    return GetLocalLedgerDepsInterface()->LnnStartConnectionFsm(connFsm);
}

void LnnNotifyMasterNodeChanged(bool isMaster, const char *masterNodeUdid, int32_t weight)
{
    return GetLocalLedgerDepsInterface()->LnnNotifyMasterNodeChanged(isMaster, masterNodeUdid, weight);
}

int32_t LnnInitFastOffline(void)
{
    return GetLocalLedgerDepsInterface()->LnnInitFastOffline();
}

void LnnNotifyNodeAddressChanged(const char *addr, const char *networkId, bool isLocal)
{
    return GetLocalLedgerDepsInterface()->LnnNotifyNodeAddressChanged(addr, networkId, isLocal);
}

int32_t LnnInitOffline(void)
{
    return GetLocalLedgerDepsInterface()->LnnInitOffline();
}

void LnnDeinitOffline(void)
{
    return GetLocalLedgerDepsInterface()->LnnDeinitOffline();
}

int32_t GetAuthRequest(uint32_t requestId, AuthRequest *request)
{
    return GetLocalLedgerDepsInterface()->GetAuthRequest(requestId, request);
}

int32_t SoftBusGetBrState(void)
{
    return GetLocalLedgerDepsInterface()->SoftBusGetBrState();
}

int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type)
{
    return GetLocalLedgerDepsInterface()->LnnSetNetCapability(capability, type);
}

int32_t LnnClearNetCapability(uint32_t *capability, NetCapability type)
{
    return GetLocalLedgerDepsInterface()->LnnClearNetCapability(capability, type);
}

int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler)
{
    return GetLocalLedgerDepsInterface()->LnnRegisterEventHandler(event, handler);
}

void LnnNotifyDeviceVerified(const char *udid)
{
    return GetLocalLedgerDepsInterface()->LnnNotifyDeviceVerified(udid);
}

int32_t LnnInitBusCenterEvent(void)
{
    return GetLocalLedgerDepsInterface()->LnnInitBusCenterEvent();
}

int32_t LnnInitBatteryInfo(void)
{
    return GetLocalLedgerDepsInterface()->LnnInitBatteryInfo();
}

void LnnDeinitBatteryInfo(void)
{
    return GetLocalLedgerDepsInterface()->LnnDeinitBatteryInfo();
}

void LnnDeinitNetworkInfo(void)
{
    return GetLocalLedgerDepsInterface()->LnnDeinitNetworkInfo();
}

void LnnDeinitDevicename(void)
{
    return GetLocalLedgerDepsInterface()->LnnDeinitDevicename();
}

const char *LnnPrintConnectionAddr(const ConnectionAddr *addr)
{
    return GetLocalLedgerDepsInterface()->LnnPrintConnectionAddr(addr);
}

bool LnnConvertAddrToAuthConnInfo(const ConnectionAddr *addr, AuthConnInfo *connInfo)
{
    return GetLocalLedgerDepsInterface()->LnnConvertAddrToAuthConnInfo(addr, connInfo);
}

int32_t LnnFsmRemoveMessageByType(FsmStateMachine *fsm, int32_t what)
{
    return GetLocalLedgerDepsInterface()->LnnFsmRemoveMessageByType(fsm, what);
}

void LnnDeinitBusCenterEvent(void)
{
    return GetLocalLedgerDepsInterface()->LnnDeinitBusCenterEvent();
}

int32_t AuthStartVerify(
    const AuthConnInfo *connInfo, const AuthVerifyParam *authVerifyParam, const AuthVerifyCallback *callback)
{
    return GetLocalLedgerDepsInterface()->AuthStartVerify(connInfo, authVerifyParam, callback);
}

bool LnnIsNeedCleanConnectionFsm(const NodeInfo *nodeInfo, ConnectionAddrType type)
{
    return GetLocalLedgerDepsInterface()->LnnIsNeedCleanConnectionFsm(nodeInfo, type);
}

int32_t AuthFlushDevice(const char *uuid, AuthLinkType type)
{
    return GetLocalLedgerDepsInterface()->AuthFlushDevice(uuid, type);
}

int32_t LnnPutDBData(int32_t dbId, char *putKey, uint32_t putKeyLen, char *putValue, uint32_t putValueLen)
{
    return GetLocalLedgerDepsInterface()->LnnPutDBData(dbId, putKey, putKeyLen, putValue, putValueLen);
}

int32_t LnnCloudSync(int32_t dbId)
{
    return GetLocalLedgerDepsInterface()->LnnCloudSync(dbId);
}

int32_t LnnSyncP2pInfo(void)
{
    return GetLocalLedgerDepsInterface()->LnnSyncP2pInfo();
}

int32_t LnnSyncWifiDirectAddr(void)
{
    return GetLocalLedgerDepsInterface()->LnnSyncWifiDirectAddr();
}

int32_t LnnInitPtk(void)
{
    return GetLocalLedgerDepsInterface()->LnnInitPtk();
}

int32_t LnnGetLocalPtkByUdid(const char *udid, char *localPtk, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->LnnGetLocalPtkByUdid(udid, localPtk, len);
}

int32_t LnnGetLocalPtkByUuid(const char *uuid, char *localPtk, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->LnnGetLocalPtkByUuid(uuid, localPtk, len);
}

int32_t LnnGetLocalDefaultPtkByUuid(const char *uuid, char *localPtk, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->LnnGetLocalDefaultPtkByUuid(uuid, localPtk, len);
}

int32_t LnnGetRemoteDefaultPtkByUuid(const char *uuid, char *remotePtk, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->LnnGetRemoteDefaultPtkByUuid(uuid, remotePtk, len);
}

int32_t LnnSyncPtk(const char *networkId)
{
    return GetLocalLedgerDepsInterface()->LnnSyncPtk(networkId);
}

int32_t UpdateLocalPtkIfValid(char *udid)
{
    return GetLocalLedgerDepsInterface()->UpdateLocalPtkIfValid(udid);
}

int32_t LnnSetLocalPtkConn(char *udid)
{
    return GetLocalLedgerDepsInterface()->LnnSetLocalPtkConn(udid);
}

int32_t LnnGenerateLocalPtk(char *udid, char *uuid)
{
    return GetLocalLedgerDepsInterface()->LnnGenerateLocalPtk(udid, uuid);
}

int32_t LnnGenerateMetaPtk(uint32_t connId)
{
    return GetLocalLedgerDepsInterface()->LnnGenerateMetaPtk(connId);
}

int32_t LnnGetMetaPtk(uint32_t connId, char *metaPtk, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->LnnGetMetaPtk(connId, metaPtk, len);
}

int32_t LnnDeleteMetaPtk(uint32_t connectionId)
{
    return GetLocalLedgerDepsInterface()->LnnDeleteMetaPtk(connectionId);
}

int32_t UpdatePtkByAuth(char *networkId, AuthHandle authHandle)
{
    return GetLocalLedgerDepsInterface()->UpdatePtkByAuth(networkId, authHandle);
}

int32_t SoftBusEnableBt(void)
{
    return GetLocalLedgerDepsInterface()->SoftBusEnableBt();
}

int32_t SoftBusDisableBt(void)
{
    return GetLocalLedgerDepsInterface()->SoftBusDisableBt();
}

int32_t SoftBusGetBtName(unsigned char *name, unsigned int *len)
{
    return GetLocalLedgerDepsInterface()->SoftBusGetBtName(name, len);
}

int32_t SoftBusSetBtName(const char *name)
{
    return GetLocalLedgerDepsInterface()->SoftBusSetBtName(name);
}

int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener, int *listenerId)
{
    return GetLocalLedgerDepsInterface()->SoftBusAddBtStateListener(listener, listenerId);
}

int32_t SoftBusRemoveBtStateListener(int listenerId)
{
    return GetLocalLedgerDepsInterface()->SoftBusRemoveBtStateListener(listenerId);
}

int32_t SoftBusBtInit(void)
{
    return GetLocalLedgerDepsInterface()->SoftBusBtInit();
}

int32_t SoftBusBase64Encode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen)
{
    return GetLocalLedgerDepsInterface()->SoftBusBase64Encode(dst, dlen, olen, src, slen);
}

int32_t SoftBusBase64Decode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen)
{
    return GetLocalLedgerDepsInterface()->SoftBusBase64Decode(dst, dlen, olen, src, slen);
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return GetLocalLedgerDepsInterface()->SoftBusGenerateStrHash(str, len, hash);
}

int32_t SoftBusGenerateSessionKey(char *key, uint32_t len)
{
    return GetLocalLedgerDepsInterface()->SoftBusGenerateSessionKey(key, len);
}

uint32_t SoftBusCryptoRand(void)
{
    return GetLocalLedgerDepsInterface()->SoftBusCryptoRand();
}

int32_t LnnGetLocalDevInfoPacked(NodeInfo *deviceInfo)
{
    return GetLocalLedgerDepsInterface()->LnnGetLocalDevInfoPacked(deviceInfo);
}

int32_t LnnRemoveStorageConfigPath(LnnFileId id)
{
    return GetLocalLedgerDepsInterface()->LnnRemoveStorageConfigPath(id);
}

int32_t InitTrustedDevInfoTable(void)
{
    return GetLocalLedgerDepsInterface()->InitTrustedDevInfoTable();
}

int32_t LnnLoadLocalBroadcastCipherKeyPacked(void)
{
    return GetLocalLedgerDepsInterface()->LnnLoadLocalBroadcastCipherKeyPacked();
}

int32_t LnnUpdateLocalBroadcastCipherKeyPacked(BroadcastCipherKey *broadcastKey)
{
    return GetLocalLedgerDepsInterface()->LnnUpdateLocalBroadcastCipherKeyPacked(broadcastKey);
}

int32_t LnnGetLocalBroadcastCipherKeyPacked(BroadcastCipherKey *broadcastKey)
{
    return GetLocalLedgerDepsInterface()->LnnGetLocalBroadcastCipherKeyPacked(broadcastKey);
}
} // extern "C"
} // namespace OHOS
