/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef AUTH_SESSION_JOSN_DEPS_MOCK_H
#define AUTH_SESSION_JOSN_DEPS_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_attest_interface.h"
#include "auth_common.h"
#include "auth_connection.h"
#include "auth_device_common_key.h"
#include "auth_hichain_adapter.h"
#include "auth_interface.h"
#include "auth_manager.h"
#include "auth_meta_manager.h"
#include "auth_session_json.h"
#include "auth_session_key.h"
#include "bus_center_manager.h"
#include "lnn_cipherkey_manager.h"
#include "lnn_common_utils.h"
#include "lnn_device_info.h"
#include "lnn_device_info_recovery.h"
#include "lnn_extdata_config.h"
#include "lnn_feature_capability.h"
#include "lnn_local_net_ledger.h"
#include "lnn_node_info.h"
#include "lnn_p2p_info.h"
#include "lnn_settingdata_event_monitor.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_json.h"
#include "softbus_adapter_socket.h"
#include "softbus_adapter_timer.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"

namespace OHOS {
class AuthSessionJsonDepsInterface {
public:
    AuthSessionJsonDepsInterface() {};
    virtual ~AuthSessionJsonDepsInterface() {};
    virtual bool JSON_GetStringFromOject(const JsonObj *obj, const char *key, char *value, uint32_t size) = 0;
    virtual bool JSON_GetInt32FromOject(const JsonObj *obj, const char *key, int32_t *value) = 0;
    virtual bool JSON_GetInt64FromOject(const JsonObj *obj, const char *key, int64_t *value) = 0;
    virtual bool JSON_GetBoolFromOject(const JsonObj *obj, const char *key, bool *value) = 0;
    virtual int32_t LnnEncryptAesGcm(AesGcmInputParam *in, int32_t keyIndex,
        uint8_t **out, uint32_t *outLen) = 0;
    virtual int32_t LnnDecryptAesGcm(AesGcmInputParam *in, uint8_t **out, uint32_t *outLen) = 0;
    virtual bool JSON_AddStringToObject(JsonObj *obj, const char *key, const char *value) = 0;
    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
    virtual int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen,
        const unsigned char *inBuf, uint32_t inLen) = 0;
    virtual int32_t LnnGetUdidByBrMac(const char *brMac, char *udid, uint32_t udidLen) = 0;
    virtual int32_t AuthFindLatestNormalizeKey(const char *udidHash,
        AuthDeviceKeyInfo *deviceKey, bool clearOldKey) = 0;
    virtual int32_t AuthFindDeviceKey(const char *udidHash, int32_t keyType, AuthDeviceKeyInfo *deviceKey) = 0;
    virtual void AuthGetLatestIdByUuid(const char *uuid,
        AuthLinkType type, bool isMeta, AuthHandle *authHandle) = 0;
    virtual AuthManager *GetAuthManagerByAuthId(int64_t authId) = 0;
    virtual int32_t GetLatestSessionKey(const SessionKeyList *list,
        AuthLinkType type, int32_t *index, SessionKey *key) = 0;
    virtual void DelDupAuthManager(AuthManager *auth) = 0;
    virtual bool IsPotentialTrustedDevice(TrustedRelationIdType idType,
        const char *deviceId, bool isPrecise, bool isPointToPoint) = 0;
    virtual int32_t ConvertBytesToUpperCaseHexString(char *outBuf, uint32_t outBufLen,
        const unsigned char *inBuf, uint32_t inLen) = 0;
    virtual int32_t ConvertHexStringToBytes(unsigned char *outBuf, uint32_t outBufLen,
        const char *inBuf, uint32_t inLen) = 0;
    virtual int32_t AuthFindNormalizeKeyByServerSide(const char *udidHash, bool isServer,
        AuthDeviceKeyInfo *deviceKey) = 0;
    virtual void AuthUpdateCreateTime(const char *udidHash, int32_t keyType, bool isServer) = 0;
    virtual bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual bool IsSupportUDIDAbatement(void) = 0;
    virtual bool JSON_AddBoolToObject(JsonObj *obj, const char *key, bool value) = 0;
    virtual bool IsNeedUDIDAbatement(const AuthSessionInfo *info) = 0;
    virtual bool JSON_AddInt32ToObject(JsonObj *obj, const char *key, int32_t value) = 0;
    virtual bool IsSupportFeatureByCapaBit(uint32_t feature, AuthCapability capaBit) = 0;
    virtual JsonObj *JSON_CreateObject() = 0;
    virtual void JSON_Delete(JsonObj *obj) = 0;
    virtual JsonObj *JSON_Parse(const char *str, uint32_t len) = 0;
    virtual const NodeInfo *LnnGetLocalNodeInfo(void) = 0;
    virtual char *JSON_PrintUnformatted(const JsonObj *obj) = 0;
    virtual int32_t GetFd(uint64_t connId) = 0;
    virtual int32_t SoftBusSocketGetPeerName(int32_t socketFd, SoftBusSockAddr *addr) = 0;
    virtual const char *SoftBusInetNtoP(int32_t af, const void *src, char *dst, int32_t size) = 0;
    virtual int32_t GetPeerUdidByNetworkId(const char *networkId, char *udid, uint32_t len) = 0;
    virtual int32_t GetIsExchangeUdidByNetworkId(const char *networkId, bool *isExchangeUdid) = 0;
    virtual int32_t LnnGetUnifiedDeviceName(char *unifiedName, uint32_t len) = 0;
    virtual int32_t LnnSetLocalStrInfo(InfoKey key, const char *info) = 0;
    virtual int32_t GetExtData(char *value, uint32_t len) = 0;
    virtual int32_t AuthMetaGetConnIdByInfo(const AuthConnInfo *connInfo, uint32_t *connectionId) = 0;
    virtual int32_t LnnGetMetaPtk(uint32_t connId, char *metaPtk, uint32_t len) = 0;
    virtual int32_t LnnGetLocalPtkByUuid(const char *uuid, char *localPtk, uint32_t len) = 0;
    virtual void LnnDumpRemotePtk(const char *oldPtk, const char *newPtk, const char *log) = 0;
    virtual int32_t SoftBusBase64Encode(unsigned char *dst, size_t dlen, size_t *olen,
        const unsigned char *src, size_t slen) = 0;
    virtual int32_t SoftBusBase64Decode(unsigned char *dst, size_t dlen, size_t *olen,
        const unsigned char *src, size_t slen) = 0;
    virtual int32_t LnnUpdateLocalBroadcastCipherKey(BroadcastCipherKey *broadcastKey) = 0;
    virtual void ProcessCipherKeySyncInfo(const void *json, const char *networkId) = 0;
    virtual bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type) = 0;
    virtual int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len) = 0;
    virtual int32_t LnnGetRemoteNumInfo(const char *netWorkId, InfoKey key, int32_t *info) = 0;
    virtual int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len);
    virtual int32_t GenerateCertificate(SoftbusCertChain *softbusCertChain, const AuthSessionInfo *info) = 0;
    virtual void FreeSoftbusChain(SoftbusCertChain *softbusCertChain) = 0;
    virtual int32_t InitSoftbusChain(SoftbusCertChain *softbusCertChain) = 0;
    virtual int32_t VerifyCertificate(SoftbusCertChain *softbusCertChain,
        const NodeInfo *nodeInfo, const AuthSessionInfo *info) = 0;
    virtual int32_t LnnGetLocalNodeInfoSafe(NodeInfo *info) = 0;
    virtual const char *LnnGetBtMac(const NodeInfo *info) = 0;
    virtual int32_t SoftBusGetBtState(void) = 0;
    virtual int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac) = 0;
    virtual int32_t ConvertBtMacToStr(char *strMac, uint32_t strMacLen,
        const uint8_t *binMac, uint32_t binMacLen) = 0;
    virtual int32_t LnnGetDeviceDisplayName(const char *nickName,
        const char *defaultName, char *deviceName, uint32_t len) = 0;
    virtual uint64_t SoftBusGetSysTimeMs(void) = 0;
    virtual uint64_t LnnGetSupportedProtocols(const NodeInfo *info) = 0;
    virtual int32_t StringToUpperCase(const char *str, char *buf, int32_t size) = 0;
    virtual int32_t LnnGetAuthPort(const NodeInfo *info) = 0;
    virtual int32_t LnnGetSessionPort(const NodeInfo *info) = 0;
    virtual int32_t LnnGetProxyPort(const NodeInfo *info) = 0;
    virtual bool JSON_AddBytesToObject(JsonObj *obj, const char *key, uint8_t *value, uint32_t size) = 0;
    virtual bool JSON_GetBytesFromObject(const JsonObj *obj, const char *key, uint8_t *value,
        uint32_t bufLen, uint32_t *size) = 0;
    virtual bool JSON_AddInt16ToObject(JsonObj *obj, const char *key, int16_t value) = 0;
    virtual bool JSON_AddInt64ToObject(JsonObj *obj, const char *key, int64_t value) = 0;
    virtual const char *LnnGetP2pMac(const NodeInfo *info) = 0;
    virtual const char *LnnGetDeviceName(const DeviceBasicInfo *info) = 0;
    virtual char *LnnConvertIdToDeviceType(uint16_t typeId) = 0;
    virtual const char *LnnGetDeviceUdid(const NodeInfo *info) = 0;
    virtual bool PackCipherKeySyncMsg(void *json) = 0;
    virtual int32_t LnnGetP2pRole(const NodeInfo *info) = 0;
    virtual int32_t LnnGetStaFrequency(const NodeInfo *info) = 0;
};
class AuthSessionJsonDepsInterfaceMock : public AuthSessionJsonDepsInterface {
public:
    AuthSessionJsonDepsInterfaceMock();
    ~AuthSessionJsonDepsInterfaceMock() override;
    MOCK_METHOD4(JSON_GetStringFromOject, bool (const JsonObj *, const char *, char *, uint32_t));
    MOCK_METHOD3(JSON_GetInt32FromOject, bool (const JsonObj *, const char *, int32_t *));
    MOCK_METHOD3(JSON_GetInt64FromOject, bool (const JsonObj *, const char *, int64_t *));
    MOCK_METHOD3(JSON_GetBoolFromOject, bool (const JsonObj *, const char *, bool *));
    MOCK_METHOD4(LnnEncryptAesGcm, int32_t (AesGcmInputParam *, int32_t, uint8_t **, uint32_t *));
    MOCK_METHOD3(JSON_AddStringToObject, bool (JsonObj *, const char *, const char *));
    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t (const unsigned char *, uint32_t, unsigned char *));
    MOCK_METHOD4(ConvertBytesToHexString, int32_t (char *, uint32_t, const unsigned char *, uint32_t));
    MOCK_METHOD3(LnnGetUdidByBrMac, int32_t (const char *, char *, uint32_t));
    MOCK_METHOD3(AuthFindLatestNormalizeKey, int32_t (const char *, AuthDeviceKeyInfo *, bool));
    MOCK_METHOD3(AuthFindDeviceKey, int32_t (const char *, int32_t, AuthDeviceKeyInfo *));
    MOCK_METHOD4(AuthGetLatestIdByUuid, void (const char *, AuthLinkType, bool, AuthHandle *));
    MOCK_METHOD1(GetAuthManagerByAuthId, AuthManager *(int64_t authId));
    MOCK_METHOD4(GetLatestSessionKey, int32_t (const SessionKeyList *, AuthLinkType, int32_t *, SessionKey *));
    MOCK_METHOD1(DelDupAuthManager, void (AuthManager *));
    MOCK_METHOD4(IsPotentialTrustedDevice, bool (TrustedRelationIdType, const char *, bool, bool));
    MOCK_METHOD4(ConvertBytesToUpperCaseHexString, int32_t (char *, uint32_t, const unsigned char *, uint32_t));
    MOCK_METHOD4(ConvertHexStringToBytes, int32_t (unsigned char *, uint32_t, const char *, uint32_t));
    MOCK_METHOD3(LnnDecryptAesGcm, int32_t (AesGcmInputParam *, uint8_t **, uint32_t *));
    MOCK_METHOD3(AuthFindNormalizeKeyByServerSide, int32_t (const char *, bool, AuthDeviceKeyInfo *));
    MOCK_METHOD3(AuthUpdateCreateTime, void (const char *, int32_t, bool));
    MOCK_METHOD2(IsFeatureSupport, bool (uint64_t feature, FeatureCapability capaBit));
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t (InfoKey, char *, uint32_t));
    MOCK_METHOD0(IsSupportUDIDAbatement, bool ());
    MOCK_METHOD3(JSON_AddBoolToObject, bool (JsonObj *, const char *, bool));
    MOCK_METHOD1(IsNeedUDIDAbatement, bool (const AuthSessionInfo *));
    MOCK_METHOD3(JSON_AddInt32ToObject, bool (JsonObj *, const char *, int32_t));
    MOCK_METHOD2(IsSupportFeatureByCapaBit, bool (uint32_t, AuthCapability));
    MOCK_METHOD0(JSON_CreateObject, JsonObj *());
    MOCK_METHOD1(JSON_Delete, void (JsonObj *obj));
    MOCK_METHOD2(JSON_Parse, JsonObj *(const char *str, uint32_t len));
    MOCK_METHOD0(LnnGetLocalNodeInfo, const NodeInfo *());
    MOCK_METHOD1(JSON_PrintUnformatted, char *(const JsonObj *obj));
    MOCK_METHOD1(GetFd, int32_t (uint64_t));
    MOCK_METHOD2(SoftBusSocketGetPeerName, int32_t (int32_t, SoftBusSockAddr *));
    MOCK_METHOD4(SoftBusInetNtoP, const char *(int32_t, const void *, char *, int32_t));
    MOCK_METHOD3(GetPeerUdidByNetworkId, int32_t (const char *, char *, uint32_t));
    MOCK_METHOD2(GetIsExchangeUdidByNetworkId, int32_t (const char *, bool *));
    MOCK_METHOD2(LnnGetUnifiedDeviceName, int32_t (char *, uint32_t));
    MOCK_METHOD2(LnnSetLocalStrInfo, int32_t (InfoKey, const char *));
    MOCK_METHOD2(GetExtData, int32_t (char *, uint32_t));
    MOCK_METHOD2(AuthMetaGetConnIdByInfo, int32_t (const AuthConnInfo *, uint32_t *));
    MOCK_METHOD3(LnnGetMetaPtk, int32_t (uint32_t, char *, uint32_t));
    MOCK_METHOD3(LnnGetLocalPtkByUuid, int32_t (const char *, char *, uint32_t));
    MOCK_METHOD3(LnnDumpRemotePtk, void (const char *, const char *, const char *));
    MOCK_METHOD5(SoftBusBase64Encode, int32_t (unsigned char *, size_t, size_t *, const unsigned char *, size_t));
    MOCK_METHOD5(SoftBusBase64Decode, int32_t (unsigned char *, size_t, size_t *, const unsigned char *, size_t));
    MOCK_METHOD1(LnnUpdateLocalBroadcastCipherKey, int32_t (BroadcastCipherKey *));
    MOCK_METHOD2(ProcessCipherKeySyncInfo, void (const void *, const char *));
    MOCK_METHOD2(LnnHasDiscoveryType, bool (const NodeInfo *, DiscoveryType));
    MOCK_METHOD3(LnnGetNetworkIdByUuid, int32_t (const char *, char *, uint32_t));
    MOCK_METHOD3(LnnGetRemoteNumInfo, int32_t(const char *, InfoKey, int32_t *));
    MOCK_METHOD3(SoftbusGetConfig, int32_t (ConfigType, unsigned char *, uint32_t));
    MOCK_METHOD2(GenerateCertificate, int32_t (SoftbusCertChain *, const AuthSessionInfo *));
    MOCK_METHOD1(FreeSoftbusChain, void (SoftbusCertChain *));
    MOCK_METHOD1(InitSoftbusChain, int32_t (SoftbusCertChain *));
    MOCK_METHOD3(VerifyCertificate, int32_t (SoftbusCertChain *, const NodeInfo *, const AuthSessionInfo *));
    MOCK_METHOD1(LnnGetLocalNodeInfoSafe, int32_t (NodeInfo *));
    MOCK_METHOD1(LnnGetBtMac, const char *(const NodeInfo *));
    MOCK_METHOD0(SoftBusGetBtState, int32_t (void));
    MOCK_METHOD1(SoftBusGetBtMacAddr, int32_t (SoftBusBtAddr *));
    MOCK_METHOD4(ConvertBtMacToStr, int32_t (char *, uint32_t, const uint8_t *, uint32_t));
    MOCK_METHOD4(LnnGetDeviceDisplayName, int32_t (const char *, const char *, char *, uint32_t));
    MOCK_METHOD0(SoftBusGetSysTimeMs, uint64_t (void));
    MOCK_METHOD1(LnnGetSupportedProtocols, uint64_t (const NodeInfo *));
    MOCK_METHOD3(StringToUpperCase, int32_t (const char *, char *, int32_t));
    MOCK_METHOD1(LnnGetAuthPort, int32_t (const NodeInfo *));
    MOCK_METHOD1(LnnGetSessionPort, int32_t (const NodeInfo *));
    MOCK_METHOD1(LnnGetProxyPort, int32_t (const NodeInfo *));
    MOCK_METHOD4(JSON_AddBytesToObject, bool (JsonObj *, const char *, uint8_t *, uint32_t));
    MOCK_METHOD5(JSON_GetBytesFromObject, bool (const JsonObj *, const char *, uint8_t *, uint32_t, uint32_t *));
    MOCK_METHOD3(JSON_AddInt16ToObject, bool (JsonObj *, const char *, int16_t));
    MOCK_METHOD3(JSON_AddInt64ToObject, bool (JsonObj *, const char *, int64_t));
    MOCK_METHOD1(LnnGetP2pMac, const char * (const NodeInfo *));
    MOCK_METHOD1(LnnGetDeviceName, const char * (const DeviceBasicInfo *));
    MOCK_METHOD1(LnnConvertIdToDeviceType, char * (uint16_t));
    MOCK_METHOD1(LnnGetDeviceUdid, const char * (const NodeInfo *));
    MOCK_METHOD1(PackCipherKeySyncMsg, bool (void *));
    MOCK_METHOD1(LnnGetP2pRole, int32_t (const NodeInfo *));
    MOCK_METHOD1(LnnGetStaFrequency, int32_t (const NodeInfo *));
};
} // namespace OHOS
#endif // AUTH_TCP_CONNECTION_MOCK_H