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

#include "auth_session_json_deps_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_authSessionJsonDepsInterface;
AuthSessionJsonDepsInterfaceMock::AuthSessionJsonDepsInterfaceMock()
{
    g_authSessionJsonDepsInterface = reinterpret_cast<void *>(this);
}

AuthSessionJsonDepsInterfaceMock::~AuthSessionJsonDepsInterfaceMock()
{
    g_authSessionJsonDepsInterface = nullptr;
}

static AuthSessionJsonDepsInterfaceMock *GetInterface()
{
    return reinterpret_cast<AuthSessionJsonDepsInterfaceMock *>(g_authSessionJsonDepsInterface);
}

extern "C" {
bool JSON_GetStringFromOject(const JsonObj *obj, const char *key, char *value, uint32_t size)
{
    return GetInterface()->JSON_GetStringFromOject(obj, key, value, size);
}

bool JSON_GetInt32FromOject(const JsonObj *obj, const char *key, int32_t *value)
{
    return GetInterface()->JSON_GetInt32FromOject(obj, key, value);
}

bool JSON_GetInt64FromOject(const JsonObj *obj, const char *key, int64_t *value)
{
    return GetInterface()->JSON_GetInt64FromOject(obj, key, value);
}

bool JSON_GetBoolFromOject(const JsonObj *obj, const char *key, bool *value)
{
    return GetInterface()->JSON_GetBoolFromOject(obj, key, value);
}

int32_t LnnEncryptAesGcm(AesGcmInputParam *in, int32_t keyIndex, uint8_t **out, uint32_t *outLen)
{
    return GetInterface()->LnnEncryptAesGcm(in, keyIndex, out, outLen);
}

int32_t LnnDecryptAesGcm(AesGcmInputParam *in, uint8_t **out, uint32_t *outLen)
{
    return GetInterface()->LnnDecryptAesGcm(in, out, outLen);
}

bool JSON_AddStringToObject(JsonObj *obj, const char *key, const char *value)
{
    return GetInterface()->JSON_AddStringToObject(obj, key, value);
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return GetInterface()->SoftBusGenerateStrHash(str, len, hash);
}

int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen,
    const unsigned char *inBuf, uint32_t inLen)
{
    return GetInterface()->ConvertBytesToHexString(outBuf, outBufLen, inBuf, inLen);
}

int32_t LnnGetUdidByBrMac(const char *brMac, char *udid, uint32_t udidLen)
{
    return GetInterface()->LnnGetUdidByBrMac(brMac, udid, udidLen);
}

int32_t AuthFindLatestNormalizeKey(const char *udidHash, AuthDeviceKeyInfo *deviceKey, bool clearOldKey)
{
    return GetInterface()->AuthFindLatestNormalizeKey(udidHash, deviceKey, clearOldKey);
}

int32_t AuthFindDeviceKey(const char *udidHash, int32_t keyType, AuthDeviceKeyInfo *deviceKey)
{
    return GetInterface()->AuthFindDeviceKey(udidHash, keyType, deviceKey);
}

void AuthGetLatestIdByUuid(const char *uuid, AuthLinkType type, bool isMeta, AuthHandle *authHandle)
{
    return GetInterface()->AuthGetLatestIdByUuid(uuid, type, isMeta, authHandle);
}

AuthManager *GetAuthManagerByAuthId(int64_t authId)
{
    return GetInterface()->GetAuthManagerByAuthId(authId);
}

int32_t GetLatestSessionKey(const SessionKeyList *list, AuthLinkType type, int32_t *index, SessionKey *key)
{
    return GetInterface()->GetLatestSessionKey(list, type, index, key);
}

void DelDupAuthManager(AuthManager *auth)
{
    return GetInterface()->DelDupAuthManager(auth);
}

bool IsPotentialTrustedDevice(TrustedRelationIdType idType,
    const char *deviceId, bool isPrecise, bool isPointToPoint)
{
    return GetInterface()->IsPotentialTrustedDevice(idType, deviceId, isPrecise, isPointToPoint);
}

int32_t ConvertBytesToUpperCaseHexString(char *outBuf, uint32_t outBufLen,
    const unsigned char *inBuf, uint32_t inLen)
{
    return GetInterface()->ConvertBytesToUpperCaseHexString(outBuf, outBufLen, inBuf, inLen);
}

int32_t ConvertHexStringToBytes(unsigned char *outBuf, uint32_t outBufLen,
    const char *inBuf, uint32_t inLen)
{
    return GetInterface()->ConvertHexStringToBytes(outBuf, outBufLen, inBuf, inLen);
}

int32_t AuthFindNormalizeKeyByServerSide(const char *udidHash, bool isServer, AuthDeviceKeyInfo *deviceKey)
{
    return GetInterface()->AuthFindNormalizeKeyByServerSide(udidHash, isServer, deviceKey);
}

void AuthUpdateCreateTime(const char *udidHash, int32_t keyType, bool isServer)
{
    return GetInterface()->AuthUpdateCreateTime(udidHash, keyType, isServer);
}

bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit)
{
    return GetInterface()->IsFeatureSupport(feature, capaBit);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetInterface()->LnnGetLocalStrInfo(key, info, len);
}

bool IsSupportUDIDAbatement(void)
{
    return GetInterface()->IsSupportUDIDAbatement();
}

bool JSON_AddBoolToObject(JsonObj *obj, const char *key, bool value)
{
    return GetInterface()->JSON_AddBoolToObject(obj, key, value);
}

bool IsNeedUDIDAbatement(const AuthSessionInfo *info)
{
    return GetInterface()->IsNeedUDIDAbatement(info);
}

bool JSON_AddInt32ToObject(JsonObj *obj, const char *key, int32_t value)
{
    return GetInterface()->JSON_AddInt32ToObject(obj, key, value);
}

bool IsSupportFeatureByCapaBit(uint32_t feature, AuthCapability capaBit)
{
    return GetInterface()->IsSupportFeatureByCapaBit(feature, capaBit);
}

JsonObj *JSON_CreateObject()
{
    return GetInterface()->JSON_CreateObject();
}

void JSON_Delete(JsonObj *obj)
{
    return GetInterface()->JSON_Delete(obj);
}

JsonObj *JSON_Parse(const char *str, uint32_t len)
{
    return GetInterface()->JSON_Parse(str, len);
}

const NodeInfo *LnnGetLocalNodeInfo(void)
{
    return GetInterface()->LnnGetLocalNodeInfo();
}

char *JSON_PrintUnformatted(const JsonObj *obj)
{
    return GetInterface()->JSON_PrintUnformatted(obj);
}

int32_t GetFd(uint64_t connId)
{
    return GetInterface()->GetFd(connId);
}

int32_t SoftBusSocketGetPeerName(int32_t socketFd, SoftBusSockAddr *addr)
{
    return GetInterface()->SoftBusSocketGetPeerName(socketFd, addr);
}

const char *SoftBusInetNtoP(int32_t af, const void *src, char *dst, int32_t size)
{
    return GetInterface()->SoftBusInetNtoP(af, src, dst, size);
}

int32_t GetPeerUdidByNetworkId(const char *networkId, char *udid, uint32_t len)
{
    return GetInterface()->GetPeerUdidByNetworkId(networkId, udid, len);
}

int32_t GetIsExchangeUdidByNetworkId(const char *networkId, bool *isExchangeUdid)
{
    return GetInterface()->GetIsExchangeUdidByNetworkId(networkId, isExchangeUdid);
}

int32_t LnnGetUnifiedDeviceName(char *unifiedName, uint32_t len)
{
    return GetInterface()->LnnGetUnifiedDeviceName(unifiedName, len);
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    return GetInterface()->LnnSetLocalStrInfo(key, info);
}

int32_t GetExtData(char *value, uint32_t len)
{
    return GetInterface()->GetExtData(value, len);
}

int32_t AuthMetaGetConnIdByInfo(const AuthConnInfo *connInfo, uint32_t *connectionId)
{
    return GetInterface()->AuthMetaGetConnIdByInfo(connInfo, connectionId);
}

int32_t LnnGetMetaPtk(uint32_t connId, char *metaPtk, uint32_t len)
{
    return GetInterface()->LnnGetMetaPtk(connId, metaPtk, len);
}

int32_t LnnGetLocalPtkByUuid(const char *uuid, char *localPtk, uint32_t len)
{
    return GetInterface()->LnnGetLocalPtkByUuid(uuid, localPtk, len);
}

void LnnDumpRemotePtk(const char *oldPtk, const char *newPtk, const char *log)
{
    return GetInterface()->LnnDumpRemotePtk(oldPtk, newPtk, log);
}

int32_t SoftBusBase64Encode(unsigned char *dst, size_t dlen, size_t *olen,
    const unsigned char *src, size_t slen)
{
    return GetInterface()->SoftBusBase64Encode(dst, dlen, olen, src, slen);
}

int32_t SoftBusBase64Decode(unsigned char *dst, size_t dlen, size_t *olen,
    const unsigned char *src, size_t slen)
{
    return GetInterface()->SoftBusBase64Decode(dst, dlen, olen, src, slen);
}

int32_t LnnUpdateLocalBroadcastCipherKey(BroadcastCipherKey *broadcastKey)
{
    return GetInterface()->LnnUpdateLocalBroadcastCipherKey(broadcastKey);
}

void ProcessCipherKeySyncInfo(const void *json, const char *networkId)
{
    return GetInterface()->ProcessCipherKeySyncInfo(json, networkId);
}

bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetInterface()->LnnHasDiscoveryType(info, type);
}

int32_t LnnGetNetworkIdByUuid(const char *uuid, char *buf, uint32_t len)
{
    return GetInterface()->LnnGetNetworkIdByUuid(uuid, buf, len);
}

int32_t LnnGetRemoteNumInfo(const char *netWorkId, InfoKey key, int32_t *info)
{
    return GetInterface()->LnnGetRemoteNumInfo(netWorkId, key, info);
}

int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    return GetInterface()->SoftbusGetConfig(type, val, len);
}

int32_t GenerateCertificate(SoftbusCertChain *softbusCertChain, const AuthSessionInfo *info)
{
    return GetInterface()->GenerateCertificate(softbusCertChain, info);
}

void FreeSoftbusChain(SoftbusCertChain *softbusCertChain)
{
    return GetInterface()->FreeSoftbusChain(softbusCertChain);
}

int32_t InitSoftbusChain(SoftbusCertChain *softbusCertChain)
{
    return GetInterface()->InitSoftbusChain(softbusCertChain);
}

int32_t VerifyCertificate(SoftbusCertChain *softbusCertChain,
    const NodeInfo *nodeInfo, const AuthSessionInfo *info)
{
    return GetInterface()->VerifyCertificate(softbusCertChain, nodeInfo, info);
}

int32_t LnnGetLocalNodeInfoSafe(NodeInfo *info)
{
    return GetInterface()->LnnGetLocalNodeInfoSafe(info);
}

const char *LnnGetBtMac(const NodeInfo *info)
{
    return GetInterface()->LnnGetBtMac(info);
}

int32_t SoftBusGetBtState(void)
{
    return GetInterface()->SoftBusGetBtState();
}

int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac)
{
    return GetInterface()->SoftBusGetBtMacAddr(mac);
}

int32_t ConvertBtMacToStr(char *strMac, uint32_t strMacLen, const uint8_t *binMac, uint32_t binMacLen)
{
    return GetInterface()->ConvertBtMacToStr(strMac, strMacLen, binMac, binMacLen);
}

int32_t LnnGetDeviceDisplayName(const char *nickName,
    const char *defaultName, char *deviceName, uint32_t len)
{
    return GetInterface()->LnnGetDeviceDisplayName(nickName, defaultName, deviceName, len);
}

uint64_t SoftBusGetSysTimeMs(void)
{
    return GetInterface()->SoftBusGetSysTimeMs();
}

uint64_t LnnGetSupportedProtocols(const NodeInfo *info)
{
    return GetInterface()->LnnGetSupportedProtocols(info);
}

int32_t StringToUpperCase(const char *str, char *buf, int32_t size)
{
    return GetInterface()->StringToUpperCase(str, buf, size);
}

int32_t LnnGetAuthPort(const NodeInfo *info)
{
    return GetInterface()->LnnGetAuthPort(info);
}

int32_t LnnGetSessionPort(const NodeInfo *info)
{
    return GetInterface()->LnnGetSessionPort(info);
}

int32_t LnnGetProxyPort(const NodeInfo *info)
{
    return GetInterface()->LnnGetProxyPort(info);
}

bool JSON_AddBytesToObject(JsonObj *obj, const char *key, uint8_t *value, uint32_t size)
{
    return GetInterface()->JSON_AddBytesToObject(obj, key, value, size);
}

bool JSON_GetBytesFromObject(const JsonObj *obj, const char *key, uint8_t *value,
    uint32_t bufLen, uint32_t *size)
{
    return GetInterface()->JSON_GetBytesFromObject(obj, key, value, bufLen, size);
}

bool JSON_AddInt16ToObject(JsonObj *obj, const char *key, int16_t value)
{
    return GetInterface()->JSON_AddInt16ToObject(obj, key, value);
}

bool JSON_AddInt64ToObject(JsonObj *obj, const char *key, int64_t value)
{
    return GetInterface()->JSON_AddInt64ToObject(obj, key, value);
}

const char *LnnGetP2pMac(const NodeInfo *info)
{
    return GetInterface()->LnnGetP2pMac(info);
}

const char *LnnGetDeviceName(const DeviceBasicInfo *info)
{
    return GetInterface()->LnnGetDeviceName(info);
}

char *LnnConvertIdToDeviceType(uint16_t typeId)
{
    return GetInterface()->LnnConvertIdToDeviceType(typeId);
}

const char *LnnGetDeviceUdid(const NodeInfo *info)
{
    return GetInterface()->LnnGetDeviceUdid(info);
}

bool PackCipherKeySyncMsg(void *json)
{
    return GetInterface()->PackCipherKeySyncMsg(json);
}

int32_t LnnGetP2pRole(const NodeInfo *info)
{
    return GetInterface()->LnnGetP2pRole(info);
}

int32_t LnnGetStaFrequency(const NodeInfo *info)
{
    return GetInterface()->LnnGetStaFrequency(info);
}
}
} // namespace OHOS