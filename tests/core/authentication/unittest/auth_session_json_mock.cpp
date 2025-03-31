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
#include "auth_session_json_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_authSessionJsonInterface;
static struct WifiDirectManager g_manager = {
    .refreshRelationShip = RefreshRelationShip,
};

AuthSessionJsonInterfaceMock::AuthSessionJsonInterfaceMock()
{
    g_authSessionJsonInterface = reinterpret_cast<void *>(this);
}

AuthSessionJsonInterfaceMock::~AuthSessionJsonInterfaceMock()
{
    g_authSessionJsonInterface = nullptr;
}

static AuthSessionJsonInterfaceMock *GetInterface()
{
    return reinterpret_cast<AuthSessionJsonInterfaceMock *>(g_authSessionJsonInterface);
}

extern "C" {
int32_t LnnGetUdidByBrMac(const char *brMac, char *udid, uint32_t udidLen)
{
    return GetInterface()->LnnGetUdidByBrMac(brMac, udid, udidLen);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetInterface()->LnnGetLocalStrInfo(key, info, len);
}

int32_t FindAuthPreLinkNodeById(uint32_t requestId, AuthPreLinkNode *reuseNode)
{
    return GetInterface()->FindAuthPreLinkNodeById(requestId, reuseNode);
}

int32_t LnnGetLocalNodeInfoSafe(NodeInfo *info)
{
    return GetInterface()->LnnGetLocalNodeInfoSafe(info);
}

bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit)
{
    return GetInterface()->IsFeatureSupport(feature, capaBit);
}

bool IsSupportFeatureByCapaBit(uint32_t feature, AuthCapability capaBit)
{
    return GetInterface()->IsSupportFeatureByCapaBit(feature, capaBit);
}

bool IsPotentialTrustedDeviceDp(const char *deviceIdHash, bool isOnlyPointToPoint)
{
    return GetInterface()->IsPotentialTrustedDeviceDp(deviceIdHash, isOnlyPointToPoint);
}

bool AuthIsLatestNormalizeKeyInTime(const char *udidHash, uint64_t time)
{
    return GetInterface()->AuthIsLatestNormalizeKeyInTime(udidHash, time);
}

bool IsSupportUDIDAbatement(void)
{
    return GetInterface()->IsSupportUDIDAbatement();
}

bool IsNeedUDIDAbatement(const AuthSessionInfo *info)
{
    return GetInterface()->IsNeedUDIDAbatement(info);
}

bool IsPotentialTrustedDevice(TrustedRelationIdType idType, const char *deviceId, bool isPrecise, bool isPointToPoint)
{
    return GetInterface()->IsPotentialTrustedDevice(idType, deviceId, isPrecise, isPointToPoint);
}

bool IsAuthPreLinkNodeExist(uint32_t requestId)
{
    return GetInterface()->IsAuthPreLinkNodeExist(requestId);
}

int32_t GetFd(uint64_t connId)
{
    return GetInterface()->GetFd(connId);
}

int32_t AddToAuthPreLinkList(uint32_t requestId, int32_t fd, ConnectionAddr *connAddr)
{
    return GetInterface()->AddToAuthPreLinkList(requestId, fd, connAddr);
}

bool GetSessionKeyProfile(int32_t sessionKeyId, uint8_t *sessionKey, uint32_t *length)
{
    return GetInterface()->GetSessionKeyProfile(sessionKeyId, sessionKey, length);
}

void DelSessionKeyProfile(int32_t sessionKeyId)
{
(void)sessionKeyId;
}

int32_t LnnGetAuthPort(const NodeInfo *info)
{
    return GetInterface()->LnnGetAuthPort(info);
}

int32_t LnnGetSessionPort(const NodeInfo *info)
{
    return GetInterface()->LnnGetSessionPort(info);
}

int32_t PostAuthData(uint64_t connId, bool toServer, const AuthDataHead *head, const uint8_t *data)
{
    return GetInterface()->PostAuthData(connId, toServer, head, data);
}

int32_t EncryptInner(const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo,
    uint8_t **outData, uint32_t *outLen)
{
    return GetInterface()->EncryptInner(list, type, inDataInfo, outData, outLen);
}

void DestroySessionKeyList(SessionKeyList *list)
{
    (void)list;
}

int32_t AuthManagerGetSessionKey(int64_t authSeq, const AuthSessionInfo *info, SessionKey *sessionKey)
{
    return GetInterface()->AuthManagerGetSessionKey(authSeq, info, sessionKey);
}

int32_t AddSessionKey(SessionKeyList *list, int32_t index, const SessionKey *key, AuthLinkType type, bool isOldKey)
{
    return GetInterface()->AddSessionKey(list, index, key, type, isOldKey);
}

int32_t SetSessionKeyAvailable(SessionKeyList *list, int32_t index)
{
    return GetInterface()->SetSessionKeyAvailable(list, index);
}

int64_t AuthDeviceGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer)
{
    return GetInterface()->AuthDeviceGetIdByConnInfo(connInfo, isServer);
}

uint32_t AuthGetDecryptSize(uint32_t inLen)
{
    return GetInterface()->AuthGetDecryptSize(inLen);
}

int32_t AuthDeviceDecrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData,
    uint32_t *outLen)
{
    return GetInterface()->AuthDeviceDecrypt(authHandle, inData, inLen, outData, outLen);
}

int32_t AuthManagerSetSessionKey(int64_t authSeq, AuthSessionInfo *info, const SessionKey *sessionKey,
    bool isConnect, bool isOldKey)
{
    return GetInterface()->AuthManagerSetSessionKey(authSeq, info, sessionKey, isConnect, isOldKey);
}

uint64_t GenerateLaneId(const char *localUdid, const char *remoteUdid, LaneLinkType linkType)
{
    return GetInterface()->GenerateLaneId(localUdid, remoteUdid, linkType);
}

int32_t UpdateLaneResourceLaneId(uint64_t oldLaneId, uint64_t newLaneId, const char *peerUdid)
{
    return GetInterface()->UpdateLaneResourceLaneId(oldLaneId, newLaneId, peerUdid);
}

struct WifiDirectManager *GetWifiDirectManager(void)
{
    return &g_manager;
}

void RefreshRelationShip(const char *remoteUuid, const char *remoteMac)
{
    (void)remoteUuid;
    (void)remoteMac;
}

int32_t DecryptInner(const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo, uint8_t **outData,
    uint32_t *outLen)
{
    return GetInterface()->DecryptInner(list, type, inDataInfo, outData, outLen);
}

int32_t DataDecompress(uint8_t *in, uint32_t inLen, uint8_t **out, uint32_t *outLen)
{
    return GetInterface()->DataDecompress(in, inLen, out, outLen);
}

const NodeInfo *LnnGetLocalNodeInfo(void)
{
    return GetInterface()->LnnGetLocalNodeInfo();
}

int32_t LnnGetProxyPort(const NodeInfo *info)
{
    return GetInterface()->LnnGetProxyPort(info);
}

const char *LnnGetBtMac(const NodeInfo *info)
{
    return GetInterface()->LnnGetBtMac(info);
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

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return GetInterface()->LnnGetLocalNumInfo(key, info);
}

int32_t InitSoftbusChain(SoftbusCertChain *softbusCertChain)
{
    return GetInterface()->InitSoftbusChain(softbusCertChain);
}

void FreeSoftbusChain(SoftbusCertChain *softbusCertChain)
{
    (void)softbusCertChain;
}

int32_t LnnGetDeviceDisplayName(const char *nickName, const char *defaultName, char *deviceName, uint32_t len)
{
    return GetInterface()->LnnGetDeviceDisplayName(nickName, defaultName, deviceName, len);
}

int32_t VerifyCertificate(SoftbusCertChain *softbusCertChain, const NodeInfo *nodeInfo, const AuthSessionInfo *info)
{
    return GetInterface()->VerifyCertificate(softbusCertChain, nodeInfo, info);
}

int32_t LnnConvertDeviceTypeToId(const char *deviceType, uint16_t *typeId)
{
    return GetInterface()->LnnConvertDeviceTypeToId(deviceType, typeId);
}

void LnnDumpRemotePtk(const char *oldPtk, const char *newPtk, const char *log)
{
    (void)oldPtk;
    (void)newPtk;
    (void)log;
}

int32_t LnnEncryptAesGcm(AesGcmInputParam *in, int32_t keyIndex, uint8_t **out, uint32_t *outLen)
{
    return GetInterface()->LnnEncryptAesGcm(in, keyIndex, out, outLen);
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
    (void)uuid;
    (void)type;
    (void)isMeta;
    (void)authHandle;
}

int32_t LnnRetrieveDeviceInfoByNetworkId(const char *networkId, NodeInfo *info)
{
    return GetInterface()->LnnRetrieveDeviceInfoByNetworkId(networkId, info);
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
    (void)auth;
}

int32_t LnnDecryptAesGcm(AesGcmInputParam *in, uint8_t **out, uint32_t *outLen)
{
    return GetInterface()->LnnDecryptAesGcm(in, out, outLen);
}

int32_t LnnGetUnifiedDeviceName(char *unifiedName, uint32_t len)
{
    return GetInterface()->LnnGetUnifiedDeviceName(unifiedName, len);
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    return GetInterface()->LnnSetLocalStrInfo(key, info);
}

const char *LnnGetDeviceUdid(const NodeInfo *info)
{
    return GetInterface()->LnnGetDeviceUdid(info);
}

uint64_t LnnGetSupportedProtocols(const NodeInfo *info)
{
    return GetInterface()->LnnGetSupportedProtocols(info);
}

int32_t GetExtData(char *value, uint32_t len)
{
    return GetInterface()->GetExtData(value, len);
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

int32_t LnnUpdateLocalBroadcastCipherKey(BroadcastCipherKey *broadcastKey)
{
    return GetInterface()->LnnUpdateLocalBroadcastCipherKey(broadcastKey);
}

bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetInterface()->LnnHasDiscoveryType(info, type);
}

void ProcessCipherKeySyncInfo(const void *json, const char *networkId)
{
    (void)json;
    (void)networkId;
}

int32_t AuthFindNormalizeKeyByServerSide(const char *udidHash, bool isServer, AuthDeviceKeyInfo *deviceKey)
{
    return GetInterface()->AuthFindNormalizeKeyByServerSide(udidHash, isServer, deviceKey);
}

void AuthUpdateCreateTime(const char *udidHash, int32_t keyType, bool isServer)
{
    (void)udidHash;
    (void)keyType;
    (void)isServer;
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return GetInterface()->SoftBusGenerateStrHash(str, len, hash);
}

int32_t SoftBusSocketGetPeerName(int32_t socketFd, SoftBusSockAddr *addr)
{
    return GetInterface()->SoftBusSocketGetPeerName(socketFd, addr);
}

int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len)
{
    return GetInterface()->LnnGetLocalByteInfo(key, info, len);
}

bool LnnIsDefaultOhosAccount(void)
{
    return GetInterface()->LnnIsDefaultOhosAccount();
}

int32_t IdServiceQueryCredential(int32_t userId, const char *udidHash, const char *accountidHash,
    bool isSameAccount, char **credList)
{
    return GetInterface()->IdServiceQueryCredential(userId, udidHash, accountidHash, isSameAccount, credList);
}

char *IdServiceGetCredIdFromCredList(int32_t userId, const char *credList)
{
    return GetInterface()->IdServiceGetCredIdFromCredList(userId, credList);
}

void IdServiceDestroyCredentialList(char **returnData)
{
    return GetInterface()->IdServiceDestroyCredentialList(returnData);
}

int32_t GetActiveOsAccountIds(void)
{
    return GetInterface()->GetActiveOsAccountIds();
}
}
}