/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef AUTH_SESSION_JSON_MOCK_H
#define AUTH_SESSION_JSON_MOCK_H

#include <gmock/gmock.h>

#include "auth_device_common_key_struct.h"
#include "auth_hichain_adapter.h"
#include "auth_identity_service_adapter.h"
#include "auth_pre_link.h"
#include "auth_session_fsm.h"
#include "auth_session_json.h"
#include "auth_session_message.h"
#include "bus_center_info_key.h"
#include "common_list.h"
#include "lnn_cipherkey_manager_struct.h"
#include "lnn_common_utils.h"
#include "lnn_feature_capability.h"
#include "lnn_lane_interface.h"
#include "lnn_node_info.h"
#include "softbus_adapter_socket.h"
#include "softbus_common.h"
#include "wifi_direct_manager.h"

namespace OHOS {
class AuthSessionJsonInterface {
public:
    AuthSessionJsonInterface() {};
    virtual ~AuthSessionJsonInterface() {};
    virtual int32_t LnnGetUdidByBrMac(const char *brMac, char *udid, uint32_t udidLen) = 0;
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t LnnGetLocalStrInfoByIfnameIdx(InfoKey key, char *info, uint32_t len, int32_t ifIdx) = 0;
    virtual int32_t FindAuthPreLinkNodeById(uint32_t requestId, AuthPreLinkNode *reuseNode) = 0;
    virtual int32_t LnnGetLocalNodeInfoSafe(NodeInfo *info) = 0;
    virtual bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit) = 0;
    virtual bool IsSupportFeatureByCapaBit(uint32_t feature, AuthCapability capaBit) = 0;
    virtual bool IsPotentialTrustedDeviceDp(const char *deviceIdHash, bool isOnlyPointToPoint) = 0;
    virtual bool IsSupportUDIDAbatement(void) = 0;
    virtual bool IsNeedUDIDAbatement(const AuthSessionInfo *info) = 0;
    virtual bool IsPotentialTrustedDevice(TrustedRelationIdType idType, const char *deviceId, bool isPrecise,
        bool isPointToPoint) = 0;
    virtual bool IsAuthPreLinkNodeExist(uint32_t requestId) = 0;
    virtual int32_t GetFd(uint64_t connId) = 0;
    virtual int32_t AddToAuthPreLinkList(uint32_t requestId, int32_t fd, ConnectionAddr *connAddr) = 0;
    virtual bool GetSessionKeyProfile(int32_t sessionKeyId, uint8_t *sessionKey, uint32_t *length) = 0;
    virtual int32_t LnnGetAuthPort(const NodeInfo *info, int32_t ifnameIdx) = 0;
    virtual int32_t LnnGetSessionPort(const NodeInfo *info, int32_t ifnameIdx) = 0;
    virtual int32_t PostAuthData(uint64_t connId, bool toServer, const AuthDataHead *head, const uint8_t *data) = 0;
    virtual int32_t EncryptInner(const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo,
        uint8_t **outData, uint32_t *outLen);
    virtual int32_t AuthManagerGetSessionKey(int64_t authSeq, const AuthSessionInfo *info,
        SessionKey *sessionKey) = 0;
    virtual int32_t AddSessionKey(SessionKeyList *list, int32_t index, const SessionKey *key, AuthLinkType type,
        bool isOldKey) = 0;
    virtual int32_t SetSessionKeyAvailable(SessionKeyList *list, int32_t index) = 0;
    virtual int64_t AuthDeviceGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer) = 0;
    virtual uint32_t AuthGetDecryptSize(uint32_t inLen) = 0;
    virtual int32_t AuthDeviceDecrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData,
        uint32_t *outLen) = 0;
    virtual int32_t AuthManagerSetSessionKey(int64_t authSeq, AuthSessionInfo *info, const SessionKey *sessionKey,
        bool isConnect, bool isOldKey) = 0;
    virtual uint64_t GenerateLaneId(const char *localUdid, const char *remoteUdid, LaneLinkType linkType) = 0;
    virtual int32_t UpdateLaneResourceLaneId(uint64_t oldLaneId, uint64_t newLaneId, const char *peerUdid) = 0;
    virtual int32_t DecryptInner(const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo,
        uint8_t **outData, uint32_t *outLen) = 0;
    virtual int32_t DataDecompress(uint8_t *in, uint32_t inLen, uint8_t **out, uint32_t *outLen) = 0;
    virtual const NodeInfo *LnnGetLocalNodeInfo(void) = 0;
    virtual int32_t LnnGetProxyPort(const NodeInfo *info, int32_t ifnameIdx) = 0;
    virtual const char *LnnGetBtMac(const NodeInfo *info) = 0;
    virtual const char *LnnGetP2pMac(const NodeInfo *info) = 0;
    virtual const char *LnnGetDeviceName(const DeviceBasicInfo *info) = 0;
    virtual char *LnnConvertIdToDeviceType(uint16_t typeId) = 0;
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info) = 0;
    virtual int32_t InitSoftbusChain(SoftbusCertChain *softbusCertChain) = 0;
    virtual int32_t LnnGetDeviceDisplayName(const char *nickName, const char *defaultName, char *deviceName,
        uint32_t len) = 0;
    virtual int32_t VerifyCertificate(SoftbusCertChain *softbusCertChain, const NodeInfo *nodeInfo,
        const AuthSessionInfo *info) = 0;
    virtual int32_t LnnConvertDeviceTypeToId(const char *deviceType, uint16_t *typeId) = 0;
    virtual int32_t LnnEncryptAesGcm(AesGcmInputParam *in, int32_t keyIndex, uint8_t **out, uint32_t *outLen) = 0;
    virtual int32_t AuthFindLatestNormalizeKey(const char *udidHash, AuthDeviceKeyInfo *deviceKey,
        bool clearOldKey) = 0;
    virtual int32_t AuthFindDeviceKey(const char *udidHash, int32_t keyType, AuthDeviceKeyInfo *deviceKey) = 0;
    virtual int32_t LnnRetrieveDeviceInfoByNetworkId(const char *networkId, NodeInfo *info) = 0;
    virtual AuthManager *GetAuthManagerByAuthId(int64_t authId) = 0;
    virtual int32_t GetLatestSessionKey(const SessionKeyList *list, AuthLinkType type, int32_t *index,
        SessionKey *key) = 0;
    virtual int32_t LnnDecryptAesGcm(AesGcmInputParam *in, uint8_t **out, uint32_t *outLen) = 0;
    virtual int32_t LnnGetUnifiedDeviceName(char *unifiedName, uint32_t len) = 0;
    virtual int32_t LnnSetLocalStrInfo(InfoKey key, const char *info) = 0;
    virtual const char *LnnGetDeviceUdid(const NodeInfo *info) = 0;
    virtual uint64_t LnnGetSupportedProtocols(const NodeInfo *info) = 0;
    virtual int32_t GetExtData(char *value, uint32_t len) = 0;
    virtual bool PackCipherKeySyncMsg(void *json) = 0;
    virtual int32_t LnnGetP2pRole(const NodeInfo *info) = 0;
    virtual int32_t LnnGetStaFrequency(const NodeInfo *info) = 0;
    virtual int32_t LnnUpdateLocalBroadcastCipherKey(BroadcastCipherKey *broadcastKey) = 0;
    virtual bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type) = 0;
    virtual int32_t AuthFindNormalizeKeyByServerSide(const char *udidHash, bool isServer,
        AuthDeviceKeyInfo *deviceKey) = 0;
    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
    virtual int32_t SoftBusSocketGetPeerName(int32_t socketFd, SoftBusSockAddr *addr) = 0;
    virtual int32_t LnnGetLocalByteInfo(InfoKey key, uint8_t *info, uint32_t len) = 0;
    virtual bool LnnIsDefaultOhosAccount(void) = 0;
    virtual char *IdServiceGetCredIdFromCredList(int32_t userId, const char *credList) = 0;
    virtual int32_t IdServiceQueryCredential(int32_t userId, const char *udidHash, const char *accountidHash,
        bool isSameAccount, char **credList) = 0;
    virtual int32_t AuthIdServiceQueryCredential(int32_t peerUserId, const char *udidHash, const char *accountidHash,
        bool isSameAccount, char **credList) = 0;
    virtual void IdServiceDestroyCredentialList(char **returnData) = 0;
    virtual int32_t GetActiveOsAccountIds(void) = 0;
    virtual bool IsSKIdInvalid(int32_t sessionKeyId, const char *accountHash, const char *udidShortHash,
        int32_t userId) = 0;
    virtual bool IsTrustedDeviceFromAccess(const char *peerAccountHash, const char *peerUdid,
        int32_t peerUserId) = 0;
};

class AuthSessionJsonInterfaceMock : public AuthSessionJsonInterface {
public:
    AuthSessionJsonInterfaceMock();
    ~AuthSessionJsonInterfaceMock() override;
    MOCK_METHOD3(LnnGetUdidByBrMac, int32_t (const char *, char *, uint32_t));
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t (InfoKey, char *, uint32_t));
    MOCK_METHOD4(LnnGetLocalStrInfoByIfnameIdx, int32_t(InfoKey, char *, uint32_t, int32_t));
    MOCK_METHOD2(FindAuthPreLinkNodeById, int32_t (uint32_t, AuthPreLinkNode *));
    MOCK_METHOD1(LnnGetLocalNodeInfoSafe, int32_t (NodeInfo *));
    MOCK_METHOD2(IsFeatureSupport, bool (uint64_t, FeatureCapability));
    MOCK_METHOD2(IsSupportFeatureByCapaBit, bool (uint32_t, AuthCapability));
    MOCK_METHOD2(IsPotentialTrustedDeviceDp, bool (const char *, bool));
    MOCK_METHOD0(IsSupportUDIDAbatement, bool (void));
    MOCK_METHOD1(IsNeedUDIDAbatement, bool (const AuthSessionInfo *));
    MOCK_METHOD4(IsPotentialTrustedDevice, bool (TrustedRelationIdType, const char *, bool, bool));
    MOCK_METHOD1(IsAuthPreLinkNodeExist, bool (uint32_t));
    MOCK_METHOD1(GetFd, int32_t (uint64_t));
    MOCK_METHOD3(AddToAuthPreLinkList, int32_t (uint32_t, int32_t, ConnectionAddr *));
    MOCK_METHOD3(GetSessionKeyProfile, bool (int32_t, uint8_t *, uint32_t *));
    MOCK_METHOD2(LnnGetAuthPort, int32_t (const NodeInfo *, int32_t));
    MOCK_METHOD2(LnnGetSessionPort, int32_t (const NodeInfo *, int32_t));
    MOCK_METHOD4(PostAuthData, int32_t (uint64_t, bool, const AuthDataHead *, const uint8_t *));
    MOCK_METHOD5(EncryptInner,
        int32_t (const SessionKeyList *, AuthLinkType, const InDataInfo *, uint8_t **, uint32_t *));
    MOCK_METHOD3(AuthManagerGetSessionKey, int32_t (int64_t, const AuthSessionInfo *, SessionKey *));
    MOCK_METHOD5(AddSessionKey, int32_t (SessionKeyList *, int32_t, const SessionKey *, AuthLinkType, bool));
    MOCK_METHOD2(SetSessionKeyAvailable, int32_t (SessionKeyList *, int32_t));
    MOCK_METHOD2(AuthDeviceGetIdByConnInfo, int64_t(const AuthConnInfo *, bool));
    MOCK_METHOD1(AuthGetDecryptSize, uint32_t (uint32_t));
    MOCK_METHOD5(AuthDeviceDecrypt, int32_t (AuthHandle *, const uint8_t *, uint32_t, uint8_t *, uint32_t *));
    MOCK_METHOD5(AuthManagerSetSessionKey, int32_t (int64_t, AuthSessionInfo *, const SessionKey *, bool, bool));
    MOCK_METHOD3(GenerateLaneId, uint64_t (const char *, const char *, LaneLinkType));
    MOCK_METHOD3(UpdateLaneResourceLaneId, int32_t(uint64_t, uint64_t, const char *));
    MOCK_METHOD5(DecryptInner, int32_t (const SessionKeyList *, AuthLinkType, const InDataInfo *, uint8_t **,
        uint32_t *));
    MOCK_METHOD4(DataDecompress, int32_t (uint8_t *, uint32_t, uint8_t **, uint32_t *));
    MOCK_METHOD0(LnnGetLocalNodeInfo, const NodeInfo * (void));
    MOCK_METHOD2(LnnGetProxyPort, int32_t (const NodeInfo *, int32_t));
    MOCK_METHOD1(LnnGetBtMac, const char * (const NodeInfo *));
    MOCK_METHOD1(LnnGetP2pMac, const char * (const NodeInfo *));
    MOCK_METHOD1(LnnGetDeviceName, const char * (const DeviceBasicInfo *));
    MOCK_METHOD1(LnnConvertIdToDeviceType, char * (uint16_t));
    MOCK_METHOD2(LnnGetLocalNumInfo, int32_t (InfoKey, int32_t *));
    MOCK_METHOD1(InitSoftbusChain, int32_t (SoftbusCertChain *));
    MOCK_METHOD4(LnnGetDeviceDisplayName, int32_t (const char *, const char *, char *, uint32_t));
    MOCK_METHOD3(VerifyCertificate, int32_t (SoftbusCertChain *, const NodeInfo *, const AuthSessionInfo *));
    MOCK_METHOD2(LnnConvertDeviceTypeToId, int32_t (const char *, uint16_t *));
    MOCK_METHOD4(LnnEncryptAesGcm, int32_t (AesGcmInputParam *, int32_t, uint8_t **, uint32_t *));
    MOCK_METHOD3(AuthFindLatestNormalizeKey, int32_t (const char *, AuthDeviceKeyInfo *, bool));
    MOCK_METHOD3(AuthFindDeviceKey, int32_t (const char *, int32_t, AuthDeviceKeyInfo *));
    MOCK_METHOD2(LnnRetrieveDeviceInfoByNetworkId, int32_t (const char *, NodeInfo *));
    MOCK_METHOD1(GetAuthManagerByAuthId, AuthManager * (int64_t));
    MOCK_METHOD4(GetLatestSessionKey, int32_t (const SessionKeyList *, AuthLinkType, int32_t *, SessionKey *));
    MOCK_METHOD3(LnnDecryptAesGcm, int32_t (AesGcmInputParam *, uint8_t **, uint32_t *));
    MOCK_METHOD2(LnnGetUnifiedDeviceName, int32_t (char *, uint32_t));
    MOCK_METHOD2(LnnSetLocalStrInfo, int32_t (InfoKey, const char *));
    MOCK_METHOD1(LnnGetDeviceUdid, const char * (const NodeInfo *));
    MOCK_METHOD1(LnnGetSupportedProtocols, uint64_t (const NodeInfo *));
    MOCK_METHOD2(GetExtData, int32_t (char *, uint32_t));
    MOCK_METHOD1(PackCipherKeySyncMsg, bool (void *));
    MOCK_METHOD1(LnnGetP2pRole, int32_t (const NodeInfo *));
    MOCK_METHOD1(LnnGetStaFrequency, int32_t (const NodeInfo *));
    MOCK_METHOD1(LnnUpdateLocalBroadcastCipherKey, int32_t (BroadcastCipherKey *));
    MOCK_METHOD2(LnnHasDiscoveryType, bool (const NodeInfo *, DiscoveryType));
    MOCK_METHOD3(AuthFindNormalizeKeyByServerSide, int32_t (const char *, bool, AuthDeviceKeyInfo *));
    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t (const unsigned char *, uint32_t, unsigned char *));
    MOCK_METHOD2(SoftBusSocketGetPeerName, int32_t (int32_t, SoftBusSockAddr *));
    MOCK_METHOD3(LnnGetLocalByteInfo, int32_t (InfoKey key, uint8_t *info, uint32_t len));
    MOCK_METHOD0(LnnIsDefaultOhosAccount, bool (void));
    MOCK_METHOD2(IdServiceGetCredIdFromCredList, char * (int32_t userId, const char *credList));
    MOCK_METHOD5(IdServiceQueryCredential, int32_t (int32_t userId, const char *udidHash,
        const char *accountidHash, bool isSameAccount, char **credList));
    MOCK_METHOD5(AuthIdServiceQueryCredential, int32_t (int32_t peerUserId, const char *udidHash,
        const char *accountidHash, bool isSameAccount, char **credList));
    MOCK_METHOD1(IdServiceDestroyCredentialList, void (char **returnData));
    MOCK_METHOD0(GetActiveOsAccountIds, int32_t(void));
    MOCK_METHOD4(IsSKIdInvalid, bool (int32_t, const char *, const char *, int32_t));
    MOCK_METHOD3(IsTrustedDeviceFromAccess, bool (const char *, const char *, int32_t));
};

extern "C" {
void DelSessionKeyProfile(int32_t sessionKeyId);
void DestroySessionKeyList(SessionKeyList *list);
void RefreshRelationShip(const char *remoteUuid, const char *remoteMac);
struct WifiDirectManager *GetWifiDirectManager(void);
void FreeSoftbusChain(SoftbusCertChain *softbusCertChain);
void LnnDumpRemotePtk(const char *oldPtk, const char *newPtk, const char *log);
void AuthGetLatestIdByUuid(const char *uuid, AuthLinkType type, bool isMeta, AuthHandle *authHandle);
void DelDupAuthManager(AuthManager *auth);
void ProcessCipherKeySyncInfo(const void *json, const char *networkId);
void AuthUpdateCreateTime(const char *udidHash, int32_t keyType, bool isServer);
}
}
#endif // AUTH_SESSION_JSON_MOCK_H