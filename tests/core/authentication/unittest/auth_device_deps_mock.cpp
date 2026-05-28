/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "auth_device_deps_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_authDeviceDepsIf;

AuthDeviceDepsInterfaceMock::AuthDeviceDepsInterfaceMock()
{
    g_authDeviceDepsIf = static_cast<void *>(this);
}

AuthDeviceDepsInterfaceMock::~AuthDeviceDepsInterfaceMock()
{
    g_authDeviceDepsIf = nullptr;
}

static AuthDeviceDepsInterface *GetAuthDeviceDepsIf()
{
    return static_cast<AuthDeviceDepsInterface *>(g_authDeviceDepsIf);
}

extern "C" {
const char *GetAuthSideStr(bool isServer)
{
    if (isServer) {
        return "server";
    }
    return "client";
}

AuthManager *GetAuthManagerByAuthId(int64_t authId)
{
    return GetAuthDeviceDepsIf()->GetAuthManagerByAuthId(authId);
}

void DelDupAuthManager(AuthManager *auth)
{
    return GetAuthDeviceDepsIf()->DelDupAuthManager(auth);
}

void RemoveNotPassedAuthManagerByUdid(const char *udid)
{
    return GetAuthDeviceDepsIf()->RemoveNotPassedAuthManagerByUdid(udid);
}

AuthManager *GetDeviceAuthManager(int64_t authSeq, const AuthSessionInfo *info,
    bool *isNewCreated, int64_t lastAuthSeq)
{
    return GetAuthDeviceDepsIf()->GetDeviceAuthManager(authSeq, info, isNewCreated, lastAuthSeq);
}

int64_t GetLatestIdByConnInfo(const AuthConnInfo *connInfo)
{
    return GetAuthDeviceDepsIf()->GetLatestIdByConnInfo(connInfo);
}

int64_t GetActiveAuthIdByConnInfo(const AuthConnInfo *connInfo, bool judgeTimeOut)
{
    return GetAuthDeviceDepsIf()->GetActiveAuthIdByConnInfo(connInfo, judgeTimeOut);
}

uint64_t GetCurrentTimeMs(void)
{
    return GetAuthDeviceDepsIf()->GetCurrentTimeMsMock();
}

int64_t GenSeq(bool isServer)
{
    return GetAuthDeviceDepsIf()->GenSeqMock(isServer);
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    return GetAuthDeviceDepsIf()->SoftBusGenerateStrHash(str, len, hash);
}

int32_t ConvertBytesToUpperCaseHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen)
{
    return GetAuthDeviceDepsIf()->ConvertBytesToUpperCaseHexString(outBuf, outBufLen, inBuf, inLen);
}

int32_t EncryptInner(const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo,
    uint8_t **outData, uint32_t *outLen)
{
    return GetAuthDeviceDepsIf()->EncryptInner(list, type, inDataInfo, outData, outLen);
}

int32_t EncryptData(const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo,
    uint8_t *outData, uint32_t *outLen)
{
    return GetAuthDeviceDepsIf()->EncryptData(list, type, inDataInfo, outData, outLen);
}

int32_t DecryptData(const SessionKeyList *list, AuthLinkType type, const InDataInfo *inDataInfo,
    uint8_t *outData, uint32_t *outLen)
{
    return GetAuthDeviceDepsIf()->DecryptData(list, type, inDataInfo, outData, outLen);
}

uint32_t AuthGetDecryptSize(uint32_t inLen)
{
    return GetAuthDeviceDepsIf()->AuthGetDecryptSize(inLen);
}

int32_t PostAuthData(uint64_t connId, bool toServer, const AuthDataHead *head, const uint8_t *data)
{
    return GetAuthDeviceDepsIf()->PostAuthData(connId, toServer, head, data);
}

int32_t ConnectAuthDevice(uint32_t requestId, const AuthConnInfo *connInfo, ConnSideType sideType)
{
    return GetAuthDeviceDepsIf()->ConnectAuthDevice(requestId, connInfo, sideType);
}

void DisconnectAuthDevice(uint64_t *connId)
{
    return GetAuthDeviceDepsIf()->DisconnectAuthDevice(connId);
}

ConnSideType GetConnSideType(uint64_t connId)
{
    return GetAuthDeviceDepsIf()->GetConnSideType(connId);
}

uint32_t GetConnId(uint64_t connId)
{
    return GetAuthDeviceDepsIf()->GetConnId(connId);
}

bool CheckAuthConnInfoType(const AuthConnInfo *connInfo)
{
    return GetAuthDeviceDepsIf()->CheckAuthConnInfoTypeMock(connInfo);
}

bool CheckAuthConnCallback(const AuthConnCallback *connCb)
{
    return GetAuthDeviceDepsIf()->CheckAuthConnCallback(connCb);
}

bool CheckVerifyCallback(const AuthVerifyCallback *verifyCb)
{
    return GetAuthDeviceDepsIf()->CheckVerifyCallback(verifyCb);
}

bool CheckSessionKeyListExistType(const SessionKeyList *list, AuthLinkType type)
{
    return GetAuthDeviceDepsIf()->CheckSessionKeyListExistType(list, type);
}

bool RequireAuthLock(void)
{
    return GetAuthDeviceDepsIf()->RequireAuthLockMock();
}

void ReleaseAuthLock(void)
{
    GetAuthDeviceDepsIf()->ReleaseAuthLockMock();
}

uint32_t AddAuthRequest(const AuthRequest *request)
{
    return GetAuthDeviceDepsIf()->AddAuthRequest(request);
}

int32_t FindAndDelAuthRequestByConnInfo(uint32_t requestId, const AuthConnInfo *connInfo)
{
    return GetAuthDeviceDepsIf()->FindAndDelAuthRequestByConnInfo(requestId, connInfo);
}

void DelAuthRequest(uint32_t requestId)
{
    return GetAuthDeviceDepsIf()->DelAuthRequest(requestId);
}

void LnnMapInit(Map *map)
{
    return GetAuthDeviceDepsIf()->LnnMapInit(map);
}

int32_t LnnMapSet(Map *map, const char *key, const void *value, uint32_t valueSize)
{
    return GetAuthDeviceDepsIf()->LnnMapSet(map, key, value, valueSize);
}

void *LnnMapGet(const Map *map, const char *key)
{
    return GetAuthDeviceDepsIf()->LnnMapGet(map, key);
}

int32_t LnnMapErase(Map *map, const char *key)
{
    return GetAuthDeviceDepsIf()->LnnMapErase(map, key);
}

void LnnMapDelete(Map *map)
{
    return GetAuthDeviceDepsIf()->LnnMapDelete(map);
}

int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len)
{
    return GetAuthDeviceDepsIf()->LnnGetNetworkIdByUdid(udid, buf, len);
}

int32_t LnnGetRemoteNodeInfoByKey(const char *key, NodeInfo *info)
{
    return GetAuthDeviceDepsIf()->LnnGetRemoteNodeInfoByKey(key, info);
}

int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len)
{
    return GetAuthDeviceDepsIf()->LnnGetLocalStrInfo(key, info, len);
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return GetAuthDeviceDepsIf()->LnnGetLocalNumInfo(key, info);
}

int32_t LnnDeleteSpecificTrustedDevInfo(const char *udid, int32_t localUserId)
{
    return GetAuthDeviceDepsIf()->LnnDeleteSpecificTrustedDevInfo(udid, localUserId);
}

int32_t JudgeDeviceTypeAndGetOsAccountIds(void)
{
    return GetAuthDeviceDepsIf()->JudgeDeviceTypeAndGetOsAccountIds();
}

void LnnHbOnTrustedRelationIncreased(int32_t groupType)
{
    return GetAuthDeviceDepsIf()->LnnHbOnTrustedRelationIncreased(groupType);
}

void LnnHbOnTrustedRelationReduced(void)
{
    return GetAuthDeviceDepsIf()->LnnHbOnTrustedRelationReduced();
}

int32_t LnnInsertSpecificTrustedDevInfo(const char *udid)
{
    return GetAuthDeviceDepsIf()->LnnInsertSpecificTrustedDevInfo(udid);
}

int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType,
    DeviceLeaveReason leaveReason)
{
    return GetAuthDeviceDepsIf()->LnnRequestLeaveSpecific(networkId, addrType, leaveReason);
}

void AuthRemoveDeviceKeyByUdidPacked(const char *udid)
{
    return GetAuthDeviceDepsIf()->AuthRemoveDeviceKeyByUdidPacked(udid);
}

int32_t AuthSessionHandleDeviceNotTrusted(const char *peerUdid)
{
    return GetAuthDeviceDepsIf()->AuthSessionHandleDeviceNotTrusted(peerUdid);
}

bool DpHasAccessControlProfile(const char *udid, bool isSameAccount, int32_t userId)
{
    return GetAuthDeviceDepsIf()->DpHasAccessControlProfile(udid, isSameAccount, userId);
}

void LnnDeleteLinkFinderInfo(const char *peerUdid)
{
    return GetAuthDeviceDepsIf()->LnnDeleteLinkFinderInfo(peerUdid);
}

int32_t RegTrustDataChangeListener(const TrustDataChangeListener *listener)
{
    return GetAuthDeviceDepsIf()->RegTrustDataChangeListener(listener);
}

int SoftBusSleepMs(unsigned int ms)
{
    GetAuthDeviceDepsIf()->SoftBusSleepMsMock(ms);
    return 0;
}

int32_t RegisterToDp(DeviceProfileChangeListener *deviceProfilePara)
{
    return GetAuthDeviceDepsIf()->RegisterToDp(deviceProfilePara);
}

int32_t InitDbListDelay(void)
{
    return GetAuthDeviceDepsIf()->InitDbListDelay();
}

void SoftbusHitraceStart(uint32_t flags, uint64_t chainId)
{
    return GetAuthDeviceDepsIf()->SoftbusHitraceStart(flags, chainId);
}

void SoftbusHitraceStop(void)
{
    return GetAuthDeviceDepsIf()->SoftbusHitraceStop();
}
}
} // namespace OHOS
