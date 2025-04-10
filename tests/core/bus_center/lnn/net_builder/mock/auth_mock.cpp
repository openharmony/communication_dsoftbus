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

#include "auth_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_authMock;
AuthInterfaceMock::AuthInterfaceMock()
{
    g_authMock = reinterpret_cast<void *>(this);
}

AuthInterfaceMock::~AuthInterfaceMock()
{
    g_authMock = nullptr;
}

static AuthInterface *GetAuthInterface()
{
    return reinterpret_cast<AuthInterface *>(g_authMock);
}

extern "C" {
void AuthHandleLeaveLNN(AuthHandle authHandle)
{
    GetAuthInterface()->AuthHandleLeaveLNN(authHandle);
}

uint32_t AuthGenRequestId(void)
{
    return GetAuthInterface()->AuthGenRequestId();
}

int32_t AuthStartVerify(const AuthConnInfo *connInfo, AuthVerifyParam *authVerifyParam,
    const AuthVerifyCallback *callback)
{
    return GetAuthInterface()->AuthStartVerify(connInfo, authVerifyParam, callback);
}

int32_t AuthGetVersion(int64_t authId, SoftBusVersion *version)
{
    return GetAuthInterface()->AuthGetVersion(authId, version);
}

int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    return GetAuthInterface()->AuthGetDeviceUuid(authId, uuid, size);
}

int32_t RegAuthTransListener(int32_t module, const AuthTransListener *listener)
{
    return GetAuthInterface()->RegAuthTransListener(module, listener);
}

void UnregAuthTransListener(int32_t module)
{
    return GetAuthInterface()->UnregAuthTransListener(module);
}

int32_t AuthPostTransData(AuthHandle authHandle, const AuthTransData *dataInfo)
{
    return GetAuthInterface()->AuthPostTransData(authHandle, dataInfo);
}

int64_t AuthGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer, bool isMeta)
{
    return GetAuthInterface()->AuthGetIdByConnInfo(connInfo, isServer, isMeta);
}

int32_t AuthFlushDevice(const char *uuid)
{
    return GetAuthInterface()->AuthFlushDevice(uuid);
}

int32_t AuthSendKeepaliveOption(const char *uuid, ModeCycle cycle)
{
    return GetAuthInterface()->AuthSendKeepaliveOption(uuid, cycle);
}

int32_t AuthStartConnVerify(const AuthConnInfo *connInfo, uint32_t requestId, const AuthConnCallback *connCallback,
    AuthVerifyModule module, bool isFastAuth)
{
    return GetAuthInterface()->AuthStartConnVerify(connInfo, requestId, connCallback, module, isFastAuth);
}

int32_t AuthMetaStartVerify(uint32_t connectionId, const AuthKeyInfo *authKeyInfo, uint32_t requestId,
    int32_t callingPid, const AuthVerifyCallback *callBack)
{
    return GetAuthInterface()->AuthMetaStartVerify(connectionId, authKeyInfo, requestId, callingPid, callBack);
}

void AuthMetaReleaseVerify(int64_t authId)
{
    return GetAuthInterface()->AuthMetaReleaseVerify(authId);
}

void AuthMetaStartVerify(const char *pkgName, int32_t pid)
{
    return GetAuthInterface()->AuthMetaStartVerify(pkgName, pid);
}

int32_t RegGroupChangeListener(const GroupChangeListener *listener)
{
    return GetAuthInterface()->RegGroupChangeListener(listener);
}

void UnregGroupChangeListener(void)
{
    return GetAuthInterface()->UnregGroupChangeListener();
}

bool AuthIsPotentialTrusted(const DeviceInfo *device, bool isOnlyPointToPoint)
{
    return GetAuthInterface()->AuthIsPotentialTrusted(device, isOnlyPointToPoint);
}

bool IsAuthHasTrustedRelation(void)
{
    return GetAuthInterface()->IsAuthHasTrustedRelation();
}

bool IsSameAccountDevice(const DeviceInfo *device)
{
    return GetAuthInterface()->IsSameAccountDevice(device);
}

bool AuthHasSameAccountGroup(void)
{
    return GetAuthInterface()->AuthHasSameAccountGroup();
}

int32_t AuthStartListening(AuthLinkType type, const char *ip, int32_t port)
{
    return GetAuthInterface()->AuthStartListening(type, ip, port);
}

void AuthStopListening(AuthLinkType type)
{
    return GetAuthInterface()->AuthStopListening(type);
}

int32_t AuthStartListeningForWifiDirect(AuthLinkType type, const char *ip, int32_t port, ListenerModule *moduleId)
{
    return GetAuthInterface()->AuthStartListeningForWifiDirect(type, ip, port, moduleId);
}

void AuthStopListeningForWifiDirect(AuthLinkType type, ListenerModule moduleId)
{
    return GetAuthInterface()->AuthStopListeningForWifiDirect(type, moduleId);
}

int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta)
{
    return GetAuthInterface()->AuthOpenConn(info, requestId, callback, isMeta);
}

void AuthCloseConn(AuthHandle authHandle)
{
    return GetAuthInterface()->AuthCloseConn(authHandle);
}

int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    return GetAuthInterface()->AuthGetPreferConnInfo(uuid, connInfo, isMeta);
}

int32_t AuthGetConnInfoByType(const char *uuid, AuthLinkType type, AuthConnInfo *connInfo, bool isMeta)
{
    return GetAuthInterface()->AuthGetConnInfoByType(uuid, type, connInfo, isMeta);
}

int32_t AuthGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    return GetAuthInterface()->AuthGetP2pConnInfo(uuid, connInfo, isMeta);
}

int32_t AuthGetHmlConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    return GetAuthInterface()->AuthGetHmlConnInfo(uuid, connInfo, isMeta);
}

int32_t AuthGetLatestAuthSeqList(const char *udid, int64_t *seqList, uint32_t num)
{
    return GetAuthInterface()->AuthGetLatestAuthSeqList(udid, seqList, num);
}

int32_t AuthGetLatestAuthSeqListByType(const char *udid, int64_t *seqList, uint64_t *authVerifyTime,
    DiscoveryType type)
{
    return GetAuthInterface()->AuthGetLatestAuthSeqListByType(udid, seqList, authVerifyTime, type);
}

void AuthGetLatestIdByUuid(const char *uuid, AuthLinkType type, bool isMeta, AuthHandle *authHandle)
{
    return GetAuthInterface()->AuthGetLatestIdByUuid(uuid, type, isMeta, authHandle);
}

int32_t AuthGetAuthHandleByIndex(const AuthConnInfo *connInfo, bool isServer, int32_t index, AuthHandle *authHandle)
{
    return GetAuthInterface()->AuthGetAuthHandleByIndex(connInfo, isServer, index, authHandle);
}

int64_t AuthGetIdByUuid(const char *uuid, AuthLinkType type, bool isServer, bool isMeta)
{
    return GetAuthInterface()->AuthGetIdByUuid(uuid, type, isServer, isMeta);
}

uint32_t AuthGetEncryptSize(int64_t authId, uint32_t inLen)
{
    return GetAuthInterface()->AuthGetEncryptSize(authId, inLen);
}

uint32_t AuthGetDecryptSize(uint32_t inLen)
{
    return GetAuthInterface()->AuthGetDecryptSize(inLen);
}

int32_t AuthEncrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    return GetAuthInterface()->AuthEncrypt(authHandle, inData, inLen, inLen, outLen);
}

int32_t AuthDecrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    return GetAuthInterface()->AuthDecrypt(authHandle, inData, inLen, outData, outLen);
}

int32_t AuthSetP2pMac(int64_t authId, const char *p2pMac)
{
    return GetAuthInterface()->AuthSetP2pMac(authId, p2pMac);
}

int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo)
{
    return GetAuthInterface()->AuthGetConnInfo(authHandle, connInfo);
}

int32_t AuthGetServerSide(int64_t authId, bool *isServer)
{
    return GetAuthInterface()->AuthGetServerSide(authId, isServer);
}

int32_t AuthGetMetaType(int64_t authId, bool *isMetaAuth)
{
    return GetAuthInterface()->AuthGetMetaType(authId, isMetaAuth);
}

uint32_t AuthGetGroupType(const char *udid, const char *uuid)
{
    return GetAuthInterface()->AuthGetGroupType(udid, uuid);
}

bool IsSupportFeatureByCapaBit(uint32_t feature, AuthCapability capaBit)
{
    return GetAuthInterface()->IsSupportFeatureByCapaBit(feature, capaBit);
}

void AuthRemoveAuthManagerByAuthHandle(AuthHandle authHandle)
{
    return GetAuthInterface()->AuthRemoveAuthManagerByAuthHandle(authHandle);
}

int32_t AuthCheckSessionKeyValidByConnInfo(const char *networkId, const AuthConnInfo *connInfo)
{
    return GetAuthInterface()->AuthCheckSessionKeyValidByConnInfo(networkId, connInfo);
}

int32_t AuthCheckSessionKeyValidByAuthHandle(const AuthHandle *authHandle)
{
    return GetAuthInterface()->AuthCheckSessionKeyValidByAuthHandle(authHandle);
}

int32_t AuthInit(void)
{
    return GetAuthInterface()->AuthInit();
}

void AuthDeinit(void)
{
    GetAuthInterface()->AuthDeinit();
}

int32_t AuthRestoreAuthManager(const char *udidHash,
    const AuthConnInfo *connInfo, uint32_t requestId, NodeInfo *nodeInfo, int64_t *authId)
{
    return GetAuthInterface()->AuthRestoreAuthManager(udidHash, connInfo, requestId, nodeInfo, authId);
}

int32_t AuthCheckMetaExist(const AuthConnInfo *connInfo, bool *isExist)
{
    return GetAuthInterface()->AuthCheckMetaExist(connInfo, isExist);
}

}
}