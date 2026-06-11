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

#include "auth_interface.h"
#include "auth_log.h"
#include "softbus_error_code.h"

int32_t RegAuthVerifyListener(const AuthVerifyListener *listener)
{
    (void)listener;
    AUTH_LOGW(AUTH_INIT, "not implement");
    return SOFTBUS_OK;
}

void UnregAuthVerifyListener(void) { }

uint32_t AuthGenRequestId(void)
{
    return 0;
}

int32_t AuthStartVerify(const AuthConnInfo *connInfo, const AuthVerifyParam *authVerifyParam,
    const AuthVerifyCallback *callback)
{
    (void)connInfo;
    (void)authVerifyParam;
    (void)callback;
    AUTH_LOGW(AUTH_CONN, "not implement");
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthHandleLeaveLNN(AuthHandle authHandle)
{
    (void)authHandle;
    return;
}

int32_t AuthFlushDevice(const char *uuid, AuthLinkType type)
{
    (void)uuid;
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t RegGroupChangeListener(const GroupChangeListener *listener)
{
    (void)listener;
    return SOFTBUS_OK;
}

void UnregGroupChangeListener(void)
{
    return;
}

int32_t AuthStartListening(AuthLinkType type, const char *ip, int32_t port)
{
    (void)type;
    (void)ip;
    (void)port;
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthStopListening(AuthLinkType type)
{
    return;
}

int32_t RegAuthTransListener(int32_t module, const AuthTransListener *listener)
{
    (void)module;
    (void)listener;
    return SOFTBUS_OK;
}

void UnregAuthTransListener(int32_t module)
{
    return;
}

int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta)
{
    (void)info;
    (void)requestId;
    (void)callback;
    (void)isMeta;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthPostTransData(AuthHandle authHandle, const AuthTransData *dataInfo)
{
    (void)authHandle;
    (void)dataInfo;
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthCloseConn(AuthHandle authHandle)
{
    (void)authHandle;
    return;
}

int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    (void)uuid;
    (void)connInfo;
    (void)isMeta;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetPreferConnInfoWithoutSle(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    (void)uuid;
    (void)connInfo;
    (void)isMeta;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    (void)uuid;
    (void)connInfo;
    (void)isMeta;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetHmlConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    (void)uuid;
    (void)connInfo;
    (void)isMeta;
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthGetLatestIdByUuid(const char *uuid, AuthLinkType type, bool isMeta, AuthHandle *authHandle)
{
    (void)uuid;
    (void)type;
    (void)isMeta;
    (void)authHandle;
}

int64_t AuthGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer, bool isMeta)
{
    (void)connInfo;
    (void)isServer;
    (void)isMeta;
    return AUTH_INVALID_ID;
}

int64_t AuthGetIdByUuid(const char *uuid, AuthLinkType type, bool isServer, bool isMeta)
{
    (void)uuid;
    (void)type;
    (void)isServer;
    (void)isMeta;
    return AUTH_INVALID_ID;
}

uint32_t AuthGetEncryptSize(int64_t authId, uint32_t inLen)
{
    return 0;
}

uint32_t AuthGetDecryptSize(uint32_t inLen)
{
    return 0;
}

int32_t AuthEncrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    (void)authHandle;
    (void)inData;
    (void)inLen;
    (void)outData;
    (void)outLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthDecrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    (void)authHandle;
    (void)inData;
    (void)inLen;
    (void)outData;
    (void)outLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthSetP2pMac(int64_t authId, const char *p2pMac)
{
    (void)authId;
    (void)p2pMac;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo)
{
    (void)authHandle;
    (void)connInfo;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetServerSide(int64_t authId, bool *isServer)
{
    (void)authId;
    (void)isServer;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size)
{
    (void)authId;
    (void)uuid;
    (void)size;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetVersion(int64_t authId, SoftBusVersion *version)
{
    (void)authId;
    (void)version;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetMetaType(int64_t authId, bool *isMetaAuth)
{
    (void)authId;
    (void)isMetaAuth;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthInit(void)
{
    AUTH_LOGW(AUTH_FSM, "not implement");
    return SOFTBUS_OK;
}

void AuthDeinit(void)
{
    return;
}

int32_t RegTrustListenerOnHichainSaStart(void)
{
    return SOFTBUS_NOT_IMPLEMENT;
}

bool IsAuthHasTrustedRelation(void)
{
    return false;
}

bool AuthIsPotentialTrusted(const DeviceInfo *device, bool isOnlyPointToPoint)
{
    (void)device;
    (void)isOnlyPointToPoint;
    return false;
}

int32_t AuthCheckMetaExist(const AuthConnInfo *connInfo, bool *isExist)
{
    (void)connInfo;
    (void)isExist;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthCheckSessionKeyValidByAuthHandle(const AuthHandle *authHandle)
{
    (void)authHandle;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthCheckSessionKeyValidByConnInfo(const char *networkId, const AuthConnInfo *connInfo)
{
    (void)networkId;
    (void)connInfo;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetAuthHandleByIndex(const AuthConnInfo *connInfo, bool isServer, int32_t index, AuthHandle *authHandle)
{
    (void)connInfo;
    (void)isServer;
    (void)index;
    (void)authHandle;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetAuthHandleByIndexForBle(const AuthConnInfo *connInfo, char *networkId, NodeInfo *info)
{
    (void)connInfo;
    (void)networkId;
    (void)info;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetConnInfoBySide(const char *uuid, AuthConnInfo *connInfo, bool isMeta, bool isClient)
{
    (void)uuid;
    (void)connInfo;
    (void)isMeta;
    (void)isClient;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetConnInfoByType(const char *uuid, AuthLinkType type, AuthConnInfo *connInfo, bool isMeta)
{
    (void)uuid;
    (void)type;
    (void)connInfo;
    (void)isMeta;
    return SOFTBUS_NOT_IMPLEMENT;
}

uint32_t AuthGetGroupType(const char *udid, const char *uuid)
{
    (void)udid;
    (void)uuid;
    return 0;
}

int64_t AuthGetIdByIp(const char *ip)
{
    (void)ip;
    return AUTH_INVALID_ID;
}

int32_t AuthGetLatestAuthSeqList(const char *udid, int64_t *seqList, uint32_t num)
{
    (void)udid;
    (void)seqList;
    (void)num;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetLatestAuthSeqListByType(const char *udid, int64_t *seqList, uint64_t *authVerifyTime, DiscoveryType type)
{
    (void)udid;
    (void)seqList;
    (void)authVerifyTime;
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGetUsbConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    (void)uuid;
    (void)connInfo;
    (void)isMeta;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool AuthHasSameAccountGroup(void)
{
    return false;
}

TrustedReturnType AuthHasTrustedRelation(void)
{
    return TRUSTED_RELATION_NOT;
}

void AuthMetaReleaseVerify(int64_t authId)
{
    (void)authId;
}

int32_t AuthMetaStartVerify(uint32_t connectionId, const AuthKeyInfo *authKeyInfo, uint32_t requestId,
    int32_t callingPid, const AuthVerifyCallback *callBack)
{
    (void)connectionId;
    (void)authKeyInfo;
    (void)requestId;
    (void)callingPid;
    (void)callBack;
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthRemoveAuthManagerByAuthHandle(AuthHandle authHandle)
{
    (void)authHandle;
}

int32_t AuthRestoreAuthManager(const char *udidHash, const AuthConnInfo *connInfo, uint32_t requestId,
    NodeInfo *nodeInfo, int64_t *authId)
{
    (void)udidHash;
    (void)connInfo;
    (void)requestId;
    (void)nodeInfo;
    (void)authId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthSendKeepaliveOption(const char *uuid, ModeCycle cycle)
{
    (void)uuid;
    (void)cycle;
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthServerDeathCallback(const char *pkgName, int32_t pid)
{
    (void)pkgName;
    (void)pid;
}

int32_t AuthStartConnVerify(const AuthConnInfo *connInfo, uint32_t requestId, const AuthConnCallback *connCallback,
    AuthVerifyModule module, bool isFastAuth)
{
    (void)connInfo;
    (void)requestId;
    (void)connCallback;
    (void)module;
    (void)isFastAuth;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthStartListeningForWifiDirect(AuthLinkType type, const char *ip, int32_t port, ListenerModule *moduleId)
{
    (void)type;
    (void)ip;
    (void)port;
    (void)moduleId;
    return SOFTBUS_NOT_IMPLEMENT;
}

void AuthStopListeningForWifiDirect(AuthLinkType type, ListenerModule moduleId)
{
    (void)type;
    (void)moduleId;
}

bool IsSameAccountDevice(const DeviceInfo *device)
{
    (void)device;
    return false;
}

bool IsSameAccountId(int64_t accountId)
{
    (void)accountId;
    return false;
}

bool IsSupportFeatureByCapaBit(uint32_t feature, AuthCapability capaBit)
{
    (void)feature;
    (void)capaBit;
    return false;
}

bool IsNeedReOpenAuthConnection(const char *uuid)
{
    (void)uuid;
    return false;
}

