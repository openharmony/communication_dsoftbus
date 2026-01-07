/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef AUTH_INTERFACE_H
#define AUTH_INTERFACE_H

#include <stdbool.h>
#include <stdint.h>
#include "lnn_node_info.h"
#include "softbus_common.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "auth_interface_struct.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t RegAuthVerifyListener(const AuthVerifyListener *listener);
void UnregAuthVerifyListener(void);
uint32_t AuthGenRequestId(void);
int32_t AuthStartVerify(const AuthConnInfo *connInfo, const AuthVerifyParam *authVerifyParam,
    const AuthVerifyCallback *callback);
int32_t AuthStartConnVerify(const AuthConnInfo *connInfo, uint32_t requestId, const AuthConnCallback *connCallback,
    AuthVerifyModule module, bool isFastAuth);
void AuthHandleLeaveLNN(AuthHandle authHandle);
int32_t AuthFlushDevice(const char *uuid, AuthLinkType type);
int32_t AuthSendKeepaliveOption(const char *uuid, ModeCycle cycle);

int32_t AuthMetaStartVerify(uint32_t connectionId, const AuthKeyInfo *authKeyInfo, uint32_t requestId,
    int32_t callingPid, const AuthVerifyCallback *callBack);
void AuthMetaReleaseVerify(int64_t authId);
void AuthServerDeathCallback(const char *pkgName, int32_t pid);

int32_t RegGroupChangeListener(const GroupChangeListener *listener);
void UnregGroupChangeListener(void);

TrustedReturnType AuthHasTrustedRelation(void);
bool AuthIsPotentialTrusted(const DeviceInfo *device, bool isOnlyPointToPoint);
bool IsAuthHasTrustedRelation(void);
bool IsSameAccountDevice(const DeviceInfo *device);
bool AuthHasSameAccountGroup(void);
bool IsSameAccountId(int64_t accountId);

int32_t AuthStartListening(AuthLinkType type, const char *ip, int32_t port);
void AuthStopListening(AuthLinkType type);

int32_t AuthStartListeningForWifiDirect(AuthLinkType type, const char *ip, int32_t port, ListenerModule *moduleId);
void AuthStopListeningForWifiDirect(AuthLinkType type, ListenerModule moduleId);

int32_t RegAuthTransListener(int32_t module, const AuthTransListener *listener);
void UnregAuthTransListener(int32_t module);

int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta);
int32_t AuthPostTransData(AuthHandle authHandle, const AuthTransData *dataInfo);
void AuthCloseConn(AuthHandle authHandle);
int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta);
int32_t AuthGetPreferConnInfoWithoutSle(const char *uuid, AuthConnInfo *connInfo, bool isMeta);
int32_t AuthGetConnInfoByType(const char *uuid, AuthLinkType type, AuthConnInfo *connInfo, bool isMeta);
int32_t AuthGetConnInfoBySide(const char *uuid, AuthConnInfo *connInfo, bool isMeta, bool isClient);
int32_t AuthGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta);
int32_t AuthGetHmlConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta);
int32_t AuthGetUsbConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta);
int32_t AuthGetLatestAuthSeqList(const char *udid, int64_t *seqList, uint32_t num);
int32_t AuthGetLatestAuthSeqListByType(const char *udid, int64_t *seqList, uint64_t *authVerifyTime,
    DiscoveryType type);
/* for ProxyChannel & P2P TcpDirectchannel */
void AuthGetLatestIdByUuid(const char *uuid, AuthLinkType type, bool isMeta, AuthHandle *authHandle);
int32_t AuthGetAuthHandleByIndex(const AuthConnInfo *connInfo, bool isServer, int32_t index, AuthHandle *authHandle);
int32_t AuthGetNodeInfoByIndexForBle(const AuthConnInfo *connInfo, char *networkId, NodeInfo *info);
int64_t AuthGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer, bool isMeta);
int64_t AuthGetIdByUuid(const char *uuid, AuthLinkType type, bool isServer, bool isMeta);
int64_t AuthGetIdByIp(const char *ip);

uint32_t AuthGetEncryptSize(int64_t authId, uint32_t inLen);
uint32_t AuthGetDecryptSize(uint32_t inLen);
int32_t AuthEncrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen);
int32_t AuthDecrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen);
int32_t AuthSetP2pMac(int64_t authId, const char *p2pMac);

int32_t AuthGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo);
int32_t AuthGetServerSide(int64_t authId, bool *isServer);
int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size);
int32_t AuthGetVersion(int64_t authId, SoftBusVersion *version);
int32_t AuthGetMetaType(int64_t authId, bool *isMetaAuth);
uint32_t AuthGetGroupType(const char *udid, const char *uuid);
bool IsSupportFeatureByCapaBit(uint32_t feature, AuthCapability capaBit);
void AuthRemoveAuthManagerByAuthHandle(AuthHandle authHandle);

int32_t AuthCheckSessionKeyValidByConnInfo(const char *networkId, const AuthConnInfo *connInfo);
int32_t AuthCheckSessionKeyValidByAuthHandle(const AuthHandle *authHandle);
int32_t AuthInit(void);
void AuthDeinit(void);
int32_t AuthRestoreAuthManager(const char *udidHash,
    const AuthConnInfo *connInfo, uint32_t requestId, NodeInfo *nodeInfo, int64_t *authId);
int32_t AuthCheckMetaExist(const AuthConnInfo *connInfo, bool *isExist);


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_INTERFACE_H */
