/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define AUTH_INVALID_ID (-1)

#define AUTH_IDENTICAL_ACCOUNT_GROUP 1
#define AUTH_PEER_TO_PEER_GROUP 256

typedef enum {
    /* nearby type v1 */
    SOFTBUS_OLD_V1 = 1,
    /* nearby type v2 */
    SOFTBUS_OLD_V2 = 2,
    /* softbus type v1 */
    SOFTBUS_NEW_V1 = 100,
    /* softbus type v2 */
    SOFTBUS_NEW_V2 = 101,
} SoftBusVersion;

typedef enum {
    AUTH_LINK_TYPE_WIFI = 1,
    AUTH_LINK_TYPE_BR,
    AUTH_LINK_TYPE_BLE,
    AUTH_LINK_TYPE_P2P,
    AUTH_LINK_TYPE_ENHANCED_P2P,
    AUTH_LINK_TYPE_MAX,
} AuthLinkType;

typedef struct {
    AuthLinkType type;
    union {
        struct {
            char brMac[BT_MAC_LEN];
        } brInfo;
        struct {
            BleProtocolType protocol;
            char bleMac[BT_MAC_LEN];
            uint8_t deviceIdHash[UDID_HASH_LEN];
            int32_t psm;
        } bleInfo;
        struct {
            char ip[IP_LEN];
            int32_t port;
            int64_t authId; /* for open p2p auth conn */
            ListenerModule moduleId; /* for open enhance p2p auth conn */
            char udid[UDID_BUF_LEN];
        } ipInfo;
    } info;
    char peerUid[MAX_ACCOUNT_HASH_LEN];
} AuthConnInfo;

typedef enum {
    ONLINE_HICHAIN = 0,
    ONLINE_METANODE,
    ONLINE_MIX,

    AUTH_TYPE_BUTT,
} AuthType;

typedef struct {
    void (*onDeviceVerifyPass)(int64_t authId, const NodeInfo *info);
    void (*onDeviceNotTrusted)(const char *peerUdid);
    void (*onDeviceDisconnect)(int64_t authId);
} AuthVerifyListener;
int32_t RegAuthVerifyListener(const AuthVerifyListener *listener);
void UnregAuthVerifyListener(void);

typedef struct {
    void (*onVerifyPassed)(uint32_t requestId, int64_t authId, const NodeInfo *info);
    void (*onVerifyFailed)(uint32_t requestId, int32_t reason);
} AuthVerifyCallback;

uint32_t AuthGenRequestId(void);
int32_t AuthStartVerify(const AuthConnInfo *connInfo, uint32_t requestId,
    const AuthVerifyCallback *callback, bool isFastAuth);
void AuthHandleLeaveLNN(int64_t authId);
int32_t AuthFlushDevice(const char *uuid);

int32_t AuthMetaStartVerify(uint32_t connectionId, const uint8_t *key, uint32_t keyLen,
    uint32_t requestId, int32_t callingPid, const AuthVerifyCallback *callBack);
void AuthMetaReleaseVerify(int64_t authId);
void AuthServerDeathCallback(const char *pkgName, int32_t pid);

typedef struct {
    void (*onGroupCreated)(const char *groupId, int32_t groupType);
    void (*onGroupDeleted)(const char *groupId);
    void (*onDeviceBound)(const char *udid, const char *groupInfo);
} GroupChangeListener;

typedef enum {
    TRUSTED_RELATION_IGNORE = 0,
    TRUSTED_RELATION_NO,
    TRUSTED_RELATION_YES,
} TrustedReturnType;

int32_t RegGroupChangeListener(const GroupChangeListener *listener);
void UnregGroupChangeListener(void);

TrustedReturnType AuthHasTrustedRelation(void);
bool AuthIsPotentialTrusted(const DeviceInfo *device);
bool IsAuthHasTrustedRelation(void);

int32_t AuthStartListening(AuthLinkType type, const char *ip, int32_t port);
void AuthStopListening(AuthLinkType type);

int32_t AuthStartListeningForWifiDirect(AuthLinkType type, const char *ip, int32_t port, ListenerModule *moduleId);
void AuthStopListeningForWifiDirect(AuthLinkType type, ListenerModule moduleId);

typedef struct {
    int32_t module;
    int32_t flag;
    int64_t seq;
    uint32_t len;
    const uint8_t *data;
} AuthTransData;

typedef struct {
    void (*onDataReceived)(int64_t authId, const AuthTransData *data);
    void (*onDisconnected)(int64_t authId);
} AuthTransListener;
int32_t RegAuthTransListener(int32_t module, const AuthTransListener *listener);
void UnregAuthTransListener(int32_t module);

typedef struct {
    void (*onConnOpened)(uint32_t requestId, int64_t authId);
    void (*onConnOpenFailed)(uint32_t requestId, int32_t reason);
} AuthConnCallback;
int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta);
int32_t AuthPostTransData(int64_t authId, const AuthTransData *dataInfo);
void AuthCloseConn(int64_t authId);
int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta);
int32_t AuthGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta);
void AuthDeleteStoredAuthKey(const char *udid, int32_t discoveryType);
int32_t AuthGetLatestAuthSeqList(const char *udid, int64_t *seqList, uint32_t num);
void AuthDeleteStoredAuthKey(const char *udid, int32_t discoveryType);

/* for ProxyChannel & P2P TcpDirectchannel */
int64_t AuthGetLatestIdByUuid(const char *uuid, AuthLinkType type, bool isMeta);
int64_t AuthGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer, bool isMeta);
int64_t AuthGetIdByUuid(const char *uuid, AuthLinkType type, bool isServer, bool isMeta);

uint32_t AuthGetEncryptSize(uint32_t inLen);
uint32_t AuthGetDecryptSize(uint32_t inLen);
int32_t AuthEncrypt(int64_t authId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen);
int32_t AuthDecrypt(int64_t authId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen);

int32_t AuthSetP2pMac(int64_t authId, const char *p2pMac);

int32_t AuthGetConnInfo(int64_t authId, AuthConnInfo *connInfo);
int32_t AuthGetServerSide(int64_t authId, bool *isServer);
int32_t AuthGetDeviceUuid(int64_t authId, char *uuid, uint16_t size);
int32_t AuthGetVersion(int64_t authId, SoftBusVersion *version);
int32_t AuthGetMetaType(int64_t authId, bool *isMetaAuth);
int32_t AuthGetGroupType(const char *udid, const char *uuid);

int32_t AuthInit(void);
void AuthDeinit(void);
int32_t AuthRestoreAuthManager(const char *udidHash,
    const AuthConnInfo *connInfo, uint32_t requestId, NodeInfo *nodeInfo, int64_t *authId);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_INTERFACE_H */