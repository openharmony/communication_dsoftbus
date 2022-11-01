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

typedef enum {
    /* nearby type v1 */
    SOFTBUS_OLD_V1 = 1,
    /* nearby type v2 */
    SOFTBUS_OLD_V2 = 2,
    /* softbus type v1 */
    SOFTBUS_NEW_V1 = 100,
} SoftBusVersion;

typedef enum {
    AUTH_LINK_TYPE_WIFI = 1,
    AUTH_LINK_TYPE_BR,
    AUTH_LINK_TYPE_BLE,
    AUTH_LINK_TYPE_P2P,
} AuthLinkType;

typedef struct {
    AuthLinkType type;
    union {
        struct {
            char brMac[BT_MAC_LEN];
        } brInfo;
        struct {
            char bleMac[BT_MAC_LEN];
            uint8_t deviceIdHash[UDID_HASH_LEN];
        } bleInfo;
        struct {
            char ip[IP_LEN];
            int32_t port;
            int64_t authId; /* for open p2p auth conn */
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
int32_t AuthStartVerify(const AuthConnInfo *connInfo, uint32_t requestId, const AuthVerifyCallback *callback);
void AuthHandleLeaveLNN(int64_t authId);
int32_t AuthFlushDevice(const char *uuid);

int32_t AuthMetaStartVerify(uint32_t connectionId, const uint8_t *key, uint32_t keyLen,
    uint32_t requestId, const AuthVerifyCallback *callBack);
void AuthMetaReleaseVerify(int64_t authId);

typedef struct {
    void (*onGroupCreated)(const char *groupId);
    void (*onGroupDeleted)(const char *groupId);
} GroupChangeListener;
int32_t RegGroupChangeListener(const GroupChangeListener *listener);
void UnregGroupChangeListener(void);

int32_t AuthStartListening(AuthLinkType type, const char *ip, int32_t port);
void AuthStopListening(AuthLinkType type);

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

/* for ProxyChannel & P2P TcpDirectchannel */
int64_t AuthGetLatestIdByUuid(const char *uuid, bool isIpConnection, bool isMeta);
int64_t AuthGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer, bool isMeta);
int64_t AuthGetIdByP2pMac(const char *p2pMac, AuthLinkType type, bool isServer, bool isMeta);

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

int32_t AuthInit(void);
void AuthDeinit(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_INTERFACE_H */
