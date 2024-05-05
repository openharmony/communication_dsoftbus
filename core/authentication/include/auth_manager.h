/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef AUTH_MANAGER_H
#define AUTH_MANAGER_H

#include <stdint.h>
#include <stdbool.h>

#include "auth_common.h"
#include "auth_interface.h"
#include "auth_normalize_request.h"
#include "auth_session_fsm.h"
#include "auth_session_key.h"
#include "common_list.h"
#include "lnn_lane_interface.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    int64_t authId;
    bool isServer;
    /* 连接信息 */
    uint64_t connId[AUTH_LINK_TYPE_MAX];
    AuthConnInfo connInfo[AUTH_LINK_TYPE_MAX];
    uint64_t lastActiveTime;
    /* 密钥信息 */
    int64_t lastAuthSeq[AUTH_LINK_TYPE_MAX];
    uint64_t lastVerifyTime;
    SessionKeyList sessionKeyList;
    /* 设备信息 */
    char p2pMac[MAC_LEN];
    char udid[UDID_BUF_LEN];
    char uuid[UUID_BUF_LEN];
    SoftBusVersion version;
    /* 认证状态 */
    bool hasAuthPassed;
    ListNode node;
} AuthManager;

typedef struct {
    int32_t messageType;
    ModeCycle cycle;
} DeviceMessageParse;

int32_t AuthManagerSetSessionKey(int64_t authSeq, AuthSessionInfo *info, const SessionKey *sessionKey,
    bool isConnect);
int32_t AuthManagerGetSessionKey(int64_t authSeq, const AuthSessionInfo *info, SessionKey *sessionKey);

void AuthManagerSetAuthPassed(int64_t authSeq, const AuthSessionInfo *info);
void AuthManagerSetAuthFailed(int64_t authSeq, const AuthSessionInfo *info, int32_t reason);
void AuthManagerSetAuthFinished(int64_t authSeq, const AuthSessionInfo *info);

int32_t DelAuthReqInfoByAuthHandle(const AuthHandle *authHandle);
void AuthFreeLane(const AuthHandle *authHandle);
int32_t GetAuthLinkTypeList(const char *networkId, AuthLinkTypeList *linkTypeList);
int32_t GetAuthConn(const char *uuid, LaneLinkType laneType, AuthConnInfo *connInfo);
int32_t AuthAllocLane(const char *networkId, uint32_t authRequestId, AuthConnCallback *callback);

/* Note: must call DelAuthManager to free. */
AuthManager *GetAuthManagerByAuthId(int64_t authId);
AuthManager *GetAuthManagerByConnInfo(const AuthConnInfo *connInfo, bool isServer);
void RemoveAuthSessionKeyByIndex(int64_t authId, int32_t index, AuthLinkType type);
void DelAuthManager(AuthManager *auth, int32_t type);
void DelDupAuthManager(AuthManager *auth);
void RemoveAuthManagerByAuthId(AuthHandle authHandle);
int32_t AuthDeviceOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback);
int32_t AuthDevicePostTransData(AuthHandle authHandle, const AuthTransData *dataInfo);
void AuthDeviceCloseConn(AuthHandle authHandle);
int32_t AuthDeviceGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo);
int32_t AuthDeviceGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo);
/*check whether AUTH device is exist or not*/
bool AuthDeviceCheckConnInfo(const char* uuid, AuthLinkType type, bool checkConnection);

/* for ProxyChannel & P2P TcpDirectchannel */
void AuthDeviceGetLatestIdByUuid(const char *uuid, AuthLinkType type, AuthHandle *authHandle);
int64_t AuthDeviceGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer);
int64_t AuthDeviceGetIdByUuid(const char *uuid, AuthLinkType type, bool isServer);
int32_t AuthDeviceGetAuthHandleByIndex(const char *udid, bool isServer, int32_t index, AuthHandle *authHandle);
AuthManager *NewAuthManager(int64_t authSeq, const AuthSessionInfo *info);

int32_t AuthDeviceEncrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData,
    uint32_t *outLen);
int32_t AuthDeviceDecrypt(AuthHandle *authHandle, const uint8_t *inData, uint32_t inLen, uint8_t *outData,
    uint32_t *outLen);
int32_t AuthDeviceSetP2pMac(int64_t authId, const char *p2pMac);

int32_t AuthVerifyAfterNotifyNormalize(NormalizeRequest *request);
int32_t AuthDeviceGetConnInfo(AuthHandle authHandle, AuthConnInfo *connInfo);
int32_t AuthDeviceGetDeviceUuid(int64_t authId, char *uuid, uint16_t size);
int32_t AuthDeviceGetVersion(int64_t authId, SoftBusVersion *version);
int32_t AuthDeviceGetServerSide(int64_t authId, bool *isServer);
int32_t AuthDeviceInit(const AuthTransCallback *callback);
int32_t RegTrustListenerOnHichainSaStart(void);
int32_t GetHmlOrP2pAuthHandle(AuthHandle **authHandle, int32_t *num);
void AuthDeviceDeinit(void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_MANAGER_H */
